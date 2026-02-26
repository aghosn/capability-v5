//! Integration tests for the `Platform` trait and `execute()` wrapper.
//!
//! Uses `TestPlatform` from `tests/common/mod.rs` as the platform under test.

#[path = "common/mod.rs"]
mod common;

use std::collections::BTreeSet;

use capability_engine::{
    execute, CapaError, Capability, CoreId, DomainCapabilityExt, DomainId, DomainPolicy,
    Domain, MonitorAPI, Platform, Update, UpdateBatch,
};
use common::TestPlatform;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Register domain `id` with the platform under parent `parent`.
fn reg(platform: &TestPlatform, id: DomainId, parent: Option<DomainId>) {
    platform.register_domain(id, parent);
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Local execute — no remote cores involved
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_execute_local_no_cores() {
    let platform = TestPlatform::new();
    let affected: BTreeSet<DomainId> = BTreeSet::new();

    let (val, batch) = execute(&platform, &affected, || {
        Ok((42u32, capability_engine::UpdateBatch::new()))
    })
    .expect("local execute should succeed");

    assert_eq!(val, 42);
    assert!(batch.is_empty());
    // No updates should have been applied
    assert!(platform.drain_updates().is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Execute with a Map update — verify apply_update is called
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_execute_apply_update_is_called() {
    let platform = TestPlatform::new();
    reg(&platform, 0, None); // root domain

    let affected: BTreeSet<DomainId> = BTreeSet::from([0]);

    execute(&platform, &affected, || {
        let mut batch = capability_engine::UpdateBatch::new();
        batch.add_map(0, 0x1000, 0x1000, 0x1000, true, true, false);
        Ok(((), batch))
    })
    .expect("should succeed");

    let updates = platform.drain_updates();
    assert_eq!(updates.len(), 1);
    assert!(matches!(
        &updates[0],
        Update::Map { domain, address, size, .. }
            if *domain == 0 && *address == 0x1000 && *size == 0x1000
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Domain revocation updates core state to the fallback
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_execute_revoke_redirects_core_to_fallback() {
    let platform = TestPlatform::new();
    const ROOT_ID: DomainId = 0;
    const CHILD_ID: DomainId = 1;
    const CORE_0: CoreId = 0;

    reg(&platform, ROOT_ID, None);
    reg(&platform, CHILD_ID, Some(ROOT_ID));

    // Simulate core 0 running the child domain
    platform.set_core_domain(CORE_0, CHILD_ID);
    assert_eq!(platform.get_core_domain(CORE_0), Some(CHILD_ID));

    // Execute a "revoke child domain" operation
    let affected: BTreeSet<DomainId> = BTreeSet::from([ROOT_ID]);

    execute(&platform, &affected, || {
        let mut batch = capability_engine::UpdateBatch::new();
        batch.add_revoke_domain_with_fallback(CHILD_ID, Some(ROOT_ID));
        Ok(((), batch))
    })
    .expect("revoke should succeed");

    // After revocation, core 0 should now be running the parent (fallback)
    assert_eq!(
        platform.get_core_domain(CORE_0),
        Some(ROOT_ID),
        "core should have switched to the fallback domain"
    );

    // Child domain should be marked as revoked
    assert!(
        platform.is_domain_revoked(CHILD_ID),
        "child domain should be marked revoked"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. TOCTOU: domain revoked before lock is acquired
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_execute_toctou_domain_revoked() {
    let platform = TestPlatform::new();
    const DOMAIN_ID: DomainId = 5;

    reg(&platform, DOMAIN_ID, None);

    // Manually mark the domain as revoked (simulates concurrent revocation)
    {
        let mut batch = capability_engine::UpdateBatch::new();
        batch.add_revoke_domain(DOMAIN_ID);
        let affected: BTreeSet<DomainId> = BTreeSet::new();
        execute(&platform, &affected, || Ok(((), batch))).unwrap();
    }

    assert!(platform.is_domain_revoked(DOMAIN_ID));

    // Attempting to execute an operation targeting the revoked domain should fail
    let affected: BTreeSet<DomainId> = BTreeSet::from([DOMAIN_ID]);
    let result = execute(&platform, &affected, || {
        Ok(((), capability_engine::UpdateBatch::new()))
    });

    assert_eq!(
        result.unwrap_err(),
        CapaError::DomainRevoked,
        "should reject operation on revoked domain"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Vital memory revocation: fallback=None → platform uses parent map
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_execute_vital_revoke_none_fallback_uses_parent_map() {
    let platform = TestPlatform::new();
    const ROOT_ID: DomainId = 0;
    const CHILD_ID: DomainId = 2;
    const CORE_0: CoreId = 0;

    reg(&platform, ROOT_ID, None);
    reg(&platform, CHILD_ID, Some(ROOT_ID)); // parent stored in platform registry

    platform.set_core_domain(CORE_0, CHILD_ID);

    let affected: BTreeSet<DomainId> = BTreeSet::new();

    // Vital memory revocation: fallback=None, platform walks parent map
    execute(&platform, &affected, || {
        let mut batch = capability_engine::UpdateBatch::new();
        batch.add_revoke_domain_with_fallback(CHILD_ID, None);
        Ok(((), batch))
    })
    .expect("vital revoke should succeed");

    // Platform should have redirected core to the parent (from its own map)
    assert_eq!(
        platform.get_core_domain(CORE_0),
        Some(ROOT_ID),
        "core should have fallen back to the registered parent"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Capability engine integration: revoke_child_domain passes fallback
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_revoke_child_domain_carries_fallback() {
    let platform = TestPlatform::new();
    const ROOT_ID: DomainId = 0;
    const CHILD_HANDLE: capability_engine::LocalHandle = 1;

    // Build root domain capability
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(ROOT_ID, 0, root_domain);
    reg(&platform, ROOT_ID, None);

    // Create a child domain using handle 1
    let child_api = MonitorAPI::from_bits(MonitorAPI::GET | MonitorAPI::REVOKE);
    let child_policy = DomainPolicy::new_restricted(0b0001, child_api);
    let child = Capability::create_child_domain(&root, child_policy, ROOT_ID, CHILD_HANDLE)
        .expect("create_child_domain should succeed");

    let child_id = child.read().data.id;
    reg(&platform, child_id, Some(ROOT_ID));

    // Root domain is already sealed (new_root); seal the child
    child.write().data.seal().unwrap();

    let affected: BTreeSet<DomainId> = BTreeSet::from([ROOT_ID]);

    let (_, batch) = execute(&platform, &affected, || {
        let updates = Capability::revoke_child_domain(&root, CHILD_HANDLE)
            .expect("revoke_child_domain should succeed");
        Ok(((), updates))
    })
    .expect("execute should succeed");

    // The UpdateBatch must contain RevokeDomain with fallback = Some(ROOT_ID)
    let revoke_update = batch.updates().iter().find(|u| {
        matches!(u, Update::RevokeDomain { domain, .. } if *domain == child_id)
    });
    assert!(revoke_update.is_some(), "should have RevokeDomain update");

    if let Some(Update::RevokeDomain { fallback, .. }) = revoke_update {
        assert_eq!(
            *fallback,
            Some(ROOT_ID),
            "fallback should be the parent domain id"
        );
    }
}
