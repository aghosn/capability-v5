//! Integration tests for the `Platform` trait and `execute()` wrapper.
//!
//! Uses `TestPlatform` from `tests/common/mod.rs` as the platform under test.

#[path = "../common/mod.rs"]
mod common;

use capability_engine::{
    execute, Capability, CoreId, Domain, DomainId, DomainPolicy, MonitorAPI, Platform, Update,
};
use capability_engine::memory::Rights;
use common::{CallLogEntry, TestPlatform};

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
    let (val, batch) = execute(&platform, false, || {
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

    execute(&platform, false, || {
        let mut batch = capability_engine::UpdateBatch::new();
        batch.add_change_rights(0, 0x1000, 0x1000, 0x1000, Rights::RW, false);
        Ok(((), batch))
    })
    .expect("should succeed");

    let updates = platform.drain_updates();
    assert_eq!(updates.len(), 1);
    assert!(matches!(
        &updates[0],
        Update::ChangeRights { domain, address, size, shootdown_required: false, .. }
            if *domain == 0 && *address == 0x1000 && *size == 0x1000
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Domain revocation updates core state to the fallback
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_execute_revoke_redirects_core_to_fallback() {
    let platform = TestPlatform::new();
    const CORE_0: CoreId = 0;

    let root = Capability::new_root(0, 0, Domain::new_root(4));
    let root_id = root.read().data.id;

    let child_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let child_h = Capability::create(&platform, &root, child_policy).unwrap().0;
    Capability::seal(&platform, &root, child_h).unwrap();
    let child = root.read().data.domain_capabilities[&child_h]
        .upgrade()
        .unwrap();
    let child_id = child.read().data.id;

    reg(&platform, root_id, None);
    reg(&platform, child_id, Some(root_id));

    // Simulate core 0 running the child domain
    platform.set_core_context(CORE_0, &child, 0);
    assert_eq!(platform.get_core_domain(CORE_0), Some(child_id));

    // Execute a "revoke child domain" operation
    execute(&platform, false, || {
        let mut batch = capability_engine::UpdateBatch::new();
        batch.add_revoke_domain_with_fallback(child_id, Some(root_id));
        Ok(((), batch))
    })
    .expect("revoke should succeed");

    // After revocation, core 0 should now be running the parent (fallback)
    assert_eq!(
        platform.get_core_domain(CORE_0),
        Some(root_id),
        "core should have switched to the fallback domain"
    );

    // Child domain should be marked as revoked
    assert!(
        platform.is_domain_revoked(child_id),
        "child domain should be marked revoked"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Exclusive lock: revoke is fully isolated from concurrent shared ops
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_execute_exclusive_blocks_shared() {
    // Verifies that an exclusive lock (revoke) and a shared lock (non-revoke)
    // cannot be held simultaneously, using real threads.
    use std::sync::atomic::{AtomicBool, Ordering};

    let platform = std::sync::Arc::new(TestPlatform::new());
    reg(&platform, 0, None);
    reg(&platform, 1, Some(0));

    // Set inside the exclusive closure to prove the lock is *actually* held.
    let exclusive_lock_held = std::sync::Arc::new(AtomicBool::new(false));
    let exclusive_done = std::sync::Arc::new(AtomicBool::new(false));

    let p_clone = platform.clone();
    let held_clone = exclusive_lock_held.clone();
    let done_clone = exclusive_done.clone();

    let t = std::thread::spawn(move || {
        execute(&*p_clone, true, || {
            // Prove we are inside execute with the exclusive lock held.
            held_clone.store(true, Ordering::SeqCst);
            // Hold the lock long enough for the shared thread to attempt entry.
            std::thread::sleep(std::time::Duration::from_millis(80));
            done_clone.store(true, Ordering::SeqCst);
            let mut batch = capability_engine::UpdateBatch::new();
            batch.add_revoke_domain_with_fallback(1, Some(0));
            Ok(((), batch))
        })
        .unwrap();
    });

    // Spin until the exclusive lock is *confirmed held* inside the closure.
    while !exclusive_lock_held.load(Ordering::SeqCst) {
        std::thread::yield_now();
    }

    // Now attempt the shared lock — must block until exclusive is released.
    execute(&*platform, false, || {
        assert!(
            exclusive_done.load(Ordering::SeqCst),
            "exclusive op must finish before shared op can run"
        );
        Ok(((), capability_engine::UpdateBatch::new()))
    })
    .unwrap();

    t.join().unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Vital memory revocation: fallback=None → platform uses parent map
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_execute_vital_revoke_none_fallback_uses_parent_map() {
    let platform = TestPlatform::new();
    const CORE_0: CoreId = 0;

    let root = Capability::new_root(0, 0, Domain::new_root(4));
    let root_id = root.read().data.id;

    let child_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let child_h = Capability::create(&platform, &root, child_policy).unwrap().0;
    Capability::seal(&platform, &root, child_h).unwrap();
    let child = root.read().data.domain_capabilities[&child_h]
        .upgrade()
        .unwrap();
    let child_id = child.read().data.id;

    reg(&platform, root_id, None);
    reg(&platform, child_id, Some(root_id)); // parent stored in platform registry

    platform.set_core_context(CORE_0, &child, 0);

    // Vital memory revocation: fallback=None, platform walks parent map
    execute(&platform, true, || {
        let mut batch = capability_engine::UpdateBatch::new();
        batch.add_revoke_domain_with_fallback(child_id, None);
        Ok(((), batch))
    })
    .expect("vital revoke should succeed");

    // Platform should have redirected core to the parent (from its own map)
    assert_eq!(
        platform.get_core_domain(CORE_0),
        Some(root_id),
        "core should have fallen back to the registered parent"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Capability engine integration: revoke_child_domain passes fallback
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_revoke_domain_carries_fallback() {
    let platform = TestPlatform::new();
    const ROOT_ID: DomainId = 0;

    // Build root domain capability
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(ROOT_ID, 0, root_domain);
    reg(&platform, ROOT_ID, None);

    let child_api = MonitorAPI::from_bits(MonitorAPI::GET | MonitorAPI::REVOKE);
    let child_policy = DomainPolicy::new_restricted(0b0001, child_api);
    let child_h =
        Capability::create(&platform, &root, child_policy).expect("create should succeed").0;

    let child = root.read().data.domain_capabilities[&child_h]
        .upgrade()
        .unwrap();
    let child_id = child.read().data.id;
    reg(&platform, child_id, Some(ROOT_ID));

    // Root domain is already sealed (new_root); seal the child
    Capability::seal(&platform, &root, child_h).unwrap();

    let batch = Capability::revoke_domain(&platform, &root, child_h)
        .expect("revoke_domain should succeed");

    // The UpdateBatch must contain RevokeDomain with fallback = Some(ROOT_ID)
    let revoke_update = batch
        .updates()
        .iter()
        .find(|u| matches!(u, Update::RevokeDomain { domain, .. } if *domain == child_id));
    assert!(revoke_update.is_some(), "should have RevokeDomain update");

    if let Some(Update::RevokeDomain { fallback, .. }) = revoke_update {
        assert_eq!(
            *fallback,
            Some(ROOT_ID),
            "fallback should be the parent domain id"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Domain revocation ordering — on_domain_revoked must precede
//    apply_update(RevokeDomain{d}) for the same d.
//
// Rationale: on bare metal, apply_update(RevokeDomain) calls the platform's
// per-domain `arch.destroy()` which frees the domain's second-stage page
// tables and IOMMU tables.  If a remote core is still bound to that domain
// at the moment destroy() runs, its VMCS's EPTP references freed memory
// and the next VMRESUME on that core is a use-after-free.
//
// The Platform contract therefore requires `on_domain_revoked(d, fb)` to
// run FIRST — inside the barrier window when all affected cores are
// stopped — so the platform can atomically re-bind those cores to the
// fallback domain (swapping the per-core `domain_cap`, VMCLEAR-ing the
// stale VMCS, installing the fallback's VMCS) *before* apply_update runs
// the teardown.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_execute_on_domain_revoked_precedes_apply_update() {
    let platform = TestPlatform::new();
    const CORE_0: CoreId = 0;
    const ROOT_ID: DomainId = 0;

    reg(&platform, ROOT_ID, None);

    // Simulate a remote core actively bound to the child domain — this is
    // exactly the "domain is running on a remote core" case the fix must
    // handle safely.
    let root_cap = Capability::new_root(0, 0, Domain::new_root(4));
    let child_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let child_h = Capability::create(&platform, &root_cap, child_policy)
        .unwrap()
        .0;
    Capability::seal(&platform, &root_cap, child_h).unwrap();
    let child_cap = root_cap.read().data.domain_capabilities[&child_h]
        .upgrade()
        .unwrap();
    let child_id = child_cap.read().data.id;
    reg(&platform, child_id, Some(ROOT_ID));
    platform.set_core_context(CORE_0, &child_cap, 0);

    // Sanity: core is bound to the child.
    assert_eq!(platform.get_core_domain(CORE_0), Some(child_id));

    // Trigger a RevokeDomain update through the engine's execute() so we
    // exercise the real ordering (barrier + apply_update + on_domain_revoked).
    execute(&platform, true, || {
        let mut batch = capability_engine::UpdateBatch::new();
        batch.add_revoke_domain_with_fallback(child_id, Some(ROOT_ID));
        Ok(((), batch))
    })
    .expect("revoke should succeed");

    // Inspect the ordered call log.
    let log = platform.drain_call_log();

    let on_revoked_idx = log
        .iter()
        .position(|e| {
            matches!(
                e,
                CallLogEntry::OnDomainRevoked { domain, .. } if *domain == child_id
            )
        })
        .expect("on_domain_revoked(child_id) must have been called");

    let apply_idx = log
        .iter()
        .position(|e| {
            matches!(
                e,
                CallLogEntry::ApplyUpdate(Update::RevokeDomain { domain, .. })
                    if *domain == child_id
            )
        })
        .expect("apply_update(RevokeDomain{child_id}) must have been called");

    assert!(
        on_revoked_idx < apply_idx,
        "on_domain_revoked(child_id) must precede apply_update(RevokeDomain{{child_id}}) \
         so the platform re-binds remote cores off the doomed domain BEFORE destroy() \
         runs.  Got log order: on_domain_revoked at #{on_revoked_idx}, \
         apply_update(RevokeDomain) at #{apply_idx}.  \
         Full log:\n{:#?}",
        log,
    );

    // After ordering is correct, the routing must have flipped to the fallback.
    assert_eq!(
        platform.get_core_domain(CORE_0),
        Some(ROOT_ID),
        "core should have been redirected to the fallback (root)"
    );
    assert!(
        platform.is_domain_revoked(child_id),
        "child domain must be marked revoked"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Cross-core domain revocation — Platform::push_core_switch is invoked
//    with the correct resume target for every affected core, BEFORE the
//    initiator's IPI/apply_update phase.
//
// See docs/design/cross-core-revoke.md — Tyche-aligned protocol.
// ─────────────────────────────────────────────────────────────────────────────

use capability_engine::{CapabilityRef, LocalHandle, VpRunState};

/// Put `domain`'s VP[vp_id] into `Running { core, caller: None }`.  Used
/// as a seed state before `Capability::switch` gets called.
fn seed_running(domain: &CapabilityRef<Domain>, vp_id: usize, core: CoreId) {
    let d = domain.read();
    let vp = d.data.policy.vprocessor_states[vp_id].clone();
    drop(d);
    *vp.run_state.write() = VpRunState::Running { core, caller: None };
}

/// Create + seal a child domain under `parent` with all 4 cores and 4 VPs.
fn make_child(
    platform: &TestPlatform,
    parent: &CapabilityRef<Domain>,
) -> (CapabilityRef<Domain>, LocalHandle) {
    let policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let num_vps = policy.num_vprocessors;
    let h = Capability::create(platform, parent, policy).unwrap().0;
    let child = parent.read().data.domain_capabilities[&h]
        .upgrade()
        .unwrap();
    for _ in 0..num_vps {
        child.write().data.add_vprocessor().unwrap();
    }
    Capability::seal(platform, parent, h).unwrap();
    let child_id = child.read().data.id;
    let parent_id = parent.read().data.id;
    platform.register_domain(child_id, Some(parent_id));
    (child, h)
}

/// Extract the `(core, source_domain_id, source_vp)` of every `PushCoreSwitch`
/// entry in the log, in order. No resume target is carried on the wire —
/// the affected core resolves that locally from its own `call_stack`; see
/// `resolve_revoke_target` below for how tests verify it.
fn switches_in(log: &[CallLogEntry]) -> Vec<(CoreId, DomainId, u64)> {
    log.iter()
        .filter_map(|e| match e {
            CallLogEntry::PushCoreSwitch {
                core,
                source_domain,
                source_vp,
            } => Some((*core, *source_domain, *source_vp)),
            _ => None,
        })
        .collect()
}

/// Simulate what the affected core does in `apply_local_core_updates`:
/// call `switch_after_callee_revoked` on `core`, which pops that core's own
/// `call_stack` to resolve its resume target locally. Returns
/// `(target_domain_id, target_vp)`.
fn resolve_revoke_target(platform: &TestPlatform, core: CoreId) -> (DomainId, u64) {
    platform.set_current_core(Some(core));
    let ctx = capability_engine::Capability::<Domain>::switch_after_callee_revoked(platform)
        .expect("switch_after_callee_revoked should resolve a target from the call_stack");
    let to_domain_id = ctx.to_domain.read().data.id;
    (
        to_domain_id,
        ctx.to_vp_id.expect("revoke-return always names a target VP"),
    )
}

/// Index of the last `PushCoreSwitch` entry (or `None`).
fn last_push_idx(log: &[CallLogEntry]) -> Option<usize> {
    log.iter()
        .rposition(|e| matches!(e, CallLogEntry::PushCoreSwitch { .. }))
}

/// Index of the first `ApplyUpdate(RevokeDomain{d})` entry for `d`.
fn first_apply_revoke_idx(log: &[CallLogEntry], d: DomainId) -> Option<usize> {
    log.iter().position(|e| {
        matches!(
            e,
            CallLogEntry::ApplyUpdate(Update::RevokeDomain { domain, .. }) if *domain == d
        )
    })
}

/// **T-basic** — root + one child, remote core running child.
///
/// Revoking child from root must emit exactly one `push_core_switch`
/// naming (remote_core, root, root_vp_id_that_did_the_switch), and it
/// must be recorded BEFORE the `apply_update(RevokeDomain{child})` entry.
#[test]
fn test_revoke_basic_pushes_switch_to_root() {
    const REMOTE_CORE: CoreId = 1;
    const INIT_CORE: CoreId = 0;

    let platform = TestPlatform::new();
    let root = Capability::new_root(0, 0, Domain::new_root(4));
    let root_id = root.read().data.id;
    platform.register_domain(root_id, None);

    // Remote core: seed root VP[REMOTE_CORE] as Running on REMOTE_CORE,
    // then switch it into the child.  After the switch, child.VP[0] is
    // Running{core: REMOTE_CORE, caller: root.VP[REMOTE_CORE]}.
    seed_running(&root, REMOTE_CORE as usize, REMOTE_CORE);
    platform.set_current_core(Some(REMOTE_CORE));
    let (child, child_h) = make_child(&platform, &root);
    let child_id = child.read().data.id;
    Capability::switch(&platform, &root, child_h, 0).unwrap();

    // Sanity: remote core is bound to child.
    assert_eq!(platform.get_core_domain(REMOTE_CORE), Some(child_id));

    // Move to the initiator core to trigger the revocation from a
    // different core.  This is the cross-core path exercised by
    // execute()'s affected_cores set.
    platform.set_current_core(Some(INIT_CORE));
    let _ = platform.drain_call_log(); // discard setup entries

    capability_engine::Capability::<Domain>::revoke_domain(&platform, &root, child_h)
        .expect("revoke_domain should succeed");

    let log = platform.drain_call_log();
    let switches = switches_in(&log);

    assert_eq!(
        switches,
        vec![(REMOTE_CORE, child_id, 0)],
        "expected exactly one push_core_switch naming (REMOTE_CORE, child, VP[0]); \
         got: {:#?}\nfull log: {:#?}",
        switches,
        log,
    );

    // Simulate the affected core resolving its own resume target locally.
    assert_eq!(
        resolve_revoke_target(&platform, REMOTE_CORE),
        (root_id, REMOTE_CORE),
        "affected core should resolve its own call_stack back to root.VP[REMOTE_CORE]"
    );

    let last_push = last_push_idx(&log).expect("push_core_switch missing");
    let first_apply = first_apply_revoke_idx(&log, child_id)
        .expect("apply_update(RevokeDomain{child}) missing");
    assert!(
        last_push < first_apply,
        "push_core_switch must be recorded BEFORE apply_update(RevokeDomain{{child}}); \
         push idx={last_push}, apply idx={first_apply}\nlog: {:#?}",
        log,
    );
}

/// **T-chain** — A→B→C, remote core running C, revoke B.
///
/// Because B is revoked (subtree ⇒ C is too), the walk must skip past B
/// and emit a switch back to A on the remote core.
#[test]
fn test_revoke_chain_walks_past_revoked_ancestor() {
    const REMOTE_CORE: CoreId = 1;
    const INIT_CORE: CoreId = 0;

    let platform = TestPlatform::new();
    // A = root
    let root = Capability::new_root(0, 0, Domain::new_root(4));
    let root_id = root.read().data.id;
    platform.register_domain(root_id, None);

    seed_running(&root, REMOTE_CORE as usize, REMOTE_CORE);
    platform.set_current_core(Some(REMOTE_CORE));

    // B under A
    let (child_b, child_b_h) = make_child(&platform, &root);

    // A → B
    Capability::switch(&platform, &root, child_b_h, 0).unwrap();

    // C under B
    let (child_c, child_c_h) = make_child(&platform, &child_b);
    let child_c_id = child_c.read().data.id;

    // B → C
    Capability::switch(&platform, &child_b, child_c_h, 0).unwrap();

    // Sanity: remote core is bound to C.
    assert_eq!(platform.get_core_domain(REMOTE_CORE), Some(child_c_id));

    // Initiate the revocation of B from the initiator core.
    platform.set_current_core(Some(INIT_CORE));
    let _ = platform.drain_call_log();

    capability_engine::Capability::<Domain>::revoke_domain(&platform, &root, child_b_h)
        .expect("revoke_domain should succeed");

    let log = platform.drain_call_log();
    let switches = switches_in(&log);

    // Exactly one push, naming the actually-Running leaf (C) on REMOTE_CORE.
    assert_eq!(
        switches,
        vec![(REMOTE_CORE, child_c_id, 0)],
        "chain revoke should push exactly one switch for the leaf VP; got: {:#?}\nlog: {:#?}",
        switches,
        log,
    );

    // The affected core must skip past revoked B and resolve back to A
    // (root), on the VP that originally did the A→B switch (VP[REMOTE_CORE]).
    assert_eq!(
        resolve_revoke_target(&platform, REMOTE_CORE),
        (root_id, REMOTE_CORE),
        "chain walk should skip revoked B and resume in A"
    );
}

/// **T-multi** — two siblings under root, each on its own remote core;
/// revoke one sibling only, the other must not be touched.
#[test]
fn test_revoke_multi_only_affected_core_pushed() {
    const CORE_A: CoreId = 1;
    const CORE_B: CoreId = 2;
    const INIT_CORE: CoreId = 0;

    let platform = TestPlatform::new();
    let root = Capability::new_root(0, 0, Domain::new_root(4));
    let root_id = root.read().data.id;
    platform.register_domain(root_id, None);

    // Two children, each bound to a different remote core via a switch
    // originating from a distinct root VP.
    seed_running(&root, CORE_A as usize, CORE_A);
    platform.set_current_core(Some(CORE_A));
    let (child_a, child_a_h) = make_child(&platform, &root);
    let child_a_id = child_a.read().data.id;
    Capability::switch(&platform, &root, child_a_h, 0).unwrap();

    seed_running(&root, CORE_B as usize, CORE_B);
    platform.set_current_core(Some(CORE_B));
    let (child_b, child_b_h) = make_child(&platform, &root);
    let child_b_id = child_b.read().data.id;
    Capability::switch(&platform, &root, child_b_h, 0).unwrap();

    // Revoke ONLY child_a.
    platform.set_current_core(Some(INIT_CORE));
    let _ = platform.drain_call_log();

    capability_engine::Capability::<Domain>::revoke_domain(&platform, &root, child_a_h)
        .expect("revoke_domain should succeed");

    let log = platform.drain_call_log();
    let switches = switches_in(&log);

    assert_eq!(
        switches,
        vec![(CORE_A, child_a_id, 0)],
        "only CORE_A should have a push; child_b's core (CORE_B) must be untouched. \
         got: {:#?}\nlog: {:#?}",
        switches,
        log,
    );

    // CORE_A must resolve back to root, on the VP that did the root→A switch.
    assert_eq!(
        resolve_revoke_target(&platform, CORE_A),
        (root_id, CORE_A),
        "CORE_A should resolve its own call_stack back to root.VP[CORE_A]"
    );

    // child_b's binding must remain intact.
    assert_eq!(platform.get_core_domain(CORE_B), Some(child_b_id));
    let _ = child_b_id;
}

/// **T-none** — revoke a domain bound to no core.  Zero pushes.
#[test]
fn test_revoke_no_running_vp_no_pushes() {
    const INIT_CORE: CoreId = 0;

    let platform = TestPlatform::new();
    let root = Capability::new_root(0, 0, Domain::new_root(4));
    let root_id = root.read().data.id;
    platform.register_domain(root_id, None);
    platform.set_current_core(Some(INIT_CORE));

    // Create + seal a child but never switch into it — no VP is Running.
    let (child, child_h) = make_child(&platform, &root);
    let child_id = child.read().data.id;
    assert_eq!(platform.get_core_domain(INIT_CORE), None);

    let _ = platform.drain_call_log();
    capability_engine::Capability::<Domain>::revoke_domain(&platform, &root, child_h)
        .expect("revoke_domain should succeed");

    let log = platform.drain_call_log();
    let switches = switches_in(&log);

    assert!(
        switches.is_empty(),
        "no core is running the child; expected 0 pushes, got: {:#?}\nlog: {:#?}",
        switches,
        log,
    );

    // Sanity: apply_update(RevokeDomain{child}) must still be emitted.
    assert!(
        first_apply_revoke_idx(&log, child_id).is_some(),
        "apply_update(RevokeDomain{{child}}) must still fire even with 0 switches\n\
         log: {:#?}",
        log,
    );
}
