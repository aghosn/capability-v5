//! Tests for A1 bugs in `send_to` and `carve_child`.
//!
//! **A1a** — `send_to` emits no `Unmap` when sending a Carve whose parent is
//!   owned by the caller.  Result: caller keeps hardware access after the send.
//!
//! **A1b** — `carve_child` emits an empty `UpdateBatch` even when the carve
//!   reduces the parent's rights (e.g. RWX → RW).  Result: the platform is
//!   never told to restrict the caller's execute permission on the carved range.
//!
//! **A1c** — sanity check: sending a capability where the caller does NOT own
//!   the parent always emits an `Unmap`.  This path is believed to be correct.

use capability_engine::memory::Rights;
use capability_engine::*;
use std::sync::Arc;

#[path = "../common/mod.rs"]
mod common;


fn setup_root() -> (CapabilityRef<Domain>, LocalHandle) {
    let platform = common::TestPlatform::new();
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);
    let mem = MemoryRegion::new_root(0x0, 0x10000);
    let mem_cap = Capability::new_root(0, 1, mem);
    root.write()
        .data
        .add_memory_capability(1, Arc::downgrade(&mem_cap));
    // Keep mem_cap alive by leaking intentionally — root holds the weak ref,
    // we need the Arc alive for the duration of the test.
    std::mem::forget(mem_cap);
    (root, 1)
}

fn make_unsealed_child(parent: &CapabilityRef<Domain>) -> (CapabilityRef<Domain>, LocalHandle) {
    let platform = common::TestPlatform::new();
    let policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let child_h = Capability::create(&platform, parent, policy).unwrap().0;
    let child = parent.read().data.domain_capabilities[&child_h]
        .upgrade()
        .unwrap();
    (child, child_h)
}

// ---------------------------------------------------------------------------
// A1a — sending a Carve (same rights) must emit Unmap for the caller
// ---------------------------------------------------------------------------

/// When dom0 carves a child from r0 (both owned by dom0, no hardware change),
/// then sends that carved child to an unsealed domain, dom0 must LOSE hardware
/// access to the carved region.  The update batch must contain:
///   Unmap  { domain: root_id, address: 0x1000, size: 0x1000 }
///   Map    { domain: d1_id,   address: 0x1000, size: 0x1000, rw }
///
/// Currently FAILS: `skip_unmap = parent_owned_by_caller = true` suppresses the Unmap.
#[test]
fn a1a_send_carve_caller_owns_parent_must_emit_unmap() {
    let platform = common::TestPlatform::new();
    let (root, r0_h) = setup_root();
    let root_id = root.read().data.id;

    // Carve [0x1000, 0x2000) with same rights — no hardware update expected yet.
    let carve_access = Access::new(0x1000, 0x1000, Rights::RWX);
    let (c1_h, _c1_sub, carve_updates) =
        Capability::carve(&platform, &root, r0_h, carve_access).unwrap();
    assert!(
        carve_updates.is_empty(),
        "Carve with same rights should not produce hardware updates yet"
    );

    // Unsealed receiver.
    let (_d1, d1_h) = make_unsealed_child(&root);
    let d1_id = root.read().data.domain_capabilities[&d1_h]
        .upgrade()
        .unwrap()
        .read()
        .data
        .id;

    let send_updates = Capability::send(&platform, &root, c1_h, d1_h, Attributes::NONE).unwrap();

    // Must unmap from root.
    let has_unmap = send_updates.updates().iter().any(|u| {
        matches!(u, Update::ChangeRights { domain, address, size, rights, .. }
            if *domain == root_id && *address == 0x1000 && *size == 0x1000 && *rights == Rights::NONE)
    });
    assert!(
        has_unmap,
        "send of a Carve must emit Unmap for the caller (got: {:?})",
        send_updates.updates()
    );

    // Must map to d1.
    let has_map = send_updates.updates().iter().any(|u| {
        matches!(u, Update::ChangeRights { domain, address, size, shootdown_required: false, .. }
            if *domain == d1_id && *address == 0x1000 && *size == 0x1000)
    });
    assert!(has_map, "send must emit Map for the receiver");
}

// ---------------------------------------------------------------------------
// A1b — carving with reduced rights must emit ChangeRights for the caller
// ---------------------------------------------------------------------------

/// dom0 owns r0 [0x0, 0x10000) RWX.  It carves [0x1000, 0x2000) with only RW.
/// The caller (dom0) must lose execute permission on that sub-range.  The
/// update batch from the carve should contain:
///   ChangeRights { domain: root_id, address: 0x1000, size: 0x1000,
///                  read: true, write: true, execute: false }
///
/// Currently FAILS: `carve_child` always returns an empty UpdateBatch.
#[test]
fn a1b_carve_with_reduced_rights_must_emit_change_rights() {
    let platform = common::TestPlatform::new();
    let (root, r0_h) = setup_root();
    let root_id = root.read().data.id;

    // Carve with RW only — X is dropped.
    let carve_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_c1_h, _c1_sub, carve_updates) =
        Capability::carve(&platform, &root, r0_h, carve_access).unwrap();

    let has_change_rights = carve_updates.updates().iter().any(|u| {
        matches!(u, Update::ChangeRights { domain, address, size, rights, shootdown_required: true, .. }
            if *domain == root_id
                && *address == 0x1000
                && *size == 0x1000
                && rights.read()
                && rights.write()
                && !rights.execute())
    });
    assert!(
        has_change_rights,
        "carve with reduced rights must emit ChangeRights for the caller (got: {:?})",
        carve_updates.updates()
    );
}

// ---------------------------------------------------------------------------
// A1c — sending a capability the caller received (does not own the parent)
//        must ALWAYS emit Unmap  [expected to PASS with current code]
// ---------------------------------------------------------------------------

/// dom0 carves r1 from r0 and sends it to dom1 (dom1 does not own r0).
/// When dom1 then sends r1 to dom3, dom1 must lose hardware access.
/// This exercises the branch where parent_owned_by_caller = false.
///
/// Expected to PASS already — included as a regression guard.
#[test]
fn a1c_send_received_capability_always_emits_unmap() {
    let platform = common::TestPlatform::new();
    let (root, r0_h) = setup_root();

    // dom0 carves r1 [0x1000, 0x2000) RWX.
    let r1_access = Access::new(0x1000, 0x1000, Rights::RWX);
    let (r1_h, _r1_sub, _) = Capability::carve(&platform, &root, r0_h, r1_access).unwrap();

    // Create dom1 (unsealed) and send r1 to it.
    let (_dom1, dom1_h) = make_unsealed_child(&root);
    let dom1 = root.read().data.domain_capabilities[&dom1_h]
        .upgrade()
        .unwrap();
    let dom1_id = dom1.read().data.id;

    Capability::send(&platform, &root, r1_h, dom1_h, Attributes::NONE).unwrap();

    // Seal dom1 so it can SEND.
    Capability::seal(&platform, &root, dom1_h).unwrap();

    // dom1 now holds r1 at handle 1 (first cap in a fresh domain).
    let r1_h_in_dom1: LocalHandle = 1;

    // Create dom3 (unsealed) in dom1's table.
    let dom3_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let dom3_h_in_dom1 = Capability::create(&platform, &dom1, dom3_policy).unwrap().0;
    let dom3 = dom1.read().data.domain_capabilities[&dom3_h_in_dom1]
        .upgrade()
        .unwrap();
    let dom3_id = dom3.read().data.id;

    // dom1 sends r1 to dom3.  dom1 does NOT own r0 (the parent of r1).
    let send_updates =
        Capability::send(&platform, &dom1, r1_h_in_dom1, dom3_h_in_dom1, Attributes::NONE).unwrap();

    // Unmap must be emitted for dom1.
    let has_unmap = send_updates.updates().iter().any(|u| {
        matches!(u, Update::ChangeRights { domain, address, size, rights, .. }
            if *domain == dom1_id && *address == 0x1000 && *size == 0x1000 && *rights == Rights::NONE)
    });
    assert!(
        has_unmap,
        "sending a received cap must emit Unmap for the sender (got: {:?})",
        send_updates.updates()
    );

    // Map must be emitted for dom3.
    let has_map = send_updates
        .updates()
        .iter()
        .any(|u| matches!(u, Update::ChangeRights { domain, shootdown_required: false, .. } if *domain == dom3_id));
    assert!(has_map, "send must emit Map for the receiver");
}
