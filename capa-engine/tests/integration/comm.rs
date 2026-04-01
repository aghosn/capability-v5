//! Integration tests for COMM region semantics.
//!
//! A COMM region is a parent-owned communication buffer bound to a child
//! domain's VP.  Its properties:
//!
//! | Property                        | Behaviour                                               |
//! |--------------------------------|---------------------------------------------------------|
//! | Registration                   | Parent-mediated: `register_comm(handle, child_h, vp)`  |
//! | Prerequisite                   | Must be a `RegionKind::Carve` with `Exclusive` status  |
//! | Attributes set at registration | `COMM | CLEAN` (NOT VITAL)                             |
//! | Carved / aliased / sent        | Rejected once COMM attribute is set                    |
//! | Multiple per domain            | Allowed; one per (child, vp) binding                   |
//! | Revocation of cap              | Emits `UncommRegion`; does NOT kill the owning domain  |
//! | Memory on revocation           | Zeroed (`ZeroMemory`) because CLEAN is implied         |
//! | Child revocation               | Auto-releases bindings, clears COMM on parent caps     |

use capability_engine::memory::Rights;
use capability_engine::*;
use parking_lot::RwLock;
use std::sync::Arc;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_domain() -> CapabilityRef<Domain> {
    let policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let mut domain = Domain::new(policy);
    domain.seal().unwrap();
    Arc::new(RwLock::new(Capability {
        owned: Ownership::new(0),
        sub_handle: 0,
        depth: 0,
        next_child_sub: 1,
        data: domain,
        channel_target: None,
        parent: std::sync::Weak::new(),
        children: Vec::new(),
    }))
}

fn make_unsealed_domain() -> CapabilityRef<Domain> {
    let policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let domain = Domain::new(policy);
    Arc::new(RwLock::new(Capability {
        owned: Ownership::new(0),
        sub_handle: 0,
        depth: 0,
        next_child_sub: 1,
        data: domain,
        channel_target: None,
        parent: std::sync::Weak::new(),
        children: Vec::new(),
    }))
}

/// Register a root memory region owned by `domain` at local handle `handle`.
fn register_root_mem(
    domain: &CapabilityRef<Domain>,
    handle: LocalHandle,
) -> CapabilityRef<MemoryRegion> {
    let owner_id = domain.read().data.id;
    let cap = Capability::new_root(owner_id, handle, MemoryRegion::new_root(0x0, 0x10000));
    cap.write().owned.owner_domain = Some(Arc::downgrade(domain));
    domain
        .write()
        .data
        .add_memory_capability(handle, Arc::downgrade(&cap));
    cap
}

/// Create a parent domain with root memory and a child domain properly
/// registered via `Capability::create` (so the capability tree is intact).
/// Returns (parent, child, child_domain_handle, root_mem_arc).
/// The root_mem_arc must be kept alive for memory Weak refs to remain valid.
fn setup_parent_child() -> (CapabilityRef<Domain>, CapabilityRef<Domain>, LocalHandle, CapabilityRef<MemoryRegion>) {
    let parent = make_domain();
    let root = register_root_mem(&parent, 1);

    let (child_dh, _) =
        Capability::create(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL))
            .unwrap();
    let child = parent
        .read()
        .data
        .get_domain_capability(child_dh)
        .unwrap()
        .upgrade()
        .unwrap();
    (parent, child, child_dh, root)
}

// ── 1. Basic registration ─────────────────────────────────────────────────────

/// Registering a carved exclusive region succeeds, sets COMM|CLEAN (not VITAL),
/// emits exactly one CommRegion update with the correct fields.
#[test]
fn test_comm_register_basic() {
    let (parent, child, child_dh, _root) = setup_parent_child();
    let parent_id = parent.read().data.id;
    let child_id = child.read().data.id;

    let (carved_h, _, _) =
        Capability::<Domain>::carve(&parent, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();

    let batch =
        Capability::<Domain>::register_comm(&parent, carved_h, child_dh, 0).unwrap();

    // Exactly one CommRegion, no UncommRegion.
    let comm_updates: Vec<_> = batch
        .updates()
        .iter()
        .filter(|u| matches!(u, Update::CommRegion { .. }))
        .collect();
    let uncomm_updates: Vec<_> = batch
        .updates()
        .iter()
        .filter(|u| matches!(u, Update::UncommRegion { .. }))
        .collect();
    assert_eq!(comm_updates.len(), 1, "must emit exactly one CommRegion");
    assert_eq!(uncomm_updates.len(), 0, "must not emit UncommRegion on registration");

    match comm_updates[0] {
        Update::CommRegion { domain_id, target_domain_id, vp_id, phys, size } => {
            assert_eq!(*domain_id, parent_id);
            assert_eq!(*target_domain_id, child_id);
            assert_eq!(*vp_id, 0);
            assert_eq!(*phys, 0x0);
            assert_eq!(*size, 0x1000);
        }
        _ => unreachable!(),
    }

    // COMM|CLEAN must be set; VITAL must NOT be set.
    let cap_ref = parent
        .read()
        .data
        .get_memory_capability(carved_h)
        .unwrap()
        .upgrade()
        .unwrap();
    let attrs = cap_ref.read().owned.attributes;
    assert!(attrs.comm(),   "COMM must be set");
    assert!(attrs.clean(),  "CLEAN must be set (implied by COMM)");
    assert!(!attrs.vital(), "VITAL must NOT be set (COMM no longer implies VITAL)");

    // comm_binding must record the child domain + VP.
    let binding = cap_ref.read().data.comm_binding;
    assert!(binding.is_some(), "comm_binding must be populated");
    let b = binding.unwrap();
    assert_eq!(b.target_domain_id, child_id);
    assert_eq!(b.vp_id, 0);

    // Child's comm_bindings vec must contain a weak ref to this cap.
    let child_bindings = &child.read().data.comm_bindings;
    assert_eq!(child_bindings.len(), 1, "child must have 1 comm_binding");
    assert!(
        Arc::ptr_eq(&child_bindings[0].upgrade().unwrap(), &cap_ref),
        "child comm_binding must point to the registered cap"
    );
}

// ── 2. COMM cap cannot be carved ─────────────────────────────────────────────

#[test]
fn test_comm_cannot_be_carved() {
    let (parent, _child, child_dh, _root) = setup_parent_child();
    let (comm_h, _, _) =
        Capability::<Domain>::carve(&parent, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();
    Capability::<Domain>::register_comm(&parent, comm_h, child_dh, 0).unwrap();

    let result =
        Capability::<Domain>::carve(&parent, comm_h, Access::new(0x0, 0x100, Rights::R));
    assert_eq!(
        result.unwrap_err(),
        CapaError::PermissionDenied,
        "carve must be rejected on a COMM region"
    );
}

// ── 3. COMM cap cannot be aliased ─────────────────────────────────────────────

#[test]
fn test_comm_cannot_be_aliased() {
    let (parent, _child, child_dh, _root) = setup_parent_child();
    let (comm_h, _, _) =
        Capability::<Domain>::carve(&parent, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();
    Capability::<Domain>::register_comm(&parent, comm_h, child_dh, 0).unwrap();

    let result =
        Capability::<Domain>::alias(&parent, comm_h, Access::new(0x0, 0x100, Rights::R));
    assert_eq!(
        result.unwrap_err(),
        CapaError::PermissionDenied,
        "alias must be rejected on a COMM region"
    );
}

// ── 4. COMM cap cannot be sent ────────────────────────────────────────────────

#[test]
fn test_comm_cannot_be_sent() {
    let (parent, _child, child_dh, _root) = setup_parent_child();
    let receiver = make_domain();
    let (comm_h, _, _) =
        Capability::<Domain>::carve(&parent, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();
    Capability::<Domain>::register_comm(&parent, comm_h, child_dh, 0).unwrap();

    parent
        .write()
        .data
        .add_domain_capability(10, Arc::downgrade(&receiver));

    let result =
        Capability::<Domain>::send(&parent, comm_h, 10, Attributes::NONE);
    assert_eq!(
        result.unwrap_err(),
        CapaError::PermissionDenied,
        "send must be rejected on a COMM region"
    );
}

// ── 5. COMM requires a Carve (alias kind rejected) ───────────────────────────

#[test]
fn test_comm_requires_carve_kind() {
    let (parent, _child, child_dh, _root) = setup_parent_child();

    let (alias_h, _) =
        Capability::<Domain>::alias(&parent, 1, Access::new(0x0, 0x1000, Rights::R)).unwrap();

    let result = Capability::<Domain>::register_comm(&parent, alias_h, child_dh, 0);
    assert_eq!(
        result.unwrap_err(),
        CapaError::PermissionDenied,
        "register_comm must reject a cap with RegionKind::Alias"
    );
}

// ── 6. COMM requires Exclusive status ────────────────────────────────────────

#[test]
fn test_comm_requires_exclusive_status() {
    let (parent, _child, child_dh, _root) = setup_parent_child();

    let (alias_h, _) =
        Capability::<Domain>::alias(&parent, 1, Access::new(0x0, 0x4000, Rights::R)).unwrap();
    let (carved_from_alias_h, _, _) =
        Capability::<Domain>::carve(&parent, alias_h, Access::new(0x0, 0x1000, Rights::R)).unwrap();

    let result = Capability::<Domain>::register_comm(&parent, carved_from_alias_h, child_dh, 0);
    assert_eq!(
        result.unwrap_err(),
        CapaError::PermissionDenied,
        "register_comm must reject a cap with RegionStatus::Aliased"
    );
}

// ── 7. Re-registering the same handle is rejected ────────────────────────────

/// Once register_comm succeeds, calling it again on the same handle fails
/// because the cap already carries the COMM attribute.
#[test]
fn test_comm_same_handle_re_register_rejected() {
    let (parent, _child, child_dh, _root) = setup_parent_child();
    let (comm_h, _, _) =
        Capability::<Domain>::carve(&parent, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();
    Capability::<Domain>::register_comm(&parent, comm_h, child_dh, 0).unwrap();

    let result = Capability::<Domain>::register_comm(&parent, comm_h, child_dh, 0);
    assert!(
        matches!(result.unwrap_err(), CapaError::InvalidOperation(_)),
        "re-registering the same handle must return InvalidOperation"
    );
}

// ── 8. Multiple COMM pages allowed (no one-shot) ─────────────────────────────

/// Multiple COMM pages can be registered for the same child domain (one per VP,
/// or separate pages for messages vs event flags).
#[test]
fn test_comm_multiple_pages_allowed() {
    let (parent, child, child_dh, _root) = setup_parent_child();
    let child_id = child.read().data.id;

    let (h1, _, _) =
        Capability::<Domain>::carve(&parent, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();
    let (h2, _, _) =
        Capability::<Domain>::carve(&parent, 1, Access::new(0x2000, 0x1000, Rights::RW)).unwrap();

    // First COMM page for VP 0.
    Capability::<Domain>::register_comm(&parent, h1, child_dh, 0).unwrap();
    // Second COMM page for VP 1.
    let batch = Capability::<Domain>::register_comm(&parent, h2, child_dh, 1).unwrap();

    // Both caps should have COMM set.
    let c1 = parent.read().data.get_memory_capability(h1).unwrap().upgrade().unwrap();
    let c2 = parent.read().data.get_memory_capability(h2).unwrap().upgrade().unwrap();
    assert!(c1.read().owned.attributes.comm());
    assert!(c2.read().owned.attributes.comm());

    // Second CommRegion update should carry VP 1.
    match &batch.updates()[0] {
        Update::CommRegion { target_domain_id, vp_id, .. } => {
            assert_eq!(*target_domain_id, child_id);
            assert_eq!(*vp_id, 1);
        }
        _ => panic!("expected CommRegion"),
    }

    // Child should have 2 comm_bindings.
    assert_eq!(child.read().data.comm_bindings.len(), 2);
}

// ── 9. Invalid VP ID rejected ────────────────────────────────────────────────

#[test]
fn test_comm_invalid_vp_id_rejected() {
    let (parent, _child, child_dh, _root) = setup_parent_child();
    let (h, _, _) =
        Capability::<Domain>::carve(&parent, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();

    // Child has num_vprocessors = popcount(0b1111) = 4, so VP 99 is invalid.
    let result = Capability::<Domain>::register_comm(&parent, h, child_dh, 99);
    assert!(
        matches!(result.unwrap_err(), CapaError::InvalidOperation(_)),
        "VP index beyond child's VP count must be rejected"
    );
}

// ── 10. Revoking the COMM cap emits UncommRegion ─────────────────────────────

#[test]
fn test_comm_revocation_emits_uncomm_region() {
    let (parent, _child, child_dh, _root) = setup_parent_child();
    let parent_id = parent.read().data.id;

    let (carved_h, carved_sub, _) =
        Capability::<Domain>::carve(&parent, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();
    Capability::<Domain>::register_comm(&parent, carved_h, child_dh, 0).unwrap();

    let batch = Capability::<Domain>::revoke(&parent, 1, carved_sub).unwrap();

    let has_uncomm = batch.updates().iter().any(|u| {
        matches!(u, Update::UncommRegion { domain_id, phys, size, .. }
            if *domain_id == parent_id && *phys == 0x0 && *size == 0x1000)
    });
    assert!(has_uncomm, "revoking a COMM cap must emit UncommRegion");
}

// ── 11. Revoking COMM does NOT trigger domain revocation ─────────────────────

/// COMM no longer implies VITAL, so revoking a COMM cap must NOT produce
/// a RevokeDomain update for the owning domain.
#[test]
fn test_comm_revocation_does_not_trigger_domain_revoke() {
    let (parent, _child, child_dh, _root) = setup_parent_child();
    let parent_id = parent.read().data.id;

    let (carved_h, carved_sub, _) =
        Capability::<Domain>::carve(&parent, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();
    Capability::<Domain>::register_comm(&parent, carved_h, child_dh, 0).unwrap();

    let batch = Capability::<Domain>::revoke(&parent, 1, carved_sub).unwrap();

    let has_revoke = batch.updates().iter().any(|u| {
        matches!(u, Update::RevokeDomain { domain, .. } if *domain == parent_id)
    });
    assert!(!has_revoke, "revoking a COMM cap must NOT generate RevokeDomain (no VITAL)");
}

// ── 12. Revoking COMM zeroes the region (CLEAN) ───────────────────────────────

#[test]
fn test_comm_revocation_zeroes_memory() {
    let (parent, _child, child_dh, _root) = setup_parent_child();

    let (carved_h, carved_sub, _) =
        Capability::<Domain>::carve(&parent, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();
    Capability::<Domain>::register_comm(&parent, carved_h, child_dh, 0).unwrap();

    let batch = Capability::<Domain>::revoke(&parent, 1, carved_sub).unwrap();

    let has_zero = batch.updates().iter().any(|u| {
        matches!(u, Update::ZeroMemory { address, size } if *address == 0x0 && *size == 0x1000)
    });
    assert!(has_zero, "revoking a COMM cap must emit ZeroMemory (CLEAN)");
}

// ── 13. Caller must be sealed (validate_operation) ──────────────────────────

/// register_comm on an unsealed domain must fail with DomainNotSealed,
/// because validate_operation(SET) requires the caller to be sealed.
#[test]
fn test_comm_requires_caller_sealed() {
    let parent = make_unsealed_domain();
    let root = register_root_mem(&parent, 1);
    // Create child manually (unsealed parent can't go through Capability::create
    // which itself requires sealing, so we seal, create, then test with an
    // unsealed grandparent-like setup).  Instead, use a sealed parent that
    // creates a child, then test register_comm from an unsealed caller.
    //
    // Simpler approach: use make_domain for parent, create child, then unseal
    // can't work (seal is one-way).  So: test that an unsealed domain that
    // owns a carved cap and a child domain handle gets DomainNotSealed.
    //
    // The trick: create everything while sealed, then create a *second*
    // unsealed domain that holds the same handles.
    drop(root);
    let sealed_parent = make_domain();
    let _root2 = register_root_mem(&sealed_parent, 1);
    let (child_dh, _) =
        Capability::create(&sealed_parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL))
            .unwrap();
    let (carved_h, _, _) =
        Capability::<Domain>::carve(&sealed_parent, 1, Access::new(0x0, 0x1000, Rights::RW))
            .unwrap();

    // Create an unsealed domain and give it the same cap + child handles
    let unsealed = make_unsealed_domain();
    {
        let cap_weak = sealed_parent.read().data.get_memory_capability(carved_h).unwrap().clone();
        let child_weak = sealed_parent.read().data.get_domain_capability(child_dh).unwrap().clone();
        let cap_arc = cap_weak.upgrade().unwrap();
        let child_arc = child_weak.upgrade().unwrap();
        // Transfer ownership
        cap_arc.write().owned.owner = unsealed.read().data.id;
        cap_arc.write().owned.owner_domain = Some(Arc::downgrade(&unsealed));
        unsealed.write().data.add_memory_capability(carved_h, Arc::downgrade(&cap_arc));
        unsealed.write().data.add_domain_capability(child_dh, Arc::downgrade(&child_arc));
    }

    let result = Capability::<Domain>::register_comm(&unsealed, carved_h, child_dh, 0);
    assert_eq!(
        result.unwrap_err(),
        CapaError::DomainNotSealed,
        "register_comm from unsealed domain must fail with DomainNotSealed"
    );
}

// ── 14. Caller must have SET API ─────────────────────────────────────────────

/// register_comm must fail with ApiNotAllowed when caller lacks SET permission.
#[test]
fn test_comm_requires_set_api() {
    // ALL minus SET
    let api_no_set = MonitorAPI::from_bits(MonitorAPI::ALL.bits() & !MonitorAPI::SET);
    let policy = DomainPolicy::new_restricted(0b1111, api_no_set);
    let mut domain = Domain::new(policy);
    domain.seal().unwrap();
    let parent = Arc::new(RwLock::new(Capability {
        owned: Ownership::new(0),
        sub_handle: 0,
        depth: 0,
        next_child_sub: 1,
        data: domain,
        channel_target: None,
        parent: std::sync::Weak::new(),
        children: Vec::new(),
    }));
    let _root = register_root_mem(&parent, 1);

    // Create child — child API must be a subset of parent's (monotonicity).
    let (child_dh, _) =
        Capability::create(&parent, DomainPolicy::new_restricted(0b1111, api_no_set))
            .unwrap();
    let (carved_h, _, _) =
        Capability::<Domain>::carve(&parent, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();

    let result = Capability::<Domain>::register_comm(&parent, carved_h, child_dh, 0);
    assert_eq!(
        result.unwrap_err(),
        CapaError::ApiNotAllowed,
        "register_comm without SET API must fail with ApiNotAllowed"
    );
}

// ── 15. META cap cannot be registered as COMM ────────────────────────────────

/// A capability with the META attribute must be rejected by register_comm.
#[test]
fn test_comm_rejects_meta_cap() {
    let (parent, _child, child_dh, _root) = setup_parent_child();

    let (carved_h, _, _) =
        Capability::<Domain>::carve(&parent, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();

    // Manually set META attribute on the carved cap.
    {
        let cap_ref = parent.read().data.get_memory_capability(carved_h).unwrap().upgrade().unwrap();
        cap_ref.write().owned.attributes = Attributes::from_bits(Attributes::META).canonicalize();
    }

    let result = Capability::<Domain>::register_comm(&parent, carved_h, child_dh, 0);
    assert!(
        matches!(result.unwrap_err(), CapaError::InvalidOperation(_)),
        "register_comm must reject a cap with META attribute"
    );
}

// ── 16. Cap with children cannot be registered as COMM ───────────────────────

/// A capability that has been carved from (has children) must be rejected,
/// even if it somehow retains Exclusive status.
#[test]
fn test_comm_rejects_cap_with_children() {
    let (parent, _child, child_dh, _root) = setup_parent_child();

    let (carved_h, _, _) =
        Capability::<Domain>::carve(&parent, 1, Access::new(0x0, 0x2000, Rights::RW)).unwrap();
    // Carve a sub-region — this makes the parent cap non-Exclusive AND adds a child.
    let _ = Capability::<Domain>::carve(&parent, carved_h, Access::new(0x0, 0x1000, Rights::RW));

    // The carved cap now has children (and is no longer Exclusive).
    // register_comm should reject it (either via Exclusive or children check).
    let result = Capability::<Domain>::register_comm(&parent, carved_h, child_dh, 0);
    assert_eq!(
        result.unwrap_err(),
        CapaError::PermissionDenied,
        "register_comm must reject a cap that has children"
    );
}

// ── 17. Duplicate COMM binding for same VP rejected ──────────────────────────

/// Binding two different COMM pages to the same VP must be rejected.
#[test]
fn test_comm_duplicate_vp_binding_rejected() {
    let (parent, _child, child_dh, _root) = setup_parent_child();

    let (h1, _, _) =
        Capability::<Domain>::carve(&parent, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();
    let (h2, _, _) =
        Capability::<Domain>::carve(&parent, 1, Access::new(0x2000, 0x1000, Rights::RW)).unwrap();

    // First COMM binding to VP 0 succeeds.
    Capability::<Domain>::register_comm(&parent, h1, child_dh, 0).unwrap();

    // Second COMM binding to the same VP 0 must fail.
    let result = Capability::<Domain>::register_comm(&parent, h2, child_dh, 0);
    assert!(
        matches!(result.unwrap_err(), CapaError::InvalidOperation(_)),
        "binding a second COMM page to the same VP must return InvalidOperation"
    );
}

// ── 18. Child revocation auto-releases COMM bindings ─────────────────────────

/// When a child domain is revoked, all parent-owned COMM pages bound to it
/// must have their COMM attribute and comm_binding cleared, and UncommRegion
/// updates emitted.
#[test]
fn test_comm_child_revocation_releases_bindings() {
    let (parent, child, child_dh, _root) = setup_parent_child();
    let parent_id = parent.read().data.id;
    let child_id = child.read().data.id;

    // Register two COMM pages bound to child.
    let (h1, _, _) =
        Capability::<Domain>::carve(&parent, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();
    let (h2, _, _) =
        Capability::<Domain>::carve(&parent, 1, Access::new(0x2000, 0x1000, Rights::RW)).unwrap();
    Capability::<Domain>::register_comm(&parent, h1, child_dh, 0).unwrap();
    Capability::<Domain>::register_comm(&parent, h2, child_dh, 1).unwrap();

    // Verify COMM is set on both.
    let c1 = parent.read().data.get_memory_capability(h1).unwrap().upgrade().unwrap();
    let c2 = parent.read().data.get_memory_capability(h2).unwrap().upgrade().unwrap();
    assert!(c1.read().owned.attributes.comm());
    assert!(c2.read().owned.attributes.comm());

    // Revoke child domain via its domain handle.
    let batch = Capability::<Domain>::revoke_domain(&parent, child_dh).unwrap();

    // COMM must be cleared on both parent caps.
    assert!(!c1.read().owned.attributes.comm(), "COMM must be cleared on c1 after child revoke");
    assert!(!c2.read().owned.attributes.comm(), "COMM must be cleared on c2 after child revoke");

    // comm_binding must be None.
    assert!(c1.read().data.comm_binding.is_none());
    assert!(c2.read().data.comm_binding.is_none());

    // Batch must contain UncommRegion for both.
    let uncomm_count = batch.updates().iter().filter(|u| {
        matches!(u, Update::UncommRegion { domain_id, target_domain_id, .. }
            if *domain_id == parent_id && *target_domain_id == child_id)
    }).count();
    assert_eq!(uncomm_count, 2, "must emit UncommRegion for each released COMM binding");
}
