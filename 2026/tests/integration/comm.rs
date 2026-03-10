//! Integration tests for COMM region semantics.
//!
//! A COMM region is a per-domain communication buffer shared between the domain
//! and the monitor.  Its properties:
//!
//! | Property                        | Behaviour                                               |
//! |--------------------------------|---------------------------------------------------------|
//! | Registration                   | Domain-mediated: `register_comm(handle)`               |
//! | Prerequisite                   | Must be a `RegionKind::Carve` with `Exclusive` status  |
//! | Attributes set at registration | `COMM | CLEAN | VITAL`                                 |
//! | Carved / aliased / sent        | Rejected once COMM attribute is set                    |
//! | Replacement                    | Allowed; emits `UncommRegion` (old) + `CommRegion` (new)|
//! | Revocation                     | Emits `UncommRegion` before `RevokeDomain` (VITAL)     |
//! | Memory on revocation           | Zeroed (`ZeroMemory`) because CLEAN is implied         |

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

// ── 1. Basic registration ─────────────────────────────────────────────────────

/// Registering a carved exclusive region succeeds, sets COMM|CLEAN|VITAL, and
/// emits exactly one CommRegion update with the correct phys/size.
#[test]
fn test_comm_register_basic() {
    let dom = make_domain();
    let dom_id = dom.read().data.id;
    let _root = register_root_mem(&dom, 1);

    let (carved_h, _, _) =
        Capability::<Domain>::carve(&dom, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();

    let batch = Capability::<Domain>::register_comm(&dom, carved_h).unwrap();

    // Exactly one CommRegion, no UncommRegion (no previous COMM).
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
    assert_eq!(uncomm_updates.len(), 0, "must not emit UncommRegion on first registration");

    match comm_updates[0] {
        Update::CommRegion { domain_id, phys, size } => {
            assert_eq!(*domain_id, dom_id);
            assert_eq!(*phys, 0x0);
            assert_eq!(*size, 0x1000);
        }
        _ => unreachable!(),
    }

    // COMM|CLEAN|VITAL must be set on the cap.
    let cap_ref = dom
        .read()
        .data
        .get_memory_capability(carved_h)
        .unwrap()
        .upgrade()
        .unwrap();
    let attrs = cap_ref.read().owned.attributes;
    assert!(attrs.comm(),  "COMM must be set");
    assert!(attrs.clean(), "CLEAN must be set (implied by COMM)");
    assert!(attrs.vital(), "VITAL must be set (implied by COMM)");

    // domain.comm_cap must point to the registered cap.
    let stored = dom
        .read()
        .data
        .comm_cap
        .as_ref()
        .and_then(|w| w.upgrade());
    assert!(stored.is_some(), "domain.comm_cap must be populated");
    assert!(
        Arc::ptr_eq(&stored.unwrap(), &cap_ref),
        "domain.comm_cap must point to the registered cap"
    );
}

// ── 2. COMM cap cannot be carved ─────────────────────────────────────────────

#[test]
fn test_comm_cannot_be_carved() {
    let dom = make_domain();
    let _root = register_root_mem(&dom, 1);
    let (comm_h, _, _) =
        Capability::<Domain>::carve(&dom, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();
    Capability::<Domain>::register_comm(&dom, comm_h).unwrap();

    let result =
        Capability::<Domain>::carve(&dom, comm_h, Access::new(0x0, 0x100, Rights::R));
    assert_eq!(
        result.unwrap_err(),
        CapaError::PermissionDenied,
        "carve must be rejected on a COMM region"
    );
}

// ── 3. COMM cap cannot be aliased ─────────────────────────────────────────────

#[test]
fn test_comm_cannot_be_aliased() {
    let dom = make_domain();
    let _root = register_root_mem(&dom, 1);
    let (comm_h, _, _) =
        Capability::<Domain>::carve(&dom, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();
    Capability::<Domain>::register_comm(&dom, comm_h).unwrap();

    let result =
        Capability::<Domain>::alias(&dom, comm_h, Access::new(0x0, 0x100, Rights::R));
    assert_eq!(
        result.unwrap_err(),
        CapaError::PermissionDenied,
        "alias must be rejected on a COMM region"
    );
}

// ── 4. COMM cap cannot be sent ────────────────────────────────────────────────

#[test]
fn test_comm_cannot_be_sent() {
    let sender = make_domain();
    let receiver = make_domain();
    let _root = register_root_mem(&sender, 1);
    let (comm_h, _, _) =
        Capability::<Domain>::carve(&sender, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();
    Capability::<Domain>::register_comm(&sender, comm_h).unwrap();

    sender
        .write()
        .data
        .add_domain_capability(10, Arc::downgrade(&receiver));

    let result =
        Capability::<Domain>::send(&sender, comm_h, 10, Attributes::NONE);
    assert_eq!(
        result.unwrap_err(),
        CapaError::PermissionDenied,
        "send must be rejected on a COMM region"
    );
}

// ── 5. COMM requires a Carve (alias kind rejected) ───────────────────────────

/// An aliased cap (RegionKind::Alias) cannot be registered as COMM.
#[test]
fn test_comm_requires_carve_kind() {
    let dom = make_domain();
    let _root = register_root_mem(&dom, 1);

    // alias_h has kind == Alias.
    let (alias_h, _) =
        Capability::<Domain>::alias(&dom, 1, Access::new(0x0, 0x1000, Rights::R)).unwrap();

    let result = Capability::<Domain>::register_comm(&dom, alias_h);
    assert_eq!(
        result.unwrap_err(),
        CapaError::PermissionDenied,
        "register_comm must reject a cap with RegionKind::Alias"
    );
}

// ── 6. COMM requires Exclusive status ────────────────────────────────────────

/// A carve from an aliased parent inherits Aliased status and must be rejected.
#[test]
fn test_comm_requires_exclusive_status() {
    let dom = make_domain();
    let _root = register_root_mem(&dom, 1);

    // Alias from root → Aliased status.
    let (alias_h, _) =
        Capability::<Domain>::alias(&dom, 1, Access::new(0x0, 0x4000, Rights::R)).unwrap();
    // Carve from the aliased cap → inherits Aliased status.
    let (carved_from_alias_h, _, _) =
        Capability::<Domain>::carve(&dom, alias_h, Access::new(0x0, 0x1000, Rights::R)).unwrap();

    let result = Capability::<Domain>::register_comm(&dom, carved_from_alias_h);
    assert_eq!(
        result.unwrap_err(),
        CapaError::PermissionDenied,
        "register_comm must reject a cap with RegionStatus::Aliased"
    );
}

// ── 7. Re-registering the same handle is also rejected ───────────────────────

/// Once register_comm succeeds, calling it again on the same handle must also
/// be rejected (domain already has a COMM page).
#[test]
fn test_comm_same_handle_re_register_rejected() {
    let dom = make_domain();
    let _root = register_root_mem(&dom, 1);
    let (comm_h, _, _) =
        Capability::<Domain>::carve(&dom, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();
    Capability::<Domain>::register_comm(&dom, comm_h).unwrap();

    // Same handle again — domain already has a COMM page.
    let result = Capability::<Domain>::register_comm(&dom, comm_h);
    assert!(
        matches!(result.unwrap_err(), CapaError::InvalidOperation(_)),
        "re-registering the same handle must return InvalidOperation"
    );
}

// ── 8. Replacing COMM is rejected (one-shot semantics) ───────────────────────

/// register_comm is a one-shot operation.  Calling it again after a COMM page
/// is already registered must be rejected, regardless of which handle is used.
#[test]
fn test_comm_cannot_replace() {
    let dom = make_domain();
    let _root = register_root_mem(&dom, 1);

    let (first_h, _, _) =
        Capability::<Domain>::carve(&dom, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();
    Capability::<Domain>::register_comm(&dom, first_h).unwrap();

    // Carve a second page and try to replace — must fail.
    let (second_h, _, _) =
        Capability::<Domain>::carve(&dom, 1, Access::new(0x2000, 0x1000, Rights::RW)).unwrap();
    let result = Capability::<Domain>::register_comm(&dom, second_h);
    assert!(
        matches!(result.unwrap_err(), CapaError::InvalidOperation(_)),
        "replacing a COMM page must return InvalidOperation"
    );

    // First cap must still have COMM set — it was not disturbed.
    let first_cap = dom
        .read()
        .data
        .get_memory_capability(first_h)
        .unwrap()
        .upgrade()
        .unwrap();
    assert!(first_cap.read().owned.attributes.comm(), "original COMM cap must be unchanged");
}

// ── 9. Revoking the COMM cap emits UncommRegion ──────────────────────────────

/// The parent revoking the COMM capability must produce an UncommRegion update
/// so the monitor can unmap its access before the domain is torn down.
#[test]
fn test_comm_revocation_emits_uncomm_region() {
    let root = make_domain();
    let child = make_unsealed_domain();
    let child_id = child.read().data.id;

    let _root_mem = register_root_mem(&root, 1);
    // Carve a sub-region for the child's COMM page.
    let (carved_h, carved_sub, _) =
        Capability::<Domain>::carve(&root, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();

    // Send to child (unsealed send: immediate transfer).
    root.write()
        .data
        .add_domain_capability(5, Arc::downgrade(&child));
    Capability::<Domain>::send(&root, carved_h, 5, Attributes::NONE).unwrap();

    // Child registers the received cap as its COMM page.
    let child_comm_h = *child.read().data.memory_capabilities.keys().next().unwrap();
    Capability::<Domain>::register_comm(&child, child_comm_h).unwrap();

    // Root revokes the COMM cap by its SubHandle.
    let batch = Capability::<Domain>::revoke(&root, 1, carved_sub).unwrap();

    let has_uncomm = batch.updates().iter().any(|u| {
        matches!(u, Update::UncommRegion { domain_id, phys, size }
            if *domain_id == child_id && *phys == 0x0 && *size == 0x1000)
    });
    assert!(has_uncomm, "revoking a COMM cap must emit UncommRegion for the owner domain");
}

// ── 10. Revoking COMM triggers domain revocation (VITAL) ─────────────────────

#[test]
fn test_comm_revocation_triggers_domain_revoke() {
    let root = make_domain();
    let child = make_unsealed_domain();
    let child_id = child.read().data.id;

    let _root_mem = register_root_mem(&root, 1);
    let (carved_h, carved_sub, _) =
        Capability::<Domain>::carve(&root, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();

    root.write()
        .data
        .add_domain_capability(5, Arc::downgrade(&child));
    Capability::<Domain>::send(&root, carved_h, 5, Attributes::NONE).unwrap();

    let child_comm_h = *child.read().data.memory_capabilities.keys().next().unwrap();
    Capability::<Domain>::register_comm(&child, child_comm_h).unwrap();

    let batch = Capability::<Domain>::revoke(&root, 1, carved_sub).unwrap();

    let has_revoke = batch.updates().iter().any(|u| {
        matches!(u, Update::RevokeDomain { domain, .. } if *domain == child_id)
    });
    assert!(has_revoke, "revoking a COMM cap must generate RevokeDomain (VITAL)");
}

// ── 11. Revoking COMM zeroes the region (CLEAN) ───────────────────────────────

#[test]
fn test_comm_revocation_zeroes_memory() {
    let root = make_domain();
    let child = make_unsealed_domain();

    let _root_mem = register_root_mem(&root, 1);
    let (carved_h, carved_sub, _) =
        Capability::<Domain>::carve(&root, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();

    root.write()
        .data
        .add_domain_capability(5, Arc::downgrade(&child));
    Capability::<Domain>::send(&root, carved_h, 5, Attributes::NONE).unwrap();

    let child_comm_h = *child.read().data.memory_capabilities.keys().next().unwrap();
    Capability::<Domain>::register_comm(&child, child_comm_h).unwrap();

    let batch = Capability::<Domain>::revoke(&root, 1, carved_sub).unwrap();

    let has_zero = batch.updates().iter().any(|u| {
        matches!(u, Update::ZeroMemory { address, size } if *address == 0x0 && *size == 0x1000)
    });
    assert!(has_zero, "revoking a COMM cap must emit ZeroMemory (CLEAN)");
}

// ── 12. UncommRegion is ordered before RevokeDomain ─────────────────────────

/// The platform needs to unmap its COMM access before the domain is torn down.
#[test]
fn test_comm_uncomm_before_revoke_domain_in_batch() {
    let root = make_domain();
    let child = make_unsealed_domain();
    let child_id = child.read().data.id;

    let _root_mem = register_root_mem(&root, 1);
    let (carved_h, carved_sub, _) =
        Capability::<Domain>::carve(&root, 1, Access::new(0x0, 0x1000, Rights::RW)).unwrap();

    root.write()
        .data
        .add_domain_capability(5, Arc::downgrade(&child));
    Capability::<Domain>::send(&root, carved_h, 5, Attributes::NONE).unwrap();

    let child_comm_h = *child.read().data.memory_capabilities.keys().next().unwrap();
    Capability::<Domain>::register_comm(&child, child_comm_h).unwrap();

    let batch = Capability::<Domain>::revoke(&root, 1, carved_sub).unwrap();

    let updates = batch.updates();
    let uncomm_pos = updates.iter().position(|u| {
        matches!(u, Update::UncommRegion { domain_id, .. } if *domain_id == child_id)
    });
    let revoke_pos = updates.iter().position(|u| {
        matches!(u, Update::RevokeDomain { domain, .. } if *domain == child_id)
    });

    assert!(uncomm_pos.is_some(), "UncommRegion must be present");
    assert!(revoke_pos.is_some(), "RevokeDomain must be present");
    assert!(
        uncomm_pos.unwrap() < revoke_pos.unwrap(),
        "UncommRegion must appear before RevokeDomain in the batch"
    );
}
