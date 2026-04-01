//! Integration tests for META memory region semantics.
//!
//! META regions are metadata allocations for the monitor.  They have the
//! following properties:
//!
//! | Property                       | Behaviour                                        |
//! |-------------------------------|--------------------------------------------------|
//! | Address space / view           | Excluded — receiver gets no MMU mapping          |
//! | Attestation                    | Included — appears like a normal region entry    |
//! | Send prerequisite              | Source region must be `RegionStatus::Exclusive`  |
//! | Re-send / carve / alias        | Rejected once META attribute is set              |
//! | Revocation                     | Triggers `RevokeDomain` for the owner (like VITAL)|
//! | Sealed receiver                | Goes through the normal pending / accept flow    |

use capability_engine::memory::Rights;
use capability_engine::*;
use parking_lot::RwLock;
use std::sync::Arc;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_sealed_domain() -> CapabilityRef<Domain> {
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

// ── 1. META region excluded from receiver address space ───────────────────────

/// Sending with META transfers the cap to the receiver but emits no mapping
/// for the receiver, and correctly unmaps from the sender.
#[test]
fn test_meta_excluded_from_address_space() {
    let sender = make_sealed_domain();
    let receiver = make_unsealed_domain();

    let sender_id = sender.read().data.id;
    let receiver_id = receiver.read().data.id;

    let _mem = register_root_mem(&sender, 1);
    sender
        .write()
        .data
        .add_domain_capability(2, Arc::downgrade(&receiver));

    let updates =
        Capability::<Domain>::send(&sender, 1, 2, Attributes::from_bits(Attributes::META))
            .unwrap();

    // Sender must have lost the region.
    assert!(sender.read().data.get_memory_capability(1).is_none());

    // Receiver holds the cap in its table.
    let recv_caps = receiver.read().data.memory_capabilities.len();
    assert_eq!(recv_caps, 1);

    // Receiver address space is EMPTY — META is excluded.
    let recv_view = compute_address_space(&receiver);
    assert!(
        recv_view.regions.is_empty(),
        "META region must not appear in the receiver's address space"
    );

    // An Unmap update must have been emitted for the sender (they gave it up).
    let has_sender_unmap = updates.updates().iter().any(|op| match op {
        Update::ChangeRights { domain, .. } => *domain == sender_id,
        _ => false,
    });
    assert!(has_sender_unmap, "sender must lose the region via ChangeRights");

    // No Map / ChangeRights update for the receiver.
    let has_receiver_map = updates.updates().iter().any(|op| match op {
        Update::ChangeRights { domain, .. } => *domain == receiver_id,
        _ => false,
    });
    assert!(
        !has_receiver_map,
        "receiver must NOT receive a ChangeRights update for a META region"
    );
}

// ── 2. META region appears in attestation ────────────────────────────────────

/// The META region must be visible in the receiver's attestation report.
#[test]
fn test_meta_appears_in_attestation() {
    let sender = make_sealed_domain();
    let receiver = make_unsealed_domain();

    let _mem = register_root_mem(&sender, 1);
    sender
        .write()
        .data
        .add_domain_capability(2, Arc::downgrade(&receiver));

    Capability::<Domain>::send(&sender, 1, 2, Attributes::from_bits(Attributes::META))
        .unwrap();

    let report = attest_domain(&receiver).report;
    assert!(
        report.contains("META"),
        "META attribute must appear in the receiver's attestation report"
    );
}

// ── 3. Only exclusive regions may be sent as META ────────────────────────────

/// An aliased (non-exclusive) region must be rejected when sent with META.
#[test]
fn test_meta_send_requires_exclusive() {
    let sender = make_sealed_domain();
    let receiver = make_unsealed_domain();

    let _sender_id = sender.read().data.id;

    // Create a root cap and alias from it — the alias is Aliased (non-exclusive).
    let _root = register_root_mem(&sender, 1);
    let (alias_h, _) = Capability::<Domain>::alias(
        &sender,
        1,
        Access::new(0x0, 0x1000, Rights::RWX),
    )
    .unwrap();

    sender
        .write()
        .data
        .add_domain_capability(10, Arc::downgrade(&receiver));

    let result = Capability::<Domain>::send(
        &sender,
        alias_h,
        10,
        Attributes::from_bits(Attributes::META),
    );
    assert_eq!(
        result.unwrap_err(),
        CapaError::PermissionDenied,
        "aliased (non-exclusive) region must be rejected for META send"
    );
}

// ── 4. META region cannot be re-sent ─────────────────────────────────────────

/// Once a cap carries the META attribute the owning domain may not send it again.
#[test]
fn test_meta_cannot_be_re_sent() {
    let sender = make_sealed_domain();
    let middle = make_unsealed_domain();
    let receiver = make_unsealed_domain();

    let _mem = register_root_mem(&sender, 1);
    sender
        .write()
        .data
        .add_domain_capability(2, Arc::downgrade(&middle));
    Capability::<Domain>::send(&sender, 1, 2, Attributes::from_bits(Attributes::META))
        .unwrap();

    // middle now holds the META cap; add receiver to middle's domain table.
    middle
        .write()
        .data
        .add_domain_capability(3, Arc::downgrade(&receiver));
    let meta_handle = *middle.read().data.memory_capabilities.keys().next().unwrap();

    let result = Capability::<Domain>::send(
        &middle,
        meta_handle,
        3,
        Attributes::NONE,
    );
    assert_eq!(
        result.unwrap_err(),
        CapaError::PermissionDenied,
        "META region must not be re-sent by the receiver"
    );
}

// ── 5. META region cannot be carved ──────────────────────────────────────────

#[test]
fn test_meta_cannot_be_carved() {
    let sender = make_sealed_domain();
    let receiver = make_unsealed_domain();

    let _mem = register_root_mem(&sender, 1);
    sender
        .write()
        .data
        .add_domain_capability(2, Arc::downgrade(&receiver));
    Capability::<Domain>::send(&sender, 1, 2, Attributes::from_bits(Attributes::META))
        .unwrap();

    let meta_handle = *receiver.read().data.memory_capabilities.keys().next().unwrap();
    let result = Capability::<Domain>::carve(
        &receiver,
        meta_handle,
        Access::new(0x0, 0x100, Rights::R),
    );
    assert_eq!(
        result.unwrap_err(),
        CapaError::PermissionDenied,
        "carve must be rejected on a META region"
    );
}

// ── 6. META region cannot be aliased ─────────────────────────────────────────

#[test]
fn test_meta_cannot_be_aliased() {
    let sender = make_sealed_domain();
    let receiver = make_unsealed_domain();

    let _mem = register_root_mem(&sender, 1);
    sender
        .write()
        .data
        .add_domain_capability(2, Arc::downgrade(&receiver));
    Capability::<Domain>::send(&sender, 1, 2, Attributes::from_bits(Attributes::META))
        .unwrap();

    let meta_handle = *receiver.read().data.memory_capabilities.keys().next().unwrap();
    let result = Capability::<Domain>::alias(
        &receiver,
        meta_handle,
        Access::new(0x0, 0x100, Rights::R),
    );
    assert_eq!(
        result.unwrap_err(),
        CapaError::PermissionDenied,
        "alias must be rejected on a META region"
    );
}

// ── 7. Revoking a META region triggers domain revocation ─────────────────────

/// Revoking a META cap must generate a `RevokeDomain` update for its owner,
/// just like VITAL.
#[test]
fn test_meta_revocation_triggers_domain_revoke() {
    let root = make_sealed_domain();
    let child = make_unsealed_domain();

    let child_id = child.read().data.id;

    // Give root a root memory region.
    let _mem = register_root_mem(&root, 1);

    // Carve a sub-region so we have a child cap to revoke.
    let (carved_h, carved_sub, _) = Capability::<Domain>::carve(
        &root,
        1,
        Access::new(0x0, 0x1000, Rights::RWX),
    )
    .unwrap();

    // Send the carved region to child with META attribute.
    root.write()
        .data
        .add_domain_capability(5, Arc::downgrade(&child));
    Capability::<Domain>::send(
        &root,
        carved_h,
        5,
        Attributes::from_bits(Attributes::META),
    )
    .unwrap();

    // Revoke the META cap from root (by sub_handle, since it was sent away).
    let updates = Capability::<Domain>::revoke(&root, 1, carved_sub).unwrap();

    let has_revoke = updates.updates().iter().any(|op| {
        matches!(op, Update::RevokeDomain { domain, .. } if *domain == child_id)
    });
    assert!(
        has_revoke,
        "revoking META capability must generate RevokeDomain for the owner domain"
    );

    // META revocation must zero the region (implicit CLEAN).
    let has_zero = updates.updates().iter().any(|op| {
        matches!(op, Update::ZeroMemory { address, size } if *address == 0x0 && *size == 0x1000)
    });
    assert!(has_zero, "revoking META must emit a ZeroMemory update for the region");

    // No spurious unmap for the receiver — META was never mapped there.
    let has_child_unmap = updates.updates().iter().any(|op| match op {
        Update::ChangeRights { domain, rights, .. } => {
            *domain == child_id && *rights == Rights::NONE
        }
        _ => false,
    });
    assert!(
        !has_child_unmap,
        "revoking META must not emit an unmap for the receiver (region was never mapped)"
    );
}

// ── 7b. META send rejects regions with children ─────────────────────────────

/// An exclusive region that still has children (carved sub-regions) must be
/// rejected when sent with META — the children would remain in the tree with
/// inconsistent semantics (parent excluded from EPT but children still mapped).
#[test]
fn test_meta_send_rejects_region_with_children() {
    let sender = make_sealed_domain();
    let receiver = make_unsealed_domain();

    let _mem = register_root_mem(&sender, 1);

    // Carve a child from the root region — parent is still Exclusive but now
    // has a non-empty children list.
    let (_carved_h, _carved_sub, _) = Capability::<Domain>::carve(
        &sender,
        1,
        Access::new(0x0, 0x1000, Rights::RWX),
    )
    .unwrap();

    sender
        .write()
        .data
        .add_domain_capability(10, Arc::downgrade(&receiver));

    let result = Capability::<Domain>::send(
        &sender,
        1,
        10,
        Attributes::from_bits(Attributes::META),
    );
    assert_eq!(
        result.unwrap_err(),
        CapaError::PermissionDenied,
        "exclusive region with children must be rejected for META send"
    );
}

// ── 8. META with sealed receiver: pending / accept flow ───────────────────────

/// Sending META to a sealed domain follows the normal freeze/pending/accept
/// flow.  After accept the receiver's address space remains empty.
#[test]
fn test_meta_sealed_send_and_accept_no_mmu_update() {
    let sender = make_sealed_domain();
    let receiver = make_sealed_domain();

    let _sender_id = sender.read().data.id;
    let receiver_id = receiver.read().data.id;

    let _mem = register_root_mem(&sender, 1);
    sender
        .write()
        .data
        .add_domain_capability(2, Arc::downgrade(&receiver));

    // Sealed send — enqueues pending, freezes handle.
    Capability::<Domain>::send(&sender, 1, 2, Attributes::from_bits(Attributes::META))
        .unwrap();

    assert!(sender.read().data.is_memory_handle_frozen(1));
    let pending_ids = receiver.read().data.get_pending_ids();
    assert_eq!(pending_ids.len(), 1, "META must enter the pending queue for a sealed receiver");

    // Accept — completes the transfer.
    let (new_handle, updates) =
        Capability::<Domain>::accept(&receiver, pending_ids[0]).unwrap();

    // Receiver holds the cap.
    assert!(receiver.read().data.get_memory_capability(new_handle).is_some());

    // Receiver address space must remain empty.
    let recv_view = compute_address_space(&receiver);
    assert!(
        recv_view.regions.is_empty(),
        "META region must not appear in the receiver's address space after accept"
    );

    // No ChangeRights issued to receiver.
    let has_receiver_update = updates.updates().iter().any(|op| match op {
        Update::ChangeRights { domain, .. } => *domain == receiver_id,
        _ => false,
    });
    assert!(
        !has_receiver_update,
        "accept of META must not generate a ChangeRights update for the receiver"
    );
}
