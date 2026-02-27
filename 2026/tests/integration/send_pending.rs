//! Tests for send / accept / reject semantics and pending capability lifecycle.
//!
//! Each test verifies one entry from the spec table in `fix_interface.md`:
//!
//! | # | Name                              | What it covers                                        |
//! |---|-----------------------------------|-------------------------------------------------------|
//! | 1 | send_then_accept                  | Happy path: handle removed from sender, new handle    |
//! |   |                                   | auto-allocated for receiver, UpdateBatch has unmap+map|
//! | 2 | send_then_reject                  | Rejection: same LocalHandle unfrozen in sender,       |
//! |   |                                   | no MMU operations, receiver pending queue cleared     |
//! | 3 | frozen_handle_refuses_ops         | While a handle is frozen, carve / alias / send on     |
//! |   |                                   | that handle all return PermissionDenied               |
//! | 4 | revoke_parent_cancels_pending     | Parent revokes the cap while it is in pending;        |
//! |   |                                   | receiver's accept returns NotFound (weak ref dead)    |
//! | 5 | revoke_sender_domain_cancels      | Sender domain is revoked while cap is in pending;     |
//! |   |                                   | receiver's accept returns PermissionDenied            |
//! | 6 | reject_then_reuse_handle          | After reject the same handle is fully operational     |
//! | 7 | accept_gives_independent_handles  | Two successive accepts into the same receiver table   |
//! |   |                                   | receive distinct, auto-allocated LocalHandles         |

use capability_engine::*;
use std::sync::Arc;
use parking_lot::RwLock;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Create a sealed domain with MonitorAPI::ALL (includes SEND and RECEIVE_AFTER_SEAL).
fn make_sealed_domain() -> CapabilityRef<Domain> {
    let policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let mut domain = Domain::new(policy);
    domain.seal().unwrap();
    Arc::new(RwLock::new(Capability {
        owned: Ownership::new(0),
        sub_handle: 0,
        data: domain,
        parent: std::sync::Weak::new(),
        children: Vec::new(),
    }))
}

/// Create a root memory capability covering [0x0, 0x10000) owned by `domain`,
/// register it at `handle` in the domain's handle table, and return the ref.
fn register_root_mem(domain: &CapabilityRef<Domain>, handle: LocalHandle) -> CapabilityRef<MemoryRegion> {
    let owner_id = domain.read().data.id;
    let cap = Capability::new_root(owner_id, handle, MemoryRegion::new_root(0x0, 0x10000));
    cap.write().owned.owner_domain = Some(Arc::downgrade(domain));
    domain.write().data.add_memory_capability(handle, Arc::downgrade(&cap));
    cap
}

// ── Test 1 — send_then_accept ─────────────────────────────────────────────────

/// What it does: A sends cap (handle 1) to B; B accepts.
/// Expected outcome: A's handle 1 is removed; B receives a new auto-allocated
/// LocalHandle; UpdateBatch contains an Unmap for A and a Map for B.
#[test]
fn send_then_accept() {
    let sender   = make_sealed_domain();
    let receiver = make_sealed_domain();
    let _mem = register_root_mem(&sender, 1);

    let sender_id   = sender.read().data.id;
    let receiver_id = receiver.read().data.id;

    // Send: freezes handle 1 in sender, enqueues pending in receiver.
    sender.write().data.add_domain_capability(1, Arc::downgrade(&receiver));
    Capability::<Domain>::send_memory(&sender, 1, 1, Attributes::NONE).unwrap();

    assert!(sender.read().data.is_memory_handle_frozen(1), "handle must be frozen after send");
    let pending_ids = receiver.read().data.get_pending_ids();
    assert_eq!(pending_ids.len(), 1);
    let pending_id = pending_ids[0];

    // Accept: fires MMU operations, transfers ownership.
    let (new_handle, updates) = Capability::<Domain>::accept_memory(&receiver, pending_id).unwrap();

    // Sender no longer has handle 1 in any form.
    assert!(sender.read().data.get_memory_capability(1).is_none(), "handle must be gone from sender");
    assert!(!sender.read().data.is_memory_handle_frozen(1), "frozen flag must be cleared");

    // Receiver has the capability under the new handle.
    assert!(receiver.read().data.get_memory_capability(new_handle).is_some());

    // Cap ownership updated.
    assert_eq!(_mem.read().owned.owner, receiver_id);

    // UpdateBatch must contain Unmap for sender and Map for receiver.
    let has_unmap = updates.updates().iter().any(|u| {
        matches!(u, Update::Unmap { domain, .. } if *domain == sender_id)
    });
    let has_map = updates.updates().iter().any(|u| {
        matches!(u, Update::Map { domain, .. } if *domain == receiver_id)
    });
    assert!(has_unmap, "UpdateBatch must contain Unmap for sender");
    assert!(has_map,   "UpdateBatch must contain Map for receiver");
}

// ── Test 2 — send_then_reject ─────────────────────────────────────────────────

/// What it does: A sends cap (handle 1) to B; B rejects.
/// Expected outcome: A's handle 1 is unfrozen with the same numeric value; no
/// MMU operations; receiver's pending queue is empty.
#[test]
fn send_then_reject() {
    let sender   = make_sealed_domain();
    let receiver = make_sealed_domain();
    let _mem = register_root_mem(&sender, 1);

    let sender_id = sender.read().data.id;

    sender.write().data.add_domain_capability(1, Arc::downgrade(&receiver));
    Capability::<Domain>::send_memory(&sender, 1, 1, Attributes::NONE).unwrap();

    let pending_id = receiver.read().data.get_pending_ids()[0];

    // Reject: unfreezes handle 1 in sender, removes pending entry.
    Capability::<Domain>::reject_memory(&receiver, pending_id).unwrap();

    // Handle 1 is back — accessible and not frozen.
    assert!(sender.read().data.get_memory_capability(1).is_some(), "handle must still be in sender's table");
    assert!(!sender.read().data.is_memory_handle_frozen(1), "handle must not be frozen after reject");

    // Pending queue is empty.
    assert!(receiver.read().data.get_pending_ids().is_empty());

    // Ownership unchanged.
    assert_eq!(_mem.read().owned.owner, sender_id);
}

// ── Test 3 — frozen_handle_refuses_ops ───────────────────────────────────────

/// What it does: A sends cap (handle 1) — handle 1 is now frozen.
/// A then attempts carve / alias / send on handle 1.
/// Expected outcome: all three return PermissionDenied; handle stays frozen.
#[test]
fn frozen_handle_refuses_ops() {
    let sender    = make_sealed_domain();
    let receiver1 = make_sealed_domain();
    let receiver2 = make_sealed_domain();
    let _cap = register_root_mem(&sender, 1);

    sender.write().data.add_domain_capability(1, Arc::downgrade(&receiver1));
    sender.write().data.add_domain_capability(2, Arc::downgrade(&receiver2));
    Capability::<Domain>::send_memory(&sender, 1, 1, Attributes::NONE).unwrap();
    assert!(sender.read().data.is_memory_handle_frozen(1));

    // carve on frozen handle → PermissionDenied
    let r = Capability::<Domain>::carve_memory(&sender, 1, Access::new(0x0, 0x1000, Rights::RW));
    assert!(matches!(r, Err(CapaError::PermissionDenied)), "carve on frozen handle must fail");

    // alias on frozen handle → PermissionDenied
    let r = Capability::<Domain>::alias_memory(&sender, 1, Access::new(0x0, 0x1000, Rights::RW));
    assert!(matches!(r, Err(CapaError::PermissionDenied)), "alias on frozen handle must fail");

    // send again (double-send) → PermissionDenied
    let r = Capability::<Domain>::send_memory(&sender, 1, 2, Attributes::NONE);
    assert!(matches!(r, Err(CapaError::PermissionDenied)), "second send on frozen handle must fail");

    // Exactly one pending entry in receiver1 — no duplicates.
    assert_eq!(receiver1.read().data.get_pending_ids().len(), 1);
    assert_eq!(receiver2.read().data.get_pending_ids().len(), 0);
}

// ── Test 4 — revoke_parent_cancels_pending ────────────────────────────────────

/// What it does: A carves a child from a root cap, sends the child to B
/// (pending), then A revokes the child via revoke_memory_child using its
/// stable SubHandle.
/// Expected outcome: the cap's Arc strong count drops to zero; B's
/// accept_memory returns NotFound because the pending weak ref is dead.
#[test]
fn revoke_parent_cancels_pending() {
    let sender   = make_sealed_domain();
    let receiver = make_sealed_domain();

    // Root cap at handle 1 in sender's table.
    let _root = register_root_mem(&sender, 1);

    // Carve a child [0x1000, 0x2000) — auto-allocates handle 2, sub_handle = 2.
    let (child_handle, _) = Capability::<Domain>::carve_memory(
        &sender,
        1,
        Access::new(0x1000, 0x1000, Rights::RW),
    ).unwrap();
    assert_eq!(child_handle, 2);

    // Send the child to receiver — freezes handle 2.
    sender.write().data.add_domain_capability(1, Arc::downgrade(&receiver));
    Capability::<Domain>::send_memory(&sender, child_handle, 1, Attributes::NONE).unwrap();

    let pending_id = receiver.read().data.get_pending_ids()[0];

    // Revoke the child using its SubHandle (= child_handle at creation time = 2).
    // The parent is at handle 1; child_sub = 2.
    Capability::<Domain>::revoke_memory_child(&sender, 1, child_handle).unwrap();

    // Now the cap's Arc strong count is 0 — the pending weak ref is dead.
    // accept_memory must return NotFound.
    let result = Capability::<Domain>::accept_memory(&receiver, pending_id);
    assert!(
        matches!(result, Err(CapaError::NotFound)),
        "accept after parent revoke must return NotFound, got: {:?}", result
    );
}

// ── Test 5 — revoke_sender_domain_cancels_pending ────────────────────────────

/// What it does: A (a child domain of parent P) sends a memory cap to B
/// (pending). P then revokes A's domain. B tries to accept.
/// Expected outcome: accept returns PermissionDenied because the sender domain
/// is now in Revoked status.
#[test]
fn revoke_sender_domain_cancels_pending() {
    // Parent domain P.
    let parent   = make_sealed_domain();
    let receiver = make_sealed_domain();

    // Create sender domain A as a child of P in the domain CDT.
    let policy    = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let parent_id = parent.read().data.id;
    let child_sub = 1u64; // sub_handle we assign to A in P's children
    let sender = Capability::create_child_domain(&parent, policy, parent_id, child_sub).unwrap();
    sender.write().data.seal().unwrap();

    // Register a memory cap in A's table at handle 1.
    let _mem = register_root_mem(&sender, 1);

    // A sends the memory cap to B.
    sender.write().data.add_domain_capability(1, Arc::downgrade(&receiver));
    Capability::<Domain>::send_memory(&sender, 1, 1, Attributes::NONE).unwrap();

    let pending_id = receiver.read().data.get_pending_ids()[0];

    // P revokes A's domain.
    Capability::revoke_child_domain(&parent, child_sub).unwrap();

    assert!(sender.read().data.is_revoked(), "sender domain must be revoked");

    // B tries to accept — must fail because sender is revoked.
    let result = Capability::<Domain>::accept_memory(&receiver, pending_id);
    assert!(
        matches!(result, Err(CapaError::PermissionDenied)),
        "accept after sender domain revoke must return PermissionDenied, got: {:?}", result
    );

    // Pending entry was cleaned up.
    assert!(receiver.read().data.get_pending_ids().is_empty());
}

// ── Test 6 — reject_then_reuse_handle ────────────────────────────────────────

/// What it does: A sends cap (handle 1) to B; B rejects; A then successfully
/// sends or carves using the same handle.
/// Expected outcome: handle 1 is fully operational after unfreeze.
#[test]
fn reject_then_reuse_handle() {
    let sender    = make_sealed_domain();
    let receiver1 = make_sealed_domain();
    let receiver2 = make_sealed_domain();
    let _cap = register_root_mem(&sender, 1);

    // First send, then reject.
    sender.write().data.add_domain_capability(1, Arc::downgrade(&receiver1));
    sender.write().data.add_domain_capability(2, Arc::downgrade(&receiver2));
    Capability::<Domain>::send_memory(&sender, 1, 1, Attributes::NONE).unwrap();
    let pending_id = receiver1.read().data.get_pending_ids()[0];
    Capability::<Domain>::reject_memory(&receiver1, pending_id).unwrap();

    // Handle 1 is unfrozen — second send must succeed.
    Capability::<Domain>::send_memory(&sender, 1, 2, Attributes::NONE)
        .expect("send after reject must succeed");

    // receiver2 has a pending entry; receiver1 has none.
    assert_eq!(receiver2.read().data.get_pending_ids().len(), 1);
    assert_eq!(receiver1.read().data.get_pending_ids().len(), 0);
}

// ── Test 7 — accept_gives_independent_handles ────────────────────────────────

/// What it does: A sends two different caps to the same receiver B; B accepts
/// both.
/// Expected outcome: B's two auto-allocated handles are distinct (no collision),
/// each pointing to the correct capability.
#[test]
fn accept_gives_independent_handles() {
    let sender   = make_sealed_domain();
    let receiver = make_sealed_domain();

    // Two root caps at handles 1 and 2 in sender's table (non-overlapping regions).
    let sender_id = sender.read().data.id;
    let cap1 = Capability::new_root(sender_id, 1, MemoryRegion::new_root(0x0000, 0x8000));
    cap1.write().owned.owner_domain = Some(Arc::downgrade(&sender));
    sender.write().data.add_memory_capability(1, Arc::downgrade(&cap1));

    let cap2 = Capability::new_root(sender_id, 2, MemoryRegion::new_root(0x8000, 0x8000));
    cap2.write().owned.owner_domain = Some(Arc::downgrade(&sender));
    sender.write().data.add_memory_capability(2, Arc::downgrade(&cap2));

    // Send both to the same receiver.
    sender.write().data.add_domain_capability(1, Arc::downgrade(&receiver));
    Capability::<Domain>::send_memory(&sender, 1, 1, Attributes::NONE).unwrap();
    Capability::<Domain>::send_memory(&sender, 2, 1, Attributes::NONE).unwrap();

    let pending_ids = receiver.read().data.get_pending_ids();
    assert_eq!(pending_ids.len(), 2);

    // Accept both.
    let (h1, _) = Capability::<Domain>::accept_memory(&receiver, pending_ids[0]).unwrap();
    let (h2, _) = Capability::<Domain>::accept_memory(&receiver, pending_ids[1]).unwrap();

    // Handles must be distinct.
    assert_ne!(h1, h2, "accepted handles must be distinct");

    // Both present in receiver's table.
    assert!(receiver.read().data.get_memory_capability(h1).is_some());
    assert!(receiver.read().data.get_memory_capability(h2).is_some());
}
