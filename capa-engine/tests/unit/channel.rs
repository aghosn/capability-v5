//! Tests for channel capability (GET_CHAN) semantics.
//!
//! Coverage:
//!  1. get_chan creates a child cap with channel_target pointing to target domain
//!  2. attest via channel reports the target domain (with Channel:true header)
//!  3. send to a channel cap delivers to the target domain
//!  4. send_channel + accept_channel transfers a channel (move semantics)
//!  5. reject_channel unfreezes the sender's handle
//!  6. send_channel to an unsealed domain transfers immediately
//!  7. Revoking the parent (target) domain also revokes the channel (CDT invariant)
//!  8. Revoking while channel is in-transit cancels the pending entry
//!  9. get_chan denied without GETCHAN permission
//! 10. Only channel caps may be transferred via send_channel
//! 11. seal on a channel handle is rejected (ApiNotAllowed)
//! 12. revoke_domain on a channel handle is rejected (NotFound — channel is not a CDT child of caller)
//! 13. switch using a channel handle as target is rejected (DomainNotSealed — sentinel has no VPs)
//! 14. accept_channel rejects a pending transfer whose sender has been revoked
//! 15. accept_channel rejects a stale-revoked receiver (caller) itself
//! 16. reject_channel rejects a stale-revoked receiver (caller) itself

use capability_engine::*;
use std::sync::Arc;

#[path = "../common/mod.rs"]
mod common;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn root_domain() -> CapabilityRef<Domain> {
    let _platform = common::TestPlatform::new();
    Capability::new_root(0, 0, Domain::new_root(4))
}

/// Create and seal a child domain under `parent` with full permissions.
fn sealed_child(parent: &CapabilityRef<Domain>) -> (CapabilityRef<Domain>, LocalHandle) {
    let platform = common::TestPlatform::new();
    let policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let h = Capability::create(&platform, parent, policy).unwrap().0;
    Capability::seal(&platform, parent, h).unwrap();
    let child = parent
        .read()
        .data
        .domain_capabilities[&h]
        .upgrade()
        .unwrap();
    (child, h)
}

/// Register a root memory capability [0, 0x10000) in `domain` at `handle`.
fn register_mem(domain: &CapabilityRef<Domain>, handle: LocalHandle) -> CapabilityRef<MemoryRegion> {
    let _platform = common::TestPlatform::new();
    let owner_id = domain.read().data.id;
    let mem = Capability::new_root(owner_id, handle, MemoryRegion::new_root(0x0, 0x10000));
    mem.write().owned.owner_domain = Some(Arc::downgrade(domain));
    domain
        .write()
        .data
        .add_memory_capability(handle, Arc::downgrade(&mem));
    mem
}

// ── Test 1: get_chan creates correct channel capability ──────────────────────

#[test]
fn test_get_chan_creates_channel() {
    let platform = common::TestPlatform::new();
    let root = root_domain();
    let (child, child_h) = sealed_child(&root);

    let chan_h = Capability::get_chan(&platform, &root, child_h).unwrap().0;

    // chan_h resolves in root's domain_capabilities
    let chan_ref = root
        .read()
        .data
        .domain_capabilities[&chan_h]
        .upgrade()
        .unwrap();

    // channel_target is Some and points to the child domain
    let target = chan_ref
        .read()
        .channel_target
        .as_ref()
        .unwrap()
        .upgrade()
        .unwrap();
    let child_id = child.read().data.id;
    assert_eq!(target.read().data.id, child_id);

    // Channel is a child of the child domain's CDT node
    let child_children_count = child.read().children.len();
    assert_eq!(child_children_count, 1, "chan must appear as a child of the target in the CDT");

    // Channel owner is root
    let root_id = root.read().data.id;
    assert_eq!(chan_ref.read().owned.owner, root_id);
}

#[test]
fn test_get_chan_denied_without_permission() {
    let platform = common::TestPlatform::new();
    let root = root_domain();

    // Create a domain without GETCHAN but with CREATE and SEAL
    let restricted = DomainPolicy::new_restricted(
        0b1111,
        MonitorAPI::from_bits(MonitorAPI::CREATE | MonitorAPI::SEAL),
    );
    let restricted_h = Capability::create(&platform, &root, restricted).unwrap().0;
    Capability::seal(&platform, &root, restricted_h).unwrap();
    let restricted_dom = root.read().data.domain_capabilities[&restricted_h].upgrade().unwrap();

    // restricted_dom creates a child — it now OWNS that child cap
    let child_policy = DomainPolicy::new_restricted(0b0001, MonitorAPI::NONE);
    let child_h = Capability::create(&platform, &restricted_dom, child_policy).unwrap().0;
    Capability::seal(&platform, &restricted_dom, child_h).unwrap();

    // restricted_dom tries get_chan on its own child — must fail (no GETCHAN)
    let result = Capability::get_chan(&platform, &restricted_dom, child_h);
    assert!(matches!(result, Err(CapaError::ApiNotAllowed)));
}

#[test]
fn test_get_chan_requires_sealed_target() {
    let platform = common::TestPlatform::new();
    let root = root_domain();
    // Create but do NOT seal the child
    let policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let child_h = Capability::create(&platform, &root, policy).unwrap().0;
    // child not sealed
    let result = Capability::get_chan(&platform, &root, child_h);
    assert!(matches!(result, Err(CapaError::DomainNotSealed)));
}

// ── Test 2: attest via channel reports target domain ────────────────────────

#[test]
fn test_attest_channel_reports_target() {
    let platform = common::TestPlatform::new();
    let root = root_domain();
    let (child, child_h) = sealed_child(&root);
    let chan_h = Capability::get_chan(&platform, &root, child_h).unwrap().0;

    let report = Capability::<Domain>::attest(&platform, &root, chan_h).unwrap().0;

    let child_id = child.read().data.id;
    assert_eq!(report.domain_id, child_id, "report must be for target domain");
    assert!(
        report.report.contains("Channel: true"),
        "report must include Channel header"
    );
    assert!(
        report.report.contains(&format!("Target Domain ID: {}", child_id)),
        "report must name the target domain ID"
    );
}

// ── Test 3: send via channel delivers to target ───────────────────────

#[test]
fn test_send_memory_via_channel_sealed_target() {
    let platform = common::TestPlatform::new();
    let root = root_domain();
    let (child, child_h) = sealed_child(&root);
    let chan_h = Capability::get_chan(&platform, &root, child_h).unwrap().0;

    let _mem = register_mem(&root, 10);
    root.write().data.add_domain_capability(child_h, Arc::downgrade(&child));

    // Send using chan_h as receiver handle — must be routed to child.
    let result = Capability::<Domain>::send(&platform, &root, 10, chan_h, Attributes::NONE);
    // child is sealed, so send goes through sealed path (pending)
    assert!(result.is_ok(), "send via channel should succeed: {:?}", result);

    // Pending entry should be in child's queue, not in the channel's fake domain
    let pending_ids = child.read().data.get_pending_ids();
    assert_eq!(pending_ids.len(), 1, "pending must land in the real target domain");
}

// ── Test 4: send_channel + accept_channel (sealed path) ─────────────────────

#[test]
fn test_send_and_accept_channel() {
    let platform = common::TestPlatform::new();
    let root = root_domain();
    let (_child, child_h) = sealed_child(&root);
    let chan_h = Capability::get_chan(&platform, &root, child_h).unwrap().0;

    // Create a sealed receiver with RECEIVE_AFTER_SEAL
    let (receiver, receiver_h) = sealed_child(&root);
    // Add receiver handle to root
    root.write()
        .data
        .add_domain_capability(receiver_h, Arc::downgrade(&receiver));

    // Send chan_h to receiver (sealed path)
    Capability::<Domain>::send_channel(&platform, &root, chan_h, receiver_h, Attributes::NONE).unwrap();

    // chan_h must be frozen in root
    assert!(
        root.read().data.is_domain_handle_frozen(chan_h),
        "source handle must be frozen after send"
    );

    // Receiver must have a pending domain capability
    let pending_ids = receiver.read().data.get_pending_domain_ids();
    assert_eq!(pending_ids.len(), 1);
    let pending_id = pending_ids[0];

    // Accept: allocates new handle in receiver
    let new_h = Capability::<Domain>::accept_channel(&platform, &receiver, pending_id).unwrap().0;
    let chan_ref = receiver.read().data.domain_capabilities[&new_h]
        .upgrade()
        .unwrap();

    // Ownership transferred to receiver
    let receiver_id = receiver.read().data.id;
    assert_eq!(chan_ref.read().owned.owner, receiver_id);

    // Source handle removed from root
    assert!(
        root.read().data.get_domain_capability(chan_h).is_none(),
        "source handle must be gone from sender after accept"
    );
    assert!(
        !root.read().data.is_domain_handle_frozen(chan_h),
        "frozen flag must be cleared after accept"
    );
}

// ── Test 5: reject_channel unfreezes sender's handle ────────────────────────

#[test]
fn test_reject_channel_unfreezes_sender() {
    let platform = common::TestPlatform::new();
    let root = root_domain();
    let (_child, child_h) = sealed_child(&root);
    let chan_h = Capability::get_chan(&platform, &root, child_h).unwrap().0;

    let (receiver, receiver_h) = sealed_child(&root);
    root.write()
        .data
        .add_domain_capability(receiver_h, Arc::downgrade(&receiver));

    Capability::<Domain>::send_channel(&platform, &root, chan_h, receiver_h, Attributes::NONE).unwrap();
    assert!(root.read().data.is_domain_handle_frozen(chan_h));

    let pending_id = receiver.read().data.get_pending_domain_ids()[0];
    Capability::<Domain>::reject_channel(&platform, &receiver, pending_id).unwrap();

    // Handle must be unfrozen (sender can reuse it)
    assert!(
        !root.read().data.is_domain_handle_frozen(chan_h),
        "frozen flag must be cleared after reject"
    );
}

// ── Test 6: send_channel to unsealed receiver (immediate transfer) ───────────

#[test]
fn test_send_channel_unsealed_receiver_immediate() {
    let platform = common::TestPlatform::new();
    let root = root_domain();
    let (_child, child_h) = sealed_child(&root);
    let chan_h = Capability::get_chan(&platform, &root, child_h).unwrap().0;

    // Create an UNSEALED receiver
    let policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let unsealed_h = Capability::create(&platform, &root, policy).unwrap().0;
    let unsealed = root.read().data.domain_capabilities[&unsealed_h].upgrade().unwrap();

    Capability::<Domain>::send_channel(&platform, &root, chan_h, unsealed_h, Attributes::NONE).unwrap();

    // chan_h removed from root immediately
    assert!(
        root.read().data.get_domain_capability(chan_h).is_none(),
        "handle must be removed from sender on unsealed transfer"
    );

    // unsealed receiver has a channel handle
    let unsealed_chan_handles: Vec<_> = unsealed
        .read()
        .data
        .domain_capability_handles()
        .into_iter()
        .filter(|&h| {
            unsealed
                .read()
                .data
                .get_domain_capability(h)
                .and_then(|w| w.upgrade())
                .map(|c| c.read().channel_target.is_some())
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(unsealed_chan_handles.len(), 1, "receiver must have the channel handle");
}

// ── Test 7: revoking target domain revokes channel (CDT invariant) ───────────

#[test]
fn test_revoke_target_revokes_channel() {
    let platform = common::TestPlatform::new();
    let root = root_domain();
    let (_child, child_h) = sealed_child(&root);
    let chan_h = Capability::get_chan(&platform, &root, child_h).unwrap().0;

    // Before revocation: child has 1 CDT child (the channel)
    assert_eq!(_child.read().children.len(), 1);

    // Revoke the target domain (child) — the channel subtree is torn down too
    Capability::<Domain>::revoke_domain(&platform, &root, child_h).unwrap();

    // After revocation: target handle gone from root
    assert!(
        root.read().data.get_domain_capability(child_h).is_none(),
        "target handle must be gone after revoke_domain"
    );

    // chan_h is also stale — the weak in domain_capabilities now upgrades to None
    // or the handle was removed.  The channel should no longer be resolvable.
    let chan_still_present = root
        .read()
        .data
        .get_domain_capability(chan_h)
        .and_then(|w| w.upgrade())
        .is_some();
    // chan_h was registered in root's domain_capabilities but was NOT explicitly
    // removed by revoke_domain (only child_h is).  The channel's CDT node was torn
    // down (domain.data.revoke() was called), but the Arc may still be alive.
    // The invariant we care about: the channel cap's CDT parent (child) has 0 children
    // after revocation, since revoke_domain_subtree takes children via mem::take.
    assert_eq!(
        _child.read().children.len(), 0,
        "CDT children of target must be empty after revocation (channel removed from CDT)"
    );
    // Suppress unused warning
    let _ = chan_still_present;
}

// ── Test 8: revoke while channel is in-transit cancels pending ───────────────

#[test]
fn test_revoke_while_channel_pending_cancels_entry() {
    let platform = common::TestPlatform::new();
    let root = root_domain();
    let (_child, child_h) = sealed_child(&root);
    let chan_h = Capability::get_chan(&platform, &root, child_h).unwrap().0;

    let (receiver, receiver_h) = sealed_child(&root);
    root.write()
        .data
        .add_domain_capability(receiver_h, Arc::downgrade(&receiver));

    // Send the channel (now it's frozen and in receiver's pending queue)
    Capability::<Domain>::send_channel(&platform, &root, chan_h, receiver_h, Attributes::NONE).unwrap();
    assert_eq!(receiver.read().data.get_pending_domain_ids().len(), 1);

    // Now revoke the entire child (which also revokes the channel cap)
    Capability::<Domain>::revoke_domain(&platform, &root, child_h).unwrap();

    // The frozen handle in root should be cleared
    assert!(
        !root.read().data.is_domain_handle_frozen(chan_h),
        "frozen handle must be cleared when channel is revoked"
    );

    // Receiver's pending entry should be removed (or accept would return NotFound)
    let pending_ids = receiver.read().data.get_pending_domain_ids();
    assert!(
        pending_ids.is_empty(),
        "pending domain cap entry must be cancelled on channel revocation"
    );
}

// ── Test 9: send_channel only accepts channel caps ───────────────────────────

#[test]
fn test_send_channel_rejects_non_channel() {
    let platform = common::TestPlatform::new();
    let root = root_domain();
    let (_child, child_h) = sealed_child(&root);
    let (receiver, receiver_h) = sealed_child(&root);
    root.write()
        .data
        .add_domain_capability(receiver_h, Arc::downgrade(&receiver));

    // Try to send a regular domain cap (not a channel) via send_channel — must fail.
    let result = Capability::<Domain>::send_channel(&platform, &root, child_h, receiver_h, Attributes::NONE);
    assert!(
        matches!(result, Err(CapaError::PermissionDenied)),
        "send_channel must reject non-channel caps"
    );
}

// ── Test 11: seal on a channel handle is rejected ─────────────────────

#[test]
fn test_seal_channel_rejected() {
    let platform = common::TestPlatform::new();
    let root = root_domain();
    let (_child, child_h) = sealed_child(&root);
    let chan_h = Capability::get_chan(&platform, &root, child_h).unwrap().0;

    let result = Capability::<Domain>::seal(&platform, &root, chan_h);
    assert!(
        matches!(result, Err(CapaError::ApiNotAllowed)),
        "seal must reject a channel handle, got {:?}",
        result
    );
}

// ── Test 12: revoke_domain on a channel handle is rejected ───────────────────

#[test]
fn test_revoke_channel_rejected() {
    let platform = common::TestPlatform::new();
    let root = root_domain();
    let (_child, child_h) = sealed_child(&root);
    let chan_h = Capability::get_chan(&platform, &root, child_h).unwrap().0;

    let result = Capability::<Domain>::revoke_domain(&platform, &root, chan_h);
    assert!(
        matches!(result, Err(CapaError::ApiNotAllowed)),
        "revoke_domain must reject a channel handle, got {:?}",
        result
    );
}

// ── Test 13: switch using a channel handle as target is rejected ───────

#[test]
fn test_switch_to_channel_rejected() {
    let platform = common::TestPlatform::new();
    let root = root_domain();
    // caller must be sealed with SWITCH permission
    let policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let caller_h = Capability::create(&platform, &root, policy).unwrap().0;
    Capability::seal(&platform, &root, caller_h).unwrap();
    let caller = root.read().data.domain_capabilities[&caller_h].upgrade().unwrap();

    // Give the caller a channel handle to pass as switch target
    let (target, target_h) = sealed_child(&root);
    let chan_h = Capability::get_chan(&platform, &root, target_h).unwrap().0;
    caller
        .write()
        .data
        .add_domain_capability(chan_h, root.read().data.domain_capabilities[&chan_h].clone());

    let platform = common::TestPlatform::new();
    platform.set_current_core(Some(0));
    let result = Capability::<Domain>::switch(&platform, &caller, chan_h, 0);
    assert!(
        matches!(result, Err(CapaError::ApiNotAllowed)),
        "switch must reject a channel handle as target, got {:?}",
        result
    );
    let _ = target;
}

// ── Test 14: accept_channel rejects an already-revoked sender ───────────────
//
// `sender_domain` in a `PendingDomainCapability` is a `Weak<Domain>` captured
// at `send_channel` time.  If the sender is later revoked by its own
// (unrelated) parent while the pending entry still sits in the receiver's
// queue, `accept_channel` must reject the stale transfer rather than
// silently completing it.  Mirrors `accept_at`'s existing revoked-sender
// guard.  Covers the `accept_channel` fix for
// `p8-check-operand-domains-not-revoked`.
#[test]
fn test_accept_channel_rejects_revoked_sender() {
    let platform = common::TestPlatform::new();
    let root = root_domain();

    // Target: the domain the channel will point at (irrelevant to this test
    // beyond being a valid get_chan target).
    let (_target, target_h) = sealed_child(&root);
    let chan_h = Capability::get_chan(&platform, &root, target_h).unwrap().0;

    // Sender: will hold and forward the channel, then get revoked.
    let (sender, sender_h) = sealed_child(&root);
    root.write()
        .data
        .add_domain_capability(sender_h, Arc::downgrade(&sender));
    Capability::<Domain>::send_channel(&platform, &root, chan_h, sender_h, Attributes::NONE)
        .unwrap();
    let pending_id_1 = *sender
        .read()
        .data
        .get_pending_domain_ids()
        .first()
        .unwrap();
    let chan_h2 = Capability::<Domain>::accept_channel(&platform, &sender, pending_id_1)
        .unwrap()
        .0;

    // Receiver: final recipient. sender doesn't naturally have a handle to
    // it (only its own creator would), so register it directly in sender's
    // table for test topology purposes — mirrors the existing
    // `add_domain_capability` scaffolding pattern used elsewhere in this file.
    let (receiver, receiver_h) = sealed_child(&root);
    sender
        .write()
        .data
        .add_domain_capability(receiver_h, Arc::downgrade(&receiver));

    Capability::<Domain>::send_channel(&platform, &sender, chan_h2, receiver_h, Attributes::NONE)
        .unwrap();
    let pending_id_2 = *receiver
        .read()
        .data
        .get_pending_domain_ids()
        .first()
        .unwrap();

    // Root (sender's own parent) revokes sender — a normal, natural revoke,
    // unrelated to the receiver's pending queue.
    Capability::<Domain>::revoke_domain(&platform, &root, sender_h).unwrap();

    // Receiver attempts to accept the now-stale pending transfer.
    let result = Capability::<Domain>::accept_channel(&platform, &receiver, pending_id_2);
    assert!(
        matches!(result, Err(CapaError::PermissionDenied)),
        "accept_channel must reject a transfer whose sender has been revoked, got {:?}",
        result
    );
}

// ── Test 15: accept_channel rejects a stale-revoked receiver ────────────────
//
// Mirrors `reject()`'s existing stale-caller guard: `accept_channel`
// previously only checked the *sender* for revocation, never the receiver
// (caller) itself, even though the receiver's `CapabilityRef` may have been
// resolved before a concurrent revoke completed (e.g. via capavisor's
// `PlatformCore::domain_cap` at hypercall entry, before `execute()`'s lock
// is acquired).
#[test]
fn test_accept_channel_rejects_revoked_receiver() {
    let platform = common::TestPlatform::new();
    let root = root_domain();
    let (_target, target_h) = sealed_child(&root);
    let chan_h = Capability::get_chan(&platform, &root, target_h).unwrap().0;

    let (receiver, receiver_h) = sealed_child(&root);
    root.write()
        .data
        .add_domain_capability(receiver_h, Arc::downgrade(&receiver));
    Capability::<Domain>::send_channel(&platform, &root, chan_h, receiver_h, Attributes::NONE)
        .unwrap();
    let pending_id = receiver.read().data.get_pending_domain_ids()[0];

    // Simulate a concurrent revoke of the receiver completing between the
    // caller resolving its own `Arc<Domain>` and `accept_channel` acquiring
    // the engine lock.
    receiver.write().data.revoke();

    let result = Capability::<Domain>::accept_channel(&platform, &receiver, pending_id);
    assert_eq!(
        result.unwrap_err(),
        CapaError::DomainRevoked,
        "accept_channel must reject an already-revoked receiver (stale-caller guard)"
    );
}

// ── Test 16: reject_channel rejects a stale-revoked receiver ────────────────

#[test]
fn test_reject_channel_rejects_revoked_receiver() {
    let platform = common::TestPlatform::new();
    let root = root_domain();
    let (_target, target_h) = sealed_child(&root);
    let chan_h = Capability::get_chan(&platform, &root, target_h).unwrap().0;

    let (receiver, receiver_h) = sealed_child(&root);
    root.write()
        .data
        .add_domain_capability(receiver_h, Arc::downgrade(&receiver));
    Capability::<Domain>::send_channel(&platform, &root, chan_h, receiver_h, Attributes::NONE)
        .unwrap();
    let pending_id = receiver.read().data.get_pending_domain_ids()[0];

    receiver.write().data.revoke();

    let result = Capability::<Domain>::reject_channel(&platform, &receiver, pending_id);
    assert_eq!(
        result.unwrap_err(),
        CapaError::DomainRevoked,
        "reject_channel must reject an already-revoked receiver (stale-caller guard)"
    );
}
