//! Pending memory transfers, rejection, revocation and stale-caller guards.

use capability_engine::*;

#[path = "../common/mod.rs"]
mod common;

fn receiver(
    platform: &common::TestPlatform,
    parent: &CapabilityRef<Domain>,
) -> (CapabilityRef<Domain>, LocalHandle) {
    let handle = Capability::create(
        platform,
        parent,
        DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL),
    )
    .unwrap()
    .0;
    let child = parent.read().data.domain_capabilities[&handle]
        .upgrade()
        .unwrap();
    Capability::seal(platform, parent, handle).unwrap();
    (child, handle)
}

fn fixture() -> (
    common::TestPlatform,
    CapabilityRef<Domain>,
    CapabilityRef<MemoryRegion>,
    LocalHandle,
) {
    let platform = common::TestPlatform::new();
    let root = Capability::new_root(0, 0, Domain::new_root(4));
    let (memory, backing) = common::bootstrap_memory(&root, 0, 0x10000);
    (platform, root, backing, memory)
}

#[test]
fn send_then_accept() {
    let (platform, sender, memory, handle) = fixture();
    let (receiver, target) = receiver(&platform, &sender);
    Capability::send(&platform, &sender, handle, target, Attributes::NONE).unwrap();
    assert!(sender.read().data.is_memory_handle_frozen(handle));
    let pending = Capability::enumerate_pending(&platform, &receiver, 0)
        .unwrap()
        .unwrap();
    let (received, updates) = Capability::accept(&platform, &receiver, pending).unwrap();
    assert!(sender.read().data.get_memory_capability(handle).is_none());
    assert!(!sender.read().data.is_memory_handle_frozen(handle));
    let held = receiver
        .read()
        .data
        .get_memory_capability(received)
        .unwrap()
        .upgrade()
        .unwrap();
    assert!(std::sync::Arc::ptr_eq(&held, &memory));
    let sender_id = sender.read().data.id;
    let receiver_id = receiver.read().data.id;
    assert_eq!(memory.read().owned.owner, receiver_id);
    assert!(updates.updates().iter().any(|u| matches!(
        u, Update::ChangeRights { domain, rights, .. }
        if *domain == sender_id && *rights == Rights::NONE
    )));
    assert!(updates.updates().iter().any(|u| matches!(
        u, Update::ChangeRights { domain, shootdown_required: false, .. }
        if *domain == receiver_id
    )));
}

#[test]
fn send_then_reject() {
    let (platform, sender, memory, handle) = fixture();
    let (receiver, target) = receiver(&platform, &sender);
    Capability::send(&platform, &sender, handle, target, Attributes::NONE).unwrap();
    let pending = Capability::enumerate_pending(&platform, &receiver, 0)
        .unwrap()
        .unwrap();
    let updates = Capability::reject(&platform, &receiver, pending).unwrap();
    assert!(
        updates.updates().is_empty(),
        "rejection must not change mappings"
    );
    assert!(sender.read().data.get_memory_capability(handle).is_some());
    assert!(!sender.read().data.is_memory_handle_frozen(handle));
    assert!(receiver.read().data.get_pending_ids().is_empty());
    assert_eq!(memory.read().owned.owner, sender.read().data.id);
}

#[test]
fn frozen_handle_refuses_ops() {
    let (platform, sender, _memory, handle) = fixture();
    let (receiver1, target1) = receiver(&platform, &sender);
    let (receiver2, target2) = receiver(&platform, &sender);
    Capability::send(&platform, &sender, handle, target1, Attributes::NONE).unwrap();
    let access = Access::new(0, 0x1000, Rights::RW);
    assert_eq!(
        Capability::carve(&platform, &sender, handle, access).unwrap_err(),
        CapaError::PermissionDenied
    );
    assert_eq!(
        Capability::alias(&platform, &sender, handle, access).unwrap_err(),
        CapaError::PermissionDenied
    );
    assert_eq!(
        Capability::send(&platform, &sender, handle, target2, Attributes::NONE).unwrap_err(),
        CapaError::PermissionDenied
    );
    assert!(sender.read().data.is_memory_handle_frozen(handle));
    assert_eq!(receiver1.read().data.get_pending_ids().len(), 1);
    assert!(receiver2.read().data.get_pending_ids().is_empty());
}

#[test]
fn revoke_parent_cancels_pending() {
    let (platform, sender, _memory, handle) = fixture();
    let (receiver, target) = receiver(&platform, &sender);
    let (carved, sub, _) = Capability::carve(
        &platform,
        &sender,
        handle,
        Access::new(0x1000, 0x1000, Rights::RW),
    )
    .unwrap();
    Capability::send(&platform, &sender, carved, target, Attributes::NONE).unwrap();
    let pending = Capability::enumerate_pending(&platform, &receiver, 0)
        .unwrap()
        .unwrap();
    Capability::revoke(&platform, &sender, handle, sub).unwrap();
    assert_eq!(
        Capability::accept(&platform, &receiver, pending).unwrap_err(),
        CapaError::NotFound
    );
}

#[test]
fn revoke_sender_domain_cancels_pending() {
    let (platform, parent, _memory, memory) = fixture();
    let (recipient, target) = receiver(&platform, &parent);
    let sender_h = Capability::create(
        &platform,
        &parent,
        DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL),
    )
    .unwrap()
    .0;
    let sender = parent.read().data.domain_capabilities[&sender_h]
        .upgrade()
        .unwrap();
    let carved = Capability::carve(
        &platform,
        &parent,
        memory,
        Access::new(0, 0x1000, Rights::RW),
    )
    .unwrap()
    .0;
    Capability::send(&platform, &parent, carved, sender_h, Attributes::NONE).unwrap();
    let channel = Capability::get_chan(&platform, &parent, target).unwrap().0;
    Capability::send(&platform, &parent, channel, sender_h, Attributes::NONE).unwrap();
    let memory = *sender
        .read()
        .data
        .memory_capabilities
        .keys()
        .next()
        .unwrap();
    let channel = *sender
        .read()
        .data
        .domain_capabilities
        .keys()
        .next()
        .unwrap();
    Capability::seal(&platform, &parent, sender_h).unwrap();
    Capability::send(&platform, &sender, memory, channel, Attributes::NONE).unwrap();
    let pending = Capability::enumerate_pending(&platform, &recipient, 0)
        .unwrap()
        .unwrap();
    Capability::revoke_domain(&platform, &parent, sender_h).unwrap();
    assert!(sender.read().data.is_revoked());
    assert_eq!(
        Capability::accept(&platform, &recipient, pending).unwrap_err(),
        CapaError::NotFound
    );
    assert!(recipient.read().data.get_pending_ids().is_empty());
}

#[test]
fn reject_then_reuse_handle() {
    let (platform, sender, _memory, handle) = fixture();
    let (receiver1, target1) = receiver(&platform, &sender);
    let (receiver2, target2) = receiver(&platform, &sender);
    Capability::send(&platform, &sender, handle, target1, Attributes::NONE).unwrap();
    let pending = Capability::enumerate_pending(&platform, &receiver1, 0)
        .unwrap()
        .unwrap();
    Capability::reject(&platform, &receiver1, pending).unwrap();
    Capability::send(&platform, &sender, handle, target2, Attributes::NONE).unwrap();
    assert_eq!(receiver2.read().data.get_pending_ids().len(), 1);
    assert!(receiver1.read().data.get_pending_ids().is_empty());
}

#[test]
fn accept_gives_independent_handles() {
    let (platform, sender, _memory, handle) = fixture();
    let (receiver, target) = receiver(&platform, &sender);
    let mut caps = Vec::new();
    for start in [0, 0x8000] {
        let carved = Capability::carve(
            &platform,
            &sender,
            handle,
            Access::new(start, 0x8000, Rights::RW),
        )
        .unwrap()
        .0;
        caps.push(
            sender
                .read()
                .data
                .get_memory_capability(carved)
                .unwrap()
                .upgrade()
                .unwrap(),
        );
        Capability::send(&platform, &sender, carved, target, Attributes::NONE).unwrap();
    }
    let pending = receiver.read().data.get_pending_ids();
    assert_eq!(pending.len(), 2);
    let h1 = Capability::accept(&platform, &receiver, pending[0])
        .unwrap()
        .0;
    let h2 = Capability::accept(&platform, &receiver, pending[1])
        .unwrap()
        .0;
    assert_ne!(h1, h2);
    for (handle, expected) in [(h1, &caps[0]), (h2, &caps[1])] {
        let held = receiver
            .read()
            .data
            .get_memory_capability(handle)
            .unwrap()
            .upgrade()
            .unwrap();
        assert!(std::sync::Arc::ptr_eq(&held, expected));
    }
}

#[test]
fn send_sealed_failed_freeze_leaves_attrs_unchanged() {
    let (platform, sender, memory, handle) = fixture();
    let (receiver, target) = receiver(&platform, &sender);
    Capability::send(&platform, &sender, handle, target, Attributes::NONE).unwrap();
    assert!(sender.read().data.is_memory_handle_frozen(handle));
    assert_eq!(
        Capability::send(
            &platform,
            &sender,
            handle,
            target,
            Attributes::from_bits(Attributes::VITAL),
        )
        .unwrap_err(),
        CapaError::PermissionDenied
    );
    assert_eq!(memory.read().owned.attributes, Attributes::NONE);
    assert_eq!(receiver.read().data.get_pending_ids().len(), 1);
}

#[test]
fn send_sealed_success_applies_attrs() {
    let (platform, sender, memory, handle) = fixture();
    let (_receiver, target) = receiver(&platform, &sender);
    let attrs = Attributes::from_bits(Attributes::VITAL);
    Capability::send(&platform, &sender, handle, target, attrs).unwrap();
    assert_eq!(memory.read().owned.attributes, attrs);
}

#[test]
fn accept_rejects_revoked_receiver() {
    let (platform, sender, _memory, handle) = fixture();
    let (receiver, target) = receiver(&platform, &sender);
    Capability::send(&platform, &sender, handle, target, Attributes::NONE).unwrap();
    let pending = Capability::enumerate_pending(&platform, &receiver, 0)
        .unwrap()
        .unwrap();
    Capability::revoke_domain(&platform, &sender, target).unwrap();
    assert_eq!(
        Capability::accept(&platform, &receiver, pending).unwrap_err(),
        CapaError::DomainRevoked
    );
}

#[test]
fn reject_rejects_revoked_receiver() {
    let (platform, sender, _memory, handle) = fixture();
    let (receiver, target) = receiver(&platform, &sender);
    Capability::send(&platform, &sender, handle, target, Attributes::NONE).unwrap();
    let pending = Capability::enumerate_pending(&platform, &receiver, 0)
        .unwrap()
        .unwrap();
    Capability::revoke_domain(&platform, &sender, target).unwrap();
    assert_eq!(
        Capability::reject(&platform, &receiver, pending).unwrap_err(),
        CapaError::DomainRevoked
    );
}
