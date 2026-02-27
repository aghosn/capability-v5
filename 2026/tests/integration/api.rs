//! Tests for the domain-mediated API (carve, alias, send, revoke, create_domain, etc.)

use capability_engine::*;
use std::sync::Arc;

/// Helper: sealed root domain with a memory root at local handle 1.
/// Returns (root, mem_root_h, _mem_root) — caller must keep `_mem_root` alive.
fn setup_root() -> (CapabilityRef<Domain>, LocalHandle, CapabilityRef<MemoryRegion>) {
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);
    let total_mem = MemoryRegion::new_root(0x0, 0x10000);
    let mem_root = Capability::new_root(0, 1, total_mem);
    root.write().data.add_memory_capability(1, Arc::downgrade(&mem_root));
    (root, 1, mem_root)
}

#[test]
fn test_carve_memory() {
    let (root, mem_root_h, _mem_root) = setup_root();
    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_h, child_sub, updates) =
        Capability::carve_memory(&root, mem_root_h, child_access).unwrap();

    assert_eq!(child_sub, 1); // first child gets sub_handle = 1
    assert!(updates.is_empty()); // same owner — no MMU updates
    assert!(root.read().data.memory_capabilities.contains_key(&child_h));
}

#[test]
fn test_alias_memory() {
    let (root, mem_root_h, _mem_root) = setup_root();
    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_h, child_sub) =
        Capability::alias_memory(&root, mem_root_h, child_access).unwrap();

    assert_eq!(child_sub, 1);
    assert!(root.read().data.memory_capabilities.contains_key(&child_h));
}

#[test]
fn test_revoke_memory_child() {
    let (root, mem_root_h, _mem_root) = setup_root();
    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_child_h, child_sub, _) =
        Capability::carve_memory(&root, mem_root_h, child_access).unwrap();

    Capability::revoke_memory_child(&root, mem_root_h, child_sub).unwrap();

    // Revoking the same sub_handle again must fail (child gone from parent's tree)
    let result = Capability::revoke_memory_child(&root, mem_root_h, child_sub);
    assert!(matches!(result, Err(CapaError::NotFound)));
}

#[test]
fn test_alias_multiple() {
    let (root, mem_root_h, _mem_root) = setup_root();
    let access1 = Access::new(0x1000, 0x1000, Rights::RW);
    let access2 = Access::new(0x2000, 0x1000, Rights::RW);

    let (child1_h, child1_sub) = Capability::alias_memory(&root, mem_root_h, access1).unwrap();
    let (child2_h, child2_sub) = Capability::alias_memory(&root, mem_root_h, access2).unwrap();

    assert_ne!(child1_h, child2_h);
    assert_ne!(child1_sub, child2_sub); // sub_handles are unique among siblings
    assert!(root.read().data.memory_capabilities.contains_key(&child1_h));
    assert!(root.read().data.memory_capabilities.contains_key(&child2_h));
}

#[test]
fn test_nested_carve_memory() {
    let (root, mem_root_h, _mem_root) = setup_root();
    let c1_access = Access::new(0x2000, 0x4000, Rights::RW);
    let (c1_h, _, _) = Capability::carve_memory(&root, mem_root_h, c1_access).unwrap();

    let c2_access = Access::new(0x3000, 0x1000, Rights::R);
    let (c2_h, _, _) = Capability::carve_memory(&root, c1_h, c2_access).unwrap();

    assert!(root.read().data.memory_capabilities.contains_key(&c1_h));
    assert!(root.read().data.memory_capabilities.contains_key(&c2_h));
    let c2 = root.read().data.memory_capabilities[&c2_h].upgrade().unwrap();
    assert_eq!(c2.read().data.kind, RegionKind::Carve);
}

#[test]
fn test_create_domain() {
    let (root, _, _mem_root) = setup_root();
    let child_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE);
    let child_h = Capability::create_domain(&root, child_policy).unwrap();

    assert!(root.read().data.domain_capabilities.contains_key(&child_h));
    let child = root.read().data.domain_capabilities[&child_h].upgrade().unwrap();
    assert_eq!(child.read().sub_handle, 1); // first domain child gets sub_handle = 1
}

#[test]
fn test_revoke_domain() {
    let (root, _, _mem_root) = setup_root();
    let child_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE);
    let child_h = Capability::create_domain(&root, child_policy).unwrap();
    let child = root.read().data.domain_capabilities[&child_h].upgrade().unwrap();

    let updates = Capability::revoke_domain(&root, child_h).unwrap();

    assert!(!updates.is_empty()); // domain revocation always produces updates
    assert!(child.read().data.is_revoked()); // child domain is now revoked
    // LocalHandle must be reclaimed — the slot should be gone from the table
    assert!(!root.read().data.domain_capabilities.contains_key(&child_h));
}

// ==================== Migrated from unit/capability.rs ====================

#[test]
fn test_nested_alias_memory() {
    let (root, mem_root_h, _mem_root) = setup_root();
    // Carve a region first
    let c1_access = Access::new(0x1000, 0x2000, Rights::RW);
    let (c1_h, _, _) = Capability::carve_memory(&root, mem_root_h, c1_access).unwrap();

    // Alias from the carved child
    let a1_access = Access::new(0x1800, 0x800, Rights::R);
    let (a1_h, _) = Capability::alias_memory(&root, c1_h, a1_access).unwrap();

    let a1 = root.read().data.memory_capabilities[&a1_h].upgrade().unwrap();
    assert_eq!(a1.read().data.kind, RegionKind::Alias);
    assert_eq!(a1.read().data.status, RegionStatus::Aliased);
}

#[test]
fn test_carve_then_alias_then_carve_memory() {
    let (root, mem_root_h, _mem_root) = setup_root();

    // Step 1: carve from root mem
    let (carved_h, _, _) =
        Capability::carve_memory(&root, mem_root_h, Access::new(0x2000, 0x2000, Rights::RW))
            .unwrap();

    // Step 2: alias from carved
    let (alias_h, _) =
        Capability::alias_memory(&root, carved_h, Access::new(0x2000, 0x1000, Rights::R))
            .unwrap();

    // Step 3: carve from alias
    let (cfa_h, _, _) =
        Capability::carve_memory(&root, alias_h, Access::new(0x2000, 0x0800, Rights::R))
            .unwrap();

    let cfa = root.read().data.memory_capabilities[&cfa_h].upgrade().unwrap();
    assert_eq!(cfa.read().data.kind, RegionKind::Carve);
    assert_eq!(cfa.read().data.status, RegionStatus::Aliased); // inherits from aliased parent
}

#[test]
fn test_revoke_complex_subtree_memory() {
    let (root, mem_root_h, _mem_root) = setup_root();

    // Branch 1: carve → alias → carve
    let (b1_h, _, _) =
        Capability::carve_memory(&root, mem_root_h, Access::new(0x0000, 0x4000, Rights::RW))
            .unwrap();
    let (b1a_h, b1a_sub) =
        Capability::alias_memory(&root, b1_h, Access::new(0x1000, 0x1000, Rights::R)).unwrap();
    let (_b1a1_h, _, _) =
        Capability::carve_memory(&root, b1a_h, Access::new(0x1000, 0x0800, Rights::R)).unwrap();

    // Branch 2: plain carve (will not be revoked)
    let (b2_h, _, _) =
        Capability::carve_memory(&root, mem_root_h, Access::new(0x5000, 0x1000, Rights::R))
            .unwrap();

    // Revoke b1a (alias node) by its sub_handle
    Capability::revoke_memory_child(&root, b1_h, b1a_sub).unwrap();

    // b1's children are now empty
    let b1_ref = root.read().data.memory_capabilities[&b1_h].upgrade().unwrap();
    assert_eq!(b1_ref.read().children.len(), 0);

    // Branch 2 is unaffected — root still tracks it
    assert!(root.read().data.memory_capabilities.contains_key(&b2_h));
}

#[test]
fn test_revoke_memory_child_nonexistent() {
    let (root, mem_root_h, _mem_root) = setup_root();
    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_child_h, _child_sub, _) =
        Capability::carve_memory(&root, mem_root_h, child_access).unwrap();

    // Try to revoke with a garbage sub_handle
    let result = Capability::revoke_memory_child(&root, mem_root_h, 999);
    assert!(matches!(result, Err(CapaError::NotFound)));

    // Valid child is untouched
    let mem_root_ref = root
        .read()
        .data
        .memory_capabilities[&mem_root_h]
        .upgrade()
        .unwrap();
    assert_eq!(mem_root_ref.read().children.len(), 1);
}

#[test]
fn test_send_memory_immediate() {
    let (root, mem_root_h, _mem_root) = setup_root();

    // Carve a child cap to send
    let (carved_h, _, _) =
        Capability::carve_memory(&root, mem_root_h, Access::new(0x1000, 0x1000, Rights::RW))
            .unwrap();

    // Create an unsealed receiver domain and register it in root's domain table
    let recv_policy = DomainPolicy::new_root(4);
    let recv_domain = Domain::new(recv_policy);
    let receiver: Arc<_> = Capability::new_root(0, 2, recv_domain);
    let receiver_id = receiver.read().data.id;
    let domain_recv_h: LocalHandle = 1;
    root.write()
        .data
        .add_domain_capability(domain_recv_h, Arc::downgrade(&receiver));

    // Send — receiver is unsealed → immediate transfer
    let updates = Capability::send_memory(&root, carved_h, domain_recv_h, Attributes::NONE).unwrap();

    // Root no longer holds the handle
    assert!(!root.read().data.memory_capabilities.contains_key(&carved_h));

    // Receiver now holds the cap
    assert_eq!(receiver.read().data.memory_capabilities.len(), 1);
    let recv_cap = receiver
        .read()
        .data
        .memory_capabilities
        .values()
        .next()
        .unwrap()
        .upgrade()
        .unwrap();
    assert_eq!(recv_cap.read().owned.owner, receiver_id);

    // Parent (mem_root) still owned by root → skip_unmap → only 1 Map update
    assert_eq!(updates.len(), 1);
    match &updates.updates()[0] {
        Update::Map { domain, .. } => assert_eq!(*domain, receiver_id),
        _ => panic!("Expected Map update"),
    }
}

#[test]
fn test_send_memory_with_attributes() {
    let (root, mem_root_h, _mem_root) = setup_root();

    let (carved_h, _, _) =
        Capability::carve_memory(&root, mem_root_h, Access::new(0x1000, 0x1000, Rights::RW))
            .unwrap();

    let recv_policy = DomainPolicy::new_root(4);
    let recv_domain = Domain::new(recv_policy);
    let receiver: Arc<_> = Capability::new_root(0, 2, recv_domain);
    let domain_recv_h: LocalHandle = 1;
    root.write()
        .data
        .add_domain_capability(domain_recv_h, Arc::downgrade(&receiver));

    let attrs = Attributes::from_bits(Attributes::CLEAN | Attributes::VITAL);
    Capability::send_memory(&root, carved_h, domain_recv_h, attrs).unwrap();

    let recv_cap = receiver
        .read()
        .data
        .memory_capabilities
        .values()
        .next()
        .unwrap()
        .upgrade()
        .unwrap();
    assert!(recv_cap.read().owned.attributes.vital());
    assert!(recv_cap.read().owned.attributes.clean());
}

#[test]
fn test_revoke_domain_tree() {
    let (root, _, _mem_root) = setup_root();

    // Create child and seal it
    let child_h = Capability::create_domain(&root, DomainPolicy::new_root(4)).unwrap();
    Capability::seal_domain_op(&root, child_h).unwrap();
    let child_ref = root.read().data.domain_capabilities[&child_h].upgrade().unwrap();

    // Create grandchild under child (child must be sealed)
    let grandchild_h = Capability::create_domain(&child_ref, DomainPolicy::new_root(4)).unwrap();
    let grandchild_ref = child_ref
        .read()
        .data
        .domain_capabilities[&grandchild_h]
        .upgrade()
        .unwrap();

    // Revoke child (and transitively grandchild)
    let updates = Capability::revoke_domain(&root, child_h).unwrap();

    assert!(root.read().children.is_empty());
    assert!(child_ref.read().data.is_revoked());
    assert!(grandchild_ref.read().data.is_revoked());
    assert!(updates.len() >= 2); // at least one RevokeDomain per domain in subtree
}
