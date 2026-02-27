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
}
