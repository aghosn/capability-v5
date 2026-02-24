//! Tests for the new instance method API

use capability_engine::*;

#[test]
fn test_instance_method_alias() {
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, region);

    // Using the new instance method API (owner inferred from parent)
    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let child = root.alias(child_access, 1).unwrap();

    // Verify ownership was inferred correctly
    assert_eq!(child.read().owned.owner, 0); // Same as parent
    assert_eq!(child.read().owned.handle, 1);
    assert_eq!(root.read().children.len(), 1);
}

#[test]
fn test_instance_method_carve() {
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, region);

    // Using the new instance method API (owner inferred from parent)
    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child, updates) = root.carve(child_access, 1).unwrap();

    // Verify ownership was inferred correctly
    assert_eq!(child.read().owned.owner, 0); // Same as parent
    assert_eq!(child.read().owned.handle, 1);
    assert_eq!(root.read().children.len(), 1);
    assert!(updates.is_empty()); // No updates when owner doesn't change
}

#[test]
fn test_instance_method_send() {
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child, _) = root.carve(child_access, 1).unwrap();

    // Using the new instance method API
    let attrs = Attributes::from_bits(Attributes::CLEAN);
    let updates = child.send(5, 10, attrs).unwrap();

    // Verify send worked
    assert_eq!(child.read().owned.owner, 5);
    assert_eq!(child.read().owned.handle, 10);
    assert!(child.read().owned.attributes.clean());
    assert_eq!(updates.len(), 1); // Should have map update
}

#[test]
fn test_instance_method_revoke() {
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_child, _) = root.carve(child_access, 1).unwrap();

    // Using the new instance method API
    let updates = root.revoke(1).unwrap();

    // Verify revocation worked
    assert_eq!(root.read().children.len(), 0);
    assert!(updates.is_empty()); // No updates when revoking own child
}

#[test]
fn test_instance_method_nested_carve() {
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, region);

    // Carve from root
    let c1_access = Access::new(0x2000, 0x4000, Rights::RW);
    let (c1, _) = root.carve(c1_access, 1).unwrap();

    // Carve from carved region using instance method
    let c2_access = Access::new(0x3000, 0x1000, Rights::R);
    let (c2, _) = c1.carve(c2_access, 2).unwrap();

    // Verify ownership inheritance
    assert_eq!(c1.read().owned.owner, 0); // Inherited from root
    assert_eq!(c2.read().owned.owner, 0); // Inherited from c1
    assert_eq!(c2.read().data.kind, RegionKind::Carve);
}

#[test]
fn test_domain_instance_method_create_child() {
    let root_domain = Domain::new_root();
    let root = Capability::new_root(0, 0, root_domain);

    // Using the new instance method API (owner inferred from parent)
    let child_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE);
    let child = root.create_child(child_policy, 1).unwrap();

    // Verify ownership was inferred correctly
    assert_eq!(child.read().owned.owner, 0); // Same as parent
    assert_eq!(child.read().owned.handle, 1);
    assert_eq!(root.read().children.len(), 1);
}

#[test]
fn test_domain_instance_method_revoke_child() {
    let root_domain = Domain::new_root();
    let root = Capability::new_root(0, 0, root_domain);

    let child_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE);
    let _child = root.create_child(child_policy, 1).unwrap();

    // Using the new instance method API
    let updates = root.revoke_child(1).unwrap();

    // Verify revocation worked
    assert_eq!(root.read().children.len(), 0);
    assert!(!updates.is_empty()); // Should have domain revocation update
}

#[test]
fn test_mixed_static_and_instance_api() {
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, region);

    // Can still use static API with explicit owner
    let child1_access = Access::new(0x1000, 0x1000, Rights::RW);
    let child1 = Capability::alias_child(&root, child1_access, 0, 1).unwrap();

    // And use instance API with inferred owner
    let child2_access = Access::new(0x2000, 0x1000, Rights::RW);
    let child2 = root.alias(child2_access, 2).unwrap();

    // Both should work
    assert_eq!(child1.read().owned.owner, 0);
    assert_eq!(child2.read().owned.owner, 0);
    assert_eq!(root.read().children.len(), 2);
}
