//! Tests for the static method API (was instance method API)

use capability_engine::*;

#[test]
fn test_instance_method_alias() {
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let child = Capability::alias_child(&root, child_access, 0).unwrap();

    assert_eq!(child.read().owned.owner, 0);
    assert_eq!(child.read().sub_handle, 1);
    assert_eq!(root.read().children.len(), 1);
}

#[test]
fn test_instance_method_carve() {
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child, updates) = Capability::carve_child(&root, child_access, 0).unwrap();

    assert_eq!(child.read().owned.owner, 0);
    assert_eq!(child.read().sub_handle, 1);
    assert_eq!(root.read().children.len(), 1);
    assert!(updates.is_empty());
}

#[test]
fn test_instance_method_send() {
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child, _) = Capability::carve_child(&root, child_access, 0).unwrap();

    let attrs = Attributes::from_bits(Attributes::CLEAN);
    let updates = Capability::send_to(&child, 0, 5, attrs).unwrap();

    assert_eq!(child.read().owned.owner, 5);
    assert_eq!(child.read().sub_handle, 1); // sub_handle doesn't change on send
    assert!(child.read().owned.attributes.clean());
    assert_eq!(updates.len(), 1);
}

#[test]
fn test_instance_method_revoke() {
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_child, _) = Capability::carve_child(&root, child_access, 0).unwrap();

    let updates = Capability::revoke_child(&root, 1).unwrap();

    assert_eq!(root.read().children.len(), 0);
    assert!(updates.is_empty());
}

#[test]
fn test_instance_method_nested_carve() {
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, region);

    let c1_access = Access::new(0x2000, 0x4000, Rights::RW);
    let (c1, _) = Capability::carve_child(&root, c1_access, 0).unwrap();

    let c2_access = Access::new(0x3000, 0x1000, Rights::R);
    let (c2, _) = Capability::carve_child(&c1, c2_access, 0).unwrap();

    assert_eq!(c1.read().owned.owner, 0);
    assert_eq!(c2.read().owned.owner, 0);
    assert_eq!(c2.read().data.kind, RegionKind::Carve);
}

#[test]
fn test_domain_instance_method_create_child() {
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);

    let child_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE);
    let child = Capability::create_child_domain(&root, child_policy, 0).unwrap();

    assert_eq!(child.read().owned.owner, 0);
    assert_eq!(child.read().sub_handle, 1);
    assert_eq!(root.read().children.len(), 1);
}

#[test]
fn test_domain_instance_method_revoke_child() {
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);

    let child_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE);
    let _child = Capability::create_child_domain(&root, child_policy, 0).unwrap();

    let updates = Capability::revoke_child_domain(&root, 1).unwrap();

    assert_eq!(root.read().children.len(), 0);
    assert!(!updates.is_empty());
}

#[test]
fn test_mixed_static_and_instance_api() {
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, region);

    let child1_access = Access::new(0x1000, 0x1000, Rights::RW);
    let child1 = Capability::alias_child(&root, child1_access, 0).unwrap();

    let child2_access = Access::new(0x2000, 0x1000, Rights::RW);
    let child2 = Capability::alias_child(&root, child2_access, 0).unwrap();

    assert_eq!(child1.read().owned.owner, 0);
    assert_eq!(child2.read().owned.owner, 0);
    assert_eq!(root.read().children.len(), 2);
}
