//! Tests for capability tree operations

use capability_engine::*;

// ==================== Basic Capability Operations ====================

#[test]
fn test_capability_tree() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    assert!(root.read().children.is_empty());
    assert!(!root.read().has_parent());
}

#[test]
fn test_alias_child() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let child = Capability::alias_child(&root, child_access, 1, 1).unwrap();

    assert_eq!(root.read().children.len(), 1);
    assert!(child.read().has_parent());
}

#[test]
fn test_carve_child() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_child, updates) = Capability::carve_child(&root, child_access, 0, 1).unwrap();

    assert_eq!(root.read().children.len(), 1);
    // Carve should NOT generate updates because owner doesn't change (parent owner = 0, child owner = 0)
    assert!(updates.is_empty());
}

#[test]
fn test_revoke_child() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_child, _) = Capability::carve_child(&root, child_access, 0, 1).unwrap();

    let updates = Capability::revoke_child(&root, 1).unwrap();

    assert_eq!(root.read().children.len(), 0);
    // Revoke should NOT generate updates for a carved child that was never sent
    // because the parent owner never lost access
    assert!(updates.is_empty());
}

// ==================== Nested Operations ====================

#[test]
fn test_nested_carve() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    // Carve a sub-region from the root
    let c1_access = Access::new(0x2000, 0x4000, Rights::RW);
    let (c1, _) = Capability::carve_child(&root, c1_access, 1, 1).unwrap();

    // Carve from the carved region
    let c2_access = Access::new(0x3000, 0x1000, Rights::R);
    let (c2, _) = Capability::carve_child(&c1, c2_access, 2, 2).unwrap();

    let c2_read = c2.read();
    assert_eq!(c2_read.data.access, c2_access);
    assert_eq!(c2_read.data.status, RegionStatus::Exclusive);
    assert_eq!(c2_read.data.kind, RegionKind::Carve);
}

#[test]
fn test_nested_alias() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    let c1_access = Access::new(0x1000, 0x2000, Rights::RW);
    let (c1, _) = Capability::carve_child(&root, c1_access, 1, 1).unwrap();

    let a1_access = Access::new(0x1800, 0x800, Rights::R);
    let a1 = Capability::alias_child(&c1, a1_access, 2, 2).unwrap();

    let a1_read = a1.read();
    assert_eq!(a1_read.data.kind, RegionKind::Alias);
    assert_eq!(a1_read.data.status, RegionStatus::Aliased);
    assert_eq!(a1_read.data.access, a1_access);
}

#[test]
fn test_carve_then_alias_then_carve() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    // Step 1: Carve a region from the root
    let (carved, _) =
        Capability::carve_child(&root, Access::new(0x2000, 0x2000, Rights::RW), 1, 1).unwrap();

    // Step 2: Alias the carved region
    let alias_access = Access::new(0x2000, 0x1000, Rights::R);
    let alias = Capability::alias_child(&carved, alias_access, 2, 2).unwrap();

    // Check alias kind and status
    {
        let alias_read = alias.read();
        assert_eq!(alias_read.data.kind, RegionKind::Alias);
        assert_eq!(alias_read.data.status, RegionStatus::Aliased);
    }

    // Step 3: Carve from the alias
    let carve_from_alias_access = Access::new(0x2000, 0x0800, Rights::R);
    let (carved_from_alias, _) =
        Capability::carve_child(&alias, carve_from_alias_access, 3, 3).unwrap();

    // Check carve kind and status
    let carved_read = carved_from_alias.read();
    assert_eq!(carved_read.data.kind, RegionKind::Carve);
    assert_eq!(carved_read.data.status, RegionStatus::Aliased); // inherits from parent
}

// ==================== Invalid Operations ====================

#[test]
fn test_carve_out_of_bounds() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    // Beyond the root region
    let access = Access::new(0x20000, 0x1000, Rights::R);
    let result = root.read().data.carve(access);
    assert!(result.is_err());
}

#[test]
fn test_alias_excessive_rights() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    // Request write rights on root that only has read
    root.write().data.access.rights = Rights::R;

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let result = root.read().data.alias(access);
    assert!(result.is_err());
}

#[test]
fn test_nested_carve_invalid_due_to_rights() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    let carve_access = Access::new(0x0, 0x4000, Rights::R);
    let (carve, _) = Capability::carve_child(&root, carve_access, 1, 1).unwrap();

    // Request WRITE, which is not present in parent
    let invalid_access = Access::new(0x1000, 0x1000, Rights::RW);
    let result = carve.read().data.carve(invalid_access);
    assert!(result.is_err());
}

// ==================== Revocation Tests ====================

#[test]
fn test_revoke_complex_subtree() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    // Branch 1
    let (b1, _) =
        Capability::carve_child(&root, Access::new(0x0000, 0x4000, Rights::RW), 1, 1).unwrap();
    let b1a = Capability::alias_child(&b1, Access::new(0x1000, 0x1000, Rights::R), 2, 2).unwrap();
    let (_b1a1, _) =
        Capability::carve_child(&b1a, Access::new(0x1000, 0x0800, Rights::R), 3, 3).unwrap();

    // Branch 2 (will not be revoked)
    let (_b2, _) =
        Capability::carve_child(&root, Access::new(0x5000, 0x1000, Rights::R), 4, 4).unwrap();

    // Revoke b1a (handle 2)
    let result = Capability::revoke_child(&b1, 2);
    assert!(result.is_ok());

    // b1 should still be there, but now empty
    assert_eq!(b1.read().children.len(), 0);

    // Root should still have 2 children (b1 and b2)
    assert_eq!(root.read().children.len(), 2);
}

#[test]
fn test_revoke_nonexistent() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    // Create a valid region in the root
    let (_valid_region, _) =
        Capability::carve_child(&root, Access::new(0x0000, 0x1000, Rights::RW), 1, 1).unwrap();

    // Try to revoke a non-existent child (handle 999)
    let result = Capability::revoke_child(&root, 999);
    assert!(result.is_err());

    // Ensure the valid_region is still present
    assert_eq!(root.read().children.len(), 1);
}

// ==================== View Computation Tests ====================

#[test]
fn test_compute_view_with_carves() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    // Carve two regions
    let (_child1, _) =
        Capability::carve_child(&root, Access::new(0x1000, 0x1000, Rights::RW), 1, 1).unwrap();
    let (_child2, _) =
        Capability::carve_child(&root, Access::new(0x3000, 0x1000, Rights::RW), 2, 2).unwrap();

    let view = root.read().compute_view();

    // View should exclude the two carved regions
    assert!(view.len() >= 2); // Should be split around carved regions
}

#[test]
fn test_view_with_aliases_unchanged() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    // Create aliases (shouldn't affect view)
    let _alias1 =
        Capability::alias_child(&root, Access::new(0x1000, 0x1000, Rights::R), 1, 1).unwrap();
    let _alias2 =
        Capability::alias_child(&root, Access::new(0x3000, 0x1000, Rights::R), 2, 2).unwrap();

    let view = root.read().compute_view();

    // View should be unchanged with only aliases
    assert_eq!(view.len(), 1);
    assert_eq!(view[0].start, 0x0);
    assert_eq!(view[0].size, 0x10000);
}

// ==================== Domain Capability Tests ====================

#[test]
fn test_create_child_domain() {
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);

    // Seal root before creating children
    let _ = root.write().data.seal();

    let child_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE);
    let child = Capability::create_child_domain(&root, child_policy, 1, 1).unwrap();

    assert_eq!(root.read().children.len(), 1);
    assert!(child.read().has_parent());
}

#[test]
fn test_revoke_child_domain() {
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);

    let child_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE);
    let (_child, _) = {
        let ch = Capability::create_child_domain(&root, child_policy, 1, 1).unwrap();
        (ch, ())
    };

    let updates = Capability::revoke_child_domain(&root, 1).unwrap();

    assert_eq!(root.read().children.len(), 0);
    assert!(!updates.is_empty());
}

#[test]
fn test_domain_tree_revocation() {
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);

    // Create a child
    let child_policy = DomainPolicy::new_root(4);
    let child = Capability::create_child_domain(&root, child_policy, 1, 1).unwrap();

    // Seal child before creating grandchildren
    assert!(child.write().data.seal().is_ok());

    // Create a grandchild
    let grandchild_policy = DomainPolicy::new_root(4);
    let _grandchild = Capability::create_child_domain(&child, grandchild_policy, 2, 2).unwrap();

    // Revoke child (should also revoke grandchild)
    let updates = Capability::revoke_child_domain(&root, 1).unwrap();

    assert_eq!(root.read().children.len(), 0);
    // Should have updates for both child and grandchild domains
    assert!(updates.len() >= 2);
}

// ==================== Send Operations ====================

#[test]
fn test_send_capability() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child, _) = Capability::carve_child(&root, child_access, 0, 1).unwrap();

    // Send to domain 5
    let updates = Capability::send_to(&child, 5, 10, Attributes::NONE).unwrap();

    // Check ownership was updated
    assert_eq!(child.read().owned.owner, 5);
    assert_eq!(child.read().owned.handle, 10);

    // Should only have map update (no unmap) because parent (owned by domain 0) still has access
    assert_eq!(updates.len(), 1);
    // Verify it's a map to the new owner
    match &updates.updates()[0] {
        Update::Map { domain, .. } => assert_eq!(*domain, 5),
        _ => panic!("Expected Map update"),
    }
}

#[test]
fn test_send_with_attributes() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child, _) = Capability::carve_child(&root, child_access, 0, 1).unwrap();

    // Send with vital and clean attributes
    let attrs = Attributes::from_bits(Attributes::CLEAN | Attributes::VITAL);
    let _updates = Capability::send_to(&child, 5, 10, attrs).unwrap();

    // Check attributes were set
    assert!(child.read().owned.attributes.vital());
    assert!(child.read().owned.attributes.clean());
}
