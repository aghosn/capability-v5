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
    let carve = Capability::carve_child(&root, carve_access, 1).unwrap();

    // Request WRITE, which is not present in parent
    let invalid_access = Access::new(0x1000, 0x1000, Rights::RW);
    let result = carve.read().data.carve(invalid_access);
    assert!(result.is_err());
}

// ==================== View Computation Tests ====================

#[test]
fn test_compute_view_with_carves() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    // Carve two regions
    let _child1 =
        Capability::carve_child(&root, Access::new(0x1000, 0x1000, Rights::RW), 1).unwrap();
    let _child2 =
        Capability::carve_child(&root, Access::new(0x3000, 0x1000, Rights::RW), 2).unwrap();

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
        Capability::alias_child(&root, Access::new(0x1000, 0x1000, Rights::R), 1).unwrap();
    let _alias2 =
        Capability::alias_child(&root, Access::new(0x3000, 0x1000, Rights::R), 2).unwrap();

    let view = root.read().compute_view();

    // View should be unchanged with only aliases
    assert_eq!(view.len(), 1);
    assert_eq!(view[0].start, 0x0);
    assert_eq!(view[0].size, 0x10000);
}
