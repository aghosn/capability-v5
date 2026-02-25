//! Tests for overlap validation between carved children

use capability_engine::*;

#[test]
fn test_alias_cannot_overlap_carved_child() {
    // Create root capability
    let mem_root = Capability::new_root(0, 1, MemoryRegion::new_root(0x0, 0x10000));

    // Carve a child region
    let access1 = Access::new(0x1000, 0x1000, Rights::RWX);
    let (_carved, _) = Capability::carve_child(&mem_root, access1, 0, 2).unwrap();

    // Try to alias a region that overlaps with the carved child - should fail
    let overlap_access = Access::new(0x1000, 0x1000, Rights::RWX);
    let result = Capability::alias_child(&mem_root, overlap_access, 0, 3);
    assert!(result.is_err());
    assert!(matches!(result, Err(CapaError::InvalidAccess)));
}

#[test]
fn test_alias_partial_overlap_rejected() {
    // Create root capability
    let mem_root = Capability::new_root(0, 1, MemoryRegion::new_root(0x0, 0x10000));

    // Carve a child region [0x1000..0x2000)
    let access1 = Access::new(0x1000, 0x1000, Rights::RWX);
    let (carved, _) = Capability::carve_child(&mem_root, access1, 0, 2).unwrap();

    // Try to alias a region [0x800..0x1800) that partially overlaps - should fail
    let overlap_access = Access::new(0x800, 0x1000, Rights::RWX);
    let result = Capability::alias_child(&mem_root, overlap_access, 0, 3);
    assert!(result.is_err());
    assert!(matches!(result, Err(CapaError::InvalidAccess)));
}

#[test]
fn test_carve_cannot_overlap_carved_child() {
    // Create root capability
    let mem_root = Capability::new_root(0, 1, MemoryRegion::new_root(0x0, 0x10000));

    // Carve a child region
    let access1 = Access::new(0x1000, 0x1000, Rights::RWX);
    let (carved1, _) = Capability::carve_child(&mem_root, access1, 0, 2).unwrap();

    // Try to carve a region that overlaps with the first carved child - should fail
    let overlap_access = Access::new(0x1000, 0x1000, Rights::RWX);
    let result = Capability::carve_child(&mem_root, overlap_access, 0, 3);
    assert!(result.is_err());
    assert!(matches!(result, Err(CapaError::InvalidAccess)));
}

#[test]
fn test_non_overlapping_operations_succeed() {
    // Create root capability
    let mem_root = Capability::new_root(0, 1, MemoryRegion::new_root(0x0, 0x10000));

    // Carve first child [0x0..0x1000)
    let access1 = Access::new(0x0, 0x1000, Rights::RWX);
    let (_carved1, _) = Capability::carve_child(&mem_root, access1, 0, 2).unwrap();

    // Alias non-overlapping region [0x1000..0x2000) - should succeed
    let access2 = Access::new(0x1000, 0x1000, Rights::RWX);
    let aliased = Capability::alias_child(&mem_root, access2, 0, 3);
    assert!(aliased.is_ok());

    // Carve another non-overlapping region [0x2000..0x3000) - should succeed
    let access3 = Access::new(0x2000, 0x1000, Rights::RWX);
    let carved2 = Capability::carve_child(&mem_root, access3, 0, 4);
    assert!(carved2.is_ok());
}

#[test]
fn test_alias_can_overlap_aliased_child() {
    // Create root capability
    let mem_root = Capability::new_root(0, 1, MemoryRegion::new_root(0x0, 0x10000));

    // Alias a child region
    let access1 = Access::new(0x1000, 0x1000, Rights::RWX);
    let _aliased1 = Capability::alias_child(&mem_root, access1, 0, 2).unwrap();

    // Alias another region that overlaps with the first alias - should succeed
    // because both are aliased (shared), not carved (exclusive)
    let overlap_access = Access::new(0x1000, 0x1000, Rights::RWX);
    let result = Capability::alias_child(&mem_root, overlap_access, 0, 3);
    assert!(result.is_ok());
}

#[test]
fn test_nested_carve_overlap_validation() {
    // Create root capability
    let mem_root = Capability::new_root(0, 1, MemoryRegion::new_root(0x0, 0x10000));

    // Carve parent [0x0..0x4000)
    let access1 = Access::new(0x0, 0x4000, Rights::RWX);
    let (parent, _) = Capability::carve_child(&mem_root, access1, 0, 2).unwrap();

    // Carve child from parent [0x1000..0x2000)
    let access2 = Access::new(0x1000, 0x1000, Rights::RWX);
    let (_child, _) = Capability::carve_child(&parent, access2, 0, 3).unwrap();

    // Try to alias from parent with overlap - should fail
    let overlap_access = Access::new(0x1500, 0x1000, Rights::RWX);
    let result = Capability::alias_child(&parent, overlap_access, 0, 4);
    assert!(result.is_err());
    assert!(matches!(result, Err(CapaError::InvalidAccess)));
}
