//! Tests for overlap validation between carved children

use capability_engine::*;
use std::sync::Arc;

#[path = "../common/mod.rs"]
mod common;


fn setup() -> (
    CapabilityRef<Domain>,
    CapabilityRef<MemoryRegion>,
    LocalHandle,
) {
    let _platform = common::TestPlatform::new();
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let mem_root = Capability::new_root(0, 1, root_region);
    root.write()
        .data
        .add_memory_capability(1, Arc::downgrade(&mem_root));
    (root, mem_root, 1)
}

#[test]
fn test_alias_cannot_overlap_carved_child() {
    let platform = common::TestPlatform::new();
    let (root, _mem_root, mem_root_h) = setup();

    // Carve a child region
    let access1 = Access::new(0x1000, 0x1000, Rights::RWX);
    let (_h, _, _) = Capability::carve(&platform, &root, mem_root_h, access1).unwrap();

    // Try to alias a region that overlaps with the carved child - should fail
    let overlap_access = Access::new(0x1000, 0x1000, Rights::RWX);
    let result = Capability::alias(&platform, &root, mem_root_h, overlap_access);
    assert!(result.is_err());
    assert!(matches!(result, Err(CapaError::InvalidAccess)));
}

#[test]
fn test_alias_partial_overlap_rejected() {
    let platform = common::TestPlatform::new();
    let (root, _mem_root, mem_root_h) = setup();

    // Carve a child region [0x1000..0x2000)
    let access1 = Access::new(0x1000, 0x1000, Rights::RWX);
    let (_h, _, _) = Capability::carve(&platform, &root, mem_root_h, access1).unwrap();

    // Try to alias a region [0x800..0x1800) that partially overlaps - should fail
    let overlap_access = Access::new(0x800, 0x1000, Rights::RWX);
    let result = Capability::alias(&platform, &root, mem_root_h, overlap_access);
    assert!(result.is_err());
    assert!(matches!(result, Err(CapaError::InvalidAccess)));
}

#[test]
fn test_carve_cannot_overlap_carved_child() {
    let platform = common::TestPlatform::new();
    let (root, _mem_root, mem_root_h) = setup();

    // Carve a child region
    let access1 = Access::new(0x1000, 0x1000, Rights::RWX);
    let (_h1, _, _) = Capability::carve(&platform, &root, mem_root_h, access1).unwrap();

    // Try to carve a region that overlaps with the first carved child - should fail
    let overlap_access = Access::new(0x1000, 0x1000, Rights::RWX);
    let result = Capability::carve(&platform, &root, mem_root_h, overlap_access);
    assert!(result.is_err());
    assert!(matches!(result, Err(CapaError::InvalidAccess)));
}

#[test]
fn test_non_overlapping_operations_succeed() {
    let platform = common::TestPlatform::new();
    let (root, _mem_root, mem_root_h) = setup();

    // Carve first child [0x0..0x1000)
    let access1 = Access::new(0x0, 0x1000, Rights::RWX);
    let (_h1, _, _) = Capability::carve(&platform, &root, mem_root_h, access1).unwrap();

    // Alias non-overlapping region [0x1000..0x2000) - should succeed
    let access2 = Access::new(0x1000, 0x1000, Rights::RWX);
    let aliased = Capability::alias(&platform, &root, mem_root_h, access2);
    assert!(aliased.is_ok());

    // Carve another non-overlapping region [0x2000..0x3000) - should succeed
    let access3 = Access::new(0x2000, 0x1000, Rights::RWX);
    let carved2 = Capability::carve(&platform, &root, mem_root_h, access3);
    assert!(carved2.is_ok());
}

#[test]
fn test_alias_can_overlap_aliased_child() {
    let platform = common::TestPlatform::new();
    let (root, _mem_root, mem_root_h) = setup();

    // Alias a child region
    let access1 = Access::new(0x1000, 0x1000, Rights::RWX);
    let (_h1, _, _)= Capability::alias(&platform, &root, mem_root_h, access1).unwrap();

    // Alias another region that overlaps with the first alias - should succeed
    // because both are aliased (shared), not carved (exclusive)
    let overlap_access = Access::new(0x1000, 0x1000, Rights::RWX);
    let result = Capability::alias(&platform, &root, mem_root_h, overlap_access);
    assert!(result.is_ok());
}

#[test]
fn test_nested_carve_overlap_validation() {
    let platform = common::TestPlatform::new();
    let (root, _mem_root, mem_root_h) = setup();

    // Carve parent [0x0..0x4000)
    let access1 = Access::new(0x0, 0x4000, Rights::RWX);
    let (parent_h, _, _) = Capability::carve(&platform, &root, mem_root_h, access1).unwrap();

    // Carve child from parent [0x1000..0x2000)
    let access2 = Access::new(0x1000, 0x1000, Rights::RWX);
    let (_child_h, _, _) = Capability::carve(&platform, &root, parent_h, access2).unwrap();

    // Try to alias from parent with overlap - should fail
    let overlap_access = Access::new(0x1500, 0x1000, Rights::RWX);
    let result = Capability::alias(&platform, &root, parent_h, overlap_access);
    assert!(result.is_err());
    assert!(matches!(result, Err(CapaError::InvalidAccess)));
}
