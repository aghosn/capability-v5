//! Tests for memory regions and access control

use capability_engine::*;

// ==================== Rights Tests ====================

#[test]
fn test_rights_subset() {
    assert!(Rights::R.is_subset_of(&Rights::RWX));
    assert!(Rights::RW.is_subset_of(&Rights::RWX));
    assert!(!Rights::RWX.is_subset_of(&Rights::RW));
}

#[test]
fn test_rights_subset_exact() {
    assert!(Rights::RWX.is_subset_of(&Rights::RWX));
    assert!(Rights::NONE.is_subset_of(&Rights::NONE));
}

#[test]
fn test_rights_intersect() {
    let r1 = Rights::RWX;
    let r2 = Rights::RW;
    let intersection = r1.intersect(&r2);

    assert!(intersection.read());
    assert!(intersection.write());
    assert!(!intersection.execute());
}

#[test]
fn test_rights_intersect_disjoint() {
    let r1 = Rights::R;
    let r2 = Rights::from_bits(Rights::WRITE);
    let intersection = r1.intersect(&r2);

    assert!(!intersection.read());
    assert!(!intersection.write());
    assert!(!intersection.execute());
}

// ==================== Access Tests ====================

#[test]
fn test_access_contained() {
    let parent = Access::new(0x1000, 0x4000, Rights::RWX);
    let child = Access::new(0x2000, 0x1000, Rights::RW);
    assert!(child.contained_in(&parent));
}

#[test]
fn test_access_not_contained_range() {
    let a1 = Access::new(0, 0x3000, Rights::R);
    let a2 = Access::new(0, 0x2000, Rights::RW);
    assert!(!a1.contained_in(&a2)); // a1's range exceeds a2's
}

#[test]
fn test_access_overlaps() {
    let a1 = Access::new(0x1000, 0x2000, Rights::R);
    let a2 = Access::new(0x2000, 0x2000, Rights::R);
    assert!(a1.overlaps(&a2));
}

#[test]
fn test_access_no_overlap() {
    let a1 = Access::new(0x1000, 0x1000, Rights::R);
    let a2 = Access::new(0x3000, 0x1000, Rights::R);
    assert!(!a1.overlaps(&a2));
}

#[test]
fn test_access_end() {
    let access = Access::new(0x1000, 0x2000, Rights::R);
    assert_eq!(access.end(), 0x3000);
}

#[test]
fn test_access_rights_subset() {
    let a1 = Access::new(0x1000, 0x1000, Rights::R);
    let a2 = Access::new(0x1000, 0x1000, Rights::RW);
    assert!(a1.rights_subset_of(&a2));
    assert!(!a2.rights_subset_of(&a1));
}

// ==================== Memory Region Creation ====================

#[test]
fn test_alias_creation() {
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let aliased = region.alias(child_access).unwrap();

    assert_eq!(aliased.status, RegionStatus::Aliased);
    assert_eq!(aliased.kind, RegionKind::Alias);
}

#[test]
fn test_carve_creation() {
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let carved = region.carve(child_access).unwrap();

    assert_eq!(carved.status, RegionStatus::Exclusive);
    assert_eq!(carved.kind, RegionKind::Carve);
}

#[test]
fn test_root_region_properties() {
    let region = MemoryRegion::new_root(0x1000, 0x5000);

    assert_eq!(region.kind, RegionKind::Carve);
    assert_eq!(region.status, RegionStatus::Exclusive);
    assert_eq!(region.access.start, 0x1000);
    assert_eq!(region.access.size, 0x5000);
    assert_eq!(region.access.rights, Rights::RWX);
}

// ==================== Invalid Memory Operations ====================

#[test]
fn test_alias_out_of_bounds() {
    let region = MemoryRegion::new_root(0x0, 0x10000);

    // Request region beyond parent bounds
    let access = Access::new(0x20000, 0x1000, Rights::R);
    let result = region.alias(access);

    assert!(result.is_err());
}

#[test]
fn test_alias_excessive_rights() {
    let mut region = MemoryRegion::new_root(0x0, 0x10000);
    region.access.rights = Rights::R; // Parent only has read

    // Request write rights
    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let result = region.alias(access);

    assert!(result.is_err());
}

#[test]
fn test_carve_out_of_bounds() {
    let region = MemoryRegion::new_root(0x0, 0x10000);

    // Request region beyond parent bounds
    let access = Access::new(0x20000, 0x1000, Rights::R);
    let result = region.carve(access);

    assert!(result.is_err());
}

#[test]
fn test_carve_excessive_rights() {
    let mut region = MemoryRegion::new_root(0x0, 0x10000);
    region.access.rights = Rights::R; // Parent only has read

    // Request write rights
    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let result = region.carve(access);

    assert!(result.is_err());
}

// ==================== Attributes Tests ====================

#[test]
fn test_attributes_none() {
    let attrs = Attributes::NONE;
    assert!(!attrs.hash());
    assert!(!attrs.clean());
    assert!(!attrs.vital());
    assert!(!attrs.meta());
}

#[test]
fn test_with_attributes() {
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let capa = Capability::new_root(0, 0, region);

    // Set attributes via ownership
    let attrs = Attributes::from_bits(Attributes::HASH | Attributes::CLEAN);
    capa.write().owned.attributes = attrs;

    assert!(capa.read().owned.attributes.hash());
    assert!(capa.read().owned.attributes.clean());
    assert!(!capa.read().owned.attributes.vital());
}

#[test]
fn test_with_hash() {
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let hash = [0xABu8; 32];

    let region_with_hash = region.with_hash(hash);

    assert_eq!(region_with_hash.content_hash, Some(hash));
}

// ==================== Status Inheritance ====================

#[test]
fn test_carve_from_exclusive_is_exclusive() {
    let region = MemoryRegion::new_root(0x0, 0x10000);
    assert_eq!(region.status, RegionStatus::Exclusive);

    let carved = region
        .carve(Access::new(0x1000, 0x1000, Rights::R))
        .unwrap();
    assert_eq!(carved.status, RegionStatus::Exclusive);
}

#[test]
fn test_carve_from_aliased_is_aliased() {
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let aliased_parent = region.alias(Access::new(0x0, 0x8000, Rights::RW)).unwrap();

    assert_eq!(aliased_parent.status, RegionStatus::Aliased);

    let carved = aliased_parent
        .carve(Access::new(0x1000, 0x1000, Rights::R))
        .unwrap();
    assert_eq!(carved.status, RegionStatus::Aliased); // Inherits from parent
}

#[test]
fn test_alias_always_aliased() {
    let region = MemoryRegion::new_root(0x0, 0x10000);

    let aliased1 = region
        .alias(Access::new(0x1000, 0x1000, Rights::R))
        .unwrap();
    assert_eq!(aliased1.status, RegionStatus::Aliased);

    // Alias from an alias
    let aliased2 = aliased1
        .alias(Access::new(0x1000, 0x500, Rights::R))
        .unwrap();
    assert_eq!(aliased2.status, RegionStatus::Aliased);
}

// ==================== Complex Access Patterns ====================

#[test]
fn test_contained_exact_match() {
    let a1 = Access::new(0, 0x2000, Rights::RW);
    let a2 = Access::new(0, 0x2000, Rights::RW);
    assert!(a1.contained_in(&a2)); // exact same range and rights
}

#[test]
fn test_contained_strict_subset_range_and_rights() {
    let a1 = Access::new(0x1000, 0x1000, Rights::R);
    let a2 = Access::new(0, 0x2000, Rights::RW);
    assert!(a1.contained_in(&a2)); // a1 is inside a2 range and has fewer rights
}

#[test]
fn test_not_contained_start_before_other() {
    let a1 = Access::new(0, 0x1000, Rights::R);
    let a2 = Access::new(0x1000, 0x2000, Rights::RW);
    assert!(!a1.contained_in(&a2)); // a1 starts before a2
}

#[test]
fn test_contained_equal_range_lesser_rights() {
    let a1 = Access::new(0, 0x2000, Rights::R);
    let a2 = Access::new(0, 0x2000, Rights::RW);
    assert!(a1.contained_in(&a2)); // a1 has fewer rights but same range
}

#[test]
fn test_not_contained_partial_overlap() {
    let a1 = Access::new(0x1000, 0x2000, Rights::R);
    let a2 = Access::new(0x0000, 0x2000, Rights::RW);
    assert!(!a1.contained_in(&a2)); // a1 spills past a2.end
}

// ==================== Edge Cases ====================

#[test]
fn test_zero_size_access() {
    let access = Access::new(0x1000, 0, Rights::R);
    assert_eq!(access.end(), 0x1000);
}

#[test]
fn test_large_memory_region() {
    let region = MemoryRegion::new_root(0, u64::MAX / 2);
    assert_eq!(region.access.size, u64::MAX / 2);
}

#[test]
fn test_multiple_attributes() {
    let attrs = Attributes::from_bits(
        Attributes::HASH | Attributes::CLEAN | Attributes::VITAL | Attributes::META,
    );

    let region = MemoryRegion::new_root(0, 0x1000);
    let capa = Capability::new_root(0, 0, region);
    capa.write().owned.attributes = attrs;

    assert!(capa.read().owned.attributes.hash());
    assert!(capa.read().owned.attributes.clean());
    assert!(capa.read().owned.attributes.vital());
    assert!(capa.read().owned.attributes.meta());
}
