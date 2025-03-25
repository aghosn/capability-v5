use capa_engine::memory_region::{Access, Rights};

#[test]
fn test_contained_exact_match() {
    let a1 = Access::new(0, 0x2000, Rights::READ | Rights::WRITE);
    let a2 = Access::new(0, 0x2000, Rights::READ | Rights::WRITE);
    assert!(a1.contained(&a2)); // exact same range and rights
}

#[test]
fn test_contained_strict_subset_range_and_rights() {
    let a1 = Access::new(0x1000, 0x1000, Rights::READ);
    let a2 = Access::new(0, 0x2000, Rights::READ | Rights::WRITE);
    assert!(a1.contained(&a2)); // a1 is inside a2 range and has fewer rights
}

#[test]
fn test_not_contained_range_exceeds() {
    let a1 = Access::new(0, 0x3000, Rights::READ);
    let a2 = Access::new(0, 0x2000, Rights::READ | Rights::WRITE);
    assert!(!a1.contained(&a2)); // a1's range exceeds a2's
}

#[test]
fn test_not_contained_rights_not_subset() {
    let a1 = Access::new(0, 0x1000, Rights::READ | Rights::WRITE);
    let a2 = Access::new(0, 0x2000, Rights::READ); // no WRITE
    assert!(!a1.contained(&a2)); // rights not a subset
}

#[test]
fn test_not_contained_start_before_other() {
    let a1 = Access::new(0, 0x1000, Rights::READ);
    let a2 = Access::new(0x1000, 0x2000, Rights::READ | Rights::WRITE);
    assert!(!a1.contained(&a2)); // a1 starts before a2
}

#[test]
fn test_contained_equal_range_lesser_rights() {
    let a1 = Access::new(0, 0x2000, Rights::READ);
    let a2 = Access::new(0, 0x2000, Rights::READ | Rights::WRITE);
    assert!(a1.contained(&a2)); // a1 has fewer rights but same range
}

#[test]
fn test_not_contained_partial_overlap() {
    let a1 = Access::new(0x1000, 0x2000, Rights::READ);
    let a2 = Access::new(0x0000, 0x2000, Rights::READ | Rights::WRITE);
    assert!(!a1.contained(&a2)); // a1 spills past a2.end
}
