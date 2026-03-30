//! Tests for address space view computation

use capability_engine::*;

#[test]
fn test_view_region_creation() {
    let access = Access::new(0x1000, 0x2000, Rights::RWX);
    let region = ViewRegion::new(access);

    assert_eq!(region.start(), 0x1000);
    assert_eq!(region.end(), 0x3000);
    assert_eq!(region.size(), 0x2000);
}

#[test]
fn test_address_space_coalesce() {
    let mut view = AddressSpaceView::new(1);

    // Add three contiguous regions with same rights
    view.add_region(ViewRegion::new(Access::new(0x0, 0x1000, Rights::RW)));
    view.add_region(ViewRegion::new(Access::new(0x1000, 0x1000, Rights::RW)));
    view.add_region(ViewRegion::new(Access::new(0x2000, 0x1000, Rights::RW)));

    assert_eq!(view.regions.len(), 3);

    view.coalesce();

    assert_eq!(view.regions.len(), 1);
    assert_eq!(view.regions[0].start(), 0x0);
    assert_eq!(view.regions[0].end(), 0x3000);
}

#[test]
fn test_address_space_no_coalesce_different_rights() {
    let mut view = AddressSpaceView::new(1);

    view.add_region(ViewRegion::new(Access::new(0x0, 0x1000, Rights::RW)));
    view.add_region(ViewRegion::new(Access::new(0x1000, 0x1000, Rights::RWX)));

    assert_eq!(view.regions.len(), 2);

    view.coalesce();

    // Should not coalesce because rights differ
    assert_eq!(view.regions.len(), 2);
}

#[test]
fn test_is_accessible() {
    let mut view = AddressSpaceView::new(1);
    view.add_region(ViewRegion::new(Access::new(0x1000, 0x1000, Rights::RW)));
    view.add_region(ViewRegion::new(Access::new(0x3000, 0x1000, Rights::RW)));

    assert!(view.is_accessible(0x1000));
    assert!(view.is_accessible(0x1500));
    assert!(!view.is_accessible(0x2000));
    assert!(view.is_accessible(0x3000));
    assert!(!view.is_accessible(0x4500));
}

#[test]
fn test_total_size() {
    let mut view = AddressSpaceView::new(1);
    view.add_region(ViewRegion::new(Access::new(0x1000, 0x1000, Rights::RW)));
    view.add_region(ViewRegion::new(Access::new(0x3000, 0x2000, Rights::RW)));

    assert_eq!(view.total_size(), 0x3000);
}
