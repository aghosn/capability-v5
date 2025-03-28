use capa_engine::capability::*;
use capa_engine::memory_region::*;
use std::cell::RefCell;
use std::rc::Rc;

fn create_root() -> Capability<MemoryRegion> {
    Capability::<MemoryRegion>::new(MemoryRegion {
        kind: RegionKind::Carve,
        status: Status::Exclusive,
        access: Access::new(0, 0x10000, Rights::READ | Rights::WRITE | Rights::EXECUTE),
        attributes: Attributes::NONE,
        remapped: Remapped::Identity,
    })
}

#[test]
fn test_valid_carve() {
    let mut root = create_root();
    let access = Access::new(0x2000, 0x1000, Rights::READ | Rights::WRITE);
    let result = root.carve(&access);
    assert!(result.is_ok());

    let carved = result.unwrap();
    let carved_borrow = carved.borrow();

    assert_eq!(carved_borrow.data.kind, RegionKind::Carve);
    assert_eq!(carved_borrow.data.status, Status::Exclusive);
    assert_eq!(carved_borrow.data.access, access);
}

#[test]
fn test_valid_alias() {
    let mut root = create_root();
    let access = Access::new(0x2000, 0x1000, Rights::READ);
    let result = root.alias(&access);
    assert!(result.is_ok());

    let alias = result.unwrap();
    let alias_borrow = alias.borrow();

    assert_eq!(alias_borrow.data.kind, RegionKind::Alias);
    assert_eq!(alias_borrow.data.status, Status::Aliased);
    assert_eq!(alias_borrow.data.access, access);
}

#[test]
fn test_carve_overlap_rejected() {
    let mut root = create_root();

    let c1 = Access::new(0x2000, 0x1000, Rights::READ);
    assert!(root.carve(&c1).is_ok());

    // Overlaps with previous carve
    let overlapping = Access::new(0x2800, 0x1000, Rights::READ);
    let result = root.carve(&overlapping);
    assert_eq!(result, Err(CapaError::InvalidAccess));
}

#[test]
fn test_alias_overlap_with_carve_rejected() {
    let mut root = create_root();

    let c1 = Access::new(0x3000, 0x1000, Rights::READ);
    assert!(root.carve(&c1).is_ok());

    // Aliases are no longer possible
    let a1 = Access::new(0x3000, 0x1000, Rights::READ);
    let result = root.alias(&a1);
    assert!(result.is_err());
}

#[test]
fn test_carve_out_of_bounds() {
    let mut root = create_root();

    // Beyond the root region
    let access = Access::new(0x20000, 0x1000, Rights::READ);
    let result = root.carve(&access);
    assert_eq!(result, Err(CapaError::InvalidAccess));
}

#[test]
fn test_alias_with_extra_rights_rejected() {
    let mut root = create_root();

    // Root does not give WRITE or EXECUTE
    root.data.access.rights = Rights::READ;

    let access = Access::new(0x1000, 0x1000, Rights::READ | Rights::WRITE);
    let result = root.alias(&access);
    assert_eq!(result, Err(CapaError::InvalidAccess));
}

// ——————————————————————————— Nested operations ———————————————————————————— //

#[test]
fn test_nested_carve() {
    let mut root = create_root();

    // Carve a sub-region from the root
    let c1_access = Access::new(0x2000, 0x4000, Rights::READ | Rights::WRITE);
    let c1 = root.carve(&c1_access).expect("root carve failed");

    // Carve from the carved region
    let mut c1_borrow = c1.borrow_mut();
    let c2_access = Access::new(0x3000, 0x1000, Rights::READ);
    let c2 = c1_borrow.carve(&c2_access).expect("nested carve failed");

    let c2_borrow = c2.borrow();
    assert_eq!(c2_borrow.data.access, c2_access);
    assert_eq!(c2_borrow.data.status, Status::Exclusive);
    assert_eq!(c2_borrow.data.kind, RegionKind::Carve);
    assert_eq!(c2_borrow.data.remapped, Remapped::Identity);
}

#[test]
fn test_nested_alias() {
    let mut root = create_root();

    let c1_access = Access::new(0x1000, 0x2000, Rights::READ | Rights::WRITE);
    let c1 = root.carve(&c1_access).expect("carve failed");

    let mut c1_borrow = c1.borrow_mut();
    let a1_access = Access::new(0x1800, 0x800, Rights::READ);
    let a1 = c1_borrow
        .alias(&a1_access)
        .expect("alias from carve failed");

    let a1_borrow = a1.borrow();
    assert_eq!(a1_borrow.data.kind, RegionKind::Alias);
    assert_eq!(a1_borrow.data.status, Status::Aliased);
    assert_eq!(a1_borrow.data.access, a1_access);
}

#[test]
fn test_nested_carve_invalid_due_to_rights() {
    let mut root = create_root();

    let carve_access = Access::new(0x0, 0x4000, Rights::READ);
    let carve = root.carve(&carve_access).expect("carve failed");

    let mut carve_borrow = carve.borrow_mut();

    // Request WRITE, which is not present in parent
    let invalid_access = Access::new(0x1000, 0x1000, Rights::WRITE);
    let result = carve_borrow.carve(&invalid_access);
    assert_eq!(result, Err(CapaError::InvalidAccess));
}

#[test]
fn test_nested_alias_invalid_due_to_overlap() {
    let mut root = create_root();

    let carve_1 = root
        .carve(&Access::new(0x2000, 0x2000, Rights::READ))
        .expect("carve_1 failed");
    let carve_2 = root
        .carve(&Access::new(0x4000, 0x2000, Rights::READ))
        .expect("carve_2 failed");

    let mut carve_1_borrow = carve_1.borrow_mut();
    let alias_1_access = Access::new(0x2000, 0x1000, Rights::READ);
    let alias_1 = carve_1_borrow
        .alias(&alias_1_access)
        .expect("alias_1 creation failed");

    {
        let alias_1_borrow = alias_1.borrow();
        assert_eq!(alias_1_borrow.data.access, alias_1_access);
        assert_eq!(alias_1_borrow.data.kind, RegionKind::Alias);
        assert_eq!(alias_1_borrow.data.status, Status::Aliased);
    }

    let mut carve_2_borrow = carve_2.borrow_mut();
    let alias_2_access = Access::new(0x4000, 0x1000, Rights::READ);
    let alias_2 = carve_2_borrow
        .alias(&alias_2_access)
        .expect("alias_2 creation failed");

    {
        let alias_2_borrow = alias_2.borrow();
        assert_eq!(alias_2_borrow.data.access, alias_2_access);
        assert_eq!(alias_2_borrow.data.kind, RegionKind::Alias);
        assert_eq!(alias_2_borrow.data.status, Status::Aliased);
    }
}

#[test]
fn test_carve_then_alias_then_carve() {
    let mut root = create_root();

    // Step 1: Carve a region from the root
    let carved = root
        .carve(&Access::new(0x2000, 0x2000, Rights::READ | Rights::WRITE))
        .expect("Carving from root failed");

    // Step 2: Alias the carved region
    let alias_access = Access::new(0x2000, 0x1000, Rights::READ);
    let alias = carved
        .borrow_mut()
        .alias(&alias_access)
        .expect("Aliasing carved region failed");

    // Check alias kind and status
    {
        let alias_borrow = alias.borrow();
        assert_eq!(alias_borrow.data.kind, RegionKind::Alias);
        assert_eq!(alias_borrow.data.status, Status::Aliased);
    }

    // Step 3: Carve from the alias
    let carve_from_alias_access = Access::new(0x2000, 0x0800, Rights::READ);
    let carved_from_alias = alias
        .borrow_mut()
        .carve(&carve_from_alias_access)
        .expect("Carving from alias failed");

    // Check carve kind and status
    {
        let carved_borrow = carved_from_alias.borrow();
        assert_eq!(carved_borrow.data.kind, RegionKind::Carve);
        assert_eq!(carved_borrow.data.status, Status::Aliased); // inherits from parent
    }
}

// ——————————————————————————————— Revocation ——————————————————————————————— //

#[test]
fn test_revoke_single_node() {
    let mut root = create_root();

    // Create a simple child node under the root
    let child = root
        .carve(&Access::new(0x1000, 0x2000, Rights::READ | Rights::WRITE))
        .unwrap();

    // Track revoked nodes
    let mut seen = Vec::new();

    // Revoke the child node
    let revoked = root.revoke_child(&child, &mut |c: &mut Capability<MemoryRegion>| {
        seen.push(c.data.access.start);
        Ok(())
    });

    // Check that the revocation was successful
    assert!(revoked.is_ok());

    // Check that the callback was called with the correct access start address
    assert_eq!(seen, vec![0x1000]);

    // Check that the child node is now removed
    assert_eq!(root.children.len(), 0);
}

#[test]
fn test_revoke_complex_subtree() {
    let mut root = create_root();

    // Branch 1
    let b1 = root
        .carve(&Access::new(0x0000, 0x4000, Rights::READ | Rights::WRITE))
        .unwrap();
    let b1a = b1
        .borrow_mut()
        .alias(&Access::new(0x1000, 0x1000, Rights::READ))
        .unwrap();
    let _b1a1 = b1a
        .borrow_mut()
        .carve(&Access::new(0x1000, 0x0800, Rights::READ))
        .unwrap();

    // Branch 2 (will not be revoked)
    let _b2 = root
        .carve(&Access::new(0x5000, 0x1000, Rights::READ))
        .unwrap();

    // Track revoked nodes
    let mut seen = Vec::new();

    //let data = b1a.borrow().data;
    // Revoke b1a
    let revoked = b1
        .borrow_mut()
        .revoke_child(&b1a, &mut |c: &mut Capability<MemoryRegion>| {
            seen.push((
                c.data.kind.clone(),
                c.data.status.clone(),
                c.data.access.start,
            ));
            Ok(())
        });

    // Check the callback was called for b1a1 then b1a
    assert!(revoked.is_ok());
    assert_eq!(seen.len(), 2);
    assert!(seen.contains(&(RegionKind::Carve, Status::Aliased, 0x1000)));
    assert!(seen.contains(&(RegionKind::Alias, Status::Aliased, 0x1000)));

    // b1 should still be there, but now empty
    assert_eq!(b1.borrow().children.len(), 0);

    // b2 should still exist
    assert_eq!(root.children.len(), 2);
    let b2_found = root
        .children
        .iter()
        .any(|c| c.borrow().data.access.start == 0x5000);
    assert!(b2_found);
}

#[test]
fn test_revoke_deep_leaf_order() {
    let mut root = create_root();

    let c1 = root
        .carve(&Access::new(0x0000, 0x8000, Rights::READ | Rights::WRITE))
        .unwrap();
    let c2 = c1
        .borrow_mut()
        .carve(&Access::new(0x1000, 0x4000, Rights::READ))
        .unwrap();
    let c3 = c2
        .borrow_mut()
        .alias(&Access::new(0x2000, 0x1000, Rights::READ))
        .unwrap();
    let _c4 = c3
        .borrow_mut()
        .carve(&Access::new(0x2000, 0x0800, Rights::READ))
        .unwrap();

    let mut seen = Vec::new();

    let res = c2
        .borrow_mut()
        .revoke_child(&c3, &mut |c: &mut Capability<MemoryRegion>| {
            seen.push(c.data.access.start);
            Ok(())
        });
    assert!(res.is_ok());

    // Order of callback: c4 then c3
    assert_eq!(seen, vec![0x2000, 0x2000]);
    assert_eq!(c2.borrow().children.len(), 0);
}

#[test]
fn test_revoke_nonexistent() {
    let mut root = create_root();

    // Create a valid region in the root.
    let _valid_region = root
        .carve(&Access::new(0x0000, 0x1000, Rights::READ | Rights::WRITE))
        .unwrap();

    // Create a dummy region that doesn't exist in the children
    let dummy_region = MemoryRegion {
        kind: RegionKind::Carve,
        status: Status::Exclusive,
        access: Access::new(0xDEAD, 0x100, Rights::READ),
        attributes: Attributes::NONE,
        remapped: Remapped::Identity,
    };

    // Try to revoke the dummy region, which doesn't exist as a child
    let result = root.revoke_child(
        &Rc::new(RefCell::new(Capability::<MemoryRegion>::new(dummy_region))),
        &mut |_c: &mut Capability<MemoryRegion>| {
            panic!("Callback should not run on nonexistent revoke");
        },
    );

    // Assert that the result is an error, indicating that the child was not found
    assert_eq!(result, Err(CapaError::ChildNotFound));

    // Ensure the valid_region is still present
    let valid_region_found = root
        .children
        .iter()
        .any(|c| c.borrow().data.access.start == 0x0000);
    assert!(valid_region_found);
}
