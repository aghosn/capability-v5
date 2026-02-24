//! Tests for update batch operations

use capability_engine::*;

// ==================== Basic Update Operations ====================

#[test]
fn test_update_batch() {
    let mut batch = UpdateBatch::new();
    batch.add_unmap(1, 0x1000, 0x1000);
    batch.add_map(2, 0x2000, 0x1000, 0x10000, true, true, false);

    assert_eq!(batch.len(), 2);
    assert_eq!(batch.affected_domains().len(), 2);
    assert!(batch.affected_domains().contains(&1));
    assert!(batch.affected_domains().contains(&2));
}

#[test]
fn test_merge_batches() {
    let mut batch1 = UpdateBatch::new();
    batch1.add_unmap(1, 0x1000, 0x1000);

    let mut batch2 = UpdateBatch::new();
    batch2.add_map(2, 0x2000, 0x1000, 0x10000, true, false, false);

    batch1.merge(batch2);
    assert_eq!(batch1.len(), 2);
    assert_eq!(batch1.affected_domains().len(), 2);
}

#[test]
fn test_empty_batch() {
    let batch = UpdateBatch::new();
    assert!(batch.is_empty());
    assert_eq!(batch.len(), 0);
    assert_eq!(batch.affected_domains().len(), 0);
}

#[test]
fn test_batch_clear() {
    let mut batch = UpdateBatch::new();
    batch.add_unmap(1, 0x1000, 0x1000);
    batch.add_map(2, 0x2000, 0x1000, 0x10000, true, true, false);

    assert!(!batch.is_empty());

    batch.clear();

    assert!(batch.is_empty());
    assert_eq!(batch.len(), 0);
    assert_eq!(batch.affected_domains().len(), 0);
}

// ==================== Update Types ====================

#[test]
fn test_unmap_update() {
    let mut batch = UpdateBatch::new();
    batch.add_unmap(5, 0x1000, 0x2000);

    let updates = batch.updates();
    assert_eq!(updates.len(), 1);

    if let Update::Unmap { domain, address, size } = &updates[0] {
        assert_eq!(*domain, 5);
        assert_eq!(*address, 0x1000);
        assert_eq!(*size, 0x2000);
    } else {
        panic!("Expected Unmap update");
    }
}

#[test]
fn test_map_update() {
    let mut batch = UpdateBatch::new();
    batch.add_map(10, 0x3000, 0x1000, 0x50000, true, false, true);

    let updates = batch.updates();
    assert_eq!(updates.len(), 1);

    if let Update::Map {
        domain,
        address,
        size,
        physical,
        read,
        write,
        execute,
    } = &updates[0]
    {
        assert_eq!(*domain, 10);
        assert_eq!(*address, 0x3000);
        assert_eq!(*size, 0x1000);
        assert_eq!(*physical, 0x50000);
        assert_eq!(*read, true);
        assert_eq!(*write, false);
        assert_eq!(*execute, true);
    } else {
        panic!("Expected Map update");
    }
}

#[test]
fn test_revoke_domain_update() {
    let mut batch = UpdateBatch::new();
    batch.add_revoke_domain(7);

    let updates = batch.updates();
    assert_eq!(updates.len(), 1);

    if let Update::RevokeDomain { domain } = &updates[0] {
        assert_eq!(*domain, 7);
    } else {
        panic!("Expected RevokeDomain update");
    }

    assert!(batch.affected_domains().contains(&7));
}

#[test]
fn test_zero_memory_update() {
    let mut batch = UpdateBatch::new();
    batch.add_zero_memory(0x8000, 0x2000);

    let updates = batch.updates();
    assert_eq!(updates.len(), 1);

    if let Update::ZeroMemory { address, size } = &updates[0] {
        assert_eq!(*address, 0x8000);
        assert_eq!(*size, 0x2000);
    } else {
        panic!("Expected ZeroMemory update");
    }

    // ZeroMemory doesn't affect a specific domain
    assert_eq!(batch.affected_domains().len(), 0);
}

// ==================== Multiple Updates ====================

#[test]
fn test_multiple_updates_same_domain() {
    let mut batch = UpdateBatch::new();

    batch.add_unmap(1, 0x1000, 0x1000);
    batch.add_unmap(1, 0x2000, 0x1000);
    batch.add_map(1, 0x3000, 0x1000, 0x10000, true, true, false);

    assert_eq!(batch.len(), 3);
    assert_eq!(batch.affected_domains().len(), 1);
    assert!(batch.affected_domains().contains(&1));
}

#[test]
fn test_multiple_updates_different_domains() {
    let mut batch = UpdateBatch::new();

    batch.add_unmap(1, 0x1000, 0x1000);
    batch.add_map(2, 0x2000, 0x1000, 0x10000, true, false, false);
    batch.add_revoke_domain(3);

    assert_eq!(batch.len(), 3);
    assert_eq!(batch.affected_domains().len(), 3);
    assert!(batch.affected_domains().contains(&1));
    assert!(batch.affected_domains().contains(&2));
    assert!(batch.affected_domains().contains(&3));
}

// ==================== Updates from Capability Operations ====================

#[test]
fn test_carve_generates_updates() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_child, updates) = Capability::carve_child(&root, child_access, 1, 1).unwrap();

    // Should generate unmap for parent
    assert!(!updates.is_empty());
    assert!(updates.affected_domains().contains(&0)); // Parent domain 0
}

#[test]
fn test_send_generates_updates() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child, _) = Capability::carve_child(&root, child_access, 0, 1).unwrap();

    let updates = Capability::send_to(&child, 5, 10, Attributes::NONE).unwrap();

    // Should have updates for both old and new owner
    assert!(!updates.is_empty());
    assert!(updates.len() >= 2); // Unmap from 0, map to 5
}

#[test]
fn test_revoke_generates_updates() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_child, _) = Capability::carve_child(&root, child_access, 1, 1).unwrap();

    let updates = Capability::revoke_child(&root, 1).unwrap();

    // Should generate updates for restoring access to parent
    assert!(!updates.is_empty());
}

#[test]
fn test_vital_revoke_generates_domain_revocation() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child, _) = Capability::carve_child(&root, child_access, 5, 1).unwrap();

    // Set vital attribute
    child.write().data.attributes.vital = true;

    let updates = Capability::revoke_child(&root, 1).unwrap();

    // Should include domain revocation update
    let has_domain_revoke = updates.updates().iter().any(|u| {
        matches!(u, Update::RevokeDomain { domain } if *domain == 5)
    });
    assert!(has_domain_revoke);
}

#[test]
fn test_clean_revoke_generates_zero_memory() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root = Capability::new_root(0, 0, root_region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child, _) = Capability::carve_child(&root, child_access, 5, 1).unwrap();

    // Set clean attribute
    child.write().data.attributes.clean = true;

    let updates = Capability::revoke_child(&root, 1).unwrap();

    // Should include zero memory update
    let has_zero = updates.updates().iter().any(|u| {
        matches!(u, Update::ZeroMemory { address, size }
            if *address == 0x1000 && *size == 0x1000)
    });
    assert!(has_zero);
}

// ==================== Update Affected Domain Tracking ====================

#[test]
fn test_affected_domain_tracking() {
    let mut batch = UpdateBatch::new();

    // Add updates for different domains
    batch.add_unmap(1, 0x1000, 0x1000);
    batch.add_map(2, 0x2000, 0x1000, 0x10000, true, false, false);
    batch.add_revoke_domain(3);
    batch.add_zero_memory(0x5000, 0x1000); // No domain

    assert_eq!(batch.affected_domains().len(), 3);

    // Verify each domain is tracked
    assert!(batch.affected_domains().contains(&1));
    assert!(batch.affected_domains().contains(&2));
    assert!(batch.affected_domains().contains(&3));
}

#[test]
fn test_merge_combines_affected_domains() {
    let mut batch1 = UpdateBatch::new();
    batch1.add_unmap(1, 0x1000, 0x1000);
    batch1.add_unmap(2, 0x2000, 0x1000);

    let mut batch2 = UpdateBatch::new();
    batch2.add_map(3, 0x3000, 0x1000, 0x10000, true, false, false);
    batch2.add_map(4, 0x4000, 0x1000, 0x20000, true, false, false);

    batch1.merge(batch2);

    assert_eq!(batch1.affected_domains().len(), 4);
    assert!(batch1.affected_domains().contains(&1));
    assert!(batch1.affected_domains().contains(&2));
    assert!(batch1.affected_domains().contains(&3));
    assert!(batch1.affected_domains().contains(&4));
}
