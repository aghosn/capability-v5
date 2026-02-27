//! Tests for update batch operations

use capability_engine::*;
use std::sync::Arc;

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

    if let Update::RevokeDomain { domain, .. } = &updates[0] {
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
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);
    let total_mem = MemoryRegion::new_root(0x0, 0x10000);
    let mem_root = Capability::new_root(0, 1, total_mem);
    root.write().data.add_memory_capability(1, Arc::downgrade(&mem_root));

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_child_h, _child_sub, updates) = Capability::carve_memory(&root, 1, child_access).unwrap();

    // Carve with same owner generates NO updates
    assert!(updates.is_empty());
}

#[test]
fn test_revoke_generates_updates() {
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);
    let total_mem = MemoryRegion::new_root(0x0, 0x10000);
    let mem_root = Capability::new_root(0, 1, total_mem);
    root.write().data.add_memory_capability(1, Arc::downgrade(&mem_root));

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_child_h, child_sub, _) = Capability::carve_memory(&root, 1, child_access).unwrap();

    let updates = Capability::revoke_memory_child(&root, 1, child_sub).unwrap();

    // Should NOT generate updates because parent never lost access (same owner)
    assert!(updates.is_empty());
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
