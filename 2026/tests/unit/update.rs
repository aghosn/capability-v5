//! Tests for update batch operations

use capability_engine::memory::Rights;
use capability_engine::*;

// ==================== Basic Update Operations ====================

#[test]
fn test_update_batch() {
    let mut batch = UpdateBatch::new();
    batch.add_change_rights(1, 0x1000, 0x1000, 0x1000, Rights::NONE, true);
    batch.add_change_rights(2, 0x2000, 0x1000, 0x10000, Rights::RW, false);

    assert_eq!(batch.len(), 2);
    assert_eq!(batch.affected_domains().len(), 2);
    assert!(batch.affected_domains().contains(&1));
    assert!(batch.affected_domains().contains(&2));
}

#[test]
fn test_merge_batches() {
    let mut batch1 = UpdateBatch::new();
    batch1.add_change_rights(1, 0x1000, 0x1000, 0x1000, Rights::NONE, true);

    let mut batch2 = UpdateBatch::new();
    batch2.add_change_rights(2, 0x2000, 0x1000, 0x10000, Rights::R, false);

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
    batch.add_change_rights(1, 0x1000, 0x1000, 0x1000, Rights::NONE, true);
    batch.add_change_rights(2, 0x2000, 0x1000, 0x10000, Rights::RW, false);

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
    batch.add_change_rights(5, 0x1000, 0x2000, 0x1000, Rights::NONE, true);

    let updates = batch.updates();
    assert_eq!(updates.len(), 1);

    if let Update::ChangeRights {
        domain,
        address,
        size,
        rights,
        ..
    } = &updates[0]
    {
        assert_eq!(*domain, 5);
        assert_eq!(*address, 0x1000);
        assert_eq!(*size, 0x2000);
        assert_eq!(*rights, Rights::NONE);
    } else {
        panic!("Expected ChangeRights update");
    }
}

#[test]
fn test_map_update() {
    let mut batch = UpdateBatch::new();
    batch.add_change_rights(10, 0x3000, 0x1000, 0x50000, Rights::RX, false);

    let updates = batch.updates();
    assert_eq!(updates.len(), 1);

    if let Update::ChangeRights {
        domain,
        address,
        size,
        physical,
        rights,
        shootdown_required,
        ..
    } = &updates[0]
    {
        assert_eq!(*domain, 10);
        assert_eq!(*address, 0x3000);
        assert_eq!(*size, 0x1000);
        assert_eq!(*physical, 0x50000);
        assert_eq!(rights.read(), true);
        assert_eq!(rights.write(), false);
        assert_eq!(rights.execute(), true);
        assert_eq!(*shootdown_required, false);
    } else {
        panic!("Expected ChangeRights update");
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

    batch.add_change_rights(1, 0x1000, 0x1000, 0x1000, Rights::NONE, true);
    batch.add_change_rights(1, 0x2000, 0x1000, 0x2000, Rights::NONE, true);
    batch.add_change_rights(1, 0x3000, 0x1000, 0x10000, Rights::RW, false);

    assert_eq!(batch.len(), 3);
    assert_eq!(batch.affected_domains().len(), 1);
    assert!(batch.affected_domains().contains(&1));
}

#[test]
fn test_multiple_updates_different_domains() {
    let mut batch = UpdateBatch::new();

    batch.add_change_rights(1, 0x1000, 0x1000, 0x1000, Rights::NONE, true);
    batch.add_change_rights(2, 0x2000, 0x1000, 0x10000, Rights::R, false);
    batch.add_revoke_domain(3);

    assert_eq!(batch.len(), 3);
    assert_eq!(batch.affected_domains().len(), 3);
    assert!(batch.affected_domains().contains(&1));
    assert!(batch.affected_domains().contains(&2));
    assert!(batch.affected_domains().contains(&3));
}

// ==================== Update Affected Domain Tracking ====================

#[test]
fn test_affected_domain_tracking() {
    let mut batch = UpdateBatch::new();

    // Add updates for different domains
    batch.add_change_rights(1, 0x1000, 0x1000, 0x1000, Rights::NONE, true);
    batch.add_change_rights(2, 0x2000, 0x1000, 0x10000, Rights::R, false);
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
    batch1.add_change_rights(1, 0x1000, 0x1000, 0x1000, Rights::NONE, true);
    batch1.add_change_rights(2, 0x2000, 0x1000, 0x2000, Rights::NONE, true);

    let mut batch2 = UpdateBatch::new();
    batch2.add_change_rights(3, 0x3000, 0x1000, 0x10000, Rights::R, false);
    batch2.add_change_rights(4, 0x4000, 0x1000, 0x20000, Rights::R, false);

    batch1.merge(batch2);

    assert_eq!(batch1.affected_domains().len(), 4);
    assert!(batch1.affected_domains().contains(&1));
    assert!(batch1.affected_domains().contains(&2));
    assert!(batch1.affected_domains().contains(&3));
    assert!(batch1.affected_domains().contains(&4));
}

// ==================== UpdateProcessor ====================

fn make_batch_for_domain(domain_id: DomainId) -> UpdateBatch {
    let mut b = UpdateBatch::new();
    b.add_change_rights(domain_id, 0x1000, 0x1000, 0x1000, capability_engine::memory::Rights::NONE, true);
    b
}

#[test]
fn test_update_processor_register_and_lookup_domain_core() {
    let proc = UpdateProcessor::new();
    proc.register_domain_on_core(1, 0);
    assert_eq!(proc.get_domain_core(1), Some(0));

    proc.unregister_domain(1);
    assert_eq!(proc.get_domain_core(1), None);
}

#[test]
fn test_submit_updates_routes_to_correct_core() {
    let proc = UpdateProcessor::new();
    proc.register_domain_on_core(42, 3); // domain 42 runs on core 3

    let batch = make_batch_for_domain(42);
    let cores = proc.submit_updates(batch);

    assert_eq!(cores.len(), 1);
    assert!(cores.contains(&3), "batch must be routed to core 3");

    let pending = proc.get_pending_updates(3);
    assert_eq!(pending.len(), 1);
    assert!(matches!(pending[0].status, UpdateStatus::Pending));
}

#[test]
fn test_submit_updates_unaffected_core_gets_nothing() {
    let proc = UpdateProcessor::new();
    proc.register_domain_on_core(10, 0);

    let batch = make_batch_for_domain(99); // domain 99 not running anywhere
    let cores = proc.submit_updates(batch);
    assert!(cores.is_empty(), "no cores should be notified for an idle domain");
    assert!(proc.get_pending_updates(0).is_empty());
}

#[test]
fn test_mark_in_progress_transitions_pending() {
    let proc = UpdateProcessor::new();
    proc.register_domain_on_core(1, 0);
    proc.submit_updates(make_batch_for_domain(1));

    assert!(proc.mark_in_progress(0, 0), "mark_in_progress must return true for a Pending entry");

    let updates = proc.get_pending_updates(0);
    assert!(updates.is_empty(), "InProgress entry must not appear in get_pending_updates");
}

#[test]
fn test_mark_in_progress_idempotent_on_non_pending() {
    let proc = UpdateProcessor::new();
    proc.register_domain_on_core(1, 0);
    proc.submit_updates(make_batch_for_domain(1));

    proc.mark_in_progress(0, 0);
    // Second mark_in_progress on the same index must return false (already InProgress).
    assert!(!proc.mark_in_progress(0, 0));
}

#[test]
fn test_mark_completed_and_clean() {
    let proc = UpdateProcessor::new();
    proc.register_domain_on_core(1, 0);
    proc.submit_updates(make_batch_for_domain(1));

    proc.mark_in_progress(0, 0);
    assert!(proc.mark_completed(0, 0));

    // Entry is Completed — still in queue until clean_completed.
    assert!(!proc.has_pending_updates(0));

    proc.clean_completed(0);
    // Queue is empty after clean.
    assert!(proc.get_pending_updates(0).is_empty());
}

#[test]
fn test_has_pending_updates() {
    let proc = UpdateProcessor::new();
    proc.register_domain_on_core(1, 0);

    assert!(!proc.has_pending_updates(0));
    proc.submit_updates(make_batch_for_domain(1));
    assert!(proc.has_pending_updates(0));

    proc.mark_in_progress(0, 0);
    assert!(!proc.has_pending_updates(0)); // InProgress is not Pending
}

#[test]
fn test_get_cores_with_pending_updates() {
    let proc = UpdateProcessor::new();
    proc.register_domain_on_core(1, 0);
    proc.register_domain_on_core(2, 1);

    proc.submit_updates(make_batch_for_domain(1)); // → core 0
    proc.submit_updates(make_batch_for_domain(2)); // → core 1

    let cores = proc.get_cores_with_pending_updates();
    assert_eq!(cores.len(), 2);
    assert!(cores.contains(&0));
    assert!(cores.contains(&1));

    // Mark core 0's update in-progress — it should drop from the list.
    proc.mark_in_progress(0, 0);
    let cores = proc.get_cores_with_pending_updates();
    assert_eq!(cores.len(), 1);
    assert!(cores.contains(&1));
}

#[test]
fn test_multiple_batches_same_core_ordered() {
    let proc = UpdateProcessor::new();
    proc.register_domain_on_core(1, 0);

    proc.submit_updates(make_batch_for_domain(1));
    proc.submit_updates(make_batch_for_domain(1));

    let pending = proc.get_pending_updates(0);
    assert_eq!(pending.len(), 2, "both batches must be queued in order");
}
