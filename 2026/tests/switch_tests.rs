//! Tests for domain switching and interrupt routing

use capability_engine::*;
use std::sync::Arc;

// ==================== Core Context Tests ====================

#[test]
fn test_core_context() {
    let ctx = CoreContext::new(0);
    assert_eq!(ctx.current_domain(), None);

    *ctx.state.write() = CoreState::Running(1);
    assert_eq!(ctx.current_domain(), Some(1));
}

#[test]
fn test_core_can_run_domain() {
    let ctx = CoreContext::new(2); // Core 2

    let mut policy = DomainPolicy::new_root(4);
    policy.cores = 0b0100; // Only core 2
    let domain = Domain::new(policy);

    assert!(ctx.can_run_domain(&domain));
}

#[test]
fn test_core_cannot_run_domain() {
    let ctx = CoreContext::new(3); // Core 3

    let mut policy = DomainPolicy::new_root(4);
    policy.cores = 0b0011; // Only cores 0 and 1
    let domain = Domain::new(policy);

    assert!(!ctx.can_run_domain(&domain));
}

// ==================== Switch Manager Tests ====================

#[test]
fn test_switch_manager() {
    let mgr = SwitchManager::new(4);
    assert!(mgr.get_core(0).is_ok());
    assert!(mgr.get_core(3).is_ok());
    assert!(mgr.get_core(4).is_err());
}

#[test]
fn test_switch_manager_core_count() {
    let mgr = SwitchManager::new(8);

    for i in 0..8 {
        assert!(mgr.get_core(i).is_ok());
    }

    assert!(mgr.get_core(8).is_err());
    assert!(mgr.get_core(100).is_err());
}

// ==================== Domain Switching Tests ====================

#[test]
fn test_domain_switch() {
    let mgr = SwitchManager::new(1);

    // Use new_root() to get domain ID 0
    let parent_domain = Domain::new_root(4);
    let parent = Capability::new_root(0, 0, parent_domain);

    let child_policy = DomainPolicy::new_restricted(0b1, MonitorAPI::NONE);
    let child_domain = Domain::new(child_policy);
    let mut child_domain = child_domain;
    child_domain.seal().unwrap();
    let child = Capability::new_child(1, 1, child_domain, Arc::downgrade(&parent));
    parent.write().add_child(child.clone());

    // Get the actual domain IDs
    let parent_id = parent.read().data.id;
    let child_id = child.read().data.id;

    // Set parent as running on core 0
    let core = mgr.get_core(0).unwrap();
    *core.state.write() = CoreState::Running(parent_id);

    // Switch to child
    let switch_ctx = mgr.switch(0, &parent, Some(&child)).unwrap();
    assert_eq!(switch_ctx.from_domain, parent_id);
    assert_eq!(switch_ctx.to_domain, child_id);
    assert!(!switch_ctx.is_return);
}

#[test]
fn test_switch_to_unsealed_fails() {
    let mgr = SwitchManager::new(1);

    let parent_domain = Domain::new_root(4);
    let parent = Capability::new_root(0, 0, parent_domain);

    let child_policy = DomainPolicy::new_restricted(0b1, MonitorAPI::NONE);
    let child_domain = Domain::new(child_policy);
    // Note: NOT sealing the child
    let child = Capability::new_child(1, 1, child_domain, Arc::downgrade(&parent));
    parent.write().add_child(child.clone());

    let parent_id = parent.read().data.id;

    // Set parent as running
    let core = mgr.get_core(0).unwrap();
    *core.state.write() = CoreState::Running(parent_id);

    // Switch should fail because child is not sealed
    let result = mgr.switch(0, &parent, Some(&child));
    assert!(result.is_err());
}

#[test]
fn test_switch_without_permission_fails() {
    let mgr = SwitchManager::new(2);

    let parent_domain = Domain::new_root(4);
    let parent = Capability::new_root(0, 0, parent_domain);

    // Child can only run on core 0
    let child_policy = DomainPolicy::new_restricted(0b01, MonitorAPI::NONE);
    let child_domain = Domain::new(child_policy);
    let mut child_domain = child_domain;
    child_domain.seal().unwrap();
    let child = Capability::new_child(1, 1, child_domain, Arc::downgrade(&parent));
    parent.write().add_child(child.clone());

    let parent_id = parent.read().data.id;

    // Set parent as running on core 1
    let core = mgr.get_core(1).unwrap();
    *core.state.write() = CoreState::Running(parent_id);

    // Switch should fail because child cannot run on core 1
    let result = mgr.switch(1, &parent, Some(&child));
    assert!(result.is_err());
}

#[test]
fn test_switch_not_running_fails() {
    let mgr = SwitchManager::new(1);

    let parent_domain = Domain::new_root(4);
    let parent = Capability::new_root(0, 0, parent_domain);

    let child_policy = DomainPolicy::new_restricted(0b1, MonitorAPI::NONE);
    let child_domain = Domain::new(child_policy);
    let mut child_domain = child_domain;
    child_domain.seal().unwrap();
    let child = Capability::new_child(1, 1, child_domain, Arc::downgrade(&parent));
    parent.write().add_child(child.clone());

    // Note: NOT setting parent as running

    // Switch should fail because parent is not running on this core
    let result = mgr.switch(0, &parent, Some(&child));
    assert!(result.is_err());
}

#[test]
fn test_return_to_parent() {
    let mgr = SwitchManager::new(1);

    let parent_domain = Domain::new_root(4);
    let parent = Capability::new_root(0, 0, parent_domain);

    let child_policy = DomainPolicy::new_restricted(0b1, MonitorAPI::NONE);
    let child_domain = Domain::new(child_policy);
    let mut child_domain = child_domain;
    child_domain.seal().unwrap();
    let child = Capability::new_child(1, 1, child_domain, Arc::downgrade(&parent));
    parent.write().add_child(child.clone());

    let parent_id = parent.read().data.id;
    let child_id = child.read().data.id;

    // Set parent as running
    let core = mgr.get_core(0).unwrap();
    *core.state.write() = CoreState::Running(parent_id);

    // Switch to child
    mgr.switch(0, &parent, Some(&child)).unwrap();

    // Now return to parent (switch with None)
    *core.state.write() = CoreState::Running(child_id);
    let switch_ctx = mgr.switch(0, &child, None).unwrap();

    assert_eq!(switch_ctx.from_domain, child_id);
    assert_eq!(switch_ctx.to_domain, parent_id);
    assert!(switch_ctx.is_return);
}

// ==================== Interrupt Routing Tests ====================

#[test]
fn test_interrupt_delivery_to_domain() {
    let mgr = SwitchManager::new(1);

    // Domain configured to deliver vector 32
    let mut policy = DomainPolicy::new_root(4);
    policy.interrupts.set_policy(32, VectorPolicy::default_deliver());
    let domain = Domain::new(policy);
    let domain_ref = Capability::new_root(0, 0, domain);

    let (handler_id, reported) = mgr.route_interrupt(32, &domain_ref, 0).unwrap();

    assert_eq!(handler_id, domain_ref.read().data.id);
    assert!(reported.is_empty()); // No reporting, just delivery
}

#[test]
fn test_interrupt_report_to_parent() {
    let mgr = SwitchManager::new(1);

    // Parent delivers vector 32
    let mut parent_policy = DomainPolicy::new_root(4);
    parent_policy.interrupts.set_policy(32, VectorPolicy::default_deliver());
    let parent_domain = Domain::new(parent_policy);
    let parent_ref = Capability::new_root(0, 0, parent_domain);

    // Child reports vector 32
    let mut child_policy = DomainPolicy::new_root(4);
    child_policy.interrupts.set_policy(32, VectorPolicy::default_report());
    let child_domain = Domain::new(child_policy);
    let child_ref = Capability::new_child(1, 1, child_domain, Arc::downgrade(&parent_ref));
    parent_ref.write().add_child(child_ref.clone());

    let child_id = child_ref.read().data.id;
    let parent_id = parent_ref.read().data.id;

    // Interrupt from child should report to child and deliver to parent
    let (handler_id, reported) = mgr.route_interrupt(32, &child_ref, 0).unwrap();

    assert_eq!(handler_id, parent_id); // Parent handles it
    assert_eq!(reported, vec![child_id]); // Child was reported to
}

#[test]
fn test_interrupt_no_handler() {
    let mgr = SwitchManager::new(1);

    // Domain configured to NOT report and NOT deliver (essentially ignores)
    let mut policy = DomainPolicy::new_root(4);
    policy.interrupts.default = VectorPolicy {
        visibility: InterruptVisibility::NotReport,
        read_set: 0,
        write_set: 0,
    };
    let domain = Domain::new(policy);
    let domain_ref = Capability::new_root(0, 0, domain);

    // Root domain with no handler should fail
    let result = mgr.route_interrupt(32, &domain_ref, 0);

    assert!(result.is_err());
}

// ==================== Resume After Interrupt ====================

#[test]
fn test_resume_after_interrupt() {
    let mgr = SwitchManager::new(1);

    // Parent delivers
    let mut parent_policy = DomainPolicy::new_root(4);
    parent_policy.interrupts.set_policy(32, VectorPolicy::default_deliver());
    let parent_domain = Domain::new(parent_policy);
    let parent_ref = Capability::new_root(0, 0, parent_domain);

    // Child reports
    let mut child_policy = DomainPolicy::new_root(4);
    child_policy.interrupts.set_policy(32, VectorPolicy::default_report());
    let child_domain = Domain::new(child_policy);
    let child_ref = Capability::new_child(1, 1, child_domain, Arc::downgrade(&parent_ref));
    parent_ref.write().add_child(child_ref.clone());

    let child_id = child_ref.read().data.id;

    // Resume from parent back to child
    let notified = mgr.resume_after_interrupt(32, &parent_ref, &child_ref).unwrap();

    // Child should be notified on the way back
    assert_eq!(notified, vec![child_id]);
}

// ==================== Multi-Level Interrupt Routing ====================

#[test]
fn test_multi_level_interrupt_routing() {
    let mgr = SwitchManager::new(1);

    // Root delivers
    let mut root_policy = DomainPolicy::new_root(4);
    root_policy.interrupts.set_policy(40, VectorPolicy::default_deliver());
    let root_domain = Domain::new(root_policy);
    let root_ref = Capability::new_root(0, 0, root_domain);

    // Level 1 reports
    let mut l1_policy = DomainPolicy::new_root(4);
    l1_policy.interrupts.set_policy(40, VectorPolicy::default_report());
    let l1_domain = Domain::new(l1_policy);
    let l1_ref = Capability::new_child(1, 1, l1_domain, Arc::downgrade(&root_ref));
    root_ref.write().add_child(l1_ref.clone());

    // Level 2 reports
    let mut l2_policy = DomainPolicy::new_root(4);
    l2_policy.interrupts.set_policy(40, VectorPolicy::default_report());
    let l2_domain = Domain::new(l2_policy);
    let l2_ref = Capability::new_child(2, 2, l2_domain, Arc::downgrade(&l1_ref));
    l1_ref.write().add_child(l2_ref.clone());

    let root_id = root_ref.read().data.id;
    let l1_id = l1_ref.read().data.id;
    let l2_id = l2_ref.read().data.id;

    // Interrupt from L2 should report to L2 and L1, then deliver to root
    let (handler_id, reported) = mgr.route_interrupt(40, &l2_ref, 0).unwrap();

    assert_eq!(handler_id, root_id);
    assert_eq!(reported, vec![l2_id, l1_id]);
}
