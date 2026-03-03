//! Tests for interrupt routing according to instruction.md requirements

use capability_engine::*;

#[test]
fn test_interrupt_routing_walk_upward() {
    // dom0 has deliver for interrupt 6
    // dom1 has report for interrupt 6
    // dom2 has not report (no visibility)
    // dom3 has not report (no visibility)

    let root_domain = Domain::new_root(4);
    let dom0 = Capability::new_root(0, 0, root_domain);

    // Create dom1 with Report policy for vector 6
    let mut dom1_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let mut vector_policy = VectorPolicy::default_report();
    vector_policy.visibility = InterruptVisibility::Report;
    dom1_policy.interrupts.set_policy(6, vector_policy);
    let dom1_h = Capability::create(&dom0, dom1_policy).unwrap();
    let dom1 = dom0.read().data.domain_capabilities[&dom1_h]
        .upgrade()
        .unwrap();
    Capability::seal(&dom0, dom1_h).unwrap();

    // Create dom2 with NotReport policy for vector 6
    let mut dom2_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let mut vector_policy_not_report = VectorPolicy::default_report();
    vector_policy_not_report.visibility = InterruptVisibility::NotReport;
    dom2_policy
        .interrupts
        .set_policy(6, vector_policy_not_report.clone());
    let dom2_h = Capability::create(&dom1, dom2_policy).unwrap();
    let dom2 = dom1.read().data.domain_capabilities[&dom2_h]
        .upgrade()
        .unwrap();
    Capability::seal(&dom1, dom2_h).unwrap();

    // Create dom3 with NotReport policy for vector 6
    let mut dom3_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    dom3_policy
        .interrupts
        .set_policy(6, vector_policy_not_report);
    let dom3_h = Capability::create(&dom2, dom3_policy).unwrap();
    let dom3 = dom2.read().data.domain_capabilities[&dom3_h]
        .upgrade()
        .unwrap();
    Capability::seal(&dom2, dom3_h).unwrap();

    let switch_mgr = SwitchManager::new(4);
    let (handler_id, reported_to) = switch_mgr.route_interrupt(6, &dom3, 0).unwrap();

    assert_eq!(handler_id, 0, "dom0 should be the handler");
    assert_eq!(reported_to.len(), 1, "Only dom1 should be reported to");
    assert_eq!(
        reported_to[0],
        dom1.read().data.id,
        "dom1 should be reported"
    );
}

#[test]
fn test_interrupt_no_handler_found() {
    // Setup: All domains have NotReport, so no handler
    let mut root_domain = Domain::new_root(4);
    let mut vector_policy = VectorPolicy::default_report();
    vector_policy.visibility = InterruptVisibility::NotReport;
    root_domain
        .policy
        .interrupts
        .set_policy(7, vector_policy.clone());
    let dom0 = Capability::new_root(0, 0, root_domain);

    let mut dom1_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    dom1_policy.interrupts.set_policy(7, vector_policy);
    let dom1_h = Capability::create(&dom0, dom1_policy).unwrap();
    let dom1 = dom0.read().data.domain_capabilities[&dom1_h]
        .upgrade()
        .unwrap();
    Capability::seal(&dom0, dom1_h).unwrap();

    let switch_mgr = SwitchManager::new(4);
    let result = switch_mgr.route_interrupt(7, &dom1, 0);
    assert!(result.is_err(), "Should fail when no handler is found");
}

#[test]
fn test_interrupt_immediate_delivery() {
    // If the interrupted domain itself has Deliver policy, it should handle it
    let root_domain = Domain::new_root(4);
    let dom0 = Capability::new_root(0, 0, root_domain);

    let mut dom1_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let mut deliver_policy = VectorPolicy::default_deliver();
    deliver_policy.visibility = InterruptVisibility::Deliver;
    dom1_policy.interrupts.set_policy(5, deliver_policy);
    let dom1_h = Capability::create(&dom0, dom1_policy).unwrap();
    let dom1 = dom0.read().data.domain_capabilities[&dom1_h]
        .upgrade()
        .unwrap();
    Capability::seal(&dom0, dom1_h).unwrap();

    let switch_mgr = SwitchManager::new(4);
    let (handler_id, reported_to) = switch_mgr.route_interrupt(5, &dom1, 0).unwrap();

    assert_eq!(
        handler_id,
        dom1.read().data.id,
        "dom1 should handle its own interrupt"
    );
    assert!(
        reported_to.is_empty(),
        "No domains to report to when handler is the interrupted domain"
    );
}

#[test]
fn test_resume_after_interrupt() {
    // Setup hierarchy with multiple Report domains
    let root_domain = Domain::new_root(4);
    let dom0 = Capability::new_root(0, 0, root_domain);

    let mut dom1_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let mut report_policy = VectorPolicy::default_report();
    report_policy.visibility = InterruptVisibility::Report;
    dom1_policy.interrupts.set_policy(8, report_policy.clone());
    let dom1_h = Capability::create(&dom0, dom1_policy).unwrap();
    let dom1 = dom0.read().data.domain_capabilities[&dom1_h]
        .upgrade()
        .unwrap();
    Capability::seal(&dom0, dom1_h).unwrap();

    let mut dom2_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    dom2_policy.interrupts.set_policy(8, report_policy);
    let dom2_h = Capability::create(&dom1, dom2_policy).unwrap();
    let dom2 = dom1.read().data.domain_capabilities[&dom2_h]
        .upgrade()
        .unwrap();
    Capability::seal(&dom1, dom2_h).unwrap();

    let switch_mgr = SwitchManager::new(4);
    let (handler_id, _) = switch_mgr.route_interrupt(8, &dom2, 0).unwrap();
    assert_eq!(handler_id, 0);

    let notified = switch_mgr.resume_after_interrupt(8, &dom0, &dom2).unwrap();
    assert_eq!(notified.len(), 2, "Both dom1 and dom2 should be notified");
}

#[test]
fn test_mixed_report_and_not_report() {
    // Test a mix of Report and NotReport in the path
    let root_domain = Domain::new_root(4);
    let dom0 = Capability::new_root(0, 0, root_domain);

    // dom1: Report
    let mut dom1_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let mut report_policy = VectorPolicy::default_report();
    report_policy.visibility = InterruptVisibility::Report;
    dom1_policy.interrupts.set_policy(9, report_policy.clone());
    let dom1_h = Capability::create(&dom0, dom1_policy).unwrap();
    let dom1 = dom0.read().data.domain_capabilities[&dom1_h]
        .upgrade()
        .unwrap();
    Capability::seal(&dom0, dom1_h).unwrap();

    // dom2: NotReport
    let mut dom2_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let mut not_report_policy = VectorPolicy::default_report();
    not_report_policy.visibility = InterruptVisibility::NotReport;
    dom2_policy.interrupts.set_policy(9, not_report_policy);
    let dom2_h = Capability::create(&dom1, dom2_policy).unwrap();
    let dom2 = dom1.read().data.domain_capabilities[&dom2_h]
        .upgrade()
        .unwrap();
    Capability::seal(&dom1, dom2_h).unwrap();

    // dom3: Report
    let mut dom3_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    dom3_policy.interrupts.set_policy(9, report_policy);
    let dom3_h = Capability::create(&dom2, dom3_policy).unwrap();
    let dom3 = dom2.read().data.domain_capabilities[&dom3_h]
        .upgrade()
        .unwrap();
    Capability::seal(&dom2, dom3_h).unwrap();

    let switch_mgr = SwitchManager::new(4);
    let (handler_id, reported_to) = switch_mgr.route_interrupt(9, &dom3, 0).unwrap();

    assert_eq!(handler_id, 0);
    // Should report to dom3 and dom1, but NOT dom2 (it has NotReport)
    assert_eq!(reported_to.len(), 2);
    assert!(reported_to.contains(&dom3.read().data.id));
    assert!(reported_to.contains(&dom1.read().data.id));
    assert!(!reported_to.contains(&dom2.read().data.id));
}
