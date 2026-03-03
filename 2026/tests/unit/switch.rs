//! Tests for domain switching (VP-aware) and interrupt routing
//!
//! Domain switching is exclusively tested via `Capability::switch` —
//! the unified VP-aware domain-mediated API (handle=0 = return to caller).
//! `SwitchManager::switch` is infrastructure; only interrupt routing tests use it directly.

use capability_engine::*;
use std::sync::Arc;

#[path = "../common/mod.rs"]
mod common;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Initialise a domain's VP[vp_id] to `Running { core, caller: None }`.
fn init_vp_running(domain: &CapabilityRef<Domain>, vp_id: usize, core: u64) {
    let d = domain.read();
    let vp = d.data.policy.vprocessor_states[vp_id].clone();
    drop(d);
    *vp.run_state.write() = VpRunState::Running { core, caller: None };
}

/// Build a sealed child domain inside `parent`, returning `(child_ref, child_handle)`.
/// Child gets `MonitorAPI::ALL` (includes SWITCH) and all 4 cores.
fn make_sealed_child(parent: &CapabilityRef<Domain>) -> (CapabilityRef<Domain>, LocalHandle) {
    let policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let h = Capability::create(parent, policy).unwrap();
    Capability::seal(parent, h).unwrap();
    let child = parent.read().data.domain_capabilities[&h]
        .upgrade()
        .unwrap();
    (child, h)
}

/// Standard test fixture: root (4 VPs, VP[0] Running on core 0) + one sealed child.
fn fixture() -> (
    CapabilityRef<Domain>,
    CapabilityRef<Domain>,
    LocalHandle,
    common::TestPlatform,
) {
    let platform = common::TestPlatform::new();

    let root = Capability::new_root(0, 0, Domain::new_root(4));
    let root_id = root.read().data.id;
    platform.register_domain(root_id, None);
    platform.set_core_domain(0, root_id);
    platform.set_current_core(Some(0));

    // VP[0] of root is Running on core 0
    init_vp_running(&root, 0, 0);
    platform.set_core_vp(0, Some(0));

    let (child, child_h) = make_sealed_child(&root);
    let child_id = child.read().data.id;
    platform.register_domain(child_id, Some(root_id));

    (root, child, child_h, platform)
}

// ── CoreContext infrastructure tests (unchanged) ─────────────────────────────

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

// ── VP-aware domain switching (positive cases) ───────────────────────────────

/// Basic switch from root VP[0] → child VP[0], then check context.
#[test]
fn test_vp_switch_domain_basic() {
    let (root, child, child_h, platform) = fixture();

    let root_id = root.read().data.id;
    let child_id = child.read().data.id;

    let ctx = Capability::switch(&root, child_h, 0, &platform).unwrap();

    assert_eq!(ctx.from_domain, root_id);
    assert_eq!(ctx.to_domain, child_id);
    assert_eq!(ctx.core_id, 0);
    assert!(!ctx.is_return);
    assert_eq!(ctx.from_vp_id, Some(0));
    assert_eq!(ctx.to_vp_id, Some(0));
}

/// switch followed by return_domain restores original domain.
#[test]
fn test_vp_return_domain_basic() {
    let (root, child, child_h, platform) = fixture();

    let root_id = root.read().data.id;
    let child_id = child.read().data.id;

    // Switch root → child VP[0]
    Capability::switch(&root, child_h, 0, &platform).unwrap();

    // Now platform says core 0 is running child; child VP[0] is Running{caller=root.VP[0]}
    let ret_ctx = Capability::switch(&child, 0, 0, &platform).unwrap();

    assert_eq!(ret_ctx.from_domain, child_id);
    assert_eq!(ret_ctx.to_domain, root_id);
    assert!(ret_ctx.is_return);
    assert_eq!(ret_ctx.from_vp_id, Some(0));
    assert_eq!(ret_ctx.to_vp_id, Some(0));
}

/// After return, root VP[0] is Available and can switch again.
#[test]
fn test_vp_switch_return_switch_again() {
    let (root, child, child_h, platform) = fixture();

    Capability::switch(&root, child_h, 0, &platform).unwrap();
    Capability::switch(&child, 0, 0, &platform).unwrap();

    // Root VP[0] should be Running again; switch one more time
    let ctx = Capability::switch(&root, child_h, 0, &platform).unwrap();
    assert_eq!(ctx.to_vp_id, Some(0));
}

/// Two-level switch chain: root → child → grandchild, then unwind both.
#[test]
fn test_vp_nested_switch_and_return() {
    let platform = common::TestPlatform::new();

    let root = Capability::new_root(0, 0, Domain::new_root(4));
    let root_id = root.read().data.id;
    platform.register_domain(root_id, None);
    platform.set_core_domain(0, root_id);
    platform.set_current_core(Some(0));
    init_vp_running(&root, 0, 0);
    platform.set_core_vp(0, Some(0));

    // child1 under root
    let child1_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let child1_h = Capability::create(&root, child1_policy).unwrap();
    Capability::seal(&root, child1_h).unwrap();
    let child1 = root.read().data.domain_capabilities[&child1_h]
        .upgrade()
        .unwrap();
    let child1_id = child1.read().data.id;
    platform.register_domain(child1_id, Some(root_id));

    // child2 under child1
    let child2_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let child2_h = Capability::create(&child1, child2_policy).unwrap();
    Capability::seal(&child1, child2_h).unwrap();
    let child2 = child1.read().data.domain_capabilities[&child2_h]
        .upgrade()
        .unwrap();
    let child2_id = child2.read().data.id;
    platform.register_domain(child2_id, Some(child1_id));

    // root → child1
    Capability::switch(&root, child1_h, 0, &platform).unwrap();

    // child1 VP[0] needs to be Running on core 0 for its own switch
    // (switch sets child1 VP[0] to Running when root switches into it)

    // child1 → child2
    let ctx12 = Capability::switch(&child1, child2_h, 0, &platform).unwrap();
    assert_eq!(ctx12.to_domain, child2_id);

    // return child2 → child1
    let ret1 = Capability::switch(&child2, 0, 0, &platform).unwrap();
    assert_eq!(ret1.to_domain, child1_id);

    // return child1 → root
    let ret0 = Capability::switch(&child1, 0, 0, &platform).unwrap();
    assert_eq!(ret0.to_domain, root_id);
}

// ── VP-aware domain switching (adversarial / error cases) ────────────────────

/// switch fails when no VP in the caller domain is Running on the current core.
#[test]
fn test_vp_switch_no_vp_running_on_core() {
    let platform = common::TestPlatform::new();

    let root = Capability::new_root(0, 0, Domain::new_root(4));
    let root_id = root.read().data.id;
    platform.register_domain(root_id, None);
    // VP[0] stays Available — not Running
    platform.set_current_core(Some(0));

    let (_, child_h) = make_sealed_child(&root);

    let result = Capability::switch(&root, child_h, 0, &platform);
    assert!(result.is_err(), "expected error when no VP running on core");
}

/// switch fails when the target VP is already Running (not Available).
#[test]
fn test_vp_switch_target_not_available() {
    let (root, child, child_h, platform) = fixture();

    // Claim child VP[0] first
    Capability::switch(&root, child_h, 0, &platform).unwrap();
    Capability::switch(&child, 0, 0, &platform).unwrap();

    // Manually set child VP[0] back to Running (simulating another core holding it)
    {
        let c = child.read();
        let vp0 = c.data.policy.vprocessor_states[0].clone();
        drop(c);
        *vp0.run_state.write() = VpRunState::Running {
            core: 99,
            caller: None,
        };
    }

    // Now try to switch again — should fail because VP[0] is Running on core 99
    let result = Capability::switch(&root, child_h, 0, &platform);
    assert!(
        result.is_err(),
        "expected error when target VP is not Available"
    );
}

/// switch fails when the target domain doesn't allow the current core.
#[test]
fn test_vp_switch_core_not_allowed() {
    let platform = common::TestPlatform::new();

    let root = Capability::new_root(0, 0, Domain::new_root(4));
    let root_id = root.read().data.id;
    platform.register_domain(root_id, None);
    platform.set_core_domain(0, root_id);
    platform.set_current_core(Some(1)); // core 1
    init_vp_running(&root, 1, 1); // root VP[1] Running on core 1

    // Child only allows core 0
    let child_policy = DomainPolicy::new_restricted(0b0001, MonitorAPI::ALL);
    let child_h = Capability::create(&root, child_policy).unwrap();
    Capability::seal(&root, child_h).unwrap();

    // Try to switch from core 1 to child — child doesn't allow core 1
    let result = Capability::switch(&root, child_h, 0, &platform);
    assert!(result.is_err(), "expected error for core not allowed");
}

/// switch fails when platform returns None for current core.
#[test]
fn test_vp_switch_unknown_core() {
    let (root, _, child_h, platform) = fixture();
    platform.set_current_core(None); // simulate unknown core

    let result = Capability::switch(&root, child_h, 0, &platform);
    assert!(
        result.is_err(),
        "expected error when current core is unknown"
    );
}

/// switch fails when the caller domain is not sealed.
#[test]
fn test_vp_switch_caller_unsealed() {
    let platform = common::TestPlatform::new();
    platform.set_current_core(Some(0));

    // Unsealed domain: Domain::new creates it Unsealed (no VPs yet).
    // switch checks is_sealed() in step 2, before any VP or target lookup,
    // so a dummy handle is fine — we never reach the target resolution step.
    let policy = DomainPolicy::new_root(4);
    let caller = Capability::new_root(0, 0, Domain::new(policy));

    let result = Capability::switch(&caller, 1 /* dummy */, 0, &platform);
    assert!(result.is_err(), "expected error for unsealed caller");
}

/// switch fails when caller lacks SWITCH permission.
#[test]
fn test_vp_switch_no_switch_api() {
    let platform = common::TestPlatform::new();
    platform.set_current_core(Some(0));

    let root = Capability::new_root(0, 0, Domain::new_root(4));
    let root_id = root.read().data.id;
    platform.register_domain(root_id, None);
    init_vp_running(&root, 0, 0);

    // Sealed caller without SWITCH permission.
    let no_switch_api = MonitorAPI::from_bits(MonitorAPI::GET | MonitorAPI::ATTEST);
    let caller_policy = DomainPolicy::new_restricted(0b1111, no_switch_api);
    let caller_h = Capability::create(&root, caller_policy).unwrap();
    Capability::seal(&root, caller_h).unwrap();
    let caller = root.read().data.domain_capabilities[&caller_h]
        .upgrade()
        .unwrap();
    let caller_id = caller.read().data.id;
    platform.register_domain(caller_id, Some(root_id));
    init_vp_running(&caller, 0, 0);

    // switch checks the api permission in step 2, before any target-handle
    // lookup, so a dummy handle is sufficient — ApiNotAllowed is returned first.
    let result = Capability::switch(&caller, 1 /* dummy */, 0, &platform);
    assert!(result.is_err(), "expected error when SWITCH api is missing");
}

/// switch fails when the target domain is not sealed.
#[test]
fn test_vp_switch_target_unsealed() {
    let (root, _, _, platform) = fixture();

    // Create unsealed child
    let child_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let child_h = Capability::create(&root, child_policy).unwrap();
    // NOT sealing

    let result = Capability::switch(&root, child_h, 0, &platform);
    assert!(result.is_err(), "expected error for unsealed target domain");
}

/// return_domain fails when the caller VP has no saved caller (initial domain, not called-into).
#[test]
fn test_vp_return_no_caller() {
    let (root, _, _, platform) = fixture();

    // root VP[0] is Running{caller: None} — no one called us
    let result = Capability::switch(&root, 0, 0, &platform);
    assert!(
        result.is_err(),
        "expected error when returning from initial VP with no caller"
    );
}

/// return_domain fails when platform returns None for current core.
#[test]
fn test_vp_return_unknown_core() {
    let (root, child, child_h, platform) = fixture();

    Capability::switch(&root, child_h, 0, &platform).unwrap();
    platform.set_current_core(None);

    let result = Capability::switch(&child, 0, 0, &platform);
    assert!(
        result.is_err(),
        "expected error when current core is unknown"
    );
}

/// return_domain fails when there is no VP running on the current core in the caller.
#[test]
fn test_vp_return_no_vp_on_core() {
    let (root, child, child_h, platform) = fixture();

    Capability::switch(&root, child_h, 0, &platform).unwrap();

    // Simulate child VP[0] no longer Running on core 0 (manually reset it)
    {
        let c = child.read();
        let vp0 = c.data.policy.vprocessor_states[0].clone();
        drop(c);
        // VP[0] is Running{core:0}, change core to something else so find_vp_on_core fails
        *vp0.run_state.write() = VpRunState::Available;
    }

    let result = Capability::switch(&child, 0, 0, &platform);
    assert!(
        result.is_err(),
        "expected error when no VP running on core in caller"
    );
}

// ── Interrupt routing tests (testing SwitchManager infrastructure) ───────────

#[test]
fn test_interrupt_delivery_to_domain() {
    let mgr = SwitchManager::new(1);

    let mut policy = DomainPolicy::new_root(4);
    policy
        .interrupts
        .set_policy(32, VectorPolicy::default_deliver());
    let domain = Domain::new(policy);
    let domain_ref = Capability::new_root(0, 0, domain);

    let (handler_id, reported) = mgr.route_interrupt(32, &domain_ref, 0).unwrap();

    assert_eq!(handler_id, domain_ref.read().data.id);
    assert!(reported.is_empty());
}

#[test]
fn test_interrupt_report_to_parent() {
    let mgr = SwitchManager::new(1);

    let mut parent_policy = DomainPolicy::new_root(4);
    parent_policy
        .interrupts
        .set_policy(32, VectorPolicy::default_deliver());
    let parent_domain = Domain::new(parent_policy);
    let parent_ref = Capability::new_root(0, 0, parent_domain);

    let mut child_policy = DomainPolicy::new_root(4);
    child_policy
        .interrupts
        .set_policy(32, VectorPolicy::default_report());
    let child_domain = Domain::new(child_policy);
    let child_ref = Capability::new_child(1, 1, 1, child_domain, Arc::downgrade(&parent_ref));
    parent_ref.write().add_child(child_ref.clone());

    let child_id = child_ref.read().data.id;
    let parent_id = parent_ref.read().data.id;

    let (handler_id, reported) = mgr.route_interrupt(32, &child_ref, 0).unwrap();

    assert_eq!(handler_id, parent_id);
    assert_eq!(reported, vec![child_id]);
}

#[test]
fn test_interrupt_no_handler() {
    let mgr = SwitchManager::new(1);

    let mut policy = DomainPolicy::new_root(4);
    policy.interrupts.default = VectorPolicy {
        visibility: InterruptVisibility::NotReport,
        read_set: 0,
        write_set: 0,
    };
    let domain = Domain::new(policy);
    let domain_ref = Capability::new_root(0, 0, domain);

    let result = mgr.route_interrupt(32, &domain_ref, 0);
    assert!(result.is_err());
}

#[test]
fn test_resume_after_interrupt() {
    let mgr = SwitchManager::new(1);

    let mut parent_policy = DomainPolicy::new_root(4);
    parent_policy
        .interrupts
        .set_policy(32, VectorPolicy::default_deliver());
    let parent_domain = Domain::new(parent_policy);
    let parent_ref = Capability::new_root(0, 0, parent_domain);

    let mut child_policy = DomainPolicy::new_root(4);
    child_policy
        .interrupts
        .set_policy(32, VectorPolicy::default_report());
    let child_domain = Domain::new(child_policy);
    let child_ref = Capability::new_child(1, 1, 1, child_domain, Arc::downgrade(&parent_ref));
    parent_ref.write().add_child(child_ref.clone());

    let child_id = child_ref.read().data.id;

    let notified = mgr
        .resume_after_interrupt(32, &parent_ref, &child_ref)
        .unwrap();
    assert_eq!(notified, vec![child_id]);
}

#[test]
fn test_multi_level_interrupt_routing() {
    let mgr = SwitchManager::new(1);

    let mut root_policy = DomainPolicy::new_root(4);
    root_policy
        .interrupts
        .set_policy(40, VectorPolicy::default_deliver());
    let root_domain = Domain::new(root_policy);
    let root_ref = Capability::new_root(0, 0, root_domain);

    let mut l1_policy = DomainPolicy::new_root(4);
    l1_policy
        .interrupts
        .set_policy(40, VectorPolicy::default_report());
    let l1_domain = Domain::new(l1_policy);
    let l1_ref = Capability::new_child(1, 1, 1, l1_domain, Arc::downgrade(&root_ref));
    root_ref.write().add_child(l1_ref.clone());

    let mut l2_policy = DomainPolicy::new_root(4);
    l2_policy
        .interrupts
        .set_policy(40, VectorPolicy::default_report());
    let l2_domain = Domain::new(l2_policy);
    let l2_ref = Capability::new_child(2, 2, 2, l2_domain, Arc::downgrade(&l1_ref));
    l1_ref.write().add_child(l2_ref.clone());

    let root_id = root_ref.read().data.id;
    let l1_id = l1_ref.read().data.id;
    let l2_id = l2_ref.read().data.id;

    let (handler_id, reported) = mgr.route_interrupt(40, &l2_ref, 0).unwrap();

    assert_eq!(handler_id, root_id);
    assert_eq!(reported, vec![l2_id, l1_id]);
}

// ── VP-aware interrupt delivery (lazy-unwind) tests ───────────────────────────

/// Helper: build a 3-domain call chain on core 0 using switch.
///
/// Returns `(dom0=handler, dom1=report/intermediate, dom2=running, platform)`.
/// dom0.vp0 → dom1.vp0 → dom2.vp0 (all on core 0).
fn setup_3domain_chain() -> (
    CapabilityRef<Domain>,
    CapabilityRef<Domain>,
    CapabilityRef<Domain>,
    common::TestPlatform,
) {
    let platform = common::TestPlatform::new();
    platform.set_current_core(Some(0));

    // dom0: root, DELIVER handler
    let dom0 = Capability::new_root(0, 0, Domain::new_root(4));
    let dom0_id = dom0.read().data.id;
    platform.register_domain(dom0_id, None);
    platform.set_core_domain(0, dom0_id);
    init_vp_running(&dom0, 0, 0);
    platform.set_core_vp(0, Some(0));

    // dom1: child of dom0, REPORT policy — intermediate
    let (dom1, dom1_h) = make_sealed_child(&dom0);
    let dom1_id = dom1.read().data.id;
    platform.register_domain(dom1_id, Some(dom0_id));

    // dom0 switches to dom1: dom0.vp0 → Locked, dom1.vp0 → Running
    Capability::switch(&dom0, dom1_h, 0, &platform).unwrap();

    // dom2: child of dom0 (visible from dom1 via parent's domain cap), sealed
    // For simplicity, create dom2 as a child of dom0, give dom1 a handle to it.
    // In a real system dom1 would have its own capability; here we test the VP
    // chain semantics directly.
    let (dom2, _dom2_h_in_dom0) = make_sealed_child(&dom0);
    let dom2_id = dom2.read().data.id;
    platform.register_domain(dom2_id, Some(dom0_id));

    // Manually add a handle for dom2 in dom1 so dom1 can switch to dom2.
    let dom2_h_in_dom1 = {
        let dom2_weak = Arc::downgrade(&dom2);
        let mut d1 = dom1.write();
        let h = d1.data.allocate_domain_handle();
        d1.data.add_domain_capability(h, dom2_weak);
        h
    };

    // dom1 switches to dom2: dom1.vp0 → Locked, dom2.vp0 → Running
    Capability::switch(&dom1, dom2_h_in_dom1, 0, &platform).unwrap();

    (dom0, dom1, dom2, platform)
}

/// `deliver_interrupt_vp` with a 2-domain chain: dom0(handler) → dom1(running).
/// After delivery: dom1.vp0 = Interrupted, dom0.vp0 = Running.
#[test]
fn test_deliver_interrupt_vp_2domain() {
    let (root, child, child_h, platform) = fixture();
    let root_id = root.read().data.id;
    let child_id = child.read().data.id;

    // Switch root → child: root.vp0 → Locked, child.vp0 → Running on core 0
    Capability::switch(&root, child_h, 0, &platform).unwrap();

    // Deliver interrupt: handler is root, interrupted is child
    let ctx = Capability::<Domain>::deliver_interrupt_vp(&child, root_id, 0, 0, &platform).unwrap();

    assert_eq!(ctx.interrupted_domain_id, child_id);
    assert_eq!(ctx.interrupted_vp_id, 0);
    assert_eq!(ctx.handler_domain_id, root_id);
    assert_eq!(ctx.handler_vp_id, 0);

    // child.vp0 must be Interrupted
    let child_vp0 = child.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(*child_vp0.run_state.read(), VpRunState::Interrupted { .. }),
        "child VP[0] should be Interrupted after delivery"
    );

    // root.vp0 must be Running on core 0
    let root_vp0 = root.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(
            *root_vp0.run_state.read(),
            VpRunState::Running { core: 0, .. }
        ),
        "root VP[0] should be Running after interrupt delivery"
    );
}

/// `deliver_interrupt_vp` with a 3-domain chain:
/// dom0(handler,Locked) → dom1(report,Locked) → dom2(running).
///
/// After delivery:
/// - dom2.vp0 = Interrupted
/// - dom1.vp0 = Suspended { callee: dom2.vp0 }
/// - dom0.vp0 = Running
#[test]
fn test_deliver_interrupt_vp_3domain() {
    let (dom0, dom1, dom2, platform) = setup_3domain_chain();

    let dom0_id = dom0.read().data.id;
    let dom2_id = dom2.read().data.id;

    let ctx = Capability::<Domain>::deliver_interrupt_vp(&dom2, dom0_id, 0, 0, &platform).unwrap();

    assert_eq!(ctx.interrupted_domain_id, dom2_id);
    assert_eq!(ctx.interrupted_vp_id, 0);
    assert_eq!(ctx.handler_domain_id, dom0_id);
    assert_eq!(ctx.handler_vp_id, 0);

    // dom2.vp0 → Interrupted
    let dom2_vp0 = dom2.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(*dom2_vp0.run_state.read(), VpRunState::Interrupted { .. }),
        "dom2 VP[0] should be Interrupted"
    );

    // dom1.vp0 → Suspended { callee: dom2.vp0 }
    let dom1_vp0 = dom1.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(*dom1_vp0.run_state.read(),
        VpRunState::Suspended { callee_domain_id, callee_vp_id, .. }
        if callee_domain_id == dom2_id && callee_vp_id == 0),
        "dom1 VP[0] should be Suspended on dom2's VP[0]"
    );

    // dom0.vp0 → Running
    let dom0_vp0 = dom0.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(
            *dom0_vp0.run_state.read(),
            VpRunState::Running { core: 0, .. }
        ),
        "dom0 VP[0] should be Running (interrupt handler)"
    );
}

/// After interrupt delivery (3-domain chain), dom0 switches to dom1 via
/// switch.  This resumes dom1.vp0 from Suspended → Running and
/// simultaneously frees dom2.vp0 from Interrupted → Available.
#[test]
fn test_interrupt_resume_frees_interrupted_callee() {
    let (dom0, dom1, dom2, platform) = setup_3domain_chain();

    let dom0_id = dom0.read().data.id;
    let dom1_id = dom1.read().data.id;

    // Deliver interrupt: dom0 becomes the handler
    Capability::<Domain>::deliver_interrupt_vp(&dom2, dom0_id, 0, 0, &platform).unwrap();

    // After delivery: dom1.vp0 = Suspended, dom2.vp0 = Interrupted

    // dom0 now does switch to dom1 (the REPORT domain).
    // dom1.vp0 is Suspended — the forward switch should accept it.
    // Build dom1's handle in dom0's table.
    let dom1_h_in_dom0 = dom0
        .read()
        .data
        .domain_capability_handles()
        .into_iter()
        .find(|&h| {
            dom0.read()
                .data
                .get_domain_capability(h)
                .and_then(|w| w.upgrade())
                .map(|c| c.read().data.id == dom1_id)
                .unwrap_or(false)
        })
        .expect("dom0 should hold a handle to dom1");

    // Switch dom0 → dom1 (Suspended → Running)
    let switch_ctx = Capability::switch(&dom0, dom1_h_in_dom0, 0, &platform).unwrap();
    assert_eq!(switch_ctx.to_domain, dom1_id);

    // dom1.vp0 should now be Running
    let dom1_vp0 = dom1.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(
            *dom1_vp0.run_state.read(),
            VpRunState::Running { core: 0, .. }
        ),
        "dom1 VP[0] should be Running after resume"
    );

    // dom2.vp0 should be Available (freed when dom1's Suspended was claimed)
    let dom2_vp0 = dom2.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(*dom2_vp0.run_state.read(), VpRunState::Available),
        "dom2 VP[0] should be Available after dom1 was resumed"
    );
}

/// `deliver_interrupt_vp` returns an error when the interrupted domain has no
/// VP running on the given core (non-VP switch path).
#[test]
fn test_deliver_interrupt_vp_no_vp_on_core() {
    let platform = common::TestPlatform::new();
    let root = Capability::new_root(0, 0, Domain::new_root(4));
    let root_id = root.read().data.id;
    // VP[0] left Available — never set to Running
    let result = Capability::<Domain>::deliver_interrupt_vp(&root, root_id, 0, 0, &platform);
    assert!(
        result.is_err(),
        "expected error when no VP is running on core"
    );
}

/// The key invariant: after interrupt delivery, a *second* VP of the intermediate
/// domain (dom1.vp1) cannot claim dom2.vp0 via `switch`.
///
/// After `deliver_interrupt_vp`, dom2.vp0 is `Interrupted`.  The forward switch
/// path only accepts `Available` or `Suspended`; `Interrupted` is rejected.
/// This prevents any VP from stealing the interrupted execution context.
#[test]
fn test_interrupted_vp_not_claimable_by_other_vp() {
    let (dom0, dom1, dom2, platform) = setup_3domain_chain();
    let dom0_id = dom0.read().data.id;
    let dom2_id = dom2.read().data.id;

    // Deliver interrupt: dom0 is handler, dom2.vp0 → Interrupted.
    Capability::<Domain>::deliver_interrupt_vp(&dom2, dom0_id, 0, 0, &platform).unwrap();

    // Sanity-check: dom2.vp0 is Interrupted.
    let dom2_vp0 = dom2.read().data.policy.vprocessor_states[0].clone();
    assert!(matches!(
        *dom2_vp0.run_state.read(),
        VpRunState::Interrupted { .. }
    ));

    // Set dom1.vp1 to Running on core 1 — simulates a second concurrent VP of dom1.
    {
        let d = dom1.read();
        let vp1 = d.data.policy.vprocessor_states[1].clone();
        drop(d);
        *vp1.run_state.write() = VpRunState::Running {
            core: 1,
            caller: None,
        };
    }
    platform.set_current_core(Some(1));

    // Find dom2's handle in dom1's capability table.
    let dom2_h_in_dom1 = dom1
        .read()
        .data
        .domain_capability_handles()
        .into_iter()
        .find(|&h| {
            dom1.read()
                .data
                .get_domain_capability(h)
                .and_then(|w| w.upgrade())
                .map(|c| c.read().data.id == dom2_id)
                .unwrap_or(false)
        })
        .expect("dom1 should hold a handle to dom2");

    // Attempt to claim dom2.vp0 from dom1.vp1 — must be rejected.
    let result = Capability::switch(&dom1, dom2_h_in_dom1, 0, &platform);
    assert!(
        result.is_err(),
        "Interrupted VP must not be claimable via switch"
    );
}

// ── T5: Multi-level Suspended chain cleanup ───────────────────────────────────
//
// 4-domain chain: dom0(handler) → dom1(Locked) → dom2(Locked) → dom3(Running)
//
// After delivering an interrupt to dom3 with dom0 as handler:
//   dom3.vp0 = Interrupted
//   dom2.vp0 = Suspended { callee: dom3.vp0 }
//   dom1.vp0 = Suspended { callee: dom2.vp0 }
//   dom0.vp0 = Running (handler)
//
// When dom0 claims dom1 (Suspended → Running):
//   dom1.vp0 → Running
//   dom2.vp0 must stay Suspended (it's not Interrupted; only Interrupted callees
//   are freed when their parent is claimed)
//
// When dom1 then claims dom2 (Suspended → Running):
//   dom2.vp0 → Running
//   dom3.vp0 → Available (it was Interrupted, so it is freed)

fn setup_4domain_chain() -> (
    CapabilityRef<Domain>,
    CapabilityRef<Domain>,
    CapabilityRef<Domain>,
    CapabilityRef<Domain>,
    common::TestPlatform,
) {
    let platform = common::TestPlatform::new();
    platform.set_current_core(Some(0));

    let dom0 = Capability::new_root(0, 0, Domain::new_root(4));
    let dom0_id = dom0.read().data.id;
    platform.register_domain(dom0_id, None);
    platform.set_core_domain(0, dom0_id);
    init_vp_running(&dom0, 0, 0);
    platform.set_core_vp(0, Some(0));

    let (dom1, dom1_h) = make_sealed_child(&dom0);
    let dom1_id = dom1.read().data.id;
    platform.register_domain(dom1_id, Some(dom0_id));
    Capability::switch(&dom0, dom1_h, 0, &platform).unwrap();

    let (dom2, _dom2_h_in_dom0) = make_sealed_child(&dom0);
    let dom2_id = dom2.read().data.id;
    platform.register_domain(dom2_id, Some(dom0_id));
    let dom2_h_in_dom1 = {
        let dom2_weak = Arc::downgrade(&dom2);
        let mut d1 = dom1.write();
        let h = d1.data.allocate_domain_handle();
        d1.data.add_domain_capability(h, dom2_weak);
        h
    };
    Capability::switch(&dom1, dom2_h_in_dom1, 0, &platform).unwrap();

    let (dom3, _dom3_h_in_dom0) = make_sealed_child(&dom0);
    let dom3_id = dom3.read().data.id;
    platform.register_domain(dom3_id, Some(dom0_id));
    let dom3_h_in_dom2 = {
        let dom3_weak = Arc::downgrade(&dom3);
        let mut d2 = dom2.write();
        let h = d2.data.allocate_domain_handle();
        d2.data.add_domain_capability(h, dom3_weak);
        h
    };
    Capability::switch(&dom2, dom3_h_in_dom2, 0, &platform).unwrap();

    let _ = (dom2_id, dom3_id); // silence unused warnings
    (dom0, dom1, dom2, dom3, platform)
}

fn find_domain_handle(holder: &CapabilityRef<Domain>, target_id: u64) -> LocalHandle {
    holder
        .read()
        .data
        .domain_capability_handles()
        .into_iter()
        .find(|&h| {
            holder
                .read()
                .data
                .get_domain_capability(h)
                .and_then(|w| w.upgrade())
                .map(|c| c.read().data.id == target_id)
                .unwrap_or(false)
        })
        .expect("handle not found")
}

/// After interrupt delivery to a 4-domain chain, verify the intermediate states:
/// dom3=Interrupted, dom2=Suspended{callee=dom3}, dom1=Suspended{callee=dom2}.
#[test]
fn test_4domain_interrupt_delivery_states() {
    let (dom0, dom1, dom2, dom3, platform) = setup_4domain_chain();
    let dom0_id = dom0.read().data.id;
    let dom2_id = dom2.read().data.id;
    let dom3_id = dom3.read().data.id;

    Capability::<Domain>::deliver_interrupt_vp(&dom3, dom0_id, 0, 0, &platform).unwrap();

    // dom3.vp0 → Interrupted
    let dom3_vp0 = dom3.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(*dom3_vp0.run_state.read(), VpRunState::Interrupted { .. }),
        "dom3 VP[0] should be Interrupted"
    );

    // dom2.vp0 → Suspended { callee: dom3.vp0 }
    let dom2_vp0 = dom2.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(*dom2_vp0.run_state.read(),
            VpRunState::Suspended { callee_domain_id, callee_vp_id, .. }
            if callee_domain_id == dom3_id && callee_vp_id == 0),
        "dom2 VP[0] should be Suspended on dom3.vp0"
    );

    // dom1.vp0 → Suspended { callee: dom2.vp0 }
    let dom1_vp0 = dom1.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(*dom1_vp0.run_state.read(),
            VpRunState::Suspended { callee_domain_id, callee_vp_id, .. }
            if callee_domain_id == dom2_id && callee_vp_id == 0),
        "dom1 VP[0] should be Suspended on dom2.vp0"
    );

    // dom0.vp0 → Running (handler)
    let dom0_vp0 = dom0.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(*dom0_vp0.run_state.read(), VpRunState::Running { core: 0, .. }),
        "dom0 VP[0] should be Running as handler"
    );
}

/// When dom0 claims dom1 (Suspended → Running), dom2 stays Suspended
/// because dom2's callee (dom3) is Interrupted, not dom2 itself.
/// Only when dom1 subsequently claims dom2 is dom3 freed to Available.
#[test]
fn test_4domain_transitive_suspended_chain_cleanup() {
    let (dom0, dom1, dom2, dom3, platform) = setup_4domain_chain();
    let dom0_id = dom0.read().data.id;
    let dom1_id = dom1.read().data.id;

    Capability::<Domain>::deliver_interrupt_vp(&dom3, dom0_id, 0, 0, &platform).unwrap();

    // Step 1: dom0 claims dom1 (Suspended → Running).
    let dom1_h = find_domain_handle(&dom0, dom1_id);
    Capability::switch(&dom0, dom1_h, 0, &platform).unwrap();

    // dom1.vp0 → Running
    let dom1_vp0 = dom1.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(*dom1_vp0.run_state.read(), VpRunState::Running { .. }),
        "dom1 VP[0] must be Running after being claimed"
    );

    // dom2.vp0 must still be Suspended (dom3 is Interrupted, not dom2)
    let dom2_vp0 = dom2.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(*dom2_vp0.run_state.read(), VpRunState::Suspended { .. }),
        "dom2 VP[0] must remain Suspended — it was dom1's callee, not Interrupted"
    );

    // dom3.vp0 must still be Interrupted
    let dom3_vp0 = dom3.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(*dom3_vp0.run_state.read(), VpRunState::Interrupted { .. }),
        "dom3 VP[0] must still be Interrupted"
    );

    // Step 2: dom1 claims dom2 (Suspended → Running).
    // dom1 is now Running on core 0; it can switch to dom2.
    let dom2_id = dom2.read().data.id;
    let dom2_h = find_domain_handle(&dom1, dom2_id);
    Capability::switch(&dom1, dom2_h, 0, &platform).unwrap();

    // dom2.vp0 → Running
    let dom2_vp0 = dom2.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(*dom2_vp0.run_state.read(), VpRunState::Running { .. }),
        "dom2 VP[0] must be Running after being claimed by dom1"
    );

    // dom3.vp0 → Available (freed because dom2's callee dom3 was Interrupted)
    let dom3_vp0 = dom3.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(*dom3_vp0.run_state.read(), VpRunState::Available),
        "dom3 VP[0] must be freed to Available when dom2 (its Suspended parent) is claimed"
    );
}
