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

/// Initialise a domain's VP[vp_id] to `Running { core }`.
fn init_vp_running(domain: &CapabilityRef<Domain>, vp_id: usize, core: u64) {
    let d = domain.read();
    let vp = d.data.policy.vprocessor_states[vp_id].clone();
    drop(d);
    *vp.run_state.write() = VpRunState::Running { core };
}

/// Build a sealed child domain inside `parent`, returning `(child_ref, child_handle)`.
/// Child gets `MonitorAPI::ALL` (includes SWITCH) and all 4 cores.
fn make_sealed_child(parent: &CapabilityRef<Domain>) -> (CapabilityRef<Domain>, LocalHandle) {
    let platform = common::TestPlatform::new();
    let policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let num_vps = policy.num_vprocessors;
    let h = Capability::create(&platform, parent, policy).unwrap().0;
    let child = parent.read().data.domain_capabilities[&h]
        .upgrade()
        .unwrap();
    // Explicitly add VPs (no longer auto-created in Domain::new)
    for _ in 0..num_vps {
        child.write().data.add_vprocessor().unwrap();
    }
    Capability::seal(&platform, parent, h).unwrap();
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
    platform.set_core_context(0, &root, 0);
    platform.set_current_core(Some(0));

    // VP[0] of root is Running on core 0
    init_vp_running(&root, 0, 0);

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
    assert_eq!(ctx.current_vp(), None);

    let domain = Capability::new_root(1, 0, Domain::new_root(1));
    let domain_id = domain.read().data.id;
    ctx.set_binding(domain, 7);
    assert_eq!(ctx.current_domain(), Some(domain_id));
    assert_eq!(ctx.current_vp(), Some(7));
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
    let _platform = common::TestPlatform::new();
    let (root, child, child_h, platform) = fixture();

    let root_id = root.read().data.id;
    let child_id = child.read().data.id;

    let ctx = Capability::switch(&platform, &root, child_h, 0).unwrap().0;

    assert_eq!(ctx.from_domain.as_ref().unwrap().read().data.id, root_id);
    assert_eq!(ctx.to_domain.read().data.id, child_id);
    assert_eq!(ctx.core_id, 0);
    assert!(!ctx.is_return);
    assert_eq!(ctx.from_vp_id, Some(0));
    assert_eq!(ctx.to_vp_id, Some(0));
}

/// switch followed by return_domain restores original domain.
#[test]
fn test_vp_return_domain_basic() {
    let _platform = common::TestPlatform::new();
    let (root, child, child_h, platform) = fixture();

    let root_id = root.read().data.id;
    let child_id = child.read().data.id;

    // Switch root → child VP[0]
    Capability::switch(&platform, &root, child_h, 0).unwrap().0;

    // Now platform says core 0 is running child; child VP[0] is Running{caller=root.VP[0]}
    let ret_ctx = Capability::switch(&platform, &child, 0, 0).unwrap().0;

    assert_eq!(
        ret_ctx.from_domain.as_ref().unwrap().read().data.id,
        child_id
    );
    assert_eq!(ret_ctx.to_domain.read().data.id, root_id);
    assert!(ret_ctx.is_return);
    assert_eq!(ret_ctx.from_vp_id, Some(0));
    assert_eq!(ret_ctx.to_vp_id, Some(0));
}

/// After return, root VP[0] is Available and can switch again.
#[test]
fn test_vp_switch_return_switch_again() {
    let _platform = common::TestPlatform::new();
    let (root, child, child_h, platform) = fixture();

    Capability::switch(&platform, &root, child_h, 0).unwrap().0;
    Capability::switch(&platform, &child, 0, 0).unwrap().0;

    // Root VP[0] should be Running again; switch one more time
    let ctx = Capability::switch(&platform, &root, child_h, 0).unwrap().0;
    assert_eq!(ctx.to_vp_id, Some(0));
}

/// Two-level switch chain: root → child → grandchild, then unwind both.
#[test]
fn test_vp_nested_switch_and_return() {
    let platform = common::TestPlatform::new();

    let root = Capability::new_root(0, 0, Domain::new_root(4));
    let root_id = root.read().data.id;
    platform.register_domain(root_id, None);
    platform.set_core_context(0, &root, 0);
    platform.set_current_core(Some(0));
    init_vp_running(&root, 0, 0);

    // child1 under root
    let child1_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let child1_h = Capability::create(&platform, &root, child1_policy)
        .unwrap()
        .0;
    let child1 = root.read().data.domain_capabilities[&child1_h]
        .upgrade()
        .unwrap();
    for _ in 0..4u64 {
        child1.write().data.add_vprocessor().unwrap();
    }
    Capability::seal(&platform, &root, child1_h).unwrap();
    let child1_id = child1.read().data.id;
    platform.register_domain(child1_id, Some(root_id));

    // child2 under child1
    let child2_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let child2_h = Capability::create(&platform, &child1, child2_policy)
        .unwrap()
        .0;
    let child2 = child1.read().data.domain_capabilities[&child2_h]
        .upgrade()
        .unwrap();
    for _ in 0..4u64 {
        child2.write().data.add_vprocessor().unwrap();
    }
    Capability::seal(&platform, &child1, child2_h).unwrap();
    let child2_id = child2.read().data.id;
    platform.register_domain(child2_id, Some(child1_id));

    // root → child1
    Capability::switch(&platform, &root, child1_h, 0).unwrap().0;

    // child1 VP[0] needs to be Running on core 0 for its own switch
    // (switch sets child1 VP[0] to Running when root switches into it)

    // child1 → child2
    let ctx12 = Capability::switch(&platform, &child1, child2_h, 0)
        .unwrap()
        .0;
    assert_eq!(ctx12.to_domain.read().data.id, child2_id);

    // return child2 → child1
    let ret1 = Capability::switch(&platform, &child2, 0, 0).unwrap().0;
    assert_eq!(ret1.to_domain.read().data.id, child1_id);

    // return child1 → root
    let ret0 = Capability::switch(&platform, &child1, 0, 0).unwrap().0;
    assert_eq!(ret0.to_domain.read().data.id, root_id);
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

    let result = Capability::switch(&platform, &root, child_h, 0);
    assert!(result.is_err(), "expected error when no VP running on core");
}

/// switch fails when the target VP is already Running (not Available).
#[test]
fn test_vp_switch_target_not_available() {
    let _platform = common::TestPlatform::new();
    let (root, child, child_h, platform) = fixture();

    // Claim child VP[0] first
    Capability::switch(&platform, &root, child_h, 0).unwrap().0;
    Capability::switch(&platform, &child, 0, 0).unwrap().0;

    // Manually set child VP[0] back to Running (simulating another core holding it)
    {
        let c = child.read();
        let vp0 = c.data.policy.vprocessor_states[0].clone();
        drop(c);
        *vp0.run_state.write() = VpRunState::Running { core: 99 };
    }

    // Now try to switch again — should fail because VP[0] is Running on core 99
    let result = Capability::switch(&platform, &root, child_h, 0);
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
    platform.set_core_context(0, &root, 0);
    platform.set_current_core(Some(1)); // core 1
    init_vp_running(&root, 1, 1); // root VP[1] Running on core 1

    // Child only allows core 0
    let child_policy = DomainPolicy::new_restricted(0b0001, MonitorAPI::ALL);
    let child_h = Capability::create(&platform, &root, child_policy)
        .unwrap()
        .0;
    Capability::seal(&platform, &root, child_h).unwrap();

    // Try to switch from core 1 to child — child doesn't allow core 1
    let result = Capability::switch(&platform, &root, child_h, 0);
    assert!(result.is_err(), "expected error for core not allowed");
}

/// switch fails when platform returns None for current core.
#[test]
fn test_vp_switch_unknown_core() {
    let _platform = common::TestPlatform::new();
    let (root, _, child_h, platform) = fixture();
    platform.set_current_core(None); // simulate unknown core

    let result = Capability::switch(&platform, &root, child_h, 0);
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

    let result = Capability::switch(&platform, &caller, 1 /* dummy */, 0);
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
    let caller_h = Capability::create(&platform, &root, caller_policy)
        .unwrap()
        .0;
    let caller = root.read().data.domain_capabilities[&caller_h]
        .upgrade()
        .unwrap();
    for _ in 0..4u64 {
        caller.write().data.add_vprocessor().unwrap();
    }
    Capability::seal(&platform, &root, caller_h).unwrap();
    let caller_id = caller.read().data.id;
    platform.register_domain(caller_id, Some(root_id));
    init_vp_running(&caller, 0, 0);

    // switch checks the api permission in step 2, before any target-handle
    // lookup, so a dummy handle is sufficient — ApiNotAllowed is returned first.
    let result = Capability::switch(&platform, &caller, 1 /* dummy */, 0);
    assert!(result.is_err(), "expected error when SWITCH api is missing");
}

/// switch fails when the target domain is not sealed.
#[test]
fn test_vp_switch_target_unsealed() {
    let _platform = common::TestPlatform::new();
    let (root, _, _, platform) = fixture();

    // Create unsealed child
    let child_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let child_h = Capability::create(&platform, &root, child_policy)
        .unwrap()
        .0;
    // NOT sealing

    let result = Capability::switch(&platform, &root, child_h, 0);
    assert!(result.is_err(), "expected error for unsealed target domain");
}

/// return_domain fails when the caller VP has no saved caller (initial domain, not called-into).
#[test]
fn test_vp_return_no_caller() {
    let _platform = common::TestPlatform::new();
    let (root, _, _, platform) = fixture();

    // root VP[0] is Running with an empty call_stack on its core — no one called us
    let result = Capability::switch(&platform, &root, 0, 0);
    assert!(
        result.is_err(),
        "expected error when returning from initial VP with no caller"
    );
}

/// return_domain fails when platform returns None for current core.
#[test]
fn test_vp_return_unknown_core() {
    let _platform = common::TestPlatform::new();
    let (root, child, child_h, platform) = fixture();

    Capability::switch(&platform, &root, child_h, 0).unwrap().0;
    platform.set_current_core(None);

    let result = Capability::switch(&platform, &child, 0, 0);
    assert!(
        result.is_err(),
        "expected error when current core is unknown"
    );
}

/// return_domain fails when there is no VP running on the current core in the caller.
#[test]
fn test_vp_return_no_vp_on_core() {
    let _platform = common::TestPlatform::new();
    let (root, child, child_h, platform) = fixture();

    Capability::switch(&platform, &root, child_h, 0).unwrap().0;

    // Simulate child VP[0] no longer Running on core 0 (manually reset it)
    {
        let c = child.read();
        let vp0 = c.data.policy.vprocessor_states[0].clone();
        drop(c);
        // VP[0] is Running{core:0}, change core to something else so find_vp_on_core fails
        *vp0.run_state.write() = VpRunState::Available {
            last_exit_reason: None,
        };
    }

    let result = Capability::switch(&platform, &child, 0, 0);
    assert!(
        result.is_err(),
        "expected error when no VP running on core in caller"
    );
}

// ── Interrupt routing tests (testing SwitchManager infrastructure) ───────────

#[test]
fn test_interrupt_delivery_to_domain() {
    let _platform = common::TestPlatform::new();
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
    let _platform = common::TestPlatform::new();
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
    let _platform = common::TestPlatform::new();
    let mgr = SwitchManager::new(1);

    let mut policy = DomainPolicy::new_root(4);
    policy.interrupts.default = VectorPolicy {
        visibility: InterruptVisibility::NotReport,
        read_set: RegBitmap::NONE,
        write_set: RegBitmap::NONE,
        injectable: false,
    };
    let domain = Domain::new(policy);
    let domain_ref = Capability::new_root(0, 0, domain);

    let result = mgr.route_interrupt(32, &domain_ref, 0);
    assert!(result.is_err());
}

#[test]
fn test_multi_level_interrupt_routing() {
    let _platform = common::TestPlatform::new();
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
    platform.set_core_context(0, &dom0, 0);
    init_vp_running(&dom0, 0, 0);

    // dom1: child of dom0, REPORT policy — intermediate
    let (dom1, dom1_h) = make_sealed_child(&dom0);
    let dom1_id = dom1.read().data.id;
    platform.register_domain(dom1_id, Some(dom0_id));

    // dom0 switches to dom1: dom0.vp0 → Locked, dom1.vp0 → Running
    Capability::switch(&platform, &dom0, dom1_h, 0).unwrap().0;

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
    Capability::switch(&platform, &dom1, dom2_h_in_dom1, 0)
        .unwrap()
        .0;

    (dom0, dom1, dom2, platform)
}

/// `deliver_interrupt_vp` with a 2-domain chain: dom0(handler) → dom1(running).
/// After delivery: dom1.vp0 = Available (unlocked by handler becoming Running),
/// dom0.vp0 = Running.
#[test]
fn test_deliver_interrupt_vp_2domain() {
    let _platform = common::TestPlatform::new();
    let (root, child, child_h, platform) = fixture();
    let root_id = root.read().data.id;
    let child_id = child.read().data.id;

    // Switch root → child: root.vp0 → Locked, child.vp0 → Running on core 0
    Capability::switch(&platform, &root, child_h, 0).unwrap().0;

    // Deliver interrupt: handler is root, interrupted is child
    let ctx = Capability::<Domain>::deliver_interrupt_vp(&platform, &child, 0, 0)
        .unwrap()
        .0;

    assert_eq!(ctx.interrupted_domain.read().data.id, child_id);
    assert_eq!(ctx.interrupted_vp_id, 0);
    assert_eq!(ctx.handler_domain.read().data.id, root_id);
    assert_eq!(ctx.handler_vp_id, 0);

    // The interrupted leaf stays reserved (Waiting, unlocks: None) — it's
    // the true leaf, no intermediate frame between it and the handler.
    let child_vp0 = child.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(
            &*child_vp0.run_state.read(),
            VpRunState::Waiting { unlocks: None, .. }
        ),
        "child VP[0] should be Waiting{{unlocks:None}} after delivery"
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
/// - dom2.vp0 = Waiting { unlocks: None }         (true leaf)
/// - dom1.vp0 = Waiting { unlocks: Some(dom2.vp0) }
/// - dom0.vp0 = Running
#[test]
fn test_deliver_interrupt_vp_3domain() {
    let (dom0, dom1, dom2, platform) = setup_3domain_chain();

    let dom0_id = dom0.read().data.id;
    let dom2_id = dom2.read().data.id;

    let ctx = Capability::<Domain>::deliver_interrupt_vp(&platform, &dom2, 0, 0)
        .unwrap()
        .0;

    assert_eq!(ctx.interrupted_domain.read().data.id, dom2_id);
    assert_eq!(ctx.interrupted_vp_id, 0);
    assert_eq!(ctx.handler_domain.read().data.id, dom0_id);
    assert_eq!(ctx.handler_vp_id, 0);

    // dom2.vp0 → Waiting { unlocks: None } (true leaf)
    let dom2_vp0 = dom2.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(
            &*dom2_vp0.run_state.read(),
            VpRunState::Waiting { unlocks: None, .. }
        ),
        "dom2 VP[0] should be Waiting{{unlocks:None}}"
    );

    // dom1.vp0 → Waiting { unlocks: Some(dom2.vp0) }
    let dom1_vp0 = dom1.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(&*dom1_vp0.run_state.read(),
        VpRunState::Waiting { unlocks: Some(callee), .. }
        if callee.domain_id == dom2_id && callee.vp_id == 0),
        "dom1 VP[0] should be Waiting on dom2's VP[0]"
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
/// switch. dom1 is explicitly configured `Report` for this vector (see
/// `VectorPolicy::default_not_report` — this used to be capa-engine's
/// blanket default for restricted domains, now opt-in), so the walk stops
/// immediately at dom1: dom1.vp0 → Running, `interrupt_return` carries the
/// vector. dom2.vp0 (dom1's callee) is left untouched — still
/// `Waiting{unlocks:None}` — no release step happens; it remains directly
/// claimable whenever dom1 itself later targets it.
#[test]
fn test_interrupt_resume_leaves_untouched_callee_waiting() {
    let (dom0, dom1, dom2, platform) = setup_3domain_chain();
    set_vector_policy(&dom1, 0, VectorPolicy::default_report());

    let dom0_id = dom0.read().data.id;
    let dom1_id = dom1.read().data.id;

    // Deliver interrupt: dom0 becomes the handler
    Capability::<Domain>::deliver_interrupt_vp(&platform, &dom2, 0, 0)
        .unwrap()
        .0;

    // After delivery: dom1.vp0 = Waiting{Some(dom2), blocked:false} (directly
    // called by the handler dom0), dom2.vp0 = Waiting{None, blocked:true}
    // (its caller dom1.vp0 hasn't itself resumed yet).
    let dom1_vp0 = dom1.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(
            &*dom1_vp0.run_state.read(),
            VpRunState::Waiting {
                blocked: false,
                ..
            }
        ),
        "dom1 VP[0] should start unblocked (directly called by the handler)"
    );
    let dom2_vp0 = dom2.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(
            &*dom2_vp0.run_state.read(),
            VpRunState::Waiting { blocked: true, .. }
        ),
        "dom2 VP[0] should start blocked (its caller dom1.vp0 hasn't resumed)"
    );

    // dom0 now does switch to dom1 (the REPORT domain).
    // dom1.vp0 is Waiting — the forward switch should accept it.
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

    // Switch dom0 → dom1 (Waiting → Running)
    let switch_ctx = Capability::switch(&platform, &dom0, dom1_h_in_dom0, 0)
        .unwrap()
        .0;
    assert_eq!(switch_ctx.to_domain.read().data.id, dom1_id);
    assert_eq!(switch_ctx.interrupt_return, Some(0));
    assert_eq!(switch_ctx.interrupt_inject, None);

    // dom1.vp0 should now be Running
    let dom1_vp0 = dom1.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(
            *dom1_vp0.run_state.read(),
            VpRunState::Running { core: 0, .. }
        ),
        "dom1 VP[0] should be Running after resume"
    );

    // dom2.vp0 stays Waiting{unlocks:None} — no release step, untouched
    // until dom1 explicitly resumes its exact callee. But since dom1.vp0 is
    // no longer Waiting (it just got resumed), dom2.vp0's blocked flag is
    // cleared as a side effect — it's now claimable by any authorized caller.
    let dom2_vp0 = dom2.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(
            &*dom2_vp0.run_state.read(),
            VpRunState::Waiting {
                unlocks: None,
                blocked: false,
                ..
            }
        ),
        "dom2 VP[0] should remain Waiting{{unlocks:None}} and become unblocked \
         after dom1 was resumed"
    );

    let _ = dom0_id;
}

/// Same 3-domain chain, but dom1 has `NotReport` policy: the resume walk
/// from dom0 does not stop at dom1 — it transparently collapses through
/// dom1 and lands on dom2 directly. dom1.vp0 is left re-pinned as `Locked`
/// (an active caller again), not `Running`, and dom2.vp0 is the one that
/// actually resumes.
#[test]
fn test_interrupt_resume_not_report_skips_to_callee() {
    let (dom0, dom1, dom2, platform) = setup_3domain_chain();
    let dom1_id = dom1.read().data.id;
    let dom2_id = dom2.read().data.id;

    // Make dom1's policy for vector 0 NotReport, so switching to dom1
    // transparently collapses down to its callee (dom2).
    set_vector_policy(&dom1, 0, not_report_policy());

    Capability::<Domain>::deliver_interrupt_vp(&platform, &dom2, 0, 0)
        .unwrap()
        .0;

    // After delivery: dom1.vp0 = Waiting{Some(dom2), blocked:false},
    // dom2.vp0 = Waiting{None, blocked:true} — same as the Report case,
    // since blocking only depends on chain position, not visibility policy.
    let dom1_vp0 = dom1.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(
            &*dom1_vp0.run_state.read(),
            VpRunState::Waiting {
                blocked: false,
                ..
            }
        )
    );
    let dom2_vp0 = dom2.read().data.policy.vprocessor_states[0].clone();
    assert!(matches!(
        &*dom2_vp0.run_state.read(),
        VpRunState::Waiting { blocked: true, .. }
    ));

    // dom0 switches to dom1 (NotReport): the walk should skip through dom1
    // and resume dom2 instead.
    let dom1_h_in_dom0 = find_domain_handle(&dom0, dom1_id);
    let switch_ctx = Capability::switch(&platform, &dom0, dom1_h_in_dom0, 0)
        .unwrap()
        .0;

    // The switch context reports dom2 as the actual target, not dom1.
    assert_eq!(switch_ctx.to_domain.read().data.id, dom2_id);
    assert_eq!(switch_ctx.to_vp_id, Some(0));

    // dom2.vp0 is now Running — it's the frame that actually resumed.
    let dom2_vp0 = dom2.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(
            *dom2_vp0.run_state.read(),
            VpRunState::Running { core: 0, .. }
        ),
        "dom2 VP[0] should be Running after the transparent collapse through dom1"
    );

    // dom1.vp0 is re-pinned as Locked (an active caller again), not Running.
    let dom1_vp0 = dom1.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(
            *dom1_vp0.run_state.read(),
            VpRunState::Locked {
                callee_domain_id,
                callee_vp_id: 0,
            } if callee_domain_id == dom2_id
        ),
        "dom1 VP[0] should be re-pinned Locked{{callee: dom2.vp0}}, not Running"
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
    let result = Capability::<Domain>::deliver_interrupt_vp(&platform, &root, 0, 0);
    assert!(
        result.is_err(),
        "expected error when no VP is running on core"
    );
    let _ = root_id;
}

/// **The core eunomia-crash regression test.** After interrupt delivery, a
/// *second* VP of the domain directly called by the handler (dom1.vp1, on a
/// *different* physical core) resumes dom1 — this must succeed with no
/// identity/ownership check: a `Waiting` VP with `blocked == false` is
/// claimable by any authorized caller, regardless of which exact VP/core
/// originally froze it (see `CoreContext::call_stack`'s doc). Prior to the
/// fix, this was incorrectly rejected with "owned by another caller".
///
/// dom1 is the frame directly called by the handler (dom0), so it starts
/// `blocked: false` immediately at delivery time — unlike a deeper frame
/// (see `test_deep_waiting_vp_blocked_until_caller_resumes` below), which
/// stays gated until its own caller resumes.
#[test]
fn test_waiting_vp_resumable_by_different_vp_same_domain() {
    let (dom0, dom1, dom2, platform) = setup_3domain_chain();
    set_vector_policy(&dom1, 0, VectorPolicy::default_report());
    let dom1_id = dom1.read().data.id;

    // Deliver interrupt: dom0 is handler, dom2.vp0 → Waiting{unlocks:None},
    // dom1.vp0 → Waiting{unlocks:Some(dom2), blocked:false}.
    Capability::<Domain>::deliver_interrupt_vp(&platform, &dom2, 0, 0)
        .unwrap()
        .0;

    // Sanity-check: dom1.vp0 is Waiting.
    let dom1_vp0 = dom1.read().data.policy.vprocessor_states[0].clone();
    assert!(matches!(
        &*dom1_vp0.run_state.read(),
        VpRunState::Waiting {
            unlocks: Some(_),
            ..
        }
    ));

    // Set dom0.vp1 to Running on core 1 — simulates a second, different VP
    // of dom0 (e.g. a different physical core) than the one (dom0.vp0) that
    // was originally frozen mid-call into dom1.
    {
        let d = dom0.read();
        let vp1 = d.data.policy.vprocessor_states[1].clone();
        drop(d);
        *vp1.run_state.write() = VpRunState::Running { core: 1 };
    }
    platform.set_current_core(Some(1));

    // Find dom1's handle in dom0's capability table.
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

    // dom0.vp1 (not dom0.vp0!) claims dom1.vp0 — must succeed.
    let (ctx, _) = Capability::switch(&platform, &dom0, dom1_h_in_dom0, 0)
        .expect("Waiting VP must be claimable by a different VP of the same domain");
    assert_eq!(ctx.to_domain.read().data.id, dom1_id);
    assert_eq!(ctx.to_vp_id, Some(0));

    let dom1_vp0 = dom1.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(
            *dom1_vp0.run_state.read(),
            VpRunState::Running { core: 1, .. }
        ),
        "dom1 VP[0] should now be Running on core 1, resumed by dom0.vp1"
    );
}

/// **Regression test for the B2/C1 bug** (two independent call chains
/// sharing a common intermediate domain): a deeper `Waiting` frame stays
/// gated (`blocked: true`) until its own direct caller has actually
/// resumed — a different VP of the caller's domain cannot skip ahead and
/// claim the deeper frame first, even though it holds a valid handle to it.
///
/// Chain: dom0(handler) → dom1 → dom2(leaf). dom2.vp0 starts
/// `blocked: true` (its caller dom1.vp0 is still Waiting). A different VP
/// of dom1 (dom1.vp1) must NOT be able to claim dom2 directly. Only after
/// dom1.vp0 itself is resumed (by any VP of dom0, the actual caller chain)
/// does dom2 become claimable by dom1.vp1.
#[test]
fn test_deep_waiting_vp_blocked_until_caller_resumes() {
    let (dom0, dom1, dom2, platform) = setup_3domain_chain();
    set_vector_policy(&dom1, 0, VectorPolicy::default_report());
    let dom0_id = dom0.read().data.id;
    let dom1_id = dom1.read().data.id;
    let dom2_id = dom2.read().data.id;

    // Deliver interrupt: dom0 is handler, dom2.vp0 → Waiting{unlocks:None,
    // blocked:true}, dom1.vp0 → Waiting{unlocks:Some(dom2), blocked:false}.
    Capability::<Domain>::deliver_interrupt_vp(&platform, &dom2, 0, 0)
        .unwrap()
        .0;

    // Set dom1.vp1 to Running on core 1 — a different VP of dom1 than the
    // one (dom1.vp0) actually in the frozen chain.
    {
        let d = dom1.read();
        let vp1 = d.data.policy.vprocessor_states[1].clone();
        drop(d);
        *vp1.run_state.write() = VpRunState::Running { core: 1 };
    }
    platform.set_current_core(Some(1));

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

    // dom1.vp1 tries to claim dom2 directly — must fail: dom2 is still
    // blocked because its caller (dom1.vp0) hasn't itself resumed.
    let result = Capability::switch(&platform, &dom1, dom2_h_in_dom1, 0);
    assert!(
        result.is_err(),
        "dom2 must not be claimable while its caller dom1.vp0 is still Waiting"
    );
    let dom2_vp0 = dom2.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(&*dom2_vp0.run_state.read(), VpRunState::Waiting { .. }),
        "dom2 must remain Waiting after the rejected claim"
    );

    // Now resume dom1.vp0 (its caller) via a different VP of dom0 — the
    // actual A1/B1/C1 pattern: dom0.vp1 claims dom1.
    {
        let d = dom0.read();
        let vp1 = d.data.policy.vprocessor_states[1].clone();
        drop(d);
        *vp1.run_state.write() = VpRunState::Running { core: 1 };
    }
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
    Capability::switch(&platform, &dom0, dom1_h_in_dom0, 0)
        .expect("dom1 must be claimable once its own caller (the handler) targets it");

    // dom2 is now unblocked as a side effect — dom1.vp1 can claim it.
    platform.set_current_core(Some(1));
    let (ctx, _) = Capability::switch(&platform, &dom1, dom2_h_in_dom1, 0)
        .expect("dom2 must become claimable once dom1 has actually resumed");
    assert_eq!(ctx.to_domain.read().data.id, dom2_id);
    let _ = dom0_id;
}

// ── T5: 4-domain chain, multi-frame Waiting cleanup ──────────────────────────
//
// dom0(handler) → dom1(Locked) → dom2(Locked) → dom3(Running)
//
// After delivering an interrupt to dom3 with dom0 as handler:
//   dom3.vp0 = Waiting { unlocks: None }
//   dom2.vp0 = Waiting { unlocks: Some(dom3.vp0) }
//   dom1.vp0 = Waiting { unlocks: Some(dom2.vp0) }
//   dom0.vp0 = Running (handler)

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
    platform.set_core_context(0, &dom0, 0);
    init_vp_running(&dom0, 0, 0);

    let (dom1, dom1_h) = make_sealed_child(&dom0);
    let dom1_id = dom1.read().data.id;
    platform.register_domain(dom1_id, Some(dom0_id));
    Capability::switch(&platform, &dom0, dom1_h, 0).unwrap().0;

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
    Capability::switch(&platform, &dom1, dom2_h_in_dom1, 0)
        .unwrap()
        .0;

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
    Capability::switch(&platform, &dom2, dom3_h_in_dom2, 0)
        .unwrap()
        .0;

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

fn not_report_policy() -> VectorPolicy {
    VectorPolicy {
        visibility: InterruptVisibility::NotReport,
        read_set: RegBitmap::NONE,
        write_set: RegBitmap::NONE,
        injectable: false,
    }
}

fn set_vector_policy(domain: &CapabilityRef<Domain>, vector: u8, policy: VectorPolicy) {
    domain
        .write()
        .data
        .policy
        .interrupts
        .set_policy(vector, policy);
}

/// After interrupt delivery to a 4-domain chain, verify the intermediate
/// states: dom3=Waiting{None}, dom2=Waiting{Some(dom3)}, dom1=Waiting{Some(dom2)}.
#[test]
fn test_4domain_interrupt_delivery_states() {
    let (dom0, dom1, dom2, dom3, platform) = setup_4domain_chain();
    let dom2_id = dom2.read().data.id;
    let dom3_id = dom3.read().data.id;

    Capability::<Domain>::deliver_interrupt_vp(&platform, &dom3, 0, 0)
        .unwrap()
        .0;

    // dom3.vp0 → Waiting { unlocks: None }
    let dom3_vp0 = dom3.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(
            &*dom3_vp0.run_state.read(),
            VpRunState::Waiting { unlocks: None, .. }
        ),
        "dom3 VP[0] should be Waiting{{unlocks:None}}"
    );

    // dom2.vp0 → Waiting { unlocks: Some(dom3.vp0) }
    let dom2_vp0 = dom2.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(&*dom2_vp0.run_state.read(),
            VpRunState::Waiting { unlocks: Some(callee), .. }
            if callee.domain_id == dom3_id && callee.vp_id == 0),
        "dom2 VP[0] should be Waiting on dom3.vp0"
    );

    // dom1.vp0 → Waiting { unlocks: Some(dom2.vp0) }
    let dom1_vp0 = dom1.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(&*dom1_vp0.run_state.read(),
            VpRunState::Waiting { unlocks: Some(callee), .. }
            if callee.domain_id == dom2_id && callee.vp_id == 0),
        "dom1 VP[0] should be Waiting on dom2.vp0"
    );

    // dom0.vp0 → Running (handler)
    let dom0_vp0 = dom0.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(
            *dom0_vp0.run_state.read(),
            VpRunState::Running { core: 0, .. }
        ),
        "dom0 VP[0] should be Running as handler"
    );
}

/// dom1/dom2/dom3 explicitly configured `Report` for vector 0 (this used to
/// be capa-engine's blanket default for restricted domains; it is now
/// opt-in — see `VectorPolicy::default_not_report`). Claiming dom1 stops
/// immediately (dom1.report == true): dom1 → Running, dom2 and dom3 are left
/// completely untouched (still Waiting) — no release step. Then claiming
/// dom2 (also `Report`) likewise stops immediately, dom3 still untouched.
#[test]
fn test_4domain_default_report_chain_stops_one_level_at_a_time() {
    let (dom0, dom1, dom2, dom3, platform) = setup_4domain_chain();
    set_vector_policy(&dom1, 0, VectorPolicy::default_report());
    set_vector_policy(&dom2, 0, VectorPolicy::default_report());
    let dom1_id = dom1.read().data.id;

    Capability::<Domain>::deliver_interrupt_vp(&platform, &dom3, 0, 0)
        .unwrap()
        .0;

    // Step 1: dom0 claims dom1 (Waiting, report=true → Running immediately).
    let dom1_h = find_domain_handle(&dom0, dom1_id);
    let (ctx1, _) = Capability::switch(&platform, &dom0, dom1_h, 0).unwrap();
    assert_eq!(ctx1.to_domain.read().data.id, dom1_id);
    assert_eq!(ctx1.interrupt_return, Some(0));
    assert_eq!(ctx1.interrupt_inject, None);

    let dom1_vp0 = dom1.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(*dom1_vp0.run_state.read(), VpRunState::Running { .. }),
        "dom1 VP[0] must be Running after being claimed"
    );

    // dom2.vp0 untouched — still Waiting on dom3.
    let dom2_vp0 = dom2.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(
            &*dom2_vp0.run_state.read(),
            VpRunState::Waiting {
                unlocks: Some(_),
                ..
            }
        ),
        "dom2 VP[0] must remain Waiting — no release step happens on claim"
    );

    // dom3.vp0 untouched — still Waiting{None}.
    let dom3_vp0 = dom3.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(
            &*dom3_vp0.run_state.read(),
            VpRunState::Waiting { unlocks: None, .. }
        ),
        "dom3 VP[0] must still be Waiting{{unlocks:None}}"
    );

    // Step 2: dom1 claims dom2 (Waiting, report=true → Running immediately).
    let dom2_id = dom2.read().data.id;
    let dom2_h = find_domain_handle(&dom1, dom2_id);
    let (ctx2, _) = Capability::switch(&platform, &dom1, dom2_h, 0).unwrap();
    assert_eq!(ctx2.interrupt_return, Some(0));

    let dom2_vp0 = dom2.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(*dom2_vp0.run_state.read(), VpRunState::Running { .. }),
        "dom2 VP[0] must be Running after being claimed by dom1"
    );

    // dom3.vp0 still untouched — still Waiting{None} until dom2 itself
    // explicitly resumes it.
    let dom3_vp0 = dom3.read().data.policy.vprocessor_states[0].clone();
    assert!(
        matches!(
            &*dom3_vp0.run_state.read(),
            VpRunState::Waiting { unlocks: None, .. }
        ),
        "dom3 VP[0] must remain Waiting{{unlocks:None}} until its exact caller resumes it"
    );
}

/// All of dom1/dom2/dom3 set to `NotReport`: the walk transparently
/// collapses through all three frames in a single switch call, landing
/// directly on dom3 (the true leaf), which resumes silently — no
/// `interrupt_return`/`interrupt_inject` signal at all.
#[test]
fn test_interrupt_resume_all_not_report_descends_to_leaf() {
    let (dom0, dom1, dom2, dom3, platform) = setup_4domain_chain();
    let vector = 0x40;
    set_vector_policy(&dom0, vector, VectorPolicy::default_deliver());
    for domain in [&dom1, &dom2, &dom3] {
        set_vector_policy(domain, vector, not_report_policy());
    }

    Capability::<Domain>::deliver_interrupt_vp(&platform, &dom3, 0, vector).unwrap();

    let dom1_id = dom1.read().data.id;
    let dom3_id = dom3.read().data.id;
    let dom1_handle = find_domain_handle(&dom0, dom1_id);
    let (ctx, _) = Capability::switch(&platform, &dom0, dom1_handle, 0).unwrap();

    assert_eq!(ctx.to_domain.read().data.id, dom3_id);
    assert_eq!(ctx.to_vp_id, Some(0));
    assert_eq!(ctx.interrupt_return, None);
    assert_eq!(ctx.interrupt_inject, None);
    assert!(matches!(
        *dom1.read().data.policy.vprocessor_states[0]
            .run_state
            .read(),
        VpRunState::Locked { .. }
    ));
    assert!(matches!(
        *dom2.read().data.policy.vprocessor_states[0]
            .run_state
            .read(),
        VpRunState::Locked { .. }
    ));
    assert!(matches!(
        *dom3.read().data.policy.vprocessor_states[0]
            .run_state
            .read(),
        VpRunState::Running { core: 0, .. }
    ));
}

/// dom1=NotReport, dom2=Report, dom3=NotReport: the walk collapses through
/// dom1 and stops at dom2 (report=true). dom2 has a callee (dom3), so this
/// is the synthetic-return case: `interrupt_return = Some(vector)`,
/// `interrupt_inject = None`. dom3 stays untouched (Waiting).
#[test]
fn test_interrupt_resume_stops_at_first_report_frame() {
    let (dom0, dom1, dom2, dom3, platform) = setup_4domain_chain();
    let vector = 0x41;
    set_vector_policy(&dom0, vector, VectorPolicy::default_deliver());
    set_vector_policy(&dom1, vector, not_report_policy());
    set_vector_policy(&dom2, vector, VectorPolicy::default_report());
    set_vector_policy(&dom3, vector, not_report_policy());

    Capability::<Domain>::deliver_interrupt_vp(&platform, &dom3, 0, vector).unwrap();

    let dom1_id = dom1.read().data.id;
    let dom2_id = dom2.read().data.id;
    let dom1_handle = find_domain_handle(&dom0, dom1_id);
    let (ctx, _) = Capability::switch(&platform, &dom0, dom1_handle, 0).unwrap();

    assert_eq!(ctx.to_domain.read().data.id, dom2_id);
    assert_eq!(ctx.to_vp_id, Some(0));
    assert_eq!(ctx.interrupt_return, Some(vector));
    assert_eq!(ctx.interrupt_inject, None);
    assert!(matches!(
        *dom1.read().data.policy.vprocessor_states[0]
            .run_state
            .read(),
        VpRunState::Locked { .. }
    ));
    assert!(matches!(
        *dom2.read().data.policy.vprocessor_states[0]
            .run_state
            .read(),
        VpRunState::Running { core: 0, .. }
    ));
    assert!(matches!(
        &*dom3.read().data.policy.vprocessor_states[0]
            .run_state
            .read(),
        VpRunState::Waiting { unlocks: None, .. }
    ));
}

/// dom1=NotReport, dom2=NotReport, dom3(leaf)=Report: the walk collapses
/// through dom1 and dom2, stopping at dom3 — the true leaf (`unlocks:
/// None`). Since dom3 has no callee, this is the **injection** case:
/// `interrupt_inject = Some(vector)`, `interrupt_return = None`.
#[test]
fn test_interrupt_resume_stops_at_leaf_with_report_injects() {
    let (dom0, dom1, dom2, dom3, platform) = setup_4domain_chain();
    let vector = 0x42;
    set_vector_policy(&dom0, vector, VectorPolicy::default_deliver());
    set_vector_policy(&dom1, vector, not_report_policy());
    set_vector_policy(&dom2, vector, not_report_policy());
    set_vector_policy(&dom3, vector, VectorPolicy::default_report());

    Capability::<Domain>::deliver_interrupt_vp(&platform, &dom3, 0, vector).unwrap();

    let dom1_id = dom1.read().data.id;
    let dom3_id = dom3.read().data.id;
    let dom1_handle = find_domain_handle(&dom0, dom1_id);
    let (ctx, _) = Capability::switch(&platform, &dom0, dom1_handle, 0).unwrap();

    assert_eq!(ctx.to_domain.read().data.id, dom3_id);
    assert_eq!(ctx.to_vp_id, Some(0));
    assert_eq!(ctx.interrupt_return, None);
    assert_eq!(ctx.interrupt_inject, Some(vector));
    assert!(matches!(
        *dom1.read().data.policy.vprocessor_states[0]
            .run_state
            .read(),
        VpRunState::Locked { .. }
    ));
    assert!(matches!(
        *dom2.read().data.policy.vprocessor_states[0]
            .run_state
            .read(),
        VpRunState::Locked { .. }
    ));
    assert!(matches!(
        *dom3.read().data.policy.vprocessor_states[0]
            .run_state
            .read(),
        VpRunState::Running { core: 0, .. }
    ));
}

/// dom1=NotReport, dom2=NotReport, dom3(leaf)=NotReport: full transparent
/// collapse all the way to the true leaf, which also resumes silently — no
/// signal whatsoever, exactly as if the interrupt never happened.
#[test]
fn test_interrupt_resume_all_not_report_including_leaf_is_fully_silent() {
    let (dom0, dom1, dom2, dom3, platform) = setup_4domain_chain();
    let vector = 0x43;
    set_vector_policy(&dom0, vector, VectorPolicy::default_deliver());
    for domain in [&dom1, &dom2, &dom3] {
        set_vector_policy(domain, vector, not_report_policy());
    }

    Capability::<Domain>::deliver_interrupt_vp(&platform, &dom3, 0, vector).unwrap();

    let dom1_id = dom1.read().data.id;
    let dom3_id = dom3.read().data.id;
    let dom1_handle = find_domain_handle(&dom0, dom1_id);
    let (ctx, _) = Capability::switch(&platform, &dom0, dom1_handle, 0).unwrap();

    assert_eq!(ctx.to_domain.read().data.id, dom3_id);
    assert_eq!(ctx.interrupt_return, None);
    assert_eq!(ctx.interrupt_inject, None);
}

/// dom1(leaf's grandparent)=Report, dom2=Report, dom3(leaf)=Report: every
/// frame stops immediately at its own level — one switch call per hop, each
/// carrying its own `interrupt_return`, and the final hop into the true leaf
/// carries `interrupt_inject` instead.
#[test]
fn test_interrupt_resume_all_report_stops_at_every_level() {
    let (dom0, dom1, dom2, dom3, platform) = setup_4domain_chain();
    let vector = 0x44;
    set_vector_policy(&dom0, vector, VectorPolicy::default_deliver());
    for domain in [&dom1, &dom2, &dom3] {
        set_vector_policy(domain, vector, VectorPolicy::default_report());
    }

    Capability::<Domain>::deliver_interrupt_vp(&platform, &dom3, 0, vector).unwrap();

    let dom1_id = dom1.read().data.id;
    let dom2_id = dom2.read().data.id;
    let dom3_id = dom3.read().data.id;

    // Hop 1: dom0 → dom1, stops immediately (report=true, has callee dom2).
    let dom1_handle = find_domain_handle(&dom0, dom1_id);
    let (ctx1, _) = Capability::switch(&platform, &dom0, dom1_handle, 0).unwrap();
    assert_eq!(ctx1.to_domain.read().data.id, dom1_id);
    assert_eq!(ctx1.interrupt_return, Some(vector));
    assert_eq!(ctx1.interrupt_inject, None);

    // Hop 2: dom1 → dom2, stops immediately (report=true, has callee dom3).
    let dom2_handle = find_domain_handle(&dom1, dom2_id);
    let (ctx2, _) = Capability::switch(&platform, &dom1, dom2_handle, 0).unwrap();
    assert_eq!(ctx2.to_domain.read().data.id, dom2_id);
    assert_eq!(ctx2.interrupt_return, Some(vector));
    assert_eq!(ctx2.interrupt_inject, None);

    // Hop 3: dom2 → dom3, the true leaf (no callee) → injection.
    let dom3_handle = find_domain_handle(&dom2, dom3_id);
    let (ctx3, _) = Capability::switch(&platform, &dom2, dom3_handle, 0).unwrap();
    assert_eq!(ctx3.to_domain.read().data.id, dom3_id);
    assert_eq!(ctx3.interrupt_return, None);
    assert_eq!(ctx3.interrupt_inject, Some(vector));
}

/// Regression for the eunomia crash: after interrupt delivery in a 4-domain
/// chain, the handler resumes an intermediate frame from a VP other than
/// the one recorded as its original caller (simulating dom0 retrying the
/// switch hypercall from a different physical core after `-EAGAIN`
/// migration). This must succeed — no ownership/identity check.
#[test]
fn test_4domain_resume_from_different_vp_and_core_succeeds() {
    let (dom0, dom1, dom2, dom3, platform) = setup_4domain_chain();
    let vector = 0x45;
    set_vector_policy(&dom0, vector, VectorPolicy::default_deliver());
    set_vector_policy(&dom1, vector, not_report_policy());
    set_vector_policy(&dom2, vector, VectorPolicy::default_report());
    set_vector_policy(&dom3, vector, not_report_policy());

    Capability::<Domain>::deliver_interrupt_vp(&platform, &dom3, 0, vector).unwrap();

    // dom0.vp1 (not vp0!) on a different core resumes dom1.
    {
        let d = dom0.read();
        let vp1 = d.data.policy.vprocessor_states[1].clone();
        drop(d);
        *vp1.run_state.write() = VpRunState::Running { core: 2 };
    }
    platform.set_current_core(Some(2));

    let dom1_id = dom1.read().data.id;
    let dom2_id = dom2.read().data.id;
    let dom1_handle = find_domain_handle(&dom0, dom1_id);
    let (ctx, _) = Capability::switch(&platform, &dom0, dom1_handle, 0)
        .expect("resuming a Waiting chain from a different VP/core must succeed");

    // Collapses through dom1 (NotReport), stops at dom2 (Report).
    assert_eq!(ctx.to_domain.read().data.id, dom2_id);
    assert_eq!(ctx.from_vp_id, Some(1));
    assert_eq!(ctx.core_id, 2);
    assert!(matches!(
        *dom2.read().data.policy.vprocessor_states[0]
            .run_state
            .read(),
        VpRunState::Running { core: 2, .. }
    ));
}

// ── Two independent chains sharing an intermediate domain ────────────────────
//
// Exact scenario the `blocked` field exists for: two independent call chains,
// A1 -> B1 -> C1 (interrupted, frozen) and A2 -> B2 (separately active,
// unrelated), both through the same domain B. B2 holds a valid handle to C
// (handles belong to the domain, not the VP), but must NOT be able to claim
// C1 until B1 has actually been resumed.

/// A1 -> B1 -> C1 interrupted (handler A), plus a separate, concurrently
/// active A2 -> B2 chain through the same domain B.
///
/// B2 must not be able to claim C1 directly (C1 is still blocked: its caller
/// B1 hasn't itself resumed). Once A1 resumes B1 (from any VP of A), C1
/// becomes independently claimable, and B2 can then claim it.
#[test]
fn test_independent_chain_cannot_steal_deeper_waiting_frame() {
    let platform = common::TestPlatform::new();
    platform.set_current_core(Some(0));

    // Domain A (root), 4 VPs (vp0 = A1, vp1 = A2).
    let a = Capability::new_root(0, 0, Domain::new_root(4));
    init_vp_running(&a, 0, 0);
    init_vp_running(&a, 1, 1);

    // Domain B, child of A, 4 VPs (vp0 = B1, vp1 = B2).
    let (b, b_h) = make_sealed_child(&a);
    set_vector_policy(&b, 0, VectorPolicy::default_report());

    // Domain C, child of A (visible to B via a manually added handle, as in
    // `setup_3domain_chain` above).
    let (c, _c_h_in_a) = make_sealed_child(&a);
    let c_id = c.read().data.id;
    let c_h_in_b = {
        let c_weak = Arc::downgrade(&c);
        let mut bw = b.write();
        let h = bw.data.allocate_domain_handle();
        bw.data.add_domain_capability(h, c_weak);
        h
    };

    // Chain 1: A1 (core 0) -> B1 (core 0) -> C1 (core 0).
    Capability::switch(&platform, &a, b_h, 0).unwrap(); // A1 Locked, B1 Running(core0)
    Capability::switch(&platform, &b, c_h_in_b, 0).unwrap(); // B1 Locked, C1 Running(core0)

    // Chain 2: A2 (core 1) -> B2 (core 1). Independent, unrelated.
    platform.set_current_core(Some(1));
    Capability::switch(&platform, &a, b_h, 1).unwrap(); // A2 Locked, B2 Running(core1)

    // Interrupt hits C1 on core 0; A is the handler.
    Capability::<Domain>::deliver_interrupt_vp(&platform, &c, 0, 0).unwrap();

    // B1 is now Waiting{unlocks:Some(C1), blocked:false} (directly called by
    // the handler A). C1 is Waiting{unlocks:None, blocked:true}.
    let b_vp0 = b.read().data.policy.vprocessor_states[0].clone();
    assert!(matches!(
        &*b_vp0.run_state.read(),
        VpRunState::Waiting {
            unlocks: Some(_),
            ..
        }
    ));

    // B2 tries to claim C1 directly, using B's (shared, domain-level) handle
    // to C. Must fail: C1 is still blocked because B1 hasn't resumed.
    platform.set_current_core(Some(1));
    let result = Capability::switch(&platform, &b, c_h_in_b, 0);
    assert!(
        result.is_err(),
        "B2 must not be able to claim C1 before B1 has resumed"
    );
    assert!(
        matches!(
            &*c.read().data.policy.vprocessor_states[0].run_state.read(),
            VpRunState::Waiting { .. }
        ),
        "C1 must remain Waiting after the rejected claim"
    );

    // A1 resumes B1 (the actual caller chain, core 0).
    platform.set_current_core(Some(0));
    Capability::switch(&platform, &a, b_h, 0)
        .expect("B1 must be claimable by A (its actual caller) once targeted");
    assert!(matches!(
        &*b_vp0.run_state.read(),
        VpRunState::Running { core: 0, .. }
    ));

    // Now C1 is unblocked as a side effect. B2 can claim it.
    platform.set_current_core(Some(1));
    let (ctx, _) = Capability::switch(&platform, &b, c_h_in_b, 0)
        .expect("C1 must become claimable by B2 once B1 has actually resumed");
    assert_eq!(ctx.to_domain.read().data.id, c_id);
}
