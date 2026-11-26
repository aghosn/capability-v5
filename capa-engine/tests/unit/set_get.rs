//! Unit tests for `Capability::set_policy`, `get_policy`, `set_register`, `get_register`.
//!
//! Covers:
//! - Happy-path reads and writes for every `PolicyIdentifier` variant.
//! - `get_policy` works on sealed domains; `set_policy` is blocked on sealed domains.
//! - Monotonicity enforcement for `Cores` and `ApiMonitor`.
//! - Register bitmaps (`VectorRegReadSet`/`VectorRegWriteSet`) are NOT monotone.
//! - `set_register`/`get_register` enforce write/read bitmaps per effective vector.
//! - `VECTOR_AVAILABLE` (0xFF) path: bitmaps apply when VP is not interrupted.
//! - Per-vector override path: bitmaps apply under a specific interrupt vector.
//! - Invalid visibility value is rejected.
//! - Bad child handle is rejected.
//! - Missing `MonitorAPI::SET`/`GET` blocks the operation.
//! - Register ID out of range is rejected.

use capability_engine::*;

#[path = "../common/mod.rs"]
mod common;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Create a root domain with 4 cores and `MonitorAPI::ALL`.
fn root() -> CapabilityRef<Domain> {
    let _platform = common::TestPlatform::new();
    Capability::new_root(0, 0, Domain::new_root(4))
}

/// Create an unsealed child under `parent` with the given policy, and return
/// `(child_ref, handle)`.
fn make_child(
    platform: &common::TestPlatform,
    parent: &CapabilityRef<Domain>,
    policy: DomainPolicy,
) -> (CapabilityRef<Domain>, LocalHandle) {
    if parent.read().data.id == 0 {
        platform.ensure_boot_memory(parent);
    }
    let num_vps = policy.num_vprocessors;
    let h = Capability::create(platform, parent, policy).unwrap().0;
    let child = parent
        .read()
        .data
        .domain_capabilities[&h]
        .upgrade()
        .unwrap();
    common::add_test_vps(platform, parent, h, num_vps);
    let pool_size = 0x100_0000 >> child.read().depth;
    common::delegate_test_memory(platform, parent, h, pool_size);
    (child, h)
}

/// Seal a child via its parent handle.
fn seal(parent: &CapabilityRef<Domain>, h: LocalHandle) {
    let platform = common::TestPlatform::new();
    Capability::seal(&platform, parent, h).unwrap();
}

/// Initialise a domain's VP[vp_id] to `Running { core }`. Only used to
/// bootstrap a root/dom0-level domain's own VP, which has no capability-op
/// path to reach `Running` for the first time (a hardware/boot fact, not a
/// capability-mediated transition) — matches `tests/unit/switch.rs`'s
/// `init_vp_running` and `tests/concurrency/loom_vp_switch.rs`'s equivalent.
fn init_vp_running(domain: &CapabilityRef<Domain>, vp_id: usize, core: u64) {
    let d = domain.read();
    let vp = d.data.policy.vprocessor_states[vp_id].clone();
    drop(d);
    *vp.run_state.write() = VpRunState::Running { core };
}

// ─────────────────────────────────────────────────────────────────────────────
// set_policy / get_policy — happy paths
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn cpuid_emulated_ranges_ignore_subleaf_only_where_configured() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (child, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(3, MonitorAPI::ALL));
    for vp in 0..2 {
        for (start, end, result) in [
            (
                (0, 0),
                (1, u32::MAX),
                CpuidResult {
                    v0: 7,
                    v1: vp as u32,
                    v2: 8,
                    v3: 9,
                },
            ),
            (
                (7, 0),
                (7, 0),
                CpuidResult {
                    v0: 1,
                    ..CpuidResult::default()
                },
            ),
            (
                (7, 1),
                (7, 1),
                CpuidResult {
                    v0: 2,
                    ..CpuidResult::default()
                },
            ),
            ((7, 2), (7, u32::MAX), CpuidResult::default()),
            (
                (u32::MAX, 0),
                (u32::MAX, u32::MAX),
                CpuidResult {
                    v0: 42,
                    ..CpuidResult::default()
                },
            ),
        ] {
            for (word, value) in [
                (0, (u64::from(result.v0) << 32) | u64::from(result.v1)),
                (1, (u64::from(result.v2) << 32) | u64::from(result.v3)),
            ] {
                Capability::set_policy_scoped(
                    &platform,
                    &parent,
                    h,
                    PolicyScope::Vp(vp),
                    PolicyIdentifier::ProcFeatureEmulateRange(
                        ResourceKind::Cpuid,
                        start.0,
                        start.1,
                        end.0,
                        end.1,
                        word,
                    ),
                    value,
                )
                .unwrap();
            }
        }
    }
    seal(&parent, h);
    init_vp_running(&parent, 0, 0);
    platform.set_current_core(Some(0));
    for vp in 0..2 {
        Capability::switch(&platform, &parent, h, vp).unwrap();
        for leaf in [0, 1] {
            for subleaf in [0, 0xc35380, u32::MAX] {
                assert_eq!(
                    Capability::cpuid_action(&platform, &child, leaf, subleaf).unwrap(),
                    FeatureAction::Emulate(CpuidResult {
                        v0: 7,
                        v1: vp as u32,
                        v2: 8,
                        v3: 9
                    }),
                );
            }
        }
        for (subleaf, eax) in [(0, 1), (1, 2), (2, 0), (u32::MAX, 0)] {
            assert_eq!(
                Capability::cpuid_action(&platform, &child, 7, subleaf).unwrap(),
                FeatureAction::Emulate(CpuidResult {
                    v0: eax,
                    ..CpuidResult::default()
                }),
            );
        }
        assert_eq!(
            Capability::cpuid_action(&platform, &child, u32::MAX, u32::MAX).unwrap(),
            FeatureAction::Emulate(CpuidResult {
                v0: 42,
                ..CpuidResult::default()
            }),
        );
        Capability::switch_return_with_exit(&platform, &child, 30).unwrap();
    }
    assert_eq!(
        Capability::set_policy_scoped(
            &platform,
            &parent,
            h,
            PolicyScope::Vp(0),
            PolicyIdentifier::ProcFeatureEmulateRange(ResourceKind::Cpuid, 0, 0, 1, u32::MAX, 0),
            0,
        )
        .unwrap_err(),
        CapaError::DomainSealed,
    );
}

#[test]
fn emulate_range_rejects_partial_updates_and_invalid_ranges_without_mutation() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (child, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(1, MonitorAPI::ALL));
    let id = PolicyIdentifier::ProcFeatureEmulateRange(ResourceKind::Cpuid, 1, 0, 1, u32::MAX, 0);
    Capability::set_policy(&platform, &parent, h, id, 42).unwrap();
    let original = child.read().data.policy.cpuid.clone();
    platform.drain_updates();
    for (id, error) in [
        (
            PolicyIdentifier::ProcFeatureEmulateRange(ResourceKind::Cpuid, 2, 0, 1, 0, 0),
            CapaError::InvalidValue,
        ),
        (
            PolicyIdentifier::ProcFeatureEmulateRange(ResourceKind::Cpuid, 1, 0, 1, u32::MAX, 2),
            CapaError::InvalidValue,
        ),
        (
            PolicyIdentifier::ProcFeatureEmulateRange(ResourceKind::Cpuid, 0, 0, 1, 0, 0),
            CapaError::RegionOverlap,
        ),
        (
            PolicyIdentifier::ProcFeatureEmulateRange(ResourceKind::Cpuid, 1, 1, 2, 0, 0),
            CapaError::RegionOverlap,
        ),
        (
            PolicyIdentifier::ProcFeatureEmulate(ResourceKind::Cpuid, 1, 0, 0),
            CapaError::RegionOverlap,
        ),
        (
            PolicyIdentifier::ProcFeatureEmulate(ResourceKind::Cpuid, 1, 0, 1),
            CapaError::NotFound,
        ),
        (
            PolicyIdentifier::ProcFeatureEmulateRange(ResourceKind::Cpuid, 1, 1, 1, 2, 1),
            CapaError::NotFound,
        ),
        (
            PolicyIdentifier::ProcFeatureEmulateRange(ResourceKind::Cpuid, 3, 0, 3, 1, 1),
            CapaError::NotFound,
        ),
    ] {
        assert_eq!(
            Capability::set_policy_scoped(&platform, &parent, h, PolicyScope::Vp(0), id, 99)
                .unwrap_err(),
            error
        );
        assert_eq!(child.read().data.policy.cpuid, original);
        assert!(child.read().data.policy.vp_policies.is_empty());
        assert!(platform.drain_updates().is_empty());
    }
    Capability::set_policy(&platform, &parent, h, id, 43).unwrap();
    assert_eq!(
        child.read().data.policy.cpuid.action(&(1, u32::MAX)),
        FeatureAction::Emulate(CpuidResult {
            v1: 43,
            ..CpuidResult::default()
        }),
    );
}

#[test]
fn msr_emulated_ranges_use_normal_interception_and_cpu_local_values() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (child, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(1, MonitorAPI::ALL));
    let id = |sub, word| {
        PolicyIdentifier::ProcFeatureEmulateRange(ResourceKind::Msr, 0x1234, sub, 0x1236, 0, word)
    };
    assert_eq!(
        Capability::set_policy(&platform, &parent, h, id(1, 0), 42).unwrap_err(),
        CapaError::InvalidValue
    );
    assert_eq!(
        Capability::set_policy(&platform, &parent, h, id(0, 1), 42).unwrap_err(),
        CapaError::NotFound
    );
    Capability::set_policy(&platform, &parent, h, id(0, 0), 42).unwrap();
    let batch = Capability::set_policy(&platform, &parent, h, id(0, 1), 43).unwrap();
    assert!(batch
        .updates()
        .iter()
        .any(|u| matches!(u, Update::PolicyChanged {
        change: PolicyChange::VpInterception { msrs, .. }, ..
    } if msrs.action(&0x1235) == FeatureAction::Emulate((43 << 32) | 42))));
    seal(&parent, h);
    init_vp_running(&parent, 0, 0);
    platform.set_current_core(Some(0));
    Capability::switch(&platform, &parent, h, 0).unwrap();
    for msr in [0x1234, 0x1235, 0x1236] {
        assert_eq!(
            Capability::msr_action(&platform, &child, msr).unwrap(),
            FeatureAction::Emulate((43 << 32) | 42)
        );
    }
    Capability::update_msr_emulate_value(&platform, &child, 0x1235, 99).unwrap();
    assert_eq!(
        Capability::msr_action(&platform, &child, 0x1235).unwrap(),
        FeatureAction::Emulate(99)
    );
    assert_eq!(
        Capability::msr_action(&platform, &child, 0x1234).unwrap(),
        FeatureAction::Emulate((43 << 32) | 42)
    );
    Capability::switch_return_with_exit(&platform, &child, 30).unwrap();
}

#[test]
fn vp_cpuid_and_writable_msr_values_are_cpu_local() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (child, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(3, MonitorAPI::ALL));
    Capability::set_policy(
        &platform,
        &parent,
        h,
        PolicyIdentifier::ProcFeatureEmulate(ResourceKind::Cpuid, 0x4000_0001, 0, 0),
        42,
    )
    .unwrap();
    for vp in 0..2 {
        Capability::set_policy_scoped(
            &platform,
            &parent,
            h,
            PolicyScope::Vp(vp),
            PolicyIdentifier::ProcFeatureEmulate(ResourceKind::Cpuid, 1, 0, 0),
            (7 << 32) | (vp << 24),
        )
        .unwrap();
        Capability::set_policy_scoped(
            &platform,
            &parent,
            h,
            PolicyScope::Vp(vp),
            PolicyIdentifier::ProcFeatureEmulate(ResourceKind::Cpuid, 1, 0, 1),
            (0x55 << 32) | vp,
        )
        .unwrap();
    }
    Capability::set_policy(
        &platform,
        &parent,
        h,
        PolicyIdentifier::ProcFeatureEmulate(ResourceKind::Msr, 0x1234, 0, 0),
        17,
    )
    .unwrap();
    seal(&parent, h);
    init_vp_running(&parent, 0, 0);
    platform.set_current_core(Some(0));
    for vp in 0..2 {
        Capability::switch(&platform, &parent, h, vp).unwrap();
        assert_eq!(
            Capability::cpuid_action(&platform, &child, 0x4000_0001, 0).unwrap(),
            FeatureAction::Emulate(CpuidResult {
                v0: 0,
                v1: 42,
                v2: 0,
                v3: 0
            }),
        );
        assert_eq!(
            Capability::cpuid_action(&platform, &child, 1, 0).unwrap(),
            FeatureAction::Emulate(CpuidResult {
                v0: 7,
                v1: (vp as u32) << 24,
                v2: 0x55,
                v3: vp as u32,
            }),
        );
        assert_eq!(
            Capability::msr_action(&platform, &child, 0x1234).unwrap(),
            FeatureAction::Emulate(17)
        );
        Capability::update_msr_emulate_value(&platform, &child, 0x1234, 100 + vp).unwrap();
        Capability::switch_return_with_exit(&platform, &child, 30).unwrap();
    }
    for vp in 0..2 {
        Capability::switch(&platform, &parent, h, vp).unwrap();
        assert_eq!(
            Capability::msr_action(&platform, &child, 0x1234).unwrap(),
            FeatureAction::Emulate(100 + vp)
        );
        Capability::switch_return_with_exit(&platform, &child, 30).unwrap();
    }
    assert_eq!(
        child.read().data.policy.msrs.action(&0x1234),
        FeatureAction::Emulate(17)
    );
    assert!(Capability::update_msr_emulate_value(&platform, &child, 0x1234, 9).is_err());
}

#[test]
fn default_register_masks_apply_after_seal_and_survive_exit_override_creation() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(1, MonitorAPI::ALL));
    for word in 0..3 {
        for id in [
            PolicyIdentifier::DefaultInterruptRegReadSet(word),
            PolicyIdentifier::DefaultInterruptRegWriteSet(word),
            PolicyIdentifier::DefaultExitRegReadSet(word),
            PolicyIdentifier::DefaultExitRegWriteSet(word),
        ] {
            Capability::set_policy(&platform, &parent, h, id, 0).unwrap();
            assert_eq!(
                Capability::get_policy(&platform, &parent, h, id).unwrap().0,
                0
            );
        }
    }
    Capability::set_policy(
        &platform,
        &parent,
        h,
        PolicyIdentifier::ExitReasonTrap(30),
        1,
    )
    .unwrap();
    for id in [
        PolicyIdentifier::ExitReasonRegReadSet(30, 0),
        PolicyIdentifier::ExitReasonRegWriteSet(30, 0),
    ] {
        assert_eq!(
            Capability::get_policy(&platform, &parent, h, id).unwrap().0,
            0
        );
    }
    Capability::set_register(&platform, &parent, h, 0, 0, 42).unwrap();
    assert_eq!(
        Capability::get_register(&platform, &parent, h, 0, 0)
            .unwrap()
            .0,
        42
    );
    seal(&parent, h);
    assert_eq!(
        Capability::set_register(&platform, &parent, h, 0, 0, 99).unwrap_err(),
        CapaError::RegisterAccessDenied,
    );
    assert_eq!(
        Capability::get_register(&platform, &parent, h, 0, 0).unwrap_err(),
        CapaError::RegisterAccessDenied,
    );
}

#[test]
fn seal_freezes_all_vp_setup_before_runtime_write_masks_apply() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (child, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(3, MonitorAPI::ALL));
    let id = child.read().data.id;
    for word in 0..3 {
        Capability::set_policy(
            &platform,
            &parent,
            h,
            PolicyIdentifier::VectorRegWriteSet(VECTOR_AVAILABLE, word),
            0,
        )
        .unwrap();
    }
    Capability::set_register(&platform, &parent, h, 0, 0, 42).unwrap();
    Capability::seal(&platform, &parent, h).unwrap();
    assert_eq!(
        platform.drain_comm_snapshots(),
        [(id, 0, RegBitmap::ALL), (id, 1, RegBitmap::ALL)]
    );
    assert_eq!(
        Capability::set_register(&platform, &parent, h, 0, 0, 99).unwrap_err(),
        CapaError::RegisterAccessDenied
    );
    assert_eq!(
        Capability::seal(&platform, &parent, h).unwrap_err(),
        CapaError::DomainSealed
    );
    assert!(platform.drain_comm_snapshots().is_empty());

    init_vp_running(&parent, 0, 0);
    platform.set_current_core(Some(0));
    Capability::switch(&platform, &parent, h, 0).unwrap();
    assert_eq!(platform.drain_comm_snapshots(), [(id, 0, RegBitmap::NONE)]);
    Capability::switch_return_with_exit(&platform, &child, 30).unwrap();
}

#[test]
fn failed_initial_vp_capture_leaves_setup_unsealed_and_retryable() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (child, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(3, MonitorAPI::ALL));
    let id = child.read().data.id;
    platform.set_comm_snapshot_failure(Some(1));
    assert!(Capability::seal(&platform, &parent, h).is_err());
    assert_eq!(child.read().data.status, DomainStatus::Unsealed);
    assert_eq!(
        platform.drain_comm_snapshots(),
        [(id, 0, RegBitmap::ALL), (id, 1, RegBitmap::ALL)]
    );
    Capability::set_register(&platform, &parent, h, 0, 0, 99).unwrap();
    platform.set_comm_snapshot_failure(None);
    Capability::seal(&platform, &parent, h).unwrap();
    assert_eq!(child.read().data.status, DomainStatus::Sealed);
    assert_eq!(
        platform.drain_comm_snapshots(),
        [(id, 0, RegBitmap::ALL), (id, 1, RegBitmap::ALL)]
    );
}

#[test]
fn invalid_scoped_policy_values_do_not_create_overrides() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (child, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(1, MonitorAPI::ALL));
    for (id, value) in [
        (
            PolicyIdentifier::ProcFeatureDefault(ResourceKind::Cpuid),
            256,
        ),
        (
            PolicyIdentifier::ProcFeatureRange(ResourceKind::Msr, 1, 0, 2, 0),
            257,
        ),
        (PolicyIdentifier::DefaultExitTrap, 2),
        (PolicyIdentifier::ExitReasonRegReadSet(30, 3), 0),
        (PolicyIdentifier::VectorRegWriteSet(32, 255), 0),
        (PolicyIdentifier::DefaultInterruptRegReadSet(3), 0),
        (
            PolicyIdentifier::ProcFeatureEmulate(ResourceKind::Cpuid, 1, 0, 2),
            0,
        ),
        (
            PolicyIdentifier::ProcFeatureEmulate(ResourceKind::Msr, 1, 1, 0),
            0,
        ),
    ] {
        assert_eq!(
            Capability::set_policy_scoped(&platform, &parent, h, PolicyScope::Vp(0), id, value)
                .unwrap_err(),
            CapaError::InvalidValue,
        );
        assert!(child.read().data.policy.vp_policies.is_empty());
    }
    assert_eq!(
        Capability::get_policy(
            &platform,
            &parent,
            h,
            PolicyIdentifier::DefaultExitRegReadSet(3)
        )
        .unwrap_err(),
        CapaError::InvalidValue,
    );
}

#[test]
fn effective_hardware_snapshots_preserve_explicit_vp_policy() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(3, MonitorAPI::ALL));
    let id = PolicyIdentifier::ProcFeatureDefault(ResourceKind::Msr);
    Capability::set_policy_scoped(&platform, &parent, h, PolicyScope::Vp(0), id, 0).unwrap();
    let batch = Capability::set_policy(&platform, &parent, h, id, 1).unwrap();
    let snapshots: Vec<_> = batch
        .updates()
        .iter()
        .filter_map(|update| match update {
            Update::PolicyChanged {
                change: PolicyChange::VpInterception { vp_id, msrs, .. },
                ..
            } => Some((*vp_id, msrs.default)),
            _ => None,
        })
        .collect();
    assert_eq!(
        snapshots,
        vec![(0, DefaultAction::Trap), (1, DefaultAction::Native)]
    );
    let batch =
        Capability::clear_vp_policy(&platform, &parent, h, 0, ExecutionPolicyKind::Msr).unwrap();
    assert!(matches!(
        batch.updates(),
        [Update::PolicyChanged { change: PolicyChange::VpInterception { vp_id: 0, msrs, .. }, .. }]
            if msrs.default == DefaultAction::Native
    ));
}

#[test]
fn vp_override_is_category_local_and_can_restore_inheritance() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(3, MonitorAPI::ALL));
    let cpuid = PolicyIdentifier::ProcFeatureDefault(ResourceKind::Cpuid);
    let msr = PolicyIdentifier::ProcFeatureDefault(ResourceKind::Msr);
    Capability::set_policy_scoped(&platform, &parent, h, PolicyScope::Vp(0), cpuid, 1).unwrap();
    Capability::set_policy(&platform, &parent, h, msr, 1).unwrap();
    Capability::set_policy(&platform, &parent, h, cpuid, 1).unwrap();
    Capability::set_policy(&platform, &parent, h, cpuid, 0).unwrap();
    for (vp, expected) in [(0, 1), (1, 0)] {
        assert_eq!(
            Capability::get_policy_scoped(&platform, &parent, h, PolicyScope::Vp(vp), cpuid)
                .unwrap()
                .0,
            expected
        );
        assert_eq!(
            Capability::get_policy_scoped(&platform, &parent, h, PolicyScope::Vp(vp), msr)
                .unwrap()
                .0,
            1
        );
    }
    Capability::clear_vp_policy(&platform, &parent, h, 0, ExecutionPolicyKind::Cpuid).unwrap();
    assert_eq!(
        Capability::get_policy_scoped(&platform, &parent, h, PolicyScope::Vp(0), cpuid)
            .unwrap()
            .0,
        0
    );
}

#[test]
fn vp_policy_rejects_resource_authority_missing_vp_and_sealed_changes() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (child, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(3, MonitorAPI::ALL));
    for id in [
        PolicyIdentifier::Cores,
        PolicyIdentifier::ApiMonitor,
        PolicyIdentifier::VectorInjectable(32),
    ] {
        assert_eq!(
            Capability::set_policy_scoped(&platform, &parent, h, PolicyScope::Vp(0), id, 0)
                .unwrap_err(),
            CapaError::InvalidValue
        );
    }
    let id = PolicyIdentifier::ProcFeatureDefault(ResourceKind::Cpuid);
    assert_eq!(
        Capability::set_policy_scoped(&platform, &parent, h, PolicyScope::Vp(2), id, 0)
            .unwrap_err(),
        CapaError::NotFound
    );
    assert!(child.read().data.policy.vp_policies.is_empty());
    seal(&parent, h);
    assert_eq!(
        Capability::set_policy_scoped(&platform, &parent, h, PolicyScope::Vp(0), id, 0)
            .unwrap_err(),
        CapaError::DomainSealed
    );
    assert_eq!(
        Capability::clear_vp_policy(&platform, &parent, h, 0, ExecutionPolicyKind::Cpuid)
            .unwrap_err(),
        CapaError::DomainSealed
    );
}

#[test]
fn vp_register_permissions_and_interrupt_delivery_use_target_vp() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (child, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(3, MonitorAPI::ALL));
    Capability::set_policy_scoped(
        &platform,
        &parent,
        h,
        PolicyScope::Vp(0),
        PolicyIdentifier::VectorRegWriteSet(VECTOR_AVAILABLE, 0),
        0,
    )
    .unwrap();
    Capability::set_policy_scoped(
        &platform,
        &parent,
        h,
        PolicyScope::Vp(1),
        PolicyIdentifier::VectorVisibility(32),
        0,
    )
    .unwrap();
    seal(&parent, h);
    assert_eq!(
        Capability::set_register(&platform, &parent, h, 0, 0, 7).unwrap_err(),
        CapaError::RegisterAccessDenied
    );
    Capability::set_register(&platform, &parent, h, 1, 0, 7).unwrap();
    init_vp_running(&parent, 0, 0);
    platform.set_current_core(Some(0));
    Capability::switch(&platform, &parent, h, 1).unwrap();
    let (ctx, _) = Capability::deliver_interrupt_vp(&platform, &child, 0, 32).unwrap();
    assert_eq!(ctx.handler_domain.read().data.id, child.read().data.id);
    assert_eq!(ctx.handler_vp_id, 1);
    Capability::switch_return_with_exit(&platform, &child, 30).unwrap();
    Capability::switch(&platform, &parent, h, 0).unwrap();
    let (ctx, _) = Capability::deliver_interrupt_vp(&platform, &child, 0, 32).unwrap();
    assert_eq!(ctx.handler_domain.read().data.id, parent.read().data.id);
}

#[test]
fn test_set_get_cores() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::Cores, 0b0011).unwrap();
    let v = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::Cores).unwrap().0;
    assert_eq!(v, 0b0011);
}

#[test]
fn test_set_get_api_monitor() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let child_api = MonitorAPI::from_bits(MonitorAPI::GET | MonitorAPI::SWITCH);
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    let bits = child_api.bits() as u64;
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::ApiMonitor, bits).unwrap();
    let v = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::ApiMonitor).unwrap().0;
    assert_eq!(v, bits);
}

#[test]
fn test_set_get_default_interrupt_visibility() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // 1 = Report
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::DefaultInterruptVisibility, 1).unwrap();
    let v = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::DefaultInterruptVisibility).unwrap().0;
    assert_eq!(v, 1);
}

#[test]
fn test_set_get_vector_visibility() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // vector 32, visibility 2 = NotReport
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorVisibility(32), 2).unwrap();
    let v = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::VectorVisibility(32)).unwrap().0;
    assert_eq!(v, 2);
}

#[test]
fn test_set_get_vector_reg_read_set() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    let bitmap: u64 = 0b1010_1010;
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegReadSet(5, 0), bitmap).unwrap();
    let v = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::VectorRegReadSet(5, 0)).unwrap().0;
    assert_eq!(v, bitmap);
}

#[test]
fn test_set_get_vector_reg_write_set() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    let bitmap: u64 = 0xDEAD_BEEF;
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegWriteSet(7, 0), bitmap).unwrap();
    let v = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::VectorRegWriteSet(7, 0)).unwrap().0;
    assert_eq!(v, bitmap);
}

// ─────────────────────────────────────────────────────────────────────────────
// get_policy works on sealed domain; set_policy is blocked
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_get_policy_works_on_sealed_domain() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // set cores before sealing
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::Cores, 0b0101).unwrap();
    seal(&parent, h);

    let v = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::Cores).unwrap().0;
    assert_eq!(v, 0b0101);
}

#[test]
fn test_set_policy_blocked_on_sealed_domain() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));
    seal(&parent, h);

    let err = Capability::set_policy(&platform, &parent, h, PolicyIdentifier::Cores, 0b0011).unwrap_err();
    assert_eq!(err, CapaError::DomainSealed);
}

// ─────────────────────────────────────────────────────────────────────────────
// Monotonicity — Cores
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_cores_monotonicity_ok_subset() {
    let platform = common::TestPlatform::new();
    let parent = root(); // parent has all 4 cores (0b1111)
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // 0b0110 ⊆ 0b1111 → ok
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::Cores, 0b0110).unwrap();
}

#[test]
fn test_cores_monotonicity_violated() {
    let platform = common::TestPlatform::new();
    let parent = root(); // parent has 0b1111
    // create a child with only 0b0011, seal it, then create a grandchild
    let (_, child_h) =
        make_child(&platform, &parent, DomainPolicy::new_restricted(0b0011, MonitorAPI::ALL));
    seal(&parent, child_h);
    let child = parent.read().data.domain_capabilities[&child_h].upgrade().unwrap();

    let (_, grandchild_h) =
        make_child(&platform, &child, DomainPolicy::new_restricted(0b0011, MonitorAPI::ALL));

    // Try to give grandchild a core that child doesn't have (bit 2 = 0b0100)
    let err = Capability::set_policy(&platform, &child, grandchild_h, PolicyIdentifier::Cores, 0b0100)
        .unwrap_err();
    assert_eq!(err, CapaError::MonotonicityViolation);
}

#[test]
fn test_cores_monotonicity_same_value_ok() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b0011, MonitorAPI::ALL));

    // Same value is still a subset — must succeed
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::Cores, 0b0011).unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// Monotonicity — ApiMonitor
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_api_monotonicity_violated() {
    let platform = common::TestPlatform::new();
    let parent = root();
    // Constrained parent: GET | SWITCH | CREATE | SET | SEAL (needs CREATE to make grandchild,
    // SET to call set_policy, SEAL to seal itself)
    let parent_api = MonitorAPI::from_bits(
        MonitorAPI::GET | MonitorAPI::SWITCH | MonitorAPI::CREATE | MonitorAPI::SET | MonitorAPI::SEAL
            | MonitorAPI::CARVE | MonitorAPI::SEND,
    );
    let (_, c_h) =
        make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, parent_api));
    seal(&parent, c_h);
    let constrained = parent.read().data.domain_capabilities[&c_h].upgrade().unwrap();

    // Now create a grandchild under the constrained domain and try to grant SET
    // (which the constrained parent doesn't have).
    let (_, gc_h) =
        make_child(&platform, &constrained, DomainPolicy::new_restricted(0b1111, parent_api));

    let full_api = MonitorAPI::ALL.bits() as u64;
    let err =
        Capability::set_policy(&platform, &constrained, gc_h, PolicyIdentifier::ApiMonitor, full_api)
            .unwrap_err();
    assert_eq!(err, CapaError::MonotonicityViolation);
}

// ─────────────────────────────────────────────────────────────────────────────
// Register bitmaps are NOT monotone
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_register_bitmaps_not_monotone() {
    let platform = common::TestPlatform::new();
    // A restricted parent should still be able to set any bitmap value on its child.
    let parent = root();
    let (_, child_h) =
        make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));
    // Parent sets a small read bitmap on child
    Capability::set_policy(&platform, &parent, child_h, PolicyIdentifier::VectorRegReadSet(10, 0), 0b0001)
        .unwrap();
    seal(&parent, child_h);
    let child = parent.read().data.domain_capabilities[&child_h].upgrade().unwrap();

    // Now set a LARGER bitmap on a grandchild through the child — must succeed (no monotonicity).
    let (_, gc_h) =
        make_child(&platform, &child, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));
    Capability::set_policy(&platform, &child, gc_h, PolicyIdentifier::VectorRegReadSet(10, 0), 0xFFFF_FFFF)
        .unwrap();
    let v =
        Capability::get_policy(&platform, &child, gc_h, PolicyIdentifier::VectorRegReadSet(10, 0)).unwrap().0;
    assert_eq!(v, 0xFFFF_FFFF);
}

// ─────────────────────────────────────────────────────────────────────────────
// Invalid visibility value
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_invalid_visibility_value_rejected() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    let err =
        Capability::set_policy(&platform, &parent, h, PolicyIdentifier::DefaultInterruptVisibility, 99)
            .unwrap_err();
    assert!(matches!(err, CapaError::InvalidOperation(_)));
}

// ─────────────────────────────────────────────────────────────────────────────
// Bad child handle
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_set_policy_bad_handle() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let bogus: LocalHandle = 9999;
    let err =
        Capability::set_policy(&platform, &parent, bogus, PolicyIdentifier::Cores, 0b0001).unwrap_err();
    assert_eq!(err, CapaError::NotFound);
}

#[test]
fn test_get_policy_bad_handle() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let bogus: LocalHandle = 9999;
    let err =
        Capability::get_policy(&platform, &parent, bogus, PolicyIdentifier::Cores).unwrap_err();
    assert_eq!(err, CapaError::NotFound);
}

// ─────────────────────────────────────────────────────────────────────────────
// Missing MonitorAPI::SET / GET permission
//
// validate_operation checks the OWNER domain's policy.api (not the caller's own
// policy). So we need a 4-level hierarchy:
//   root → controller (restricted api, sealed) → caller (sealed) → target
// When caller invokes set/get, it checks caller.owned.owner_domain = controller,
// and controller's policy doesn't have the required bit → ApiNotAllowed.
// ─────────────────────────────────────────────────────────────────────────────

/// Build: root → controller (given api, sealed) → caller (sealed).
/// Returns (caller_ref, target_handle_in_caller).
fn make_restricted_caller(
    root: &CapabilityRef<Domain>,
    controller_api: MonitorAPI,
) -> (CapabilityRef<Domain>, LocalHandle, CapabilityRef<Domain>) {
    let platform = common::TestPlatform::new();
    // controller: sealed under root
    let ctrl_h = Capability::create(&platform, root, DomainPolicy::new_restricted(0b1111, controller_api)).unwrap().0;
    seal(root, ctrl_h);
    let ctrl = root.read().data.domain_capabilities[&ctrl_h].upgrade().unwrap();

    // caller: sealed under controller
    let caller_h = Capability::create(&platform, &ctrl, DomainPolicy::new_restricted(0b1111, controller_api)).unwrap().0;
    seal(&ctrl, caller_h);
    let caller = ctrl.read().data.domain_capabilities[&caller_h].upgrade().unwrap();

    // target: unsealed child of caller
    let target_h = Capability::create(&platform, &caller, DomainPolicy::new_restricted(0b1111, controller_api)).unwrap().0;

    (caller, target_h, ctrl)
}

#[test]
fn test_set_policy_requires_set_permission() {
    let platform = common::TestPlatform::new();
    let parent = root();
    // controller has CREATE + SEAL + GET but NOT SET
    let no_set = MonitorAPI::from_bits(
        MonitorAPI::CREATE | MonitorAPI::SEAL | MonitorAPI::GET,
    );
    let (caller, target_h, _ctrl) = make_restricted_caller(&parent, no_set);

    let err =
        Capability::set_policy(&platform, &caller, target_h, PolicyIdentifier::Cores, 0b0001).unwrap_err();
    assert_eq!(err, CapaError::ApiNotAllowed);
}

#[test]
fn test_get_policy_requires_get_permission() {
    let platform = common::TestPlatform::new();
    let parent = root();
    // controller has CREATE + SEAL + SET but NOT GET
    let no_get = MonitorAPI::from_bits(
        MonitorAPI::CREATE | MonitorAPI::SEAL | MonitorAPI::SET,
    );
    let (caller, target_h, _ctrl) = make_restricted_caller(&parent, no_get);

    let err = Capability::get_policy(&platform, &caller, target_h, PolicyIdentifier::Cores).unwrap_err();
    assert_eq!(err, CapaError::ApiNotAllowed);
}

// ─────────────────────────────────────────────────────────────────────────────
// set_register / get_register — VECTOR_AVAILABLE path (VP not interrupted)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_set_get_register_available_vp() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Allow reg 0 for read and write under VECTOR_AVAILABLE (0xFF).
    let bitmap: u64 = 1; // bit 0 set
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegReadSet(VECTOR_AVAILABLE, 0), bitmap)
        .unwrap();
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegWriteSet(VECTOR_AVAILABLE, 0), bitmap)
        .unwrap();

    // VP[0] is Available by default → effective vector = VECTOR_AVAILABLE.
    Capability::set_register(&platform, &parent, h, 0, 0, 0xCAFE).unwrap();
    let v = Capability::get_register(&platform, &parent, h, 0, 0).unwrap().0;
    assert_eq!(v, 0xCAFE);
}

#[test]
fn test_set_register_denied_when_bit_not_in_write_bitmap() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // write bitmap for VECTOR_AVAILABLE has bit 0 but NOT bit 1
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegWriteSet(VECTOR_AVAILABLE, 0), 0b01)
        .unwrap();
    seal(&parent, h);

    let err = Capability::set_register(&platform, &parent, h, 0, 1, 42).unwrap_err();
    assert_eq!(err, CapaError::RegisterAccessDenied);
}

#[test]
fn test_get_register_denied_when_bit_not_in_read_bitmap() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // read bitmap for VECTOR_AVAILABLE has bit 0 but NOT bit 2
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegReadSet(VECTOR_AVAILABLE, 0), 0b01)
        .unwrap();
    seal(&parent, h);

    let err = Capability::get_register(&platform, &parent, h, 0, 2).unwrap_err();
    assert_eq!(err, CapaError::RegisterAccessDenied);
}

// ─────────────────────────────────────────────────────────────────────────────
// set_register / get_register — per-vector override path (VP interrupted)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_set_get_register_interrupted_vp_uses_vector_override() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (child, h) =
        make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Grant access to reg 3 under vector 42 only.
    let bitmap: u64 = 1 << 3;
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegWriteSet(42, 0), bitmap).unwrap();
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegReadSet(42, 0), bitmap).unwrap();

    // Put VP[0] into a real Interrupted { vector: 42 } state via the actual
    // switch + deliver_interrupt_vp domain-mediated calls, not a raw
    // run_state write. Child keeps the default Report policy so the
    // interrupted leaf (child's own VP[0]) is what ends up Interrupted,
    // while parent (Deliver by default) resumes to Running as the handler.
    seal(&parent, h);
    init_vp_running(&parent, 0, 0);
    platform.set_current_core(Some(0));
    Capability::switch(&platform, &parent, h, 0).unwrap();
    Capability::deliver_interrupt_vp(&platform, &child, 0, 42).unwrap();

    Capability::set_register(&platform, &parent, h, 0, 3, 0xBEEF).unwrap();
    let v = Capability::get_register(&platform, &parent, h, 0, 3).unwrap().0;
    assert_eq!(v, 0xBEEF);
}

#[test]
fn test_register_access_blocked_for_different_vector() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (child, h) =
        make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Restrict the default VECTOR_AVAILABLE write bitmap (default_report sets u64::MAX).
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegWriteSet(VECTOR_AVAILABLE, 0), 0).unwrap();

    // Only allow reg 3 under vector 42.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegWriteSet(42, 0), 1 << 3).unwrap();
    // Explicitly deny vector 99.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegWriteSet(99, 0), 0).unwrap();

    // VP is interrupted by vector 99 → override write_set = 0. Reached via
    // the real switch + deliver_interrupt_vp calls, not a raw run_state
    // write. Child keeps the default Report policy so the interrupted leaf
    // (child's own VP[0]) is what ends up Interrupted.
    seal(&parent, h);
    init_vp_running(&parent, 0, 0);
    platform.set_current_core(Some(0));
    Capability::switch(&platform, &parent, h, 0).unwrap();
    Capability::deliver_interrupt_vp(&platform, &child, 0, 99).unwrap();

    let err = Capability::set_register(&platform, &parent, h, 0, 3, 0xBEEF).unwrap_err();
    assert_eq!(err, CapaError::RegisterAccessDenied);
}

#[test]
fn test_vector_override_does_not_affect_available_vp() {
    // A bitmap set for vector 42 must NOT grant access when the VP is Available.
    let parent = root();
    let platform = common::TestPlatform::new();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Clear the default VECTOR_AVAILABLE write bitmap so only per-vector overrides grant access.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegWriteSet(VECTOR_AVAILABLE, 0), 0).unwrap();

    // Grant write access to reg 5 only under vector 42.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegWriteSet(42, 0), 1 << 5).unwrap();
    seal(&parent, h);

    // VP[0] is Available by default.
    let err = Capability::set_register(&platform, &parent, h, 0, 5, 99).unwrap_err();
    assert_eq!(err, CapaError::RegisterAccessDenied);
}

// ─────────────────────────────────────────────────────────────────────────────
// set_register / get_register — Running VP must be denied
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_set_register_denied_when_vp_running() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (_child, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Grant full write access under VECTOR_AVAILABLE so bitmaps are not the obstacle.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegWriteSet(VECTOR_AVAILABLE, 0), u64::MAX)
        .unwrap();

    // Confirm write works while Available.
    Capability::set_register(&platform, &parent, h, 0, 0, 0x1).unwrap();

    // Transition to Running via a real `Capability::switch` call — register
    // access must now be denied.
    seal(&parent, h);
    init_vp_running(&parent, 0, 0);
    platform.set_current_core(Some(0));
    Capability::switch(&platform, &parent, h, 0).unwrap();
    let err = Capability::set_register(&platform, &parent, h, 0, 0, 0x2).unwrap_err();
    assert_eq!(err, CapaError::RegisterAccessDenied);
}

#[test]
fn test_get_register_denied_when_vp_running() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (_child, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Grant full read access under VECTOR_AVAILABLE.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegReadSet(VECTOR_AVAILABLE, 0), u64::MAX)
        .unwrap();

    // Confirm read works while Available.
    Capability::get_register(&platform, &parent, h, 0, 0).unwrap().0;

    // Transition to Running via a real `Capability::switch` call — register
    // access must now be denied.
    seal(&parent, h);
    init_vp_running(&parent, 0, 0);
    platform.set_current_core(Some(0));
    Capability::switch(&platform, &parent, h, 0).unwrap();
    let err = Capability::get_register(&platform, &parent, h, 0, 0).unwrap_err();
    assert_eq!(err, CapaError::RegisterAccessDenied);
}

// ─────────────────────────────────────────────────────────────────────────────
// Register out of range
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_set_register_out_of_range() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // TestPlatform has register_count() = 64; reg 64 is out of range.
    let err = Capability::set_register(&platform, &parent, h, 0, 64, 0).unwrap_err();
    assert_eq!(err, CapaError::RegisterOutOfRange);
}

#[test]
fn test_get_register_out_of_range() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    let err = Capability::get_register(&platform, &parent, h, 0, 64).unwrap_err();
    assert_eq!(err, CapaError::RegisterOutOfRange);
}

// ─────────────────────────────────────────────────────────────────────────────
// Missing MonitorAPI::SET / GET for registers
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_set_register_requires_set_permission() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let no_set = MonitorAPI::from_bits(MonitorAPI::CREATE | MonitorAPI::SEAL | MonitorAPI::GET);
    let (caller, target_h, _ctrl) = make_restricted_caller(&parent, no_set);

    let err = Capability::set_register(&platform, &caller, target_h, 0, 0, 0).unwrap_err();
    assert_eq!(err, CapaError::ApiNotAllowed);
}

#[test]
fn test_get_register_requires_get_permission() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let no_get = MonitorAPI::from_bits(MonitorAPI::CREATE | MonitorAPI::SEAL | MonitorAPI::SET);
    let (caller, target_h, _ctrl) = make_restricted_caller(&parent, no_get);

    let err = Capability::get_register(&platform, &caller, target_h, 0, 0).unwrap_err();
    assert_eq!(err, CapaError::ApiNotAllowed);
}

// ─────────────────────────────────────────────────────────────────────────────
// set_register / get_register work on sealed domains
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_set_register_works_on_sealed_domain() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (child, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Grant write access to reg 0 under VECTOR_AVAILABLE before sealing.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegWriteSet(VECTOR_AVAILABLE, 0), 1)
        .unwrap();
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegReadSet(VECTOR_AVAILABLE, 0), 1)
        .unwrap();

    seal(&parent, h);

    // VP is still Available after sealing, so effective vector = VECTOR_AVAILABLE.
    Capability::set_register(&platform, &parent, h, 0, 0, 123).unwrap();
    let v = Capability::get_register(&platform, &parent, h, 0, 0).unwrap().0;
    assert_eq!(v, 123);

    // Silence unused-variable warning
    let _ = child;
}

// ─────────────────────────────────────────────────────────────────────────────
// Bad VP id
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_set_register_bad_vp_id() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // VP 999 does not exist (domain has only num_cores VPs).
    let err = Capability::set_register(&platform, &parent, h, 999, 0, 0).unwrap_err();
    assert_eq!(err, CapaError::NotFound);
}

#[test]
fn test_get_register_bad_vp_id() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    let err = Capability::get_register(&platform, &parent, h, 999, 0).unwrap_err();
    assert_eq!(err, CapaError::NotFound);
}

// ─────────────────────────────────────────────────────────────────────────────
// VectorVisibility: inherits default on new entry; can be updated independently
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_vector_visibility_inherits_default() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Set the default to Report (1)
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::DefaultInterruptVisibility, 1).unwrap();

    // Setting visibility for a brand-new vector should create an entry that starts
    // with the inherited default (Report) and then overrides to NotReport (2).
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorVisibility(10), 2).unwrap();
    let v = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::VectorVisibility(10)).unwrap().0;
    assert_eq!(v, 2);

    // Other vectors still return the default (Report = 1).
    let def = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::VectorVisibility(11)).unwrap().0;
    assert_eq!(def, 1);
}

#[test]
fn test_vector_visibility_independent_of_read_write_set() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Set visibility and bitmaps independently for the same vector.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorVisibility(5), 1).unwrap();
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegReadSet(5, 0), 0b111).unwrap();
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegWriteSet(5, 0), 0b011).unwrap();

    assert_eq!(
        Capability::get_policy(&platform, &parent, h, PolicyIdentifier::VectorVisibility(5)).unwrap().0,
        1
    );
    assert_eq!(
        Capability::get_policy(&platform, &parent, h, PolicyIdentifier::VectorRegReadSet(5, 0)).unwrap().0,
        0b111
    );
    assert_eq!(
        Capability::get_policy(&platform, &parent, h, PolicyIdentifier::VectorRegWriteSet(5, 0)).unwrap().0,
        0b011
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// VectorInjectable: orthogonal to visibility, not monotone, defaults from
// the effective per-vector policy (default_report()'s injectable=true).
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_set_get_vector_injectable() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Default policy (default_report()) is injectable=true.
    let v = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::VectorInjectable(20)).unwrap().0;
    assert_eq!(v, 1);

    // Explicitly disable injection for this vector.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorInjectable(20), 0).unwrap();
    let v = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::VectorInjectable(20)).unwrap().0;
    assert_eq!(v, 0);

    // Other vectors are unaffected.
    let other = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::VectorInjectable(21)).unwrap().0;
    assert_eq!(other, 1);
}

#[test]
fn test_vector_injectable_independent_of_visibility() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Set visibility to NotReport (2) while keeping the vector injectable —
    // this is exactly the "parent wants sole, explicit control over this
    // vector" pattern: automatic real-hardware routing is suppressed, but
    // THEMIS_INJECT_INTERRUPT for it remains permitted.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorVisibility(9), 2).unwrap();
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorInjectable(9), 1).unwrap();

    assert_eq!(
        Capability::get_policy(&platform, &parent, h, PolicyIdentifier::VectorVisibility(9)).unwrap().0,
        2
    );
    assert_eq!(
        Capability::get_policy(&platform, &parent, h, PolicyIdentifier::VectorInjectable(9)).unwrap().0,
        1
    );

    // Conversely: Deliver visibility with injection explicitly disabled.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorVisibility(11), 0).unwrap();
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorInjectable(11), 0).unwrap();
    assert_eq!(
        Capability::get_policy(&platform, &parent, h, PolicyIdentifier::VectorVisibility(11)).unwrap().0,
        0
    );
    assert_eq!(
        Capability::get_policy(&platform, &parent, h, PolicyIdentifier::VectorInjectable(11)).unwrap().0,
        0
    );
}

#[test]
fn test_vector_injectable_not_monotone() {
    let platform = common::TestPlatform::new();
    let parent = root();
    // Parent's own default policy has injectable=true (default_report()),
    // but VectorInjectable must not be subject to any monotonicity check —
    // a child may be set to false (more "restrictive" in one reading) or
    // stay true; either way this must succeed without MonotonicityViolation.
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorInjectable(3), 0).unwrap();
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorInjectable(3), 1).unwrap();
    let v = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::VectorInjectable(3)).unwrap().0;
    assert_eq!(v, 1);
}

#[test]
fn test_effective_vector_switches_on_interrupt() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (_child, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Allow reg 0 write under VECTOR_AVAILABLE but NOT under vector 1.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegWriteSet(VECTOR_AVAILABLE, 0), 1).unwrap();
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::VectorRegWriteSet(1, 0), 0).unwrap();

    seal(&parent, h);

    // While Available (not yet switched into): write should succeed.
    Capability::set_register(&platform, &parent, h, 0, 0, 1).unwrap();

    // Switch into the child (Available -> Running), then deliver an
    // interrupt on vector 1. Child keeps the default Report policy so the
    // interrupted leaf (child's own VP[0]) is what ends up Interrupted,
    // with parent (Deliver by default) resuming to Running as the handler.
    init_vp_running(&parent, 0, 0);
    platform.set_current_core(Some(0));
    Capability::switch(&platform, &parent, h, 0).unwrap();
    Capability::deliver_interrupt_vp(&platform, &_child, 0, 1).unwrap();

    // After interrupt by vector 1: write must be denied.
    let err = Capability::set_register(&platform, &parent, h, 0, 0, 2).unwrap_err();
    assert_eq!(err, CapaError::RegisterAccessDenied);

    // Switch into the child again: this resumes the Interrupted VP back to
    // Running (real forward-switch resume path, not a raw run_state write).
    Capability::switch(&platform, &parent, h, 0).unwrap();

    // Back to Running: write must still be denied (VP is executing).
    let err = Capability::set_register(&platform, &parent, h, 0, 0, 3).unwrap_err();
    assert_eq!(err, CapaError::RegisterAccessDenied);
}

// ─────────────────────────────────────────────────────────────────────────────
// set_policy(Cores) adjusts num_vprocessors
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_set_cores_narrows_vp_count() {
    let platform = common::TestPlatform::new();
    let parent = root();
    // Child starts with 4 cores (0b1111) and thus 4 VPs.
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));
    let get_vps = || {
        let child_weak = parent.read().data.domain_capabilities[&h].clone();
        child_weak.upgrade().unwrap().read().data.policy.num_vprocessors
    };
    assert_eq!(get_vps(), 4);

    // Narrow to 2 cores — VP count must drop to 2.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::Cores, 0b0011).unwrap();
    assert_eq!(get_vps(), 2);
}

#[test]
fn test_set_cores_no_change_when_same_popcount() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));
    // 0b0101 has popcount 2 — VP count must be clamped to 2 even though old count was 4.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::Cores, 0b0101).unwrap();
    let vps = parent.read().data.domain_capabilities[&h]
        .upgrade().unwrap().read().data.policy.num_vprocessors;
    assert_eq!(vps, 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// Interrupt visibility monotonicity
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_default_visibility_monotonicity_enforced() {
    let platform = common::TestPlatform::new();
    // Root has Deliver (0). Create a child, restrict its default to NotReport (2),
    // seal it, then verify that its grandchild cannot be given Deliver (0).
    let parent = root();
    let (child, child_h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Restrict child default to NotReport — allowed (2 >= 0 relative to parent Deliver).
    Capability::set_policy(&platform, &parent, child_h, PolicyIdentifier::DefaultInterruptVisibility, 2).unwrap();
    seal(&parent, child_h);

    // Create grandchild under the now-sealed child.
    let grand_h = Capability::create(&platform, &child, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL)).unwrap().0;

    // NotReport (2) is allowed for grandchild.
    Capability::set_policy(&platform, &child, grand_h, PolicyIdentifier::DefaultInterruptVisibility, 2).unwrap();

    // Deliver (0) must be denied: parent (child) has NotReport (2), 0 < 2.
    let err = Capability::set_policy(&platform, &child, grand_h, PolicyIdentifier::DefaultInterruptVisibility, 0).unwrap_err();
    assert_eq!(err, CapaError::MonotonicityViolation);

    // Report (1) must also be denied: 1 < 2.
    let err = Capability::set_policy(&platform, &child, grand_h, PolicyIdentifier::DefaultInterruptVisibility, 1).unwrap_err();
    assert_eq!(err, CapaError::MonotonicityViolation);
}

#[test]
fn test_vector_visibility_monotonicity_enforced() {
    let platform = common::TestPlatform::new();
    // Root has Deliver (0) default. Create child, set its vector 5 to Report (1), seal it.
    // Grandchild must not be allowed Deliver (0) for vector 5.
    let parent = root();
    let (child, parent_h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));
    Capability::set_policy(&platform, &parent, parent_h, PolicyIdentifier::VectorVisibility(5), 1).unwrap(); // Report
    seal(&parent, parent_h);

    // Create grandchild under the sealed child.
    let grand_h = Capability::create(&platform, &child, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL)).unwrap().0;

    // Try to set grandchild's vector 5 to Deliver (0) — must be denied (0 < 1).
    let err = Capability::set_policy(&platform, &child, grand_h, PolicyIdentifier::VectorVisibility(5), 0).unwrap_err();
    assert_eq!(err, CapaError::MonotonicityViolation);

    // Report (1) should succeed.
    Capability::set_policy(&platform, &child, grand_h, PolicyIdentifier::VectorVisibility(5), 1).unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// seal — SEAL permission check
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_seal_domain_denied_without_seal_permission() {
    let platform = common::TestPlatform::new();
    let parent = root();
    // Create a child without SEAL in its API, but with CREATE so it can make grandchildren.
    let no_seal_api = MonitorAPI::from_bits(MonitorAPI::CREATE | MonitorAPI::SET | MonitorAPI::GET);
    let (child, child_h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, no_seal_api));
    seal(&parent, child_h);

    // child is now sealed with CREATE but NOT SEAL.
    // The grandchild must have only the permissions child has (monotonicity).
    let grand_h = Capability::create(&platform, &child, DomainPolicy::new_restricted(0b1111, no_seal_api)).unwrap().0;

    // Attempting to seal grand_h through child must be denied.
    let err = Capability::seal(&platform, &child, grand_h).unwrap_err();
    assert_eq!(err, CapaError::ApiNotAllowed);
}

#[test]
fn test_seal_domain_allowed_with_seal_permission() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));
    // parent has SEAL (root has ALL), so sealing should succeed.
    Capability::seal(&platform, &parent, h).unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// ExitPolicy — set_policy / get_policy
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_set_get_default_exit_trap() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Default for restricted child is trap=true (1).
    let v = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::DefaultExitTrap).unwrap().0;
    assert_eq!(v, 1);

    // Root has trap=false, so child can set trap=false (less restrictive parent).
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::DefaultExitTrap, 0).unwrap();
    let v = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::DefaultExitTrap).unwrap().0;
    assert_eq!(v, 0);

    // Set back to trap=true.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::DefaultExitTrap, 1).unwrap();
    let v = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::DefaultExitTrap).unwrap().0;
    assert_eq!(v, 1);
}

#[test]
fn test_set_get_exit_reason_trap() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Default is trap=true; override exit reason 10 (CPUID) to local.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::ExitReasonTrap(10), 0).unwrap();
    let v = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::ExitReasonTrap(10)).unwrap().0;
    assert_eq!(v, 0);

    // Unoverridden exit reason still returns default.
    let v = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::ExitReasonTrap(48)).unwrap().0;
    assert_eq!(v, 1);
}

#[test]
fn test_set_get_exit_reason_reg_bitmaps() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Set read bitmap for exit reason 48 (EPT violation), word 0.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::ExitReasonRegReadSet(48, 0), 0b1010).unwrap();
    let v = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::ExitReasonRegReadSet(48, 0)).unwrap().0;
    assert_eq!(v, 0b1010);

    // Write bitmap.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::ExitReasonRegWriteSet(48, 0), 0b0101).unwrap();
    let v = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::ExitReasonRegWriteSet(48, 0)).unwrap().0;
    assert_eq!(v, 0b0101);
}

#[test]
fn test_exit_monotonicity_child_cannot_untrap() {
    let platform = common::TestPlatform::new();
    let parent = root();
    // Create intermediate with trap=true default (restricted).
    let (mid, mid_h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));
    Capability::seal(&platform, &parent, mid_h).unwrap();

    // Create grandchild under mid.
    let (_, gc_h) = make_child(&platform, &mid, DomainPolicy::new_restricted(0b0011, MonitorAPI::ALL));

    // mid has trap=true default. Grandchild cannot set trap=false.
    let err = Capability::set_policy(&platform, &mid, gc_h, PolicyIdentifier::DefaultExitTrap, 0).unwrap_err();
    assert_eq!(err, CapaError::MonotonicityViolation);

    // Per-exit-reason: mid traps everything (default=true), so gc can't un-trap reason 10.
    let err = Capability::set_policy(&platform, &mid, gc_h, PolicyIdentifier::ExitReasonTrap(10), 0).unwrap_err();
    assert_eq!(err, CapaError::MonotonicityViolation);
}

#[test]
fn test_exit_monotonicity_parent_local_child_can_choose() {
    let platform = common::TestPlatform::new();
    let parent = root();
    // Root has trap=false (local). Child can set either trap=true or trap=false.
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Set to local (same as parent) — allowed.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::DefaultExitTrap, 0).unwrap();

    // Set back to trap — always allowed (more restrictive).
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::DefaultExitTrap, 1).unwrap();
}

#[test]
fn test_exit_policy_blocked_after_seal() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));
    Capability::seal(&platform, &parent, h).unwrap();

    // set_policy should fail on sealed domain.
    let err = Capability::set_policy(&platform, &parent, h, PolicyIdentifier::DefaultExitTrap, 0).unwrap_err();
    assert_eq!(err, CapaError::DomainSealed);
}

#[test]
fn test_exit_get_policy_works_after_seal() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Set some policy before seal.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::ExitReasonTrap(10), 0).unwrap();
    Capability::seal(&platform, &parent, h).unwrap();

    // get_policy should still work on sealed domain.
    let v = Capability::get_policy(&platform, &parent, h, PolicyIdentifier::ExitReasonTrap(10)).unwrap().0;
    assert_eq!(v, 0);
}

#[test]
fn test_exit_per_reason_override_independent() {
    let platform = common::TestPlatform::new();
    let parent = root();
    let (_, h) = make_child(&platform, &parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Override two different exit reasons.
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::ExitReasonTrap(10), 0).unwrap();
    Capability::set_policy(&platform, &parent, h, PolicyIdentifier::ExitReasonTrap(48), 0).unwrap();

    // Both read back correctly.
    assert_eq!(
        Capability::get_policy(&platform, &parent, h, PolicyIdentifier::ExitReasonTrap(10)).unwrap().0, 0
    );
    assert_eq!(
        Capability::get_policy(&platform, &parent, h, PolicyIdentifier::ExitReasonTrap(48)).unwrap().0, 0
    );

    // Non-overridden reason still default.
    assert_eq!(
        Capability::get_policy(&platform, &parent, h, PolicyIdentifier::ExitReasonTrap(12)).unwrap().0, 1
    );
}
