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
    Capability::new_root(0, 0, Domain::new_root(4))
}

/// Create an unsealed child under `parent` with the given policy, and return
/// `(child_ref, handle)`.
fn make_child(
    parent: &CapabilityRef<Domain>,
    policy: DomainPolicy,
) -> (CapabilityRef<Domain>, LocalHandle) {
    let num_vps = policy.num_vprocessors;
    let h = Capability::create(parent, policy).unwrap().0;
    let child = parent
        .read()
        .data
        .domain_capabilities[&h]
        .upgrade()
        .unwrap();
    // Explicitly add VPs (no longer auto-created in Domain::new)
    for _ in 0..num_vps as u64 {
        child.write().data.add_vprocessor().unwrap();
    }
    (child, h)
}

/// Seal a child via its parent handle.
fn seal(parent: &CapabilityRef<Domain>, h: LocalHandle) {
    Capability::seal(parent, h).unwrap();
}

/// Force VP[vp_id] of `domain` into `Interrupted { vector }`.
fn set_vp_interrupted(domain: &CapabilityRef<Domain>, vp_id: usize, vector: u8) {
    let d = domain.read();
    let vp = d.data.policy.vprocessor_states[vp_id].clone();
    drop(d);
    *vp.run_state.write() = VpRunState::Interrupted { vector };
}

/// Force VP[vp_id] of `domain` into `Running { core: 0 }`.
fn set_vp_running(domain: &CapabilityRef<Domain>, vp_id: usize) {
    let d = domain.read();
    let vp = d.data.policy.vprocessor_states[vp_id].clone();
    drop(d);
    *vp.run_state.write() = VpRunState::Running { core: 0, caller: None };
}

// ─────────────────────────────────────────────────────────────────────────────
// set_policy / get_policy — happy paths
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_set_get_cores() {
    let parent = root();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    Capability::set_policy(&parent, h, PolicyIdentifier::Cores, 0b0011).unwrap();
    let v = Capability::get_policy(&parent, h, PolicyIdentifier::Cores).unwrap();
    assert_eq!(v, 0b0011);
}

#[test]
fn test_set_get_api_monitor() {
    let parent = root();
    let child_api = MonitorAPI::from_bits(MonitorAPI::GET | MonitorAPI::SWITCH);
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    let bits = child_api.bits() as u64;
    Capability::set_policy(&parent, h, PolicyIdentifier::ApiMonitor, bits).unwrap();
    let v = Capability::get_policy(&parent, h, PolicyIdentifier::ApiMonitor).unwrap();
    assert_eq!(v, bits);
}

#[test]
fn test_set_get_default_interrupt_visibility() {
    let parent = root();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // 1 = Report
    Capability::set_policy(&parent, h, PolicyIdentifier::DefaultInterruptVisibility, 1).unwrap();
    let v = Capability::get_policy(&parent, h, PolicyIdentifier::DefaultInterruptVisibility).unwrap();
    assert_eq!(v, 1);
}

#[test]
fn test_set_get_vector_visibility() {
    let parent = root();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // vector 32, visibility 2 = NotReport
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorVisibility(32), 2).unwrap();
    let v = Capability::get_policy(&parent, h, PolicyIdentifier::VectorVisibility(32)).unwrap();
    assert_eq!(v, 2);
}

#[test]
fn test_set_get_vector_reg_read_set() {
    let parent = root();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    let bitmap: u64 = 0b1010_1010;
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegReadSet(5), bitmap).unwrap();
    let v = Capability::get_policy(&parent, h, PolicyIdentifier::VectorRegReadSet(5)).unwrap();
    assert_eq!(v, bitmap);
}

#[test]
fn test_set_get_vector_reg_write_set() {
    let parent = root();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    let bitmap: u64 = 0xDEAD_BEEF;
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegWriteSet(7), bitmap).unwrap();
    let v = Capability::get_policy(&parent, h, PolicyIdentifier::VectorRegWriteSet(7)).unwrap();
    assert_eq!(v, bitmap);
}

// ─────────────────────────────────────────────────────────────────────────────
// get_policy works on sealed domain; set_policy is blocked
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_get_policy_works_on_sealed_domain() {
    let parent = root();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // set cores before sealing
    Capability::set_policy(&parent, h, PolicyIdentifier::Cores, 0b0101).unwrap();
    seal(&parent, h);

    let v = Capability::get_policy(&parent, h, PolicyIdentifier::Cores).unwrap();
    assert_eq!(v, 0b0101);
}

#[test]
fn test_set_policy_blocked_on_sealed_domain() {
    let parent = root();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));
    seal(&parent, h);

    let err = Capability::set_policy(&parent, h, PolicyIdentifier::Cores, 0b0011).unwrap_err();
    assert_eq!(err, CapaError::DomainSealed);
}

// ─────────────────────────────────────────────────────────────────────────────
// Monotonicity — Cores
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_cores_monotonicity_ok_subset() {
    let parent = root(); // parent has all 4 cores (0b1111)
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // 0b0110 ⊆ 0b1111 → ok
    Capability::set_policy(&parent, h, PolicyIdentifier::Cores, 0b0110).unwrap();
}

#[test]
fn test_cores_monotonicity_violated() {
    let parent = root(); // parent has 0b1111
    // create a child with only 0b0011, seal it, then create a grandchild
    let (_, child_h) =
        make_child(&parent, DomainPolicy::new_restricted(0b0011, MonitorAPI::ALL));
    seal(&parent, child_h);
    let child = parent.read().data.domain_capabilities[&child_h].upgrade().unwrap();

    let (_, grandchild_h) =
        make_child(&child, DomainPolicy::new_restricted(0b0011, MonitorAPI::ALL));

    // Try to give grandchild a core that child doesn't have (bit 2 = 0b0100)
    let err = Capability::set_policy(&child, grandchild_h, PolicyIdentifier::Cores, 0b0100)
        .unwrap_err();
    assert_eq!(err, CapaError::MonotonicityViolation);
}

#[test]
fn test_cores_monotonicity_same_value_ok() {
    let parent = root();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b0011, MonitorAPI::ALL));

    // Same value is still a subset — must succeed
    Capability::set_policy(&parent, h, PolicyIdentifier::Cores, 0b0011).unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// Monotonicity — ApiMonitor
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_api_monotonicity_violated() {
    let parent = root();
    // Constrained parent: only GET | SWITCH
    let parent_api = MonitorAPI::from_bits(MonitorAPI::GET | MonitorAPI::SWITCH);
    let (_, c_h) =
        make_child(&parent, DomainPolicy::new_restricted(0b1111, parent_api));
    seal(&parent, c_h);
    let constrained = parent.read().data.domain_capabilities[&c_h].upgrade().unwrap();

    // Now create a grandchild under the constrained domain and try to grant SET
    // (which the constrained parent doesn't have).
    let (_, gc_h) =
        make_child(&constrained, DomainPolicy::new_restricted(0b1111, parent_api));

    let full_api = MonitorAPI::ALL.bits() as u64;
    let err =
        Capability::set_policy(&constrained, gc_h, PolicyIdentifier::ApiMonitor, full_api)
            .unwrap_err();
    assert_eq!(err, CapaError::MonotonicityViolation);
}

// ─────────────────────────────────────────────────────────────────────────────
// Register bitmaps are NOT monotone
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_register_bitmaps_not_monotone() {
    // A restricted parent should still be able to set any bitmap value on its child.
    let parent = root();
    let (_, child_h) =
        make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));
    // Parent sets a small read bitmap on child
    Capability::set_policy(&parent, child_h, PolicyIdentifier::VectorRegReadSet(10), 0b0001)
        .unwrap();
    seal(&parent, child_h);
    let child = parent.read().data.domain_capabilities[&child_h].upgrade().unwrap();

    // Now set a LARGER bitmap on a grandchild through the child — must succeed (no monotonicity).
    let (_, gc_h) =
        make_child(&child, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));
    Capability::set_policy(&child, gc_h, PolicyIdentifier::VectorRegReadSet(10), 0xFFFF_FFFF)
        .unwrap();
    let v =
        Capability::get_policy(&child, gc_h, PolicyIdentifier::VectorRegReadSet(10)).unwrap();
    assert_eq!(v, 0xFFFF_FFFF);
}

// ─────────────────────────────────────────────────────────────────────────────
// Invalid visibility value
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_invalid_visibility_value_rejected() {
    let parent = root();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    let err =
        Capability::set_policy(&parent, h, PolicyIdentifier::DefaultInterruptVisibility, 99)
            .unwrap_err();
    assert!(matches!(err, CapaError::InvalidOperation(_)));
}

// ─────────────────────────────────────────────────────────────────────────────
// Bad child handle
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_set_policy_bad_handle() {
    let parent = root();
    let bogus: LocalHandle = 9999;
    let err =
        Capability::set_policy(&parent, bogus, PolicyIdentifier::Cores, 0b0001).unwrap_err();
    assert_eq!(err, CapaError::NotFound);
}

#[test]
fn test_get_policy_bad_handle() {
    let parent = root();
    let bogus: LocalHandle = 9999;
    let err =
        Capability::get_policy(&parent, bogus, PolicyIdentifier::Cores).unwrap_err();
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
    // controller: sealed under root
    let (_, ctrl_h) = make_child(root, DomainPolicy::new_restricted(0b1111, controller_api));
    seal(root, ctrl_h);
    let ctrl = root.read().data.domain_capabilities[&ctrl_h].upgrade().unwrap();

    // caller: sealed under controller
    let (_, caller_h) = make_child(&ctrl, DomainPolicy::new_restricted(0b1111, controller_api));
    seal(&ctrl, caller_h);
    let caller = ctrl.read().data.domain_capabilities[&caller_h].upgrade().unwrap();

    // target: unsealed child of caller
    let (_, target_h) = make_child(&caller, DomainPolicy::new_restricted(0b1111, controller_api));

    (caller, target_h, ctrl)
}

#[test]
fn test_set_policy_requires_set_permission() {
    let parent = root();
    // controller has CREATE + SEAL + GET but NOT SET
    let no_set = MonitorAPI::from_bits(
        MonitorAPI::CREATE | MonitorAPI::SEAL | MonitorAPI::GET,
    );
    let (caller, target_h, _ctrl) = make_restricted_caller(&parent, no_set);

    let err =
        Capability::set_policy(&caller, target_h, PolicyIdentifier::Cores, 0b0001).unwrap_err();
    assert_eq!(err, CapaError::ApiNotAllowed);
}

#[test]
fn test_get_policy_requires_get_permission() {
    let parent = root();
    // controller has CREATE + SEAL + SET but NOT GET
    let no_get = MonitorAPI::from_bits(
        MonitorAPI::CREATE | MonitorAPI::SEAL | MonitorAPI::SET,
    );
    let (caller, target_h, _ctrl) = make_restricted_caller(&parent, no_get);

    let err = Capability::get_policy(&caller, target_h, PolicyIdentifier::Cores).unwrap_err();
    assert_eq!(err, CapaError::ApiNotAllowed);
}

// ─────────────────────────────────────────────────────────────────────────────
// set_register / get_register — VECTOR_AVAILABLE path (VP not interrupted)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_set_get_register_available_vp() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Allow reg 0 for read and write under VECTOR_AVAILABLE (0xFF).
    let bitmap: u64 = 1; // bit 0 set
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegReadSet(VECTOR_AVAILABLE), bitmap)
        .unwrap();
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegWriteSet(VECTOR_AVAILABLE), bitmap)
        .unwrap();

    // VP[0] is Available by default → effective vector = VECTOR_AVAILABLE.
    Capability::set_register(&parent, h, 0, 0, 0xCAFE, &platform).unwrap();
    let v = Capability::get_register(&parent, h, 0, 0, &platform).unwrap();
    assert_eq!(v, 0xCAFE);
}

#[test]
fn test_set_register_denied_when_bit_not_in_write_bitmap() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // write bitmap for VECTOR_AVAILABLE has bit 0 but NOT bit 1
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegWriteSet(VECTOR_AVAILABLE), 0b01)
        .unwrap();

    let err = Capability::set_register(&parent, h, 0, 1, 42, &platform).unwrap_err();
    assert_eq!(err, CapaError::RegisterAccessDenied);
}

#[test]
fn test_get_register_denied_when_bit_not_in_read_bitmap() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // read bitmap for VECTOR_AVAILABLE has bit 0 but NOT bit 2
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegReadSet(VECTOR_AVAILABLE), 0b01)
        .unwrap();

    let err = Capability::get_register(&parent, h, 0, 2, &platform).unwrap_err();
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
        make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Grant access to reg 3 under vector 42 only.
    let bitmap: u64 = 1 << 3;
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegWriteSet(42), bitmap).unwrap();
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegReadSet(42), bitmap).unwrap();

    // Put VP[0] in Interrupted { vector: 42 }
    set_vp_interrupted(&child, 0, 42);

    Capability::set_register(&parent, h, 0, 3, 0xBEEF, &platform).unwrap();
    let v = Capability::get_register(&parent, h, 0, 3, &platform).unwrap();
    assert_eq!(v, 0xBEEF);
}

#[test]
fn test_register_access_blocked_for_different_vector() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (child, h) =
        make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Restrict the default VECTOR_AVAILABLE write bitmap (default_report sets u64::MAX).
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegWriteSet(VECTOR_AVAILABLE), 0).unwrap();

    // Only allow reg 3 under vector 42.
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegWriteSet(42), 1 << 3).unwrap();
    // Explicitly deny vector 99.
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegWriteSet(99), 0).unwrap();

    // VP is interrupted by vector 99 → override write_set = 0.
    set_vp_interrupted(&child, 0, 99);

    let err = Capability::set_register(&parent, h, 0, 3, 0xBEEF, &platform).unwrap_err();
    assert_eq!(err, CapaError::RegisterAccessDenied);
}

#[test]
fn test_vector_override_does_not_affect_available_vp() {
    // A bitmap set for vector 42 must NOT grant access when the VP is Available.
    let parent = root();
    let platform = common::TestPlatform::new();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Clear the default VECTOR_AVAILABLE write bitmap so only per-vector overrides grant access.
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegWriteSet(VECTOR_AVAILABLE), 0).unwrap();

    // Grant write access to reg 5 only under vector 42.
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegWriteSet(42), 1 << 5).unwrap();

    // VP[0] is Available by default.
    let err = Capability::set_register(&parent, h, 0, 5, 99, &platform).unwrap_err();
    assert_eq!(err, CapaError::RegisterAccessDenied);
}

// ─────────────────────────────────────────────────────────────────────────────
// set_register / get_register — Running VP must be denied
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_set_register_denied_when_vp_running() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (child, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Grant full write access under VECTOR_AVAILABLE so bitmaps are not the obstacle.
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegWriteSet(VECTOR_AVAILABLE), u64::MAX)
        .unwrap();

    // Confirm write works while Available.
    Capability::set_register(&parent, h, 0, 0, 0x1, &platform).unwrap();

    // Transition to Running — register access must now be denied.
    set_vp_running(&child, 0);
    let err = Capability::set_register(&parent, h, 0, 0, 0x2, &platform).unwrap_err();
    assert_eq!(err, CapaError::RegisterAccessDenied);
}

#[test]
fn test_get_register_denied_when_vp_running() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (child, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Grant full read access under VECTOR_AVAILABLE.
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegReadSet(VECTOR_AVAILABLE), u64::MAX)
        .unwrap();

    // Confirm read works while Available.
    Capability::get_register(&parent, h, 0, 0, &platform).unwrap();

    // Transition to Running — register access must now be denied.
    set_vp_running(&child, 0);
    let err = Capability::get_register(&parent, h, 0, 0, &platform).unwrap_err();
    assert_eq!(err, CapaError::RegisterAccessDenied);
}

// ─────────────────────────────────────────────────────────────────────────────
// Register out of range
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_set_register_out_of_range() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // TestPlatform has register_count() = 64; reg 64 is out of range.
    let err = Capability::set_register(&parent, h, 0, 64, 0, &platform).unwrap_err();
    assert_eq!(err, CapaError::RegisterOutOfRange);
}

#[test]
fn test_get_register_out_of_range() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    let err = Capability::get_register(&parent, h, 0, 64, &platform).unwrap_err();
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

    let err = Capability::set_register(&caller, target_h, 0, 0, 0, &platform).unwrap_err();
    assert_eq!(err, CapaError::ApiNotAllowed);
}

#[test]
fn test_get_register_requires_get_permission() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let no_get = MonitorAPI::from_bits(MonitorAPI::CREATE | MonitorAPI::SEAL | MonitorAPI::SET);
    let (caller, target_h, _ctrl) = make_restricted_caller(&parent, no_get);

    let err = Capability::get_register(&caller, target_h, 0, 0, &platform).unwrap_err();
    assert_eq!(err, CapaError::ApiNotAllowed);
}

// ─────────────────────────────────────────────────────────────────────────────
// set_register / get_register work on sealed domains
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_set_register_works_on_sealed_domain() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (child, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Grant write access to reg 0 under VECTOR_AVAILABLE before sealing.
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegWriteSet(VECTOR_AVAILABLE), 1)
        .unwrap();
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegReadSet(VECTOR_AVAILABLE), 1)
        .unwrap();

    seal(&parent, h);

    // VP is still Available after sealing, so effective vector = VECTOR_AVAILABLE.
    Capability::set_register(&parent, h, 0, 0, 123, &platform).unwrap();
    let v = Capability::get_register(&parent, h, 0, 0, &platform).unwrap();
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
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // VP 999 does not exist (domain has only num_cores VPs).
    let err = Capability::set_register(&parent, h, 999, 0, 0, &platform).unwrap_err();
    assert_eq!(err, CapaError::NotFound);
}

#[test]
fn test_get_register_bad_vp_id() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    let err = Capability::get_register(&parent, h, 999, 0, &platform).unwrap_err();
    assert_eq!(err, CapaError::NotFound);
}

// ─────────────────────────────────────────────────────────────────────────────
// VectorVisibility: inherits default on new entry; can be updated independently
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_vector_visibility_inherits_default() {
    let parent = root();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Set the default to Report (1)
    Capability::set_policy(&parent, h, PolicyIdentifier::DefaultInterruptVisibility, 1).unwrap();

    // Setting visibility for a brand-new vector should create an entry that starts
    // with the inherited default (Report) and then overrides to NotReport (2).
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorVisibility(10), 2).unwrap();
    let v = Capability::get_policy(&parent, h, PolicyIdentifier::VectorVisibility(10)).unwrap();
    assert_eq!(v, 2);

    // Other vectors still return the default (Report = 1).
    let def = Capability::get_policy(&parent, h, PolicyIdentifier::VectorVisibility(11)).unwrap();
    assert_eq!(def, 1);
}

#[test]
fn test_vector_visibility_independent_of_read_write_set() {
    let parent = root();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Set visibility and bitmaps independently for the same vector.
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorVisibility(5), 1).unwrap();
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegReadSet(5), 0b111).unwrap();
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegWriteSet(5), 0b011).unwrap();

    assert_eq!(
        Capability::get_policy(&parent, h, PolicyIdentifier::VectorVisibility(5)).unwrap(),
        1
    );
    assert_eq!(
        Capability::get_policy(&parent, h, PolicyIdentifier::VectorRegReadSet(5)).unwrap(),
        0b111
    );
    assert_eq!(
        Capability::get_policy(&parent, h, PolicyIdentifier::VectorRegWriteSet(5)).unwrap(),
        0b011
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Transition from Available → Interrupted changes effective policy
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_effective_vector_switches_on_interrupt() {
    let parent = root();
    let platform = common::TestPlatform::new();
    let (child, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Allow reg 0 write under VECTOR_AVAILABLE but NOT under vector 1.
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegWriteSet(VECTOR_AVAILABLE), 1).unwrap();
    Capability::set_policy(&parent, h, PolicyIdentifier::VectorRegWriteSet(1), 0).unwrap();

    // While Available: write should succeed.
    Capability::set_register(&parent, h, 0, 0, 1, &platform).unwrap();

    // After interrupt by vector 1: write must be denied.
    set_vp_interrupted(&child, 0, 1);
    let err = Capability::set_register(&parent, h, 0, 0, 2, &platform).unwrap_err();
    assert_eq!(err, CapaError::RegisterAccessDenied);

    // Back to Running: write must still be denied (VP is executing).
    set_vp_running(&child, 0);
    let err = Capability::set_register(&parent, h, 0, 0, 3, &platform).unwrap_err();
    assert_eq!(err, CapaError::RegisterAccessDenied);
}

// ─────────────────────────────────────────────────────────────────────────────
// set_policy(Cores) adjusts num_vprocessors
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_set_cores_narrows_vp_count() {
    let parent = root();
    // Child starts with 4 cores (0b1111) and thus 4 VPs.
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));
    let get_vps = || {
        let child_weak = parent.read().data.domain_capabilities[&h].clone();
        child_weak.upgrade().unwrap().read().data.policy.num_vprocessors
    };
    assert_eq!(get_vps(), 4);

    // Narrow to 2 cores — VP count must drop to 2.
    Capability::set_policy(&parent, h, PolicyIdentifier::Cores, 0b0011).unwrap();
    assert_eq!(get_vps(), 2);
}

#[test]
fn test_set_cores_no_change_when_same_popcount() {
    let parent = root();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));
    // 0b0101 has popcount 2 — VP count must be clamped to 2 even though old count was 4.
    Capability::set_policy(&parent, h, PolicyIdentifier::Cores, 0b0101).unwrap();
    let vps = parent.read().data.domain_capabilities[&h]
        .upgrade().unwrap().read().data.policy.num_vprocessors;
    assert_eq!(vps, 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// Interrupt visibility monotonicity
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_default_visibility_monotonicity_enforced() {
    // Root has Deliver (0). Create a child, restrict its default to NotReport (2),
    // seal it, then verify that its grandchild cannot be given Deliver (0).
    let parent = root();
    let (child, child_h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));

    // Restrict child default to NotReport — allowed (2 >= 0 relative to parent Deliver).
    Capability::set_policy(&parent, child_h, PolicyIdentifier::DefaultInterruptVisibility, 2).unwrap();
    seal(&parent, child_h);

    // Create grandchild under the now-sealed child.
    let grand_h = Capability::create(
        &child, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL),
    ).unwrap().0;

    // NotReport (2) is allowed for grandchild.
    Capability::set_policy(&child, grand_h, PolicyIdentifier::DefaultInterruptVisibility, 2).unwrap();

    // Deliver (0) must be denied: parent (child) has NotReport (2), 0 < 2.
    let err = Capability::set_policy(
        &child, grand_h, PolicyIdentifier::DefaultInterruptVisibility, 0,
    ).unwrap_err();
    assert_eq!(err, CapaError::MonotonicityViolation);

    // Report (1) must also be denied: 1 < 2.
    let err = Capability::set_policy(
        &child, grand_h, PolicyIdentifier::DefaultInterruptVisibility, 1,
    ).unwrap_err();
    assert_eq!(err, CapaError::MonotonicityViolation);
}

#[test]
fn test_vector_visibility_monotonicity_enforced() {
    // Root has Deliver (0) default. Create child, set its vector 5 to Report (1), seal it.
    // Grandchild must not be allowed Deliver (0) for vector 5.
    let parent = root();
    let (child, parent_h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));
    Capability::set_policy(&parent, parent_h, PolicyIdentifier::VectorVisibility(5), 1).unwrap(); // Report
    seal(&parent, parent_h);

    // Create grandchild under the sealed child.
    let grand_h = Capability::create(
        &child, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL),
    ).unwrap().0;

    // Try to set grandchild's vector 5 to Deliver (0) — must be denied (0 < 1).
    let err = Capability::set_policy(
        &child, grand_h, PolicyIdentifier::VectorVisibility(5), 0,
    ).unwrap_err();
    assert_eq!(err, CapaError::MonotonicityViolation);

    // Report (1) should succeed.
    Capability::set_policy(&child, grand_h, PolicyIdentifier::VectorVisibility(5), 1).unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// seal — SEAL permission check
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_seal_domain_denied_without_seal_permission() {
    let parent = root();
    // Create a child without SEAL in its API, but with CREATE so it can make grandchildren.
    let no_seal_api = MonitorAPI::from_bits(MonitorAPI::CREATE | MonitorAPI::SET | MonitorAPI::GET);
    let (child, child_h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, no_seal_api));
    seal(&parent, child_h);

    // child is now sealed with CREATE but NOT SEAL.
    // The grandchild must have only the permissions child has (monotonicity).
    let grand_h = Capability::create(
        &child, DomainPolicy::new_restricted(0b1111, no_seal_api),
    ).unwrap().0;

    // Attempting to seal grand_h through child must be denied.
    let err = Capability::seal(&child, grand_h).unwrap_err();
    assert_eq!(err, CapaError::ApiNotAllowed);
}

#[test]
fn test_seal_domain_allowed_with_seal_permission() {
    let parent = root();
    let (_, h) = make_child(&parent, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL));
    // parent has SEAL (root has ALL), so sealing should succeed.
    Capability::seal(&parent, h).unwrap();
}
