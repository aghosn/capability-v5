//! Tests for domain operations and policies

use capability_engine::*;

#[path = "../common/mod.rs"]
mod common;


// ==================== Domain Creation and Sealing ====================

#[test]
fn test_domain_creation() {
    let _platform = common::TestPlatform::new();
    let policy = DomainPolicy::new_root(4);
    let domain = Domain::new(policy);
    assert_eq!(domain.status, DomainStatus::Unsealed);
    assert!(!domain.is_sealed());
}

#[test]
fn test_domain_seal() {
    let _platform = common::TestPlatform::new();
    let policy = DomainPolicy::new_root(4);
    let mut domain = Domain::new(policy);
    assert!(domain.seal().is_ok());
    assert!(domain.is_sealed());
}

#[test]
fn test_cannot_seal_twice() {
    let _platform = common::TestPlatform::new();
    let policy = DomainPolicy::new_root(4);
    let mut domain = Domain::new(policy);
    assert!(domain.seal().is_ok());

    // Attempting to seal again should fail
    let result = domain.seal();
    assert_eq!(result, Err(CapaError::DomainSealed));
}

#[test]
fn test_root_domain_is_sealed() {
    let _platform = common::TestPlatform::new();
    let domain = Domain::new_root(4);
    assert_eq!(domain.id, 0);
    assert!(domain.is_sealed());
    assert_eq!(domain.status, DomainStatus::Sealed);
}

// ==================== API Subset Tests ====================

#[test]
fn test_api_subset() {
    let _platform = common::TestPlatform::new();
    let api1 = MonitorAPI::from_bits(MonitorAPI::CREATE | MonitorAPI::SEAL);
    let api2 = MonitorAPI::ALL;
    assert!(api1.is_subset_of(&api2));
    assert!(!api2.is_subset_of(&api1));
}

#[test]
fn test_api_subset_exact_match() {
    let _platform = common::TestPlatform::new();
    let api1 = MonitorAPI::ALL;
    let api2 = MonitorAPI::ALL;
    assert!(api1.is_subset_of(&api2));
}

#[test]
fn test_api_subset_none_is_subset_of_all() {
    let _platform = common::TestPlatform::new();
    assert!(MonitorAPI::NONE.is_subset_of(&MonitorAPI::ALL));
}

// ==================== Policy Subset Tests ====================

#[test]
fn test_policy_subset() {
    let _platform = common::TestPlatform::new();
    let parent = DomainPolicy::new_root(4);
    let child = DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE);
    assert!(child.is_subset_of(&parent).is_ok());
}

#[test]
fn test_policy_subset_cores() {
    let _platform = common::TestPlatform::new();
    let parent = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let child = DomainPolicy::new_restricted(0b0011, MonitorAPI::ALL);
    assert!(child.is_subset_of(&parent).is_ok());
}

#[test]
fn test_policy_not_subset_cores() {
    let _platform = common::TestPlatform::new();
    let parent = DomainPolicy::new_restricted(0b0011, MonitorAPI::ALL);
    let child = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    assert_eq!(
        child.is_subset_of(&parent),
        Err(CapaError::MonotonicityViolation)
    );
}

#[test]
fn test_policy_not_subset_api() {
    let _platform = common::TestPlatform::new();
    let parent = DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE);
    let child = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    assert_eq!(
        child.is_subset_of(&parent),
        Err(CapaError::MonotonicityViolation)
    );
}

// ==================== Domain Revocation ====================

#[test]
fn test_domain_revocation() {
    let _platform = common::TestPlatform::new();
    let policy = DomainPolicy::new_root(4);
    let mut domain = Domain::new(policy);
    domain.seal().unwrap();

    domain.revoke();
    assert!(domain.is_revoked());
    assert_eq!(domain.status, DomainStatus::Revoked);
}

// ==================== Interrupt Policy Tests ====================

#[test]
fn test_interrupt_policy_default() {
    let _platform = common::TestPlatform::new();
    let policy = InterruptPolicy::new_default(VectorPolicy::default_deliver());

    // All vectors should use the default policy
    for i in 0..=255u8 {
        let vec_policy = policy.get_policy(i);
        assert!(matches!(
            vec_policy.visibility,
            InterruptVisibility::Deliver
        ));
    }
}

#[test]
fn test_interrupt_policy_override() {
    let _platform = common::TestPlatform::new();
    let mut policy = InterruptPolicy::new_default(VectorPolicy::default_deliver());

    // Override vector 32
    policy.set_policy(32, VectorPolicy::default_report());

    // Vector 32 should have Report visibility
    let vec32_policy = policy.get_policy(32);
    assert!(matches!(
        vec32_policy.visibility,
        InterruptVisibility::Report
    ));

    // Other vectors should still have Deliver
    let vec10_policy = policy.get_policy(10);
    assert!(matches!(
        vec10_policy.visibility,
        InterruptVisibility::Deliver
    ));
}

// ==================== Virtual Processor State Tests ====================

#[test]
fn test_vprocessor_state_creation() {
    let _platform = common::TestPlatform::new();
    let vproc = VProcessorState::new(1);
    assert_eq!(vproc.id, 1);
    assert!(vproc.platform_data.is_empty());
}

#[test]
fn test_add_vprocessor_state() {
    let _platform = common::TestPlatform::new();
    use std::sync::Arc;
    let mut policy = DomainPolicy::new_root(4);
    assert_eq!(policy.vprocessor_states.len(), 0);

    let vproc = Arc::new(VProcessorState::new(1));
    policy.add_vprocessor_state(vproc);

    assert_eq!(policy.vprocessor_states.len(), 1);
    assert_eq!(policy.vprocessor_states[0].id, 1);
}

// ==================== Domain ID Generation ====================

#[test]
fn test_domain_id_generation() {
    let _platform = common::TestPlatform::new();
    let policy = DomainPolicy::new_root(4);
    let domain1 = Domain::new(policy.clone());
    let domain2 = Domain::new(policy.clone());

    // IDs should be unique and increasing
    assert_ne!(domain1.id, domain2.id);
    assert!(domain2.id > domain1.id);
}

#[test]
fn test_root_domain_has_id_zero() {
    let _platform = common::TestPlatform::new();
    let root = Domain::new_root(4);
    assert_eq!(root.id, 0);
}

// ==================== Policy Combinations ====================

#[test]
fn test_policy_with_limited_cores_and_api() {
    let _platform = common::TestPlatform::new();
    let api = MonitorAPI::from_bits(MonitorAPI::ATTEST | MonitorAPI::ENUMERATE);
    let policy = DomainPolicy::new_restricted(
        0b1010, // Cores 1 and 3
        api,
    );

    assert_eq!(policy.cores, 0b1010);
    assert!(policy.api.attest());
    assert!(policy.api.enumerate());
    assert!(!policy.api.create());
}

#[test]
fn test_complex_policy_hierarchy() {
    let _platform = common::TestPlatform::new();
    let root_policy = DomainPolicy::new_root(4);

    let level1_api =
        MonitorAPI::from_bits(MonitorAPI::CREATE | MonitorAPI::SEAL | MonitorAPI::ATTEST);
    let level1_policy = DomainPolicy::new_restricted(
        0b1111, // Cores 0-3
        level1_api,
    );

    let level2_api = MonitorAPI::from_bits(MonitorAPI::ATTEST);
    let level2_policy = DomainPolicy::new_restricted(
        0b0011, // Cores 0-1 (subset of level1)
        level2_api,
    );

    // level1 should be subset of root
    assert!(level1_policy.is_subset_of(&root_policy).is_ok());

    // level2 should be subset of level1
    assert!(level2_policy.is_subset_of(&level1_policy).is_ok());

    // level2 should be subset of root (transitivity)
    assert!(level2_policy.is_subset_of(&root_policy).is_ok());
}

// ==================== Interrupt Policies in Domain Creation ====================

#[test]
fn test_domain_with_custom_interrupt_policy() {
    let _platform = common::TestPlatform::new();
    let mut int_policy = InterruptPolicy::new_default(VectorPolicy::default_report());

    // Set specific vectors to deliver
    int_policy.set_policy(32, VectorPolicy::default_deliver());
    int_policy.set_policy(33, VectorPolicy::default_deliver());

    let mut domain_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE);
    domain_policy.interrupts = int_policy;

    let domain = Domain::new(domain_policy);

    // Check interrupt policies
    assert!(matches!(
        domain.policy.interrupts.get_policy(32).visibility,
        InterruptVisibility::Deliver
    ));
    assert!(matches!(
        domain.policy.interrupts.get_policy(33).visibility,
        InterruptVisibility::Deliver
    ));
    assert!(matches!(
        domain.policy.interrupts.get_policy(40).visibility,
        InterruptVisibility::Report
    ));
}

// ==================== Edge Cases ====================

#[test]
fn test_policy_subset_all_cores() {
    let _platform = common::TestPlatform::new();
    let parent = DomainPolicy::new_root(4); // All cores
    let child = DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE);

    // Child with 4 cores should be subset of parent with all cores
    assert!(child.is_subset_of(&parent).is_ok());
}

#[test]
fn test_receive_after_seal_flag() {
    let _platform = common::TestPlatform::new();
    let root_policy = DomainPolicy::new_root(4);
    assert!(root_policy.receive_after_seal());

    let restricted_policy = DomainPolicy::new_restricted(0b1, MonitorAPI::NONE);
    assert!(!restricted_policy.receive_after_seal());
}

#[test]
fn test_receive_after_seal_in_api_bitmap() {
    let _platform = common::TestPlatform::new();
    // Verify it's in the API bitmap as bit 12
    let api_with = MonitorAPI::from_bits(MonitorAPI::RECEIVE_AFTER_SEAL);
    assert!(api_with.receive_after_seal());
    assert_eq!(api_with.bits(), 1 << 12);

    let api_without = MonitorAPI::from_bits(0);
    assert!(!api_without.receive_after_seal());
}

#[test]
fn test_receive_after_seal_in_all_permissions() {
    let _platform = common::TestPlatform::new();
    // ALL should include RECEIVE_AFTER_SEAL
    assert!(MonitorAPI::ALL.receive_after_seal());
    assert_eq!(
        MonitorAPI::ALL.bits() & MonitorAPI::RECEIVE_AFTER_SEAL,
        MonitorAPI::RECEIVE_AFTER_SEAL
    );
}

#[test]
fn test_receive_after_seal_subset_check() {
    let _platform = common::TestPlatform::new();
    let parent_api = MonitorAPI::from_bits(MonitorAPI::RECEIVE_AFTER_SEAL | MonitorAPI::GET);
    let child_api_with = MonitorAPI::from_bits(MonitorAPI::RECEIVE_AFTER_SEAL);
    let child_api_without = MonitorAPI::from_bits(MonitorAPI::GET);

    // Child with RECEIVE_AFTER_SEAL should be subset of parent with it
    assert!(child_api_with.is_subset_of(&parent_api));

    // Child with GET should be subset of parent with GET
    assert!(child_api_without.is_subset_of(&parent_api));

    // Child with RECEIVE_AFTER_SEAL cannot be subset of parent without it
    let parent_without = MonitorAPI::from_bits(MonitorAPI::GET);
    assert!(!child_api_with.is_subset_of(&parent_without));
}

#[test]
fn test_receive_after_seal_monotonicity() {
    let _platform = common::TestPlatform::new();
    let parent = DomainPolicy::new_root(4); // Has RECEIVE_AFTER_SEAL
    let child_without = DomainPolicy::new_restricted(0b1, MonitorAPI::NONE);

    // Child without should be subset of parent with
    assert!(child_without.is_subset_of(&parent).is_ok());

    // But trying to create parent without and child with should fail
    let parent_without_api = MonitorAPI::from_bits(MonitorAPI::GET);
    let parent_without = DomainPolicy::new_restricted(0b1111, parent_without_api);

    let child_with_api = MonitorAPI::from_bits(MonitorAPI::RECEIVE_AFTER_SEAL);
    let child_with = DomainPolicy::new_restricted(0b1, child_with_api);

    assert_eq!(
        child_with.is_subset_of(&parent_without),
        Err(CapaError::MonotonicityViolation)
    );
}

#[test]
fn test_receive_after_seal_explicit_grant() {
    let _platform = common::TestPlatform::new();
    // Create a domain with explicit RECEIVE_AFTER_SEAL permission
    let api = MonitorAPI::from_bits(MonitorAPI::GET | MonitorAPI::RECEIVE_AFTER_SEAL);
    let policy = DomainPolicy::new_restricted(0b1, api);

    assert!(policy.receive_after_seal());
    assert!(policy.api.get());
}

#[test]
fn test_receive_after_seal_default_values() {
    let _platform = common::TestPlatform::new();
    // Root should have it by default (ALL includes it)
    let root = Domain::new_root(4);
    assert!(root.policy.receive_after_seal());

    // Restricted domain should not have it unless explicitly granted
    let restricted = DomainPolicy::new_restricted(0b1, MonitorAPI::NONE);
    assert!(!restricted.receive_after_seal());

    // Can be explicitly added
    let with_receive =
        DomainPolicy::new_restricted(0b1, MonitorAPI::from_bits(MonitorAPI::RECEIVE_AFTER_SEAL));
    assert!(with_receive.receive_after_seal());
}

// ==================== Caller API Enforcement ====================
//
// These tests verify that the CALLER domain's own API policy is checked,
// not the caller's parent's policy. Regression tests for a bug where
// validate_operation() traversed owned.owner_domain (= parent) instead
// of checking the caller's own data.policy.

/// Helper: create a sealed root domain capability.
fn root_cap() -> CapabilityRef<Domain> {
    let _platform = common::TestPlatform::new();
    Capability::new_root(0, 0, Domain::new_root(4))
}

/// Helper: create a sealed child under `parent` with the given API, return its Arc.
fn sealed_child_with_api(
    parent: &CapabilityRef<Domain>,
    api: MonitorAPI,
) -> (CapabilityRef<Domain>, LocalHandle) {
    let platform = common::TestPlatform::new();
    let policy = DomainPolicy::new_restricted(0b1111, api);
    let num_vps = policy.num_vprocessors;
    let (h, _) = Capability::create(&platform, parent, policy).unwrap();
    let child = parent
        .read()
        .data
        .domain_capabilities[&h]
        .upgrade()
        .unwrap();
    for _ in 0..num_vps as u64 {
        child.write().data.add_vprocessor().unwrap();
    }
    Capability::seal(&platform, parent, h).unwrap();
    (child, h)
}

#[test]
fn test_create_requires_create_api() {
    let platform = common::TestPlatform::new();
    let root = root_cap();
    // Give child everything EXCEPT CREATE
    let api = MonitorAPI::from_bits(
        MonitorAPI::GET | MonitorAPI::SET | MonitorAPI::SEAL | MonitorAPI::SWITCH | MonitorAPI::REVOKE,
    );
    let (child, _) = sealed_child_with_api(&root, api);

    let grandchild_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::from_bits(MonitorAPI::GET));
    let err = Capability::create(&platform, &child, grandchild_policy).unwrap_err();
    assert_eq!(err, CapaError::ApiNotAllowed);
}

#[test]
fn test_create_succeeds_with_create_api() {
    let platform = common::TestPlatform::new();
    let root = root_cap();
    let api = MonitorAPI::from_bits(MonitorAPI::CREATE | MonitorAPI::SEAL);
    let (child, _) = sealed_child_with_api(&root, api);

    let grandchild_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::from_bits(MonitorAPI::SEAL));
    assert!(Capability::create(&platform, &child, grandchild_policy).is_ok());
}

#[test]
fn test_revoke_requires_revoke_api() {
    let platform = common::TestPlatform::new();
    let root = root_cap();
    // Give child CREATE + SEAL but NOT REVOKE
    let api = MonitorAPI::from_bits(MonitorAPI::CREATE | MonitorAPI::SEAL);
    let (child, _) = sealed_child_with_api(&root, api);

    // Child creates a grandchild
    let gc_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::from_bits(MonitorAPI::SEAL));
    let (gc_h, _) = Capability::create(&platform, &child, gc_policy).unwrap();
    Capability::seal(&platform, &child, gc_h).unwrap();

    let err = Capability::revoke_domain(&platform, &child, gc_h).unwrap_err();
    assert_eq!(err, CapaError::ApiNotAllowed);
}

#[test]
fn test_set_policy_requires_set_api() {
    let platform = common::TestPlatform::new();
    let root = root_cap();
    // Give child CREATE but NOT SET
    let api = MonitorAPI::from_bits(MonitorAPI::CREATE | MonitorAPI::SEAL);
    let (child, _) = sealed_child_with_api(&root, api);

    let gc_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::from_bits(MonitorAPI::SEAL));
    let (gc_h, _) = Capability::create(&platform, &child, gc_policy).unwrap();

    let err = Capability::set_policy(&platform, &child, gc_h, PolicyIdentifier::Cores, 0b0001).unwrap_err();
    assert_eq!(err, CapaError::ApiNotAllowed);
}

#[test]
fn test_get_policy_requires_get_api() {
    let platform = common::TestPlatform::new();
    let root = root_cap();
    // Give child CREATE + SEAL but NOT GET
    let api = MonitorAPI::from_bits(MonitorAPI::CREATE | MonitorAPI::SEAL);
    let (child, _) = sealed_child_with_api(&root, api);

    let gc_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::from_bits(MonitorAPI::SEAL));
    let (gc_h, _) = Capability::create(&platform, &child, gc_policy).unwrap();

    let err = Capability::get_policy(&platform, &child, gc_h, PolicyIdentifier::Cores).unwrap_err();
    assert_eq!(err, CapaError::ApiNotAllowed);
}
