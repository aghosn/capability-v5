//! Tests for domain operations and policies

use capability_engine::*;

// ==================== Domain Creation and Sealing ====================

#[test]
fn test_domain_creation() {
    let policy = DomainPolicy::new_root();
    let domain = Domain::new(policy);
    assert_eq!(domain.status, DomainStatus::Unsealed);
    assert!(!domain.is_sealed());
}

#[test]
fn test_domain_seal() {
    let policy = DomainPolicy::new_root();
    let mut domain = Domain::new(policy);
    assert!(domain.seal().is_ok());
    assert!(domain.is_sealed());
}

#[test]
fn test_cannot_seal_twice() {
    let policy = DomainPolicy::new_root();
    let mut domain = Domain::new(policy);
    assert!(domain.seal().is_ok());

    // Attempting to seal again should fail
    let result = domain.seal();
    assert_eq!(result, Err(CapaError::DomainSealed));
}

#[test]
fn test_root_domain_is_sealed() {
    let domain = Domain::new_root();
    assert_eq!(domain.id, 0);
    assert!(domain.is_sealed());
    assert_eq!(domain.status, DomainStatus::Sealed);
}

// ==================== API Subset Tests ====================

#[test]
fn test_api_subset() {
    let api1 = MonitorAPI::from_bits(MonitorAPI::CREATE | MonitorAPI::SEAL);
    let api2 = MonitorAPI::ALL;
    assert!(api1.is_subset_of(&api2));
    assert!(!api2.is_subset_of(&api1));
}

#[test]
fn test_api_subset_exact_match() {
    let api1 = MonitorAPI::ALL;
    let api2 = MonitorAPI::ALL;
    assert!(api1.is_subset_of(&api2));
}

#[test]
fn test_api_subset_none_is_subset_of_all() {
    assert!(MonitorAPI::NONE.is_subset_of(&MonitorAPI::ALL));
}

// ==================== Policy Subset Tests ====================

#[test]
fn test_policy_subset() {
    let parent = DomainPolicy::new_root();
    let child = DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE);
    assert!(child.is_subset_of(&parent).is_ok());
}

#[test]
fn test_policy_subset_cores() {
    let parent = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let child = DomainPolicy::new_restricted(0b0011, MonitorAPI::ALL);
    assert!(child.is_subset_of(&parent).is_ok());
}

#[test]
fn test_policy_not_subset_cores() {
    let parent = DomainPolicy::new_restricted(0b0011, MonitorAPI::ALL);
    let child = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    assert_eq!(child.is_subset_of(&parent), Err(CapaError::MonotonicityViolation));
}

#[test]
fn test_policy_not_subset_api() {
    let parent = DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE);
    let child = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    assert_eq!(child.is_subset_of(&parent), Err(CapaError::MonotonicityViolation));
}

// ==================== Domain Revocation ====================

#[test]
fn test_domain_revocation() {
    let policy = DomainPolicy::new_root();
    let mut domain = Domain::new(policy);
    domain.seal().unwrap();

    domain.revoke();
    assert!(domain.is_revoked());
    assert_eq!(domain.status, DomainStatus::Revoked);
}

// ==================== Interrupt Policy Tests ====================

#[test]
fn test_interrupt_policy_default() {
    let policy = InterruptPolicy::new_default(VectorPolicy::default_deliver());

    // All vectors should use the default policy
    for i in 0..=255u8 {
        let vec_policy = policy.get_policy(i);
        assert!(matches!(vec_policy.visibility, InterruptVisibility::Deliver));
    }
}

#[test]
fn test_interrupt_policy_override() {
    let mut policy = InterruptPolicy::new_default(VectorPolicy::default_deliver());

    // Override vector 32
    policy.set_policy(32, VectorPolicy::default_report());

    // Vector 32 should have Report visibility
    let vec32_policy = policy.get_policy(32);
    assert!(matches!(vec32_policy.visibility, InterruptVisibility::Report));

    // Other vectors should still have Deliver
    let vec10_policy = policy.get_policy(10);
    assert!(matches!(vec10_policy.visibility, InterruptVisibility::Deliver));
}

// ==================== Virtual Processor State Tests ====================

#[test]
fn test_vprocessor_state_creation() {
    let vproc = VProcessorState::new(1);
    assert_eq!(vproc.id, 1);
    assert!(vproc.registers.is_empty());
    assert!(vproc.platform_data.is_empty());
}

#[test]
fn test_add_vprocessor_state() {
    let mut policy = DomainPolicy::new_root();
    assert_eq!(policy.vprocessor_states.len(), 0);

    let vproc = VProcessorState::new(1);
    policy.add_vprocessor_state(vproc);

    assert_eq!(policy.vprocessor_states.len(), 1);
    assert_eq!(policy.vprocessor_states[0].id, 1);
}

// ==================== Domain ID Generation ====================

#[test]
fn test_domain_id_generation() {
    let policy = DomainPolicy::new_root();
    let domain1 = Domain::new(policy.clone());
    let domain2 = Domain::new(policy.clone());

    // IDs should be unique and increasing
    assert_ne!(domain1.id, domain2.id);
    assert!(domain2.id > domain1.id);
}

#[test]
fn test_root_domain_has_id_zero() {
    let root = Domain::new_root();
    assert_eq!(root.id, 0);
}

// ==================== Policy Combinations ====================

#[test]
fn test_policy_with_limited_cores_and_api() {
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
    let root_policy = DomainPolicy::new_root();

    let level1_api = MonitorAPI::from_bits(MonitorAPI::CREATE | MonitorAPI::SEAL | MonitorAPI::ATTEST);
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
    let parent = DomainPolicy::new_root(); // All cores
    let child = DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE);

    // Child with 4 cores should be subset of parent with all cores
    assert!(child.is_subset_of(&parent).is_ok());
}

#[test]
fn test_receive_after_seal_flag() {
    let root_policy = DomainPolicy::new_root();
    assert!(root_policy.receive_after_seal);

    let restricted_policy = DomainPolicy::new_restricted(0b1, MonitorAPI::NONE);
    assert!(!restricted_policy.receive_after_seal);
}
