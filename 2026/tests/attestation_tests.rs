//! Tests for attestation and enumeration functionality

use capability_engine::*;

#[test]
fn test_attest_domain() {
    let policy = DomainPolicy::new_root();
    let domain = Domain::new(policy);
    let domain_ref = Capability::new_root(0, 0, domain);

    let report = attest_domain(&domain_ref);
    assert!(report.report.contains("Domain ID"));
    assert!(report.signature.is_none());
}

#[test]
fn test_enumerate_tree() {
    let root_policy = DomainPolicy::new_root();
    let root_domain = Domain::new(root_policy);
    let root_ref = Capability::new_root(0, 0, root_domain);

    let child_policy = DomainPolicy::new_root();
    let child_domain = Domain::new(child_policy);
    let child_ref = Capability::new_child(1, 1, child_domain, std::sync::Arc::downgrade(&root_ref));
    root_ref.write().add_child(child_ref);

    let ids = enumerate_domain_tree(&root_ref);
    assert_eq!(ids.len(), 2);
}

#[test]
fn test_attest_with_signature() {
    let policy = DomainPolicy::new_root();
    let domain = Domain::new(policy);
    let domain_ref = Capability::new_root(0, 0, domain);

    let mut report = attest_domain(&domain_ref);
    assert!(report.signature.is_none());

    let signature = vec![1, 2, 3, 4, 5];
    report = report.with_signature(signature.clone());
    assert_eq!(report.signature, Some(signature));
}

#[test]
fn test_attest_memory_region() {
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let mem_root = Capability::new_root(0, 0, root_region);

    let report = attest_memory_region(&mem_root);
    assert!(report.contains("Memory Region"));
    assert!(report.contains("Kind:"));
    assert!(report.contains("Status:"));
}

#[test]
fn test_enumerate_tree_with_multiple_levels() {
    let root_policy = DomainPolicy::new_root();
    let root_domain = Domain::new(root_policy);
    let root_ref = Capability::new_root(0, 0, root_domain);

    // Create first level children
    let child1_policy = DomainPolicy::new_root();
    let child1_domain = Domain::new(child1_policy);
    let child1_ref = Capability::new_child(1, 1, child1_domain, std::sync::Arc::downgrade(&root_ref));
    root_ref.write().add_child(child1_ref.clone());

    let child2_policy = DomainPolicy::new_root();
    let child2_domain = Domain::new(child2_policy);
    let child2_ref = Capability::new_child(2, 2, child2_domain, std::sync::Arc::downgrade(&root_ref));
    root_ref.write().add_child(child2_ref);

    // Create second level child under child1
    let grandchild_policy = DomainPolicy::new_root();
    let grandchild_domain = Domain::new(grandchild_policy);
    let grandchild_ref = Capability::new_child(3, 3, grandchild_domain, std::sync::Arc::downgrade(&child1_ref));
    child1_ref.write().add_child(grandchild_ref);

    let ids = enumerate_domain_tree(&root_ref);
    assert_eq!(ids.len(), 4); // root + 2 children + 1 grandchild
}
