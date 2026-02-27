//! Tests for attestation and enumeration functionality

use capability_engine::*;

#[test]
fn test_attest_domain() {
    let policy = DomainPolicy::new_root(4);
    let domain = Domain::new(policy);
    let domain_ref = Capability::new_root(0, 0, domain);

    let report = attest_domain(&domain_ref);
    assert!(report.report.contains("Domain ID"));
    assert!(report.signature.is_none());
}

#[test]
fn test_enumerate_tree() {
    let root_domain = Domain::new_root(4);
    let root_ref = Capability::new_root(0, 0, root_domain);

    // Use create_domain which requires root to be sealed (new_root is already sealed)
    let child_policy = DomainPolicy::new_root(4);
    let _child_h = Capability::create_domain(&root_ref, child_policy).unwrap();

    let ids = enumerate_domain_tree(&root_ref);
    assert_eq!(ids.len(), 2);
}

#[test]
fn test_attest_with_signature() {
    let policy = DomainPolicy::new_root(4);
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
    let root_domain = Domain::new_root(4);
    let root_ref = Capability::new_root(0, 0, root_domain);

    // Create first level children using domain-mediated API
    let child1_h = Capability::create_domain(&root_ref, DomainPolicy::new_root(4)).unwrap();
    let _child2_h = Capability::create_domain(&root_ref, DomainPolicy::new_root(4)).unwrap();

    // Seal child1 before creating grandchild under it
    Capability::seal_domain_op(&root_ref, child1_h).unwrap();
    let child1_ref = root_ref
        .read()
        .data
        .domain_capabilities[&child1_h]
        .upgrade()
        .unwrap();

    // Create grandchild under child1
    let _grandchild_h = Capability::create_domain(&child1_ref, DomainPolicy::new_root(4)).unwrap();

    let ids = enumerate_domain_tree(&root_ref);
    assert_eq!(ids.len(), 4); // root + 2 children + 1 grandchild
}
