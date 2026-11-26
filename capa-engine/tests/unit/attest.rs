//! Tests for attestation and enumeration functionality

use capability_engine::*;

#[path = "../common/mod.rs"]
mod common;


#[test]
fn test_build_structured_attestation() {
    let _platform = common::TestPlatform::new();
    let policy = DomainPolicy::new_root(4);
    let domain = Domain::new(policy);
    let domain_ref = Capability::new_root(0, 0, domain);
    let domain_id = domain_ref.read().data.id;

    let report = build_structured_attestation(&domain_ref);
    assert_eq!(report.domain_id, domain_id);
    assert!(report.mem_caps.is_empty());
    assert!(report.dom_caps.is_empty());
}

#[test]
fn test_enumerate_tree() {
    let platform = common::TestPlatform::new();
    let root_domain = Domain::new_root(4);
    let root_ref = Capability::new_root(0, 0, root_domain);

    // Use create which requires root to be sealed (new_root is already sealed)
    let child_policy = DomainPolicy::new_root(4);
    let _child_h = Capability::create(&platform, &root_ref, child_policy).unwrap().0;

    let ids = enumerate_domain_tree(&root_ref);
    assert_eq!(ids.len(), 2);
}

#[test]
fn test_attest_memory_region() {
    let _platform = common::TestPlatform::new();
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let mem_root = Capability::new_root(0, 0, root_region);

    let report = attest_memory_region(&mem_root);
    assert!(report.contains("Memory Region"));
    assert!(report.contains("Kind:"));
    assert!(report.contains("Status:"));
}

#[test]
fn test_enumerate_tree_with_multiple_levels() {
    let platform = common::TestPlatform::new();
    let root_domain = Domain::new_root(4);
    let root_ref = Capability::new_root(0, 0, root_domain);

    // Create first level children using domain-mediated API
    let child1_h = Capability::create(&platform, &root_ref, DomainPolicy::new_root(4)).unwrap().0;
    let _child2_h = Capability::create(&platform, &root_ref, DomainPolicy::new_root(4)).unwrap().0;

    // Seal child1 before creating grandchild under it
    Capability::seal(&platform, &root_ref, child1_h).unwrap();
    let child1_ref = root_ref.read().data.domain_capabilities[&child1_h]
        .upgrade()
        .unwrap();

    // Create grandchild under child1
    let _grandchild_h = Capability::create(&platform, &child1_ref, DomainPolicy::new_root(4)).unwrap().0;

    let ids = enumerate_domain_tree(&root_ref);
    assert_eq!(ids.len(), 4); // root + 2 children + 1 grandchild
}

#[test]
fn test_attest_self_structured_requires_sealed_and_permission() {
    let platform = common::TestPlatform::new();
    let root_domain = Domain::new_root(4);
    let root_ref = Capability::new_root(0, 0, root_domain);

    // Unsealed child lacks ATTEST-gated access to its own structured report.
    let child_h = Capability::create(&platform, &root_ref, DomainPolicy::new_root(4))
        .unwrap()
        .0;
    let child_ref = root_ref.read().data.domain_capabilities[&child_h]
        .upgrade()
        .unwrap();
    assert_eq!(
        Capability::attest_self_structured(&platform, &child_ref).unwrap_err(),
        CapaError::DomainNotSealed
    );

    Capability::seal(&platform, &root_ref, child_h).unwrap();
    let (report, _) = Capability::attest_self_structured(&platform, &child_ref).unwrap();
    let child_id = child_ref.read().data.id;
    assert_eq!(report.domain_id, child_id);
}

#[test]
fn self_attestation_delivery_holds_operation_lock_and_propagates_errors() {
    let platform = common::TestPlatform::new();
    let root = Capability::new_root(0, 0, Domain::new_root(1));
    let root_id = root.read().data.id;
    for generate in [true, false] {
        let error = Capability::with_self_attestation(&platform, &root, generate, |id, report| {
            assert_eq!(id, root_id);
            assert!(
                platform.operation_lock_is_held(),
                "revocation must remain excluded"
            );
            if generate {
                assert_eq!(report.unwrap().domain_id, root_id);
            } else {
                assert!(report.is_none());
            }
            Err::<(), _>(CapaError::NotificationQueueFull)
        })
        .unwrap_err();
        assert_eq!(error, CapaError::NotificationQueueFull);
        assert!(
            !platform.operation_lock_is_held(),
            "delivery errors must release the lock"
        );
    }
}

#[test]
fn self_attestation_continuation_does_not_read_inventory() {
    use std::sync::mpsc;
    use std::time::Duration;

    let platform = common::TestPlatform::new();
    let root = Capability::new_root(0, 0, Domain::new_root(1));
    let child_h = Capability::create(
        &platform,
        &root,
        DomainPolicy::new_restricted(1, MonitorAPI::ALL),
    )
    .unwrap()
    .0;
    let child = root.read().data.domain_capabilities[&child_h]
        .upgrade()
        .unwrap();
    Capability::with_self_attestation(&platform, &root, true, |_, report| {
        assert_eq!(report.unwrap().dom_caps.len(), 1);
        Ok(())
    })
    .unwrap();

    // A report walk would block on this inventory entry; validation must not.
    let inventory_guard = child.write();
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            Capability::with_self_attestation(&platform, &root, false, |_, report| {
                assert!(report.is_none());
                tx.send(()).unwrap();
                Ok(())
            })
        });
        let completed = rx.recv_timeout(Duration::from_secs(5));
        drop(inventory_guard);
        worker.join().unwrap().unwrap();
        completed.expect("continuation walked the inventory instead of serving cached data");
    });
}

#[test]
fn self_attestation_validates_initial_and_continuation_callers() {
    let platform = common::TestPlatform::new();
    let root = Capability::new_root(0, 0, Domain::new_root(1));
    let child_h = Capability::create(
        &platform,
        &root,
        DomainPolicy::new_restricted(1, MonitorAPI::NONE),
    )
    .unwrap()
    .0;
    let child = root.read().data.domain_capabilities[&child_h]
        .upgrade()
        .unwrap();
    let rejected = |expected| {
        for generate in [true, false] {
            let result = Capability::with_self_attestation(
                &platform,
                &child,
                generate,
                |_, _| -> Result<()> {
                    panic!("unauthorized attestation reached delivery");
                },
            );
            assert_eq!(result.unwrap_err(), expected);
        }
    };
    rejected(CapaError::DomainNotSealed);
    Capability::seal(&platform, &root, child_h).unwrap();
    rejected(CapaError::ApiNotAllowed);
    Capability::revoke_domain(&platform, &root, child_h).unwrap();
    rejected(CapaError::DomainRevoked);
}
