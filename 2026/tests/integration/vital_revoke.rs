//! Test generated from CLI session

use capability_engine::*;
use std::sync::Arc;

#[test]
fn test_session() {
    // Initialize root domain and memory
    let root_domain = Domain::new_root(4);
    let root_domain = Capability::new_root(0, 0, root_domain);
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root_mem = Capability::new_root(0, 1, root_region);
    root_domain.write().data.add_memory_capability(1, Arc::downgrade(&root_mem));

    // Create child domain: dom1
    let api = MonitorAPI::from_bits(0xfff);
    let policy = DomainPolicy::new_restricted(0x1, api);
    let root_id = root_domain.read().data.id;
    let dom1 = Capability::create_child_domain(&root_domain, policy, root_id, 2).unwrap();
    root_domain.write().data.add_domain_capability(2, Arc::downgrade(&dom1));

    // Carve memory region: r1
    let access = Access::new(0x0, 0x1000, Rights::RWX);
    let (r1, _) = Capability::carve_child(&root_mem, access, 0, 2).unwrap();

    // Send r1 to dom1
    let domain_id = dom1.read().data.id;
    let _updates = Capability::send_to(&r1, 0, domain_id, Attributes::from_bits(Attributes::VITAL | Attributes::CLEAN)).unwrap();
    dom1.write().data.add_memory_capability(1, Arc::downgrade(&r1));

    // Alias memory region: r2
    let access = Access::new(0x0, 0x1000, Rights::RWX);
    let _r2 = Capability::alias_child(&r1, access, domain_id, 2).unwrap();

    // Seal domain: dom1
    dom1.write().data.seal().unwrap();

    // Attest domain: root_domain
    let _attestation = attest_domain(&root_domain);
    // Verify attestation if needed

    // Attest domain: dom1
    let _attestation = attest_domain(&dom1);
    // Verify attestation if needed

    // Revoke r1 from root_mem (r1 is VITAL, so this should generate a domain revocation update)
    let updates = Capability::revoke_child_ref(&root_mem, &r1).unwrap();

    // Verify that the update batch contains a domain revocation for dom1
    let has_domain_revoke = updates.updates().iter().any(|op| {
        matches!(op, Update::RevokeDomain { domain, .. } if *domain == domain_id)
    });

    assert!(
        has_domain_revoke,
        "Revoking VITAL capability should generate RevokeDomain update for owner"
    );

    // In a real system, the monitor would process this update and actually revoke dom1
    // For this test, we simulate that by manually revoking the domain
    dom1.write().data.revoke();

    // Verify that dom1 is now revoked
    assert_eq!(
        dom1.read().data.status,
        DomainStatus::Revoked,
        "dom1 should be revoked after processing the VITAL revocation update"
    );

    // Test completed successfully
}
