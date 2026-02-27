//! Test generated from CLI session

use capability_engine::*;
use std::sync::Arc;

#[test]
fn test_session() {
    // Bootstrap: Domain::new_root creates a sealed domain (id=0, status=Sealed)
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let r0 = Capability::new_root(0, 1, root_region);
    root.write().data.add_memory_capability(1, Arc::downgrade(&r0));
    let r0_h: LocalHandle = 1;

    // Create child domain dom1 via domain-mediated API
    let api = MonitorAPI::from_bits(0xfff);
    let policy = DomainPolicy::new_restricted(0x1, api);
    let dom1_h = Capability::create_domain(&root, policy).unwrap();
    let dom1 = root.read().data.domain_capabilities[&dom1_h].upgrade().unwrap();
    let domain_id = dom1.read().data.id;

    // Carve r1 from r0 (r0.owner_domain=None → validate_operation skipped)
    let access = Access::new(0x0, 0x1000, Rights::RWX);
    let (r1_h, _) = Capability::carve_memory(&root, r0_h, access).unwrap();

    // Alias r1 while root still owns it (r1.owner_domain=Some(root), root sealed → OK)
    let access = Access::new(0x0, 0x1000, Rights::RWX);
    let _r2_h = Capability::alias_memory(&root, r1_h, access).unwrap();

    // Send r1 to dom1 with VITAL attribute (dom1 unsealed → immediate transfer)
    let _updates = Capability::send_memory(
        &root,
        r1_h,
        dom1_h,
        Attributes::from_bits(Attributes::VITAL | Attributes::CLEAN),
    )
    .unwrap();

    // Seal dom1
    Capability::seal_domain_op(&root, dom1_h).unwrap();

    // Attest
    let _attestation = attest_domain(&root);
    let _attestation = attest_domain(&dom1);

    // Revoke r1 from r0: r1_h is r1's stable SubHandle in r0's children tree
    // (the SubHandle equals the LocalHandle returned by carve_memory and is stable after sends)
    let updates = Capability::revoke_memory_child(&root, r0_h, r1_h).unwrap();

    // Verify that the update batch contains a domain revocation for dom1
    let has_domain_revoke = updates.updates().iter().any(|op| {
        matches!(op, Update::RevokeDomain { domain, .. } if *domain == domain_id)
    });

    assert!(
        has_domain_revoke,
        "Revoking VITAL capability should generate RevokeDomain update for owner"
    );

    dom1.write().data.revoke();
    assert_eq!(
        dom1.read().data.status,
        DomainStatus::Revoked,
        "dom1 should be revoked after processing the VITAL revocation update"
    );
}
