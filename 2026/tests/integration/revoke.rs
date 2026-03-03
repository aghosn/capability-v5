//! Tests for revoke logic with re-enabling parent access

use capability_engine::memory::Rights;
use capability_engine::*;
use std::sync::Arc;

fn bootstrap() -> (
    CapabilityRef<Domain>,
    CapabilityRef<MemoryRegion>,
    LocalHandle,
) {
    let root_domain = Domain::new_root(4); // already sealed
    let root = Capability::new_root(0, 0, root_domain);
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let r0 = Capability::new_root(0, 1, root_region);
    root.write()
        .data
        .add_memory_capability(1, Arc::downgrade(&r0));
    let r0_h: LocalHandle = 1;
    (root, r0, r0_h)
}

#[test]
fn test_revoke_carved_child_never_sent() {
    let (root, _r0, r0_h) = bootstrap();

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_child_h, child_sub, _) = Capability::carve_memory(&root, r0_h, child_access).unwrap();

    // Revoke the child — it was never sent, so owner unchanged, no MMU updates
    let updates = Capability::revoke_memory_child(&root, r0_h, child_sub).unwrap();
    assert!(updates.is_empty());
}

#[test]
fn test_revoke_carved_child_after_send() {
    let (root, _r0, r0_h) = bootstrap();

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_h, child_sub, _) = Capability::carve_memory(&root, r0_h, child_access).unwrap();

    // Create an unsealed receiver domain — send causes immediate transfer
    let dom5_h =
        Capability::create_domain(&root, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL))
            .unwrap();
    let dom5 = root.read().data.domain_capabilities[&dom5_h]
        .upgrade()
        .unwrap();
    let dom5_id = dom5.read().data.id;

    let _send_updates = Capability::send_memory(&root, child_h, dom5_h, Attributes::NONE).unwrap();

    // After send to unsealed receiver, child_h was removed from root's table; revoke by handle.
    let revoke_updates = Capability::revoke_memory_child(&root, r0_h, child_sub).unwrap();

    // 1. Unmap from dom5, 2. Remap to root
    assert_eq!(revoke_updates.len(), 2);

    let root_id = root.read().data.id;
    let updates_list = revoke_updates.updates();

    let has_unmap = updates_list.iter().any(|u| {
        matches!(u, Update::ChangeRights { domain, address, size, rights, .. }
            if *domain == dom5_id && *address == 0x1000 && *size == 0x1000 && *rights == Rights::NONE)
    });
    assert!(has_unmap, "Should unmap from child's domain");

    let has_map = updates_list.iter().any(|u| {
        matches!(u, Update::ChangeRights { domain, address, size, shootdown_required: false, .. }
            if *domain == root_id && *address == 0x1000 && *size == 0x1000)
    });
    assert!(has_map, "Should remap to parent's domain");
}

#[test]
fn test_revoke_aliased_child_no_remapping() {
    let (root, _r0, r0_h) = bootstrap();

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_h, child_sub) = Capability::alias_memory(&root, r0_h, child_access).unwrap();

    // Create an unsealed receiver domain
    let dom5_h =
        Capability::create_domain(&root, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL))
            .unwrap();
    let dom5 = root.read().data.domain_capabilities[&dom5_h]
        .upgrade()
        .unwrap();
    let dom5_id = dom5.read().data.id;

    let _send_updates = Capability::send_memory(&root, child_h, dom5_h, Attributes::NONE).unwrap();

    let revoke_updates = Capability::revoke_memory_child(&root, r0_h, child_sub).unwrap();

    // Aliased children must NOT generate a remap to parent (alias never removed parent access).
    let root_id = root.read().data.id;
    let has_map_to_parent = revoke_updates
        .updates()
        .iter()
        .any(|u| matches!(u, Update::ChangeRights { domain, shootdown_required: false, .. } if *domain == root_id));
    assert!(
        !has_map_to_parent,
        "Aliased children should not remap to parent on revoke"
    );

    // Aliased children MUST unmap from the receiver domain.
    let has_unmap_receiver = revoke_updates
        .updates()
        .iter()
        .any(|u| matches!(u, Update::ChangeRights { domain, rights, shootdown_required: true, .. }
            if *domain == dom5_id && *rights == Rights::NONE));
    assert!(
        has_unmap_receiver,
        "Alias receiver must be unmapped on revoke"
    );
}

#[test]
fn test_revoke_with_clean_and_remap() {
    let (root, _r0, r0_h) = bootstrap();

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_h, child_sub, _) = Capability::carve_memory(&root, r0_h, child_access).unwrap();

    // Create an unsealed receiver domain
    let dom5_h =
        Capability::create_domain(&root, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL))
            .unwrap();
    let dom5 = root.read().data.domain_capabilities[&dom5_h]
        .upgrade()
        .unwrap();
    let dom5_id = dom5.read().data.id;

    let attrs = Attributes::from_bits(Attributes::CLEAN);
    let _send_updates = Capability::send_memory(&root, child_h, dom5_h, attrs).unwrap();

    let revoke_updates = Capability::revoke_memory_child(&root, r0_h, child_sub).unwrap();

    // 1. ZeroMemory (CLEAN), 2. Unmap from dom5, 3. Remap to root
    assert_eq!(revoke_updates.len(), 3);

    let root_id = root.read().data.id;
    let updates_list = revoke_updates.updates();

    let has_zero = updates_list.iter().any(|u| {
        matches!(u, Update::ZeroMemory { address, size }
            if *address == 0x1000 && *size == 0x1000)
    });
    assert!(has_zero, "Should zero memory due to CLEAN attribute");

    let has_unmap = updates_list
        .iter()
        .any(|u| matches!(u, Update::ChangeRights { domain, rights, .. } if *domain == dom5_id && *rights == Rights::NONE));
    assert!(has_unmap);

    let has_map = updates_list
        .iter()
        .any(|u| matches!(u, Update::ChangeRights { domain, shootdown_required: false, .. } if *domain == root_id));
    assert!(has_map);
}

#[test]
fn test_nested_carve_revoke() {
    let (root, _r0, r0_h) = bootstrap();
    let root_id = root.read().data.id;

    // Root carves child1
    let c1_access = Access::new(0x2000, 0x4000, Rights::RW);
    let (child1_h, child1_sub, _) = Capability::carve_memory(&root, r0_h, c1_access).unwrap();

    // Create dom5 (unsealed) to receive child1
    let dom5_h =
        Capability::create_domain(&root, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL))
            .unwrap();
    let dom5 = root.read().data.domain_capabilities[&dom5_h]
        .upgrade()
        .unwrap();

    // Send child1 to dom5 (immediate transfer — dom5 is unsealed)
    let _send1 = Capability::send_memory(&root, child1_h, dom5_h, Attributes::NONE).unwrap();

    // Seal dom5 so it can carve from child1
    Capability::seal_domain_op(&root, dom5_h).unwrap();

    // After send, child1 is the first (and only) cap in dom5's memory table → handle 1
    let child1_h_in_dom5: LocalHandle = 1;
    let c2_access = Access::new(0x3000, 0x1000, Rights::R);
    let (child2_h_in_dom5, _, _) =
        Capability::carve_memory(&dom5, child1_h_in_dom5, c2_access).unwrap();

    // Create dom10 (unsealed) to receive child2
    let dom10_h =
        Capability::create_domain(&root, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL))
            .unwrap();
    let dom10 = root.read().data.domain_capabilities[&dom10_h]
        .upgrade()
        .unwrap();

    // Register dom10 in dom5's domain table so dom5 can send to it.
    let dom10_h_in_dom5: LocalHandle = 1;
    dom5.write()
        .data
        .add_domain_capability(dom10_h_in_dom5, Arc::downgrade(&dom10));

    let _send2 =
        Capability::send_memory(&dom5, child2_h_in_dom5, dom10_h_in_dom5, Attributes::NONE)
            .unwrap();

    // Revoke child1 from root — the entire subtree (including child2) is revoked
    let revoke_updates = Capability::revoke_memory_child(&root, r0_h, child1_sub).unwrap();

    assert!(revoke_updates.len() >= 2);

    // Root should regain access to child1's full region
    let parent_regains = revoke_updates.updates().iter().any(|u| {
        matches!(u, Update::ChangeRights { domain, address, size, shootdown_required: false, .. }
            if *domain == root_id && *address == 0x2000 && *size == 0x4000)
    });
    assert!(
        parent_regains,
        "Parent should regain access to child1's region"
    );
}

#[test]
fn test_revoke_preserves_parent_rights() {
    let root_domain = Domain::new_root(4); // already sealed
    let root = Capability::new_root(0, 0, root_domain);

    // Bootstrap with R-only root region
    let mut region = MemoryRegion::new_root(0x0, 0x10000);
    region.access.rights = Rights::R;
    let r0 = Capability::new_root(0, 1, region);
    root.write()
        .data
        .add_memory_capability(1, Arc::downgrade(&r0));
    let r0_h: LocalHandle = 1;
    let root_id = root.read().data.id;

    let child_access = Access::new(0x1000, 0x1000, Rights::R);
    let (child_h, child_sub, _) = Capability::carve_memory(&root, r0_h, child_access).unwrap();

    // Create an unsealed receiver domain
    let dom5_h =
        Capability::create_domain(&root, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL))
            .unwrap();
    let _dom5 = root.read().data.domain_capabilities[&dom5_h]
        .upgrade()
        .unwrap();

    let _send = Capability::send_memory(&root, child_h, dom5_h, Attributes::NONE).unwrap();

    let revoke_updates = Capability::revoke_memory_child(&root, r0_h, child_sub).unwrap();

    // Remap must honour parent's R-only rights
    let has_correct_rights = revoke_updates.updates().iter().any(|u| {
        if let Update::ChangeRights {
            domain,
            rights,
            shootdown_required: false,
            ..
        } = u
        {
            *domain == root_id && rights.read() && !rights.write() && !rights.execute()
        } else {
            false
        }
    });
    assert!(
        has_correct_rights,
        "Remapping should preserve parent's original rights"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-level revocation tests
// ─────────────────────────────────────────────────────────────────────────────

/// 3-level memory tree: root → child1 → child2 (different owners at each level).
/// Revocation must produce exactly 4 ChangeRights updates: Unmap+Remap for child2,
/// then Unmap+Remap for child1.
#[test]
fn test_multi_level_revoke_exact_updates() {
    let (root, _r0, r0_h) = bootstrap();
    let root_id = root.read().data.id;

    // Root carves child1 [0x2000, 0x4000) RW
    let c1_access = Access::new(0x2000, 0x4000, Rights::RW);
    let (child1_h, child1_sub, _) = Capability::carve_memory(&root, r0_h, c1_access).unwrap();

    // Create dom5 (unsealed), send child1 immediately, then seal dom5
    let dom5_h =
        Capability::create_domain(&root, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL))
            .unwrap();
    let dom5 = root.read().data.domain_capabilities[&dom5_h]
        .upgrade()
        .unwrap();
    let dom5_id = dom5.read().data.id;

    Capability::send_memory(&root, child1_h, dom5_h, Attributes::NONE).unwrap();
    Capability::seal_domain_op(&root, dom5_h).unwrap();

    // dom5 carves child2 [0x3000, 0x1000) R from child1 (handle 1 in dom5's table)
    let child1_h_in_dom5: LocalHandle = 1;
    let c2_access = Access::new(0x3000, 0x1000, Rights::R);
    let (child2_h_in_dom5, _, _) =
        Capability::carve_memory(&dom5, child1_h_in_dom5, c2_access).unwrap();

    // Create dom10 via root, register in dom5's domain table, send child2 to dom10
    let dom10_h =
        Capability::create_domain(&root, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL))
            .unwrap();
    let dom10 = root.read().data.domain_capabilities[&dom10_h]
        .upgrade()
        .unwrap();
    let dom10_id = dom10.read().data.id;

    let dom10_h_in_dom5: LocalHandle = 1;
    dom5.write()
        .data
        .add_domain_capability(dom10_h_in_dom5, Arc::downgrade(&dom10));
    Capability::send_memory(&dom5, child2_h_in_dom5, dom10_h_in_dom5, Attributes::NONE).unwrap();

    // Revoke child1 from root — cascades to child2
    let revoke_updates = Capability::revoke_memory_child(&root, r0_h, child1_sub).unwrap();
    let updates = revoke_updates.updates();

    // Must generate exactly 4 updates:
    //  1. Unmap dom10 from child2's range  (shootdown: true)
    //  2. Remap dom5  to  child2's range   (shootdown: false, rights = child1's RW)
    //  3. Unmap dom5  from child1's range  (shootdown: true)
    //  4. Remap root  to  child1's range   (shootdown: false, rights = mem_root's RWX)
    assert_eq!(updates.len(), 4, "3-level tree with distinct owners generates exactly 4 updates");

    let has_unmap_dom10 = updates.iter().any(|u| {
        matches!(u, Update::ChangeRights { domain, address, size, rights, shootdown_required: true, .. }
            if *domain == dom10_id && *address == 0x3000 && *size == 0x1000 && *rights == Rights::NONE)
    });
    assert!(has_unmap_dom10, "must unmap child2's range from dom10");

    let has_remap_dom5_child2 = updates.iter().any(|u| {
        matches!(u, Update::ChangeRights { domain, address, size, shootdown_required: false, .. }
            if *domain == dom5_id && *address == 0x3000 && *size == 0x1000)
    });
    assert!(has_remap_dom5_child2, "must remap child2's range back to dom5");

    let has_unmap_dom5 = updates.iter().any(|u| {
        matches!(u, Update::ChangeRights { domain, address, size, rights, shootdown_required: true, .. }
            if *domain == dom5_id && *address == 0x2000 && *size == 0x4000 && *rights == Rights::NONE)
    });
    assert!(has_unmap_dom5, "must unmap child1's full range from dom5");

    let has_remap_root = updates.iter().any(|u| {
        matches!(u, Update::ChangeRights { domain, address, size, shootdown_required: false, .. }
            if *domain == root_id && *address == 0x2000 && *size == 0x4000)
    });
    assert!(has_remap_root, "must remap child1's full range back to root");
}

/// Mixed subtree: one carved child sent away (generates Unmap+Remap) and one
/// aliased child sent away (generates no ChangeRights — aliases are shared).
/// Revocation of the parent must produce exactly 4 updates.
#[test]
fn test_revoke_mixed_carved_and_alias_subtree() {
    let (root, _r0, r0_h) = bootstrap();
    let root_id = root.read().data.id;

    // Root carves child1 [0x2000, 0x6000) RW, sends to dom5, seals dom5
    let c1_access = Access::new(0x2000, 0x6000, Rights::RW);
    let (child1_h, child1_sub, _) = Capability::carve_memory(&root, r0_h, c1_access).unwrap();

    let dom5_h =
        Capability::create_domain(&root, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL))
            .unwrap();
    let dom5 = root.read().data.domain_capabilities[&dom5_h]
        .upgrade()
        .unwrap();
    let dom5_id = dom5.read().data.id;

    Capability::send_memory(&root, child1_h, dom5_h, Attributes::NONE).unwrap();
    Capability::seal_domain_op(&root, dom5_h).unwrap();

    // dom5 carves child2 [0x2000, 0x2000) R from child1 and sends to dom_carved_recv
    let child1_h_in_dom5: LocalHandle = 1;
    let c2_access = Access::new(0x2000, 0x2000, Rights::R);
    let (child2_h_in_dom5, _, _) =
        Capability::carve_memory(&dom5, child1_h_in_dom5, c2_access).unwrap();

    let dom_carved_recv_h =
        Capability::create_domain(&root, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL))
            .unwrap();
    let dom_carved_recv = root.read().data.domain_capabilities[&dom_carved_recv_h]
        .upgrade()
        .unwrap();
    let dom_carved_recv_id = dom_carved_recv.read().data.id;

    dom5.write()
        .data
        .add_domain_capability(1, Arc::downgrade(&dom_carved_recv));
    Capability::send_memory(&dom5, child2_h_in_dom5, 1, Attributes::NONE).unwrap();

    // dom5 aliases alias1 [0x4000, 0x1000) R from child1 and sends to dom_alias_recv
    // alias1 does NOT overlap with the carved child2 [0x2000, 0x4000)
    let alias_access = Access::new(0x4000, 0x1000, Rights::R);
    let (alias1_h_in_dom5, _) =
        Capability::alias_memory(&dom5, child1_h_in_dom5, alias_access).unwrap();

    let dom_alias_recv_h =
        Capability::create_domain(&root, DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL))
            .unwrap();
    let dom_alias_recv = root.read().data.domain_capabilities[&dom_alias_recv_h]
        .upgrade()
        .unwrap();
    let dom_alias_recv_id = dom_alias_recv.read().data.id;

    dom5.write()
        .data
        .add_domain_capability(2, Arc::downgrade(&dom_alias_recv));
    Capability::send_memory(&dom5, alias1_h_in_dom5, 2, Attributes::NONE).unwrap();

    // Revoke child1 — alias branch generates no ChangeRights updates
    let revoke_updates = Capability::revoke_memory_child(&root, r0_h, child1_sub).unwrap();
    let updates = revoke_updates.updates();

    // Exactly 5 updates:
    //  Unmap dom_carved_recv + Remap dom5 (child2's range)
    //  Unmap dom5 + Remap root (child1's full range)
    //  Unmap dom_alias_recv (alias1's range — alias never remaps parent)
    assert_eq!(updates.len(), 5, "must generate 5 ChangeRights updates");

    let has_unmap_carved = updates.iter().any(|u| {
        matches!(u, Update::ChangeRights { domain, address, size, rights, shootdown_required: true, .. }
            if *domain == dom_carved_recv_id && *address == 0x2000 && *size == 0x2000 && *rights == Rights::NONE)
    });
    assert!(has_unmap_carved, "must unmap carved child from its receiver");

    let has_remap_dom5_child2 = updates.iter().any(|u| {
        matches!(u, Update::ChangeRights { domain, address, size, shootdown_required: false, .. }
            if *domain == dom5_id && *address == 0x2000 && *size == 0x2000)
    });
    assert!(has_remap_dom5_child2, "dom5 must regain carved child's range");

    let has_unmap_dom5 = updates.iter().any(|u| {
        matches!(u, Update::ChangeRights { domain, address, size, rights, shootdown_required: true, .. }
            if *domain == dom5_id && *address == 0x2000 && *size == 0x6000 && *rights == Rights::NONE)
    });
    assert!(has_unmap_dom5, "must unmap child1's full range from dom5");

    let has_remap_root = updates.iter().any(|u| {
        matches!(u, Update::ChangeRights { domain, address, size, shootdown_required: false, .. }
            if *domain == root_id && *address == 0x2000 && *size == 0x6000)
    });
    assert!(has_remap_root, "root must regain child1's full range");

    // Alias receiver MUST be unmapped (alias was sent to another domain).
    let alias_recv_unmap = updates.iter().any(|u| {
        matches!(u, Update::ChangeRights { domain, rights, shootdown_required: true, .. }
            if *domain == dom_alias_recv_id && *rights == Rights::NONE)
    });
    assert!(alias_recv_unmap, "alias receiver must be unmapped on revoke");
}
