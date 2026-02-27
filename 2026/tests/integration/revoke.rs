//! Tests for revoke logic with re-enabling parent access

use capability_engine::*;
use std::sync::Arc;

fn bootstrap() -> (CapabilityRef<Domain>, CapabilityRef<MemoryRegion>, LocalHandle) {
    let root_domain = Domain::new_root(4); // already sealed
    let root = Capability::new_root(0, 0, root_domain);
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let r0 = Capability::new_root(0, 1, root_region);
    root.write().data.add_memory_capability(1, Arc::downgrade(&r0));
    let r0_h: LocalHandle = 1;
    (root, r0, r0_h)
}

#[test]
fn test_revoke_carved_child_never_sent() {
    let (root, _r0, r0_h) = bootstrap();

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_h, _) = Capability::carve_memory(&root, r0_h, child_access).unwrap();

    // Revoke the child — it was never sent, so owner unchanged, no MMU updates
    let updates = Capability::revoke_memory_child(&root, r0_h, child_h).unwrap();
    assert!(updates.is_empty());
}

#[test]
fn test_revoke_carved_child_after_send() {
    let (root, _r0, r0_h) = bootstrap();

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_h, _) = Capability::carve_memory(&root, r0_h, child_access).unwrap();

    // Create an unsealed receiver domain — send causes immediate transfer
    let dom5_h = Capability::create_domain(
        &root,
        DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL),
    )
    .unwrap();
    let dom5 = root.read().data.domain_capabilities[&dom5_h].upgrade().unwrap();
    let dom5_id = dom5.read().data.id;

    let _send_updates = Capability::send_memory(&root, child_h, dom5_h, Attributes::NONE).unwrap();

    // Revoke: parent_h = r0_h, child_sub = child_h (stable sub_handle)
    let revoke_updates = Capability::revoke_memory_child(&root, r0_h, child_h).unwrap();

    // 1. Unmap from dom5, 2. Remap to root
    assert_eq!(revoke_updates.len(), 2);

    let root_id = root.read().data.id;
    let updates_list = revoke_updates.updates();

    let has_unmap = updates_list.iter().any(|u| {
        matches!(u, Update::Unmap { domain, address, size }
            if *domain == dom5_id && *address == 0x1000 && *size == 0x1000)
    });
    assert!(has_unmap, "Should unmap from child's domain");

    let has_map = updates_list.iter().any(|u| {
        matches!(u, Update::Map { domain, address, size, .. }
            if *domain == root_id && *address == 0x1000 && *size == 0x1000)
    });
    assert!(has_map, "Should remap to parent's domain");
}

#[test]
fn test_revoke_aliased_child_no_remapping() {
    let (root, _r0, r0_h) = bootstrap();

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let child_h = Capability::alias_memory(&root, r0_h, child_access).unwrap();

    // Create an unsealed receiver domain
    let dom5_h = Capability::create_domain(
        &root,
        DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL),
    )
    .unwrap();
    let dom5 = root.read().data.domain_capabilities[&dom5_h].upgrade().unwrap();

    let _send_updates = Capability::send_memory(&root, child_h, dom5_h, Attributes::NONE).unwrap();

    let revoke_updates = Capability::revoke_memory_child(&root, r0_h, child_h).unwrap();

    // Aliased children must NOT generate a remap to parent
    let root_id = root.read().data.id;
    let has_map_to_parent = revoke_updates
        .updates()
        .iter()
        .any(|u| matches!(u, Update::Map { domain, .. } if *domain == root_id));
    assert!(!has_map_to_parent, "Aliased children should not remap to parent on revoke");
}

#[test]
fn test_revoke_with_clean_and_remap() {
    let (root, _r0, r0_h) = bootstrap();

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_h, _) = Capability::carve_memory(&root, r0_h, child_access).unwrap();

    // Create an unsealed receiver domain
    let dom5_h = Capability::create_domain(
        &root,
        DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL),
    )
    .unwrap();
    let dom5 = root.read().data.domain_capabilities[&dom5_h].upgrade().unwrap();
    let dom5_id = dom5.read().data.id;

    let attrs = Attributes::from_bits(Attributes::CLEAN);
    let _send_updates = Capability::send_memory(&root, child_h, dom5_h, attrs).unwrap();

    let revoke_updates = Capability::revoke_memory_child(&root, r0_h, child_h).unwrap();

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
        .any(|u| matches!(u, Update::Unmap { domain, .. } if *domain == dom5_id));
    assert!(has_unmap);

    let has_map = updates_list
        .iter()
        .any(|u| matches!(u, Update::Map { domain, .. } if *domain == root_id));
    assert!(has_map);
}

#[test]
fn test_nested_carve_revoke() {
    let (root, _r0, r0_h) = bootstrap();
    let root_id = root.read().data.id;

    // Root carves child1
    let c1_access = Access::new(0x2000, 0x4000, Rights::RW);
    let (child1_h, _) = Capability::carve_memory(&root, r0_h, c1_access).unwrap();

    // Create dom5 (unsealed) to receive child1
    let dom5_h = Capability::create_domain(
        &root,
        DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL),
    )
    .unwrap();
    let dom5 = root.read().data.domain_capabilities[&dom5_h].upgrade().unwrap();

    // Send child1 to dom5 (immediate transfer — dom5 is unsealed)
    let _send1 = Capability::send_memory(&root, child1_h, dom5_h, Attributes::NONE).unwrap();

    // Seal dom5 so it can carve from child1
    Capability::seal_domain_op(&root, dom5_h).unwrap();

    // After send, child1 is the first (and only) cap in dom5's memory table → handle 1
    let child1_h_in_dom5: LocalHandle = 1;
    let c2_access = Access::new(0x3000, 0x1000, Rights::R);
    let (child2_h_in_dom5, _) =
        Capability::carve_memory(&dom5, child1_h_in_dom5, c2_access).unwrap();

    // Create dom10 (unsealed) to receive child2
    let dom10_h = Capability::create_domain(
        &root,
        DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL),
    )
    .unwrap();
    let dom10 = root.read().data.domain_capabilities[&dom10_h].upgrade().unwrap();

    // Register dom10 in dom5's domain table so dom5 can send to it.
    let dom10_h_in_dom5: LocalHandle = 1;
    dom5.write().data.add_domain_capability(dom10_h_in_dom5, Arc::downgrade(&dom10));

    let _send2 =
        Capability::send_memory(&dom5, child2_h_in_dom5, dom10_h_in_dom5, Attributes::NONE).unwrap();

    // Revoke child1 from root — the entire subtree (including child2) is revoked
    let revoke_updates = Capability::revoke_memory_child(&root, r0_h, child1_h).unwrap();

    assert!(revoke_updates.len() >= 2);

    // Root should regain access to child1's full region
    let parent_regains = revoke_updates.updates().iter().any(|u| {
        matches!(u, Update::Map { domain, address, size, .. }
            if *domain == root_id && *address == 0x2000 && *size == 0x4000)
    });
    assert!(parent_regains, "Parent should regain access to child1's region");
}

#[test]
fn test_revoke_preserves_parent_rights() {
    let root_domain = Domain::new_root(4); // already sealed
    let root = Capability::new_root(0, 0, root_domain);

    // Bootstrap with R-only root region
    let mut region = MemoryRegion::new_root(0x0, 0x10000);
    region.access.rights = Rights::R;
    let r0 = Capability::new_root(0, 1, region);
    root.write().data.add_memory_capability(1, Arc::downgrade(&r0));
    let r0_h: LocalHandle = 1;
    let root_id = root.read().data.id;

    let child_access = Access::new(0x1000, 0x1000, Rights::R);
    let (child_h, _) = Capability::carve_memory(&root, r0_h, child_access).unwrap();

    // Create an unsealed receiver domain
    let dom5_h = Capability::create_domain(
        &root,
        DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL),
    )
    .unwrap();
    let dom5 = root.read().data.domain_capabilities[&dom5_h].upgrade().unwrap();

    let _send = Capability::send_memory(&root, child_h, dom5_h, Attributes::NONE).unwrap();

    let revoke_updates = Capability::revoke_memory_child(&root, r0_h, child_h).unwrap();

    // Remap must honour parent's R-only rights
    let has_correct_rights = revoke_updates.updates().iter().any(|u| {
        if let Update::Map { domain, read, write, execute, .. } = u {
            *domain == root_id && *read && !*write && !*execute
        } else {
            false
        }
    });
    assert!(has_correct_rights, "Remapping should preserve parent's original rights");
}
