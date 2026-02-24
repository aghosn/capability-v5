//! Tests for revoke logic with re-enabling parent access

use capability_engine::*;

#[test]
fn test_revoke_carved_child_never_sent() {
    // Setup: Parent carves a child but never sends it
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let parent = Capability::new_root(0, 0, region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_child, _) = parent.carve(child_access, 1).unwrap();

    // Revoke the child
    let updates = parent.revoke(1).unwrap();

    // Since child was never sent (owner == parent owner), no updates needed
    // Parent never lost access in the first place
    assert!(updates.is_empty());
}

#[test]
fn test_revoke_carved_child_after_send() {
    // Setup: Parent carves a child and sends it to another domain
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let parent = Capability::new_root(0, 0, region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child, _) = parent.carve(child_access, 1).unwrap();

    // Send child to domain 5 (changes ownership and handle)
    let _send_updates = child.send(5, 10, Attributes::NONE).unwrap();

    // Now revoke the child using Arc reference (not handle, since handle changed)
    let revoke_updates = parent.revoke_ref(&child).unwrap();

    // Should have 2 updates:
    // 1. Unmap from child's domain (5)
    // 2. Remap to parent's domain (0)
    assert_eq!(revoke_updates.len(), 2);

    let updates_list = revoke_updates.updates();

    // Check for unmap from domain 5
    let has_unmap = updates_list.iter().any(|u| {
        matches!(u, Update::Unmap { domain, address, size }
            if *domain == 5 && *address == 0x1000 && *size == 0x1000)
    });
    assert!(has_unmap, "Should unmap from child's domain");

    // Check for map to domain 0
    let has_map = updates_list.iter().any(|u| {
        matches!(u, Update::Map { domain, address, size, .. }
            if *domain == 0 && *address == 0x1000 && *size == 0x1000)
    });
    assert!(has_map, "Should remap to parent's domain");
}

#[test]
fn test_revoke_aliased_child_no_remapping() {
    // Setup: Parent creates an aliased child and sends it
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let parent = Capability::new_root(0, 0, region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let child = parent.alias(child_access, 1).unwrap();

    // Send child to domain 5 (changes ownership and handle)
    let _send_updates = child.send(5, 10, Attributes::NONE).unwrap();

    // Revoke the child using Arc reference
    let revoke_updates = parent.revoke_ref(&child).unwrap();

    // Aliased children should NOT cause remapping to parent
    // Because aliases don't remove access from parent
    // So we should only have cleanup, not remapping
    let updates_list = revoke_updates.updates();

    // Should NOT have a map to parent's domain
    let has_map_to_parent = updates_list.iter().any(|u| {
        matches!(u, Update::Map { domain, .. } if *domain == 0)
    });
    assert!(!has_map_to_parent, "Aliased children should not remap to parent on revoke");
}

#[test]
fn test_revoke_with_clean_and_remap() {
    // Setup: Carved child with CLEAN attribute, sent to another domain
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let parent = Capability::new_root(0, 0, region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child, _) = parent.carve(child_access, 1).unwrap();

    // Send with CLEAN attribute
    let attrs = Attributes::from_bits(Attributes::CLEAN);
    let _send_updates = child.send(5, 10, attrs).unwrap();

    // Revoke using Arc reference
    let revoke_updates = parent.revoke_ref(&child).unwrap();

    // Should have 3 updates:
    // 1. Zero memory (CLEAN attribute)
    // 2. Unmap from child's domain
    // 3. Remap to parent's domain
    assert_eq!(revoke_updates.len(), 3);

    let updates_list = revoke_updates.updates();

    // Check for zero memory
    let has_zero = updates_list.iter().any(|u| {
        matches!(u, Update::ZeroMemory { address, size }
            if *address == 0x1000 && *size == 0x1000)
    });
    assert!(has_zero, "Should zero memory due to CLEAN attribute");

    // Check for unmap
    let has_unmap = updates_list.iter().any(|u| {
        matches!(u, Update::Unmap { domain, .. } if *domain == 5)
    });
    assert!(has_unmap);

    // Check for remap to parent
    let has_map = updates_list.iter().any(|u| {
        matches!(u, Update::Map { domain, .. } if *domain == 0)
    });
    assert!(has_map);
}

#[test]
fn test_nested_carve_revoke() {
    // Setup: Parent carves child1, child1 carves child2, both sent to different domains
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let parent = Capability::new_root(0, 0, region);

    // Parent (domain 0) carves child1
    let c1_access = Access::new(0x2000, 0x4000, Rights::RW);
    let (child1, _) = parent.carve(c1_access, 1).unwrap();

    // Send child1 to domain 5
    let _send1 = child1.send(5, 1, Attributes::NONE).unwrap();

    // Child1 (now owned by domain 5) carves child2
    let c2_access = Access::new(0x3000, 0x1000, Rights::R);
    let (child2, _) = child1.carve(c2_access, 2).unwrap();

    // Send child2 to domain 10
    let _send2 = child2.send(10, 1, Attributes::NONE).unwrap();

    // Now revoke child1 from parent
    // This should revoke the entire subtree including child2
    let revoke_updates = parent.revoke(1).unwrap();

    // Should have updates for:
    // - Unmapping child2 from domain 10
    // - Remapping child2's region to child1's owner (domain 5)
    // - Unmapping child1 from domain 5
    // - Remapping child1's region to parent's owner (domain 0)
    assert!(revoke_updates.len() >= 2); // At least unmap from 5 and map to 0

    let updates_list = revoke_updates.updates();

    // Check parent regains access to child1's region
    let parent_regains = updates_list.iter().any(|u| {
        matches!(u, Update::Map { domain, address, size, .. }
            if *domain == 0 && *address == 0x2000 && *size == 0x4000)
    });
    assert!(parent_regains, "Parent should regain access to child1's region");
}

#[test]
fn test_revoke_preserves_parent_rights() {
    // Setup: Parent with limited rights carves child and sends it
    let mut region = MemoryRegion::new_root(0x0, 0x10000);
    region.access.rights = Rights::R; // Parent only has READ
    let parent = Capability::new_root(0, 0, region);

    let child_access = Access::new(0x1000, 0x1000, Rights::R);
    let (child, _) = parent.carve(child_access, 1).unwrap();

    // Send to domain 5
    let _send = child.send(5, 10, Attributes::NONE).unwrap();

    // Revoke using Arc reference
    let revoke_updates = parent.revoke_ref(&child).unwrap();

    let updates_list = revoke_updates.updates();

    // Check that remap preserves parent's rights (READ only)
    let has_correct_rights = updates_list.iter().any(|u| {
        if let Update::Map { domain, read, write, execute, .. } = u {
            *domain == 0 && *read && !*write && !*execute
        } else {
            false
        }
    });
    assert!(has_correct_rights, "Remapping should preserve parent's original rights");
}
