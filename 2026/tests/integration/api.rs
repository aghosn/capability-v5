//! Tests for the domain-mediated API (carve, alias, send, revoke, create, etc.)

use capability_engine::memory::Rights;
use capability_engine::*;
use std::sync::Arc;

/// Helper: sealed root domain with a memory root at local handle 1.
/// Returns (root, mem_root_h, _mem_root) — caller must keep `_mem_root` alive.
fn setup_root() -> (
    CapabilityRef<Domain>,
    LocalHandle,
    CapabilityRef<MemoryRegion>,
) {
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);
    let total_mem = MemoryRegion::new_root(0x0, 0x10000);
    let mem_root = Capability::new_root(0, 1, total_mem);
    root.write()
        .data
        .add_memory_capability(1, Arc::downgrade(&mem_root));
    (root, 1, mem_root)
}

#[test]
fn test_carve_memory() {
    let (root, mem_root_h, _mem_root) = setup_root();
    let child_access = Access::new(0x1000, 0x1000, Rights::RWX);
    let (child_h, child_sub, updates) =
        Capability::carve(&root, mem_root_h, child_access).unwrap();

    assert_eq!(child_sub, 1); // first child gets sub_handle = 1
    assert!(updates.is_empty()); // same rights as parent — no MMU updates (fast path)
    assert!(root.read().data.memory_capabilities.contains_key(&child_h));
}

#[test]
fn test_alias_memory() {
    let (root, mem_root_h, _mem_root) = setup_root();
    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_h, child_sub) = Capability::alias(&root, mem_root_h, child_access).unwrap();

    assert_eq!(child_sub, 1);
    assert!(root.read().data.memory_capabilities.contains_key(&child_h));
}

#[test]
fn test_revoke_memory_child() {
    let (root, mem_root_h, _mem_root) = setup_root();
    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_child_h, child_sub, _) =
        Capability::carve(&root, mem_root_h, child_access).unwrap();

    Capability::revoke(&root, mem_root_h, child_sub).unwrap();

    // Revoking the same sub_handle again must fail (child gone from parent's tree)
    let result = Capability::revoke(&root, mem_root_h, child_sub);
    assert!(matches!(result, Err(CapaError::NotFound)));
}

#[test]
fn test_alias_multiple() {
    let (root, mem_root_h, _mem_root) = setup_root();
    let access1 = Access::new(0x1000, 0x1000, Rights::RW);
    let access2 = Access::new(0x2000, 0x1000, Rights::RW);

    let (child1_h, child1_sub) = Capability::alias(&root, mem_root_h, access1).unwrap();
    let (child2_h, child2_sub) = Capability::alias(&root, mem_root_h, access2).unwrap();

    assert_ne!(child1_h, child2_h);
    assert_ne!(child1_sub, child2_sub); // sub_handles are unique among siblings
    assert!(root.read().data.memory_capabilities.contains_key(&child1_h));
    assert!(root.read().data.memory_capabilities.contains_key(&child2_h));
}

#[test]
fn test_nested_carve_memory() {
    let (root, mem_root_h, _mem_root) = setup_root();
    let c1_access = Access::new(0x2000, 0x4000, Rights::RW);
    let (c1_h, _, _) = Capability::carve(&root, mem_root_h, c1_access).unwrap();

    let c2_access = Access::new(0x3000, 0x1000, Rights::R);
    let (c2_h, _, _) = Capability::carve(&root, c1_h, c2_access).unwrap();

    assert!(root.read().data.memory_capabilities.contains_key(&c1_h));
    assert!(root.read().data.memory_capabilities.contains_key(&c2_h));
    let c2 = root.read().data.memory_capabilities[&c2_h]
        .upgrade()
        .unwrap();
    assert_eq!(c2.read().data.kind, RegionKind::Carve);
}

#[test]
fn test_create_domain() {
    let (root, _, _mem_root) = setup_root();
    let child_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE);
    let child_h = Capability::create(&root, child_policy).unwrap().0;

    assert!(root.read().data.domain_capabilities.contains_key(&child_h));
    let child = root.read().data.domain_capabilities[&child_h]
        .upgrade()
        .unwrap();
    assert_eq!(child.read().sub_handle, 1); // first domain child gets sub_handle = 1
}

#[test]
fn test_revoke_domain() {
    let (root, _, _mem_root) = setup_root();
    let child_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE);
    let child_h = Capability::create(&root, child_policy).unwrap().0;
    let child = root.read().data.domain_capabilities[&child_h]
        .upgrade()
        .unwrap();

    let updates = Capability::revoke_domain(&root, child_h).unwrap();

    assert!(!updates.is_empty()); // domain revocation always produces updates
    assert!(child.read().data.is_revoked()); // child domain is now revoked
                                             // LocalHandle must be reclaimed — the slot should be gone from the table
    assert!(!root.read().data.domain_capabilities.contains_key(&child_h));
}

// ==================== Migrated from unit/capability.rs ====================

#[test]
fn test_nested_alias_memory() {
    let (root, mem_root_h, _mem_root) = setup_root();
    // Carve a region first
    let c1_access = Access::new(0x1000, 0x2000, Rights::RW);
    let (c1_h, _, _) = Capability::carve(&root, mem_root_h, c1_access).unwrap();

    // Alias from the carved child
    let a1_access = Access::new(0x1800, 0x800, Rights::R);
    let (a1_h, _) = Capability::alias(&root, c1_h, a1_access).unwrap();

    let a1 = root.read().data.memory_capabilities[&a1_h]
        .upgrade()
        .unwrap();
    assert_eq!(a1.read().data.kind, RegionKind::Alias);
    assert_eq!(a1.read().data.status, RegionStatus::Aliased);
}

#[test]
fn test_carve_then_alias_then_carve_memory() {
    let (root, mem_root_h, _mem_root) = setup_root();

    // Step 1: carve from root mem
    let (carved_h, _, _) =
        Capability::carve(&root, mem_root_h, Access::new(0x2000, 0x2000, Rights::RW))
            .unwrap();

    // Step 2: alias from carved
    let (alias_h, _) =
        Capability::alias(&root, carved_h, Access::new(0x2000, 0x1000, Rights::R)).unwrap();

    // Step 3: carve from alias
    let (cfa_h, _, _) =
        Capability::carve(&root, alias_h, Access::new(0x2000, 0x0800, Rights::R)).unwrap();

    let cfa = root.read().data.memory_capabilities[&cfa_h]
        .upgrade()
        .unwrap();
    assert_eq!(cfa.read().data.kind, RegionKind::Carve);
    assert_eq!(cfa.read().data.status, RegionStatus::Aliased); // inherits from aliased parent
}

#[test]
fn test_revoke_complex_subtree_memory() {
    let (root, mem_root_h, _mem_root) = setup_root();

    // Branch 1: carve → alias → carve
    let (b1_h, _, _) =
        Capability::carve(&root, mem_root_h, Access::new(0x0000, 0x4000, Rights::RW))
            .unwrap();
    let (b1a_h, b1a_sub) =
        Capability::alias(&root, b1_h, Access::new(0x1000, 0x1000, Rights::R)).unwrap();
    let (_b1a1_h, _, _) =
        Capability::carve(&root, b1a_h, Access::new(0x1000, 0x0800, Rights::R)).unwrap();

    // Branch 2: plain carve (will not be revoked)
    let (b2_h, _, _) =
        Capability::carve(&root, mem_root_h, Access::new(0x5000, 0x1000, Rights::R))
            .unwrap();

    // Revoke b1a (alias node) by its sub_handle
    Capability::revoke(&root, b1_h, b1a_sub).unwrap();

    // b1's children are now empty
    let b1_ref = root.read().data.memory_capabilities[&b1_h]
        .upgrade()
        .unwrap();
    assert_eq!(b1_ref.read().children.len(), 0);

    // Branch 2 is unaffected — root still tracks it
    assert!(root.read().data.memory_capabilities.contains_key(&b2_h));
}

#[test]
fn test_revoke_memory_child_nonexistent() {
    let (root, mem_root_h, _mem_root) = setup_root();
    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_child_h, _child_sub, _) =
        Capability::carve(&root, mem_root_h, child_access).unwrap();

    // Try to revoke with a garbage sub_handle
    let result = Capability::revoke(&root, mem_root_h, 999);
    assert!(matches!(result, Err(CapaError::NotFound)));

    // Valid child is untouched
    let mem_root_ref = root.read().data.memory_capabilities[&mem_root_h]
        .upgrade()
        .unwrap();
    assert_eq!(mem_root_ref.read().children.len(), 1);
}

#[test]
fn test_send_memory_immediate() {
    let (root, mem_root_h, _mem_root) = setup_root();

    // Carve a child cap to send
    let (carved_h, _, _) =
        Capability::carve(&root, mem_root_h, Access::new(0x1000, 0x1000, Rights::RW))
            .unwrap();

    // Create an unsealed receiver domain and register it in root's domain table
    let recv_policy = DomainPolicy::new_root(4);
    let recv_domain = Domain::new(recv_policy);
    let receiver: Arc<_> = Capability::new_root(0, 2, recv_domain);
    let receiver_id = receiver.read().data.id;
    let domain_recv_h: LocalHandle = 1;
    root.write()
        .data
        .add_domain_capability(domain_recv_h, Arc::downgrade(&receiver));

    // Send — receiver is unsealed → immediate transfer
    let updates =
        Capability::send(&root, carved_h, domain_recv_h, Attributes::NONE).unwrap();

    // Root no longer holds the handle
    assert!(!root.read().data.memory_capabilities.contains_key(&carved_h));

    // Receiver now holds the cap
    assert_eq!(receiver.read().data.memory_capabilities.len(), 1);
    let recv_cap = receiver
        .read()
        .data
        .memory_capabilities
        .values()
        .next()
        .unwrap()
        .upgrade()
        .unwrap();
    assert_eq!(recv_cap.read().owned.owner, receiver_id);

    // With view-diff semantics, root loses access to the carved range (Unmap)
    // and receiver gains it (Map) — both updates are emitted correctly.
    assert_eq!(updates.len(), 2);
    let has_unmap = updates
        .updates()
        .iter()
        .any(|u| matches!(u, Update::ChangeRights { rights, .. } if *rights == Rights::NONE));
    let has_map_for_receiver = updates
        .updates()
        .iter()
        .any(|u| matches!(u, Update::ChangeRights { domain, shootdown_required: false, .. } if *domain == receiver_id));
    assert!(has_unmap, "Expected Unmap update for caller");
    assert!(has_map_for_receiver, "Expected Map update for receiver");
}

#[test]
fn test_send_memory_with_attributes() {
    let (root, mem_root_h, _mem_root) = setup_root();

    let (carved_h, _, _) =
        Capability::carve(&root, mem_root_h, Access::new(0x1000, 0x1000, Rights::RW))
            .unwrap();

    let recv_policy = DomainPolicy::new_root(4);
    let recv_domain = Domain::new(recv_policy);
    let receiver: Arc<_> = Capability::new_root(0, 2, recv_domain);
    let domain_recv_h: LocalHandle = 1;
    root.write()
        .data
        .add_domain_capability(domain_recv_h, Arc::downgrade(&receiver));

    let attrs = Attributes::from_bits(Attributes::CLEAN | Attributes::VITAL);
    Capability::send(&root, carved_h, domain_recv_h, attrs).unwrap();

    let recv_cap = receiver
        .read()
        .data
        .memory_capabilities
        .values()
        .next()
        .unwrap()
        .upgrade()
        .unwrap();
    assert!(recv_cap.read().owned.attributes.vital());
    assert!(recv_cap.read().owned.attributes.clean());
}

#[test]
fn test_revoke_domain_tree() {
    let (root, _, _mem_root) = setup_root();

    // Create child and seal it
    let child_h = Capability::create(&root, DomainPolicy::new_root(4)).unwrap().0;
    Capability::seal(&root, child_h).unwrap();
    let child_ref = root.read().data.domain_capabilities[&child_h]
        .upgrade()
        .unwrap();

    // Create grandchild under child (child must be sealed)
    let grandchild_h = Capability::create(&child_ref, DomainPolicy::new_root(4)).unwrap().0;
    let grandchild_ref = child_ref.read().data.domain_capabilities[&grandchild_h]
        .upgrade()
        .unwrap();

    // Revoke child (and transitively grandchild)
    let updates = Capability::revoke_domain(&root, child_h).unwrap();

    assert!(root.read().children.is_empty());
    assert!(child_ref.read().data.is_revoked());
    assert!(grandchild_ref.read().data.is_revoked());
    assert!(updates.len() >= 2); // at least one RevokeDomain per domain in subtree
}

// ==================== Tree Semantics (ported from unit/capability.rs) ====================

/// Carving with rights that exceed the parent cap's rights must be rejected.
/// Tests rights monotonicity through a two-level tree.
#[test]
fn test_nested_carve_excessive_rights() {
    let (root, mem_root_h, _mem_root) = setup_root();
    // mem_root has RWX; carve a child with RW only
    let rw_access = Access::new(0x2000, 0x2000, Rights::RW);
    let (rw_h, _, _) = Capability::carve(&root, mem_root_h, rw_access).unwrap();

    // Try to carve from the RW child with RWX — execute bit not in parent, must fail
    let rwx_access = Access::new(0x2000, 0x1000, Rights::RWX);
    let result = Capability::carve(&root, rw_h, rwx_access);
    assert!(result.is_err(), "carve with rights exceeding parent must fail");
}

/// After sending a carved (exclusive) cap to another domain, the sender's
/// address space must no longer include that range.
#[test]
fn test_address_space_shrinks_after_send_of_carve() {
    let (root, mem_root_h, _mem_root) = setup_root();

    // Carve [0x2000, 0x4000) exclusively from root's mem
    let carved_access = Access::new(0x2000, 0x2000, Rights::RW);
    let (carved_h, _, _) = Capability::carve(&root, mem_root_h, carved_access).unwrap();

    // Send to an unsealed receiver (immediate transfer)
    let recv_h =
        Capability::create(&root, DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE))
            .unwrap().0;
    Capability::send(&root, carved_h, recv_h, Attributes::NONE).unwrap();

    // Root lost the carved handle; its remaining cap (mem_root) has a hole where
    // the carved child was — so the carved range must no longer be accessible.
    let view = compute_address_space(&root);
    assert!(
        !view.is_accessible(0x2000),
        "carved range must not be accessible to root after send"
    );
    assert!(!view.is_accessible(0x3000));

    // Surrounding ranges remain accessible via mem_root
    assert!(view.is_accessible(0x0000));
    assert!(view.is_accessible(0x1000));
    assert!(view.is_accessible(0x4000));
    assert!(view.is_accessible(0x5000));
}

/// After sending an aliased cap to another domain, the sender's address space
/// must still include that range — aliases are shared, not exclusive.
#[test]
fn test_address_space_unchanged_after_send_of_alias() {
    let (root, mem_root_h, _mem_root) = setup_root();

    // Alias [0x2000, 0x4000) from root's mem (shared — does not remove from parent view)
    let alias_access = Access::new(0x2000, 0x2000, Rights::R);
    let (alias_h, _) = Capability::alias(&root, mem_root_h, alias_access).unwrap();

    // Send the alias to an unsealed receiver
    let recv_h =
        Capability::create(&root, DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE))
            .unwrap().0;
    Capability::send(&root, alias_h, recv_h, Attributes::NONE).unwrap();

    // Root's full range must remain accessible: aliasing is shared, so mem_root's
    // view is unchanged regardless of whether the alias handle was transferred.
    let view = compute_address_space(&root);
    assert!(view.is_accessible(0x0000));
    assert!(
        view.is_accessible(0x2000),
        "aliased range must still be accessible to root after send"
    );
    assert!(view.is_accessible(0x3000));
    assert!(view.is_accessible(0x4000));
    assert!(view.is_accessible(0x5000));
}

// ─────────────────────────────────────────────────────────────────────────────
// Depth and multi-level domain revocation tests
// ─────────────────────────────────────────────────────────────────────────────

/// The `depth` field is 0 for root capabilities and increments by 1 for each
/// level in the tree, for both memory and domain capabilities.
#[test]
fn test_depth_invariant() {
    let (root, mem_root_h, mem_root) = setup_root();

    // Memory root is at depth 0
    assert_eq!(mem_root.read().depth, 0, "mem_root should have depth 0");

    // Level-1 carve has depth 1
    let l1_access = Access::new(0x1000, 0x4000, Rights::RW);
    let (l1_h, _, _) = Capability::carve(&root, mem_root_h, l1_access).unwrap();
    let l1 = root.read().data.memory_capabilities[&l1_h]
        .upgrade()
        .unwrap();
    assert_eq!(l1.read().depth, 1, "level-1 carve should have depth 1");

    // Level-2 carve from level-1 has depth 2
    let l2_access = Access::new(0x2000, 0x1000, Rights::R);
    let (l2_h, _, _) = Capability::carve(&root, l1_h, l2_access).unwrap();
    let l2 = root.read().data.memory_capabilities[&l2_h]
        .upgrade()
        .unwrap();
    assert_eq!(l2.read().depth, 2, "level-2 carve should have depth 2");

    // Alias of the root region has depth 1
    let alias_access = Access::new(0x6000, 0x1000, Rights::R);
    let (alias_h, _) = Capability::alias(&root, mem_root_h, alias_access).unwrap();
    let alias = root.read().data.memory_capabilities[&alias_h]
        .upgrade()
        .unwrap();
    assert_eq!(alias.read().depth, 1, "alias of root memory should have depth 1");

    // Root domain has depth 0
    assert_eq!(root.read().depth, 0, "root domain should have depth 0");

    // Level-1 child domain has depth 1
    let child_h = Capability::create(&root, DomainPolicy::new_root(4)).unwrap().0;
    let child = root.read().data.domain_capabilities[&child_h]
        .upgrade()
        .unwrap();
    assert_eq!(child.read().depth, 1, "child domain should have depth 1");

    // Level-2 grandchild domain (child must be sealed first) has depth 2
    Capability::seal(&root, child_h).unwrap();
    let grandchild_h = Capability::create(&child, DomainPolicy::new_root(4)).unwrap().0;
    let grandchild = child.read().data.domain_capabilities[&grandchild_h]
        .upgrade()
        .unwrap();
    assert_eq!(grandchild.read().depth, 2, "grandchild domain should have depth 2");
}

/// Revoking a child domain propagates through a 3-level subtree.
/// All domains in the subtree receive a `RevokeDomain` update with the same
/// fallback = the direct parent of the revoked subtree root.
#[test]
fn test_multi_level_domain_revoke() {
    let (root, _, _mem_root) = setup_root();
    let root_id = root.read().data.id;

    // Build a 3-level subtree under root: child → grandchild → great_grandchild
    let child_h = Capability::create(&root, DomainPolicy::new_root(4)).unwrap().0;
    Capability::seal(&root, child_h).unwrap();
    let child_ref = root.read().data.domain_capabilities[&child_h]
        .upgrade()
        .unwrap();
    let child_id = child_ref.read().data.id;

    let grandchild_h = Capability::create(&child_ref, DomainPolicy::new_root(4)).unwrap().0;
    Capability::seal(&child_ref, grandchild_h).unwrap();
    let grandchild_ref = child_ref.read().data.domain_capabilities[&grandchild_h]
        .upgrade()
        .unwrap();
    let grandchild_id = grandchild_ref.read().data.id;

    let great_grandchild_h =
        Capability::create(&grandchild_ref, DomainPolicy::new_root(4)).unwrap().0;
    let great_grandchild_ref = grandchild_ref.read().data.domain_capabilities[&great_grandchild_h]
        .upgrade()
        .unwrap();
    let great_grandchild_id = great_grandchild_ref.read().data.id;

    // Revoke child (transitively revokes grandchild and great_grandchild)
    let updates = Capability::revoke_domain(&root, child_h).unwrap();
    let updates_list = updates.updates();

    // Exactly 3 RevokeDomain updates — one per domain in the subtree
    let revoke_updates: Vec<_> = updates_list
        .iter()
        .filter(|u| matches!(u, Update::RevokeDomain { .. }))
        .collect();
    assert_eq!(revoke_updates.len(), 3, "one RevokeDomain per domain in the 3-level subtree");

    // All 3 must carry fallback = Some(root_id)
    for u in &revoke_updates {
        if let Update::RevokeDomain { fallback, .. } = u {
            assert_eq!(
                *fallback,
                Some(root_id),
                "fallback must be the revoked subtree root's parent (root_id)"
            );
        }
    }

    // All 3 domains covered
    let has_child = revoke_updates
        .iter()
        .any(|u| matches!(u, Update::RevokeDomain { domain, .. } if *domain == child_id));
    let has_grandchild = revoke_updates
        .iter()
        .any(|u| matches!(u, Update::RevokeDomain { domain, .. } if *domain == grandchild_id));
    let has_great_grandchild = revoke_updates
        .iter()
        .any(|u| matches!(u, Update::RevokeDomain { domain, .. } if *domain == great_grandchild_id));
    assert!(has_child, "child must have a RevokeDomain update");
    assert!(has_grandchild, "grandchild must have a RevokeDomain update");
    assert!(has_great_grandchild, "great_grandchild must have a RevokeDomain update");

    // All 3 are marked revoked in their domain state
    assert!(child_ref.read().data.is_revoked(), "child must be revoked");
    assert!(grandchild_ref.read().data.is_revoked(), "grandchild must be revoked");
    assert!(
        great_grandchild_ref.read().data.is_revoked(),
        "great_grandchild must be revoked"
    );
}
