//! Tests for VITAL-triggered domain revocation cascade.
//!
//! BUG: When a VITAL (or META) memory capability is revoked, the owning domain
//! should be fully cleaned up — its memory caps revoked, parent ranges restored,
//! child domains recursively revoked.  Currently, `revoke_subtree` only emits
//! `RevokeDomain` without calling `revoke_domain_subtree`, leaving the dead
//! domain's memory caps as zombies.
//!
//! These tests document the expected correct behavior and will FAIL until the
//! bug is fixed.

use capability_engine::memory::Rights;
use capability_engine::*;
use std::sync::Arc;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Sealed root domain with a root memory region [0x0, 0x40000) at handle 1.
fn bootstrap() -> (
    CapabilityRef<Domain>,
    CapabilityRef<MemoryRegion>,
    LocalHandle,
) {
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);
    let root_region = MemoryRegion::new_root(0x0, 0x40000);
    let r0 = Capability::new_root(0, 1, root_region);
    root.write()
        .data
        .add_memory_capability(1, Arc::downgrade(&r0));
    (root, r0, 1)
}

/// Create unsealed child domain under parent, returns (handle_in_parent, CapabilityRef).
fn create_child(
    parent: &CapabilityRef<Domain>,
) -> (LocalHandle, CapabilityRef<Domain>) {
    let h = Capability::create(
        parent,
        DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL),
    )
    .unwrap()
    .0;
    let child = parent.read().data.domain_capabilities[&h]
        .upgrade()
        .unwrap();
    (h, child)
}

// ═══════════════════════════════════════════════════════════════════════════════
// § Test 1: VITAL revoke cascades domain cleanup
// ═══════════════════════════════════════════════════════════════════════════════

/// Scenario:
///   root owns r0 [0x0, 0x40000).
///   root creates app (unsealed).
///   root carves app_code [0x0, 0x10000) from r0, sends to app.
///   root carves app_meta [0x20000, 0x4000) from r0, sends to app with META.
///   root seals app.
///   root revokes app_meta from r0.
///
/// Expected: VITAL fires (META implies VITAL).  app is killed.
///   - app_code should be revoked from the CDT (cascade).
///   - root should regain [0x0, 0x10000) via ChangeRights re-map.
///   - root should regain [0x20000, 0x4000) via ChangeRights re-map (META zero'd first).
///   - app domain should be marked revoked.
///   - RevokeDomain for app should be in the updates.
#[test]
fn test_vital_revoke_cascades_memory_cleanup() {
    let (root, _r0, r0_h) = bootstrap();
    let root_id = root.read().data.id;

    // Create child domain "app"
    let (app_h, app) = create_child(&root);
    let app_id = app.read().data.id;

    // Carve app_code [0x0, 0x10000) RWX, send to app (unsealed → immediate)
    let (app_code_h, _, _) =
        Capability::carve(&root, r0_h, Access::new(0x0, 0x10000, Rights::RWX)).unwrap();
    Capability::send(&root, app_code_h, app_h, Attributes::NONE).unwrap();

    // Carve app_meta [0x20000, 0x4000) RW, send to app with META
    let (app_meta_h, app_meta_sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x20000, 0x4000, Rights::RW)).unwrap();
    Capability::send(
        &root,
        app_meta_h,
        app_h,
        Attributes::from_bits(Attributes::META),
    )
    .unwrap();

    // Seal app
    Capability::seal(&root, app_h).unwrap();

    // Revoke app_meta from r0 — VITAL fires
    let updates = Capability::revoke(&root, r0_h, app_meta_sub).unwrap();
    let list = updates.updates();

    // (1) RevokeDomain for app must be present
    let has_revoke_domain = list
        .iter()
        .any(|u| matches!(u, Update::RevokeDomain { domain, .. } if *domain == app_id));
    assert!(
        has_revoke_domain,
        "VITAL revoke must emit RevokeDomain for the owning domain"
    );

    // (2) app domain must be marked revoked
    assert!(
        app.read().data.is_revoked(),
        "app domain must be marked revoked after VITAL trigger"
    );

    // (3) Root must regain app_code's range [0x0, 0x10000) via ChangeRights re-map.
    //     This is the cascade: app_code was owned by app, its parent (in r0) is owned
    //     by root.  Cascade should call revoke_child on app_code, generating a re-map.
    let has_app_code_restore = list.iter().any(|u| {
        matches!(
            u,
            Update::ChangeRights {
                domain,
                address,
                size,
                rights,
                shootdown_required: false,
                ..
            } if *domain == root_id && *address == 0x0 && *size == 0x10000 && *rights != Rights::NONE
        )
    });
    assert!(
        has_app_code_restore,
        "VITAL cascade must restore app_code range [0x0, 0x10000) to root via re-map.\n\
         Without cascade, app_code becomes a zombie and root permanently loses this range.\n\
         Updates: {:?}",
        list
    );

    // (4) app_code should be revoked from the CDT — the cap's parent (r0) should
    //     no longer list it as a child.
    let r0_children = _r0.read().children.len();
    assert_eq!(
        r0_children, 0,
        "r0 should have no CDT children after VITAL cascade cleans up app_code"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// § Test 2: META revoke cascades (META implies VITAL + CLEAN)
// ═══════════════════════════════════════════════════════════════════════════════

/// Same as test 1 but using META explicitly.  META → CLEAN + VITAL.
/// The META region must be zeroed AND the cascade must clean up the domain.
#[test]
fn test_meta_revoke_cascades_with_zero_and_cleanup() {
    let (root, _r0, r0_h) = bootstrap();
    let root_id = root.read().data.id;

    let (app_h, app) = create_child(&root);
    let app_id = app.read().data.id;

    // Send non-META memory to app first
    let (code_h, _, _) =
        Capability::carve(&root, r0_h, Access::new(0x0, 0x8000, Rights::RWX)).unwrap();
    Capability::send(&root, code_h, app_h, Attributes::NONE).unwrap();

    // Send META memory to app
    let (meta_h, meta_sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x10000, 0x2000, Rights::RW)).unwrap();
    Capability::send(
        &root,
        meta_h,
        app_h,
        Attributes::from_bits(Attributes::META),
    )
    .unwrap();

    Capability::seal(&root, app_h).unwrap();

    // Revoke the META cap
    let updates = Capability::revoke(&root, r0_h, meta_sub).unwrap();
    let list = updates.updates();

    // META region must be zeroed (CLEAN attribute)
    let has_zero = list.iter().any(|u| {
        matches!(u, Update::ZeroMemory { address, size } if *address == 0x10000 && *size == 0x2000)
    });
    assert!(has_zero, "META revoke must zero the region");

    // RevokeDomain for app
    let has_revoke = list
        .iter()
        .any(|u| matches!(u, Update::RevokeDomain { domain, .. } if *domain == app_id));
    assert!(has_revoke, "META revoke must emit RevokeDomain");

    // Cascade: root must regain [0x0, 0x8000)
    let has_code_restore = list.iter().any(|u| {
        matches!(
            u,
            Update::ChangeRights {
                domain,
                address,
                size,
                shootdown_required: false,
                ..
            } if *domain == root_id && *address == 0x0 && *size == 0x8000
        )
    });
    assert!(
        has_code_restore,
        "META cascade must restore code range to root.\nUpdates: {:?}",
        list
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// § Test 3: Transitive VITAL cascade — revoking ancestor triggers VITAL
//           in descendant owned by another domain
// ═══════════════════════════════════════════════════════════════════════════════

/// Scenario:
///   root owns r0.
///   root creates monitor (unsealed).
///   root carves region_a, sends to monitor (no special attrs).
///   monitor seals.
///   monitor creates app (unsealed).
///   monitor carves sub_region from region_a, sends to app with VITAL.
///   monitor seals app.
///
///   root revokes region_a from r0.
///     → revoke_subtree processes region_a's subtree.
///     → sub_region (in app, VITAL) triggers RevokeDomain(app).
///     → But sub_region's parent (region_a's child) was owned by monitor,
///       and region_a itself is being revoked.
///
/// Expected:
///   - Both monitor's sub-region AND app's VITAL cap are revoked.
///   - app gets RevokeDomain.
///   - The cascade should clean up app's other memory caps (if any).
#[test]
fn test_transitive_vital_in_subtree_revoke() {
    let (root, _r0, r0_h) = bootstrap();

    // Create monitor domain
    let (monitor_h, monitor) = create_child(&root);
    let _monitor_id = monitor.read().data.id;

    // Carve region_a [0x0, 0x10000) and send to monitor
    let (region_a_h, region_a_sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x0, 0x10000, Rights::RWX)).unwrap();
    Capability::send(&root, region_a_h, monitor_h, Attributes::NONE).unwrap();

    // Seal monitor so it can create children
    Capability::seal(&root, monitor_h).unwrap();

    // Monitor creates app
    let (app_h_in_mon, app) = create_child(&monitor);
    let app_id = app.read().data.id;

    // Monitor carves sub_region [0x0, 0x4000) from region_a and sends to app with VITAL
    let mon_region_h: LocalHandle = 1; // monitor's handle for region_a
    let (sub_h, _, _) =
        Capability::carve(&monitor, mon_region_h, Access::new(0x0, 0x4000, Rights::RWX))
            .unwrap();
    Capability::send(
        &monitor,
        sub_h,
        app_h_in_mon,
        Attributes::from_bits(Attributes::VITAL | Attributes::CLEAN),
    )
    .unwrap();
    Capability::seal(&monitor, app_h_in_mon).unwrap();

    // Root revokes region_a from r0 — this processes the entire subtree
    let updates = Capability::revoke(&root, r0_h, region_a_sub).unwrap();
    let list = updates.updates();

    // app must get RevokeDomain (VITAL fired)
    let has_app_revoke = list
        .iter()
        .any(|u| matches!(u, Update::RevokeDomain { domain, .. } if *domain == app_id));
    assert!(
        has_app_revoke,
        "Transitive VITAL must emit RevokeDomain for app.\nUpdates: {:?}",
        list
    );

    // app must be marked revoked
    assert!(
        app.read().data.is_revoked(),
        "app must be marked revoked after transitive VITAL"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// § Test 4: VITAL cascade cleans up child domains of the dead domain
// ═══════════════════════════════════════════════════════════════════════════════

/// Scenario:
///   root creates app, sends app_code and app_meta (META).
///   app creates sub_app as a child domain.
///   app carves sub_code from app_code, sends to sub_app.
///
///   root revokes app_meta → VITAL fires → app dies.
///
/// Expected:
///   - app is revoked.
///   - sub_app is also revoked (recursive cascade through child domains).
///   - RevokeDomain for both app and sub_app in updates.
///   - root regains app_code range.
#[test]
fn test_vital_cascade_revokes_child_domains() {
    let (root, _r0, r0_h) = bootstrap();
    let root_id = root.read().data.id;

    let (app_h, app) = create_child(&root);
    let app_id = app.read().data.id;

    // Send app_code [0x0, 0x10000) to app
    let (code_h, _, _) =
        Capability::carve(&root, r0_h, Access::new(0x0, 0x10000, Rights::RWX)).unwrap();
    Capability::send(&root, code_h, app_h, Attributes::NONE).unwrap();

    // Send app_meta [0x20000, 0x4000) to app with META
    let (meta_h, meta_sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x20000, 0x4000, Rights::RW)).unwrap();
    Capability::send(
        &root,
        meta_h,
        app_h,
        Attributes::from_bits(Attributes::META),
    )
    .unwrap();

    Capability::seal(&root, app_h).unwrap();

    // app creates sub_app
    let (sub_app_h, sub_app) = create_child(&app);
    let sub_app_id = sub_app.read().data.id;

    // app carves sub_code [0x0, 0x4000) from app_code, sends to sub_app
    let app_code_h: LocalHandle = 1; // app's handle for app_code
    let (sub_code_h, _, _) =
        Capability::carve(&app, app_code_h, Access::new(0x0, 0x4000, Rights::RWX)).unwrap();
    Capability::send(&app, sub_code_h, sub_app_h, Attributes::NONE).unwrap();

    // Revoke app_meta → VITAL cascade
    let updates = Capability::revoke(&root, r0_h, meta_sub).unwrap();
    let list = updates.updates();

    // Both domains must be revoked
    let revoked_domains: Vec<u64> = list
        .iter()
        .filter_map(|u| {
            if let Update::RevokeDomain { domain, .. } = u {
                Some(*domain)
            } else {
                None
            }
        })
        .collect();

    assert!(
        revoked_domains.contains(&app_id),
        "app must be revoked.\nRevoked domains: {:?}\nUpdates: {:?}",
        revoked_domains,
        list
    );
    assert!(
        revoked_domains.contains(&sub_app_id),
        "sub_app must be revoked (cascade through child domains).\n\
         Revoked domains: {:?}\nUpdates: {:?}",
        revoked_domains,
        list
    );

    // root must regain app_code range
    let has_restore = list.iter().any(|u| {
        matches!(
            u,
            Update::ChangeRights {
                domain,
                address,
                size,
                shootdown_required: false,
                ..
            } if *domain == root_id && *address == 0x0 && *size == 0x10000
        )
    });
    assert!(
        has_restore,
        "root must regain app_code [0x0, 0x10000) after VITAL cascade.\nUpdates: {:?}",
        list
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// § Test 5: Explicit VITAL attribute (not META) triggers cascade
// ═══════════════════════════════════════════════════════════════════════════════

/// VITAL without META: the cap IS mapped into the receiver (unlike META which
/// is excluded from EPT).  Revoking it should still trigger cascade.
#[test]
fn test_explicit_vital_triggers_cascade() {
    let (root, _r0, r0_h) = bootstrap();
    let root_id = root.read().data.id;

    let (app_h, app) = create_child(&root);
    let app_id = app.read().data.id;

    // Send app_code [0x0, 0x8000) to app (normal)
    let (code_h, _, _) =
        Capability::carve(&root, r0_h, Access::new(0x0, 0x8000, Rights::RWX)).unwrap();
    Capability::send(&root, code_h, app_h, Attributes::NONE).unwrap();

    // Send vital_region [0x10000, 0x2000) with VITAL+CLEAN (not META)
    let (vital_h, vital_sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x10000, 0x2000, Rights::RW)).unwrap();
    Capability::send(
        &root,
        vital_h,
        app_h,
        Attributes::from_bits(Attributes::VITAL | Attributes::CLEAN),
    )
    .unwrap();

    Capability::seal(&root, app_h).unwrap();

    // Revoke the VITAL cap
    let updates = Capability::revoke(&root, r0_h, vital_sub).unwrap();
    let list = updates.updates();

    // RevokeDomain for app
    assert!(
        list.iter()
            .any(|u| matches!(u, Update::RevokeDomain { domain, .. } if *domain == app_id)),
        "Explicit VITAL revoke must emit RevokeDomain"
    );

    // Cascade: root must regain [0x0, 0x8000)
    let has_code_restore = list.iter().any(|u| {
        matches!(
            u,
            Update::ChangeRights {
                domain,
                address,
                size,
                shootdown_required: false,
                ..
            } if *domain == root_id && *address == 0x0 && *size == 0x8000
        )
    });
    assert!(
        has_code_restore,
        "VITAL cascade must restore code range to root.\nUpdates: {:?}",
        list
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// § Test 6: VITAL cascade with COMM binding cleanup
// ═══════════════════════════════════════════════════════════════════════════════

// Note: COMM cleanup is part of revoke_domain_subtree Phase 5.
// A comprehensive COMM+VITAL test would be complex; for now we focus on
// the memory cascade which is the critical path.

// ═══════════════════════════════════════════════════════════════════════════════
// § Test 7: Multiple VITAL caps in the same subtree
// ═══════════════════════════════════════════════════════════════════════════════

/// Two domains each own a VITAL cap under the same parent.
/// Revoking the parent should emit RevokeDomain for both.
/// The cascade for the first domain should not interfere with the second.
#[test]
fn test_multiple_vital_caps_same_subtree() {
    let (root, _r0, r0_h) = bootstrap();

    let (app1_h, app1) = create_child(&root);
    let app1_id = app1.read().data.id;

    let (app2_h, app2) = create_child(&root);
    let app2_id = app2.read().data.id;

    // Carve a parent region and carve two VITAL sub-regions for each domain
    let (parent_h, parent_sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x0, 0x10000, Rights::RWX)).unwrap();

    let (v1_h, _, _) =
        Capability::carve(&root, parent_h, Access::new(0x0, 0x4000, Rights::RW)).unwrap();
    Capability::send(
        &root,
        v1_h,
        app1_h,
        Attributes::from_bits(Attributes::VITAL | Attributes::CLEAN),
    )
    .unwrap();

    let (v2_h, _, _) =
        Capability::carve(&root, parent_h, Access::new(0x8000, 0x4000, Rights::RW)).unwrap();
    Capability::send(
        &root,
        v2_h,
        app2_h,
        Attributes::from_bits(Attributes::VITAL | Attributes::CLEAN),
    )
    .unwrap();

    Capability::seal(&root, app1_h).unwrap();
    Capability::seal(&root, app2_h).unwrap();

    // Revoke parent region → both VITAL caps are in the subtree
    let updates = Capability::revoke(&root, r0_h, parent_sub).unwrap();
    let list = updates.updates();

    let revoked: Vec<u64> = list
        .iter()
        .filter_map(|u| {
            if let Update::RevokeDomain { domain, .. } = u {
                Some(*domain)
            } else {
                None
            }
        })
        .collect();

    assert!(
        revoked.contains(&app1_id),
        "app1 must be revoked.\nRevoked: {:?}",
        revoked
    );
    assert!(
        revoked.contains(&app2_id),
        "app2 must be revoked.\nRevoked: {:?}",
        revoked
    );

    // Both domains should be marked revoked
    assert!(app1.read().data.is_revoked());
    assert!(app2.read().data.is_revoked());
}

// ═══════════════════════════════════════════════════════════════════════════════
// § Test 8: Explicit revoke-domain vs VITAL produce equivalent results
// ═══════════════════════════════════════════════════════════════════════════════

/// Build two identical setups.  One uses explicit `revoke_domain`, the other
/// triggers VITAL.  Both should produce the same domain state afterward.
#[test]
fn test_vital_equivalent_to_explicit_revoke_domain() {
    // Setup A: explicit revoke_domain
    let (root_a, _r0_a, r0_h_a) = bootstrap();
    let (app_h_a, app_a) = create_child(&root_a);

    let (code_h_a, _, _) =
        Capability::carve(&root_a, r0_h_a, Access::new(0x0, 0x8000, Rights::RWX)).unwrap();
    Capability::send(&root_a, code_h_a, app_h_a, Attributes::NONE).unwrap();
    Capability::seal(&root_a, app_h_a).unwrap();

    let updates_a = Capability::revoke_domain(&root_a, app_h_a).unwrap();

    // Setup B: VITAL trigger
    let (root_b, _r0_b, r0_h_b) = bootstrap();
    let (app_h_b, app_b) = create_child(&root_b);

    let (code_h_b, _, _) =
        Capability::carve(&root_b, r0_h_b, Access::new(0x0, 0x8000, Rights::RWX)).unwrap();
    Capability::send(&root_b, code_h_b, app_h_b, Attributes::NONE).unwrap();

    let (vital_h_b, vital_sub_b, _) =
        Capability::carve(&root_b, r0_h_b, Access::new(0x10000, 0x2000, Rights::RW)).unwrap();
    Capability::send(
        &root_b,
        vital_h_b,
        app_h_b,
        Attributes::from_bits(Attributes::VITAL | Attributes::CLEAN),
    )
    .unwrap();
    Capability::seal(&root_b, app_h_b).unwrap();

    let updates_b = Capability::revoke(&root_b, r0_h_b, vital_sub_b).unwrap();

    // Both domains should be revoked
    assert!(app_a.read().data.is_revoked(), "setup A: app must be revoked");
    assert!(app_b.read().data.is_revoked(), "setup B: app must be revoked");

    // Both should clean up memory: root regains [0x0, 0x8000)
    let root_a_id = root_a.read().data.id;
    let root_b_id = root_b.read().data.id;

    let has_restore_a = updates_a.updates().iter().any(|u| {
        matches!(
            u,
            Update::ChangeRights {
                domain,
                address,
                size,
                shootdown_required: false,
                ..
            } if *domain == root_a_id && *address == 0x0 && *size == 0x8000
        )
    });

    let has_restore_b = updates_b.updates().iter().any(|u| {
        matches!(
            u,
            Update::ChangeRights {
                domain,
                address,
                size,
                shootdown_required: false,
                ..
            } if *domain == root_b_id && *address == 0x0 && *size == 0x8000
        )
    });

    assert!(
        has_restore_a,
        "Setup A (explicit revoke_domain) must restore code range.\nUpdates: {:?}",
        updates_a.updates()
    );
    assert!(
        has_restore_b,
        "Setup B (VITAL trigger) must restore code range — same as explicit.\nUpdates: {:?}",
        updates_b.updates()
    );

    // Both should have their CDT cleaned up (no root cap children left in tree)
    // Note: domain's memory_capabilities BTreeMap may still hold stale handles,
    // but the CDT entries (parent→child links) should be cleaned up.
    let r0_a_children = _r0_a.read().children.len();
    let r0_b_children = _r0_b.read().children.len();
    assert_eq!(
        r0_a_children, 0,
        "Setup A: root memory should have no CDT children after domain revoke"
    );
    assert_eq!(
        r0_b_children, 0,
        "Setup B: root memory should have no CDT children after VITAL cascade"
    );
}
