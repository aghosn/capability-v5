//! Integration tests for address-translation hooks (Phase 2).
//!
//! Verifies that carve/send/accept/revoke correctly maintain each
//! domain's `AddressMap` and that emitted `ChangeRights` updates carry
//! the correct GPA (`address`) and HPA (`physical`).

use capability_engine::*;
use std::sync::Arc;

// ── helpers ──────────────────────────────────────────────────────────────────

fn bootstrap() -> (CapabilityRef<Domain>, CapabilityRef<MemoryRegion>, LocalHandle) {
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let r0 = Capability::new_root(0, 1, root_region);
    root.write()
        .data
        .add_memory_capability(1, Arc::downgrade(&r0));
    (root, r0, 1)
}

/// Seed root's AddressMap with a non-identity mapping.
fn seed_map(root: &CapabilityRef<Domain>, hpa: u64, size: u64, rights: Rights, gpa: u64) {
    let mut w = root.write();
    let _ = w.data.address_map.insert(
        hpa,
        size,
        rights,
        #[cfg(feature = "cache_coloring")]
        None,
        Some(gpa),
    );
}

/// Create a child domain under root (unsealed).
fn make_child(root: &CapabilityRef<Domain>) -> (LocalHandle, CapabilityRef<Domain>) {
    let api = MonitorAPI::from_bits(0xfff);
    let policy = DomainPolicy::new_restricted(0b1111, api);
    let h = Capability::create(root, policy).unwrap().0;
    let dom = root
        .read()
        .data
        .domain_capabilities[&h]
        .upgrade()
        .unwrap();
    (h, dom)
}

/// Return the DomainId for a domain capability.
fn dom_id(dom: &CapabilityRef<Domain>) -> DomainId {
    dom.read().data.id
}

// ── carve ────────────────────────────────────────────────────────────────────

#[test]
fn test_carve_splits_address_map() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x4000, Rights::RWX, 0x8_0000);

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_child_h, _child_sub, updates) =
        Capability::carve(&root, r0_h, access).unwrap();

    // Map should be split into 3 entries.
    let r = root.read();
    let entries = r.data.address_map.entries();
    assert_eq!(entries.len(), 3, "split should produce 3 entries");

    // Before: [GPA 0x8_0000, size 0x4000, RWX]
    // After:  [0x8_0000, 0x1000, RWX] [0x8_1000, 0x1000, RW] [0x8_2000, 0x2000, RWX]
    match entries.get(&0x8_1000).expect("middle entry") {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x1000);
            assert_eq!(m.size, 0x1000);
            assert_eq!(m.rights, Rights::RW);
        }
        _ => panic!("expected Mapped"),
    }
    drop(r);

    // The carve update for root should carry GPA, not HPA.
    for u in updates.updates() {
        if let Update::ChangeRights {
            domain, address, physical, ..
        } = u
        {
            if *domain == 0 {
                assert!(
                    *address >= 0x8_0000,
                    "address should be GPA (>= 0x8_0000), got {:#x}",
                    address
                );
                assert!(
                    *physical < 0x10000,
                    "physical should be HPA (< 0x10000), got {:#x}",
                    physical
                );
            }
        }
    }
}

#[test]
fn test_carve_same_rights_no_split() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x4000, Rights::RWX, 0x8_0000);

    let access = Access::new(0x1000, 0x1000, Rights::RWX);
    let (_h, _sub, updates) = Capability::carve(&root, r0_h, access).unwrap();

    // With refcounting, the carved child adds a contribution to the overlapping
    // sub-range, splitting into 3 segments with different refcounts.
    // But effective rights are identical everywhere → no view_diff updates.
    let r = root.read();
    assert_eq!(
        r.data.address_map.entries().len(),
        3,
        "refcounted: 3 segments (different contributor counts)"
    );
    // All segments should have the same effective rights (RWX).
    for (_, entry) in r.data.address_map.entries() {
        match entry {
            MapEntry::Mapped(m) => assert_eq!(m.rights, Rights::RWX),
            _ => panic!("expected Mapped"),
        }
    }
    drop(r);
    assert!(updates.is_empty(), "same rights → no view_diff updates");
}

// ── send (unsealed) ──────────────────────────────────────────────────────────

#[test]
fn test_send_blocks_sender_and_inserts_receiver() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x4000, Rights::RWX, 0x8_0000);

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_h, _sub, _) = Capability::carve(&root, r0_h, access).unwrap();

    let (dom1_h, dom1) = make_child(&root);
    let _updates =
        Capability::send(&root, child_h, dom1_h, Attributes::NONE).unwrap();

    // Sender: carved entry should be Blocked.
    let r = root.read();
    match r.data.address_map.entries().get(&0x8_1000).expect("blocked") {
        MapEntry::Blocked { hpa_start, size } => {
            assert_eq!(*hpa_start, 0x1000);
            assert_eq!(*size, 0x1000);
        }
        _ => panic!("expected Blocked after send"),
    }
    drop(r);

    // Receiver: should have exactly one Mapped entry (identity GPA).
    let d = dom1.read();
    let recv_entries = d.data.address_map.entries();
    assert_eq!(recv_entries.len(), 1);
    match recv_entries.values().next().unwrap() {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x1000);
            assert_eq!(m.size, 0x1000);
            assert_eq!(m.rights, Rights::RW);
        }
        _ => panic!("expected Mapped in receiver"),
    }
}

#[test]
fn test_alias_send_does_not_block() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x4000, Rights::RWX, 0x8_0000);

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_h, _sub, _) = Capability::carve(&root, r0_h, access).unwrap();

    let alias_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (alias_h, _) = Capability::alias(&root, child_h, alias_access).unwrap();

    let (dom1_h, _dom1) = make_child(&root);
    let _updates =
        Capability::send(&root, alias_h, dom1_h, Attributes::NONE).unwrap();

    // Sender's carved entry should still be Mapped (alias ≠ block).
    let r = root.read();
    match r.data.address_map.entries().get(&0x8_1000).expect("mapped") {
        MapEntry::Mapped(m) => assert_eq!(m.rights, Rights::RW),
        MapEntry::Blocked { .. } => panic!("alias send must NOT block sender"),
    }
}

// ── revoke ───────────────────────────────────────────────────────────────────

#[test]
fn test_revoke_unblocks_sender_and_removes_receiver() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x4000, Rights::RWX, 0x8_0000);

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_h, child_sub, _) = Capability::carve(&root, r0_h, access).unwrap();

    let (dom1_h, dom1) = make_child(&root);
    let _updates =
        Capability::send(&root, child_h, dom1_h, Attributes::NONE).unwrap();

    let revoke_updates = Capability::revoke(&root, r0_h, child_sub).unwrap();

    // Sender: unblocked → back to Mapped with parent rights (RWX).
    // The entry may have been coalesced with neighbours, so use translate.
    let r = root.read();
    let (gpa, _, rights) = r
        .data
        .address_map
        .translate(0x1000, 0x1000)
        .expect("HPA 0x1000 should be translatable after unblock");
    assert_eq!(rights, Rights::RWX, "should be restored to parent rights");
    assert_eq!(gpa, 0x8_1000, "GPA should match original mapping");
    drop(r);

    // Receiver: entries cleaned up.
    let d = dom1.read();
    assert!(
        d.data.address_map.entries().is_empty(),
        "receiver map should be empty after revoke"
    );
    drop(d);

    // Revoke updates for root should carry GPA.
    for u in revoke_updates.updates() {
        if let Update::ChangeRights {
            domain, address, physical, ..
        } = u
        {
            if *domain == 0 {
                assert!(
                    *address >= 0x8_0000,
                    "revoke: address should be GPA, got {:#x}",
                    address
                );
                assert!(
                    *physical < 0x10000,
                    "revoke: physical should be HPA, got {:#x}",
                    physical
                );
            }
        }
    }
}

#[test]
fn test_revoke_never_sent_carve_no_deadlock() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x4000, Rights::RWX, 0x8_0000);

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_child_h, child_sub, _) = Capability::carve(&root, r0_h, access).unwrap();

    // Revoke without send — must not deadlock.
    let updates = Capability::revoke(&root, r0_h, child_sub).unwrap();

    // No cross-domain transfer → no ChangeRights expected.
    let change_rights_count = updates
        .updates()
        .iter()
        .filter(|u| matches!(u, Update::ChangeRights { .. }))
        .count();
    assert_eq!(change_rights_count, 0, "never-sent carve → no ChangeRights");

    // Map should still have entries (split happened but revoke of
    // same-domain carve doesn't undo the split).
    let r = root.read();
    assert!(
        !r.data.address_map.entries().is_empty(),
        "map should still have entries"
    );
}

#[test]
fn test_revoke_with_alias_subtree() {
    // Covers the deadlock fix: alias owned by root under a cap
    // that was sent to dom1 → revoke_subtree encounters root's
    // domain while root.write() is held.
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x4000, Rights::RWX, 0x8_0000);

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_h, child_sub, _) =
        Capability::carve(&root, r0_h, access).unwrap();

    // Alias r1 (stays owned by root even after r1 is sent).
    let alias_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_alias_h, _) = Capability::alias(&root, child_h, alias_access).unwrap();

    // Create dom1 and send r1 (the carve, not the alias) to it.
    let (dom1_h, dom1) = make_child(&root);
    let dom1_id = dom_id(&dom1);
    let _updates =
        Capability::send(&root, child_h, dom1_h, Attributes::NONE).unwrap();

    // Revoke r1 (and its alias subtree) — must NOT deadlock.
    let revoke_updates = Capability::revoke(&root, r0_h, child_sub).unwrap();

    // Should have ChangeRights for both root (restore) and dom1 (unmap).
    let has_root_restore = revoke_updates.updates().iter().any(|u| {
        matches!(
            u,
            Update::ChangeRights { domain, rights, shootdown_required: false, .. }
                if *domain == 0 && *rights != Rights::NONE
        )
    });
    let has_dom1_unmap = revoke_updates.updates().iter().any(|u| {
        matches!(
            u,
            Update::ChangeRights { domain, rights, .. }
                if *domain == dom1_id && *rights == Rights::NONE
        )
    });
    assert!(has_root_restore, "should restore root's access");
    assert!(has_dom1_unmap, "should unmap from dom1");

    // Sender unblocked (may be coalesced, so use translate).
    let r = root.read();
    let result = r.data.address_map.translate(0x1000, 0x1000);
    assert!(result.is_ok(), "sender should be unblocked");
    let (_, _, rights) = result.unwrap();
    assert_eq!(rights, Rights::RWX, "restored to parent rights");
}

// ── accept (sealed receiver) ─────────────────────────────────────────────────

#[test]
fn test_accept_blocks_and_inserts() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x4000, Rights::RWX, 0x8_0000);

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_h, child_sub, _) = Capability::carve(&root, r0_h, access).unwrap();

    // Need RECEIVE_AFTER_SEAL for sealed-domain accept path.
    let api = MonitorAPI::from_bits(0xfff | MonitorAPI::RECEIVE_AFTER_SEAL);
    let policy = DomainPolicy::new_restricted(0b1111, api);
    let dom1_h = Capability::create(&root, policy).unwrap().0;
    let dom1 = root
        .read()
        .data
        .domain_capabilities[&dom1_h]
        .upgrade()
        .unwrap();
    Capability::seal(&root, dom1_h).unwrap();

    // Send to sealed → pending.
    let _send_updates =
        Capability::send(&root, child_h, dom1_h, Attributes::NONE).unwrap();

    // Accept materialises the transfer (pending_id = 0, first pending).
    let (_accepted_h, _accept_updates) = Capability::accept(&dom1, 0).unwrap();

    // Sender blocked.
    let r = root.read();
    assert!(
        matches!(
            r.data.address_map.entries().get(&0x8_1000),
            Some(MapEntry::Blocked { .. })
        ),
        "accept should block sender"
    );
    drop(r);

    // Receiver has the entry.
    let d = dom1.read();
    assert_eq!(d.data.address_map.entries().len(), 1);
    drop(d);

    // Revoke restores sender (may coalesce, so use translate).
    let _revoke = Capability::revoke(&root, r0_h, child_sub).unwrap();
    let r = root.read();
    let result = r.data.address_map.translate(0x1000, 0x1000);
    assert!(result.is_ok(), "revoke after accept should unblock");
}

// ── GPA fidelity across full lifecycle ───────────────────────────────────────

#[test]
fn test_full_lifecycle_gpa_fidelity() {
    let (root, _r0, r0_h) = bootstrap();
    // Non-identity GPA: HPA [0x2000..0x6000) at GPA 0xC_0000.
    seed_map(&root, 0x2000, 0x4000, Rights::RWX, 0xC_0000);

    // Carve [0x3000..0x4000) with RW.
    let access = Access::new(0x3000, 0x1000, Rights::RW);
    let (child_h, child_sub, carve_updates) =
        Capability::carve(&root, r0_h, access).unwrap();

    // Verify carve update GPA.
    for u in carve_updates.updates() {
        if let Update::ChangeRights {
            domain: 0, address, ..
        } = u
        {
            assert_eq!(
                *address, 0xC_1000,
                "carve: GPA for HPA 0x3000 should be 0xC_1000"
            );
        }
    }

    // Send to dom1.
    let (dom1_h, dom1) = make_child(&root);
    let dom1_id = dom_id(&dom1);
    let send_updates =
        Capability::send(&root, child_h, dom1_h, Attributes::NONE).unwrap();

    // Send updates for dom1 should use dom1's GPA (identity by default).
    for u in send_updates.updates() {
        if let Update::ChangeRights {
            domain, address, physical, ..
        } = u
        {
            if *domain == dom1_id {
                assert_eq!(*address, 0x3000, "receiver identity GPA");
                assert_eq!(*physical, 0x3000, "receiver HPA");
            }
        }
    }

    // Revoke.
    let revoke_updates = Capability::revoke(&root, r0_h, child_sub).unwrap();

    // Root's restore should use GPA 0xC_1000.
    for u in revoke_updates.updates() {
        if let Update::ChangeRights {
            domain: 0,
            address,
            physical,
            rights,
            ..
        } = u
        {
            if *rights != Rights::NONE {
                assert_eq!(
                    *address, 0xC_1000,
                    "revoke restore: GPA should be 0xC_1000"
                );
                assert_eq!(*physical, 0x3000, "revoke restore: HPA should be 0x3000");
            }
        }
    }

    // Dom1's unmap should use dom1's GPA (identity = 0x3000).
    for u in revoke_updates.updates() {
        if let Update::ChangeRights {
            domain,
            address,
            physical,
            rights,
            ..
        } = u
        {
            if *domain == dom1_id && *rights == Rights::NONE {
                assert_eq!(
                    *address, 0x3000,
                    "dom1 unmap: GPA should be identity 0x3000"
                );
                assert_eq!(*physical, 0x3000, "dom1 unmap: HPA should be 0x3000");
            }
        }
    }
}

// ── send_at with explicit GPA hint ──────────────────────────────────────────

#[test]
fn test_send_at_receiver_gets_requested_gpa() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x4000, Rights::RWX, 0x8_0000);

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_h, _sub, _) = Capability::carve(&root, r0_h, access).unwrap();

    let (dom1_h, dom1) = make_child(&root);
    let dom1_id = dom_id(&dom1);

    // Send with explicit GPA hint: receiver should see region at 0xF_0000.
    let updates = Capability::send_at(
        &root,
        child_h,
        dom1_h,
        Attributes::NONE,
        Some(0xF_0000),
    )
    .unwrap();

    // Receiver's AddressMap should have the entry at GPA 0xF_0000.
    let d = dom1.read();
    let recv_entries = d.data.address_map.entries();
    assert_eq!(recv_entries.len(), 1);
    let (&gpa, entry) = recv_entries.iter().next().unwrap();
    assert_eq!(gpa, 0xF_0000, "receiver GPA should match hint");
    match entry {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x1000, "HPA unchanged");
            assert_eq!(m.gpa_start, 0xF_0000, "GPA from hint");
            assert_eq!(m.size, 0x1000);
            assert_eq!(m.rights, Rights::RW);
        }
        _ => panic!("expected Mapped"),
    }
    drop(d);

    // ChangeRights for receiver should carry the requested GPA.
    for u in updates.updates() {
        if let Update::ChangeRights {
            domain, address, physical, ..
        } = u
        {
            if *domain == dom1_id {
                assert_eq!(
                    *address, 0xF_0000,
                    "receiver update should use requested GPA"
                );
                assert_eq!(*physical, 0x1000, "physical should be HPA");
            }
        }
    }
}

#[test]
fn test_send_at_none_gives_identity() {
    let (root, _r0, r0_h) = bootstrap();

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_h, _sub, _) = Capability::carve(&root, r0_h, access).unwrap();

    let (dom1_h, dom1) = make_child(&root);

    // send_at with None → same as send() → identity GPA.
    let _updates = Capability::send_at(
        &root,
        child_h,
        dom1_h,
        Attributes::NONE,
        None,
    )
    .unwrap();

    let d = dom1.read();
    let (&gpa, _) = d.data.address_map.entries().iter().next().unwrap();
    assert_eq!(gpa, 0x1000, "None hint → identity GPA = HPA");
}

#[test]
fn test_accept_preserves_gpa_hint() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x4000, Rights::RWX, 0x8_0000);

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_h, _sub, _) = Capability::carve(&root, r0_h, access).unwrap();

    // Sealed receiver with RECEIVE_AFTER_SEAL.
    let api = MonitorAPI::from_bits(0xfff | MonitorAPI::RECEIVE_AFTER_SEAL);
    let policy = DomainPolicy::new_restricted(0b1111, api);
    let dom1_h = Capability::create(&root, policy).unwrap().0;
    let dom1 = root
        .read()
        .data
        .domain_capabilities[&dom1_h]
        .upgrade()
        .unwrap();
    let dom1_id = dom_id(&dom1);
    Capability::seal(&root, dom1_h).unwrap();

    // Send with GPA hint to sealed domain → pending.
    let _send = Capability::send_at(
        &root,
        child_h,
        dom1_h,
        Attributes::NONE,
        Some(0xD_0000),
    )
    .unwrap();

    // Accept → GPA hint should be preserved from pending entry.
    let (_h, accept_updates) = Capability::accept(&dom1, 0).unwrap();

    let d = dom1.read();
    let (&gpa, _) = d.data.address_map.entries().iter().next().unwrap();
    assert_eq!(gpa, 0xD_0000, "accept should preserve GPA hint from send");
    drop(d);

    // Accept updates for receiver should carry the GPA.
    for u in accept_updates.updates() {
        if let Update::ChangeRights {
            domain, address, ..
        } = u
        {
            if *domain == dom1_id {
                assert_eq!(
                    *address, 0xD_0000,
                    "accept update should use GPA hint"
                );
            }
        }
    }
}

#[test]
fn test_accept_at_overrides_sender_hint() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x4000, Rights::RWX, 0x8_0000);

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_h, _sub, _) = Capability::carve(&root, r0_h, access).unwrap();

    let api = MonitorAPI::from_bits(0xfff | MonitorAPI::RECEIVE_AFTER_SEAL);
    let policy = DomainPolicy::new_restricted(0b1111, api);
    let dom1_h = Capability::create(&root, policy).unwrap().0;
    let dom1 = root
        .read()
        .data
        .domain_capabilities[&dom1_h]
        .upgrade()
        .unwrap();
    let dom1_id = dom_id(&dom1);
    Capability::seal(&root, dom1_h).unwrap();

    // Sender requests GPA 0xD_0000.
    let _send = Capability::send_at(
        &root,
        child_h,
        dom1_h,
        Attributes::NONE,
        Some(0xD_0000),
    )
    .unwrap();

    // Receiver overrides to 0xE_0000.
    let (_h, accept_updates) =
        Capability::accept_at(&dom1, 0, Some(0xE_0000)).unwrap();

    let d = dom1.read();
    let (&gpa, _) = d.data.address_map.entries().iter().next().unwrap();
    assert_eq!(gpa, 0xE_0000, "accept_at should override sender's hint");
    drop(d);

    for u in accept_updates.updates() {
        if let Update::ChangeRights {
            domain, address, ..
        } = u
        {
            if *domain == dom1_id {
                assert_eq!(
                    *address, 0xE_0000,
                    "accept_at update should use receiver's GPA"
                );
            }
        }
    }
}

#[test]
fn test_accept_at_none_falls_back_to_sender() {
    let (root, _r0, r0_h) = bootstrap();

    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_h, _sub, _) = Capability::carve(&root, r0_h, access).unwrap();

    let api = MonitorAPI::from_bits(0xfff | MonitorAPI::RECEIVE_AFTER_SEAL);
    let policy = DomainPolicy::new_restricted(0b1111, api);
    let dom1_h = Capability::create(&root, policy).unwrap().0;
    let dom1 = root
        .read()
        .data
        .domain_capabilities[&dom1_h]
        .upgrade()
        .unwrap();
    Capability::seal(&root, dom1_h).unwrap();

    // Sender requests GPA 0xD_0000.
    let _send = Capability::send_at(
        &root,
        child_h,
        dom1_h,
        Attributes::NONE,
        Some(0xD_0000),
    )
    .unwrap();

    // accept_at with None → falls back to sender's hint.
    let (_h, _) = Capability::accept_at(&dom1, 0, None).unwrap();

    let d = dom1.read();
    let (&gpa, _) = d.data.address_map.entries().iter().next().unwrap();
    assert_eq!(gpa, 0xD_0000, "accept_at(None) should use sender's hint");
}

// ── adversarial: conflicting GPA hints ──────────────────────────────────────

/// Send two regions to the same receiver at the same GPA.
/// The second insert should fail — the receiver's AddressMap must not
/// silently overwrite the first mapping.
#[test]
fn test_send_at_conflicting_gpa() {
    let (root, _r0, r0_h) = bootstrap();

    // Carve two disjoint regions.
    let (c1_h, _s1, _) =
        Capability::carve(&root, r0_h, Access::new(0x1000, 0x1000, Rights::RW)).unwrap();
    let (c2_h, _s2, _) =
        Capability::carve(&root, r0_h, Access::new(0x2000, 0x1000, Rights::RW)).unwrap();

    let (dom1_h, dom1) = make_child(&root);

    // First send at GPA 0xA_0000 — should succeed.
    Capability::send_at(&root, c1_h, dom1_h, Attributes::NONE, Some(0xA_0000)).unwrap();

    let d = dom1.read();
    assert_eq!(d.data.address_map.entries().len(), 1);
    drop(d);

    // Second send at the SAME GPA — must fail (overlap).
    let result = Capability::send_at(&root, c2_h, dom1_h, Attributes::NONE, Some(0xA_0000));
    assert!(matches!(result, Err(CapaError::RegionOverlap)));

    // Receiver should still have only the first mapping at 0xA_0000.
    let d = dom1.read();
    assert_eq!(
        d.data.address_map.entries().len(),
        1,
        "conflicting GPA insert should be rejected — only first mapping kept"
    );
    match d.data.address_map.entries().get(&0xA_0000).unwrap() {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x1000, "first mapping should be preserved");
        }
        _ => panic!("expected Mapped"),
    }

    // The cap should still belong to the caller (rolled back).
    let r = root.read();
    assert!(
        r.data.get_memory_capability(c2_h).is_some(),
        "cap must be rolled back to caller"
    );
}

/// Accept at a GPA that is already occupied in the receiver's map.
#[test]
fn test_accept_at_conflicting_gpa() {
    let (root, _r0, r0_h) = bootstrap();

    let (c1_h, _s1, _) =
        Capability::carve(&root, r0_h, Access::new(0x1000, 0x1000, Rights::RW)).unwrap();
    let (c2_h, _s2, _) =
        Capability::carve(&root, r0_h, Access::new(0x2000, 0x1000, Rights::RW)).unwrap();

    let api = MonitorAPI::from_bits(0xfff | MonitorAPI::RECEIVE_AFTER_SEAL);
    let policy = DomainPolicy::new_restricted(0b1111, api);
    let dom1_h = Capability::create(&root, policy).unwrap().0;
    let dom1 = root
        .read()
        .data
        .domain_capabilities[&dom1_h]
        .upgrade()
        .unwrap();
    Capability::seal(&root, dom1_h).unwrap();

    // Send first cap (no GPA hint — gets identity 0x1000).
    Capability::send(&root, c1_h, dom1_h, Attributes::NONE).unwrap();
    let (_h1, _) = Capability::accept(&dom1, 0).unwrap();

    // Send second cap with GPA hint = 0x1000 (collides with first).
    Capability::send_at(&root, c2_h, dom1_h, Attributes::NONE, Some(0x1000)).unwrap();
    let result = Capability::accept_at(&dom1, 1, Some(0x1000));
    assert!(matches!(result, Err(CapaError::RegionOverlap)));

    // Only the first mapping should exist at GPA 0x1000.
    let d = dom1.read();
    assert_eq!(
        d.data.address_map.entries().len(),
        1,
        "overlapping accept should be rejected"
    );
    match d.data.address_map.entries().get(&0x1000).unwrap() {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x1000, "first mapping preserved");
        }
        _ => panic!("expected Mapped"),
    }
}

/// Verify that a Blocked GPA entry (from a sent carve) prevents
/// insert at the same address.  Scenario: root carves, sends to
/// dom1 (blocking root's entry), then receives something back at
/// the blocked GPA — the insert must fail.
#[test]
fn test_blocked_gpa_prevents_insert() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x4000, Rights::RWX, 0x8_0000);

    // Carve + send → root's GPA 0x8_1000 becomes Blocked.
    let (c1_h, _sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x1000, 0x1000, Rights::RW)).unwrap();
    let (dom1_h, _dom1) = make_child(&root);
    Capability::send(&root, c1_h, dom1_h, Attributes::NONE).unwrap();

    // Confirm it's blocked.
    let r = root.read();
    assert!(
        matches!(
            r.data.address_map.entries().get(&0x8_1000),
            Some(MapEntry::Blocked { .. })
        ),
        "entry should be Blocked after send"
    );
    drop(r);

    // Try to insert directly into root's map at the blocked GPA.
    let mut w = root.write();
    let result = w.data.address_map.insert(
        0x5000,
        0x1000,
        Rights::RW,
        #[cfg(feature = "cache_coloring")]
        None,
        Some(0x8_1000), // collides with Blocked entry
    );
    assert!(result.is_err(), "insert at Blocked GPA should fail");
}

/// Verify view-aware insert: when a cap with carved children is sent,
/// the receiver sees Mapped entries for visible ranges and Blocked for
/// the carved-away gap.
///
/// Scenario:
///   1. Root carves c1 = [0x1000, 0x3000)  (size 0x2000)
///   2. Carve c2 = [0x1800, 0x2000)  from c1 (size 0x800)
///   3. Send c1 to dom1 at GPA 0xA_0000
///   4. dom1's AddressMap should have:
///        Mapped at 0xA_0000 (HPA 0x1000, size 0x800)  — before c2
///        Blocked at 0xA_0800 (HPA 0x1800, size 0x800) — c2's gap
///        Mapped at 0xA_1000 (HPA 0x2000, size 0x1000) — after c2
///   5. Attempting to fill the gap with another cap should fail.
#[test]
fn test_view_aware_insert_shows_blocked_gap() {
    let (root, _r0, r0_h) = bootstrap();

    // 1. Carve c1 = [0x1000, 0x3000)
    let (c1_h, _c1, _) =
        Capability::carve(&root, r0_h, Access::new(0x1000, 0x2000, Rights::RW)).unwrap();

    // 2. Carve c2 = [0x1800, 0x2000) from c1
    let (_c2_h, _c2, _) =
        Capability::carve(&root, c1_h, Access::new(0x1800, 0x800, Rights::RW)).unwrap();

    // 3. Send c1 to dom1 at GPA 0xA_0000 (unsealed).
    let (dom1_h, dom1) = make_child(&root);
    Capability::send_at(&root, c1_h, dom1_h, Attributes::NONE, Some(0xA_0000)).unwrap();

    // 4. Verify dom1's AddressMap:
    let d = dom1.read();
    let entries = d.data.address_map.entries();
    // Should have 3 entries: Mapped, Blocked, Mapped
    assert_eq!(entries.len(), 3, "expected 3 entries (mapped, blocked, mapped)");

    // Before c2: Mapped at GPA 0xA_0000, HPA 0x1000, size 0x800
    match entries.get(&0xA_0000).unwrap() {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x1000);
            assert_eq!(m.size, 0x800);
        }
        other => panic!("expected Mapped at 0xA_0000, got {:?}", other),
    }

    // Gap (c2): Blocked at GPA 0xA_0800, HPA 0x1800, size 0x800
    match entries.get(&0xA_0800).unwrap() {
        MapEntry::Blocked { hpa_start, size } => {
            assert_eq!(*hpa_start, 0x1800);
            assert_eq!(*size, 0x800);
        }
        other => panic!("expected Blocked at 0xA_0800, got {:?}", other),
    }

    // After c2: Mapped at GPA 0xA_1000, HPA 0x2000, size 0x1000
    match entries.get(&0xA_1000).unwrap() {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x2000);
            assert_eq!(m.size, 0x1000);
        }
        other => panic!("expected Mapped at 0xA_1000, got {:?}", other),
    }
    drop(d);

    // 5. Attempt to fill the gap with another capability — must fail.
    let (c3_h, _c3, _) =
        Capability::carve(&root, r0_h, Access::new(0x5000, 0x800, Rights::RW)).unwrap();
    let result = Capability::send_at(&root, c3_h, dom1_h, Attributes::NONE, Some(0xA_0800));
    assert!(
        matches!(result, Err(CapaError::RegionOverlap)),
        "insert at blocked gap must fail"
    );
}

// ── MAP_SELF tests ──────────────────────────────────────────────────────────
//
// MAP_SELF operates on a domain's OWN address map.  All interesting scenarios
// involve multiple capabilities within the SAME domain's map, NOT cross-domain
// parent/child relationships.

/// Helper: create a child domain with all permissions (incl. MAP_SELF).
fn make_child_with_map_self(root: &CapabilityRef<Domain>) -> (LocalHandle, CapabilityRef<Domain>) {
    let api = MonitorAPI::ALL;
    let policy = DomainPolicy::new_restricted(0b1111, api);
    let h = Capability::create(root, policy).unwrap().0;
    let dom = root
        .read()
        .data
        .domain_capabilities[&h]
        .upgrade()
        .unwrap();
    (h, dom)
}

/// Get the first memory handle in a domain.
fn first_mem_handle(dom: &CapabilityRef<Domain>) -> LocalHandle {
    let r = dom.read();
    *r.data.memory_capabilities.keys().next().expect("no memory caps")
}

/// Find the memory handle whose mapped_gpas entry equals `gpa`.
fn handle_at_gpa(dom: &CapabilityRef<Domain>, gpa: u64) -> LocalHandle {
    let r = dom.read();
    *r.data
        .mapped_gpas
        .iter()
        .find(|(_, &g)| g == gpa)
        .expect("no handle at that GPA")
        .0
}

// ── basic ───────────────────────────────────────────────────────────────────

/// Basic: carve + send to child + seal + MAP_SELF to new GPA.
#[test]
fn test_map_self_basic_remap() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    let (ch, _sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x1000, 0x1000, Rights::RW)).unwrap();
    let (dom_h, dom) = make_child_with_map_self(&root);
    Capability::send(&root, ch, dom_h, Attributes::NONE).unwrap();
    Capability::seal(&root, dom_h).unwrap();

    let cap_h = first_mem_handle(&dom);
    {
        let d = dom.read();
        assert!(d.data.address_map.entries().contains_key(&0x1000));
    }

    let updates = Capability::map_self(&dom, cap_h, 0x5_0000).unwrap();

    let d = dom.read();
    assert!(!d.data.address_map.entries().contains_key(&0x1000));
    match d.data.address_map.entries().get(&0x5_0000).expect("new GPA") {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x1000);
            assert_eq!(m.size, 0x1000);
            assert_eq!(m.rights, Rights::RW);
        }
        _ => panic!("expected Mapped"),
    }
    drop(d);
    assert!(!updates.is_empty(), "MAP_SELF should produce updates");
}

/// MAP_SELF from a non-identity initial GPA (send_at with hint).
#[test]
fn test_map_self_from_nonidentity_gpa() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    let (ch, _sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x2000, 0x1000, Rights::RW)).unwrap();
    let (dom_h, dom) = make_child_with_map_self(&root);
    Capability::send_at(&root, ch, dom_h, Attributes::NONE, Some(0xA_0000)).unwrap();
    Capability::seal(&root, dom_h).unwrap();

    let cap_h = first_mem_handle(&dom);
    let _updates = Capability::map_self(&dom, cap_h, 0xB_0000).unwrap();

    let d = dom.read();
    assert!(!d.data.address_map.entries().contains_key(&0xA_0000));
    match d.data.address_map.entries().get(&0xB_0000).expect("new") {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x2000);
            assert_eq!(m.size, 0x1000);
        }
        _ => panic!("expected Mapped"),
    }
}

/// Re-MAP_SELF: remap the same cap twice in succession.
#[test]
fn test_map_self_twice() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    let (ch, _sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x1000, 0x1000, Rights::RW)).unwrap();
    let (dom_h, dom) = make_child_with_map_self(&root);
    Capability::send_at(&root, ch, dom_h, Attributes::NONE, Some(0x10_0000)).unwrap();
    Capability::seal(&root, dom_h).unwrap();

    let cap_h = first_mem_handle(&dom);

    Capability::map_self(&dom, cap_h, 0x20_0000).unwrap();
    {
        let d = dom.read();
        assert!(d.data.address_map.entries().contains_key(&0x20_0000));
        assert!(!d.data.address_map.entries().contains_key(&0x10_0000));
    }

    Capability::map_self(&dom, cap_h, 0x30_0000).unwrap();
    let d = dom.read();
    assert!(d.data.address_map.entries().contains_key(&0x30_0000));
    assert!(!d.data.address_map.entries().contains_key(&0x20_0000));
}

/// MAP_SELF a cap with a carved-away child: blocked gap moves with it.
#[test]
fn test_map_self_with_carved_hole() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    // Carve c1 = [0x1000..0x5000).
    let (c1_h, _c1, _) =
        Capability::carve(&root, r0_h, Access::new(0x1000, 0x4000, Rights::RW)).unwrap();
    // Carve c2 = [0x2000..0x3000) from c1 (hole in c1).
    let (_c2_h, _c2, _) =
        Capability::carve(&root, c1_h, Access::new(0x2000, 0x1000, Rights::RW)).unwrap();

    // Send c1 to child at GPA 0xA_0000.
    let (dom_h, dom) = make_child_with_map_self(&root);
    Capability::send_at(&root, c1_h, dom_h, Attributes::NONE, Some(0xA_0000)).unwrap();
    Capability::seal(&root, dom_h).unwrap();

    let c1_child_h = first_mem_handle(&dom);

    // Before: mapped + blocked + mapped.
    {
        let d = dom.read();
        assert!(matches!(d.data.address_map.entries().get(&0xA_1000),
            Some(MapEntry::Blocked { .. })));
    }

    // MAP_SELF c1 to GPA 0xB_0000.
    let _updates = Capability::map_self(&dom, c1_child_h, 0xB_0000).unwrap();

    let d = dom.read();
    let e = d.data.address_map.entries();

    // Old entries gone.
    assert!(!e.contains_key(&0xA_0000));

    // Mapped [0xB_0000, 0x1000) = HPA 0x1000.
    match e.get(&0xB_0000).expect("first mapped") {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x1000);
            assert_eq!(m.size, 0x1000);
        }
        _ => panic!("expected Mapped"),
    }
    // Blocked [0xB_1000, 0x1000) = HPA 0x2000.
    match e.get(&0xB_1000).expect("blocked") {
        MapEntry::Blocked { hpa_start, size } => {
            assert_eq!(*hpa_start, 0x2000);
            assert_eq!(*size, 0x1000);
        }
        _ => panic!("expected Blocked"),
    }
    // Mapped [0xB_2000, 0x2000) = HPA 0x3000.
    match e.get(&0xB_2000).expect("second mapped") {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x3000);
            assert_eq!(m.size, 0x2000);
        }
        _ => panic!("expected Mapped"),
    }
}

// ── alias within same domain + MAP_SELF ─────────────────────────────────────

/// The real scenario: child receives R1, aliases a sub-range, MAP_SELFs the
/// alias elsewhere.  R1's contribution to the overlapping region survives.
#[test]
fn test_map_self_alias_within_domain() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    // Send a big region to child at GPA 0x0.
    let (c1_h, _sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x0, 0x5000, Rights::RW)).unwrap();
    let (dom_h, dom) = make_child_with_map_self(&root);
    Capability::send(&root, c1_h, dom_h, Attributes::NONE).unwrap();
    Capability::seal(&root, dom_h).unwrap();

    let r1_h = first_mem_handle(&dom);

    // Child aliases [0x0..0x1000) RW from its own R1.
    let (alias_h, _alias_sub) = Capability::alias(&dom, r1_h, Access::new(0x0, 0x1000, Rights::RW)).unwrap();

    // Before MAP_SELF: the [0x0..0x1000) region has refcount 2 (R1 + alias).
    // MAP_SELF alias to GPA 0x6000.
    let _updates = Capability::map_self(&dom, alias_h, 0x6000).unwrap();

    let d = dom.read();
    let e = d.data.address_map.entries();

    // R1's entry at [0x0..0x5000) should still cover 0x0.
    // (The [0x0..0x1000) sub-range had refcount 2, now back to 1 after alias left.)
    let entry_0 = e.get(&0x0).expect("R1 still at GPA 0x0");
    match entry_0 {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x0);
            assert_eq!(m.rights, Rights::RW);
        }
        _ => panic!("R1 at 0x0 should still be Mapped"),
    }

    // Alias at [0x6000..0x7000).
    match e.get(&0x6000).expect("alias at new GPA") {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x0);
            assert_eq!(m.size, 0x1000);
            assert_eq!(m.rights, Rights::RW);
        }
        _ => panic!("alias should be Mapped at 0x6000"),
    }
}

/// Full alias of entire region, then MAP_SELF it elsewhere.
/// R1 = [0x0..0x5000) RW.  Alias = [0x0..0x5000) RW (full).
/// MAP_SELF alias to 0x10000.
/// R1's entries must survive (refcount drops from 2→1, not destroyed).
#[test]
fn test_map_self_full_alias_same_domain() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    let (c1_h, _sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x0, 0x5000, Rights::RW)).unwrap();
    let (dom_h, dom) = make_child_with_map_self(&root);
    Capability::send(&root, c1_h, dom_h, Attributes::NONE).unwrap();
    Capability::seal(&root, dom_h).unwrap();

    let r1_h = first_mem_handle(&dom);

    // Full alias.
    let (alias_h, _) =
        Capability::alias(&dom, r1_h, Access::new(0x0, 0x5000, Rights::RW)).unwrap();

    // MAP_SELF alias to 0x1_0000.
    let _updates = Capability::map_self(&dom, alias_h, 0x1_0000).unwrap();

    let d = dom.read();
    let e = d.data.address_map.entries();

    // R1 still at GPA 0x0.
    let r1_entry = e.get(&0x0).expect("R1 at 0x0 must survive");
    match r1_entry {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x0);
            assert_eq!(m.rights, Rights::RW);
        }
        _ => panic!("expected Mapped"),
    }

    // Alias at 0x1_0000.
    match e.get(&0x1_0000).expect("alias at 0x1_0000") {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x0);
            assert_eq!(m.size, 0x5000);
            assert_eq!(m.rights, Rights::RW);
        }
        _ => panic!("expected Mapped"),
    }
}

/// Overlapping rights via alias within same domain.
///
/// Parent RWX [0..0x5000], child aliases sub-range [0..0x1000] with RX.
/// At [0..0x1000]: R(2)W(1)X(2) = effective RWX (parent + alias both contribute).
/// After MAP_SELF alias to 0x10000:
///   [0..0x1000]: R(1)W(1)X(1) = still RWX (parent alone).
///   [0x10000..0x11000]: R(1)W(0)X(1) = RX (alias alone).
///
/// Note: visible rights change at the source is impossible because alias rights
/// are always ⊆ parent rights. The refcount change is verified structurally.
#[test]
fn test_map_self_alias_different_rights() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    let (c1_h, _sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x0, 0x5000, Rights::RWX)).unwrap();
    let (dom_h, dom) = make_child_with_map_self(&root);
    Capability::send(&root, c1_h, dom_h, Attributes::NONE).unwrap();
    Capability::seal(&root, dom_h).unwrap();

    let r1_h = first_mem_handle(&dom);

    // Alias sub-range [0x0..0x1000) with RX (subset of parent's RWX).
    let (alias_h, _) =
        Capability::alias(&dom, r1_h, Access::new(0x0, 0x1000, Rights::RX)).unwrap();

    // Before MAP_SELF: [0x0..0x1000) has R(2)W(1)X(2) = RWX.
    {
        let d = dom.read();
        match d.data.address_map.entries().get(&0x0).expect("entry at 0") {
            MapEntry::Mapped(m) => assert_eq!(m.rights, Rights::RWX,
                "R(2)W(1)X(2) → RWX"),
            _ => panic!("expected Mapped"),
        }
    }

    // MAP_SELF alias to 0x10000.
    let _updates = Capability::map_self(&dom, alias_h, 0x10000).unwrap();

    let d = dom.read();
    let e = d.data.address_map.entries();

    // [0x0..0x1000): parent alone → R(1)W(1)X(1) = RWX (no visible change).
    match e.get(&0x0).expect("parent at 0x0") {
        MapEntry::Mapped(m) => {
            assert_eq!(m.rights, Rights::RWX,
                "parent alone still RWX — alias rights were subset");
        }
        _ => panic!("expected Mapped"),
    }

    // [0x10000..0x11000): alias (RX).
    match e.get(&0x10000).expect("alias at 0x10000") {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x0);
            assert_eq!(m.size, 0x1000);
            assert_eq!(m.rights, Rights::RX);
        }
        _ => panic!("expected Mapped"),
    }
}

/// Two caps in child's map.  MAP_SELF one onto the other → overlap rejected,
/// both remain at original GPAs (rollback).
#[test]
fn test_map_self_overlap_rejected() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    let (c1, _s1, _) =
        Capability::carve(&root, r0_h, Access::new(0x1000, 0x1000, Rights::RW)).unwrap();
    let (c2, _s2, _) =
        Capability::carve(&root, r0_h, Access::new(0x3000, 0x1000, Rights::RW)).unwrap();

    let (dom_h, dom) = make_child_with_map_self(&root);
    Capability::send_at(&root, c1, dom_h, Attributes::NONE, Some(0x10_0000)).unwrap();
    Capability::send_at(&root, c2, dom_h, Attributes::NONE, Some(0x20_0000)).unwrap();
    Capability::seal(&root, dom_h).unwrap();

    let c1_h = handle_at_gpa(&dom, 0x10_0000);

    let result = Capability::map_self(&dom, c1_h, 0x20_0000);
    assert!(
        matches!(result, Err(CapaError::RegionOverlap)),
        "MAP_SELF onto existing cap must fail: {:?}", result
    );

    // Rollback: both still at original GPAs.
    let d = dom.read();
    assert!(d.data.address_map.entries().contains_key(&0x10_0000));
    assert!(d.data.address_map.entries().contains_key(&0x20_0000));
}

// ── error cases ─────────────────────────────────────────────────────────────

/// MAP_SELF without MAP_SELF permission → ApiNotAllowed.
#[test]
fn test_map_self_permission_denied_no_api() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    let (ch, _sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x1000, 0x1000, Rights::RW)).unwrap();
    let (dom_h, dom) = make_child(&root);
    Capability::send(&root, ch, dom_h, Attributes::NONE).unwrap();
    Capability::seal(&root, dom_h).unwrap();

    let cap_h = first_mem_handle(&dom);
    let result = Capability::map_self(&dom, cap_h, 0x5_0000);
    assert!(
        matches!(result, Err(CapaError::ApiNotAllowed)),
        "MAP_SELF without permission: {:?}", result
    );
}

/// MAP_SELF on unsealed domain → DomainNotSealed.
#[test]
fn test_map_self_requires_sealed() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    let (ch, _sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x1000, 0x1000, Rights::RW)).unwrap();
    let (dom_h, dom) = make_child_with_map_self(&root);
    Capability::send(&root, ch, dom_h, Attributes::NONE).unwrap();
    // NOT sealed.

    let cap_h = first_mem_handle(&dom);
    let result = Capability::map_self(&dom, cap_h, 0x5_0000);
    assert!(
        matches!(result, Err(CapaError::DomainNotSealed)),
        "unsealed: {:?}", result
    );
}

/// MAP_SELF with nonexistent handle → NotFound.
#[test]
fn test_map_self_not_found() {
    let (root, _r0, _r0_h) = bootstrap();
    let (dom_h, dom) = make_child_with_map_self(&root);
    Capability::seal(&root, dom_h).unwrap();

    let result = Capability::map_self(&dom, 999, 0x5_0000);
    assert!(matches!(result, Err(CapaError::NotFound)), "{:?}", result);
}

/// MAP_SELF on a frozen handle → PermissionDenied.
#[test]
fn test_map_self_frozen_handle_rejected() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    let (ch, _sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x1000, 0x1000, Rights::RW)).unwrap();
    let (dom_h, dom) = make_child_with_map_self(&root);
    Capability::send(&root, ch, dom_h, Attributes::NONE).unwrap();
    let cap_h = first_mem_handle(&dom);
    dom.write().data.frozen_handles.insert(cap_h);
    Capability::seal(&root, dom_h).unwrap();

    let result = Capability::map_self(&dom, cap_h, 0x5_0000);
    assert!(
        matches!(result, Err(CapaError::PermissionDenied)),
        "frozen: {:?}", result
    );
}

// ── corner cases ────────────────────────────────────────────────────────────

/// MAP_SELF to the same GPA is a no-op: entry should survive unchanged.
#[test]
fn test_map_self_same_gpa_noop() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    let (ch, _sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x0, 0x2000, Rights::RW)).unwrap();
    let (dom_h, dom) = make_child_with_map_self(&root);
    Capability::send_at(&root, ch, dom_h, Attributes::NONE, Some(0x10_0000)).unwrap();
    Capability::seal(&root, dom_h).unwrap();

    let cap_h = first_mem_handle(&dom);

    // Snapshot before.
    let before_keys = {
        let d = dom.read();
        d.data.address_map.entries().keys().copied().collect::<Vec<_>>()
    };

    // MAP_SELF to the same GPA it already occupies.
    let updates = Capability::map_self(&dom, cap_h, 0x10_0000).unwrap();

    // Should produce no updates (nothing changed).
    assert!(updates.updates().is_empty(),
        "same-GPA remap should produce 0 updates, got {}", updates.updates().len());

    // Entries should be identical (same keys, same count).
    let after = {
        let d = dom.read();
        d.data.address_map.entries().keys().copied().collect::<Vec<_>>()
    };
    assert_eq!(before_keys, after, "map keys should be unchanged");
}

/// MAP_SELF a cap to GPA immediately adjacent to another cap (no gap, no overlap).
#[test]
fn test_map_self_adjacent_to_existing() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    let (c1_h, _s1, _) =
        Capability::carve(&root, r0_h, Access::new(0x0, 0x1000, Rights::RW)).unwrap();
    let (c2_h, _s2, _) =
        Capability::carve(&root, r0_h, Access::new(0x2000, 0x1000, Rights::RW)).unwrap();

    let (dom_h, dom) = make_child_with_map_self(&root);
    Capability::send_at(&root, c1_h, dom_h, Attributes::NONE, Some(0x10_0000)).unwrap();
    Capability::send_at(&root, c2_h, dom_h, Attributes::NONE, Some(0x30_0000)).unwrap();
    Capability::seal(&root, dom_h).unwrap();

    let c2_child_h = handle_at_gpa(&dom, 0x30_0000);

    // Move c2 immediately after c1: [0x10_0000..0x11_000) + [0x11_000..0x12_000).
    let _updates = Capability::map_self(&dom, c2_child_h, 0x10_1000).unwrap();

    let d = dom.read();
    let e = d.data.address_map.entries();
    assert!(e.contains_key(&0x10_0000), "c1 still at original GPA");
    assert!(e.contains_key(&0x10_1000), "c2 now adjacent");
    assert!(!e.contains_key(&0x30_0000), "c2 no longer at old GPA");
}

/// MAP_SELF overlap rejection rolls back: the cap stays at its old GPA.
#[test]
fn test_map_self_overlap_rollback_preserves_state() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    let (c1_h, _s1, _) =
        Capability::carve(&root, r0_h, Access::new(0x0, 0x2000, Rights::RW)).unwrap();
    let (c2_h, _s2, _) =
        Capability::carve(&root, r0_h, Access::new(0x4000, 0x2000, Rights::RW)).unwrap();

    let (dom_h, dom) = make_child_with_map_self(&root);
    Capability::send_at(&root, c1_h, dom_h, Attributes::NONE, Some(0x10_0000)).unwrap();
    Capability::send_at(&root, c2_h, dom_h, Attributes::NONE, Some(0x20_0000)).unwrap();
    Capability::seal(&root, dom_h).unwrap();

    let c1_child_h = handle_at_gpa(&dom, 0x10_0000);

    // Snapshot before attempted overlap.
    let before_keys = {
        let d = dom.read();
        d.data.address_map.entries().keys().copied().collect::<Vec<_>>()
    };

    // Attempt overlap: c1 [0x2000 size] at 0x1F_F000 → [0x1FF000..0x201000)
    // overlaps c2 at [0x200000..0x202000).
    let result = Capability::map_self(&dom, c1_child_h, 0x1F_F000);
    assert!(matches!(result, Err(CapaError::RegionOverlap)),
        "expected RegionOverlap, got {:?}", result);

    // State must be exactly the same as before the failed attempt.
    let after_keys = {
        let d = dom.read();
        d.data.address_map.entries().keys().copied().collect::<Vec<_>>()
    };
    assert_eq!(before_keys, after_keys, "rollback must restore exact state");

    // mapped_gpas should still show old GPA.
    let tracked_gpa = dom.read().data.mapped_gpas[&c1_child_h];
    assert_eq!(tracked_gpa, 0x10_0000, "tracked GPA must be unchanged");
}

/// MAP_SELF a small alias multiple times across the address space.
#[test]
fn test_map_self_alias_bouncing() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    let (c1_h, _sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x0, 0x4000, Rights::RWX)).unwrap();
    let (dom_h, dom) = make_child_with_map_self(&root);
    Capability::send(&root, c1_h, dom_h, Attributes::NONE).unwrap();
    Capability::seal(&root, dom_h).unwrap();

    let parent_h = first_mem_handle(&dom);

    // Create alias of sub-range [0x0..0x1000).
    let (alias_h, _) =
        Capability::alias(&dom, parent_h, Access::new(0x0, 0x1000, Rights::RW)).unwrap();

    // Bounce alias through several GPAs.
    let gpas = [0x10_0000, 0x20_0000, 0x30_0000, 0x10_0000];
    for &gpa in &gpas {
        Capability::map_self(&dom, alias_h, gpa).unwrap();
        let d = dom.read();
        let e = d.data.address_map.entries();
        assert!(e.contains_key(&gpa), "alias must be at GPA {:#x}", gpa);
        // Parent always survives at its original GPA.
        assert!(e.contains_key(&0x0), "parent must survive at 0x0");
        drop(d);
    }

    // Final check: alias at last GPA, parent intact.
    let d = dom.read();
    let e = d.data.address_map.entries();
    assert!(e.contains_key(&0x10_0000));
    match e.get(&0x0).expect("parent at 0") {
        MapEntry::Mapped(m) => assert_eq!(m.rights, Rights::RWX),
        _ => panic!("expected Mapped"),
    }
}

/// MAP_SELF a cap with carved hole to a non-page-aligned offset from root's
/// region.  Verifies blocked gap's GPA moves correctly with arbitrary base.
#[test]
fn test_map_self_carved_hole_nonaligned_base() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    // c1 = [0x0..0x4000), hole c2 = [0x1000..0x2000).
    let (c1_h, _c1, _) =
        Capability::carve(&root, r0_h, Access::new(0x0, 0x4000, Rights::RW)).unwrap();
    let (_c2_h, _c2, _) =
        Capability::carve(&root, c1_h, Access::new(0x1000, 0x1000, Rights::RW)).unwrap();

    let (dom_h, dom) = make_child_with_map_self(&root);
    Capability::send_at(&root, c1_h, dom_h, Attributes::NONE, Some(0x5_0000)).unwrap();
    Capability::seal(&root, dom_h).unwrap();

    let c1_child = first_mem_handle(&dom);

    // Move to 0x7_3000 (arbitrary non-zero-low-bits base).
    let _updates = Capability::map_self(&dom, c1_child, 0x7_3000).unwrap();

    let d = dom.read();
    let e = d.data.address_map.entries();

    // [0x7_3000, 0x1000) mapped (HPA 0x0).
    match e.get(&0x7_3000).expect("first segment") {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x0);
            assert_eq!(m.size, 0x1000);
        }
        _ => panic!("expected Mapped"),
    }
    // [0x7_4000, 0x1000) blocked (HPA 0x1000 — carved child).
    match e.get(&0x7_4000).expect("blocked gap") {
        MapEntry::Blocked { hpa_start, size } => {
            assert_eq!(*hpa_start, 0x1000);
            assert_eq!(*size, 0x1000);
        }
        _ => panic!("expected Blocked"),
    }
    // [0x7_5000, 0x2000) mapped (HPA 0x2000).
    match e.get(&0x7_5000).expect("second segment") {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x2000);
            assert_eq!(m.size, 0x2000);
        }
        _ => panic!("expected Mapped"),
    }
    // Old GPA cleaned up.
    assert!(!e.contains_key(&0x5_0000));
}

/// Multiple aliases of same parent sub-range: MAP_SELF one, others stay.
/// All aliases contribute to the same GPA region; removing one only decrements.
#[test]
fn test_map_self_multiple_aliases_same_range() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    let (c1_h, _sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x0, 0x4000, Rights::RWX)).unwrap();
    let (dom_h, dom) = make_child_with_map_self(&root);
    Capability::send(&root, c1_h, dom_h, Attributes::NONE).unwrap();
    Capability::seal(&root, dom_h).unwrap();

    let parent_h = first_mem_handle(&dom);

    // Create 3 aliases of the same sub-range [0x0..0x1000).
    let (a1, _) = Capability::alias(&dom, parent_h, Access::new(0x0, 0x1000, Rights::RW)).unwrap();
    let (a2, _) = Capability::alias(&dom, parent_h, Access::new(0x0, 0x1000, Rights::RW)).unwrap();
    let (a3, _) = Capability::alias(&dom, parent_h, Access::new(0x0, 0x1000, Rights::RW)).unwrap();

    // At [0x0..0x1000): parent(RWX) + a1(RW) + a2(RW) + a3(RW) = R(4)W(4)X(1).
    // Effective rights = RWX.

    // Move a1 away.
    Capability::map_self(&dom, a1, 0x10_0000).unwrap();

    // [0x0..0x1000): parent(RWX) + a2(RW) + a3(RW) = R(3)W(3)X(1) = RWX.
    {
        let d = dom.read();
        match d.data.address_map.entries().get(&0x0).expect("at 0") {
            MapEntry::Mapped(m) => assert_eq!(m.rights, Rights::RWX),
            _ => panic!("expected Mapped"),
        }
    }

    // Move a2 away.
    Capability::map_self(&dom, a2, 0x20_0000).unwrap();

    // [0x0..0x1000): parent(RWX) + a3(RW) = R(2)W(2)X(1) = RWX.
    {
        let d = dom.read();
        match d.data.address_map.entries().get(&0x0).expect("at 0") {
            MapEntry::Mapped(m) => assert_eq!(m.rights, Rights::RWX),
            _ => panic!("expected Mapped"),
        }
    }

    // Move a3 away.
    Capability::map_self(&dom, a3, 0x30_0000).unwrap();

    // [0x0..0x1000): parent alone → R(1)W(1)X(1) = RWX.
    let d = dom.read();
    match d.data.address_map.entries().get(&0x0).expect("parent at 0") {
        MapEntry::Mapped(m) => assert_eq!(m.rights, Rights::RWX),
        _ => panic!("expected Mapped"),
    }

    // All 3 aliases at their new GPAs.
    assert!(d.data.address_map.entries().contains_key(&0x10_0000));
    assert!(d.data.address_map.entries().contains_key(&0x20_0000));
    assert!(d.data.address_map.entries().contains_key(&0x30_0000));
}

/// MAP_SELF produces correct UpdateBatch entries (GPA + HPA).
#[test]
fn test_map_self_update_batch_correctness() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    let (ch, _sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x1000, 0x2000, Rights::RW)).unwrap();
    let (dom_h, dom) = make_child_with_map_self(&root);
    Capability::send_at(&root, ch, dom_h, Attributes::NONE, Some(0x10_0000)).unwrap();
    Capability::seal(&root, dom_h).unwrap();

    let child_id = dom_id(&dom);
    let cap_h = first_mem_handle(&dom);

    let updates = Capability::map_self(&dom, cap_h, 0x50_0000).unwrap();

    // Should have updates for the child domain:
    // - Remove at old GPA (0x10_0000, size 0x2000)
    // - Add at new GPA (0x50_0000, size 0x2000)
    let child_updates: Vec<_> = updates
        .updates()
        .iter()
        .filter(|u| match u {
            Update::ChangeRights { domain, .. } => *domain == child_id,
            _ => false,
        })
        .collect();

    assert!(!child_updates.is_empty(), "must have updates for child domain");

    // Verify GPAs are in the expected range (not HPAs).
    for u in &child_updates {
        if let Update::ChangeRights { address, physical, .. } = u {
            // Addresses should be GPAs (our test puts them at 0x10_0000+ or 0x50_0000+).
            assert!(
                *address >= 0x10_0000 || *address >= 0x50_0000,
                "address should be GPA, got {:#x}", address
            );
            // Physicals should be HPAs (< 0x10000 for our test).
            assert!(
                *physical < 0x10000,
                "physical should be HPA, got {:#x}", physical
            );
        }
    }
}

/// MAP_SELF the parent cap itself (not just an alias) to a different GPA.
#[test]
fn test_map_self_parent_cap_with_alias_staying() {
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    let (c1_h, _sub, _) =
        Capability::carve(&root, r0_h, Access::new(0x0, 0x4000, Rights::RWX)).unwrap();
    let (dom_h, dom) = make_child_with_map_self(&root);
    Capability::send(&root, c1_h, dom_h, Attributes::NONE).unwrap();
    Capability::seal(&root, dom_h).unwrap();

    let parent_h = first_mem_handle(&dom);

    // Alias [0x0..0x1000) at same GPA → adds refcount.
    let (alias_h, _) =
        Capability::alias(&dom, parent_h, Access::new(0x0, 0x1000, Rights::RW)).unwrap();

    // MAP_SELF the PARENT to a new GPA. Alias stays behind.
    let _updates = Capability::map_self(&dom, parent_h, 0x10_0000).unwrap();

    let d = dom.read();
    let e = d.data.address_map.entries();

    // Alias sub-range [0x0..0x1000) should survive at its original GPA.
    match e.get(&0x0).expect("alias at 0") {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x0);
            assert_eq!(m.size, 0x1000);
            assert_eq!(m.rights, Rights::RW, "alias alone has RW");
        }
        _ => panic!("expected Mapped"),
    }

    // Parent should be at new GPA with its full range.
    // Parent's view = [0x0..0x4000) minus carved children. No carve here, so full.
    // But wait — the alias doesn't carve, so parent's view is [0x0..0x4000).
    // At [0x10_0000..0x14_000): parent's footprint → RWX.
    match e.get(&0x10_0000).expect("parent at new GPA") {
        MapEntry::Mapped(m) => {
            assert_eq!(m.hpa_start, 0x0);
            assert_eq!(m.rights, Rights::RWX);
        }
        _ => panic!("expected Mapped"),
    }

    // [0x1000..0x4000) at old GPA should be gone (parent left).
    assert!(!e.contains_key(&0x1000),
        "parent's non-alias region should be gone from old GPA");

    // Verify alias handle tracking is correct.
    drop(d);
    let alias_gpa = dom.read().data.mapped_gpas[&alias_h];
    assert_eq!(alias_gpa, 0x0, "alias GPA unchanged");
}

// ── double-map (VTOM) ────────────────────────────────────────────────────────

/// When an alias is sent at a different GPA to a domain that already has
/// a superset physical mapping (same physical pages visible at a different GPA),
/// `view_diff` produces no updates (the physical view is unchanged). The engine
/// must still emit a ChangeRights for the new GPA so the platform maps it.
#[test]
fn test_send_alias_subset_at_different_gpa_emits_change_rights() {
    // Setup: root with a 64K region.
    let (root, _r0, r0_h) = bootstrap();
    seed_map(&root, 0x0, 0x10000, Rights::RWX, 0x0);

    // Create child domain.
    let (child_h, child_dom) = make_child(&root);
    let child_id = dom_id(&child_dom);

    // Alias the full region and send to child at GPA 0 (identity).
    let access_full = Access::new(0x0, 0x10000, Rights::RWX);
    let (alias1_h, _alias1_sub) =
        Capability::alias(&root, r0_h, access_full).unwrap();
    let updates1 = Capability::send_at(&root, alias1_h, child_h, Attributes::NONE, Some(0x0))
        .unwrap();

    // Verify the first send emits ChangeRights for the child at GPA 0.
    let cr1: Vec<_> = updates1
        .updates()
        .iter()
        .filter(|u| matches!(u, Update::ChangeRights { domain, .. } if *domain == child_id))
        .collect();
    assert!(
        !cr1.is_empty(),
        "first send should produce ChangeRights for child"
    );

    // Now alias a SUBSET (4K at HPA 0x2000) and send at a completely different GPA (0x8000_0000).
    let access_sub = Access::new(0x2000, 0x1000, Rights::RWX);
    let (alias2_h, _alias2_sub) =
        Capability::alias(&root, r0_h, access_sub).unwrap();
    let vtom_gpa: u64 = 0x8000_0000;
    let updates2 =
        Capability::send_at(&root, alias2_h, child_h, Attributes::NONE, Some(vtom_gpa))
            .unwrap();

    // The critical check: even though the child already sees HPA 0x2000-0x3000
    // (via the 64K mapping), a ChangeRights at GPA 0x8000_0000 must be emitted.
    let cr2: Vec<_> = updates2
        .updates()
        .iter()
        .filter_map(|u| match u {
            Update::ChangeRights {
                domain,
                address,
                physical,
                size,
                rights,
                ..
            } if *domain == child_id => Some((*address, *physical, *size, *rights)),
            _ => None,
        })
        .collect();
    assert!(
        !cr2.is_empty(),
        "subset alias at different GPA must emit ChangeRights (VTOM double-map)"
    );
    let (addr, phys, sz, r) = cr2[0];
    assert_eq!(addr, vtom_gpa, "address should be the VTOM GPA");
    assert_eq!(phys, 0x2000, "physical should be the subset HPA");
    assert_eq!(sz, 0x1000, "size should match the alias");
    assert_eq!(r, Rights::RWX, "rights should be RWX");
}
