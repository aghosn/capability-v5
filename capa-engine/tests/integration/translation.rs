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

    let r = root.read();
    assert_eq!(
        r.data.address_map.entries().len(),
        1,
        "same rights → no split"
    );
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
