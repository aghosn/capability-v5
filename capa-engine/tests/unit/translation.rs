//! Tests for the address translation layer (AddressMap).
//!
//! These tests only compile when `address_translation` is enabled.

use capability_engine::memory::Rights;
use capability_engine::translation::{AddressMap, MapEntry, MappingEntry};
#[cfg(feature = "cache_coloring")]
use capability_engine::translation::ColorBitmap;

/// Helper: insert without color bitmap.
fn ins(
    map: &mut AddressMap,
    hpa: u64,
    size: u64,
    rights: Rights,
    hint: Option<u64>,
) -> core::result::Result<u64, &'static str> {
    map.insert(
        hpa,
        size,
        rights,
        #[cfg(feature = "cache_coloring")]
        None,
        hint,
    )
}

// ── insert ──────────────────────────────────────────────────────

#[test]
fn insert_identity_map() {
    let mut map = AddressMap::new();
    let gpa = ins(&mut map, 0x1000, 0x2000, Rights::RWX, None).unwrap();
    assert_eq!(gpa, 0x1000); // identity: GPA == HPA
    assert_eq!(map.entries().len(), 1);
}

#[test]
fn insert_with_hint() {
    let mut map = AddressMap::new();
    let gpa = ins(&mut map, 0x1000, 0x2000, Rights::RWX, Some(0x5000)).unwrap();
    assert_eq!(gpa, 0x5000);
}

#[test]
fn insert_overlap_rejected() {
    let mut map = AddressMap::new();
    ins(&mut map, 0x1000, 0x2000, Rights::RWX, None).unwrap();
    assert!(ins(&mut map, 0x2000, 0x2000, Rights::RWX, None).is_err());
}

#[test]
fn insert_adjacent_ok() {
    let mut map = AddressMap::new();
    ins(&mut map, 0x1000, 0x1000, Rights::RWX, None).unwrap();
    ins(&mut map, 0x2000, 0x1000, Rights::RWX, None).unwrap();
    assert_eq!(map.entries().len(), 2);
}

// ── translate ───────────────────────────────────────────────────

#[test]
fn translate_identity() {
    let mut map = AddressMap::new();
    ins(&mut map, 0x1000, 0x4000, Rights::RW, None).unwrap();
    let (gpa, sz, r) = map.translate(0x2000, 0x1000).unwrap();
    assert_eq!(gpa, 0x2000);
    assert_eq!(sz, 0x1000);
    assert_eq!(r, Rights::RW);
}

#[test]
fn translate_with_offset() {
    let mut map = AddressMap::new();
    ins(&mut map, 0x1000, 0x4000, Rights::RW, Some(0xA000)).unwrap();
    let (gpa, sz, r) = map.translate(0x2000, 0x1000).unwrap();
    assert_eq!(gpa, 0xB000); // A000 + (2000 - 1000)
    assert_eq!(sz, 0x1000);
    assert_eq!(r, Rights::RW);
}

#[test]
fn translate_not_found() {
    let map = AddressMap::new();
    assert!(map.translate(0x1000, 0x1000).is_err());
}

// ── split ───────────────────────────────────────────────────────

#[test]
fn split_middle() {
    let mut map = AddressMap::new();
    ins(&mut map, 0x0, 0x9000, Rights::RWX, None).unwrap();
    map.split(0x3000, 0x3000, Rights::RW).unwrap();
    assert_eq!(map.entries().len(), 3);

    // Left [0x0..0x3000) RWX
    match map.entries().get(&0x0).unwrap() {
        MapEntry::Mapped(m) => {
            assert_eq!(m.size, 0x3000);
            assert_eq!(m.rights, Rights::RWX);
        }
        _ => panic!("expected Mapped"),
    }
    // Middle [0x3000..0x6000) RW
    match map.entries().get(&0x3000).unwrap() {
        MapEntry::Mapped(m) => {
            assert_eq!(m.size, 0x3000);
            assert_eq!(m.rights, Rights::RW);
            assert_eq!(m.hpa_start, 0x3000);
        }
        _ => panic!("expected Mapped"),
    }
    // Right [0x6000..0x9000) RWX
    match map.entries().get(&0x6000).unwrap() {
        MapEntry::Mapped(m) => {
            assert_eq!(m.size, 0x3000);
            assert_eq!(m.rights, Rights::RWX);
            assert_eq!(m.hpa_start, 0x6000);
        }
        _ => panic!("expected Mapped"),
    }
}

#[test]
fn split_at_start() {
    let mut map = AddressMap::new();
    ins(&mut map, 0x0, 0x6000, Rights::RWX, None).unwrap();
    map.split(0x0, 0x2000, Rights::R).unwrap();
    assert_eq!(map.entries().len(), 2);
    match map.entries().get(&0x0).unwrap() {
        MapEntry::Mapped(m) => assert_eq!(m.rights, Rights::R),
        _ => panic!(),
    }
}

#[test]
fn split_at_end() {
    let mut map = AddressMap::new();
    ins(&mut map, 0x0, 0x6000, Rights::RWX, None).unwrap();
    map.split(0x4000, 0x2000, Rights::R).unwrap();
    assert_eq!(map.entries().len(), 2);
    match map.entries().get(&0x4000).unwrap() {
        MapEntry::Mapped(m) => {
            assert_eq!(m.rights, Rights::R);
            assert_eq!(m.size, 0x2000);
        }
        _ => panic!(),
    }
}

#[test]
fn split_same_rights_noop() {
    let mut map = AddressMap::new();
    ins(&mut map, 0x0, 0x6000, Rights::RWX, None).unwrap();
    map.split(0x2000, 0x2000, Rights::RWX).unwrap();
    assert_eq!(map.entries().len(), 1);
}

#[test]
fn split_out_of_range() {
    let mut map = AddressMap::new();
    ins(&mut map, 0x1000, 0x2000, Rights::RWX, None).unwrap();
    assert!(map.split(0x0, 0x4000, Rights::R).is_err());
}

// ── block / unblock ─────────────────────────────────────────────

#[test]
fn block_and_unblock() {
    let mut map = AddressMap::new();
    ins(&mut map, 0x0, 0x9000, Rights::RWX, None).unwrap();
    map.split(0x3000, 0x3000, Rights::RW).unwrap();
    let m = map.block(0x3000).unwrap();
    assert_eq!(m.size, 0x3000);
    assert_eq!(m.rights, Rights::RW);
    assert!(map.translate(0x3000, 0x1000).is_err());

    map.unblock(0x3000, Rights::RWX).unwrap();
    let (gpa, _, rights) = map.translate(0x3000, 0x1000).unwrap();
    assert_eq!(gpa, 0x3000);
    assert_eq!(rights, Rights::RWX);
}

#[test]
fn unblock_coalesces() {
    let mut map = AddressMap::new();
    ins(&mut map, 0x0, 0x2000, Rights::RWX, None).unwrap();
    ins(&mut map, 0x2000, 0x2000, Rights::RWX, None).unwrap();
    map.split(0x1000, 0x1000, Rights::R).unwrap();
    map.block(0x1000).unwrap();
    assert_eq!(map.entries().len(), 3);

    map.unblock(0x1000, Rights::RWX).unwrap();
    assert_eq!(map.entries().len(), 1);
    match map.entries().get(&0x0).unwrap() {
        MapEntry::Mapped(m) => {
            assert_eq!(m.size, 0x4000);
            assert_eq!(m.rights, Rights::RWX);
        }
        _ => panic!(),
    }
}

#[test]
fn block_not_mapped_err() {
    let mut map = AddressMap::new();
    assert!(map.block(0x1000).is_err());
}

#[test]
fn unblock_not_blocked_err() {
    let mut map = AddressMap::new();
    ins(&mut map, 0x1000, 0x2000, Rights::RWX, None).unwrap();
    assert!(map.unblock(0x1000, Rights::RWX).is_err());
}

// ── remove ──────────────────────────────────────────────────────

#[test]
fn remove_entry() {
    let mut map = AddressMap::new();
    ins(&mut map, 0x1000, 0x2000, Rights::RWX, None).unwrap();
    let entry = map.remove(0x1000).unwrap();
    assert_eq!(entry.size(), 0x2000);
    assert!(map.entries().is_empty());
}

#[test]
fn remove_missing() {
    let mut map = AddressMap::new();
    assert!(map.remove(0x1000).is_err());
}

// ── color bitmap ────────────────────────────────────────────────

#[cfg(feature = "cache_coloring")]
mod color_tests {
    use capability_engine::translation::ColorBitmap;

    #[test]
    fn bitmap_all_64() {
        let bm = ColorBitmap::all(64);
        assert_eq!(bm.popcount(), 64);
        assert!(bm.contains(0));
        assert!(bm.contains(63));
    }

    #[test]
    fn bitmap_all_100() {
        let bm = ColorBitmap::all(100);
        assert_eq!(bm.popcount(), 100);
        assert!(bm.contains(99));
        assert!(!bm.contains(100));
    }

    #[test]
    fn bitmap_subset() {
        let all = ColorBitmap::all(64);
        let sub = ColorBitmap::from_raw(vec![0x0F]);
        assert!(sub.is_subset_of(&all));
        assert!(!all.is_subset_of(&sub));
    }
}

// ── RightsRefCount ──────────────────────────────────────────────

mod refcount_tests {
    use capability_engine::memory::Rights;
    use capability_engine::translation::{AddressMap, MapEntry, RightsRefCount};

    #[cfg(feature = "cache_coloring")]
    use capability_engine::translation::ColorBitmap;

    /// Helper: insert without color bitmap.
    fn ins(
        map: &mut AddressMap,
        hpa: u64,
        size: u64,
        rights: Rights,
        hint: Option<u64>,
    ) -> core::result::Result<u64, &'static str> {
        map.insert(
            hpa,
            size,
            rights,
            #[cfg(feature = "cache_coloring")]
            None,
            hint,
        )
    }

    // ── RightsRefCount unit tests ──────────────────────────────

    #[test]
    fn refcount_from_rights_rw() {
        let rc = RightsRefCount::from_rights(Rights::RW);
        assert_eq!(rc.read, 1);
        assert_eq!(rc.write, 1);
        assert_eq!(rc.execute, 0);
        assert_eq!(rc.effective_rights(), Rights::RW);
        assert!(!rc.is_empty());
    }

    #[test]
    fn refcount_from_rights_none() {
        let rc = RightsRefCount::from_rights(Rights::NONE);
        assert_eq!(rc.read, 0);
        assert_eq!(rc.write, 0);
        assert_eq!(rc.execute, 0);
        assert!(rc.is_empty());
        assert_eq!(rc.effective_rights(), Rights::NONE);
    }

    #[test]
    fn refcount_add_sub() {
        let mut rc = RightsRefCount::from_rights(Rights::RW);
        rc.add(Rights::RX);
        // R(2), W(1), X(1)
        assert_eq!(rc.read, 2);
        assert_eq!(rc.write, 1);
        assert_eq!(rc.execute, 1);
        assert_eq!(rc.effective_rights(), Rights::RWX);

        rc.sub(Rights::RW);
        // R(1), W(0), X(1)
        assert_eq!(rc.read, 1);
        assert_eq!(rc.write, 0);
        assert_eq!(rc.execute, 1);
        assert_eq!(rc.effective_rights(), Rights::RX);
    }

    #[test]
    fn refcount_sub_saturates() {
        let mut rc = RightsRefCount::ZERO;
        rc.sub(Rights::RWX);
        assert!(rc.is_empty());
    }

    // ── add_contribution tests ─────────────────────────────────

    #[test]
    fn add_contribution_to_empty_map() {
        let mut map = AddressMap::new();
        map.add_contribution(0x0, 0x0, 0x4000, Rights::RW, false).unwrap();

        assert_eq!(map.entries().len(), 1);
        match map.entries().get(&0x0).unwrap() {
            MapEntry::Mapped(m) => {
                assert_eq!(m.hpa_start, 0x0);
                assert_eq!(m.size, 0x4000);
                assert_eq!(m.rights, Rights::RW);
            }
            _ => panic!("expected Mapped"),
        }
    }

    #[test]
    fn add_contribution_overlapping_same_hpa() {
        let mut map = AddressMap::new();
        // R0: [GPA 0x0..0x10000] RW
        map.add_contribution(0x0, 0x0, 0x10000, Rights::RW, false).unwrap();
        // R1: [GPA 0x5000..0x6000] RX (same HPA, alias)
        map.add_contribution(0x5000, 0x5000, 0x1000, Rights::RX, false).unwrap();

        // Should have 3 segments: [0..5000] RW, [5000..6000] RWX, [6000..10000] RW
        assert_eq!(map.entries().len(), 3);

        match map.entries().get(&0x0).unwrap() {
            MapEntry::Mapped(m) => {
                assert_eq!(m.size, 0x5000);
                assert_eq!(m.rights, Rights::RW);
            }
            _ => panic!("expected Mapped"),
        }
        match map.entries().get(&0x5000).unwrap() {
            MapEntry::Mapped(m) => {
                assert_eq!(m.size, 0x1000);
                assert_eq!(m.rights, Rights::RWX);
            }
            _ => panic!("expected Mapped"),
        }
        match map.entries().get(&0x6000).unwrap() {
            MapEntry::Mapped(m) => {
                assert_eq!(m.size, 0xA000);
                assert_eq!(m.rights, Rights::RW);
            }
            _ => panic!("expected Mapped"),
        }
    }

    #[test]
    fn add_contribution_hpa_conflict_rejected() {
        let mut map = AddressMap::new();
        map.add_contribution(0x0, 0x0, 0x4000, Rights::RW, false).unwrap();
        // Different HPA at same GPA → error.
        let err = map.add_contribution(0x1000, 0x9000, 0x1000, Rights::R, false);
        assert!(err.is_err());
    }

    #[test]
    fn add_contribution_blocked() {
        let mut map = AddressMap::new();
        map.add_contribution(0x1000, 0x1000, 0x2000, Rights::NONE, true).unwrap();

        assert_eq!(map.entries().len(), 1);
        match map.entries().get(&0x1000).unwrap() {
            MapEntry::Blocked { hpa_start, size } => {
                assert_eq!(*hpa_start, 0x1000);
                assert_eq!(*size, 0x2000);
            }
            _ => panic!("expected Blocked"),
        }
    }

    #[test]
    fn add_contribution_adjacent_coalesces() {
        let mut map = AddressMap::new();
        // Two adjacent contributions with same rights and contiguous HPA.
        map.add_contribution(0x0, 0x0, 0x2000, Rights::RW, false).unwrap();
        map.add_contribution(0x2000, 0x2000, 0x2000, Rights::RW, false).unwrap();

        // Should coalesce into one segment.
        assert_eq!(map.entries().len(), 1);
        match map.entries().get(&0x0).unwrap() {
            MapEntry::Mapped(m) => {
                assert_eq!(m.size, 0x4000);
                assert_eq!(m.rights, Rights::RW);
            }
            _ => panic!("expected Mapped"),
        }
    }

    #[test]
    fn add_contribution_no_coalesce_different_rights() {
        let mut map = AddressMap::new();
        map.add_contribution(0x0, 0x0, 0x2000, Rights::RW, false).unwrap();
        map.add_contribution(0x2000, 0x2000, 0x2000, Rights::RX, false).unwrap();

        // Different rights → no coalescing.
        assert_eq!(map.entries().len(), 2);
    }

    #[test]
    fn no_coalesce_different_refcounts_same_effective_rights() {
        let mut map = AddressMap::new();
        // [0x0..0x2000] with RW from one contributor → R(1)W(1)
        map.add_contribution(0x0, 0x0, 0x2000, Rights::RW, false).unwrap();
        // [0x2000..0x4000] with RW from two contributors → R(2)W(2)
        map.add_contribution(0x2000, 0x2000, 0x2000, Rights::RW, false).unwrap();
        map.add_contribution(0x2000, 0x2000, 0x2000, Rights::RW, false).unwrap();

        // Both have effective rights RW, but different refcounts → must NOT coalesce.
        assert_eq!(map.entries().len(), 2);
        // Verify both show RW
        match map.entries().get(&0x0).unwrap() {
            MapEntry::Mapped(m) => assert_eq!(m.rights, Rights::RW),
            _ => panic!(),
        }
        match map.entries().get(&0x2000).unwrap() {
            MapEntry::Mapped(m) => assert_eq!(m.rights, Rights::RW),
            _ => panic!(),
        }
    }

    // ── remove_contribution tests ──────────────────────────────

    #[test]
    fn remove_contribution_single_contributor() {
        let mut map = AddressMap::new();
        map.add_contribution(0x0, 0x0, 0x4000, Rights::RW, false).unwrap();
        map.remove_contribution(0x0, 0x0, 0x4000, Rights::RW, false).unwrap();

        // Should be empty — last contributor removed.
        assert!(map.entries().is_empty());
    }

    #[test]
    fn remove_contribution_one_of_two() {
        let mut map = AddressMap::new();
        // R0: [0..0x10000] RW
        map.add_contribution(0x0, 0x0, 0x10000, Rights::RW, false).unwrap();
        // R1: [0x5000..0x6000] RX (overlapping alias)
        map.add_contribution(0x5000, 0x5000, 0x1000, Rights::RX, false).unwrap();

        // Remove R1's contribution.
        map.remove_contribution(0x5000, 0x5000, 0x1000, Rights::RX, false).unwrap();

        // R0 should be uniform RW again, coalesced back to 1 entry.
        assert_eq!(map.entries().len(), 1);
        match map.entries().get(&0x0).unwrap() {
            MapEntry::Mapped(m) => {
                assert_eq!(m.size, 0x10000);
                assert_eq!(m.rights, Rights::RW);
            }
            _ => panic!("expected Mapped"),
        }
    }

    #[test]
    fn remove_contribution_partial_range() {
        let mut map = AddressMap::new();
        map.add_contribution(0x0, 0x0, 0x4000, Rights::RW, false).unwrap();

        // Remove only [0x1000..0x2000).
        map.remove_contribution(0x1000, 0x1000, 0x1000, Rights::RW, false).unwrap();

        // Should have 2 entries: [0..0x1000] RW, [0x2000..0x4000] RW.
        assert_eq!(map.entries().len(), 2);
        match map.entries().get(&0x0).unwrap() {
            MapEntry::Mapped(m) => assert_eq!(m.size, 0x1000),
            _ => panic!("expected Mapped"),
        }
        match map.entries().get(&0x2000).unwrap() {
            MapEntry::Mapped(m) => assert_eq!(m.size, 0x2000),
            _ => panic!("expected Mapped"),
        }
    }

    #[test]
    fn remove_contribution_blocked() {
        let mut map = AddressMap::new();
        // Add mapped, then blocked on top.
        map.add_contribution(0x0, 0x0, 0x4000, Rights::RW, false).unwrap();
        map.add_contribution(0x1000, 0x1000, 0x1000, Rights::NONE, true).unwrap();

        // Should have 3 entries: [0..1000] RW, [1000..2000] Blocked, [2000..4000] RW
        assert_eq!(map.entries().len(), 3);
        match map.entries().get(&0x1000).unwrap() {
            MapEntry::Blocked { .. } => {}
            _ => panic!("expected Blocked"),
        }

        // Remove the blocked flag.
        map.remove_contribution(0x1000, 0x1000, 0x1000, Rights::NONE, true).unwrap();

        // Should coalesce back to a single [0..4000] RW entry.
        assert_eq!(map.entries().len(), 1);
        match map.entries().get(&0x0).unwrap() {
            MapEntry::Mapped(m) => {
                assert_eq!(m.size, 0x4000);
                assert_eq!(m.rights, Rights::RW);
            }
            _ => panic!("expected Mapped after unblock"),
        }
    }

    // ── The user's key scenario ────────────────────────────────
    //
    // R0 [HPA 0x0..0x10000] RW at GPA 0x0
    // R1 [HPA 0x5000..0x6000] RX at GPA 0x5000 (alias)
    // Projection: [0..5000] RW, [5000..6000] RWX, [6000..10000] RW
    //
    // MAP_SELF(R1, GPA 0x20000):
    //   remove R1 @ 0x5000
    //   add R1 @ 0x20000
    //
    // After: [0..10000] RW (coalesced), [20000..21000] RX

    #[test]
    fn scenario_map_self_alias_move() {
        let mut map = AddressMap::new();

        // R0: full range RW
        map.add_contribution(0x0, 0x0, 0x10000, Rights::RW, false).unwrap();
        // R1: alias sub-range RX
        map.add_contribution(0x5000, 0x5000, 0x1000, Rights::RX, false).unwrap();
        assert_eq!(map.entries().len(), 3);

        // Simulate MAP_SELF: remove old, add new.
        map.remove_contribution(0x5000, 0x5000, 0x1000, Rights::RX, false).unwrap();
        map.add_contribution(0x20000, 0x5000, 0x1000, Rights::RX, false).unwrap();

        // R0 should be uniform again.
        assert_eq!(map.entries().len(), 2);
        match map.entries().get(&0x0).unwrap() {
            MapEntry::Mapped(m) => {
                assert_eq!(m.size, 0x10000);
                assert_eq!(m.rights, Rights::RW);
            }
            _ => panic!("expected Mapped"),
        }
        // R1 at new GPA.
        match map.entries().get(&0x20000).unwrap() {
            MapEntry::Mapped(m) => {
                assert_eq!(m.hpa_start, 0x5000);
                assert_eq!(m.size, 0x1000);
                assert_eq!(m.rights, Rights::RX);
            }
            _ => panic!("expected Mapped"),
        }
    }

    // ── Full alias scenario (the bug that motivated this) ──────
    //
    // R0 [0..0x5000] RWX at GPA 0
    // R1 [0..0x5000] RWX at GPA 0 (full alias, same HPA)
    // MAP_SELF(R1, 0x8000): R0 must survive at GPA 0

    #[test]
    fn scenario_full_alias_no_clobber() {
        let mut map = AddressMap::new();

        // R0
        map.add_contribution(0x0, 0x0, 0x5000, Rights::RWX, false).unwrap();
        // R1 (full alias, same HPA)
        map.add_contribution(0x0, 0x0, 0x5000, Rights::RWX, false).unwrap();

        // MAP_SELF R1 to 0x8000.
        map.remove_contribution(0x0, 0x0, 0x5000, Rights::RWX, false).unwrap();
        map.add_contribution(0x8000, 0x0, 0x5000, Rights::RWX, false).unwrap();

        // R0 still at GPA 0.
        assert_eq!(map.entries().len(), 2);
        match map.entries().get(&0x0).unwrap() {
            MapEntry::Mapped(m) => {
                assert_eq!(m.size, 0x5000);
                assert_eq!(m.rights, Rights::RWX);
            }
            _ => panic!("R0 must survive"),
        }
        // R1 at new GPA.
        match map.entries().get(&0x8000).unwrap() {
            MapEntry::Mapped(m) => {
                assert_eq!(m.hpa_start, 0x0);
                assert_eq!(m.size, 0x5000);
                assert_eq!(m.rights, Rights::RWX);
            }
            _ => panic!("expected Mapped at new GPA"),
        }
    }

    // ── User's scenario: R0 + partial alias R1, MAP_SELF R1 ───
    //
    // R0 [0x0..0x5000] at GPA 0
    // R1 [0x0..0x1000] (alias) at GPA 0
    // MAP_SELF(R1, 0x6000)
    // Result: R0 [0x0..0x5000], R1 [0x6000..0x7000]

    #[test]
    fn scenario_partial_alias_map_self() {
        let mut map = AddressMap::new();

        map.add_contribution(0x0, 0x0, 0x5000, Rights::RWX, false).unwrap();
        map.add_contribution(0x0, 0x0, 0x1000, Rights::RWX, false).unwrap();

        // MAP_SELF R1.
        map.remove_contribution(0x0, 0x0, 0x1000, Rights::RWX, false).unwrap();
        map.add_contribution(0x6000, 0x0, 0x1000, Rights::RWX, false).unwrap();

        // R0 still spans full range.
        match map.entries().get(&0x0).unwrap() {
            MapEntry::Mapped(m) => {
                assert_eq!(m.size, 0x5000);
                assert_eq!(m.rights, Rights::RWX);
            }
            _ => panic!("R0 must survive"),
        }
        // R1 at new GPA.
        match map.entries().get(&0x6000).unwrap() {
            MapEntry::Mapped(m) => {
                assert_eq!(m.hpa_start, 0x0);
                assert_eq!(m.size, 0x1000);
            }
            _ => panic!("expected R1 at 0x6000"),
        }
    }

    // ── Carve with blocked hole, MAP_SELF moves the hole ───────

    #[test]
    fn scenario_blocked_moves_with_parent() {
        let mut map = AddressMap::new();

        // R0 footprint: mapped [0..0x1000], blocked [0x1000..0x2000], mapped [0x2000..0x5000]
        map.add_contribution(0x0, 0x0, 0x1000, Rights::RWX, false).unwrap();
        map.add_contribution(0x1000, 0x1000, 0x1000, Rights::NONE, true).unwrap();
        map.add_contribution(0x2000, 0x2000, 0x3000, Rights::RWX, false).unwrap();

        assert_eq!(map.entries().len(), 3);

        // MAP_SELF R0 to GPA 0x8000: remove old footprint, add at new GPA.
        map.remove_contribution(0x0, 0x0, 0x1000, Rights::RWX, false).unwrap();
        map.remove_contribution(0x1000, 0x1000, 0x1000, Rights::NONE, true).unwrap();
        map.remove_contribution(0x2000, 0x2000, 0x3000, Rights::RWX, false).unwrap();

        assert!(map.entries().is_empty());

        map.add_contribution(0x8000, 0x0, 0x1000, Rights::RWX, false).unwrap();
        map.add_contribution(0x9000, 0x1000, 0x1000, Rights::NONE, true).unwrap();
        map.add_contribution(0xA000, 0x2000, 0x3000, Rights::RWX, false).unwrap();

        assert_eq!(map.entries().len(), 3);
        match map.entries().get(&0x8000).unwrap() {
            MapEntry::Mapped(m) => assert_eq!(m.size, 0x1000),
            _ => panic!("expected Mapped"),
        }
        match map.entries().get(&0x9000).unwrap() {
            MapEntry::Blocked { size, .. } => assert_eq!(*size, 0x1000),
            _ => panic!("expected Blocked"),
        }
        match map.entries().get(&0xA000).unwrap() {
            MapEntry::Mapped(m) => assert_eq!(m.size, 0x3000),
            _ => panic!("expected Mapped"),
        }
    }

    // ── Triple overlap: 3 caps contributing different rights ───

    #[test]
    fn triple_overlap_rights_accumulate() {
        let mut map = AddressMap::new();

        // R0: [0..0x4000] R
        map.add_contribution(0x0, 0x0, 0x4000, Rights::R, false).unwrap();
        // R1: [0x1000..0x3000] W (overlaps middle)
        map.add_contribution(0x1000, 0x1000, 0x2000,
            Rights::from_bits(Rights::WRITE), false).unwrap();
        // R2: [0x2000..0x4000] X (overlaps right portion)
        map.add_contribution(0x2000, 0x2000, 0x2000,
            Rights::from_bits(Rights::EXECUTE), false).unwrap();

        // [0x0..0x1000]: R only
        // [0x1000..0x2000]: R + W = RW
        // [0x2000..0x3000]: R + W + X = RWX
        // [0x3000..0x4000]: R + X = RX
        assert_eq!(map.entries().len(), 4);

        match map.entries().get(&0x0).unwrap() {
            MapEntry::Mapped(m) => assert_eq!(m.rights, Rights::R),
            _ => panic!(),
        }
        match map.entries().get(&0x1000).unwrap() {
            MapEntry::Mapped(m) => assert_eq!(m.rights, Rights::RW),
            _ => panic!(),
        }
        match map.entries().get(&0x2000).unwrap() {
            MapEntry::Mapped(m) => assert_eq!(m.rights, Rights::RWX),
            _ => panic!(),
        }
        match map.entries().get(&0x3000).unwrap() {
            MapEntry::Mapped(m) => assert_eq!(m.rights, Rights::RX),
            _ => panic!(),
        }

        // Remove R1's contribution → middle becomes R only, right becomes R+X.
        map.remove_contribution(0x1000, 0x1000, 0x2000,
            Rights::from_bits(Rights::WRITE), false).unwrap();

        // [0x0..0x2000]: R (coalesced)
        // [0x2000..0x4000]: R + X = RX (coalesced)
        assert_eq!(map.entries().len(), 2);
        match map.entries().get(&0x0).unwrap() {
            MapEntry::Mapped(m) => {
                assert_eq!(m.size, 0x2000);
                assert_eq!(m.rights, Rights::R);
            }
            _ => panic!(),
        }
        match map.entries().get(&0x2000).unwrap() {
            MapEntry::Mapped(m) => {
                assert_eq!(m.size, 0x2000);
                assert_eq!(m.rights, Rights::RX);
            }
            _ => panic!(),
        }
    }

    // ── Zero-size contribution is a no-op ──────────────────────

    #[test]
    fn zero_size_contribution_noop() {
        let mut map = AddressMap::new();
        map.add_contribution(0x0, 0x0, 0, Rights::RW, false).unwrap();
        assert!(map.entries().is_empty());
    }

    // ── Existing insert() API still works ──────────────────────
    // (Compatibility: legacy insert adds a single segment.)

    #[test]
    fn legacy_insert_then_add_contribution() {
        let mut map = AddressMap::new();
        ins(&mut map, 0x0, 0x4000, Rights::RW, None).unwrap();

        // Now overlay with add_contribution for an alias.
        map.add_contribution(0x1000, 0x1000, 0x1000, Rights::RX, false).unwrap();

        assert_eq!(map.entries().len(), 3);
        match map.entries().get(&0x1000).unwrap() {
            MapEntry::Mapped(m) => assert_eq!(m.rights, Rights::RWX),
            _ => panic!(),
        }
    }
}
