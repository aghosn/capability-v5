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
