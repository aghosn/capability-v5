//! Unit tests for the generic interposition policy (`ProcFeatureConfig<T>`).
//!
//! Tests cover:
//! - Default action fallback
//! - Range insert and lookup (Trap, Native)
//! - Emulate point entries
//! - Overlap rejection
//! - Sorted insertion order
//! - Remove entries
//! - Update emulate values
//! - Edge cases (adjacent ranges, full u32 range)
//! - Both CPUID and MSR instantiations
//! - CPUID subleaf granularity

use capability_engine::interposition::*;

/// Helper: CPUID range covering all subleaves of leaf range [start, end].
fn cpuid_range(start: u32, end: u32) -> ((u32, u32), (u32, u32)) {
    ((start, 0), (end, u32::MAX))
}

/// Helper: CPUID point entry for a specific (leaf, subleaf).
fn cpuid_point(leaf: u32, subleaf: u32) -> ((u32, u32), (u32, u32)) {
    ((leaf, subleaf), (leaf, subleaf))
}

// ═══════════════════════════════════════════════════════════════════════════ //
//  Basic ProcFeatureConfig operations (using Cpuid as the test vehicle)
// ═══════════════════════════════════════════════════════════════════════════ //

#[test]
fn default_trap_returns_none_on_lookup() {
    let policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    assert!(policy.lookup(&(0x0, 0)).is_none());
    assert!(policy.lookup(&(0x4000_0100, 0)).is_none());
    assert!(policy.lookup(&(u32::MAX, u32::MAX)).is_none());
}

#[test]
fn default_native_returns_none_on_lookup() {
    let policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Native);
    assert!(policy.lookup(&(42, 0)).is_none());
}

#[test]
fn insert_native_range_and_lookup() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    policy.insert_range(cpuid_range(0x10, 0x20), DefaultAction::Native).unwrap();

    // Inside range
    assert!(matches!(
        policy.lookup(&(0x10, 0)),
        Some(ProcFeaturePolicy::Native(_))
    ));
    assert!(matches!(
        policy.lookup(&(0x15, 0)),
        Some(ProcFeaturePolicy::Native(_))
    ));
    assert!(matches!(
        policy.lookup(&(0x20, 0)),
        Some(ProcFeaturePolicy::Native(_))
    ));

    // Outside range → default
    assert!(policy.lookup(&(0x0F, u32::MAX)).is_none());
    assert!(policy.lookup(&(0x21, 0)).is_none());
}

#[test]
fn insert_trap_range_and_lookup() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Native);
    policy.insert_range(cpuid_range(0x100, 0x1FF), DefaultAction::Trap).unwrap();

    assert!(matches!(
        policy.lookup(&(0x150, 0)),
        Some(ProcFeaturePolicy::Trap(_))
    ));
    assert!(policy.lookup(&(0x200, 0)).is_none());
}

#[test]
fn insert_emulate_point_and_lookup() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    let result = CpuidResult { v0: 39, v1: 0x1234, v2: 0x5678, v3: 0x9ABC };
    policy.insert_emulate(cpuid_point(0x4000_0100, 0), result.clone()).unwrap();

    match policy.lookup(&(0x4000_0100, 0)) {
        Some(ProcFeaturePolicy::Emulate(_, v)) => assert_eq!(*v, result),
        other => panic!("expected Emulate, got {:?}", other),
    }

    // Adjacent leaves should not match
    assert!(policy.lookup(&(0x4000_00FF, 0)).is_none());
    assert!(policy.lookup(&(0x4000_0101, 0)).is_none());
    // Different subleaf should not match
    assert!(policy.lookup(&(0x4000_0100, 1)).is_none());
}

#[test]
fn insert_emulate_range_and_lookup() {
    let mut policy: MsrPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    policy.insert_emulate((0x800, 0x83F), 0xDEAD_BEEF).unwrap();

    match policy.lookup(&0x810) {
        Some(ProcFeaturePolicy::Emulate(_, v)) => assert_eq!(*v, 0xDEAD_BEEF),
        other => panic!("expected Emulate, got {:?}", other),
    }
    assert!(policy.lookup(&0x7FF).is_none());
    assert!(policy.lookup(&0x840).is_none());
}

// ═══════════════════════════════════════════════════════════════════════════ //
//  Multiple ranges — sorted order and binary search
// ═══════════════════════════════════════════════════════════════════════════ //

#[test]
fn multiple_ranges_sorted_insertion() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    // Insert out of order
    policy.insert_range(cpuid_range(0x100, 0x1FF), DefaultAction::Native).unwrap();
    policy.insert_range(cpuid_range(0x10, 0x20), DefaultAction::Native).unwrap();
    policy.insert_range(cpuid_range(0x1000, 0x1FFF), DefaultAction::Trap).unwrap();

    // All should be findable
    assert!(matches!(policy.lookup(&(0x15, 0)), Some(ProcFeaturePolicy::Native(_))));
    assert!(matches!(policy.lookup(&(0x150, 0)), Some(ProcFeaturePolicy::Native(_))));
    assert!(matches!(policy.lookup(&(0x1500, 0)), Some(ProcFeaturePolicy::Trap(_))));

    // Gaps between ranges → default
    assert!(policy.lookup(&(0x50, 0)).is_none());
    assert!(policy.lookup(&(0x500, 0)).is_none());
}

#[test]
fn mixed_types_in_overrides() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    policy.insert_range(cpuid_range(0x10, 0x20), DefaultAction::Native).unwrap();
    let result = CpuidResult { v0: 1, v1: 2, v2: 3, v3: 4 };
    policy.insert_emulate(cpuid_point(0x30, 0), result.clone()).unwrap();
    policy.insert_range(cpuid_range(0x40, 0x50), DefaultAction::Trap).unwrap();

    assert!(matches!(policy.lookup(&(0x15, 0)), Some(ProcFeaturePolicy::Native(_))));
    assert!(matches!(policy.lookup(&(0x30, 0)), Some(ProcFeaturePolicy::Emulate(_, _))));
    assert!(matches!(policy.lookup(&(0x45, 0)), Some(ProcFeaturePolicy::Trap(_))));
    assert!(policy.lookup(&(0x25, 0)).is_none());
    assert!(policy.lookup(&(0x35, 0)).is_none());
}

// ═══════════════════════════════════════════════════════════════════════════ //
//  Overlap rejection
// ═══════════════════════════════════════════════════════════════════════════ //

#[test]
fn overlap_exact_same_range() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    policy.insert_range(cpuid_range(0x10, 0x20), DefaultAction::Native).unwrap();
    assert_eq!(
        policy.insert_range(cpuid_range(0x10, 0x20), DefaultAction::Trap),
        Err(InsertError::Overlap)
    );
}

#[test]
fn overlap_partial_left() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    policy.insert_range(cpuid_range(0x10, 0x20), DefaultAction::Native).unwrap();
    assert_eq!(
        policy.insert_range(cpuid_range(0x05, 0x15), DefaultAction::Native),
        Err(InsertError::Overlap)
    );
}

#[test]
fn overlap_partial_right() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    policy.insert_range(cpuid_range(0x10, 0x20), DefaultAction::Native).unwrap();
    assert_eq!(
        policy.insert_range(cpuid_range(0x15, 0x25), DefaultAction::Native),
        Err(InsertError::Overlap)
    );
}

#[test]
fn overlap_contained() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    policy.insert_range(cpuid_range(0x10, 0x20), DefaultAction::Native).unwrap();
    assert_eq!(
        policy.insert_range(cpuid_range(0x12, 0x18), DefaultAction::Trap),
        Err(InsertError::Overlap)
    );
}

#[test]
fn overlap_containing() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    policy.insert_range(cpuid_range(0x10, 0x20), DefaultAction::Native).unwrap();
    assert_eq!(
        policy.insert_range(cpuid_range(0x05, 0x25), DefaultAction::Trap),
        Err(InsertError::Overlap)
    );
}

#[test]
fn overlap_emulate_with_range() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    policy.insert_range(cpuid_range(0x10, 0x20), DefaultAction::Native).unwrap();
    assert_eq!(
        policy.insert_emulate(
            cpuid_point(0x15, 0),
            CpuidResult { v0: 0, v1: 0, v2: 0, v3: 0 }
        ),
        Err(InsertError::Overlap)
    );
}

#[test]
fn adjacent_ranges_no_overlap() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    // Leaf 0x10..0x1F (all subleaves)
    policy.insert_range(cpuid_range(0x10, 0x1F), DefaultAction::Native).unwrap();
    // Leaf 0x20..0x2F (all subleaves) — adjacent leaf, no overlap
    policy.insert_range(cpuid_range(0x20, 0x2F), DefaultAction::Trap).unwrap();

    assert!(matches!(policy.lookup(&(0x1F, 0)), Some(ProcFeaturePolicy::Native(_))));
    assert!(matches!(policy.lookup(&(0x20, 0)), Some(ProcFeaturePolicy::Trap(_))));
}

// ═══════════════════════════════════════════════════════════════════════════ //
//  Invalid range
// ═══════════════════════════════════════════════════════════════════════════ //

#[test]
fn invalid_range_end_less_than_start() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    assert_eq!(
        policy.insert_range(((0x20, 0), (0x10, 0)), DefaultAction::Native),
        Err(InsertError::InvalidRange)
    );
}

// ═══════════════════════════════════════════════════════════════════════════ //
//  Remove
// ═══════════════════════════════════════════════════════════════════════════ //

#[test]
fn remove_existing_entry() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    policy.insert_range(cpuid_range(0x10, 0x20), DefaultAction::Native).unwrap();
    assert!(policy.lookup(&(0x15, 0)).is_some());

    assert!(policy.remove(&(0x15, 0)));
    assert!(policy.lookup(&(0x15, 0)).is_none());
}

#[test]
fn remove_nonexistent_returns_false() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    assert!(!policy.remove(&(0x42, 0)));
}

// ═══════════════════════════════════════════════════════════════════════════ //
//  Update emulate value
// ═══════════════════════════════════════════════════════════════════════════ //

#[test]
fn update_emulate_value_success() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    let v1 = CpuidResult { v0: 1, v1: 2, v2: 3, v3: 4 };
    let v2 = CpuidResult { v0: 10, v1: 20, v2: 30, v3: 40 };
    policy.insert_emulate(cpuid_point(0x100, 0), v1).unwrap();

    policy.update_emulate_value(&(0x100, 0), v2.clone()).unwrap();

    match policy.lookup(&(0x100, 0)) {
        Some(ProcFeaturePolicy::Emulate(_, v)) => assert_eq!(*v, v2),
        other => panic!("expected Emulate, got {:?}", other),
    }
}

#[test]
fn update_emulate_value_not_found() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    let v = CpuidResult { v0: 1, v1: 2, v2: 3, v3: 4 };
    assert_eq!(
        policy.update_emulate_value(&(0x100, 0), v),
        Err(InsertError::NotFound)
    );
}

#[test]
fn update_emulate_on_native_range_fails() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    policy.insert_range(cpuid_range(0x100, 0x200), DefaultAction::Native).unwrap();
    let v = CpuidResult { v0: 1, v1: 2, v2: 3, v3: 4 };
    assert_eq!(
        policy.update_emulate_value(&(0x150, 0), v),
        Err(InsertError::NotFound)
    );
}

// ═══════════════════════════════════════════════════════════════════════════ //
//  EmulateConst — read-only emulate (write always discarded)
// ═══════════════════════════════════════════════════════════════════════════ //

#[test]
fn insert_emulate_const_and_lookup() {
    let mut policy: MsrPolicy = ProcFeatureConfig::new(DefaultAction::Native);
    policy.insert_emulate_const((0x300, 0x33F), 0).unwrap();

    match policy.lookup(&0x310) {
        Some(ProcFeaturePolicy::EmulateConst(_, v)) => assert_eq!(*v, 0),
        other => panic!("expected EmulateConst, got {:?}", other),
    }
    assert!(policy.lookup(&0x2FF).is_none());
    assert!(policy.lookup(&0x340).is_none());
}

#[test]
fn update_emulate_value_never_matches_emulate_const() {
    // The whole point of EmulateConst: `update_emulate_value` — the API
    // capavisor's generic WRMSR/CPUID-write dispatch calls to implement
    // the writable "scratch register" Emulate semantics — must never be
    // able to mutate an EmulateConst entry. A write targeting one must
    // report NotFound so the caller discards it, leaving reads pinned to
    // the value set at creation forever.
    let mut policy: MsrPolicy = ProcFeatureConfig::new(DefaultAction::Native);
    policy.insert_emulate_const((0x300, 0x33F), 0).unwrap();

    assert_eq!(
        policy.update_emulate_value(&0x310, 0xFFFF_FFFF),
        Err(InsertError::NotFound)
    );
    // Value must be unchanged.
    match policy.lookup(&0x310) {
        Some(ProcFeaturePolicy::EmulateConst(_, v)) => assert_eq!(*v, 0),
        other => panic!("expected EmulateConst still at 0, got {:?}", other),
    }
}

#[test]
fn emulate_const_overlaps_with_emulate_and_trap() {
    // EmulateConst must participate in overlap checking exactly like every
    // other override kind — it's still a range claim in the same table.
    let mut policy: MsrPolicy = ProcFeatureConfig::new(DefaultAction::Native);
    policy.insert_emulate_const((0x300, 0x33F), 0).unwrap();

    assert_eq!(
        policy.insert_emulate((0x320, 0x350), 1),
        Err(InsertError::Overlap)
    );
    assert_eq!(
        policy.insert_range((0x2F0, 0x300), DefaultAction::Trap),
        Err(InsertError::Overlap)
    );
    // Adjacent, non-overlapping range is fine.
    policy.insert_emulate((0x340, 0x350), 1).unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════ //
//  Edge cases
// ═══════════════════════════════════════════════════════════════════════════ //

#[test]
fn single_point_range() {
    let mut policy: MsrPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    policy.insert_range((0x6E0, 0x6E0), DefaultAction::Native).unwrap();

    assert!(matches!(policy.lookup(&0x6E0), Some(ProcFeaturePolicy::Native(_))));
    assert!(policy.lookup(&0x6DF).is_none());
    assert!(policy.lookup(&0x6E1).is_none());
}

#[test]
fn boundary_values_u32() {
    let mut policy: MsrPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    policy.insert_range((0, 0), DefaultAction::Native).unwrap();
    policy.insert_range((u32::MAX, u32::MAX), DefaultAction::Native).unwrap();

    assert!(matches!(policy.lookup(&0), Some(ProcFeaturePolicy::Native(_))));
    assert!(matches!(policy.lookup(&u32::MAX), Some(ProcFeaturePolicy::Native(_))));
    assert!(policy.lookup(&1).is_none());
    assert!(policy.lookup(&(u32::MAX - 1)).is_none());
}

#[test]
fn range_helper_extracts_correctly() {
    let r = cpuid_range(0x10, 0x20);
    let policy_entry: ProcFeaturePolicy<Cpuid> = ProcFeaturePolicy::Trap(r);
    assert_eq!(*policy_entry.range(), r);

    let r2 = cpuid_range(0x30, 0x40);
    let policy_entry: ProcFeaturePolicy<Cpuid> = ProcFeaturePolicy::Native(r2);
    assert_eq!(*policy_entry.range(), r2);

    let v = CpuidResult { v0: 1, v1: 2, v2: 3, v3: 4 };
    let r3 = cpuid_point(0x50, 0);
    let policy_entry: ProcFeaturePolicy<Cpuid> = ProcFeaturePolicy::Emulate(r3, v);
    assert_eq!(*policy_entry.range(), r3);
}

// ═══════════════════════════════════════════════════════════════════════════ //
//  MSR-specific tests
// ═══════════════════════════════════════════════════════════════════════════ //

#[test]
fn msr_emulate_u64_value() {
    let mut policy: MsrPolicy = ProcFeatureConfig::new(DefaultAction::Native);
    policy.insert_emulate((0xC000_0080, 0xC000_0080), 0xDEAD_BEEF_CAFE_BABE).unwrap();

    match policy.lookup(&0xC000_0080) {
        Some(ProcFeaturePolicy::Emulate(_, v)) => {
            assert_eq!(*v, 0xDEAD_BEEF_CAFE_BABE);
        }
        other => panic!("expected Emulate, got {:?}", other),
    }
}

#[test]
fn msr_x2apic_range_native() {
    let mut policy: MsrPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    policy.insert_range((0x800, 0x83F), DefaultAction::Native).unwrap();

    for msr in 0x800..=0x83F {
        assert!(matches!(
            policy.lookup(&msr),
            Some(ProcFeaturePolicy::Native(_))
        ));
    }
    assert!(policy.lookup(&0x7FF).is_none());
    assert!(policy.lookup(&0x840).is_none());
}

// ═══════════════════════════════════════════════════════════════════════════ //
//  CoCo scenario: CPUID 0x4000_0100 emulate
// ═══════════════════════════════════════════════════════════════════════════ //

#[test]
fn coco_cpuid_scenario() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);

    // Themis hypervisor leaves: native (all subleaves)
    policy.insert_range(cpuid_range(0x4000_0000, 0x4000_00FF), DefaultAction::Native).unwrap();

    // CoCo detection leaf: emulate with VTOM=39 + signature (subleaf 0 only)
    let coco = CpuidResult {
        v0: 39,
        v1: u32::from_le_bytes(*b"Them"),
        v2: u32::from_le_bytes(*b"isCo"),
        v3: u32::from_le_bytes(*b"Co\0\0"),
    };
    policy.insert_emulate(cpuid_point(0x4000_0100, 0), coco.clone()).unwrap();

    // TSC leaf: native (all subleaves)
    policy.insert_range(cpuid_range(0x15, 0x15), DefaultAction::Native).unwrap();

    // CoCo leaf returns emulated values
    match policy.lookup(&(0x4000_0100, 0)) {
        Some(ProcFeaturePolicy::Emulate(_, v)) => {
            assert_eq!(v.v0, 39);
            assert_eq!(v.v1, u32::from_le_bytes(*b"Them"));
            assert_eq!(v.v2, u32::from_le_bytes(*b"isCo"));
            assert_eq!(v.v3, u32::from_le_bytes(*b"Co\0\0"));
        }
        other => panic!("expected Emulate for CoCo leaf, got {:?}", other),
    }

    // Themis base leaf: native
    assert!(matches!(
        policy.lookup(&(0x4000_0000, 0)),
        Some(ProcFeaturePolicy::Native(_))
    ));

    // TSC leaf: native
    assert!(matches!(
        policy.lookup(&(0x15, 0)),
        Some(ProcFeaturePolicy::Native(_))
    ));

    // Random leaf: default (Trap)
    assert!(policy.lookup(&(0x0B, 0)).is_none());
}

#[test]
fn dom0_no_coco_leaf() {
    // Dom0 policy: native by default, no CoCo emulate entry
    let policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Native);

    // CoCo leaf → default (Native, returns native CPUID which won't have Themis signature)
    assert!(policy.lookup(&(0x4000_0100, 0)).is_none());
}

// ═══════════════════════════════════════════════════════════════════════════ //
//  CPUID subleaf granularity
// ═══════════════════════════════════════════════════════════════════════════ //

#[test]
fn subleaf_distinct_emulate_entries() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);

    let sub0 = CpuidResult { v0: 0xA, v1: 0xB, v2: 0xC, v3: 0xD };
    let sub1 = CpuidResult { v0: 0x1, v1: 0x2, v2: 0x3, v3: 0x4 };

    policy.insert_emulate(cpuid_point(0x7, 0), sub0.clone()).unwrap();
    policy.insert_emulate(cpuid_point(0x7, 1), sub1.clone()).unwrap();

    // Each subleaf returns its own value
    match policy.lookup(&(0x7, 0)) {
        Some(ProcFeaturePolicy::Emulate(_, v)) => assert_eq!(*v, sub0),
        other => panic!("expected sub0 Emulate, got {:?}", other),
    }
    match policy.lookup(&(0x7, 1)) {
        Some(ProcFeaturePolicy::Emulate(_, v)) => assert_eq!(*v, sub1),
        other => panic!("expected sub1 Emulate, got {:?}", other),
    }

    // Subleaf 2 → default (Trap)
    assert!(policy.lookup(&(0x7, 2)).is_none());
}

#[test]
fn subleaf_range_covers_all_subleaves() {
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);
    policy.insert_range(cpuid_range(0x10, 0x10), DefaultAction::Native).unwrap();

    // All subleaves of leaf 0x10 should match
    assert!(matches!(policy.lookup(&(0x10, 0)), Some(ProcFeaturePolicy::Native(_))));
    assert!(matches!(policy.lookup(&(0x10, 1)), Some(ProcFeaturePolicy::Native(_))));
    assert!(matches!(policy.lookup(&(0x10, 100)), Some(ProcFeaturePolicy::Native(_))));
    assert!(matches!(policy.lookup(&(0x10, u32::MAX)), Some(ProcFeaturePolicy::Native(_))));

    // Different leaf → default
    assert!(policy.lookup(&(0x11, 0)).is_none());
}

#[test]
fn subleaf_emulate_no_cross_contamination() {
    // Regression test: previously bulk CPUID push caused subleaf 1 queries
    // to return subleaf 0 values because Input was u32 (leaf only).
    let mut policy: CpuidPolicy = ProcFeatureConfig::new(DefaultAction::Trap);

    let sub0_vals = CpuidResult { v0: 0xDEAD, v1: 0xBEEF, v2: 0xCAFE, v3: 0xBABE };
    policy.insert_emulate(cpuid_point(0x7, 0), sub0_vals.clone()).unwrap();

    // Subleaf 0 matches
    assert!(matches!(policy.lookup(&(0x7, 0)), Some(ProcFeaturePolicy::Emulate(_, _))));
    // Subleaf 1 does NOT match — falls through to default
    assert!(policy.lookup(&(0x7, 1)).is_none());
}
