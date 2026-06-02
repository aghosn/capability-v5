//! Internal helpers for `ThemisPlatform`: UC-aware EPT mapping and
//! capability-engine `Rights`-to-EPT-flag conversion.
//!
//! NOTE: These helpers are x86-only (EPT-flavored). When porting to
//! ARM, equivalents will live next to the Stage-2 page-table backend.

#![cfg(target_arch = "x86_64")]

use ept::{EptEntryFlags, EptMapper, EptMemoryType};

use crate::mem::UncacheableRanges;

// ── UC-aware EPT range mapping helper ─────────────────────────────────────── //

/// Map `[gpa, gpa+size)` → `[hpa, hpa+size)` into `ept`, splitting the range at
/// UC boundaries so that MMIO sub-ranges use [`EptMemoryType::UC`] and all other
/// sub-ranges use [`EptMemoryType::WB`].
pub(super) fn map_range_typed(
    ept: &mut EptMapper,
    meta: &mut crate::mem::MetaAllocator,
    gpa: u64,
    hpa: u64,
    size: usize,
    flags: EptEntryFlags,
    uc_ranges: &UncacheableRanges,
) {
    let mut cur_gpa = gpa;
    let mut cur_hpa = hpa;
    let mut remaining = size;

    while remaining > 0 {
        match uc_ranges.first_overlap(cur_hpa, remaining as u64) {
            None => {
                ept.map_range(meta, cur_gpa, cur_hpa, remaining, flags, EptMemoryType::WB);
                return;
            }
            Some((ov_start, ov_end)) => {
                if ov_start > cur_hpa {
                    let wb_size = (ov_start - cur_hpa) as usize;
                    ept.map_range(meta, cur_gpa, cur_hpa, wb_size, flags, EptMemoryType::WB);
                    cur_gpa += wb_size as u64;
                    cur_hpa += wb_size as u64;
                    remaining -= wb_size;
                }
                let uc_size = ((ov_end - cur_hpa) as usize).min(remaining);
                ept.map_range(meta, cur_gpa, cur_hpa, uc_size, flags, EptMemoryType::UC);
                cur_gpa += uc_size as u64;
                cur_hpa += uc_size as u64;
                remaining -= uc_size;
            }
        }
    }
}
// ── Helpers ───────────────────────────────────────────────────────────────── //

/// Convert capability-engine `Rights` to EPT entry permission flags.
pub(super) fn rights_to_ept_flags(rights: &capability_engine::Rights) -> EptEntryFlags {
    let mut flags = EptEntryFlags::empty();
    if rights.read() {
        flags |= EptEntryFlags::READ;
    }
    if rights.write() {
        flags |= EptEntryFlags::WRITE;
    }
    if rights.execute() {
        flags |= EptEntryFlags::SUPERVISOR_EXECUTE | EptEntryFlags::USER_EXECUTE;
    }
    flags
}
