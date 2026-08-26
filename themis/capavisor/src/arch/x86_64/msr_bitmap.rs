//! Project a domain's [`MsrPolicy`] into the VMX MSR bitmap page.
//!
//! ## Why this exists
//!
//! The MSR bitmap (one page, see SDM Vol 3C §24.6.9) controls which
//! WRMSR/RDMSR instructions cause a VM exit. The capability engine
//! tracks per-domain interposition policy in [`MsrPolicy`]: each MSR is
//! either `Trap`, `Emulate(value)`, or `Native`, with a domain-wide
//! default. Capavisor's monitor loop consults this policy on every MSR
//! exit (see `monitor.rs`), but only MSRs whose bitmap bit is **set**
//! exit in the first place. If the bitmap is more permissive than the
//! policy, the policy is silently bypassed and **A1 is violated**
//! (capability engine never validates the access).
//!
//! This module enforces the invariant **bitmap ⊇ policy**: every MSR
//! that the policy says `Trap` or `Emulate` has its bitmap bit set.
//! `Native` bits are cleared so the access runs without exit.
//!
//! ## Bitmap layout
//!
//! Per SDM Vol 3C §24.6.9, the 4 KiB bitmap is split into four 1 KiB
//! sub-bitmaps:
//!
//! ```text
//!   [   0..1023] RDMSR bitmap, MSRs 0x00000000–0x00001FFF
//!   [1024..2047] RDMSR bitmap, MSRs 0xC0000000–0xC0001FFF
//!   [2048..3071] WRMSR bitmap, MSRs 0x00000000–0x00001FFF
//!   [3072..4095] WRMSR bitmap, MSRs 0xC0000000–0xC0001FFF
//! ```
//!
//! Bit `N` in a sub-bitmap is at byte `N/8`, bit `N%8`. Bit 1 = trap,
//! bit 0 = pass-through. MSRs outside these two ranges always exit.
//!
//! ## Coverage
//!
//! The bitmap can only express trap/no-trap for MSRs in the two covered
//! ranges. Policy entries that fall outside (e.g., a hypothetical
//! `Trap` on MSR `0x40000000`) are no-ops at the bitmap level, but the
//! CPU traps on out-of-range MSR access regardless, so `lookup_msr_action`
//! still gets a chance to enforce the policy.

use capability_engine::interposition::{
    DefaultAction, Msr, MsrPolicy, ProcFeature, ProcFeaturePolicy,
};

/// MSR bitmap page is exactly 4 KiB.
pub const MSR_BITMAP_BYTES: usize = 4096;

const SUB_BITMAP_BYTES: usize = 1024;
const RDMSR_LOW_OFFSET: usize = 0;
const RDMSR_HIGH_OFFSET: usize = SUB_BITMAP_BYTES;
const WRMSR_LOW_OFFSET: usize = 2 * SUB_BITMAP_BYTES;
const WRMSR_HIGH_OFFSET: usize = 3 * SUB_BITMAP_BYTES;

/// Two MSR ranges covered by the bitmap (Intel SDM Vol 3C §24.6.9).
const LOW_RANGE: (u32, u32) = (0x0000_0000, 0x0000_1FFF);
const HIGH_RANGE: (u32, u32) = (0xC000_0000, 0xC000_1FFF);

/// Set the bitmap background to match `default` for **all** covered MSR
/// indices. Overrides previously applied via `apply_range` / `trap_msr`
/// will be clobbered — the caller is expected to re-apply them after
/// (this is how the engine sequences `PolicyChange::MsrDefault` followed
/// by re-emitted override events).
///
/// # Safety
/// Same constraints as [`populate_from_policy`].
pub unsafe fn set_default(bitmap_phys: u64, hhdm: u64, default: DefaultAction) {
    let bitmap = (bitmap_phys + hhdm) as *mut u8;
    let byte: u8 = match default {
        DefaultAction::Trap => 0xFF,
        DefaultAction::Native => 0x00,
    };
    unsafe {
        core::ptr::write_bytes(bitmap, byte, MSR_BITMAP_BYTES);
    }
}

/// Set bits for the inclusive MSR range `[start..=end]` in both the
/// RDMSR and WRMSR sub-bitmaps. `trap = true` forces VM exit on access;
/// `trap = false` makes the access pass through to hardware.
///
/// # Safety
/// Same constraints as [`populate_from_policy`].
pub unsafe fn apply_range(
    bitmap_phys: u64,
    hhdm: u64,
    start: u32,
    end: u32,
    trap: bool,
) {
    let bitmap = (bitmap_phys + hhdm) as *mut u8;
    apply_to_subrange(bitmap, RDMSR_LOW_OFFSET, LOW_RANGE, start, end, trap);
    apply_to_subrange(bitmap, WRMSR_LOW_OFFSET, LOW_RANGE, start, end, trap);
    apply_to_subrange(bitmap, RDMSR_HIGH_OFFSET, HIGH_RANGE, start, end, trap);
    apply_to_subrange(bitmap, WRMSR_HIGH_OFFSET, HIGH_RANGE, start, end, trap);
}

/// Set (or clear) the trap bit for a single MSR in both RDMSR and WRMSR
/// sub-bitmaps. Convenience wrapper around [`apply_range`] for one MSR.
///
/// # Safety
/// Same constraints as [`populate_from_policy`].
pub unsafe fn trap_msr(bitmap_phys: u64, hhdm: u64, msr: u32, trap: bool) {
    unsafe {
        apply_range(bitmap_phys, hhdm, msr, msr, trap);
    }
}

/// Populate the MSR bitmap at `bitmap_phys` (HHDM-mapped) so that every
/// MSR whose policy resolves to `Trap`, `Emulate`, or `EmulateConst` traps,
/// and every MSR whose policy resolves to `Native` runs natively.
///
/// # Safety
/// `bitmap_phys` must be a valid 4 KiB-aligned physical address backing
/// the MSR bitmap page for the VMCS being configured, and the caller
/// must guarantee no concurrent reader (the VMCS must not be loaded on
/// any core, or this must run before first VMENTRY).
pub unsafe fn populate_from_policy(bitmap_phys: u64, hhdm: u64, policy: &MsrPolicy) {
    let bitmap = (bitmap_phys + hhdm) as *mut u8;

    // ── Step 1: fill from the default action ─────────────────────────────
    let default_byte: u8 = match policy.default {
        DefaultAction::Trap => 0xFF, // every covered MSR traps
        DefaultAction::Native => 0x00, // every covered MSR passes through
    };
    unsafe {
        core::ptr::write_bytes(bitmap, default_byte, MSR_BITMAP_BYTES);
    }

    // ── Step 2: apply overrides ─────────────────────────────────────────
    // Each override is a contiguous MSR range with one of three actions.
    // For Trap/Emulate we set the bits (force exit); for Native we clear
    // them (pass-through). Overrides spanning both covered MSR ranges are
    // applied to whichever sub-range they intersect.
    for rule in &policy.overrides {
        let trap_bits = match rule {
            ProcFeaturePolicy::Trap(_)
            | ProcFeaturePolicy::Emulate(_, _)
            | ProcFeaturePolicy::EmulateConst(_, _) => true,
            ProcFeaturePolicy::Native(_) => false,
        };
        let range = rule.range();
        let start = <Msr as ProcFeature>::range_start(range);
        let end = <Msr as ProcFeature>::range_end(range);

        apply_to_subrange(bitmap, RDMSR_LOW_OFFSET, LOW_RANGE, start, end, trap_bits);
        apply_to_subrange(bitmap, WRMSR_LOW_OFFSET, LOW_RANGE, start, end, trap_bits);
        apply_to_subrange(bitmap, RDMSR_HIGH_OFFSET, HIGH_RANGE, start, end, trap_bits);
        apply_to_subrange(bitmap, WRMSR_HIGH_OFFSET, HIGH_RANGE, start, end, trap_bits);
    }
}

/// Set or clear bits for the intersection of `[start..=end]` (inclusive,
/// in absolute MSR numbers) with `sub_range` (the MSR window covered by
/// this 1 KiB sub-bitmap), written into `bitmap[sub_offset..]`.
fn apply_to_subrange(
    bitmap: *mut u8,
    sub_offset: usize,
    sub_range: (u32, u32),
    start: u32,
    end: u32,
    trap: bool,
) {
    let (sub_lo, sub_hi) = sub_range;
    if end < sub_lo || start > sub_hi {
        return;
    }
    let lo = start.max(sub_lo);
    let hi = end.min(sub_hi);

    for msr in lo..=hi {
        let bit_index = (msr - sub_lo) as usize;
        let byte_off = sub_offset + (bit_index / 8);
        let mask = 1u8 << (bit_index % 8);
        unsafe {
            let p = bitmap.add(byte_off);
            let cur = p.read_volatile();
            let next = if trap { cur | mask } else { cur & !mask };
            p.write_volatile(next);
        }
    }
}

/// Returns `true` if `msr` falls in one of the two ranges the bitmap can
/// express (`LOW_RANGE` / `HIGH_RANGE`, SDM Vol 3C §24.6.9). MSRs outside
/// both ranges always cause a VM exit regardless of the bitmap, so callers
/// dispatching a `Native`-policy MSR that still trapped (i.e. it's outside
/// both ranges) use this to distinguish "safe to really pass through" from
/// "must inject #GP" — see `vmexit/msr.rs`'s local handlers.
pub fn in_bitmap_range(msr: u32) -> bool {
    (msr >= LOW_RANGE.0 && msr <= LOW_RANGE.1) || (msr >= HIGH_RANGE.0 && msr <= HIGH_RANGE.1)
}
