//! MSR virtualization.
//!
//! Centralizes the policy for which MSRs are trapped (vs. passed through to
//! hardware) and how trapped MSRs are emulated on RDMSR / WRMSR VMEXITs.
//!
//! # Design
//!
//! Every MSR that causes a VMEXIT goes through [`handle_rdmsr`] / [`handle_wrmsr`].
//! Each returns an [`MsrResult`] telling the caller what to do:
//!
//! - `Emulated(value)` — the MSR was handled; return `value` to the guest
//!   (RDMSR) or consume the write (WRMSR).
//! - `Passthrough` — read/write the physical MSR on behalf of the guest.
//! - `GpFault` — inject #GP(0).
//!
//! The MSR bitmap (initialized by [`init_bitmap`]) must stay in sync with
//! the handler: every MSR that is trapped in the bitmap must be recognized
//! here, and vice versa.
//!
//! # Extending
//!
//! To emulate a new MSR:
//! 1. Add it to the trapped ranges in [`TRAPPED_RANGES`].
//! 2. Handle it in [`handle_rdmsr`] / [`handle_wrmsr`].
//!    Return `Emulated(value)` for a real emulation or `Emulated(0)` to stub.

use x86::msr;

// ── Trapped MSR ranges ──────────────────────────────────────────────────── //

/// Contiguous ranges of MSR addresses that are trapped (bit = 1) in the MSR
/// bitmap.  All MSRs in these ranges cause VMEXITs on RDMSR / WRMSR.
///
/// Keep sorted by start address for readability.
const TRAPPED_RANGES: &[(u32, u32)] = &[
    // Architectural perf-monitoring counters (IA32_PMC0–7)
    (msr::IA32_PMC0, msr::IA32_PMC7),
    // Perf event selectors (IA32_PERFEVTSEL0–7)
    (msr::IA32_PERFEVTSEL0, msr::IA32_PERFEVTSEL7),
    // Fixed-function counters (IA32_FIXED_CTR0–2)
    (msr::IA32_FIXED_CTR0, msr::IA32_FIXED_CTR2),
    // Perf capabilities
    (msr::IA32_PERF_CAPABILITIES, msr::IA32_PERF_CAPABILITIES),
    // Fixed CTR ctrl + global perf status/ctrl/ovf (0x38D–0x396)
    (msr::IA32_FIXED_CTR_CTRL, 0x396),
    // Uncore counters & ARB perfevtsel (0x3B0–0x3C7)
    (0x3B0, 0x3C7),
    // Full-width architectural counters (IA32_A_PMC0–7)
    (msr::IA32_A_PMC0, msr::IA32_A_PMC7),
    // CBO uncore PMU (0x700–0x73F)
    (0x700, 0x73F),
    // Extended uncore PMU — Rocket Lake / Tiger Lake (0xE00–0xE7F)
    (0xE00, 0xE7F),
];

/// Returns `true` if `msr` falls within any [`TRAPPED_RANGES`] entry.
fn is_trapped(msr: u32) -> bool {
    TRAPPED_RANGES
        .iter()
        .any(|&(lo, hi)| msr >= lo && msr <= hi)
}

// ── Handler return type ─────────────────────────────────────────────────── //

/// Result of an MSR access handled by this module.
pub enum MsrResult {
    /// MSR was emulated; use the contained value (RDMSR) or acknowledge the
    /// write (WRMSR).
    Emulated(u64),
    /// The VMEXIT handler should read/write the physical MSR directly.
    Passthrough,
    /// Inject #GP(0) into the guest.
    #[allow(dead_code)]
    GpFault,
}

// ── RDMSR / WRMSR handlers ──────────────────────────────────────────────── //

/// Handle a trapped RDMSR.
///
/// `ecx` is the MSR index from guest RCX.
pub fn handle_rdmsr(ecx: u32) -> MsrResult {
    if is_trapped(ecx) {
        // TODO: for MSRs that have meaningful emulation (e.g.
        // IA32_PERF_CAPABILITIES), add per-MSR logic here and return
        // `Emulated(real_value)`.  For now stub everything to zero.
        MsrResult::Emulated(0)
    } else {
        MsrResult::Passthrough
    }
}

/// Handle a trapped WRMSR.
///
/// `ecx` is the MSR index, `value` is the 64-bit value the guest wants to
/// write (EDX:EAX combined).
pub fn handle_wrmsr(ecx: u32, _value: u64) -> MsrResult {
    if is_trapped(ecx) {
        // Silently discard writes to perf/uncore MSRs.
        MsrResult::Emulated(0)
    } else {
        MsrResult::Passthrough
    }
}

// ── MSR bitmap initialization ───────────────────────────────────────────── //

/// Initialize the MSR bitmap page at virtual address `bitmap_virt`.
///
/// The page must be 4 KiB and already zeroed (all-passthrough).  This
/// function sets trap bits (read + write) for every MSR listed in
/// [`TRAPPED_RANGES`].
///
/// MSR bitmap layout (Intel SDM §25.6.9):
///   bytes    0–1023: read  bitmap for MSRs 0x00000000–0x00001FFF
///   bytes 1024–2047: read  bitmap for MSRs 0xC0000000–0xC0001FFF
///   bytes 2048–3071: write bitmap for MSRs 0x00000000–0x00001FFF
///   bytes 3072–4095: write bitmap for MSRs 0xC0000000–0xC0001FFF
pub fn init_bitmap(bitmap_virt: *mut u8) {
    for &(lo, hi) in TRAPPED_RANGES {
        for msr in lo..=hi {
            let byte = (msr / 8) as usize;
            let bit = 1u8 << (msr % 8);
            unsafe {
                // Read bitmap (offset 0)
                let p = bitmap_virt.add(byte);
                p.write_volatile(p.read_volatile() | bit);
                // Write bitmap (offset 2048)
                let p = bitmap_virt.add(2048 + byte);
                p.write_volatile(p.read_volatile() | bit);
            }
        }
    }
}

// ── Utility ─────────────────────────────────────────────────────────────── //

/// Returns `true` if `ecx` falls in one of the two ranges covered by the
/// MSR bitmap (0x0000–0x1FFF or 0xC000_0000–0xC000_1FFF).
pub fn in_bitmap_range(ecx: u32) -> bool {
    ecx <= 0x1FFF || (0xC000_0000..=0xC000_1FFF).contains(&ecx)
}
