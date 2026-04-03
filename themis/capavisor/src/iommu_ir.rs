//! VT-d Interrupt Remapping Table (IRT) management.
//!
//! Each DRHD unit has one 4 KiB IRT page holding 256 × 16-byte IRTEs.
//! IRTE index N is used for interrupt vector N (1:1 mapping).
//!
//! Three IRTE modes are supported:
//!
//! - **Remapped** (`irte_program_remapped`): fixed delivery to a specific LAPIC
//!   and vector.  Used for `Report`/`NotReport` vectors — the interrupt is
//!   delivered to the capavisor's notification LAPIC so it can decide routing.
//!
//! - **Posted** (`irte_program_posted`): direct delivery into a VP's Posted
//!   Interrupt Descriptor (PID).  Used for `Deliver` vectors — the IOMMU sets
//!   `PID.PIR[V]` and sends a notification IPI, and the interrupt arrives in
//!   the guest with **no VM exit**.
//!
//! - **Invalid** (`irte_invalidate`): clears Present; the IOMMU will fault or
//!   ignore any interrupt arriving at this index.
//!
//! # IRTE write ordering
//! The VT-d spec requires that a Present IRTE is updated by:
//! 1. Clear `P` (write low word with `P=0`).
//! 2. Write the high word (PDA for posted, source-id for remapped).
//! 3. Write the low word with the final value (`P=1`).
//!
//! `irte_write` follows this protocol for both modes.
//!
//! # Invalidation
//! On QEMU the emulated IOMMU re-reads each IRTE on every interrupt, so
//! clearing `P` is sufficient for `irte_invalidate`.  On real hardware an
//! IEC (Interrupt Entry Cache) invalidation descriptor must be submitted via
//! the Invalidation Queue — this is deferred to a later phase.

/// Notification vector sent to a core when a posted interrupt is signalled
/// via IPI (same constant as `vmcs::POSTED_INTR_NOTIFY_VEC`).
const NV: u8 = crate::vmcs::POSTED_INTR_NOTIFY_VEC;

// ── Public API ─────────────────────────────────────────────────────────── //

/// Program a **remapped** IRTE at `index` in the IRT page at `irt_phys`.
///
/// Fixed delivery to `lapic_id` (physical APIC ID) with interrupt `vector`.
/// Trigger mode is edge (`TM=0`); delivery mode is Fixed (`DLM=000`).
///
/// Used for `Report`/`NotReport` vectors: the interrupt arrives at the
/// capavisor notification path rather than directly in a child VP.
///
/// # Safety
/// `irt_phys` must be a valid 4 KiB IRT page accessible via HHDM.
/// `index` must be < 256.
pub(crate) unsafe fn irte_program_remapped(
    irt_phys: u64,
    hhdm: u64,
    index: u8,
    lapic_id: u32,
    vector: u8,
) {
    // Low 64-bit word layout (VT-d spec §9.10, remapped IRTE):
    //   [0]     P  = 1  (present)
    //   [1]     FPD = 0
    //   [2]     DM  = 0 (physical destination mode)
    //   [3]     RH  = 0
    //   [4]     TM  = 0 (edge trigger)
    //   [7:5]   DLM = 0 (fixed delivery)
    //   [23:16] Vector
    //   [63:32] Destination ID (physical APIC ID in low 8 bits = bits[39:32])
    let low = 1u64 | ((vector as u64) << 16) | ((lapic_id as u64) << 32);
    let high = 0u64;
    unsafe { irte_write(irt_phys, hhdm, index, low, high) };
}

/// Program a **posted interrupt** IRTE at `index` in the IRT page at `irt_phys`.
///
/// Sets `IM=1` (posted mode): the IOMMU atomically sets `PID.PIR[vector]`
/// in the target VP's PID, and sends a notification IPI with vector `NV`
/// to `ndst` if `PID.ON` was 0.  Interrupt delivery requires **no VM exit**.
///
/// `ndst` is the physical LAPIC ID of the core where the VP is currently
/// running.  Call `irte_update_ndst` when the VP migrates.
///
/// # Safety
/// `irt_phys` must be a valid 4 KiB IRT page, `pid_phys` a valid 64-byte
/// aligned PID page, both accessible via HHDM.  `index` must be < 256.
pub(crate) unsafe fn irte_program_posted(
    irt_phys: u64,
    hhdm: u64,
    index: u8,
    pid_phys: u64,
    ndst: u32,
) {
    // Low 64-bit word layout (VT-d spec §9.11, posted IRTE):
    //   [0]     P    = 1  (present)
    //   [1]     FPD  = 0
    //   [14:2]  RSVD = 0
    //   [15]    IM   = 1  (posted mode; distinguishes from remapped)
    //   [23:16] NV       (Notification Vector for the IPI sent on ON=0→1)
    //   [31:24] RSVD = 0
    //   [63:32] NDST     (notification destination: physical APIC ID)
    //
    // High 64-bit word:
    //   [63:0]  PDA = pid_phys >> 6  (PID is 64-byte aligned; lower 6 bits = 0)
    let low = 1u64
        | (1u64   << 15)            // IM = 1 (posted mode)
        | ((NV    as u64) << 16)    // Notification Vector
        | ((ndst  as u64) << 32); // NDST
    let high = pid_phys >> 6; // PDA (Posted Interrupt Descriptor Address)
    unsafe { irte_write(irt_phys, hhdm, index, low, high) };
}

/// Update the `NDST` field of an existing posted IRTE in-place.
///
/// Called when a VP migrates to a different physical core after `activate()`,
/// without reprogramming the entire IRTE.
///
/// # Safety
/// `irt_phys` must be a valid IRT page accessible via HHDM.  `index` < 256.
pub(crate) unsafe fn irte_update_ndst(irt_phys: u64, hhdm: u64, index: u8, ndst: u32) {
    let low_ptr = irte_virt(irt_phys, hhdm, index) as *mut u64;
    let low = unsafe { low_ptr.read_volatile() };
    // Replace bits [63:32] (NDST) with the new LAPIC ID.
    let new_low = (low & 0x0000_0000_FFFF_FFFF) | ((ndst as u64) << 32);
    unsafe { low_ptr.write_volatile(new_low) };
}

/// Clear IRTE at `index` — set `P=0` and zero all fields.
///
/// After this call the IOMMU will not match any interrupt to this entry.
/// On QEMU this is immediately effective.  On real hardware, an IEC
/// invalidation descriptor must be submitted to flush the IRTE cache
/// (deferred to a later phase).
///
/// # Safety
/// `irt_phys` must be a valid IRT page accessible via HHDM.  `index` < 256.
pub(crate) unsafe fn irte_invalidate(irt_phys: u64, hhdm: u64, index: u8) {
    unsafe { irte_write(irt_phys, hhdm, index, 0, 0) };
}

// ── Internal helpers ───────────────────────────────────────────────────── //

/// Virtual (HHDM) address of IRTE[index].
#[inline]
fn irte_virt(irt_phys: u64, hhdm: u64, index: u8) -> u64 {
    irt_phys + hhdm + (index as u64) * 16
}

/// Write a 128-bit IRTE following the VT-d update protocol:
/// 1. Write low word with `P=0` (clears present first).
/// 2. Write high word.
/// 3. Write low word with final value (sets `P` to its intended state).
///
/// # Safety
/// Caller must ensure `irt_phys` is valid and `index` < 256.
unsafe fn irte_write(irt_phys: u64, hhdm: u64, index: u8, low: u64, high: u64) {
    let base = irte_virt(irt_phys, hhdm, index);
    let low_ptr = base as *mut u64;
    let high_ptr = (base + 8) as *mut u64;

    unsafe {
        low_ptr.write_volatile(low & !1u64); // step 1: P=0
        high_ptr.write_volatile(high); // step 2: high word
        low_ptr.write_volatile(low); // step 3: final low (P may be 1)
    }
}
