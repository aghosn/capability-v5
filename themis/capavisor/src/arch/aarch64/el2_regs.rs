//! AArch64 EL2 system register configuration.
//!
//! Configures HCR_EL2 (hypervisor control), CPTR_EL2, and other EL2
//! control registers needed before entering a guest.

use crate::serial_println;

// ── HCR_EL2 bit definitions ─────────────────────────────────────────────── //

/// VM — Virtualization enable (Stage-2 translation).
pub const HCR_VM: u64 = 1 << 0;
/// SWIO — Set/Way Invalidation Override.
pub const HCR_SWIO: u64 = 1 << 1;
/// FMO — Physical FIQ routing to EL2.
pub const HCR_FMO: u64 = 1 << 3;
/// IMO — Physical IRQ routing to EL2.
pub const HCR_IMO: u64 = 1 << 4;
/// AMO — Physical SError/Async abort routing to EL2.
pub const HCR_AMO: u64 = 1 << 5;
/// TWI — Trap WFI to EL2.
pub const HCR_TWI: u64 = 1 << 13;
/// TWE — Trap WFE to EL2.
pub const HCR_TWE: u64 = 1 << 14;
/// TSC — Trap SMC to EL2.
pub const HCR_TSC: u64 = 1 << 19;
/// TACR — Trap ACTLR to EL2.
pub const HCR_TACR: u64 = 1 << 21;
/// RW — EL1 is AArch64 (if 0, EL1 is AArch32).
pub const HCR_RW: u64 = 1 << 31;

// ── CPTR_EL2 bit definitions ─────────────────────────────────────────────── //

/// TFP — Trap FP/SIMD (bit 10). Set to 0 to allow FP access at EL1/EL0.
const CPTR_TFP: u64 = 1 << 10;
/// TCPAC — Trap CPACR_EL1 access (bit 31). Set to 0 to not trap.
const CPTR_TCPAC: u64 = 1 << 31;
/// RES1 bits for non-VHE CPTR_EL2 (bits 13:12, 9, 7:0 — all ones).
const CPTR_RES1: u64 = 0x33FF;

/// Configure EL2 system registers for hypervisor operation.
///
/// This sets up:
/// - HCR_EL2: enable Stage-2, trap interrupts, EL1=AArch64
/// - CPTR_EL2: don't trap FP/SIMD
///
/// # Safety
/// Must be called at EL2, after MMU is enabled.
pub unsafe fn configure_el2() {
    // ── HCR_EL2: Hypervisor Configuration Register ──────────────────────── //
    // VM=1:  Enable Stage-2 translation (needed for guest isolation)
    // SWIO:  Clean guest S/W cache ops (required for correctness)
    // IMO:   Route physical IRQs to EL2 (hypervisor handles interrupts)
    // FMO:   Route physical FIQs to EL2
    // AMO:   Route physical SErrors to EL2
    // TSC:   Trap SMC to EL2 (guest can't bypass hypervisor)
    // RW:    EL1 runs AArch64
    //
    // NOTE: VM=1 requires VTTBR_EL2 and VTCR_EL2 to be configured before
    // entering a guest. We set VM=0 for now, will enable when Stage-2 is ready.
    let hcr = HCR_SWIO | HCR_IMO | HCR_FMO | HCR_AMO | HCR_TSC | HCR_RW;
    core::arch::asm!("msr HCR_EL2, {}", in(reg) hcr, options(nostack));

    // ── CPTR_EL2: Coprocessor Trap Register ─────────────────────────────── //
    // Don't trap FP/SIMD or CPACR access.
    let cptr = CPTR_RES1 & !CPTR_TFP & !CPTR_TCPAC;
    core::arch::asm!("msr CPTR_EL2, {}", in(reg) cptr, options(nostack));

    // ── CNTHCTL_EL2: Counter-timer Hypervisor Control ───────────────────── //
    // Allow EL1/EL0 to access physical timers without trapping to EL2.
    // EL1PCTEN=1 (bit 0): EL1 can read CNTPCT_EL0
    // EL1PCEN=1 (bit 1): EL1 can access EL1 physical timer
    let cnthctl: u64 = (1 << 0) | (1 << 1);
    core::arch::asm!("msr CNTHCTL_EL2, {}", in(reg) cnthctl, options(nostack));

    // ── CNTVOFF_EL2: Virtual counter offset ─────────────────────────────── //
    // No offset — guest sees real counter value.
    core::arch::asm!("msr CNTVOFF_EL2, xzr", options(nostack));

    core::arch::asm!("isb", options(nostack));

    serial_println!("EL2 sysregs configured (HCR={:#x}, CPTR={:#x})", hcr, cptr);
}
