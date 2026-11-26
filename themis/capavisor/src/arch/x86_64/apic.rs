//! Minimal Local APIC (LAPIC) operations needed by the capavisor.
//!
//! These are intentionally narrow: read the current core's LAPIC ID and
//! wake a remote monitor using an INIT IPI. Full
//! LAPIC virtualisation lives in the VAPIC (virtual APIC) page handed to
//! guests via the VMCS.

use crate::arch::x86_64::layout::{APIC_REG_ICR_HIGH, APIC_REG_ICR_LOW, LAPIC_MMIO_BASE};

/// Return the physical LAPIC ID of the calling CPU via CPUID leaf 1.
#[inline]
pub(crate) fn current_lapic_id() -> u32 {
    let cpuid = core::arch::x86_64::__cpuid(1);
    (cpuid.ebx >> 24) as u32
}

/// Send an INIT IPI to the physical LAPIC
/// identified by `ndst_lapic_id`, using the xAPIC Interrupt Command
/// Register (ICR) at MMIO offset `0x300`/`0x310` from `hhdm +
/// LAPIC_MMIO_BASE` (`0xFEE0_0000`).
///
/// INIT exits non-root mode independently of pin controls. Hardware posted
/// interrupts are disabled, so a fixed notification vector would instead
/// reach the guest as an unrelated interrupt.
///
/// # Safety
/// Must be called from VMX root mode.  Caller is responsible for the
/// surrounding ordering (e.g. setting `PID.ON = 1` before this call so
/// the target core observes the request when it processes the PID).
pub(crate) unsafe fn send_monitor_ipi(ndst_lapic_id: u32, hhdm: u64) {
    let apic_base = hhdm + LAPIC_MMIO_BASE;
    unsafe {
        let icr_hi = (apic_base + APIC_REG_ICR_HIGH) as *mut u32;
        let icr_lo = (apic_base + APIC_REG_ICR_LOW) as *mut u32;
        core::ptr::write_volatile(icr_hi, ndst_lapic_id << 24);
        core::ptr::write_volatile(icr_lo, (1u32 << 14) | (0x5u32 << 8));
    }
}
