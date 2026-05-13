//! Timer interrupt support via LAPIC one-shot mode.
//!
//! Programs the LAPIC timer in one-shot mode with a configurable vector.
//! Uses LAPIC initial-count register for countdown.

use core::sync::atomic::AtomicU64;

/// Timer interrupt vector (above the 32 exception vectors).
pub const TIMER_VECTOR: u8 = 32;

/// Counter incremented by the timer ISR.
pub static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

// LAPIC MMIO base (default, identity-mapped).
const LAPIC_BASE: u64 = 0xFEE0_0000;
// LAPIC register offsets.
const LAPIC_SVR: u64 = 0x0F0;
const LAPIC_LVT_TIMER: u64 = 0x320;
const LAPIC_EOI: u64 = 0x0B0;
const LAPIC_TIMER_ICR: u64 = 0x380; // Initial count register
const LAPIC_TIMER_DCR: u64 = 0x3E0; // Divide configuration register

#[inline(always)]
unsafe fn lapic_read(offset: u64) -> u32 {
    let addr = (LAPIC_BASE + offset) as *const u32;
    core::ptr::read_volatile(addr)
}

#[inline(always)]
unsafe fn lapic_write(offset: u64, val: u32) {
    let addr = (LAPIC_BASE + offset) as *mut u32;
    core::ptr::write_volatile(addr, val);
}

#[inline(always)]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack));
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Initialise the LAPIC timer in one-shot mode on `TIMER_VECTOR`.
pub fn init() {
    unsafe {
        // Enable LAPIC (SVR bit 8 = APIC Software Enable).
        let svr = lapic_read(LAPIC_SVR);
        lapic_write(LAPIC_SVR, svr | (1 << 8));

        // Divide configuration: divide by 1 (0x0B).
        lapic_write(LAPIC_TIMER_DCR, 0x0B);

        // LVT timer: one-shot mode (bits[18:17]=00), vector, unmasked.
        lapic_write(LAPIC_LVT_TIMER, TIMER_VECTOR as u32);
    }
}

/// Arm the timer to fire after `count` LAPIC timer ticks.
pub fn arm(count: u32) {
    unsafe {
        lapic_write(LAPIC_TIMER_ICR, count);
    }
}

/// Send EOI to the LAPIC (called from the ISR).
pub fn eoi() {
    unsafe {
        lapic_write(LAPIC_EOI, 0);
    }
}

/// Read the current TSC value.
pub fn now() -> u64 {
    rdtsc()
}
