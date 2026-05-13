//! Timer interrupt support via LAPIC TSC-deadline mode.
//!
//! Programs the LAPIC timer in TSC-deadline mode (WRMSR 0x6E0) and
//! delivers interrupts on a configurable vector.

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

// LVT timer mode bits.
const LVT_TSC_DEADLINE: u32 = 2 << 17; // bits [18:17] = 10b
const _LVT_MASKED: u32 = 1 << 16;

// MSR for TSC-deadline.
const IA32_TSC_DEADLINE: u32 = 0x6E0;

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
unsafe fn wrmsr(msr: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    core::arch::asm!("wrmsr", in("ecx") msr, in("eax") lo, in("edx") hi);
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

/// Initialise the LAPIC timer in TSC-deadline mode on `TIMER_VECTOR`.
pub fn init() {
    unsafe {
        // Enable LAPIC (SVR bit 8 = APIC Software Enable).
        let svr = lapic_read(LAPIC_SVR);
        lapic_write(LAPIC_SVR, svr | (1 << 8));

        // Configure LVT timer: TSC-deadline mode, our vector, unmasked.
        lapic_write(LAPIC_LVT_TIMER, LVT_TSC_DEADLINE | (TIMER_VECTOR as u32));
    }
}

/// Arm a one-shot timer at the given absolute TSC deadline.
pub fn arm(deadline: u64) {
    unsafe {
        wrmsr(IA32_TSC_DEADLINE, deadline);
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
