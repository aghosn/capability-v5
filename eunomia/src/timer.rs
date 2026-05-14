//! Timer interrupt support via LAPIC TSC-deadline mode.
//!
//! Programs the LAPIC timer in TSC-deadline mode (WRMSR to IA32_TSC_DEADLINE).
//! This is the modern path used by all real guest OSes and is properly emulated
//! by the capavisor (WRMSR trap → forwarded to CHV → timerfd → irqfd injection).

use core::sync::atomic::AtomicU64;

/// Timer interrupt vector.  Must match CHV's LOCAL_TIMER_VECTOR (0xEC)
/// so that the timerfd→irqfd injection path delivers on this vector.
pub const TIMER_VECTOR: u8 = 0xEC;

/// Counter incremented by the timer ISR.
pub static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

// LAPIC MMIO base (default, identity-mapped).
const LAPIC_BASE: u64 = 0xFEE0_0000;
// LAPIC register offsets.
const LAPIC_SVR: u64 = 0x0F0;
const LAPIC_LVT_TIMER: u64 = 0x320;
const LAPIC_EOI: u64 = 0x0B0;

/// IA32_TSC_DEADLINE MSR number.
const IA32_TSC_DEADLINE: u32 = 0x6E0;

/// LVT timer mode: TSC-deadline (bits[18:17] = 10).
const LVT_TSC_DEADLINE_MODE: u32 = 0b10 << 17;

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

#[inline(always)]
unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    core::arch::asm!("wrmsr", in("ecx") msr, in("eax") lo, in("edx") hi, options(nostack));
}

/// Initialise the LAPIC timer in TSC-deadline mode on `TIMER_VECTOR`.
pub fn init() {
    unsafe {
        // Enable LAPIC (SVR bit 8 = APIC Software Enable).
        let svr = lapic_read(LAPIC_SVR);
        lapic_write(LAPIC_SVR, svr | (1 << 8));

        // LVT timer: TSC-deadline mode (bits[18:17]=10), vector, unmasked.
        lapic_write(LAPIC_LVT_TIMER, LVT_TSC_DEADLINE_MODE | TIMER_VECTOR as u32);
    }
}

/// Arm the timer to fire when TSC reaches `now() + tsc_delta`.
pub fn arm(tsc_delta: u64) {
    let deadline = rdtsc() + tsc_delta;
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
