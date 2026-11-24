//! Verify that a parent-owned timer wakes a halted VP repeatedly.

#![no_std]
#![no_main]

use core::sync::atomic::Ordering;
use eunomia::test_harness::TestCase;

extern crate eunomia;

static TESTS: &[TestCase] = &[
    TestCase { name: "timer_wakes_halted_vp", func: test_timer_wakes_halted_vp },
];

#[no_mangle]
pub fn app_main(_services: &eunomia::KernelServices) -> ! {
    eunomia::test_harness::run(TESTS);
}

fn test_timer_wakes_halted_vp() -> Result<(), &'static str> {
    eunomia::timer::init();
    for _ in 0..3 {
        unsafe { core::arch::asm!("cli"); }
        let before = eunomia::timer::TIMER_TICKS.load(Ordering::SeqCst);
        eunomia::timer::arm(150_000_000);
        while eunomia::timer::TIMER_TICKS.load(Ordering::SeqCst) == before {
            unsafe { core::arch::asm!("sti; hlt; cli"); }
        }
    }
    Ok(())
}
