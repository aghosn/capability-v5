//! Timer test workload — verifies LAPIC TSC-deadline timer fires.

#![no_std]
#![no_main]

use core::sync::atomic::Ordering;
use eunomia::test_harness::TestCase;

extern crate eunomia;

static TESTS: &[TestCase] = &[
    TestCase { name: "timer_fires", func: test_timer_fires },
];

#[no_mangle]
pub fn app_main(_services: &eunomia::KernelServices) -> ! {
    eunomia::test_harness::run(TESTS);
}

fn test_timer_fires() -> Result<(), &'static str> {
    eunomia::timer::init();

    // The policy under test tells us, via IA32_TSC_DEADLINE's RDMSR-Emulate
    // stored value, whether it expects the timer to actually fire
    // (`deliver.json`, injectable: true) or to be suppressed
    // (`suppress.json`, injectable: false) — see
    // `eunomia::timer::expected_fire` doc comment.
    let expect_fire = eunomia::timer::expected_fire();

    let before = eunomia::timer::TIMER_TICKS.load(Ordering::SeqCst);

    // Arm timer ~1ms in the future (assuming ~3 GHz TSC).
    eunomia::timer::arm(3_000_000);

    // Enable interrupts so the timer can fire.
    unsafe { core::arch::asm!("sti"); }

    // Busy-wait with ~100ms timeout.
    let timeout = eunomia::timer::now() + 200_000_000;
    loop {
        let ticks = eunomia::timer::TIMER_TICKS.load(Ordering::SeqCst);
        if ticks > before {
            unsafe { core::arch::asm!("cli"); }
            return if expect_fire {
                Ok(())
            } else {
                Err("timer fired but policy expected it to be suppressed")
            };
        }
        if eunomia::timer::now() > timeout {
            unsafe { core::arch::asm!("cli"); }
            return if expect_fire {
                Err("timer did not fire within timeout")
            } else {
                Ok(())
            };
        }
        core::hint::spin_loop();
    }
}
