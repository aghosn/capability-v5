//! Timer test workload — verifies TSC-deadline LAPIC timer fires.

use core::sync::atomic::Ordering;
use eunomia::test_harness::TestCase;

static TESTS: &[TestCase] = &[
    TestCase { name: "timer_fires", func: test_timer_fires },
];

pub fn app_main(_services: &eunomia::KernelServices) -> ! {
    eunomia::test_harness::run(TESTS);
}

fn test_timer_fires() -> Result<(), &'static str> {
    eunomia::timer::init();

    let before = eunomia::timer::TIMER_TICKS.load(Ordering::SeqCst);

    // Arm timer with a large count (fires after ~1M LAPIC ticks).
    eunomia::timer::arm(1_000_000);

    // Enable interrupts so the timer can fire.
    unsafe { core::arch::asm!("sti"); }

    // Busy-wait with ~100ms timeout.
    let timeout = eunomia::timer::now() + 200_000_000;
    loop {
        let ticks = eunomia::timer::TIMER_TICKS.load(Ordering::SeqCst);
        if ticks > before {
            unsafe { core::arch::asm!("cli"); }
            return Ok(());
        }
        if eunomia::timer::now() > timeout {
            unsafe { core::arch::asm!("cli"); }
            return Err("timer did not fire within timeout");
        }
        core::hint::spin_loop();
    }
}
