//! Scheduler test workload — verifies cooperative context switching.

#![no_std]
#![no_main]

extern crate eunomia;

use core::sync::atomic::{AtomicU32, Ordering};
use eunomia::test_harness::TestCase;

static TESTS: &[TestCase] = &[
    TestCase { name: "single_task", func: test_single_task },
    TestCase { name: "two_tasks_interleave", func: test_two_tasks_interleave },
    TestCase { name: "yield_round_robin", func: test_yield_round_robin },
    TestCase { name: "task_names", func: test_task_names },
];

#[no_mangle]
pub fn app_main(_services: &eunomia::KernelServices) -> ! {
    eunomia::test_harness::run(TESTS);
}

// ── Shared counters for inter-task communication ───────────────────────── //

static COUNTER_A: AtomicU32 = AtomicU32::new(0);
static COUNTER_B: AtomicU32 = AtomicU32::new(0);
static ORDER: AtomicU32 = AtomicU32::new(0);

fn reset_counters() {
    COUNTER_A.store(0, Ordering::SeqCst);
    COUNTER_B.store(0, Ordering::SeqCst);
    ORDER.store(0, Ordering::SeqCst);
}

// ── Tests ──────────────────────────────────────────────────────────────── //

fn test_single_task() -> Result<(), &'static str> {
    reset_counters();
    eunomia::sched::init();
    eunomia::sched::spawn("single", || {
        COUNTER_A.store(42, Ordering::SeqCst);
    });
    eunomia::sched::run();

    if COUNTER_A.load(Ordering::SeqCst) != 42 {
        return Err("single task did not run");
    }
    Ok(())
}

fn test_two_tasks_interleave() -> Result<(), &'static str> {
    reset_counters();
    eunomia::sched::init();

    eunomia::sched::spawn("task_a", || {
        ORDER.fetch_add(1, Ordering::SeqCst); // 1
        eunomia::sched::yield_now();
        ORDER.fetch_add(1, Ordering::SeqCst); // 3
    });

    eunomia::sched::spawn("task_b", || {
        ORDER.fetch_add(1, Ordering::SeqCst); // 2
        eunomia::sched::yield_now();
        ORDER.fetch_add(1, Ordering::SeqCst); // 4
    });

    eunomia::sched::run();

    let final_order = ORDER.load(Ordering::SeqCst);
    if final_order != 4 {
        return Err("expected 4 order increments");
    }
    Ok(())
}

fn test_yield_round_robin() -> Result<(), &'static str> {
    reset_counters();
    eunomia::sched::init();

    eunomia::sched::spawn("inc_a", || {
        for _ in 0..5 {
            COUNTER_A.fetch_add(1, Ordering::SeqCst);
            eunomia::sched::yield_now();
        }
    });

    eunomia::sched::spawn("inc_b", || {
        for _ in 0..5 {
            COUNTER_B.fetch_add(1, Ordering::SeqCst);
            eunomia::sched::yield_now();
        }
    });

    eunomia::sched::run();

    let a = COUNTER_A.load(Ordering::SeqCst);
    let b = COUNTER_B.load(Ordering::SeqCst);
    if a != 5 || b != 5 {
        return Err("expected both counters at 5");
    }
    Ok(())
}

fn test_task_names() -> Result<(), &'static str> {
    eunomia::sched::init();
    // Outside run(), current should be "idle".
    if eunomia::sched::current_name() != "idle" {
        return Err("expected idle outside run()");
    }
    Ok(())
}
