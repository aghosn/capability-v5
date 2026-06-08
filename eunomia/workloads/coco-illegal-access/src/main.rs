//! coco-illegal-access — confidential workload that just busy-loops with a
//! recognizable sentinel pattern in its heap.
//!
//! This workload is paired with the `coco-attacker` dom0 user program and
//! exists solely to validate dom0↔dom1 memory isolation:
//!
//!   1. CHV boots us in confidential mode (`--platform confidential=on`),
//!      so the capa-engine CARVE+SEND path strips dom0 EPT for every page
//!      backing this guest.
//!   2. We write a 64-bit sentinel pattern across our heap pages so a leak
//!      would be obvious in the attacker's report.
//!   3. We spin forever, giving the attacker time to enumerate carved HPAs
//!      (via THHV_DEBUG_LIST_HPAS) and probe them.  Every probe must take an
//!      EPT_VIOLATION → #GP(0) → SIGSEGV in the attacker.

#![no_std]
#![no_main]

extern crate alloc;
extern crate eunomia;

use alloc::vec::Vec;

const PAGE_SIZE: usize = 4096;
const SENTINEL: u64 = 0xC0C0_DEAD_BEEF_C0C0;

/// How many pages we touch with the sentinel.
const SENTINEL_PAGES: usize = 64;

#[no_mangle]
pub fn app_main(_services: &eunomia::KernelServices) -> ! {
    eunomia::println!("[coco-illegal-access] up; writing sentinel ...");

    // Pin a buffer in the heap and stamp every 8 bytes with SENTINEL.
    let mut buf: Vec<u64> = Vec::with_capacity(SENTINEL_PAGES * PAGE_SIZE / 8);
    for _ in 0..(SENTINEL_PAGES * PAGE_SIZE / 8) {
        buf.push(SENTINEL);
    }

    // Print the buffer GPA so it is visible in the trace (purely diagnostic;
    // the attacker does not need it — it probes by HPA via thhv).
    let gpa = buf.as_ptr() as u64;
    eunomia::println!(
        "[coco-illegal-access] sentinel buf gpa={:#x} len={} pages, val={:#018x}",
        gpa,
        SENTINEL_PAGES,
        SENTINEL,
    );
    eunomia::println!("[coco-illegal-access] READY — entering busy loop");

    // Keep the value alive by touching it occasionally so the optimizer
    // cannot drop the allocation.  No hlt: we want the vCPU active and the
    // guest pages resident.
    let mut tick: u64 = 0;
    loop {
        // Re-read one cell so the compiler keeps `buf` alive.
        let v = unsafe { core::ptr::read_volatile(buf.as_ptr()) };
        core::hint::black_box(v);
        tick = tick.wrapping_add(1);
        if tick % 0x4000_0000 == 0 {
            eunomia::println!("[coco-illegal-access] alive tick={}", tick);
        }
        core::hint::spin_loop();
    }
}
