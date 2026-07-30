//! Revoke test workload — a long-lived spinner that emits a periodic
//! heartbeat on the serial console.
//!
//! Purpose: driver for the cross-core `REVOKE_DOMAIN` integration test.
//! The test harness (dom0 shell script) boots this workload, waits until
//! it sees enough heartbeats to know the child is running on a
//! capavisor core, then closes the CHV partition fd.  thhv's
//! `partition_destroy` fires `themis_revoke_domain`; the capavisor's
//! cross-core protocol must swap the child off, tear it down, and
//! resume dom0 without panicking.
//!
//! Heartbeat prefix `[EUNOMIA-REVOKE]` is grep'd by the harness.

#![no_std]
#![no_main]

extern crate eunomia;

use core::hint::spin_loop;

#[no_mangle]
pub fn app_main(_services: &eunomia::KernelServices) -> ! {
    eunomia::println!("[EUNOMIA-REVOKE] alive");

    // Emit a few heartbeats so the harness sees us running, then drop
    // into a permanent tight-spin (NO println, NO VMEXIT) so that when
    // the harness fires REVOKE_DOMAIN from another dom0 core, the child
    // is guaranteed to be actively running in guest mode — exercising
    // the cross-core swap (INIT-preempt Case A) path.
    let mut beat: u64 = 0;
    for _ in 0..3 {
        for _ in 0..10_000_000u64 {
            spin_loop();
        }
        beat = beat.wrapping_add(1);
        eunomia::println!("[EUNOMIA-REVOKE] beat={}", beat);
    }
    eunomia::println!("[EUNOMIA-REVOKE] entering steady spin");
    loop {
        spin_loop();
    }
}
