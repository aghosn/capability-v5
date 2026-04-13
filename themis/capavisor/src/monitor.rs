//! Generic monitor loop — platform-agnostic exit dispatch.
//!
//! This module contains the main run loop that all domains (dom0 and children)
//! execute on each core. The loop:
//!
//! 1. Enters the guest via `Vp::run` (delegates to arch-specific code).
//! 2. Pattern-matches on `SemanticExit` (platform-agnostic policy logic).
//! 3. Delegates back to arch code for local handling or forwards to parent
//!    via the capability engine.
//!
//! Arch-internal exits (XSETBV, INIT, interrupt-window drain) never reach this
//! loop — they are handled inside `run` and return `ArchHandled`.
//!
//! The loop is fully generic over `A: ArchVpOps`. It takes a `Vp<A>` which
//! wraps the arch backend and its VP handle. Policy lookups go through
//! `ThemisPlatform` (the capability-engine bridge, obtained from the global).

use core::sync::atomic::Ordering;

use capability_engine::Platform as _;
use crate::arch_traits::traits::ArchVpOps;
use crate::arch_traits::types::{ExitInfo, SemanticExit, Vp};
use crate::platform::ThemisPlatform;
use crate::serial_println;

// ── Generic monitor loop ──────────────────────────────────────────────────── //

/// Per-core monitor loop: enters the guest, dispatches exits via policy,
/// and delegates to arch or generic handlers. Never returns.
///
/// Takes a platform-agnostic `Vp<A>` which wraps the arch backend and VP
/// handle. All arch-specific operations go through `ArchVpOps` methods.
/// Policy logic (exit trap lookup, interrupt routing) is generic.
pub fn monitor_loop<A: ArchVpOps>(vp: &mut Vp<A>) -> ! {
    loop {
        let platform = get_platform();

        let exit = vp.run();

        match exit {
            SemanticExit::ArchHandled => continue,

            SemanticExit::Shutdown { reason } => {
                serial_println!("[FATAL] Guest shutdown (reason={})", reason);
                halt_forever();
            }

            SemanticExit::Hypercall => {
                vp.dispatch_hypercall();
            }

            SemanticExit::ExternalInterrupt { vector } => {
                handle_external_interrupt(vp, platform, vector);
            }

            SemanticExit::TimerExpired => {
                handle_preemption_timer(vp, platform);
            }

            SemanticExit::PolicyDriven { reason, ref info } => {
                // EPT violation doorbell fast-path: always checked before policy.
                if let ExitInfo::EptViolation { gpa, qualification } = info {
                    if vp.check_doorbell(*gpa, *qualification) {
                        continue;
                    }
                }

                if lookup_exit_trap(platform, reason) {
                    vp.forward_exit(reason);
                } else {
                    vp.handle_local(reason, info);
                }
            }
        }
    }
}

// ── Platform access ───────────────────────────────────────────────────────── //

fn get_platform() -> &'static ThemisPlatform {
    let ptr = crate::PLATFORM_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        serial_println!("[MONITOR] No platform — halting");
        halt_forever();
    }
    // SAFETY: ThemisPlatform lives in CapaState on the BSP stack frame which
    // never returns (_start -> launch -> monitor_loop is divergent).
    unsafe { &*ptr }
}

// ── Policy lookup (generic) ───────────────────────────────────────────────── //

/// Look up whether the current domain's ExitPolicy traps this exit reason.
/// Returns `true` (forward to parent) or `false` (handle locally).
/// Defaults to `true` (fail-closed) if no capability is found.
fn lookup_exit_trap(platform: &ThemisPlatform, reason: u32) -> bool {
    let core_id = platform.get_current_core().unwrap_or(0) as usize;
    platform
        .get_core_cap(core_id)
        .map(|c| c.read().data.policy.exits.get_action(reason).trap)
        .unwrap_or(true)
}

// ── Interrupt handling (generic policy, arch primitives) ───────────────────── //

/// Handle an external interrupt exit.
///
/// Generic policy logic: consults InterruptPolicy to decide routing,
/// then delegates to `Vp::forward_interrupt` for the arch-specific
/// register copy + context switch.
#[allow(unused_variables)]
fn handle_external_interrupt<A: ArchVpOps>(
    vp: &mut Vp<A>,
    platform: &ThemisPlatform,
    vector: u32,
) {
    use crate::arch::vmexit::EXIT_REASON_EXTERNAL_INTERRUPT;

    let core_id = platform.get_current_core().unwrap_or(0) as usize;
    let exit_trap = platform
        .get_core_cap(core_id)
        .map(|c| c.read().data.policy.exits.get_action(
            EXIT_REASON_EXTERNAL_INTERRUPT).trap)
        .unwrap_or(true);

    if !exit_trap {
        return;
    }

    #[cfg(feature = "quantum-sched")]
    {
        use capability_engine::InterruptVisibility;
        if let Some(cap) = platform.get_core_cap(core_id) {
            let vis = cap
                .read()
                .data
                .policy
                .interrupts
                .get_policy(vector as u8)
                .visibility;
            if vis != InterruptVisibility::Deliver {
                if let Some(old) = platform.take_deferred(core_id) {
                    vp.forward_interrupt(old);
                    platform.set_deferred(core_id, vector as u8);
                    return;
                }
                platform.set_deferred(core_id, vector as u8);
                return;
            }
        }
    }

    vp.forward_interrupt(vector as u8);
}

/// Handle preemption timer exit.
///
/// For quantum-sched: flush deferred vectors on quantum expiry.
/// For all domains: reset the timer and resume.
#[allow(unused_variables)]
fn handle_preemption_timer<A: ArchVpOps>(vp: &mut Vp<A>, platform: &ThemisPlatform) {
    #[cfg(feature = "quantum-sched")]
    {
        let core_id = platform.get_current_core().unwrap_or(0) as usize;
        if let Some(vec) = platform.take_deferred(core_id) {
            vp.reset_timer();
            vp.forward_interrupt(vec);
            return;
        }
    }

    vp.reset_timer();
}

// ── Utility ───────────────────────────────────────────────────────────────── //

fn halt_forever() -> ! {
    loop {
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}
