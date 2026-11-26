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

use crate::arch_traits::traits::ArchVpOps;
use crate::arch_traits::types::{ExitInfo, SemanticExit, Vp};
use crate::platform::ThemisPlatform;
use crate::serial_println;
use capability_engine::{Capability, FeatureAction as InterpositionAction, Platform as _};

// ── Generic monitor loop ──────────────────────────────────────────────────── //

/// Per-core monitor loop: enters the guest, dispatches exits via policy,
/// and delegates to arch or generic handlers. Never returns.
///
/// Takes a platform-agnostic `Vp<A>` which wraps the arch backend and VP
/// handle. All arch-specific operations go through `ArchVpOps` methods.
/// Policy logic (exit trap lookup, interrupt routing) is generic.
pub fn monitor_loop<A: ArchVpOps>(vp: &mut Vp<A>) -> ! {
    // Pin the ActiveVcpu pointer in this core's CoreContext so that
    // Platform::poll_and_respond_cross_core can reach it when applying
    // cross-core Switch updates (VMCLEAR/VMPTRLD).  monitor_loop is
    // divergent — the Vp<A> lives forever at this stack address, so
    // no clear needed.
    {
        let platform = get_platform();
        if let Some(core_id) = platform.get_current_core() {
            platform.pin_active_vcpu(core_id, &mut vp.handle as *mut _ as *mut u8);
        }
    }

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
                handle_policy_exit(vp, platform, reason, info);
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

// ── Policy-driven exit handling ───────────────────────────────────────────── //

fn policy_or_halt<T>(result: capability_engine::Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            serial_println!("[MONITOR] engine policy/state failure: {:?}", error);
            halt_forever();
        }
    }
}

fn handle_policy_exit<A: ArchVpOps>(
    vp: &mut Vp<A>,
    platform: &ThemisPlatform,
    reason: u32,
    info: &ExitInfo,
) {
    let core = policy_or_halt(
        platform
            .get_current_core()
            .ok_or(capability_engine::CapaError::NotFound),
    );
    let binding = policy_or_halt(platform.switch_manager().get_core(core).and_then(|core| {
        core.current_binding()
            .ok_or(capability_engine::CapaError::NotFound)
    }));
    policy_or_halt(Capability::with_vp_exit(platform, &binding, |exit| {
        if let ExitInfo::Cpuid { leaf, subleaf } = info {
            match exit.cpuid_action(*leaf, *subleaf) {
                InterpositionAction::Trap => {
                    exit.forward(reason)?;
                }
                InterpositionAction::Native => vp.handle_local(reason, info),
                InterpositionAction::Emulate(result)
                | InterpositionAction::EmulateConst(result) => {
                    vp.emulate_cpuid(&result);
                }
            }
            return Ok(());
        }
        if let ExitInfo::Msr {
            number,
            is_write,
            value,
        } = info
        {
            match exit.msr_action(*number) {
                InterpositionAction::Trap => {
                    exit.forward(reason)?;
                }
                InterpositionAction::Native => vp.handle_local(reason, info),
                InterpositionAction::Emulate(stored) if !is_write => {
                    if vp.try_emulate_rdmsr(*number, stored).is_err() {
                        vp.emulate_rdmsr(stored);
                    }
                }
                InterpositionAction::Emulate(_) => {
                    if vp.try_emulate_wrmsr(*number, *value).is_err() {
                        exit.update_msr_emulate_value(*number, *value)?;
                        vp.next_rip();
                    }
                }
                InterpositionAction::EmulateConst(stored) if !is_write => vp.emulate_rdmsr(stored),
                InterpositionAction::EmulateConst(_) => vp.next_rip(),
            }
            return Ok(());
        }
        if exit.exit_action(reason).trap {
            exit.forward(reason)?;
        } else {
            vp.handle_local(reason, info);
        }
        Ok(())
    }));
}

// ── Interrupt handling (generic policy, arch primitives) ───────────────────── //

/// Handle an external interrupt exit.
///
/// Generic policy logic: `Vp::forward_interrupt` (arch-specific) consults
/// `InterruptPolicy` to route the vector — direct injection into the
/// running child if it has `Deliver` visibility, otherwise lazy-unwind to
/// the handler (dom0) — and performs the register copy + context switch.
fn handle_external_interrupt<A: ArchVpOps>(vp: &mut Vp<A>, _platform: &ThemisPlatform, vector: u32) {
    vp.forward_interrupt(vector);
}

/// Handle preemption timer exit.
///
/// Gives the arch-side MSR emulators a chance to consume the timer (e.g.
/// injecting `0xEC` for an emulated TSC-deadline expiry). If consumed, no
/// re-arm: the emulator already programmed any next deadline. Otherwise
/// just reset the timer for its next general-purpose use.
fn handle_preemption_timer<A: ArchVpOps>(vp: &mut Vp<A>, _platform: &ThemisPlatform) {
    if vp.try_consume_preemption_timer() {
        return;
    }

    vp.reset_timer();
}

// ── Utility ───────────────────────────────────────────────────────────────── //

fn halt_forever() -> ! {
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("cli; hlt", options(nomem, nostack));
        }
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack));
        }
    }
}
