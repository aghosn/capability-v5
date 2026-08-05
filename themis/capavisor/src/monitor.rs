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
use capability_engine::interposition::{DefaultAction, ProcFeaturePolicy};
use capability_engine::{Capability, Platform as _};

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
                // CPUID interposition: per-(leaf, subleaf) policy overrides ExitPolicy.
                if let ExitInfo::Cpuid { leaf, subleaf } = info {
                    match lookup_cpuid_action(platform, *leaf, *subleaf) {
                        InterpositionAction::Trap => {
                            vp.forward_exit(reason);
                            continue;
                        }
                        InterpositionAction::Native => {
                            vp.handle_local(reason, info);
                            continue;
                        }
                        InterpositionAction::Emulate(result) => {
                            vp.emulate_cpuid(&result);
                            continue;
                        }
                    }
                }

                // MSR interposition: per-MSR policy overrides ExitPolicy.
                if let ExitInfo::Msr {
                    number, is_write, value,
                } = info
                {
                    let action = lookup_msr_action(platform, *number);
                    if !is_write {
                        // RDMSR: existing semantics — Emulate returns the
                        // policy's stored value.
                        match action {
                            InterpositionAction::Trap => {
                                vp.forward_exit(reason);
                                continue;
                            }
                            InterpositionAction::Native => {
                                vp.handle_local(reason, info);
                                continue;
                            }
                            InterpositionAction::Emulate(stored) => {
                                vp.emulate_rdmsr(stored);
                                continue;
                            }
                        }
                    } else {
                        // WRMSR: symmetric three-state.
                        // Emulate ⇒ try capavisor's internal MSR emulator
                        // registry; fail-closed to Trap (forward to parent)
                        // when no handler is registered.
                        match action {
                            InterpositionAction::Trap => {
                                vp.forward_exit(reason);
                                continue;
                            }
                            InterpositionAction::Native => {
                                vp.handle_local(reason, info);
                                continue;
                            }
                            InterpositionAction::Emulate(_) => {
                                // Try capavisor's internal WRMSR registry first
                                // (TSC_DEADLINE, APIC_BASE, …).  If no handler
                                // is registered, treat the MSR as a per-domain
                                // scratch register: store `value` in the policy
                                // (so the next RDMSR returns it) and advance
                                // RIP without a parent round-trip.
                                match vp.try_emulate_wrmsr(*number, *value) {
                                    Ok(()) => continue,
                                    Err(()) => {
                                        let _ = update_msr_emulate_value(
                                            platform, *number, *value,
                                        );
                                        vp.next_rip();
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }

                // Default: consult ExitPolicy for all other exit reasons.
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

// ── CPUID / MSR interposition ─────────────────────────────────────────────── //

/// Result of looking up a CPUID or MSR interposition policy.
enum InterpositionAction<V> {
    Trap,
    Native,
    Emulate(V),
}

/// Look up CPUID interposition policy for a specific (leaf, subleaf).
fn lookup_cpuid_action(
    platform: &ThemisPlatform,
    leaf: u32,
    subleaf: u32,
) -> InterpositionAction<capability_engine::interposition::CpuidResult> {
    let core_id = platform.get_current_core().unwrap_or(0) as usize;
    let Some(cap) = platform.get_core_cap(core_id) else {
        return InterpositionAction::Trap; // fail-closed
    };
    let guard = cap.read();
    let cpuid_cfg = &guard.data.policy.cpuid;
    let key = (leaf, subleaf);
    match cpuid_cfg.lookup(&key) {
        Some(ProcFeaturePolicy::Emulate(_, value)) => InterpositionAction::Emulate(*value),
        Some(ProcFeaturePolicy::Native(_)) => InterpositionAction::Native,
        Some(ProcFeaturePolicy::Trap(_)) => InterpositionAction::Trap,
        None => match cpuid_cfg.default {
            DefaultAction::Trap => InterpositionAction::Trap,
            DefaultAction::Native => InterpositionAction::Native,
        },
    }
}

/// Look up MSR interposition policy for a specific MSR number.
fn lookup_msr_action(platform: &ThemisPlatform, msr: u32) -> InterpositionAction<u64> {
    let core_id = platform.get_current_core().unwrap_or(0) as usize;
    let Some(cap) = platform.get_core_cap(core_id) else {
        return InterpositionAction::Trap; // fail-closed
    };
    let guard = cap.read();
    let msr_cfg = &guard.data.policy.msrs;
    match msr_cfg.lookup(&msr) {
        Some(ProcFeaturePolicy::Emulate(_, value)) => InterpositionAction::Emulate(*value),
        Some(ProcFeaturePolicy::Native(_)) => InterpositionAction::Native,
        Some(ProcFeaturePolicy::Trap(_)) => InterpositionAction::Trap,
        None => match msr_cfg.default {
            DefaultAction::Trap => InterpositionAction::Trap,
            DefaultAction::Native => InterpositionAction::Native,
        },
    }
}

/// Update the stored Emulate value for an MSR in the current core's
/// domain policy.  Returns `true` if an Emulate entry existed and was
/// updated, `false` otherwise (caller falls back to Trap semantics).
///
/// Goes through `Capability::update_msr_emulate_value` (capa-engine,
/// `platform::execute`-mediated) rather than taking a direct write lock on
/// the domain capability — per axiom A9, all domain-state mutation must go
/// through the capability engine's interface, the same as every other
/// policy write in this codebase (`set_policy`, `deliver_interrupt_vp`,
/// etc.).
fn update_msr_emulate_value(platform: &ThemisPlatform, msr: u32, value: u64) -> bool {
    let core_id = platform.get_current_core().unwrap_or(0) as usize;
    let Some(cap) = platform.get_core_cap(core_id) else {
        return false;
    };
    Capability::update_msr_emulate_value(platform, &cap, msr, value).is_ok()
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
