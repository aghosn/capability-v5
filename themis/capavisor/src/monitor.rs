//! Generic monitor loop — platform-agnostic exit dispatch.
//!
//! This module contains the main run loop that all domains (dom0 and children)
//! execute on each core. The loop:
//!
//! 1. Enters the guest via `ArchVpOps::enter_and_decode` (arch-specific).
//! 2. Pattern-matches on `SemanticExit` (platform-agnostic policy logic).
//! 3. Delegates back to arch code for local handling or forwards to parent
//!    via the capability engine.
//!
//! Arch-internal exits (XSETBV, INIT, interrupt-window) never reach this
//! loop — they are handled inside `enter_and_decode` and return `ArchHandled`.
//!
//! Phase F2: The loop is structurally generic but uses concrete x86 types
//! (`ActiveVcpu`, `ThemisPlatform`). Full trait generification is Phase A7.

use core::sync::atomic::Ordering;

use capability_engine::Platform as _;
use crate::arch_traits::types::{ExitInfo, SemanticExit};
use crate::platform::ThemisPlatform;
use crate::vcpu::ActiveVcpu;
use crate::{serial_debug, serial_println};

// ── Generic monitor loop ──────────────────────────────────────────────────── //

/// Per-core monitor loop: enters the guest, dispatches exits via policy,
/// and delegates to arch or generic handlers. Never returns.
///
/// This replaces the old `vmexit::monitor_loop` + `handle_vmexit` which
/// intermixed arch decoding, policy lookup, and handling in one function.
pub fn monitor_loop(vcpu: &mut ActiveVcpu) -> ! {
    loop {
        // ── 1. Enter guest + decode exit (arch-specific) ──
        let platform_ptr = crate::PLATFORM_PTR.load(Ordering::Acquire);
        let platform = if !platform_ptr.is_null() {
            unsafe { &*platform_ptr }
        } else {
            // Pre-platform: just run and halt on failure.
            serial_println!("[MONITOR] No platform — halting");
            halt_forever();
        };

        let exit_reason = match unsafe { vcpu.run() } {
            Ok(reason) => reason,
            Err(e) => {
                serial_println!("[FATAL] VM entry failed: {:?}", e);
                halt_forever();
            }
        };

        let exit = crate::arch::vmexit::classify_and_handle_internal(
            vcpu,
            exit_reason,
            platform,
        );

        // ── 2. Dispatch on semantic exit (generic policy logic) ──
        match exit {
            SemanticExit::ArchHandled => continue,

            SemanticExit::Shutdown { reason } => {
                serial_println!("[FATAL] Guest shutdown (reason={})", reason);
                halt_forever();
            }

            SemanticExit::Hypercall => {
                // Generic dispatch: all VMCALLs go through the capability
                // engine uniformly, regardless of domain.
                if let Some(result) = crate::hypercall::handle_vmcall(vcpu) {
                    use crate::vcpu::Reg;
                    vcpu.set_reg(Reg::Rax, result.rax);
                    vcpu.set_reg(Reg::Rdi, result.rdi);
                    vcpu.set_reg(Reg::Rsi, result.rsi);
                    vcpu.set_reg(Reg::Rdx, result.rdx);
                    crate::arch::vmexit::next_instruction(vcpu);
                }
                // None → SWITCH swapped the vcpu; no writeback needed.
            }

            SemanticExit::ExternalInterrupt { vector } => {
                // Generic: consult InterruptPolicy, route via capability
                // engine hierarchy (A3 lazy-unwind model).
                handle_external_interrupt(vcpu, platform, vector);
            }

            SemanticExit::TimerExpired => {
                handle_preemption_timer(vcpu, platform);
            }

            SemanticExit::PolicyDriven { reason, ref info } => {
                // ── 3. Consult ExitPolicy for this domain ──
                let trap = lookup_exit_trap(platform, reason);

                // EPT violation doorbell fast-path: always checked before policy.
                if let ExitInfo::EptViolation { gpa, qualification } = info {
                    if let Some(true) = crate::arch::vmexit::check_ept_doorbell(
                        platform, vcpu, *gpa, *qualification,
                    ) {
                        continue;
                    }
                }

                if trap {
                    // Forward to parent via capability engine.
                    crate::hypercall::forward_child_exit(vcpu, reason);
                } else {
                    // Local handling (arch-specific).
                    crate::arch::vmexit::handle_local_exit(vcpu, reason, info, platform);
                }
            }
        }
    }
}

// ── Policy lookup ─────────────────────────────────────────────────────────── //

/// Look up whether the current domain's ExitPolicy traps this exit reason.
///
/// Returns `true` (forward to parent) or `false` (handle locally).
/// Defaults to `true` (fail-closed) if no capability is found.
fn lookup_exit_trap(platform: &ThemisPlatform, reason: u32) -> bool {
    let core_id = platform.get_current_core().unwrap_or(0) as usize;
    platform
        .get_core_cap(core_id)
        .map(|c| c.read().data.policy.exits.get_action(reason).trap)
        .unwrap_or(true)
}

// ── Interrupt handling (generic logic, arch primitives) ───────────────────── //

/// Handle an external interrupt exit.
///
/// Uses the same logic as the old `handle_external_interrupt` in vmexit.rs
/// but structured as generic dispatch:
/// 1. Check if dom0 (trap=false): just resume (interrupt exiting is off).
/// 2. Check quantum-sched deferred vector optimization.
/// 3. Forward to handler domain via capability engine (A3 lazy-unwind).
#[allow(unused_variables)]
fn handle_external_interrupt(
    vcpu: &mut ActiveVcpu,
    platform: &ThemisPlatform,
    vector: u32,
) {
    let core_id = platform.get_current_core().unwrap_or(0) as usize;
    let exit_trap = platform
        .get_core_cap(core_id)
        .map(|c| c.read().data.policy.exits.get_action(
            crate::arch::vmexit::EXIT_REASON_EXTERNAL_INTERRUPT).trap)
        .unwrap_or(true);

    if !exit_trap {
        // Dom0: interrupt exiting off, this shouldn't fire. Resume.
        serial_debug!("[DOM0-EXT-INTR]");
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
                    crate::hypercall::forward_interrupt_to_handler(vcpu, old);
                    platform.set_deferred(core_id, vector as u8);
                    return;
                }
                platform.set_deferred(core_id, vector as u8);
                return;
            }
        }
    }

    // A3 lazy-unwind: forward to handler domain immediately.
    crate::hypercall::forward_interrupt_to_handler(vcpu, vector as u8);
}

/// Handle preemption timer exit.
///
/// For quantum-sched: flush deferred vectors on quantum expiry.
/// For all domains: reset the timer and resume.
#[allow(unused_variables)]
fn handle_preemption_timer(vcpu: &mut ActiveVcpu, platform: &ThemisPlatform) {
    use x86::vmx::vmcs;
    use crate::arch::vmexit::PREEMPTION_TIMER_TICKS;

    #[cfg(feature = "quantum-sched")]
    {
        let core_id = platform.get_current_core().unwrap_or(0) as usize;
        if let Some(vec) = platform.take_deferred(core_id) {
            vcpu.set(
                vmcs::guest::VMX_PREEMPTION_TIMER_VALUE,
                PREEMPTION_TIMER_TICKS,
            );
            crate::hypercall::forward_interrupt_to_handler(vcpu, vec);
            return;
        }
    }

    // No deferred vector — reset timer, stay in guest.
    vcpu.set(
        vmcs::guest::VMX_PREEMPTION_TIMER_VALUE,
        PREEMPTION_TIMER_TICKS,
    );
}

// ── Utility ───────────────────────────────────────────────────────────────── //

fn halt_forever() -> ! {
    loop {
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}
