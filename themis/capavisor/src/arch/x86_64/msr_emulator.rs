//! Capavisor-internal MSR emulator registry.
//!
//! Routed via the per-domain [`MsrPolicy`] in the capability engine: when
//! the policy returns `Emulate`, the generic monitor calls into
//! [`crate::arch_traits::traits::ArchVpOps::try_emulate_wrmsr`], which on
//! x86 dispatches here. Handlers may produce side effects (e.g. arming
//! the VMX preemption timer for TSC-deadline emulation).
//!
//! Today's only entry: **IA32_TSC_DEADLINE (0x6E0)** — emulates the
//! TSC-deadline LAPIC timer using the VMX preemption timer, so the
//! guest never round-trips through CHV's userspace timerfd path.
//!
//! ## Design
//!
//! - **Per-CPU state.** Each core owns one VP at a time, so a fixed
//!   `[AtomicU64; MAX_CORES]` indexed by core id is sufficient.
//! - **Lazy programming.** `wrmsr_tsc_deadline` writes the preemption-timer
//!   VMCS field directly; the value is recomputed on every WRMSR.
//! - **Timer rate.** The VMX preemption timer ticks at TSC>>N where N is
//!   `IA32_VMX_MISC[4:0]`. Read once at boot and cached.
//! - **Injection.** On `EXIT_REASON_VMX_PREEMPTION_TIMER`, the generic
//!   monitor calls [`maybe_inject_tsc_deadline`]; if the cached deadline
//!   has passed, vector `0xEC` (Linux's LOCAL_TIMER_VECTOR) is injected
//!   and the deadline is cleared.
//!
//! ## Asymmetry with RDMSR
//!
//! WRMSR Emulate without a registered handler **traps to parent** (the
//! safe default). RDMSR Emulate keeps its existing semantics: on
//! Emulate without a handler, the policy's stored value is returned —
//! that path lives in `monitor.rs` and does not pass through here.

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use x86::vmx::vmcs;

use crate::arch::x86_64::pid::inject_via_pid;
use crate::arch::x86_64::vcpu_ext::ActiveVcpuExt;
use crate::platform::MAX_CORES;
use crate::vcpu::ActiveVcpu;

// ── Constants ─────────────────────────────────────────────────────────────── //

/// IA32_TSC_DEADLINE — written by Linux's LAPIC timer driver in TSC-deadline
/// mode (Intel SDM Vol 3A §10.5.4.1).
pub const MSR_IA32_TSC_DEADLINE: u32 = 0x6E0;

/// IA32_APIC_BASE — read by Linux during early boot to learn the LAPIC base
/// physical address and the EN/EXTD mode bits.  Children are pinned to
/// x2APIC mode by capavisor (VIRTUALIZE_X2APIC_MODE in VMCS); the RDMSR
/// returns a fixed value set via the engine's MSR_EMULATE policy
/// (BASE | EN | EXTD), and WRMSR is silently dropped so a guest cannot
/// disable EXTD and try to fall back to xAPIC MMIO.
pub const MSR_IA32_APIC_BASE: u32 = 0x1B;

/// IA32_VMX_MISC — bits [4:0] hold the preemption-timer rate divisor:
/// the timer decrements once every 2^N TSC ticks (Intel SDM Vol 3D, A.6).
const IA32_VMX_MISC: u32 = 0x485;

/// Linux's LAPIC timer vector (`LOCAL_TIMER_VECTOR`). Same value used by
/// CHV's existing irqfd-driven LAPIC timer (vm_impl.rs).
const LOCAL_TIMER_VECTOR: u8 = 0xEC;

/// Maximum 32-bit value the VMX preemption timer accepts.
const PREEMPT_MAX: u64 = u32::MAX as u64;

/// Sentinel meaning "no pending deadline" — guest never writes 0 to
/// TSC_DEADLINE in practice (writing 0 disarms it, and we treat that
/// the same way: clear pending).
const NO_DEADLINE: u64 = 0;

// ── Per-CPU state ─────────────────────────────────────────────────────────── //

/// Per-core pending TSC deadline (TSC value at which to inject 0xEC),
/// or `NO_DEADLINE` if no timer is currently armed for the guest.
static TSC_DEADLINE: [AtomicU64; MAX_CORES] = {
    const INIT: AtomicU64 = AtomicU64::new(NO_DEADLINE);
    [INIT; MAX_CORES]
};

/// Cached `IA32_VMX_MISC[4:0]` divisor exponent. Latched on first use
/// (any core); identical across cores in practice.
static TSC_DIVISOR_SHIFT: AtomicU8 = AtomicU8::new(u8::MAX);

#[inline]
fn tsc_divisor_shift() -> u8 {
    let cached = TSC_DIVISOR_SHIFT.load(Ordering::Relaxed);
    if cached != u8::MAX {
        return cached;
    }
    let n = (unsafe { x86::msr::rdmsr(IA32_VMX_MISC) } & 0x1F) as u8;
    TSC_DIVISOR_SHIFT.store(n, Ordering::Relaxed);
    n
}

#[inline]
fn rdtsc_now() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

// ── Public API ────────────────────────────────────────────────────────────── //

/// Attempt to handle a WRMSR via capavisor's internal emulator registry.
///
/// Returns `Ok(())` if a registered handler took ownership of the write
/// (caller advances RIP and resumes the guest), or `Err(())` if no
/// handler exists for `msr` (caller should trap to parent).
pub fn try_handle_wrmsr(vcpu: &mut ActiveVcpu, core_id: usize, msr: u32, value: u64) -> Result<(), ()> {
    match msr {
        MSR_IA32_TSC_DEADLINE => {
            handle_wrmsr_tsc_deadline(vcpu, core_id, value);
            Ok(())
        }
        MSR_IA32_APIC_BASE => {
            // x2APIC is pinned for child VMs by capavisor.  Linux's
            // __x2apic_enable() unconditionally writes back IA32_APIC_BASE
            // with EXTD set; we accept the write but never apply it,
            // forcing the guest to stay in x2APIC mode.  The matching
            // RDMSR returns the policy's stored Emulate value
            // (BASE | EN | EXTD) via monitor.rs without entering this
            // handler.
            let _ = (vcpu, core_id, value);
            Ok(())
        }
        _ => Err(()),
    }
}

/// Called from the generic preemption-timer exit handler. Returns `true`
/// if the timer fired for a capavisor-emulated TSC deadline (and the
/// LAPIC timer vector was injected); `false` if the timer was for the
/// generic quantum-sched re-arm path.
pub fn maybe_inject_tsc_deadline(vcpu: &mut ActiveVcpu, core_id: usize) -> bool {
    if core_id >= MAX_CORES {
        return false;
    }
    let deadline = TSC_DEADLINE[core_id].load(Ordering::Relaxed);
    if deadline == NO_DEADLINE {
        return false;
    }

    let now = rdtsc_now();
    if now < deadline {
        // Spurious early fire (e.g. quantum-sched timer), or another
        // wakeup raced with us. Reprogram preemption timer for the
        // remaining TSC distance and return false so the caller still
        // resumes without injection.
        program_preemption_timer(vcpu, deadline.saturating_sub(now));
        return false;
    }

    TSC_DEADLINE[core_id].store(NO_DEADLINE, Ordering::Relaxed);
    deliver_timer_vector(vcpu);
    true
}

/// Inject `LOCAL_TIMER_VECTOR` into the guest, gated by interruptibility.
///
/// VM-entry consistency rejects external-interrupt injection via
/// VMENTRY_INTR_INFO when RFLAGS.IF=0 or STI/MOV-SS shadowing — that
/// caused exit reason 33 (invalid guest state) when the guest was in a
/// CLI region. When the window is closed, push the vector into local
/// PIR and enable interrupt-window exiting so
/// [`drain_pir_on_interrupt_window`] delivers it on the next IF=1
/// transition.
fn deliver_timer_vector(vcpu: &mut ActiveVcpu) {
    if vcpu.guest_can_accept_external() {
        vcpu.inject_external_vector(LOCAL_TIMER_VECTOR);
        return;
    }

    // Push into PIR (local — same core as this VP) and arm interrupt-window
    // exiting. `drain_pir_inject_lowest` (called from
    // `drain_pir_on_interrupt_window`) handles delivery + clearing.
    let pid_phys = vcpu.pid_phys();
    if pid_phys != 0 {
        let ptr = crate::PLATFORM_PTR.load(Ordering::Acquire);
        let hhdm = if ptr.is_null() { 0 } else { unsafe { (*ptr).hhdm_offset() } };
        unsafe { inject_via_pid(pid_phys, hhdm, LOCAL_TIMER_VECTOR, false) };
    }
    vcpu.set_interrupt_window_exit(true);
}

// ── Internal helpers ──────────────────────────────────────────────────────── //

fn handle_wrmsr_tsc_deadline(vcpu: &mut ActiveVcpu, core_id: usize, deadline: u64) {
    if core_id >= MAX_CORES {
        return;
    }

    if deadline == 0 {
        // Linux disarms the timer by writing 0.
        TSC_DEADLINE[core_id].store(NO_DEADLINE, Ordering::Relaxed);
        // Push the preemption timer far out so it stops thrashing the
        // monitor; the next genuine arm will reprogram it.
        program_preemption_timer(vcpu, u64::MAX);
        return;
    }

    TSC_DEADLINE[core_id].store(deadline, Ordering::Relaxed);
    let now = rdtsc_now();
    let delta_tsc = deadline.saturating_sub(now);
    program_preemption_timer(vcpu, delta_tsc);
}

/// Write `delta_tsc` (in guest-TSC units) to the VMCS preemption-timer
/// field after applying the IA32_VMX_MISC rate-divisor shift, clamped
/// to the 32-bit timer width.
fn program_preemption_timer(vcpu: &mut ActiveVcpu, delta_tsc: u64) {
    let shift = tsc_divisor_shift() as u32;
    let ticks = (delta_tsc >> shift).min(PREEMPT_MAX);
    // A value of 0 fires immediately on next entry; clamp to 1 if the
    // deadline already passed so we get a clean exit and inject the
    // vector via maybe_inject_tsc_deadline.
    let ticks = if ticks == 0 { 1 } else { ticks };
    vcpu.set(vmcs::guest::VMX_PREEMPTION_TIMER_VALUE, ticks);
}
