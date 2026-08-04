//! VP-switching pipeline. Three triggers, one mechanism:
//!
//!   1. Explicit  — guest issues SWITCH VMCALL          → `do_switch`
//!   2. Exit-driven — child raises exit dom0 must see   → `forward_child_exit`
//!   3. Intr-driven — external interrupt to Deliver-policy handler
//!                                                      → `forward_interrupt_to_handler`
//!
//! All three converge on `arch::vcpu_switch::swap_active_vp` (the
//! VMCLEAR/VMPTRLD primitive) plus posted-interrupt drain helpers
//! (`drain_pir_*`) for the destination VP.

extern crate alloc;

use core::sync::atomic::Ordering;

use capability_engine::{
    Capability, CapabilityRef, Domain, DomainId, InterruptVisibility, Platform, RegBitmap,
};
use themis_abi::errors;

use super::write_reply;
use crate::hypercall::{HypercallResult};
use crate::arch::x86_64::apic::current_lapic_id;
use crate::arch::x86_64::iommu_ir::sync_irte_ndst;
use crate::arch::x86_64::pid::inject_via_pid;
use crate::arch::x86_64::reg_apply::apply_pending_reg;
use crate::arch::x86_64::vcpu_ext::ActiveVcpuExt;
use crate::arch::x86_64::vcpu_switch::swap_active_vp;
use crate::arch::x86_64::vmexit::EXIT_REASON_EPT_VIOLATION;
use crate::platform::ThemisPlatform;
use crate::{serial_debug, serial_println};
use crate::vcpu::{ActiveVcpu, Reg};


// ── SWITCH (sync mode) ───────────────────────────────────────────────────── //

/// SWITCH (0x0A): swap the current ActiveVcpu for the target (callee) VP.
///
/// SWITCH is symmetric — the target may be a child (descent into a
/// subdomain), a parent (return from a child), or any other domain the
/// caller holds a capability to. The capa-engine validates the transition;
/// this function performs the platform-level swap.
///
/// The monitor loop's `vcpu` is replaced: the caller (`from`) is deactivated
/// and stored in its VcpuSlot; the target (`to`) is taken from its slot,
/// activated, and becomes the new `vcpu`. The next `vcpu.run()` in the
/// monitor loop enters the target guest.
///
/// On success the active VP has been swapped; the dispatcher
/// (`handle_vmcall`) must NOT write a reply or advance RIP — the caller's
/// RIP was already advanced past the SWITCH VMCALL in step 3 below before
/// the swap, and the now-active target has its own register state.
///
/// On early error (before the swap), this function writes the error reply
/// and advances the caller's RIP itself, then returns.
pub(crate) fn do_switch(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    to_domain_handle: u64,
    vp_id: u64,
    vcpu: &mut ActiveVcpu,
) {
    use themis_abi::regs::VpRegister;

    let vp_idx = vp_id as usize;

    // ── 1a. Resolve target domain ID + COMM HPA (before Capability::switch) ──
    // MUST happen before Capability::switch transitions the target VP to Running,
    // because set_register (used to validate the dirty COMM page registers)
    // rejects writes to a VP that is already in Running state.
    let (to_domain_id_pre, comm_hpa) = {
        let c = caller.read();
        let to_weak = match c.data.get_domain_capability(to_domain_handle) {
            Some(w) => w.clone(),
            None => {
                write_reply(vcpu, HypercallResult::error(errors::ERR_NOTFOUND));
                vcpu.next_rip();
                return;
            }
        };
        drop(c);
        let to_ref = match to_weak.upgrade() {
            Some(r) => r,
            None => {
                write_reply(vcpu, HypercallResult::error(errors::ERR_NOTFOUND));
                vcpu.next_rip();
                return;
            }
        };
        let to_id = to_ref.read().data.id;
        // Invariant: target is alive in the capa-engine (weak upgrade succeeded
        // just above), so it must also be in the platform map. A miss = capa/
        // platform desync, almost certainly a registration ordering bug.
        let hpa = platform
            .domain_arc(to_id)
            .expect("[do_switch] target PlatformDomain missing (capa/platform desync)")
            .lock()
            .comm_hpas
            .get(vp_idx)
            .copied()
            .unwrap_or(0);
        (to_id, hpa)
    };

    // ── 1b. Snapshot COMM page dirty registers while target VP is Available ──
    // Use VpCommView to encapsulate the unsafe page mapping; then capability-
    // check each register (we cannot call set_register, which would re-mark
    // the dirty bit and cause infinite replay).
    let pending: alloc::vec::Vec<(VpRegister, u64)> = {
        let hhdm = platform.hhdm_offset();
        // SAFETY: comm_hpa was registered for this VP via THHV_CREATE_VP and
        // no other view is held on this code path.
        match unsafe { crate::comm::VpCommView::map(comm_hpa, hhdm) } {
            None => alloc::vec::Vec::new(),
            Some(mut view) => view
                .take_dirty()
                .into_iter()
                .filter(|(reg, _)| {
                    Capability::check_register_write(
                        caller,
                        to_domain_handle,
                        vp_id,
                        *reg as u64,
                        platform,
                    )
                    .is_ok()
                })
                .collect(),
        }
    };

    // ── 2. Capability engine: forward switch (run-state transitions) ──
    // Target VP transitions Available → Running here; must be after COMM read above.
    let switch_ctx = match Capability::switch(platform, caller, to_domain_handle, vp_id) {
        Ok((ctx, _batch)) => ctx,
        Err(e) => {
            serial_debug!("[SWITCH] validation failed: target={} vp_id={} err={:?}", to_domain_handle, vp_id, e);
            write_reply(vcpu, HypercallResult::from(e));
            vcpu.next_rip();
            return;
        }
    };

    let to_domain_id: DomainId = switch_ctx.to_domain.read().data.id;
    let to_vp_idx = switch_ctx.to_vp_id.unwrap_or(vp_id) as usize;
    let from_domain_id: DomainId = switch_ctx
        .from_domain
        .as_ref()
        .expect("do_switch's forward path always names a source domain")
        .read()
        .data
        .id;
    let from_vp_id = switch_ctx.from_vp_id.unwrap_or(0) as usize;

    // ── 3. Advance caller (from-VP) RIP past SWITCH VMCALL (while its VMCS
    //       is still loaded and VMEXIT_INSTRUCTION_LEN is valid).
    //
    // Invariant: a VP stored in its VcpuSlot always has RIP positioned at
    // the next instruction it should execute — never AT a VMCALL it has
    // already taken.  No resume path needs to re-advance this RIP.
    vcpu.next_rip();

    // ── 4. Swap from → to via the shared helper.
    //       Cap-engine validated the transition, so the dst slot / domain
    //       must exist; helper panics otherwise.
    let current_lapic = current_lapic_id();
    unsafe {
        swap_active_vp(
            vcpu,
            platform,
            (from_domain_id, from_vp_id),
            (to_domain_id, to_vp_idx),
            "SWITCH",
        );
    }

    // ── 5. Sync IRTE.NDST so hardware-posted device interrupts for Deliver
    //       vectors are routed to this core by the IOMMU.
    {
        let to_ref = platform.get_core_cap(switch_ctx.core_id as usize);
        if let Some(to_cap) = to_ref {
            sync_irte_ndst(platform, &to_cap, current_lapic);
        }
    }

    // ── 6. (VMX preemption timer is NOT reset here.) ──
    // The timer counts down across target re-entries.  It is only
    // reset to PREEMPTION_TIMER_TICKS when the timer actually fires
    // (EXIT_REASON_VMX_PREEMPTION_TIMER in vmexit.rs).

    // ── 6a. Interrupt inject: the target VP was `Waiting`/`report`-true
    // with no callee of its own — i.e. it was the true leaf actually
    // executing when an interrupt hit a Deliver-policy handler somewhere
    // up its chain (see `SwitchContext::interrupt_inject`). It has no
    // switch-call return to observe the interrupt through, so the vector
    // must be delivered the same way a real hardware interrupt would be:
    // queue it into the target's own PIR here (same core, no IPI needed —
    // `is_remote = false`) so step 7's drain picks it up under the same
    // priority (device before timer) and IF-gating rules as any other
    // pending vector.
    //
    // KNOWN DESIGN DISCREPANCY (tracked in todo.md, needs careful
    // clarification before this can be considered settled): this fires
    // whenever the leaf's OWN `InterruptVisibility` for `vector` was
    // `Report` (see `capa-engine`'s `deliver_interrupt_vp` /
    // `switch_domain_forward`) — i.e. the vector was already fully
    // routed to and handled by a `Deliver`-policy ancestor via the
    // external-interrupt lazy-unwind path. Re-injecting it here means
    // the domain observes the SAME vector a second time, even though
    // `Report` is documented (`capa-engine/src/domain.rs`) as "reported
    // to domain but handled by parent" — i.e. NOT meant to be redelivered
    // raw to this domain. For domains without a real handler for that
    // vector (e.g. eunomia guests, whose IDT only covers 0-31 and their
    // own owned vectors) this can produce a `#GP`; for domains with a
    // full IDT (e.g. a real Linux child) it instead produces a spurious
    // duplicate-interrupt storm. Root-caused 2026-07-30 against the
    // eunomia-timer intermittent #GP and a nested Linux guest's spurious
    // LAPIC-timer storm.
    //
    // STOP-GAP (2026-07-30): raw re-injection disabled entirely below.
    // An attempt to instead scope the leaf's `InterruptVisibility` to
    // `NotReport`/`Suppress` per-vector (both via a per-workload
    // `--themis-config` and via `standard.json`'s built-in profile) had
    // NO effect at the time, because `cloud-hypervisor/hypervisor/src/
    // themis/policy_walker.rs` never walked `ThemisConfig.policies
    // .interrupts` into any `THHV_SET_POLICY` op — `InterruptsConfig` was
    // parsed/validated by `config.rs` but otherwise entirely dead.
    // Disabling the injection outright was the correct interim behavior:
    // it makes `Report` actually mean "reported to domain but handled by
    // parent, not redelivered", matching the documented semantics, at the
    // cost of no longer being able to say `Deliver` vs `Report` distinctly
    // at the injection site for now (both silently coalesce to
    // "did not re-inject").
    //
    // UPDATE (interrupt_semantics branch): `policy_walker.rs::walk_interrupts`
    // now projects `policies.interrupts` into `THHV_SET_POLICY` calls, so
    // per-vector `InterruptVisibility` (and the new, independent
    // `injectable` bit gating `THEMIS_INJECT_INTERRUPT`) IS configurable
    // from JSON today. Re-enabling raw redelivery for `Report`-visibility
    // vectors here still needs the `VpRunState::Waiting`/semantics design
    // review noted above before it's safe to flip back on.
    let _ = switch_ctx.interrupt_inject;

    // ── 7. PIR → VMENTRY_INTR_INFO drain (software interrupt delivery) ──
    // PROCESS_POSTED_INTERRUPTS is never set (see vmcs.rs and A3), so the
    // processor never auto-delivers from the PID — capavisor uses PIR as a
    // software queue and drains it here under capability control.  Helper
    // injects the LOWEST pending vector (device IRQs before timer) via the
    // legacy VM-entry path and returns whether vectors remain.  Set the
    // interrupt-window-exiting bit accordingly so we retry on the next
    // IF=1 transition.
    //
    // Note: this also clears interrupt-window-exiting in the
    // nothing-pending case; the old code skipped that branch, but it is
    // safe (and arguably correct) to clear it whenever PIR is empty.
    {
        let remaining = drain_pir_inject_lowest(vcpu, platform);
        vcpu.set_interrupt_window_exit(remaining);
    }

    // ── 8. Apply all pending COMM-page registers to the now-active target.
    //       `apply_pending_reg` dispatches GPR vs VMCS-field internally.
    if to_domain_id == to_domain_id_pre && to_vp_idx == vp_idx {
        for (reg, val) in &pending {
            apply_pending_reg(vcpu, *reg, *val);
        }
    }

    // ── 9. Interrupt return: if the target VP was Suspended (multi-hop
    // interrupt unwind), deliver a synthetic SWITCH return result so the
    // domain sees "my callee was preempted by interrupt V".
    //
    // Per the VcpuSlot RIP invariant (step 3 above), the target VP's saved
    // RIP is already past its SWITCH VMCALL, so no RIP advance is needed
    // here — only the result registers.
    if let Some(vector) = switch_ctx.interrupt_return {
        vcpu.set_reg(Reg::Rax, errors::SUCCESS);
        vcpu.set_reg(Reg::Rdi, vector as u64);
        vcpu.set_reg(Reg::Rsi, 0);
        vcpu.set_reg(Reg::Rdx, 0);
    }

    // Active VP is now the target; handle_vmcall returns without writing a
    // reply or advancing RIP. The monitor loop will call vcpu.run() on the
    // child next.
}

// ── Child exit forwarding ────────────────────────────────────────────────── //

/// Atomically drain the VP's posted-interrupt request (PIR) array, inject the
/// lowest pending vector via legacy VM-entry injection, and put remaining
/// vectors back for next time.  Returns `true` if any vectors remain in PIR
/// after this call (so the caller can enable interrupt-window exiting).
///
/// The PIR is used purely as a software queue (see A3, A8): remote cores drop
/// vectors via `inject_via_pid`, and the next SWITCH or interrupt-window exit
/// drains them here under capability/policy control.  Lowest vector first so
/// device IRQs are prioritised over the timer.
///
/// Skips injection if `vcpu` cannot accept an external interrupt
/// (IF=0 or STI/MOV-SS blocking) — the snapshot is then OR'd back into PIR
/// untouched so it can be retried on the next interrupt-window exit.
///
/// Returns `false` if the VP has no PID (legacy / non-posted setup).
pub(crate) fn drain_pir_inject_lowest(
    vcpu: &mut ActiveVcpu,
    platform: &crate::platform::ThemisPlatform,
) -> bool {
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    let pid_phys = vcpu.pid_phys();
    if pid_phys == 0 {
        return false;
    }
    let hhdm = platform.hhdm_offset();
    let pir_base = (pid_phys + hhdm) as *const AtomicU64;

    let mut pir_snapshot = [0u64; 4];
    let mut any_set = false;
    for i in 0..4 {
        pir_snapshot[i] = unsafe { (*pir_base.add(i)).swap(0, Ordering::AcqRel) };
        if pir_snapshot[i] != 0 {
            any_set = true;
        }
    }

    // Clear ON (Outstanding Notification).
    let on_ptr = ((pid_phys + hhdm) + 32) as *const AtomicU32;
    unsafe { (*on_ptr).store(0, Ordering::Release) };

    if !any_set {
        return false;
    }

    let can_accept = vcpu.guest_can_accept_external();

    if can_accept {
        // Find lowest pending vector (device-first).
        for i in 0..4usize {
            if pir_snapshot[i] != 0 {
                let bit = pir_snapshot[i].trailing_zeros();
                let vector = (i * 64 + bit as usize) as u8;
                pir_snapshot[i] &= !(1u64 << bit);
                vcpu.inject_external_vector(vector);
                break;
            }
        }
    }

    // Put any remaining (or all, if IF blocked) vectors back in PIR.
    let mut remaining = false;
    for i in 0..4usize {
        if pir_snapshot[i] != 0 {
            remaining = true;
            unsafe { (*pir_base.add(i)).fetch_or(pir_snapshot[i], Ordering::AcqRel) };
        }
    }
    remaining
}

/// Called from `handle_vmexit` when the current domain is not dom0.
///
/// Called on EXIT_REASON_INTERRUPT_WINDOW (7): the guest's IF just became 1.
/// Drain PIR, inject lowest pending vector, and manage the interrupt-window
/// exiting bit based on whether vectors remain.
pub(crate) fn drain_pir_on_interrupt_window(
    vcpu: &mut ActiveVcpu,
    platform: &crate::platform::ThemisPlatform,
) {
    let remaining = drain_pir_inject_lowest(vcpu, platform);
    vcpu.set_interrupt_window_exit(remaining);
}

// ── Swap-back helpers (shared by forward_child_exit and ────────────────── //
// forward_interrupt_to_handler) ─────────────────────────────────────────── //

/// Shared prefix: load PLATFORM_PTR, look up the running core, and fetch the
/// capability for the currently-running child domain on that core. Returns
/// `(platform, core_id, child_cap)`. Panics with the supplied `tag` on any
/// missing entry — both call sites already treat these as invariants.
fn current_core_child_cap(
    tag: &'static str,
) -> (&'static ThemisPlatform, u64, CapabilityRef<Domain>) {
    let platform_ptr = crate::PLATFORM_PTR.load(Ordering::Relaxed);
    assert!(!platform_ptr.is_null(), "[{}] PLATFORM_PTR null", tag);
    let platform: &'static ThemisPlatform = unsafe { &*platform_ptr };
    let core_id = platform
        .get_current_core()
        .unwrap_or_else(|| panic!("[{}] get_current_core failed", tag));
    let child_cap = platform
        .get_core_cap(core_id as usize)
        .unwrap_or_else(|| panic!("[{}] get_core_cap failed", tag));
    (platform, core_id as u64, child_cap)
}

/// Copy the `read_set`-filtered subset of vcpu registers to the from-VP's COMM
/// page and, when `intercept_msg` is supplied, write it at the intercept slot.
/// Returns `true` iff a COMM page was mapped (i.e. `comm_hpa != 0` and map
/// succeeded). No-op when the from-VP has no COMM page registered.
fn copy_filtered_regs_to_comm(
    platform: &ThemisPlatform,
    vcpu: &mut ActiveVcpu,
    from_domain_id: DomainId,
    from_vp_id: usize,
    read_set: RegBitmap,
    intercept_msg: Option<&themis_abi::regs::InterceptMessage>,
) -> bool {
    let from_arc = platform
        .domain_arc(from_domain_id)
        .expect("[SWAP_BACK] from-domain PlatformDomain not found");
    let comm_hpa = from_arc
        .lock()
        .comm_hpas
        .get(from_vp_id)
        .copied()
        .unwrap_or(0);
    if comm_hpa == 0 {
        return false;
    }
    let hhdm = platform.hhdm_offset();
    // SAFETY: comm_hpa was registered for this VP via THHV_CREATE_VP and no
    // other VpCommView is held on this code path.
    let Some(mut view) = (unsafe { crate::comm::VpCommView::map(comm_hpa, hhdm) }) else {
        return false;
    };
    view.copy_regs_from_vcpu(vcpu, |r| read_set.is_set(r as u64));
    if let Some(msg) = intercept_msg {
        view.write_intercept(msg);
    }
    true
}

/// Write the 4-register swap-back reply: Rax=status, Rdi=val1, Rsi=0, Rdx=0.
/// Used by both swap-back paths to hand control back to the destination VP.
fn write_swap_reply(vcpu: &mut ActiveVcpu, status: u64, val1: u64) {
    vcpu.set_reg(Reg::Rax, status);
    vcpu.set_reg(Reg::Rdi, val1);
    vcpu.set_reg(Reg::Rsi, 0);
    vcpu.set_reg(Reg::Rdx, 0);
}

/// Forward a child-domain VM exit to its parent (dom0).
///
/// Reads the child's interrupt policy for this exit reason to determine
/// which registers to copy back to the child's COMM page (so the parent
/// can read them).  Then swaps back to the parent — to the parent this
/// looks like a normal return from the SWITCH VMCALL with the exit reason
/// in rdi.
pub(crate) fn forward_child_exit(vcpu: &mut ActiveVcpu, exit_reason: u32) {
    use themis_abi::regs::{InterceptMessage, ThemicMessageHeader, THEMIC_MSG_VP_INTERCEPT};
    use x86::vmx::vmcs;

    let (platform, _core_id, child_cap) = current_core_child_cap("CHILD_EXIT");

    // Look up the exit policy for the forwarded exit reason.
    let read_set = {
        let c = child_cap.read();
        let action = c.data.policy.exits.get_action(exit_reason);
        action.read_set
    };

    // ── Capa engine: return switch (child → parent) ──
    // Records exit_reason in the child VP's Available state so that the resume
    // path (register_access_check) uses the correct ExitPolicy write_set.
    let (return_ctx, _batch) =
        Capability::switch_return_with_exit(platform, &child_cap, exit_reason)
            .expect("[CHILD_EXIT] return switch failed");

    let child_domain_id = return_ctx
        .from_domain
        .as_ref()
        .expect("child-exit return switch always names a source domain")
        .read()
        .data
        .id;
    let child_vp_id = return_ctx.from_vp_id.unwrap_or(0) as usize;
    let parent_domain_id = return_ctx.to_domain.read().data.id;
    let parent_vp_id = return_ctx.to_vp_id.unwrap_or(0) as usize;

    // ── Build the slim intercept message (with optional MMIO bytes) ──
    let is_ept_violation = exit_reason == EXIT_REASON_EPT_VIOLATION;
    let exit_qual = vcpu.try_get(vmcs::ro::EXIT_QUALIFICATION).unwrap_or(0);
    let instr_len = vcpu.try_get(vmcs::ro::VMEXIT_INSTRUCTION_LEN).unwrap_or(0) as u32;
    let guest_phys = vcpu
        .try_get(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL)
        .unwrap_or(0);

    // For I/O instruction exits (exit reason 30), extract port/size/direction
    // from the exit qualification via the typed decoder.
    const IO_EXIT_REASON: u32 = 30;
    let (io_port, io_size, io_is_write) = if exit_reason == IO_EXIT_REASON {
        let info = crate::arch::x86_64::vmexit_decode::ExitQualification(exit_qual).io();
        (
            info.port_or_dx(vcpu),
            info.size,
            if info.is_write { 1u8 } else { 0u8 },
        )
    } else {
        (0u16, 0u8, 0u8)
    };

    let mut msg = InterceptMessage {
        header: ThemicMessageHeader {
            message_type: THEMIC_MSG_VP_INTERCEPT,
            payload_size: (core::mem::size_of::<InterceptMessage>()
                - core::mem::size_of::<ThemicMessageHeader>())
                as u32,
            sequence: 0,
        },
        exit_reason,
        instruction_length: instr_len,
        exit_qualification: exit_qual,
        guest_physical_address: guest_phys,
        port_number: io_port,
        access_size: io_size,
        is_write: io_is_write,
        ..InterceptMessage::default()
    };

    // ── MMIO instruction decode for EPT violations ──
    // Supply the raw instruction bytes so CHV's iced-x86 emulator can decode
    // and emulate the faulting instruction.
    if is_ept_violation {
        let guest_rip = vcpu.rip();
        let hhdm = platform.hhdm_offset();
        let ept_root = {
            let child_arc = platform
                .domain_arc(child_domain_id)
                .expect("[CHILD_EXIT] child PlatformDomain not found");
            let cd = child_arc.lock();
            cd.arch.ept().map(|e| e.root_phys())
        };
        if let Some(ept_root) = ept_root {
            let guest_cr3 = vcpu.try_get(vmcs::guest::CR3).unwrap_or(0);
            if let Some(insn_gpa) = crate::arch::x86_64::page_walk::guest_gva_to_gpa(ept_root, hhdm, guest_cr3, guest_rip) {
                if let Some(insn_hpa) = crate::arch::x86_64::page_walk::ept_gpa_to_hpa(ept_root, hhdm, insn_gpa) {
                    let insn_ptr = (insn_hpa + hhdm) as *const u8;
                    let mut insn_bytes = [0u8; 16];
                    let avail = core::cmp::min(16, 0x1000 - (insn_hpa & 0xFFF) as usize);
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            insn_ptr,
                            insn_bytes.as_mut_ptr(),
                            avail,
                        );
                    }
                    msg.instruction_bytes = insn_bytes;
                } else {
                    serial_println!("[MMIO-DECODE] EPT fail GPA {:#x}", insn_gpa);
                }
            } else {
                serial_println!("[MMIO-DECODE] GVA fail RIP {:#x}", guest_rip);
            }
        }
    }

    // ── Copy filtered regs + intercept message into child's COMM page ──
    copy_filtered_regs_to_comm(
        platform,
        vcpu,
        child_domain_id,
        child_vp_id,
        read_set,
        Some(&msg),
    );

    // Advance the child's RIP past the faulting instruction while the
    // child VMCS is still loaded. EPT violations are handled differently:
    // CHV's iced-x86 emulator decodes the instruction, emulates it, and
    // advances RIP itself. We must NOT advance RIP here for EPT violations.
    if !is_ept_violation {
        vcpu.next_rip();
    }

    // ── Swap child → parent via the shared helper. ──
    unsafe {
        swap_active_vp(
            vcpu,
            platform,
            (child_domain_id, child_vp_id),
            (parent_domain_id, parent_vp_id),
            "CHILD_EXIT",
        );
    }
    // IRTE.NDST sync is not needed here: the parent (dom0) uses remapped IRTEs
    // (not posted), so its interrupts are not routed via posted-interrupt NDST.

    // To the parent, this is a return from SWITCH VMCALL.
    // RAX = SUCCESS, RDI = exit_reason. (The parent's RIP was advanced past
    // the SWITCH VMCALL in `do_switch` before VMCLEAR-ing its VMCS.)
    write_swap_reply(vcpu, errors::SUCCESS, exit_reason as u64);
}


// ── Interrupt forwarding ─────────────────────────────────────────────────── //
/// child domain VP is running on this core.
///
/// Routes the interrupt to the handler (Deliver-policy ancestor, which in Phase 1
/// is always dom0) using the lazy-unwind model:
///
/// 1. `deliver_interrupt_vp`: transitions child VP → Available, dom0 VP → Running.
/// 2. VMCLEAR child → store InactiveVcpu in child's VcpuSlot.
/// 3. Take dom0's InactiveVcpu from dom0's VcpuSlot → VMPTRLD dom0.
/// 4. Set `VMENTRY_INTERRUPTION_INFO_FIELD` = external interrupt V (type=0, valid).
/// 5. Dom0 RIP is left unchanged (stays AT the SWITCH VMCALL, since `do_switch`
///    does not advance RIP before storing dom0 to its slot).  After the interrupt
///    fires and `iret` returns, dom0 re-executes SWITCH → finds child VP Available
///    → VMLAUNCH resumes child from its saved VMCS state.
///
/// Routing uses `InterruptPolicy`: if the running child domain has `Deliver`
/// visibility for this vector, the interrupt is injected directly into the child
/// (it owns the vector).  Otherwise (Report/NotReport) the interrupt is forwarded
/// to dom0 via lazy-unwind.
pub(crate) fn forward_interrupt_to_handler(vcpu: &mut ActiveVcpu, vector: u8) {
    let (platform, core_id, child_cap) = current_core_child_cap("INTR_FWD");

    // Consult the child's interrupt policy for this vector.
    let child_visibility = child_cap
        .read()
        .data
        .policy
        .interrupts
        .get_policy(vector)
        .visibility;

    // Diagnostic: log first 20 + every 500th call to trace interrupt routing.
    {
        use core::sync::atomic::{AtomicU64, Ordering as O};
        static FWD_COUNT: AtomicU64 = AtomicU64::new(0);
        let n = FWD_COUNT.fetch_add(1, O::Relaxed);
        if n < 20 || n % 500 == 0 {
            serial_rtdbg!(
                "[INTR_FWD] #{} vec={:#x} vis={:?} core={}",
                n,
                vector,
                child_visibility,
                core_id
            );
        }
    }

    serial_rtdbg!("[INTR_FWD] vec={} vis={:?}", vector, child_visibility);
    if child_visibility == InterruptVisibility::Deliver {
        // Child owns this vector — inject directly without context switch.
        if vcpu.guest_can_accept_external() {
            vcpu.inject_external_vector(vector);
        } else {
            unsafe { inject_via_pid(vcpu.pid_phys(), platform.hhdm_offset(), vector, false) };
            vcpu.set_interrupt_window_exit(true);
        }
        return;
    }

    // Look up the interrupt policy read_set for register filtering.
    let read_set = child_cap
        .read()
        .data
        .policy
        .interrupts
        .get_policy(vector)
        .read_set;

    // Lazy-unwind: child VP → Interrupted, handler VP → Running.
    let intr_ctx = match Capability::deliver_interrupt_vp(
        platform,
        &child_cap,
        core_id,
        vector,
    ) {
        Ok((ctx, _batch)) => ctx,
        Err(_e) => {
            serial_debug!(
                "[INTR_FWD] interrupt routing failed: {:?}",
                _e
            );
            return;
        }
    };

    // Copy child registers allowed by InterruptPolicy.read_set into comm page.
    use themis_abi::regs::{
        InterceptMessage, ThemicMessageHeader, THEMIC_MSG_VP_INTERCEPT,
    };
    let msg = InterceptMessage {
        header: ThemicMessageHeader {
            message_type: THEMIC_MSG_VP_INTERCEPT,
            payload_size: (core::mem::size_of::<InterceptMessage>()
                - core::mem::size_of::<ThemicMessageHeader>())
                as u32,
            sequence: 0,
        },
        exit_reason: crate::arch::x86_64::vmexit::EXIT_REASON_EXTERNAL_INTERRUPT,
        exit_qualification: vector as u64,
        ..InterceptMessage::default()
    };
    copy_filtered_regs_to_comm(
        platform,
        vcpu,
        intr_ctx.interrupted_domain.read().data.id,
        intr_ctx.interrupted_vp_id as usize,
        read_set,
        Some(&msg),
    );

    // ── Swap child → handler via the shared helper. ──
    unsafe {
        swap_active_vp(
            vcpu,
            platform,
            (
                intr_ctx.interrupted_domain.read().data.id,
                intr_ctx.interrupted_vp_id as usize,
            ),
            (
                intr_ctx.handler_domain.read().data.id,
                intr_ctx.handler_vp_id as usize,
            ),
            "INTR_FWD",
        );
    }

    // Inject the interrupt via VM-entry event injection.
    // Format: bit 31=valid, bits [10:8]=type (0=external interrupt), bits [7:0]=vector.
    // Guard: injecting with IF=0 or STI/MOV-SS blocking causes VM-entry failure.
    if vcpu.guest_can_accept_external() {
        vcpu.inject_external_vector(vector);
    } else {
        unsafe { inject_via_pid(vcpu.pid_phys(), platform.hhdm_offset(), vector, false) };
        vcpu.set_interrupt_window_exit(true);
    }

    // Return ERR_RETRY with the preempting vector in RDI (per A3 contract).
    // Per the VcpuSlot RIP invariant (see do_switch step 4), the handler's
    // saved RIP is already past its SWITCH VMCALL — no advance needed here.
    write_swap_reply(vcpu, errors::ERR_RETRY, vector as u64);
}
