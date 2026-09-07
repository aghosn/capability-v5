//! x86-64 implementation of `ArchHypercall`.
//!
//! Hosts the per-opcode handlers that need raw x86 VP state (VMCS, PIR, VMX
//! intrinsics) and exposes them to the generic dispatcher in
//! `crate::hypercall::handle_vmcall` via the `ArchHypercall` trait impl below.
//!
//! Submodules:
//!   - `switch`   — `do_switch` + the swap mechanics it shares with
//!                  `forward_child_exit` / `forward_interrupt_to_handler`
//!                  / `drain_pir_on_interrupt_window`.
//!   - `doorbell` — `do_ring_doorbell`, `do_inject_interrupt`.
//!   - `vp`       — `do_add_vp`.

pub mod doorbell;
pub mod switch;
pub mod vp;

use capability_engine::{CapabilityRef, Domain};

use crate::arch::x86_64::x86_platform::X86Platform;
use crate::hypercall::{ArchHypercall, HypercallResult};
use crate::platform::ThemisPlatform;
use crate::vcpu::ActiveVcpu;

/// Write a hypercall result into the calling VP's reply registers
/// (RAX/RDI/RSI/RDX). Does NOT advance RIP — callers must invoke
/// `vcpu.next_rip()` separately. Used by the x86 swap-handler early-error
/// paths in `switch.rs` / `doorbell.rs`, which write the reply themselves
/// rather than going through the generic dispatcher.
pub(super) fn write_reply(vcpu: &mut ActiveVcpu, r: HypercallResult) {
    use crate::vcpu::Reg;
    vcpu.set_reg(Reg::Rax, r.status);
    vcpu.set_reg(Reg::Rdi, r.val0);
    vcpu.set_reg(Reg::Rsi, r.val1);
    vcpu.set_reg(Reg::Rdx, r.val2);
}

impl ArchHypercall for X86Platform {
    fn h_add_vp(
        &mut self,
        _vcpu: &mut ActiveVcpu,
        platform: &ThemisPlatform,
        caller: &CapabilityRef<Domain>,
        child_domain_handle: u64,
        comm_cap_handle: u64,
    ) -> HypercallResult {
        vp::do_add_vp(platform, caller, child_domain_handle, comm_cap_handle)
    }

    fn h_switch(
        &mut self,
        vcpu: &mut ActiveVcpu,
        platform: &ThemisPlatform,
        caller: &CapabilityRef<Domain>,
        to_domain_handle: u64,
        vp_id: u64,
    ) {
        switch::do_switch(platform, caller, to_domain_handle, vp_id, vcpu);
    }

    fn h_ring_doorbell(
        &mut self,
        vcpu: &mut ActiveVcpu,
        platform: &ThemisPlatform,
        caller: &CapabilityRef<Domain>,
        gpa: u64,
        value: u64,
    ) {
        doorbell::do_ring_doorbell(platform, caller, gpa, value, vcpu);
    }

    fn h_inject_interrupt(
        &mut self,
        _vcpu: &mut ActiveVcpu,
        platform: &ThemisPlatform,
        caller: &CapabilityRef<Domain>,
        child_domain_handle: u64,
        vp_id: u32,
        vector: u8,
    ) -> HypercallResult {
        doorbell::do_inject_interrupt(platform, caller, child_domain_handle, vp_id, vector)
    }
}
