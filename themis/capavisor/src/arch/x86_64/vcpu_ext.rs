//! Ergonomic accessors for the foreign `vmx::ActiveVcpu` type.
//!
//! `ActiveVcpu` is defined in the external `vmx` crate so the orphan rule
//! prevents adding inherent methods to it from the capavisor. This module
//! provides a local extension trait that wraps the verbose
//! `vcpu.get(vmcs::guest::FIELD)` / `vcpu.set(vmcs::guest::FIELD, value)`
//! pattern for the three VMCS-resident registers that capavisor reads/writes
//! pervasively (RIP, RSP, RFLAGS), plus `next_rip()` to advance RIP past the
//! current instruction.
//!
//! General-purpose registers are not wrapped here: `ActiveVcpu::get_reg(Reg)`
//! from the `vmx` crate already provides typed access for those.

use x86::vmx::vmcs;

use crate::vcpu::ActiveVcpu;

// ── Guest interruptibility constants (Intel SDM Vol 3C §24.4.2, §27.2.1) ── //

/// RFLAGS bit 9: Interrupt Flag. Guest can accept interrupts when set.
const RFLAGS_IF: u64 = 1 << 9;
/// Interruptibility-state bits [1:0]: blocking by STI (bit 0) or MOV SS (bit 1).
const INTERRUPTIBILITY_STI_MOV_SS: u64 = 0x3;
/// PRIMARY_PROCBASED_EXEC_CONTROLS bit 2: interrupt-window exiting (Intel SDM §24.6.2).
const PRIMARY_INTERRUPT_WINDOW_EXITING: u64 = 1 << 2;
/// VMENTRY_INTERRUPTION_INFO_FIELD: bit 31 = valid, bits [10:8] = type (0 = external).
const VMENTRY_INTR_INFO_VALID: u64 = 1 << 31;
/// PIN_BASED_EXEC_CONTROLS bit 7: process posted interrupts (Intel SDM §24.6.1).
const PINBASED_PROCESS_POSTED_INTR: u64 = 1 << 7;
/// VMENTRY_CONTROLS bit 9: IA-32e mode guest (Intel SDM §24.8.1).
const VMENTRY_IA32E_MODE_GUEST: u64 = 1 << 9;

pub trait ActiveVcpuExt {
    fn rip(&self) -> u64;
    fn set_rip(&mut self, value: u64);
    fn rsp(&self) -> u64;
    fn set_rsp(&mut self, value: u64);
    fn rflags(&self) -> u64;
    #[allow(dead_code)]
    fn set_rflags(&mut self, value: u64);

    /// Advance guest RIP past the instruction that caused the current
    /// VMEXIT, using VMCS field `VMEXIT_INSTRUCTION_LEN`.
    fn next_rip(&mut self);

    /// Schedule an external-interrupt injection for the next VM entry by
    /// writing `VMENTRY_INTERRUPTION_INFO_FIELD` (type=external, valid=1).
    ///
    /// Caller is responsible for any guest-acceptability gate; the processor
    /// will fail VM entry if RFLAGS.IF=0 or STI/MOV-SS blocking is active.
    /// See [`guest_can_accept_external`](Self::guest_can_accept_external).
    fn inject_external_vector(&mut self, vector: u8);

    /// Returns `true` iff the guest currently has RFLAGS.IF=1 and is not
    /// blocked by STI or MOV-SS interruptibility shadows — i.e. it would
    /// accept a freshly-injected external interrupt at the next VM entry.
    fn guest_can_accept_external(&self) -> bool;

    /// Toggle interrupt-window exiting in `PRIMARY_PROCBASED_EXEC_CONTROLS`
    /// so the processor exits as soon as the guest can accept an interrupt.
    fn set_interrupt_window_exit(&mut self, enabled: bool);

    /// Returns `true` iff posted-interrupt processing is enabled on this VP
    /// (`PIN_BASED_EXEC_CONTROLS` bit 7). When set, callers should route
    /// notifications via the PID; otherwise fall back to VM-entry injection.
    fn posted_interrupts_enabled(&self) -> bool;

    /// Track guest EFER.LMA in `VMENTRY_CONTROLS.IA32E_MODE_GUEST` (bit 9).
    /// VM entry consistency requires this bit to match EFER.LMA — see
    /// Intel SDM Vol 3C §26.3.1.1. Used by `SET_REG(EFER)`.
    fn set_long_mode_guest(&mut self, lma: bool);
}

impl ActiveVcpuExt for ActiveVcpu {
    #[inline]
    fn rip(&self) -> u64 {
        self.get(vmcs::guest::RIP)
    }

    #[inline]
    fn set_rip(&mut self, value: u64) {
        self.set(vmcs::guest::RIP, value);
    }

    #[inline]
    fn rsp(&self) -> u64 {
        self.get(vmcs::guest::RSP)
    }

    #[inline]
    fn set_rsp(&mut self, value: u64) {
        self.set(vmcs::guest::RSP, value);
    }

    #[inline]
    fn rflags(&self) -> u64 {
        self.get(vmcs::guest::RFLAGS)
    }

    #[inline]
    fn set_rflags(&mut self, value: u64) {
        self.set(vmcs::guest::RFLAGS, value);
    }

    #[inline]
    fn next_rip(&mut self) {
        let len = self.get(vmcs::ro::VMEXIT_INSTRUCTION_LEN);
        let rip = self.get(vmcs::guest::RIP);
        self.set(vmcs::guest::RIP, rip + len);
    }

    #[inline]
    fn inject_external_vector(&mut self, vector: u8) {
        let intr_info = VMENTRY_INTR_INFO_VALID | (vector as u64);
        self.set(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, intr_info);
    }

    #[inline]
    fn guest_can_accept_external(&self) -> bool {
        let if_set = self.get(vmcs::guest::RFLAGS) & RFLAGS_IF != 0;
        let blocking =
            self.get(vmcs::guest::INTERRUPTIBILITY_STATE) & INTERRUPTIBILITY_STI_MOV_SS != 0;
        if_set && !blocking
    }

    #[inline]
    fn set_interrupt_window_exit(&mut self, enabled: bool) {
        let primary = self.get(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS);
        let new = if enabled {
            primary | PRIMARY_INTERRUPT_WINDOW_EXITING
        } else {
            primary & !PRIMARY_INTERRUPT_WINDOW_EXITING
        };
        self.set(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS, new);
    }

    #[inline]
    fn posted_interrupts_enabled(&self) -> bool {
        self.get(vmcs::control::PINBASED_EXEC_CONTROLS) & PINBASED_PROCESS_POSTED_INTR != 0
    }

    #[inline]
    fn set_long_mode_guest(&mut self, lma: bool) {
        let entry = self.get(vmcs::control::VMENTRY_CONTROLS);
        let new = if lma {
            entry | VMENTRY_IA32E_MODE_GUEST
        } else {
            entry & !VMENTRY_IA32E_MODE_GUEST
        };
        if new != entry {
            self.set(vmcs::control::VMENTRY_CONTROLS, new);
        }
    }
}
