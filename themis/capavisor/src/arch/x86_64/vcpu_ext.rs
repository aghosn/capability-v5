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
}
