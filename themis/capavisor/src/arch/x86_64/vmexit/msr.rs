//! RDMSR / WRMSR local handlers (exit reasons 31, 32).
//!
//! Reached only for MSRs whose per-domain `MsrPolicy` resolves to `Native`
//! but still trap — i.e. MSRs outside the two ranges the VMX MSR bitmap can
//! express (SDM Vol 3C §24.6.9), which always VM-exit regardless of the
//! bitmap. Emulates `IA32_EFER` from the VMCS, passes through any other
//! in-bitmap-range MSR, injects #GP otherwise.
//!
//! MSRs the policy resolves to `Trap`/`Emulate` never reach this file —
//! they're dispatched generically by `monitor.rs` against the capability
//! engine's `MsrPolicy` before `handle_local` is ever called.

use x86::msr;
use x86::vmx::vmcs;

use crate::vcpu::{ActiveVcpu, Reg};
use crate::arch::x86_64::vcpu_ext::ActiveVcpuExt;

use super::{inject_gp, MSR_LOW_MASK};

/// Handle RDMSR locally (exit reason 31).
pub(super) fn handle_rdmsr_local(vcpu: &mut ActiveVcpu) {
    let ecx = vcpu.reg(Reg::Rcx) as u32;
    if ecx == msr::IA32_EFER {
        let value = vcpu.get(vmcs::guest::IA32_EFER_FULL);
        vcpu.set_reg(Reg::Rax, value & MSR_LOW_MASK);
        vcpu.set_reg(Reg::Rdx, (value >> 32) & MSR_LOW_MASK);
        vcpu.next_rip();
    } else if crate::arch::msr_bitmap::in_bitmap_range(ecx) {
        let value = unsafe { msr::rdmsr(ecx) };
        vcpu.set_reg(Reg::Rax, value & MSR_LOW_MASK);
        vcpu.set_reg(Reg::Rdx, (value >> 32) & MSR_LOW_MASK);
        vcpu.next_rip();
    } else {
        inject_gp(vcpu);
    }
}

/// Handle WRMSR locally (exit reason 32).
pub(super) fn handle_wrmsr_local(vcpu: &mut ActiveVcpu) {
    let ecx = vcpu.reg(Reg::Rcx) as u32;
    let value = ((vcpu.reg(Reg::Rdx) & MSR_LOW_MASK) << 32) | (vcpu.reg(Reg::Rax) & MSR_LOW_MASK);
    if ecx == msr::IA32_EFER {
        vcpu.set(vmcs::guest::IA32_EFER_FULL, value);
        vcpu.next_rip();
    } else if crate::arch::msr_bitmap::in_bitmap_range(ecx) {
        unsafe { msr::wrmsr(ecx, value) };
        vcpu.next_rip();
    } else {
        inject_gp(vcpu);
    }
}
