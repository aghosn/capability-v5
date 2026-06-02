//! RDMSR / WRMSR local handlers (exit reasons 31, 32).
//!
//! Pass through safe MSRs via `msr_virt`, emulate IA32_EFER from the VMCS,
//! inject #GP for blocked MSRs.

use x86::msr;
use x86::vmx::vmcs;

use crate::vcpu::{ActiveVcpu, Reg};
use crate::arch::x86_64::vcpu_ext::ActiveVcpuExt;

use super::{inject_gp, MSR_LOW_MASK};

/// Handle RDMSR locally (exit reason 31).
///
/// Reads MSR via msr_virt virtualisation layer, passes through safe MSRs,
/// injects #GP for blocked ones.
pub(super) fn handle_rdmsr_local(vcpu: &mut ActiveVcpu) {
    let ecx = vcpu.reg(Reg::Rcx) as u32;
    if ecx == msr::IA32_EFER {
        let value = vcpu.get(vmcs::guest::IA32_EFER_FULL);
        vcpu.set_reg(Reg::Rax, value & MSR_LOW_MASK);
        vcpu.set_reg(Reg::Rdx, (value >> 32) & MSR_LOW_MASK);
        vcpu.next_rip();
    } else {
        match crate::arch::msr_virt::handle_rdmsr(ecx) {
            crate::arch::msr_virt::MsrResult::Emulated(v) => {
                vcpu.set_reg(Reg::Rax, v & MSR_LOW_MASK);
                vcpu.set_reg(Reg::Rdx, (v >> 32) & MSR_LOW_MASK);
                vcpu.next_rip();
            }
            crate::arch::msr_virt::MsrResult::Passthrough => {
                if crate::arch::msr_virt::in_bitmap_range(ecx) {
                    let value = unsafe { msr::rdmsr(ecx) };
                    vcpu.set_reg(Reg::Rax, value & MSR_LOW_MASK);
                    vcpu.set_reg(Reg::Rdx, (value >> 32) & MSR_LOW_MASK);
                    vcpu.next_rip();
                } else {
                    inject_gp(vcpu);
                }
            }
            crate::arch::msr_virt::MsrResult::GpFault => {
                inject_gp(vcpu);
            }
        }
    }
}

/// Handle WRMSR locally (exit reason 32).
pub(super) fn handle_wrmsr_local(vcpu: &mut ActiveVcpu) {
    let ecx = vcpu.reg(Reg::Rcx) as u32;
    let value = ((vcpu.reg(Reg::Rdx) & MSR_LOW_MASK) << 32) | (vcpu.reg(Reg::Rax) & MSR_LOW_MASK);
    if ecx == msr::IA32_EFER {
        vcpu.set(vmcs::guest::IA32_EFER_FULL, value);
        vcpu.next_rip();
    } else {
        match crate::arch::msr_virt::handle_wrmsr(ecx, value) {
            crate::arch::msr_virt::MsrResult::Emulated(_) => {
                vcpu.next_rip();
            }
            crate::arch::msr_virt::MsrResult::Passthrough => {
                if crate::arch::msr_virt::in_bitmap_range(ecx) {
                    unsafe { msr::wrmsr(ecx, value) };
                    vcpu.next_rip();
                } else {
                    inject_gp(vcpu);
                }
            }
            crate::arch::msr_virt::MsrResult::GpFault => {
                inject_gp(vcpu);
            }
        }
    }
}
