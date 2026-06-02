//! CR-access exit handler (exit reason 28).
//!
//! Emulates MOV to/from CR0/CR3/CR4/CR8 and mirrors EFER.LMA on
//! paging-enable transitions.

use x86::controlregs::{Cr0, Cr4};
use x86::vmx::vmcs;
use x86::vmx::vmcs::control;

use crate::arch::x86_64::vmexit_decode::{ControlReg, CrAccessInfo, ExitQualification};
use crate::arch::x86_64::vcpu_ext::ActiveVcpuExt;
use crate::serial_debug;
use crate::vcpu::ActiveVcpu;

use super::Ia32Efer;

/// CR access exit (reason 28).
///
/// Emulates MOV to/from CR0/CR3/CR4/CR8.
pub(super) fn handle_cr_access(vcpu: &mut ActiveVcpu) {
    let info = ExitQualification(vcpu.get(vmcs::ro::EXIT_QUALIFICATION)).cr();

    match info {
        CrAccessInfo::MovToCr { cr, src } => {
            let val = src.read(vcpu);
            match cr {
                ControlReg::Cr0 => {
                    let cr0_mask = vcpu.get(control::CR0_GUEST_HOST_MASK);
                    let old_cr0 = vcpu.get(vmcs::guest::CR0);
                    let new_cr0 = (old_cr0 & cr0_mask) | (val & !cr0_mask);
                    vcpu.set(vmcs::guest::CR0, new_cr0);

                    // Entering paging with EFER.LME set => transition to long
                    // mode; mirror by setting EFER.LMA (SDM Vol 3A §9.8.5).
                    let pg = Cr0::CR0_ENABLE_PAGING.bits() as u64;
                    if (old_cr0 & pg) == 0 && (new_cr0 & pg) != 0 {
                        let efer = vcpu.get(vmcs::guest::IA32_EFER_FULL);
                        if efer & Ia32Efer::LME.bits() != 0 {
                            vcpu.set(
                                vmcs::guest::IA32_EFER_FULL,
                                efer | Ia32Efer::LMA.bits(),
                            );
                        }
                    }
                }
                ControlReg::Cr3 => vcpu.set(vmcs::guest::CR3, val),
                ControlReg::Cr4 => {
                    // Keep VMXE forced on — the guest cannot clear it without
                    // immediate vmentry failure.
                    let val = val | (Cr4::CR4_ENABLE_VMX.bits() as u64);
                    vcpu.set(vmcs::guest::CR4, val);
                }
                ControlReg::Cr8 => { /* CR8 / TPR — ignore for now */ }
                ControlReg::Other(_n) => {
                    serial_debug!("[VMEXIT] MOV to CR{} val={:#x} (unexpected)", _n, val);
                }
            }
        }
        CrAccessInfo::MovFromCr { cr, dst } => {
            let val = match cr {
                ControlReg::Cr0 => vcpu.get(vmcs::guest::CR0),
                ControlReg::Cr3 => vcpu.get(vmcs::guest::CR3),
                ControlReg::Cr4 => vcpu.get(vmcs::guest::CR4),
                _ => 0,
            };
            dst.write(vcpu, val);
        }
        CrAccessInfo::Clts | CrAccessInfo::LmswRegister { .. } | CrAccessInfo::LmswMemory { .. } => {
            // CLTS/LMSW unhandled today; just advance RIP.
        }
    }
    vcpu.next_rip();
}
