//! VMX exit-reason classifier — the front door of the monitor loop.
//!
//! Maps a raw VMX exit reason into a [`SemanticExit`], handling
//! arch-internal exits (INIT, XSETBV, interrupt-window, EOI-induced)
//! directly and returning `SemanticExit::ArchHandled` for them.
//!
//! Exits that need the generic monitor loop's attention are returned as
//! `Hypercall`, `ExternalInterrupt`, `TimerExpired`, `PolicyDriven`, or
//! `Shutdown`.

use x86::vmx::vmcs;

use crate::arch_traits::types::{ExitInfo, SemanticExit};
use crate::arch::x86_64::vmexit_decode::{intr_type, ApicAccessType, ExitQualification, IntrInfo};
use crate::vcpu::{ActiveVcpu, Reg};

use super::{
    apic, fatal, handle_xsetbv, APIC_REG_ICR_HIGH, APIC_REG_ICR_LOW,
    EXIT_REASON_APIC_ACCESS, EXIT_REASON_APIC_WRITE, EXIT_REASON_CPUID, EXIT_REASON_CR_ACCESS,
    EXIT_REASON_EOI_INDUCED, EXIT_REASON_EPT_MISCONFIG, EXIT_REASON_EPT_VIOLATION,
    EXIT_REASON_EXCEPTION_NMI, EXIT_REASON_EXTERNAL_INTERRUPT, EXIT_REASON_HLT,
    EXIT_REASON_INIT_SIGNAL, EXIT_REASON_INTERRUPT_WINDOW, EXIT_REASON_IO_INSTRUCTION,
    EXIT_REASON_RDMSR, EXIT_REASON_SIPI, EXIT_REASON_TRIPLE_FAULT,
    EXIT_REASON_VMCALL, EXIT_REASON_VMENTRY_INVALID_GUEST, EXIT_REASON_VMX_PREEMPTION_TIMER,
    EXIT_REASON_WRMSR, EXIT_REASON_XSETBV, MSR_LOW_MASK,
};

/// Classify a raw VMX exit reason into a [`SemanticExit`], handling
/// arch-internal exits (INIT, XSETBV, interrupt-window, EOI-induced)
/// directly and returning `SemanticExit::ArchHandled` for them.
///
/// This is the x86 implementation of `ArchVpOps::run`'s
/// decode + internal-handling phase. Called after `vcpu.run()` succeeds.
///
/// Exits that need the generic monitor loop's attention are returned as
/// `Hypercall`, `ExternalInterrupt`, `TimerExpired`, `PolicyDriven`, or
/// `Shutdown`.
pub(crate) fn classify_and_handle_internal(
    vcpu: &mut ActiveVcpu,
    reason: u32,
    platform: &crate::platform::ThemisPlatform,
) -> SemanticExit {
    use capability_engine::Platform;
    match reason {
        // ── Fatal exits ──
        EXIT_REASON_VMENTRY_INVALID_GUEST => {
            use core::sync::atomic::Ordering;
            let platform_ptr = crate::PLATFORM_PTR.load(Ordering::Acquire);
            let p = if !platform_ptr.is_null() {
                Some(unsafe { &*platform_ptr })
            } else {
                None
            };
            let cid = p
                .map(|p| p.get_current_core().unwrap_or(0) as usize)
                .unwrap_or(0);
            fatal::dump_vmentry_failure(vcpu, p, cid);
            SemanticExit::Shutdown { reason }
        }
        EXIT_REASON_TRIPLE_FAULT => {
            fatal::dump_triple_fault(vcpu);
            SemanticExit::Shutdown { reason }
        }
        EXIT_REASON_EPT_MISCONFIG => {
            fatal::dump_ept_misconfig(vcpu);
            SemanticExit::Shutdown { reason }
        }

        // ── Arch-internal exits (handled here, never reach generic loop) ──
        EXIT_REASON_INIT_SIGNAL => {
            platform.poll_and_respond_cross_core();
            SemanticExit::ArchHandled
        }
        EXIT_REASON_XSETBV => {
            handle_xsetbv(vcpu);
            SemanticExit::ArchHandled
        }
        EXIT_REASON_INTERRUPT_WINDOW => {
            crate::arch::x86_64::hypercall::switch::drain_pir_on_interrupt_window(vcpu, platform);
            SemanticExit::ArchHandled
        }
        EXIT_REASON_EOI_INDUCED => {
            // A3: EOI-exit bitmap is all-zero → should never fire.
            SemanticExit::ArchHandled
        }

        // ── Always-generic exits ──
        EXIT_REASON_VMCALL => SemanticExit::Hypercall,

        EXIT_REASON_EXTERNAL_INTERRUPT => {
            let info = IntrInfo(vcpu.get(vmcs::ro::VMEXIT_INTERRUPTION_INFO));
            SemanticExit::ExternalInterrupt { vector: info.vector() as u32 }
        }

        EXIT_REASON_VMX_PREEMPTION_TIMER => SemanticExit::TimerExpired,

        // ── EXCEPTION_NMI: split NMI (→ interrupt routing) vs exception (→ policy) ──
        EXIT_REASON_EXCEPTION_NMI => {
            let intr_info = IntrInfo(vcpu.get(vmcs::ro::VMEXIT_INTERRUPTION_INFO));
            if intr_info.intr_type() == intr_type::NMI {
                // NMI → route like an interrupt (vector 2).
                SemanticExit::ExternalInterrupt {
                    vector: x86::irq::NONMASKABLE_INTERRUPT_VECTOR as u32,
                }
            } else {
                let error_code = if intr_info.delivers_error_code() {
                    Some(vcpu.get(vmcs::ro::VMEXIT_INTERRUPTION_ERR_CODE) as u32)
                } else {
                    None
                };
                SemanticExit::PolicyDriven {
                    reason,
                    info: ExitInfo::Exception {
                        vector: intr_info.vector(),
                        error_code,
                        is_nmi: false,
                    },
                }
            }
        }

        // ── CPUID: all leaves go through policy-driven path ──
        // The parent domain controls what the child sees via Native/Emulate/Trap
        // overrides.  Native falls through to handle_cpuid_local which has the
        // capavisor's own leaf responses.
        EXIT_REASON_CPUID => {
            let leaf = vcpu.reg(Reg::Rax) as u32;
            let subleaf = vcpu.reg(Reg::Rcx) as u32;
            SemanticExit::PolicyDriven {
                reason,
                info: ExitInfo::Cpuid { leaf, subleaf },
            }
        }

        // ── APIC access/write: ICR writes → policy (parent needs for SIPI), others → local ──
        EXIT_REASON_APIC_ACCESS => {
            let info = ExitQualification(vcpu.get(vmcs::ro::EXIT_QUALIFICATION)).apic();
            let is_icr_write = info.access == ApicAccessType::DataWrite
                && info.offset == Some(APIC_REG_ICR_LOW);
            if is_icr_write {
                // ICR write — decode value for parent.
                let icr_low =
                    apic::decode_apic_write_value(vcpu, platform).unwrap_or(vcpu.reg(Reg::Rax) as u32);
                let hhdm = platform.hhdm_offset();
                let vapic = (vcpu.vapic_phys() + hhdm) as *const u32;
                let icr_high = unsafe { vapic.add(APIC_REG_ICR_HIGH / 4).read_volatile() };
                vcpu.set_reg(Reg::Rax, icr_low as u64);
                vcpu.set_reg(Reg::Rcx, icr_high as u64);
                SemanticExit::PolicyDriven {
                    reason,
                    info: ExitInfo::ApicIcr { icr_low, icr_high },
                }
            } else {
                apic::handle_apic_access_exit(vcpu, platform);
                SemanticExit::ArchHandled
            }
        }
        EXIT_REASON_APIC_WRITE => {
            let info = ExitQualification(vcpu.get(vmcs::ro::EXIT_QUALIFICATION)).apic();
            if info.offset == Some(APIC_REG_ICR_LOW) {
                // ICR write under VIRT_X2APIC_MODE / APIC_REGISTER_VIRT:
                // hardware has already deposited the value into the
                // virtual-APIC page before exit.  For x2APIC WRMSR(0x830)
                // the 64-bit value is split into VAPIC[0x300] (low) +
                // VAPIC[0x310] (high, holding the raw 32-bit destination
                // APIC ID — SDM §29.5.1).  The downstream parent (CHV)
                // decodes ICR_HIGH as xAPIC (dest in bits [31:24]); since
                // child VMs are pinned to x2APIC mode by capavisor we
                // normalize the destination back into the xAPIC layout
                // here so the parent's existing decoder works unchanged.
                let hhdm = platform.hhdm_offset();
                let vapic_virt = (vcpu.vapic_phys() + hhdm) as *const u32;
                let icr_low = unsafe { vapic_virt.add(APIC_REG_ICR_LOW / 4).read_volatile() };
                let icr_high_x2 = unsafe { vapic_virt.add(APIC_REG_ICR_HIGH / 4).read_volatile() };
                let icr_high = (icr_high_x2 & 0xFF) << 24;
                vcpu.set_reg(Reg::Rax, icr_low as u64);
                vcpu.set_reg(Reg::Rcx, icr_high as u64);
                SemanticExit::PolicyDriven {
                    reason: EXIT_REASON_APIC_ACCESS, // normalize to APIC_ACCESS for parent
                    info: ExitInfo::ApicIcr { icr_low, icr_high },
                }
            } else {
                // Non-ICR APIC write: hardware handled (VID for EOI, etc.)
                SemanticExit::ArchHandled
            }
        }

        // ── Policy-driven exits with decoded info ──
        EXIT_REASON_EPT_VIOLATION => {
            let gpa = vcpu.get(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL);
            let qual = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
            SemanticExit::PolicyDriven {
                reason,
                info: ExitInfo::EptViolation {
                    gpa,
                    qualification: qual,
                },
            }
        }

        EXIT_REASON_IO_INSTRUCTION => {
            let info = ExitQualification(vcpu.get(vmcs::ro::EXIT_QUALIFICATION)).io();
            SemanticExit::PolicyDriven {
                reason,
                info: ExitInfo::IoInstruction {
                    port: info.port_or_dx(vcpu),
                    size: info.size,
                    is_write: info.is_write,
                    value: vcpu.reg(Reg::Rax) as u32,
                },
            }
        }

        EXIT_REASON_CR_ACCESS => {
            let qual = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
            SemanticExit::PolicyDriven {
                reason,
                info: ExitInfo::CrAccess {
                    qualification: qual,
                },
            }
        }

        EXIT_REASON_RDMSR => {
            let ecx = vcpu.reg(Reg::Rcx) as u32;
            SemanticExit::PolicyDriven {
                reason,
                info: ExitInfo::Msr {
                    number: ecx,
                    is_write: false,
                    value: 0,
                },
            }
        }

        EXIT_REASON_WRMSR => {
            let ecx = vcpu.reg(Reg::Rcx) as u32;
            let value =
                ((vcpu.reg(Reg::Rdx) & MSR_LOW_MASK) << 32) | (vcpu.reg(Reg::Rax) & MSR_LOW_MASK);
            SemanticExit::PolicyDriven {
                reason,
                info: ExitInfo::Msr {
                    number: ecx,
                    is_write: true,
                    value,
                },
            }
        }

        EXIT_REASON_SIPI => {
            let vector_page =
                ExitQualification(vcpu.get(vmcs::ro::EXIT_QUALIFICATION)).sipi_vector_page();
            SemanticExit::PolicyDriven {
                reason,
                info: ExitInfo::Sipi { vector_page },
            }
        }

        EXIT_REASON_HLT => SemanticExit::PolicyDriven {
            reason,
            info: ExitInfo::Halt,
        },

        // ── Fallback: generic policy-driven ──
        _ => SemanticExit::PolicyDriven {
            reason,
            info: ExitInfo::Other,
        },
    }
}
