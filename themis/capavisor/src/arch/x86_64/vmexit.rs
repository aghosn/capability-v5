//! VMEXIT handler and monitor loop.
//!
//! After R1 refactoring, the naked `vmexit_trampoline` has been replaced by
//! `ActiveVcpu::run()`, which enters/exits the guest as a function call.
//! `monitor_loop` calls `run()` in a loop and dispatches exits through
//! `handle_vmexit`.

use x86::controlregs::{Cr0, Cr4};
use x86::vmx::vmcs::control::EntryControls;
use x86::msr;
use x86::vmx::vmcs;
use x86::vmx::vmcs::control;

use crate::vcpu::{ActiveVcpu, Reg};
use crate::arch::x86_64::vcpu_ext::ActiveVcpuExt;
use crate::arch::x86_64::vmexit_decode::{
    intr_type, ApicAccessType, ControlReg, CrAccessInfo, ExitQualification, IntrInfo,
};
use crate::{serial_debug, serial_println};

use capability_engine::Platform;

// ── DomainComm discovery statics (written once at boot, read by CPUID handler) ─ //
use core::sync::atomic::AtomicU32;
use core::sync::atomic::AtomicU64;

/// Dom0 DomainComm region GPA (set by init_themis, read by CPUID leaf 0x40000002).
pub static DOMCOMM_GPA: AtomicU64 = AtomicU64::new(0);
/// Dom0 DomainComm region size in pages.
pub static DOMCOMM_PAGES: AtomicU32 = AtomicU32::new(0);

// ── x2APIC MSR range (SDM Vol 3 §10.12.1) ──────────────────────────────── //
// In x2APIC mode every APIC register is accessed via MSRs 0x800–0x83F.
// We virtualise these through the VAPIC page rather than letting the guest
// touch the real LAPIC.
#[allow(dead_code)]
const X2APIC_MSR_BASE: u32 = 0x800;
#[allow(dead_code)]
const X2APIC_MSR_END: u32 = 0x840; // exclusive

// Notable x2APIC register offsets (MSR = BASE + offset/16).
#[allow(dead_code)]
const X2APIC_ID: u32 = 0x802;
#[allow(dead_code)]
const X2APIC_VER: u32 = 0x803;
#[allow(dead_code)]
const X2APIC_TPR: u32 = 0x808;
#[allow(dead_code)]
const X2APIC_PPR: u32 = 0x80A;
#[allow(dead_code)]
const X2APIC_EOI: u32 = 0x80B;
#[allow(dead_code)]
const X2APIC_LDR: u32 = 0x80D;
#[allow(dead_code)]
const X2APIC_SVR: u32 = 0x80F;
#[allow(dead_code)]
const X2APIC_ISR0: u32 = 0x810;
#[allow(dead_code)]
const X2APIC_TMR0: u32 = 0x818;
#[allow(dead_code)]
const X2APIC_IRR0: u32 = 0x820;
#[allow(dead_code)]
const X2APIC_ESR: u32 = 0x828;
#[allow(dead_code)]
const X2APIC_ICR: u32 = 0x830;
#[allow(dead_code)]
const X2APIC_LVT_TIMER: u32 = 0x832;
#[allow(dead_code)]
const X2APIC_LVT_THERMAL: u32 = 0x833;
#[allow(dead_code)]
const X2APIC_LVT_PERF: u32 = 0x834;
#[allow(dead_code)]
const X2APIC_LVT_LINT0: u32 = 0x835;
#[allow(dead_code)]
const X2APIC_LVT_LINT1: u32 = 0x836;
#[allow(dead_code)]
const X2APIC_LVT_ERROR: u32 = 0x837;
#[allow(dead_code)]
const X2APIC_TIMER_ICR: u32 = 0x838;
#[allow(dead_code)]
const X2APIC_TIMER_CCR: u32 = 0x839;
#[allow(dead_code)]
const X2APIC_TIMER_DCR: u32 = 0x83E;
#[allow(dead_code)]
const X2APIC_SELF_IPI: u32 = 0x83F;

// ── Exit reason constants (Intel SDM Vol 3C §27.9.1) ─────────────────────── //

// VMX preemption timer: ~2 seconds at 3 GHz with TSC rate divisor = 5.
// Timer ticks = desired_ns / (2^N * TSC_period_ns), where N = 5 (typical).
pub const PREEMPTION_TIMER_TICKS: u64 = 60_000_000;

pub const EXIT_REASON_EXCEPTION_NMI: u32 = 0;
pub const EXIT_REASON_EXTERNAL_INTERRUPT: u32 = 1;
pub const EXIT_REASON_TRIPLE_FAULT: u32 = 2;
pub const EXIT_REASON_INIT_SIGNAL: u32 = 3;
pub const EXIT_REASON_SIPI: u32 = 4;
pub const EXIT_REASON_INTERRUPT_WINDOW: u32 = 7;
pub const EXIT_REASON_CPUID: u32 = 10;
pub const EXIT_REASON_HLT: u32 = 12;
pub const EXIT_REASON_VMCALL: u32 = 18;

// ── APIC register offsets (Intel SDM Vol 3A §10.4.1) ─────────────────────── //

const APIC_REG_EOI: usize = 0x0B0;
const APIC_REG_ICR_LOW: usize = 0x300;
const APIC_REG_ICR_HIGH: usize = 0x310;
const APIC_REG_ISR_BASE: usize = 0x100; // ISR: 8 × 32-bit words at 0x100–0x170

// ── VMEXIT / VMENTRY interruption info field ─────────────────────────────── //
//
// Bit layout and `intr_type::*` constants live in `vmexit_decode::IntrInfo`
// (SDM Vol 3C §24.9.2).  Callers wrap the raw word in `IntrInfo(word)` and
// use its named accessors / builder, never raw masks here.

// ── APIC-access exit qualification (Intel SDM Vol 3C §27.2.1) ────────────── //
//
// (Decoded via `vmexit_decode::ApicAccessInfo`; no raw masks needed here.)

// ── Themis CPUID hypervisor leaves ─────────────────────────────────────── //
//
// The Themis-specific leaf IDs and signature live in `themis_abi::cpuid` so
// dom0 and capavisor cannot drift; we only define the *range* terminators
// here, which are Intel/AMD-wide conventions (0x4000_0000..0x4FFF_FFFF =
// hypervisor) plus a Themis-internal debug-leaf range.
//
// Highest currently-defined Themis leaf, returned in EAX of LEAF_BASE.
// Update if a new `LEAF_*` is added to `themis_abi::cpuid`.
const CPUID_THEMIS_MAX: u32 = themis_abi::cpuid::LEAF_IVSHMEM;
const CPUID_HV_RANGE_END: u32 = 0x4FFFFFFF;
const CPUID_DEBUG_RANGE_START: u32 = 0xDEAD0000;
const CPUID_DEBUG_RANGE_END: u32 = 0xDEADFFFF;

// Themis capacity limits (exposed via CPUID_THEMIS_LIMITS)
const THEMIS_MAX_VPS: u32 = 256;
const THEMIS_MAX_PARTITIONS: u32 = 1024;
const THEMIS_MAX_MEM_REGIONS: u32 = 4096;

// ── SIPI constants (Intel SDM Vol 3A §8.4.4) ─────────────────────────────── //

/// Real-mode CS access rights: P=1, S=1, type=B (code, exec/read, accessed).
const SIPI_CS_ACCESS_RIGHTS: u64 = 0x009B;
/// CR0 initial value for VMX real-mode: PE + NE (required by IA32_VMX_CR0_FIXED0).
const SIPI_CR0_INITIAL: u64 = 0x30;
/// Real-mode segment limit (64 KiB).
const REALMODE_SEG_LIMIT: u64 = 0xFFFF;

// ── EFER bit definitions (Intel SDM Vol 3A §2.2.1) ───────────────────────── //
// Not exposed as bitflags by the `x86` crate; mirror the same shape as
// `x86::controlregs::{Cr0,Cr4}` so callers can write `Ia32Efer::LME.bits()`.
bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Ia32Efer: u64 {
        /// System Call Extensions (SYSCALL/SYSRET enable in 64-bit mode).
        const SCE = 1 << 0;
        /// Long Mode Enable.
        const LME = 1 << 8;
        /// Long Mode Active (set by CPU when paging is enabled with LME).
        const LMA = 1 << 10;
        /// No-Execute Enable.
        const NXE = 1 << 11;
    }
}

// ── MSR value split (Intel SDM Vol 2B §RDMSR/WRMSR) ──────────────────────── //

const MSR_LOW_MASK: u64 = 0xFFFF_FFFF;

pub const EXIT_REASON_CR_ACCESS: u32 = 28;
pub const EXIT_REASON_IO_INSTRUCTION: u32 = 30;
pub const EXIT_REASON_RDMSR: u32 = 31;
pub const EXIT_REASON_WRMSR: u32 = 32;
pub const EXIT_REASON_VMENTRY_INVALID_GUEST: u32 = 33;
pub const EXIT_REASON_EPT_VIOLATION: u32 = 48;
pub const EXIT_REASON_EPT_MISCONFIG: u32 = 49;
pub const EXIT_REASON_VMX_PREEMPTION_TIMER: u32 = 52;
pub const EXIT_REASON_XSETBV: u32 = 55;
/// APIC-access VM exit (SDM Vol 3C §29.4): guest accessed the APIC-access
/// page while VIRTUALIZE_APIC_ACCESSES (secondary bit 0) was set.
pub const EXIT_REASON_APIC_ACCESS: u32 = 44;
/// EOI-induced VM exit (SDM Vol 3C §29.1.4): VID=1, guest wrote EOI, and the
/// delivered vector's bit was set in the EOI-exit bitmap.  Used to notify the
/// capability engine when a REPORT-visibility vector completes.
pub const EXIT_REASON_EOI_INDUCED: u32 = 45;
/// APIC-write VM exit (SDM Vol 3C §29.4.3.3): APIC_REGISTER_VIRT wrote to
/// VAPIC page, processor now exits so VMM can process side-effects.
/// RIP is already past the faulting instruction.
pub const EXIT_REASON_APIC_WRITE: u32 = 56;

// ── Exit classification ───────────────────────────────────────────────────── //

use crate::arch_traits::types::{ExitInfo, SemanticExit};

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
            dump_vmentry_failure(vcpu, p, cid);
            SemanticExit::Shutdown { reason }
        }
        EXIT_REASON_TRIPLE_FAULT => {
            dump_triple_fault(vcpu);
            SemanticExit::Shutdown { reason }
        }
        EXIT_REASON_EPT_MISCONFIG => {
            dump_ept_misconfig(vcpu);
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
                    decode_apic_write_value(vcpu, platform).unwrap_or(vcpu.reg(Reg::Rax) as u32);
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
                handle_apic_access_exit(vcpu, platform);
                SemanticExit::ArchHandled
            }
        }
        EXIT_REASON_APIC_WRITE => {
            let info = ExitQualification(vcpu.get(vmcs::ro::EXIT_QUALIFICATION)).apic();
            if info.offset == Some(APIC_REG_ICR_LOW) {
                let hhdm = platform.hhdm_offset();
                let vapic_virt = (vcpu.vapic_phys() + hhdm) as *const u32;
                let icr_low = unsafe { vapic_virt.add(APIC_REG_ICR_LOW / 4).read_volatile() };
                vcpu.set_reg(Reg::Rax, icr_low as u64);
                SemanticExit::PolicyDriven {
                    reason: EXIT_REASON_APIC_ACCESS, // normalize to APIC_ACCESS for parent
                    info: ExitInfo::ApicIcr {
                        icr_low,
                        icr_high: 0,
                    },
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

/// Handle a local (non-trapped) exit for x86.
///
/// Called by the generic monitor loop when `ExitPolicy` says `trap=false`.
/// Dispatches to the appropriate x86-specific local handler based on the
/// exit reason and decoded info.
pub(crate) fn handle_local_exit(
    vcpu: &mut ActiveVcpu,
    reason: u32,
    info: &ExitInfo,
    platform: &crate::platform::ThemisPlatform,
) {
    match reason {
        EXIT_REASON_CPUID => handle_cpuid_local(vcpu, platform),
        EXIT_REASON_RDMSR => handle_rdmsr_local(vcpu),
        EXIT_REASON_WRMSR => handle_wrmsr_local(vcpu),
        EXIT_REASON_CR_ACCESS => handle_cr_access(vcpu),
        EXIT_REASON_EXCEPTION_NMI => reinject_exception(vcpu),
        EXIT_REASON_EPT_VIOLATION => {
            // No special local handling; advance RIP and return.
            vcpu.next_rip();
        }
        EXIT_REASON_SIPI => {
            // AP bootstrap — only fires for dom0 (children use virtual LAPIC).
            if let ExitInfo::Sipi { vector_page } = info {
                let cs_base = (*vector_page as u64) << 12;
                let cs_selector = (*vector_page as u64) << 8;
                vcpu.set(vmcs::guest::CS_SELECTOR, cs_selector);
                vcpu.set(vmcs::guest::CS_BASE, cs_base);
                vcpu.set(vmcs::guest::CS_LIMIT, REALMODE_SEG_LIMIT);
                vcpu.set(vmcs::guest::CS_ACCESS_RIGHTS, SIPI_CS_ACCESS_RIGHTS);
                vcpu.set_rip(0);
                vcpu.set(vmcs::guest::CR0, unsafe {
                    crate::arch::vmcs::vmcs_adjust_cr0(SIPI_CR0_INITIAL)
                });
                vcpu.set(vmcs::guest::ACTIVITY_STATE, 0);
                vcpu.set(
                    vmcs::guest::VMX_PREEMPTION_TIMER_VALUE,
                    PREEMPTION_TIMER_TICKS,
                );
                crate::serial_println!(
                    "[VMEXIT] SIPI vector={:#x} startup={:#x} — AP activated",
                    vector_page,
                    cs_base,
                );
            }
        }
        EXIT_REASON_HLT | EXIT_REASON_IO_INSTRUCTION => vcpu.next_rip(),
        _ => vcpu.next_rip(),
    }
    sync_ia32e_mode_guest(vcpu);
}

// ── HOST_RIP stub ─────────────────────────────────────────────────────────── //

/// Handle XSETBV (exit reason 55): guest wants to set XCR0.
///
/// Masks the guest-requested value with the host's supported XCR0 bits and
/// always sets bit 0 (x87 FPU).  Used for both dom0 and child domain exits.
fn handle_xsetbv(vcpu: &mut ActiveVcpu) {
    let xcr = vcpu.reg(Reg::Rcx) as u32;
    let val = (vcpu.reg(Reg::Rdx) << 32) | (vcpu.reg(Reg::Rax) & MSR_LOW_MASK);
    if xcr == 0 {
        let lo: u32;
        let hi: u32;
        unsafe {
            core::arch::asm!(
                "xgetbv",
                in("ecx") 0u32,
                out("eax") lo,
                out("edx") hi,
                options(nomem, nostack),
            );
        }
        let host_xcr0 = ((hi as u64) << 32) | (lo as u64);
        let safe_val = (val & host_xcr0) | 1;
        unsafe {
            core::arch::asm!(
                "xsetbv",
                in("ecx") 0u32,
                in("eax") safe_val as u32,
                in("edx") (safe_val >> 32) as u32,
                options(nomem, nostack),
            );
        }
    }
    vcpu.next_rip();
}

/// Stub HOST_RIP target — halts if reached without going through `vcpu.run()`.
///
/// `setup_vmcs_for_vp` writes this as HOST_RIP; `ActiveVcpu::run()` overwrites
/// it with its own return label before every VM entry.  If this stub is ever
/// reached, something is seriously wrong.
#[unsafe(naked)]
pub unsafe extern "C" fn host_rip_stub() -> ! {
    core::arch::naked_asm!("cli", "55: hlt", "jmp 55b");
}

// ── Local handlers (called from handle_local_exit and classify_and_handle_internal) ──

/// CR access exit (reason 28).
///
/// Emulates MOV to/from CR0/CR3/CR4/CR8.
fn handle_cr_access(vcpu: &mut ActiveVcpu) {
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

// ── Fatal exit dump helpers ───────────────────────────────────────────────── //

fn dump_vmentry_failure(
    vcpu: &ActiveVcpu,
    platform: Option<&crate::platform::ThemisPlatform>,
    core_id: usize,
) {
    while crate::SERIAL_LOCK.swap(true, core::sync::atomic::Ordering::Acquire) {
        core::hint::spin_loop();
    }
    let domain_id = platform
        .map(|p| p.core_domain_id(core_id))
        .unwrap_or(u64::MAX);
    let qual = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
    let cr0 = vcpu.get(vmcs::guest::CR0);
    let cr4 = vcpu.get(vmcs::guest::CR4);
    let cr3 = vcpu.get(vmcs::guest::CR3);
    let rip = vcpu.rip();
    let rsp = vcpu.rsp();
    let rflags = vcpu.rflags();
    let efer = vcpu.get(vmcs::guest::IA32_EFER_FULL);
    let cs_sel = vcpu.get(vmcs::guest::CS_SELECTOR);
    let cs_base = vcpu.get(vmcs::guest::CS_BASE);
    let cs_lim = vcpu.get(vmcs::guest::CS_LIMIT);
    let cs_ar = vcpu.get(vmcs::guest::CS_ACCESS_RIGHTS);
    let ss_sel = vcpu.get(vmcs::guest::SS_SELECTOR);
    let ss_ar = vcpu.get(vmcs::guest::SS_ACCESS_RIGHTS);
    let tr_ar = vcpu.get(vmcs::guest::TR_ACCESS_RIGHTS);
    let ldtr_ar = vcpu.get(vmcs::guest::LDTR_ACCESS_RIGHTS);
    let activity = vcpu.get(vmcs::guest::ACTIVITY_STATE);
    let interrupt = vcpu.get(vmcs::guest::INTERRUPTIBILITY_STATE);
    let link_ptr = vcpu.get(vmcs::guest::LINK_PTR_FULL);
    let vpid = vcpu.get(control::VPID);
    let entry_ctrl = vcpu.get(control::VMENTRY_CONTROLS);
    let pin_ctrl = vcpu.get(control::PINBASED_EXEC_CONTROLS);
    let proc2_ctrl = vcpu.get(control::SECONDARY_PROCBASED_EXEC_CONTROLS);
    let intr_info = vcpu.get(control::VMENTRY_INTERRUPTION_INFO_FIELD);
    let cr0_mask = vcpu.get(control::CR0_GUEST_HOST_MASK);
    let cr0_shadow = vcpu.get(control::CR0_READ_SHADOW);
    let cr4_mask = vcpu.get(control::CR4_GUEST_HOST_MASK);
    let cr4_shadow = vcpu.get(control::CR4_READ_SHADOW);
    serial_println!(
        "[FATAL] exit 33 dom={} core={} EXIT_QUAL={:#x} (check={})\n\
         CR0={:#x} CR4={:#x} CR3={:#x} EFER={:#x}\n\
         RIP={:#x} RSP={:#x} RFLAGS={:#x}\n\
         CS sel={:#x} base={:#x} lim={:#x} ar={:#x}\n\
         SS sel={:#x} ar={:#x} TR_AR={:#x} LDTR_AR={:#x}\n\
         activity={} interrupt={:#x} link_ptr={:#x} vpid={}\n\
         ENTRY_CTRL={:#x} PIN={:#x} PROC2={:#x}\n\
         INTR_INFO={:#x}\n\
         CR0_MASK={:#x} CR0_SHADOW={:#x} CR4_MASK={:#x} CR4_SHADOW={:#x}",
        domain_id,
        core_id,
        qual,
        qual & 0xf,
        cr0,
        cr4,
        cr3,
        efer,
        rip,
        rsp,
        rflags,
        cs_sel,
        cs_base,
        cs_lim,
        cs_ar,
        ss_sel,
        ss_ar,
        tr_ar,
        ldtr_ar,
        activity,
        interrupt,
        link_ptr,
        vpid,
        entry_ctrl,
        pin_ctrl,
        proc2_ctrl,
        intr_info,
        cr0_mask,
        cr0_shadow,
        cr4_mask,
        cr4_shadow,
    );
    serial_println!(
        "  RAX={:#018x}  RBX={:#018x}  RCX={:#018x}",
        vcpu.reg(Reg::Rax),
        vcpu.reg(Reg::Rbx),
        vcpu.reg(Reg::Rcx)
    );
    crate::SERIAL_LOCK.store(false, core::sync::atomic::Ordering::Release);
}

fn dump_triple_fault(vcpu: &ActiveVcpu) {
    while crate::SERIAL_LOCK.swap(true, core::sync::atomic::Ordering::Acquire) {
        core::hint::spin_loop();
    }
    let rip = vcpu.rip();
    let rsp = vcpu.rsp();
    let cr0 = vcpu.get(vmcs::guest::CR0);
    let cr3 = vcpu.get(vmcs::guest::CR3);
    let cr4 = vcpu.get(vmcs::guest::CR4);
    let efer = vcpu.get(vmcs::guest::IA32_EFER_FULL);
    let rflags = vcpu.rflags();
    let cs_sel = vcpu.get(vmcs::guest::CS_SELECTOR);
    let cs_base = vcpu.get(vmcs::guest::CS_BASE);
    let cs_ar = vcpu.get(vmcs::guest::CS_ACCESS_RIGHTS);
    let ss_sel = vcpu.get(vmcs::guest::SS_SELECTOR);
    let ss_ar = vcpu.get(vmcs::guest::SS_ACCESS_RIGHTS);
    let entry_ctl = vcpu.get(control::VMENTRY_CONTROLS);
    let act = vcpu.get(vmcs::guest::ACTIVITY_STATE);
    let interruptibility = vcpu.get(vmcs::guest::INTERRUPTIBILITY_STATE);
    let idtr_base = vcpu.get(vmcs::guest::IDTR_BASE);
    let idtr_limit = vcpu.get(vmcs::guest::IDTR_LIMIT);
    serial_println!("===== TRIPLE FAULT (vpid={}) =====", vcpu.vpid());
    serial_println!(
        "  RIP={:#018x}  RSP={:#018x}  RFLAGS={:#010x}",
        rip,
        rsp,
        rflags
    );
    serial_println!(
        "  CR0={:#010x}  CR3={:#010x}  CR4={:#010x}  EFER={:#010x}",
        cr0,
        cr3,
        cr4,
        efer
    );
    serial_println!(
        "  CS: sel={:#06x} base={:#010x} ar={:#06x}  SS: sel={:#06x} ar={:#06x}",
        cs_sel,
        cs_base,
        cs_ar,
        ss_sel,
        ss_ar
    );
    serial_println!("  IDTR: base={:#018x} limit={:#06x}", idtr_base, idtr_limit);
    serial_println!(
        "  entry_ctl={:#010x}  activity={} interruptibility={:#x}",
        entry_ctl,
        act,
        interruptibility
    );
    serial_println!(
        "  RAX={:#018x}  RBX={:#018x}  RCX={:#018x}",
        vcpu.reg(Reg::Rax),
        vcpu.reg(Reg::Rbx),
        vcpu.reg(Reg::Rcx)
    );
    serial_println!(
        "  RDX={:#018x}  RSI={:#018x}  RDI={:#018x}",
        vcpu.reg(Reg::Rdx),
        vcpu.reg(Reg::Rsi),
        vcpu.reg(Reg::Rdi)
    );
    serial_println!(
        "  R8 ={:#018x}  R9 ={:#018x}  R10={:#018x}",
        vcpu.reg(Reg::R8),
        vcpu.reg(Reg::R9),
        vcpu.reg(Reg::R10)
    );
    serial_println!(
        "  RBP={:#018x}  R12={:#018x}  R13={:#018x}",
        vcpu.reg(Reg::Rbp),
        vcpu.reg(Reg::R12),
        vcpu.reg(Reg::R13)
    );
    serial_println!("=================================");
    crate::SERIAL_LOCK.store(false, core::sync::atomic::Ordering::Release);
}

fn dump_ept_misconfig(vcpu: &ActiveVcpu) {
    while crate::SERIAL_LOCK.swap(true, core::sync::atomic::Ordering::Acquire) {
        core::hint::spin_loop();
    }
    let gpa = vcpu.get(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL);
    let rip = vcpu.rip();
    serial_println!(
        "[VMEXIT] EPT misconfig vpid={} GPA={:#x} RIP={:#x}",
        vcpu.vpid(),
        gpa,
        rip
    );
    crate::SERIAL_LOCK.store(false, core::sync::atomic::Ordering::Release);
}

// ── Shared local handlers ─────────────────────────────────────────────────── //
// These are used by BOTH the dom0 path and the policy-driven child path
// (when ExitPolicy has trap=false for the exit reason).

/// Re-inject a guest exception/NMI back into the vCPU (exit reason 0).
///
/// Reads the VM-exit interruption info, reconstructs the VM-entry injection
/// field, and copies the error code if present.  Used by both the dom0 path
/// and child domains with `trap=false` for EXCEPTION_NMI.
fn reinject_exception(vcpu: &mut ActiveVcpu) {
    let info = IntrInfo(vcpu.get(vmcs::ro::VMEXIT_INTERRUPTION_INFO));
    let vector = info.vector();
    let has_error_code = info.delivers_error_code();

    if vector == x86::irq::INVALID_OPCODE_VECTOR || vector == x86::irq::DOUBLE_FAULT_VECTOR {
        let rip = vcpu.rip();
        let name = match vector {
            x86::irq::INVALID_OPCODE_VECTOR => "#UD",
            x86::irq::DOUBLE_FAULT_VECTOR => "#DF",
            _ => "??",
        };
        serial_println!("[VMEXIT] exception {} at RIP={:#018x}", name, rip);
    }

    let inject = IntrInfo::encode(vector, info.intr_type(), has_error_code);
    vcpu.set(control::VMENTRY_INTERRUPTION_INFO_FIELD, inject);
    if has_error_code {
        let err = vcpu.get(vmcs::ro::VMEXIT_INTERRUPTION_ERR_CODE);
        vcpu.set(control::VMENTRY_EXCEPTION_ERR_CODE, err);
    }
    vcpu.set(control::VMENTRY_INSTRUCTION_LEN, 0);
}

/// Handle CPUID locally: native cpuid + masking (exit reason 10).
///
/// Executes `cpuid` on the physical CPU, applies security masks (AVX-512,
/// XSAVE area), and intercepts Themis hypervisor leaves.
/// Used by both the dom0 path and child domains with `trap=false` for CPUID.
fn handle_cpuid_local(vcpu: &mut ActiveVcpu, platform: &crate::platform::ThemisPlatform) {
    let leaf = vcpu.reg(Reg::Rax) as u32;
    let sub_leaf = vcpu.reg(Reg::Rcx) as u32;
    let result = core::arch::x86_64::__cpuid_count(leaf, sub_leaf);
    let mut eax = result.eax;
    let mut ebx = result.ebx;
    let mut ecx = result.ecx;
    let mut edx = result.edx;

    match (leaf, sub_leaf) {
        (0x1, _) => {
            ecx &= !(1u32 << 31); // hide hypervisor-present bit
        }
        (0x7, 0) => {
            // AVX-512 feature bits in CPUID.07H:0H (Intel SDM Vol 2A §3.2).
            // Hiding all of them coerces guests onto AVX2 ISA, avoiding
            // XSAVE-area sizing issues and FPU state corruption risks for
            // domains we don't expose AVX-512 to.
            bitflags::bitflags! {
                struct Avx512Ebx: u32 {
                    const AVX512F          = 1 << 16;
                    const AVX512DQ         = 1 << 17;
                    const AVX512_IFMA      = 1 << 21;
                    const AVX512PF         = 1 << 26;
                    const AVX512ER         = 1 << 27;
                    const AVX512CD         = 1 << 28;
                    const AVX512BW         = 1 << 30;
                    const AVX512VL         = 1 << 31;
                }
                struct Avx512Ecx: u32 {
                    const AVX512_VBMI       = 1 << 1;
                    const AVX512_VBMI2      = 1 << 6;
                    const AVX512_VNNI       = 1 << 11;
                    const AVX512_BITALG     = 1 << 12;
                    const AVX512_VPOPCNTDQ  = 1 << 14;
                    // Bits 4 and 5 in this mask are reserved/AVX-512-adjacent
                    // (kept for parity with the pre-bitflags mask).
                    const RESERVED_BIT_4    = 1 << 4;
                    const RESERVED_BIT_5    = 1 << 5;
                }
                struct Avx512Edx: u32 {
                    const AVX512_4VNNIW       = 1 << 2;
                    const AVX512_4FMAPS       = 1 << 3;
                    const AVX512_VP2INTERSECT = 1 << 8;
                    const AVX512_FP16         = 1 << 23;
                }
            }
            ebx &= !Avx512Ebx::all().bits();
            ecx &= !Avx512Ecx::all().bits();
            edx &= !Avx512Edx::all().bits();
        }
        (0xD, 0) => {
            eax = 0x7; // x87 + SSE + AVX
            ebx = 0x340;
            ecx = 0x340;
            edx = 0;
        }
        (0xD, 1) => {
            ebx = 0x340;
            ecx = 0;
            edx = 0;
        }
        (0xD, sub) if matches!(sub, 5..=7 | 9) => {
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
        (themis_abi::cpuid::LEAF_BASE, _) => {
            eax = CPUID_THEMIS_MAX;
            ebx = themis_abi::cpuid::SIG_EBX;
            ecx = themis_abi::cpuid::SIG_ECX;
            edx = themis_abi::cpuid::SIG_EDX;
        }
        (themis_abi::cpuid::LEAF_FEATURES, _) => {
            eax = 0b00001;
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
        (themis_abi::cpuid::LEAF_DOMCOMM, _) => {
            // Per-domain DomainComm discovery: look up the calling domain's
            // DomainComm header HPA.  Falls back to the global dom0 value
            // for domains that don't have their own DomainComm yet.
            let mut found = false;
            if let Some(core_id) = platform.get_current_core() {
                let dom_id = platform.core_domain_id(core_id as usize);
                if let Some(arc) = platform.domain_arc(dom_id) {
                    let pd = arc.lock();
                    if let Some(ref dc) = pd.domcomm {
                        eax = dc.header_hpa as u32;
                        ebx = (dc.header_hpa >> 32) as u32;
                        ecx = 1 + dc.rx.page_hpas.len() as u32 + dc.tx.page_hpas.len() as u32;
                        edx = 0;
                        found = true;
                    }
                }
            }
            if !found {
                // Fallback: global dom0 values (bootstrap path).
                let gpa = DOMCOMM_GPA.load(core::sync::atomic::Ordering::Relaxed);
                let pages = DOMCOMM_PAGES.load(core::sync::atomic::Ordering::Relaxed);
                eax = gpa as u32;
                ebx = (gpa >> 32) as u32;
                ecx = pages;
                edx = 0;
            }
        }
        (themis_abi::cpuid::LEAF_LIMITS, _) => {
            eax = THEMIS_MAX_VPS;
            ebx = THEMIS_MAX_PARTITIONS;
            ecx = THEMIS_MAX_MEM_REGIONS;
            edx = 0;
        }
        // Leaf 0x40000004: ivshmem device info (subleaf = device index).
        // Values are pushed by CHV as Emulate overrides via SET_POLICY.
        // Native handler returns zeros (no ivshmem when handled locally).
        (themis_abi::cpuid::LEAF_IVSHMEM, _) => {
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
        (themis_abi::cpuid::LEAF_BASE..=CPUID_HV_RANGE_END, _) => {
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
        (CPUID_DEBUG_RANGE_START..=CPUID_DEBUG_RANGE_END, _) => {
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
        // Leaf 0x15: TSC / Core Crystal Clock
        (0x15, _) => {
            eax = 1; // denominator
            ebx = 120; // numerator
            ecx = 25_000_000; // crystal Hz
            edx = 0;
        }
        _ => {}
    }

    vcpu.set_reg(Reg::Rax, eax as u64);
    vcpu.set_reg(Reg::Rbx, ebx as u64);
    vcpu.set_reg(Reg::Rcx, ecx as u64);
    vcpu.set_reg(Reg::Rdx, edx as u64);
    vcpu.next_rip();
}

/// Handle RDMSR locally (exit reason 31).
///
/// Reads MSR via msr_virt virtualisation layer, passes through safe MSRs,
/// injects #GP for blocked ones.
fn handle_rdmsr_local(vcpu: &mut ActiveVcpu) {
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
fn handle_wrmsr_local(vcpu: &mut ActiveVcpu) {
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

// ── Helpers ───────────────────────────────────────────────────────────────── //

/// Handle an APIC-access VM exit (exit reason 44).
///
/// Triggered when the guest accesses the APIC-access page (GPA 0xFEE00000)
/// while VIRTUALIZE_APIC_ACCESSES is set.  With APIC_REGISTER_VIRT=1 and
/// VID=1, most register reads and EOI/TPR writes are handled by hardware
/// without an exit.  This handler sees the remaining accesses (e.g. ICR
/// writes for IPI delivery, non-standard register accesses).
///
/// Current policy: emulate read accesses from the VAPIC page; log and
/// advance RIP for write accesses.  ICR-based IPI emulation can be added
/// here when multi-VP child domains are needed.
///
/// Exit qualification bit layout (SDM Vol 3C §27.2.1 Table 27-6):
///   bits[11:0] — access offset within the 4 KB APIC-access page
///   bits[15:12] — access type: 0=data-read, 1=data-write, 2=instr-fetch,
///                              3=read-during-event-delivery, 10=GPA-read
fn handle_apic_access_exit(vcpu: &mut ActiveVcpu, platform: &crate::platform::ThemisPlatform) {
    let info = ExitQualification(vcpu.get(vmcs::ro::EXIT_QUALIFICATION)).apic();
    let offset = match info.offset {
        Some(off) => off,
        None => {
            // GPA-mode access — nothing meaningful to do, advance RIP.
            vcpu.next_rip();
            return;
        }
    };

    let hhdm = platform.hhdm_offset();

    let vapic_phys = vcpu.vapic_phys();
    let vapic_virt = (vapic_phys + hhdm) as *mut u32;

    match info.access {
        ApicAccessType::DataRead | ApicAccessType::EventDeliveryLinear => {
            // Data read or read during event delivery: return VAPIC page value.
            let word_idx = offset / 4;
            let val = unsafe { vapic_virt.add(word_idx).read_volatile() };
            vcpu.set_reg(Reg::Rax, val as u64);
        }
        ApicAccessType::DataWrite => {
            // Data write: decode instruction to find source register value,
            // then mirror into VAPIC page.
            let val = decode_apic_write_value(vcpu, platform).unwrap_or(vcpu.reg(Reg::Rax) as u32);

            if offset == APIC_REG_EOI {
                // EOI: clear the highest-priority bit in the ISR (In-Service
                // Register, offsets 0x100-0x170 = 8 × 32-bit words = 256 bits).
                // Scan from highest word (0x170) down to lowest (0x100).
                for w in (0..8).rev() {
                    let isr_idx = (APIC_REG_ISR_BASE / 4) + w; // word index in VAPIC page
                    let isr_val = unsafe { vapic_virt.add(isr_idx).read_volatile() };
                    if isr_val != 0 {
                        let bit = 31 - isr_val.leading_zeros();
                        unsafe {
                            vapic_virt
                                .add(isr_idx)
                                .write_volatile(isr_val & !(1 << bit));
                        }
                        break;
                    }
                }
            } else {
                let word_idx = offset / 4;
                unsafe { vapic_virt.add(word_idx).write_volatile(val) };
            }
        }
        _ => {
            serial_println!(
                "[APIC_ACCESS] unhandled access type {:?} offset={:#x} — advancing RIP",
                info.access,
                offset
            );
        }
    }
    vcpu.next_rip();
}

/// Decode the faulting MOV instruction at guest RIP to extract the 32-bit
/// value being written for an APIC-access write exit.
///
/// Handles the common `mov [mem], reg32` (opcode 0x89) and
/// `mov [mem], imm32` (opcode 0xC7 /0) patterns emitted by `writel()`.
/// Returns `None` if the instruction can't be decoded.
fn decode_apic_write_value(
    vcpu: &mut ActiveVcpu,
    platform: &crate::platform::ThemisPlatform,
) -> Option<u32> {
    use crate::arch::x86_64::page_walk::{ept_gpa_to_hpa, guest_gva_to_gpa};

    let hhdm = platform.hhdm_offset();
    let guest_rip = vcpu.rip();
    let guest_cr3 = vcpu.get(vmcs::guest::CR3);
    let ept_root = vcpu.get(x86::vmx::vmcs::control::EPTP_FULL);

    let insn_gpa = guest_gva_to_gpa(ept_root, hhdm, guest_cr3, guest_rip)?;
    let insn_hpa = ept_gpa_to_hpa(ept_root, hhdm, insn_gpa)?;
    let insn_ptr = (insn_hpa + hhdm) as *const u8;
    let avail = core::cmp::min(16, 0x1000 - (insn_hpa & 0xFFF) as usize);
    let mut buf = [0u8; 16];
    unsafe { core::ptr::copy_nonoverlapping(insn_ptr, buf.as_mut_ptr(), avail) };

    // Skip prefixes: REX (0x40-0x4F), operand-size (0x66), address-size (0x67)
    let mut i = 0;
    let mut rex: u8 = 0;
    while i < avail {
        match buf[i] {
            0x40..=0x4F => {
                rex = buf[i];
                i += 1;
            }
            0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x3E | 0x26 | 0x64 | 0x65 | 0x36 => {
                i += 1;
            }
            _ => break,
        }
    }
    if i >= avail {
        return None;
    }

    let opcode = buf[i];
    i += 1;
    if i >= avail {
        return None;
    }

    match opcode {
        0x89 => {
            // MOV r/m32, r32: source register in ModRM reg field (bits 5:3)
            let modrm = buf[i];
            let reg_idx = ((modrm >> 3) & 0x7) | (if rex & 0x4 != 0 { 0x8 } else { 0 });
            let val = match reg_idx {
                0 => vcpu.reg(Reg::Rax),
                1 => vcpu.reg(Reg::Rcx),
                2 => vcpu.reg(Reg::Rdx),
                3 => vcpu.reg(Reg::Rbx),
                4 => return None, // RSP — not a valid APIC write source
                5 => vcpu.reg(Reg::Rbp),
                6 => vcpu.reg(Reg::Rsi),
                7 => vcpu.reg(Reg::Rdi),
                8 => vcpu.reg(Reg::R8),
                9 => vcpu.reg(Reg::R9),
                10 => vcpu.reg(Reg::R10),
                11 => vcpu.reg(Reg::R11),
                12 => vcpu.reg(Reg::R12),
                13 => vcpu.reg(Reg::R13),
                14 => vcpu.reg(Reg::R14),
                15 => vcpu.reg(Reg::R15),
                _ => return None,
            };
            Some(val as u32)
        }
        0xC7 => {
            // MOV r/m32, imm32: immediate follows ModRM (+SIB+disp)
            let modrm = buf[i];
            i += 1;
            let md = modrm >> 6;
            let rm = modrm & 0x7;
            // Skip SIB byte if present
            if md != 3 && rm == 4 {
                i += 1;
            }
            // Skip displacement
            match md {
                0 => {
                    if rm == 5 {
                        i += 4;
                    }
                }
                1 => {
                    i += 1;
                }
                2 => {
                    i += 4;
                }
                _ => {}
            }
            if i + 4 > avail {
                return None;
            }
            let imm = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
            Some(imm)
        }
        _ => None,
    }
}

/// Inject a virtual interrupt directly via the VAPIC page (VID path).
///
/// Sets VIRR[`vector`] in the VAPIC page (offset 0x200, same layout as xAPIC
/// IRR) and updates RVI in the guest interrupt-status VMCS field so the
/// processor delivers the interrupt on the next VMENTRY without an IPI.
///
/// # Safety
/// `vapic_virt` must be the host-virtual address of the 4 KB VAPIC page whose
/// physical address was written to VMCS `VIRTUAL_APIC_PAGE_ADDR`.  The VMCS
/// for `vcpu` must be current (VMPTRLD'd) when this function is called.
/// Caller must hold the VP lock.
/// Inject #GP(0) into the guest.
fn inject_gp(vcpu: &mut ActiveVcpu) {
    let info = IntrInfo::encode(
        x86::irq::GENERAL_PROTECTION_FAULT_VECTOR,
        intr_type::HARDWARE_EXCEPTION,
        true, // #GP delivers an error code
    );
    vcpu.set(control::VMENTRY_INTERRUPTION_INFO_FIELD, info);
    vcpu.set(control::VMENTRY_EXCEPTION_ERR_CODE, 0);
    vcpu.set(control::VMENTRY_INSTRUCTION_LEN, 0);
}

/// Keep the IA32E_MODE_GUEST entry control in sync with guest EFER.LMA.
fn sync_ia32e_mode_guest(vcpu: &mut ActiveVcpu) {
    let efer = vcpu.get(vmcs::guest::IA32_EFER_FULL);
    let lma = efer & Ia32Efer::LMA.bits() != 0;

    let entry = vcpu.get(control::VMENTRY_CONTROLS);
    let ia32e_bit = EntryControls::IA32E_MODE_GUEST.bits() as u64;
    let current = entry & ia32e_bit != 0;

    if lma != current {
        let new_entry = if lma {
            entry | ia32e_bit
        } else {
            entry & !ia32e_bit
        };
        vcpu.set(control::VMENTRY_CONTROLS, new_entry);
    }
}

