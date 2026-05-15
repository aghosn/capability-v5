//! VMEXIT handler and monitor loop.
//!
//! After R1 refactoring, the naked `vmexit_trampoline` has been replaced by
//! `ActiveVcpu::run()`, which enters/exits the guest as a function call.
//! `monitor_loop` calls `run()` in a loop and dispatches exits through
//! `handle_vmexit`.

use x86::msr;
use x86::vmx::vmcs;
use x86::vmx::vmcs::control;

use crate::vcpu::{ActiveVcpu, Reg};
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

// ── VMEXIT interruption info field (Intel SDM Vol 3C §24.9.2) ────────────── //

const INTR_INFO_VECTOR_MASK: u64 = 0xFF;
const INTR_INFO_TYPE_SHIFT: u32 = 8;
const INTR_INFO_TYPE_MASK: u64 = 0x7;
const INTR_INFO_VALID: u64 = 1 << 31;
const INTR_TYPE_NMI: u64 = 2;

// ── APIC-access exit qualification (Intel SDM Vol 3C §27.2.1) ────────────── //

const APIC_ACCESS_OFFSET_MASK: u64 = 0xFFF;
const APIC_ACCESS_TYPE_SHIFT: u32 = 12;
const APIC_ACCESS_TYPE_MASK: u64 = 0xF;
const APIC_ACCESS_TYPE_WRITE: u64 = 1;

// ── Themis CPUID hypervisor leaves (§ custom ABI) ─────────────────────────── //

const CPUID_THEMIS_BASE: u32 = 0x40000000;
const CPUID_THEMIS_MAX: u32 = 0x40000003;
const CPUID_THEMIS_FEATURES: u32 = 0x40000001;
const CPUID_THEMIS_DOMCOMM: u32 = 0x40000002;
const CPUID_THEMIS_LIMITS: u32 = 0x40000003;
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
            crate::hypercall::drain_pir_on_interrupt_window(vcpu, platform);
            SemanticExit::ArchHandled
        }
        EXIT_REASON_EOI_INDUCED => {
            // A3: EOI-exit bitmap is all-zero → should never fire.
            SemanticExit::ArchHandled
        }

        // ── Always-generic exits ──
        EXIT_REASON_VMCALL => SemanticExit::Hypercall,

        EXIT_REASON_EXTERNAL_INTERRUPT => {
            let info = vcpu.get(vmcs::ro::VMEXIT_INTERRUPTION_INFO);
            let vector = (info & INTR_INFO_VECTOR_MASK) as u32;
            SemanticExit::ExternalInterrupt { vector }
        }

        EXIT_REASON_VMX_PREEMPTION_TIMER => SemanticExit::TimerExpired,

        // ── EXCEPTION_NMI: split NMI (→ interrupt routing) vs exception (→ policy) ──
        EXIT_REASON_EXCEPTION_NMI => {
            let intr_info = vcpu.get(vmcs::ro::VMEXIT_INTERRUPTION_INFO);
            let exc_type = ((intr_info >> INTR_INFO_TYPE_SHIFT) & INTR_INFO_TYPE_MASK) as u8;
            if exc_type as u64 == INTR_TYPE_NMI {
                // NMI → route like an interrupt (vector 2).
                SemanticExit::ExternalInterrupt { vector: 2 }
            } else {
                let vector = (intr_info & INTR_INFO_VECTOR_MASK) as u8;
                let has_error = (intr_info >> 11) & 1;
                let error_code = if has_error == 1 {
                    Some(vcpu.get(vmcs::ro::VMEXIT_INTERRUPTION_ERR_CODE) as u32)
                } else {
                    None
                };
                SemanticExit::PolicyDriven {
                    reason,
                    info: ExitInfo::Exception {
                        vector,
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
            let qual = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
            let offset = qual & APIC_ACCESS_OFFSET_MASK;
            let acc_type = (qual >> APIC_ACCESS_TYPE_SHIFT) & APIC_ACCESS_TYPE_MASK;
            if offset == APIC_REG_ICR_LOW as u64 && acc_type == APIC_ACCESS_TYPE_WRITE {
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
            let qual = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
            let offset = qual & APIC_ACCESS_OFFSET_MASK;
            if offset == APIC_REG_ICR_LOW as u64 {
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
            let qual = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
            let port = ((qual >> 16) & 0xFFFF) as u16;
            let size = ((qual & 0x7) + 1) as u8;
            let is_write = (qual & 0x8) == 0;
            let value = vcpu.reg(Reg::Rax) as u32;
            SemanticExit::PolicyDriven {
                reason,
                info: ExitInfo::IoInstruction {
                    port,
                    size,
                    is_write,
                    value,
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
            let qual = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
            let vector_page = (qual & 0xFF) as u8;
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
        EXIT_REASON_CPUID => handle_cpuid_local(vcpu),
        EXIT_REASON_RDMSR => handle_rdmsr_local(vcpu),
        EXIT_REASON_WRMSR => handle_wrmsr_local(vcpu),
        EXIT_REASON_CR_ACCESS => handle_cr_access(vcpu),
        EXIT_REASON_EXCEPTION_NMI => reinject_exception(vcpu),
        EXIT_REASON_EPT_VIOLATION => {
            // Doorbell fast-path: check first.
            if let ExitInfo::EptViolation { gpa, qualification } = info {
                if let Some(true) = handle_ept_doorbell(platform, vcpu, *gpa, *qualification) {
                    return;
                }
            }
            // No doorbell match: for local handling, just advance RIP.
            next_instruction(vcpu);
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
                vcpu.set(vmcs::guest::RIP, 0);
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
        EXIT_REASON_HLT | EXIT_REASON_IO_INSTRUCTION => next_instruction(vcpu),
        _ => next_instruction(vcpu),
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
    next_instruction(vcpu);
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
    let qual = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
    let cr_num = (qual & 0xF) as u32;
    let acc = (qual >> 4) & 0x3;
    let reg_idx = (qual >> 8) & 0xF;

    if acc == 0 {
        // MOV to CR
        let val = gpr_by_index(vcpu, reg_idx);
        match cr_num {
            0 => {
                let cr0_mask = vcpu.get(control::CR0_GUEST_HOST_MASK);
                let old_cr0 = vcpu.get(vmcs::guest::CR0);
                let new_cr0 = (old_cr0 & cr0_mask) | (val & !cr0_mask);
                vcpu.set(vmcs::guest::CR0, new_cr0);

                let pg = 1u64 << 31;
                if (old_cr0 & pg) == 0 && (new_cr0 & pg) != 0 {
                    let efer = vcpu.get(vmcs::guest::IA32_EFER_FULL);
                    if efer & (1 << 8) != 0 {
                        vcpu.set(vmcs::guest::IA32_EFER_FULL, efer | (1 << 10));
                    }
                }
            }
            3 => vcpu.set(vmcs::guest::CR3, val),
            4 => {
                let val = val | (1u64 << 13); // keep VMXE
                vcpu.set(vmcs::guest::CR4, val);
            }
            8 => { /* CR8 / TPR — ignore for now */ }
            _ => {
                serial_debug!("[VMEXIT] MOV to CR{} val={:#x} (unexpected)", cr_num, val);
            }
        }
    } else if acc == 1 {
        // MOV from CR
        let val = match cr_num {
            0 => vcpu.get(vmcs::guest::CR0),
            3 => vcpu.get(vmcs::guest::CR3),
            4 => vcpu.get(vmcs::guest::CR4),
            _ => 0,
        };
        set_gpr_by_index(vcpu, reg_idx, val);
    }
    next_instruction(vcpu);
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
    let rip = vcpu.get(vmcs::guest::RIP);
    let rsp = vcpu.get(vmcs::guest::RSP);
    let rflags = vcpu.get(vmcs::guest::RFLAGS);
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
    let rip = vcpu.get(vmcs::guest::RIP);
    let rsp = vcpu.get(vmcs::guest::RSP);
    let cr0 = vcpu.get(vmcs::guest::CR0);
    let cr3 = vcpu.get(vmcs::guest::CR3);
    let cr4 = vcpu.get(vmcs::guest::CR4);
    let efer = vcpu.get(vmcs::guest::IA32_EFER_FULL);
    let rflags = vcpu.get(vmcs::guest::RFLAGS);
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
    let rip = vcpu.get(vmcs::guest::RIP);
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
    let info = vcpu.get(vmcs::ro::VMEXIT_INTERRUPTION_INFO);
    let vector = (info & INTR_INFO_VECTOR_MASK) as u8;
    let exc_type = ((info >> INTR_INFO_TYPE_SHIFT) & INTR_INFO_TYPE_MASK) as u8;
    let has_error_code = (info >> 11) & 1;

    if vector == 6 || vector == 8 {
        let rip = vcpu.get(vmcs::guest::RIP);
        let name = match vector {
            6 => "#UD",
            8 => "#DF",
            _ => "??",
        };
        serial_println!("[VMEXIT] exception {} at RIP={:#018x}", name, rip);
    }

    let inject = INTR_INFO_VALID
        | ((exc_type as u64) << INTR_INFO_TYPE_SHIFT)
        | (vector as u64)
        | (has_error_code << 11);
    vcpu.set(control::VMENTRY_INTERRUPTION_INFO_FIELD, inject);
    if has_error_code == 1 {
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
fn handle_cpuid_local(vcpu: &mut ActiveVcpu) {
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
            const AVX512_EBX: u32 = (1 << 16)
                | (1 << 17)
                | (1 << 21)
                | (1 << 26)
                | (1 << 27)
                | (1 << 28)
                | (1 << 30)
                | (1 << 31);
            const AVX512_ECX: u32 =
                (1 << 1) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 11) | (1 << 12) | (1 << 14);
            const AVX512_EDX: u32 = (1 << 2) | (1 << 3) | (1 << 8) | (1 << 23);
            ebx &= !AVX512_EBX;
            ecx &= !AVX512_ECX;
            edx &= !AVX512_EDX;
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
        (CPUID_THEMIS_BASE, _) => {
            eax = CPUID_THEMIS_MAX;
            ebx = u32::from_le_bytes(*b"Them");
            ecx = u32::from_le_bytes(*b"isCa");
            edx = u32::from_le_bytes(*b"pa  ");
        }
        (CPUID_THEMIS_FEATURES, _) => {
            eax = 0b00001;
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
        (CPUID_THEMIS_DOMCOMM, _) => {
            let gpa = DOMCOMM_GPA.load(core::sync::atomic::Ordering::Relaxed);
            let pages = DOMCOMM_PAGES.load(core::sync::atomic::Ordering::Relaxed);
            eax = gpa as u32;
            ebx = (gpa >> 32) as u32;
            ecx = pages;
            edx = 0;
        }
        (CPUID_THEMIS_LIMITS, _) => {
            eax = THEMIS_MAX_VPS;
            ebx = THEMIS_MAX_PARTITIONS;
            ecx = THEMIS_MAX_MEM_REGIONS;
            edx = 0;
        }
        (CPUID_THEMIS_BASE..=CPUID_HV_RANGE_END, _) => {
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
    next_instruction(vcpu);
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
        next_instruction(vcpu);
    } else {
        match crate::arch::msr_virt::handle_rdmsr(ecx) {
            crate::arch::msr_virt::MsrResult::Emulated(v) => {
                vcpu.set_reg(Reg::Rax, v & MSR_LOW_MASK);
                vcpu.set_reg(Reg::Rdx, (v >> 32) & MSR_LOW_MASK);
                next_instruction(vcpu);
            }
            crate::arch::msr_virt::MsrResult::Passthrough => {
                if crate::arch::msr_virt::in_bitmap_range(ecx) {
                    let value = unsafe { msr::rdmsr(ecx) };
                    vcpu.set_reg(Reg::Rax, value & MSR_LOW_MASK);
                    vcpu.set_reg(Reg::Rdx, (value >> 32) & MSR_LOW_MASK);
                    next_instruction(vcpu);
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
        next_instruction(vcpu);
    } else {
        match crate::arch::msr_virt::handle_wrmsr(ecx, value) {
            crate::arch::msr_virt::MsrResult::Emulated(_) => {
                next_instruction(vcpu);
            }
            crate::arch::msr_virt::MsrResult::Passthrough => {
                if crate::arch::msr_virt::in_bitmap_range(ecx) {
                    unsafe { msr::wrmsr(ecx, value) };
                    next_instruction(vcpu);
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
    let qual = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
    let offset = (qual & APIC_ACCESS_OFFSET_MASK) as usize; // byte offset within APIC page
    let acc_type = (qual >> APIC_ACCESS_TYPE_SHIFT) & APIC_ACCESS_TYPE_MASK;

    let hhdm = platform.hhdm_offset();

    let vapic_phys = vcpu.vapic_phys();
    let vapic_virt = (vapic_phys + hhdm) as *mut u32;

    match acc_type {
        0 | 3 => {
            // Data read or read during event delivery: return VAPIC page value.
            let word_idx = offset / 4;
            let val = unsafe { vapic_virt.add(word_idx).read_volatile() };
            vcpu.set_reg(Reg::Rax, val as u64);
        }
        1 => {
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
                "[APIC_ACCESS] unhandled access type {} offset={:#x} — advancing RIP",
                acc_type,
                offset
            );
        }
    }
    next_instruction(vcpu);
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
    use crate::hypercall::{ept_gpa_to_hpa, guest_gva_to_gpa};

    let hhdm = platform.hhdm_offset();
    let guest_rip = vcpu.get(vmcs::guest::RIP);
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
    let info: u64 = INTR_INFO_VALID | (3 << INTR_INFO_TYPE_SHIFT) | 13 | (1 << 11);
    vcpu.set(control::VMENTRY_INTERRUPTION_INFO_FIELD, info);
    vcpu.set(control::VMENTRY_EXCEPTION_ERR_CODE, 0);
    vcpu.set(control::VMENTRY_INSTRUCTION_LEN, 0);
}

/// Advance guest RIP by the instruction length that caused the VMEXIT.
pub(crate) fn next_instruction(vcpu: &mut ActiveVcpu) {
    let len = vcpu.get(vmcs::ro::VMEXIT_INSTRUCTION_LEN);
    let rip = vcpu.get(vmcs::guest::RIP);
    vcpu.set(vmcs::guest::RIP, rip + len);
}

/// Read a guest GPR by the register index encoded in the CR-access exit
/// qualification (SDM Table 27-3: 0=RAX,1=RCX,2=RDX,3=RBX,4=RSP,5=RBP,
/// 6=RSI,7=RDI,8–15=R8–R15).
fn gpr_by_index(vcpu: &ActiveVcpu, idx: u64) -> u64 {
    match idx {
        0 => vcpu.reg(Reg::Rax),
        1 => vcpu.reg(Reg::Rcx),
        2 => vcpu.reg(Reg::Rdx),
        3 => vcpu.reg(Reg::Rbx),
        4 => vcpu.get(vmcs::guest::RSP), // RSP lives in VMCS
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
        _ => 0,
    }
}

/// Write a guest GPR by the register index (same encoding as `gpr_by_index`).
fn set_gpr_by_index(vcpu: &mut ActiveVcpu, idx: u64, val: u64) {
    match idx {
        0 => vcpu.set_reg(Reg::Rax, val),
        1 => vcpu.set_reg(Reg::Rcx, val),
        2 => vcpu.set_reg(Reg::Rdx, val),
        3 => vcpu.set_reg(Reg::Rbx, val),
        4 => vcpu.set(vmcs::guest::RSP, val),
        5 => vcpu.set_reg(Reg::Rbp, val),
        6 => vcpu.set_reg(Reg::Rsi, val),
        7 => vcpu.set_reg(Reg::Rdi, val),
        8 => vcpu.set_reg(Reg::R8, val),
        9 => vcpu.set_reg(Reg::R9, val),
        10 => vcpu.set_reg(Reg::R10, val),
        11 => vcpu.set_reg(Reg::R11, val),
        12 => vcpu.set_reg(Reg::R12, val),
        13 => vcpu.set_reg(Reg::R13, val),
        14 => vcpu.set_reg(Reg::R14, val),
        15 => vcpu.set_reg(Reg::R15, val),
        _ => {}
    }
}

/// Keep the IA32E_MODE_GUEST entry control in sync with guest EFER.LMA.
fn sync_ia32e_mode_guest(vcpu: &mut ActiveVcpu) {
    let efer = vcpu.get(vmcs::guest::IA32_EFER_FULL);
    let lma = (efer >> 10) & 1;

    let entry = vcpu.get(control::VMENTRY_CONTROLS);
    let ia32e_bit = 1u64 << 9;
    let current = (entry >> 9) & 1;

    if lma != current {
        let new_entry = if lma == 1 {
            entry | ia32e_bit
        } else {
            entry & !ia32e_bit
        };
        vcpu.set(control::VMENTRY_CONTROLS, new_entry);
    }
}

/// Doorbell fast-path for EPT violations.
///
/// Looks up the faulting `gpa` in the child domain's capavisor-internal
/// doorbell table.  On a match:
///   1. Writes a `DoorbellNotify` message to the parent's DomainComm RX ring.
///   2. Advances the child RIP past the faulting write instruction.
///   3. Returns `Some(true)` — caller should VMRESUME child immediately.
///
/// In synchronous (same-core SWITCH) mode the parent is parked and will drain
/// the RX ring when the child eventually exits normally.  An IPI is not sent
/// because the parent VP is not running; it will observe the ring message on
/// its next wakeup.  Future async-mode support will add cross-core IPI here.
///
/// Returns `Some(false)` if no doorbell matches (caller should forward_child_exit).
/// Returns `None` if the platform state is not ready for doorbell lookup.
/// Public doorbell check for the generic monitor loop.
pub(crate) fn check_ept_doorbell(
    platform: &crate::platform::ThemisPlatform,
    vcpu: &mut ActiveVcpu,
    gpa: u64,
    qual: u64,
) -> Option<bool> {
    handle_ept_doorbell(platform, vcpu, gpa, qual)
}

fn handle_ept_doorbell(
    platform: &crate::platform::ThemisPlatform,
    vcpu: &mut ActiveVcpu,
    gpa: u64,
    qual: u64,
) -> Option<bool> {
    use crate::platform::{THEMIC_DOORBELL_FLAG_ANY_SIZE, THEMIC_DOORBELL_FLAG_ANY_VALUE};
    use themis_abi::domcomm;

    // EPT qualification bit 1 = data write; bit 0 = data read; bit 2 = instr fetch.
    let is_write = (qual & (1 << 1)) != 0;
    if !is_write {
        return Some(false);
    }

    let core_id = platform.get_current_core()?;
    let child_domain_id = platform.core_domain_id(core_id as usize);

    let child_arc = platform.domain_arc(child_domain_id)?;
    let child_pd = child_arc.lock();

    // Extract write size from EPT exit qualification bits [4:3].
    let write_size: u32 = match (qual >> 3) & 0x3 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };

    let written_value = vcpu.reg(Reg::Rax);

    serial_rtdbg!(
        "[DOORBELL] EPT gpa={:#x} sz={} val={:#x} #db={}",
        gpa,
        write_size,
        written_value,
        child_pd.doorbells.len()
    );

    let matched: Option<(u32, u64, u64, u32)> = child_pd.doorbells.iter().find_map(|e| {
        if e.gpa != gpa {
            return None;
        }
        let any_value = e.flags & THEMIC_DOORBELL_FLAG_ANY_VALUE != 0;
        let any_size = e.flags & THEMIC_DOORBELL_FLAG_ANY_SIZE != 0;
        if !any_size && e.size != write_size {
            return None;
        }
        if !any_value && e.datamatch != written_value {
            return None;
        }
        Some((e.doorbell_id, e.gpa, written_value, write_size))
    });

    let (doorbell_id, matched_gpa, value, size) = match matched {
        Some(m) => m,
        None => {
            serial_rtdbg!("[DOORBELL] no match gpa={:#x}", gpa);
            return Some(false);
        }
    };

    drop(child_pd);

    let parent_domain_id = {
        let guard = child_arc.lock();
        guard.parent?
    };

    let parent_arc = platform.domain_arc(parent_domain_id)?;
    let mut parent_pd = parent_arc.lock();

    let notify = domcomm::DoorbellNotify {
        doorbell_id,
        reserved: 0,
        gpa: matched_gpa,
        value,
        size,
        reserved2: 0,
    };
    let notify_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &notify as *const domcomm::DoorbellNotify as *const u8,
            core::mem::size_of::<domcomm::DoorbellNotify>(),
        )
    };
    let enqueued = parent_pd.domcomm_rx_enqueue(domcomm::msg_types::DOORBELL_NOTIFY, notify_bytes);
    serial_rtdbg!(
        "[DOORBELL] match db_id={} → parent enq={}",
        doorbell_id,
        enqueued
    );

    drop(parent_pd);

    next_instruction(vcpu);

    Some(true)
}
