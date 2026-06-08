//! VMEXIT handler and monitor loop.
//!
//! After R1 refactoring, the naked `vmexit_trampoline` has been replaced by
//! `ActiveVcpu::run()`, which enters/exits the guest as a function call.
//! `monitor_loop` calls `run()` in a loop and dispatches exits through
//! `handle_vmexit`.
//!
//! This module is split into several submodules:
//!   - `classify`: `classify_and_handle_internal` — the front-door exit-reason
//!     dispatcher invoked by the generic monitor loop.
//!   - `cr`: CR-access exit handler (`handle_cr_access`).
//!   - `cpuid`: `handle_cpuid_local` (native cpuid + masking + Themis leaves).
//!   - `msr`: `handle_rdmsr_local` / `handle_wrmsr_local`.
//!   - `apic`: `handle_apic_access_exit` + `decode_apic_write_value`.
//!   - `fatal`: VM-entry-failure / triple-fault / EPT-misconfig dumpers.
//!
//! Constants, statics, the `Ia32Efer` bitflags, the small shared helpers
//! (`handle_xsetbv`, `reinject_exception`, `inject_gp`, `sync_ia32e_mode_guest`),
//! the HOST_RIP stub, and the `handle_local_exit` dispatcher live here.

use x86::vmx::vmcs;
use x86::vmx::vmcs::control;
use x86::vmx::vmcs::control::EntryControls;

use crate::arch::x86_64::vmexit_decode::{intr_type, IntrInfo};
use crate::arch::x86_64::vcpu_ext::ActiveVcpuExt;
use crate::vcpu::{ActiveVcpu, Reg};
use crate::serial_println;

mod apic;
mod classify;
mod cpuid;
mod cr;
mod fatal;
mod msr;

pub(crate) use classify::classify_and_handle_internal;

// ── DomainComm discovery statics (written once at boot, read by CPUID handler) ─ //
use core::sync::atomic::AtomicU32;
use core::sync::atomic::AtomicU64;

/// Domcomm header GPA, written by `boot::probe_domcomm_capabilities`.
pub static DOMCOMM_GPA: AtomicU64 = AtomicU64::new(0);
/// Total domcomm pages (header + RX + TX), same provenance as `DOMCOMM_GPA`.
pub static DOMCOMM_PAGES: AtomicU32 = AtomicU32::new(0);

// ── x2APIC MSR range (SDM Vol 3 §10.12.1) ──────────────────────────────── //

#[allow(dead_code)]
const X2APIC_MSR_BASE: u32 = 0x800;
#[allow(dead_code)]
const X2APIC_MSR_END: u32 = 0x840; // exclusive

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
//
// Sourced from `themis_abi::vmx_exit_reasons` (single source of truth shared
// with the userspace VMM) and re-exported under the SDM-style
// `EXIT_REASON_<NAME>` aliases that local call sites expect.

/// VMX-preemption-timer ticks loaded on every VMENTRY (~30 ms at 2 GHz / 128).
pub const PREEMPTION_TIMER_TICKS: u64 = 60_000_000;

pub use themis_abi::vmx_exit_reasons::{
    APIC_ACCESS as EXIT_REASON_APIC_ACCESS, APIC_WRITE as EXIT_REASON_APIC_WRITE,
    CPUID as EXIT_REASON_CPUID, CR_ACCESS as EXIT_REASON_CR_ACCESS,
    EOI_INDUCED as EXIT_REASON_EOI_INDUCED, EPT_MISCONFIG as EXIT_REASON_EPT_MISCONFIG,
    EPT_VIOLATION as EXIT_REASON_EPT_VIOLATION, EXCEPTION_NMI as EXIT_REASON_EXCEPTION_NMI,
    EXTERNAL_INTERRUPT as EXIT_REASON_EXTERNAL_INTERRUPT, HLT as EXIT_REASON_HLT,
    INIT_SIGNAL as EXIT_REASON_INIT_SIGNAL, INTERRUPT_WINDOW as EXIT_REASON_INTERRUPT_WINDOW,
    IO_INSTRUCTION as EXIT_REASON_IO_INSTRUCTION, RDMSR as EXIT_REASON_RDMSR,
    SIPI as EXIT_REASON_SIPI, TRIPLE_FAULT as EXIT_REASON_TRIPLE_FAULT,
    VMCALL as EXIT_REASON_VMCALL, VMENTRY_INVALID_GUEST as EXIT_REASON_VMENTRY_INVALID_GUEST,
    VMX_PREEMPTION_TIMER as EXIT_REASON_VMX_PREEMPTION_TIMER, WRMSR as EXIT_REASON_WRMSR,
    XSETBV as EXIT_REASON_XSETBV,
};

// ── APIC register offsets (Intel SDM Vol 3A §10.4.1) ─────────────────────── //

pub(super) const APIC_REG_EOI: usize = 0x0B0;
pub(super) const APIC_REG_ICR_LOW: usize = 0x300;
pub(super) const APIC_REG_ICR_HIGH: usize = 0x310;
pub(super) const APIC_REG_ISR_BASE: usize = 0x100; // ISR: 8 × 32-bit words at 0x100–0x170

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
pub(super) const CPUID_THEMIS_MAX: u32 = themis_abi::cpuid::LEAF_IVSHMEM;
pub(super) const CPUID_HV_RANGE_END: u32 = 0x4FFFFFFF;
pub(super) const CPUID_DEBUG_RANGE_START: u32 = 0xDEAD0000;
pub(super) const CPUID_DEBUG_RANGE_END: u32 = 0xDEADFFFF;

// Themis capacity limits (exposed via CPUID_THEMIS_LIMITS)
pub(super) const THEMIS_MAX_VPS: u32 = 256;
pub(super) const THEMIS_MAX_PARTITIONS: u32 = 1024;
pub(super) const THEMIS_MAX_MEM_REGIONS: u32 = 4096;

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

pub(super) const MSR_LOW_MASK: u64 = 0xFFFF_FFFF;

// (EXIT_REASON_* re-exports above already cover CR_ACCESS, IO_INSTRUCTION,
// RDMSR, WRMSR, VMENTRY_INVALID_GUEST, EPT_VIOLATION, EPT_MISCONFIG,
// VMX_PREEMPTION_TIMER, XSETBV, APIC_ACCESS, EOI_INDUCED, APIC_WRITE.)

// ── Local-exit dispatch ──────────────────────────────────────────────────── //

use crate::arch_traits::types::ExitInfo;

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
        EXIT_REASON_CPUID => cpuid::handle_cpuid_local(vcpu, platform),
        EXIT_REASON_RDMSR => msr::handle_rdmsr_local(vcpu),
        EXIT_REASON_WRMSR => msr::handle_wrmsr_local(vcpu),
        EXIT_REASON_CR_ACCESS => cr::handle_cr_access(vcpu),
        EXIT_REASON_EXCEPTION_NMI => reinject_exception(vcpu),
        EXIT_REASON_EPT_VIOLATION => {
            // CPL=3: an unprivileged process touched a GPA that is no longer
            // present in this domain's EPT (typically a page that was sent to
            // a child via CARVE+SEND).  Inject #GP(0) so Linux delivers
            // SIGSEGV to the offending user process — userspace can install a
            // handler with siglongjmp to demonstrate the isolation property.
            //
            // CPL=0: kernel-context EPT violation.  We can't safely inject
            // #PF (Linux walks guest PT, sees the entry present, treats the
            // fault as spurious, and re-runs the instruction → infinite EPT
            // loop) or #GP (no extable for the typical HHDM access path —
            // would oops).  Log the event and advance RIP; the load is
            // effectively skipped (destination register unchanged).
            let cs_sel = vcpu.get(vmcs::guest::CS_SELECTOR);
            let cpl = (cs_sel & 0x3) as u8;
            let gpa = if let ExitInfo::EptViolation { gpa, .. } = info { *gpa } else { 0 };
            if cpl == 3 {
                serial_println!(
                    "[VMEXIT] EPT_VIOLATION CPL=3 gpa={:#x} rip={:#018x} → inject #GP(0)",
                    gpa, vcpu.rip()
                );
                inject_gp(vcpu);
            } else {
                serial_println!(
                    "[VMEXIT] EPT_VIOLATION CPL=0 gpa={:#x} rip={:#018x} → skip (no inject)",
                    gpa, vcpu.rip()
                );
                vcpu.next_rip();
            }
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
pub(super) fn handle_xsetbv(vcpu: &mut ActiveVcpu) {
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

// ── Shared local helpers ─────────────────────────────────────────────────── //

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

/// Inject #GP(0) into the guest.
pub(super) fn inject_gp(vcpu: &mut ActiveVcpu) {
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
