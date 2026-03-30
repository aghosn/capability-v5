//! VMEXIT handler and monitor loop.
//!
//! After R1 refactoring, the naked `vmexit_trampoline` has been replaced by
//! `ActiveVcpu::run()`, which enters/exits the guest as a function call.
//! `monitor_loop` calls `run()` in a loop and dispatches exits through
//! `handle_vmexit`.

use x86::msr;
use x86::vmx::vmcs;
use x86::vmx::vmcs::control;

use crate::vcpu::{ActiveVcpu, Reg, VmxError};
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

// ── HOST_RIP stub ─────────────────────────────────────────────────────────── //

/// Handle XSETBV (exit reason 55): guest wants to set XCR0.
///
/// Masks the guest-requested value with the host's supported XCR0 bits and
/// always sets bit 0 (x87 FPU).  Used for both dom0 and child domain exits.
fn handle_xsetbv(vcpu: &mut ActiveVcpu) {
    let xcr = vcpu.reg(Reg::Rcx) as u32;
    let val = (vcpu.reg(Reg::Rdx) << 32) | (vcpu.reg(Reg::Rax) & 0xFFFF_FFFF);
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

// ── Monitor loop ──────────────────────────────────────────────────────────── //

/// Per-core monitor loop: enters the guest via `vcpu.run()` and dispatches
/// VMEXITs.  Never returns.
pub fn monitor_loop(vcpu: &mut ActiveVcpu) -> ! {
    loop {
        let exit_reason = match unsafe { vcpu.run() } {
            Ok(reason) => reason,
            Err(e) => {
                serial_println!("[FATAL] VM entry failed: {:?}", e);
                if matches!(e, VmxError::VmFailValid) {
                    if let Ok(err) = vcpu.try_get(vmcs::ro::VM_INSTRUCTION_ERROR) {
                        serial_println!("  VM_INSTRUCTION_ERROR={}", err);
                    }
                }
                halt_forever();
            }
        };
        // SAFETY: VMCS is loaded via ActiveVcpu and we just exited from the guest.
        unsafe {
            handle_vmexit(vcpu, exit_reason);
        }
    }
}

// ── VMEXIT dispatch ───────────────────────────────────────────────────────── //

/// Handle a single VMEXIT.
///
/// Called from `monitor_loop` after `vcpu.run()` returns.  Dispatches based on
/// the basic exit reason and modifies guest state through `ActiveVcpu` methods.
///
/// # Safety
/// The VMCS must be loaded on the current core (guaranteed by `ActiveVcpu`).
unsafe fn handle_vmexit(vcpu: &mut ActiveVcpu, basic_reason: u32) {
    use core::sync::atomic::Ordering;

    //TODO(aghosn): Not sure about this. We have two matches depending on whether we're dom0 or
    //dom1. This should not really be the case, and dom1 will be able to create dom2 later on too.
    //We should have a more homogeneous way of handling the exits, that takes into account the
    //capability state.

    // ── Child domain exit forwarding ──
    // If the current core is running a child domain (not dom0), forward the
    // exit to the parent — except for capavisor-internal exits (external
    // interrupts, preemption timer) which are handled transparently.
    {
        let platform_ptr = crate::PLATFORM_PTR.load(Ordering::Acquire);
        if !platform_ptr.is_null() {
            let platform = unsafe { &*platform_ptr };
            if let Some(core_id) = platform.get_current_core() {
                let domain_id = platform.core_domain_id(core_id as usize);
                if domain_id != 0 && domain_id != u64::MAX {
                    // VM-entry failure due to invalid guest state — VMCS fields
                    // violated Intel SDM 26.3 checks.  Dump state and panic; this
                    // should never happen once VMCS initialisation is correct.
                    if basic_reason == EXIT_REASON_VMENTRY_INVALID_GUEST {
                        let exit_qual = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
                        let cr0 = vcpu.get(vmcs::guest::CR0);
                        let cr4 = vcpu.get(vmcs::guest::CR4);
                        let cr3 = vcpu.get(vmcs::guest::CR3);
                        let rip = vcpu.get(vmcs::guest::RIP);
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
                        // exit_qual bits 3:0 encode the failing check (SDM Table 27-7)
                        serial_println!(
                            "[FATAL] exit 33 dom={} core={} EXIT_QUAL={:#x} (check={})\n\
                             CR0={:#x} CR4={:#x} CR3={:#x} EFER={:#x}\n\
                             RIP={:#x} RFLAGS={:#x}\n\
                             CS sel={:#x} base={:#x} lim={:#x} ar={:#x}\n\
                             SS sel={:#x} ar={:#x} TR_AR={:#x} LDTR_AR={:#x}\n\
                             activity={} interrupt={:#x} link_ptr={:#x} vpid={}\n\
                             ENTRY_CTRL={:#x} PIN={:#x} PROC2={:#x}\n\
                             INTR_INFO={:#x}\n\
                             CR0_MASK={:#x} CR0_SHADOW={:#x} CR4_MASK={:#x} CR4_SHADOW={:#x}",
                            domain_id,
                            core_id,
                            exit_qual,
                            exit_qual & 0xf,
                            cr0,
                            cr4,
                            cr3,
                            efer,
                            rip,
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
                        panic!(
                            "exit 33: dom={} core={} qual={:#x}",
                            domain_id, core_id, exit_qual
                        );
                    }

                    match basic_reason {
                        EXIT_REASON_EXTERNAL_INTERRUPT => {
                            // Physical interrupt fired while child was running.
                            // ACK_INTERRUPT_ON_EXIT consumed the vector.
                            // A3 lazy-unwind: forward to handler domain immediately.
                            let intr_info = vcpu.get(vmcs::ro::VMEXIT_INTERRUPTION_INFO);
                            let vector = (intr_info & 0xFF) as u8;
                            crate::hypercall::forward_interrupt_to_handler(vcpu, vector);
                            return;
                        }
                        EXIT_REASON_INTERRUPT_WINDOW => {
                            // Guest IF just became 1 — drain PIR and inject pending
                            // device interrupt that was deferred because IF was 0.
                            crate::hypercall::drain_pir_on_interrupt_window(vcpu, platform);
                            return;
                        }
                        EXIT_REASON_EXCEPTION_NMI => {
                            // NMI fired while child was running (NMI_EXITING=1 for child VPs).
                            // NMIs cannot be posted via PIR — forward to dom0 as vector 2.
                            // Child's default Report policy routes it via lazy-unwind to dom0.
                            let intr_info = vcpu.get(vmcs::ro::VMEXIT_INTERRUPTION_INFO);
                            let exc_type = ((intr_info >> 8) & 0x7) as u8;
                            if exc_type == 2 {
                                // Type 2 = NMI; forward to dom0.
                                crate::hypercall::forward_interrupt_to_handler(vcpu, 2);
                            } else {
                                // Exception from child VM (not NMI) — forward via general path.
                                crate::hypercall::forward_child_exit(vcpu, basic_reason);
                            }
                            return;
                        }
                        EXIT_REASON_VMX_PREEMPTION_TIMER => {
                            // Preemption timer expired. Reset for next quantum.
                            // No yield — interrupts are forwarded immediately (A3).
                            vcpu.set(
                                vmcs::guest::VMX_PREEMPTION_TIMER_VALUE,
                                PREEMPTION_TIMER_TICKS,
                            );
                            return;
                        }
                        EXIT_REASON_INIT_SIGNAL => {
                            // An INIT IPI fired while a child VP was running.
                            // This is the capavisor's own cross-core notification
                            // mechanism (INVEPT, drain per-core update queue, etc.)
                            // — identical to the dom0 path.  Process pending work
                            // and re-enter the child.
                            // Dom1's SMP AP wakeup uses CHV's virtual LAPIC
                            // emulation (MMIO exits), not hardware INIT signals.
                            use crate::PLATFORM_PTR;
                            use core::sync::atomic::Ordering;
                            let ptr = PLATFORM_PTR.load(Ordering::Acquire);
                            if !ptr.is_null() {
                                let platform = unsafe { &*ptr };
                                platform.poll_and_respond_cross_core();
                            }
                            return;
                        }
                        EXIT_REASON_VMCALL => {
                            // Route child VMCALLs directly to the capability engine,
                            // same as dom0. This enables dom1 to create dom2, etc.
                            if let Some(result) = crate::hypercall::handle_vmcall(vcpu) {
                                vcpu.set_reg(Reg::Rax, result.rax);
                                vcpu.set_reg(Reg::Rdi, result.rdi);
                                vcpu.set_reg(Reg::Rsi, result.rsi);
                                vcpu.set_reg(Reg::Rdx, result.rdx);
                                next_instruction(vcpu);
                            }
                            // None → SWITCH swapped the vcpu; no writeback needed.
                            return;
                        }
                        EXIT_REASON_CPUID => {
                            // Intercept hypervisor-identification leaves so child
                            // domains see "ThemisCapa" (same as dom0) regardless of
                            // what CHV would return.  All other leaves are forwarded
                            // to CHV via the normal child-exit path.
                            let leaf = vcpu.reg(Reg::Rax) as u32;
                            match leaf {
                                0x40000000..=0x4FFFFFFF => {
                                    let (eax, ebx, ecx, edx) = match leaf {
                                        0x40000000 => (
                                            0x40000003u32,
                                            u32::from_le_bytes(*b"Them"),
                                            u32::from_le_bytes(*b"isCa"),
                                            u32::from_le_bytes(*b"pa  "),
                                        ),
                                        0x40000001 => (0b00001, 0, 0, 0),
                                        0x40000003 => (256, 1024, 4096, 0),
                                        // Leaf 0x40000010: Hyper-V TSC frequency
                                        // ECX = TSC freq in kHz — Linux reads this
                                        // via hv_get_tsc_khz() when running on Hyper-V.
                                        0x40000010 => (0, 0, 3000000u32, 0),
                                        _ => (0, 0, 0, 0),
                                    };
                                    vcpu.set_reg(Reg::Rax, eax as u64);
                                    vcpu.set_reg(Reg::Rbx, ebx as u64);
                                    vcpu.set_reg(Reg::Rcx, ecx as u64);
                                    vcpu.set_reg(Reg::Rdx, edx as u64);
                                    next_instruction(vcpu);
                                    return;
                                }
                                // Leaf 0x15: Time Stamp Counter / Core Crystal Clock
                                // Linux uses this for fast TSC calibration.
                                // EAX=denom, EBX=numer, ECX=crystal Hz.
                                // TSC freq = crystal * numer / denom.
                                // 25 MHz crystal × 120 / 1 = 3000 MHz.
                                0x15 => {
                                    vcpu.set_reg(Reg::Rax, 1u64);         // denominator
                                    vcpu.set_reg(Reg::Rbx, 120u64);       // numerator
                                    vcpu.set_reg(Reg::Rcx, 25_000_000u64); // crystal Hz
                                    vcpu.set_reg(Reg::Rdx, 0u64);
                                    next_instruction(vcpu);
                                    return;
                                }
                                _ => {
                                    // Non-hypervisor leaf: forward to CHV.
                                    crate::hypercall::forward_child_exit(vcpu, basic_reason);
                                    return;
                                }
                            }
                        }
                        EXIT_REASON_APIC_ACCESS => {
                            // Handle most LAPIC accesses locally (virtual APIC page).
                            // ICR writes (offset 0x300) are forwarded to CHV so
                            // it can detect IPI delivery modes (INIT/SIPI) and
                            // manage AP lifecycle — capavisor stays boot-agnostic.
                            let qual = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
                            let offset = qual & 0xFFF;
                            let acc_type = (qual >> 12) & 0xF;
                            if offset == 0x300 && acc_type == 1 {
                                // ICR low write — forward to parent VMM.
                                crate::hypercall::forward_child_exit(
                                    vcpu, EXIT_REASON_APIC_ACCESS);
                                return;
                            }
                            handle_apic_access_exit(vcpu);
                            return;
                        }
                        EXIT_REASON_XSETBV => {
                            // XSETBV is a host-level operation (sets physical XCR0).
                            // Handle it in the capavisor like dom0 — don't forward.
                            handle_xsetbv(vcpu);
                            return;
                        }
                        EXIT_REASON_EPT_VIOLATION => {
                            let gpa = vcpu.get(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL);
                            let qual = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);

                            // Doorbell fast-path: match GPA against child's doorbell table.
                            if let Some(true) = handle_ept_doorbell(platform, vcpu, gpa, qual) {
                                return;
                            }

                            // No match — forward to parent for MMIO emulation.
                            crate::hypercall::forward_child_exit(vcpu, basic_reason);
                            return;
                        }
                        _ => {
                            // All other exits: forward to parent.
                            crate::hypercall::forward_child_exit(vcpu, basic_reason);
                            return;
                        }
                    }
                }
            }
        }
    }

    match basic_reason {
        EXIT_REASON_INIT_SIGNAL => {
            // Cross-core preemption: the initiating core sent an INIT assert
            // to force a VMEXIT from non-root mode.  The actual work (drain
            // the per-core update queue, INVEPT, etc.) happens in
            // poll_and_respond_cross_core via the PLATFORM_PTR global.
            use crate::PLATFORM_PTR;
            use core::sync::atomic::Ordering;
            let ptr = PLATFORM_PTR.load(Ordering::Acquire);
            if !ptr.is_null() {
                let platform = unsafe { &*ptr };
                platform.poll_and_respond_cross_core();
            }
            // Do NOT advance RIP — INIT is not an instruction-based exit.
        }

        EXIT_REASON_SIPI => {
            let qual = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
            let vector = qual & 0xFF;
            let cs_base = vector << 12;
            let cs_selector = vector << 8;

            vcpu.set(vmcs::guest::CS_SELECTOR, cs_selector);
            vcpu.set(vmcs::guest::CS_BASE, cs_base);
            vcpu.set(vmcs::guest::CS_LIMIT, 0xFFFF);
            vcpu.set(vmcs::guest::CS_ACCESS_RIGHTS, 0x009B);
            vcpu.set(vmcs::guest::RIP, 0);
            // CR0 must satisfy IA32_VMX_CR0_FIXED0 (PE + ET + NE required by VMX).
            vcpu.set(vmcs::guest::CR0, unsafe { crate::vmcs::vmcs_adjust_cr0(0x30) });
            vcpu.set(vmcs::guest::ACTIVITY_STATE, 0);
            vcpu.set(
                vmcs::guest::VMX_PREEMPTION_TIMER_VALUE,
                PREEMPTION_TIMER_TICKS,
            );

            serial_println!(
                "[VMEXIT] SIPI vector={:#x} startup={:#x} — AP activated",
                vector,
                cs_base,
            );
        }

        EXIT_REASON_EXTERNAL_INTERRUPT => {
            // With EXTERNAL_INTERRUPT_EXITING=0 for dom0, this should not
            // fire.  If it does (forced by must_be_1 on this hardware),
            // just VMRESUME — the interrupt is pending and will be delivered
            // to the guest on VM entry.
            serial_rtdbg!("[DOM0-EXT-INTR]");
        }

        EXIT_REASON_CPUID => {
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
                    // Hide WAITPKG (ECX bit 5) and all AVX-512 sub-features.
                    // AVX-512 is advertised by the host but child VMs may not
                    // have matching XSAVE state configuration, causing
                    // paranoid_xstate_size_valid failures and userspace #UD
                    // on XGETBV (BUG-12).  Masking here cascades to CHV's
                    // CPUID policy so child domains never see AVX-512 either.
                    const AVX512_EBX: u32 = (1 << 16) // AVX512F
                        | (1 << 17) // AVX512DQ
                        | (1 << 21) // AVX512_IFMA
                        | (1 << 26) // AVX512PF
                        | (1 << 27) // AVX512ER
                        | (1 << 28) // AVX512CD
                        | (1 << 30) // AVX512BW
                        | (1 << 31); // AVX512VL
                    const AVX512_ECX: u32 = (1 << 1) // AVX512_VBMI
                        | (1 << 4)  // PKU/OSPKE
                        | (1 << 5)  // WAITPKG
                        | (1 << 6)  // AVX512_VBMI2
                        | (1 << 11) // AVX512_VNNI
                        | (1 << 12) // AVX512_BITALG
                        | (1 << 14); // AVX512_VPOPCNTDQ
                    const AVX512_EDX: u32 = (1 << 2) // AVX512_4VNNIW
                        | (1 << 3)  // AVX512_4FMAPS
                        | (1 << 8)  // AVX512_VP2INTERSECT
                        | (1 << 23); // AVX512_FP16
                    ebx &= !AVX512_EBX;
                    ecx &= !AVX512_ECX;
                    edx &= !AVX512_EDX;
                }
                (0xD, 0) => {
                    // Restrict XSAVE state to x87 + SSE + AVX only.
                    // Without AVX-512 features, the XSAVE area must not
                    // include opmask/ZMM components or sizes won't match.
                    eax = 0x7;   // bits 0,1,2 = x87 + SSE + AVX
                    ebx = 0x340; // 832 bytes (512 legacy + 64 header + 256 AVX)
                    ecx = 0x340;
                    edx = 0;
                }
                (0xD, 1) => {
                    // XSAVES (bit 3): passed through — ENABLE_XSAVES is
                    // set in secondary proc-based controls.
                    // Fix compact size to match reduced feature set.
                    ebx = 0x340;
                    ecx = 0;
                    edx = 0;
                }
                (0xD, sub) if matches!(sub, 5..=7 | 9) => {
                    // AVX-512 XSAVE component sub-leaves: zero them out.
                    eax = 0; ebx = 0; ecx = 0; edx = 0;
                }
                // Themis hypervisor identification leaves.
                // Leaf 0x40000000: vendor string "ThemisCapa" (10 bytes) in
                //   EBX:ECX:EDX, matching Hyper-V convention for 12-byte strings
                //   (we pad the last 2 bytes with spaces).
                //   EAX = max hypervisor leaf (0x40000003).
                //
                // Leaf 0x40000001: feature flags.
                //   EAX[0] = sync scheduling (VMCALL_SWITCH) supported.
                //   EAX[1] = async scheduling (START_VP/RESUME_VP) supported.
                //   EAX[2] = META VP-state pages available (Phase 10).
                //   EAX[3] = ThemIC (event flags + doorbell) available.
                //   EAX[4] = device assignment (VT-d) available.
                //
                // Leaf 0x40000003: capacity limits.
                //   EAX = max VPs per partition, EBX = max partitions,
                //   ECX = max memory regions.
                //
                // All other leaves in the range: zero.
                (0x40000000, _) => {
                    // "Them" "isCa" "pa  "  (each chunk is little-endian u32)
                    eax = 0x40000003;
                    ebx = u32::from_le_bytes(*b"Them");
                    ecx = u32::from_le_bytes(*b"isCa");
                    edx = u32::from_le_bytes(*b"pa  ");
                }
                (0x40000001, _) => {
                    eax = 0b00001; // bit 0: sync scheduling supported
                    ebx = 0;
                    ecx = 0;
                    edx = 0;
                }
                (0x40000002, _) => {
                    // DomainComm discovery: GPA and page count.
                    // Set by init_themis → bootstrap_init_domcomm.
                    let gpa = DOMCOMM_GPA.load(Ordering::Relaxed);
                    let pages = DOMCOMM_PAGES.load(Ordering::Relaxed);
                    eax = gpa as u32; // GPA low 32 bits
                    ebx = (gpa >> 32) as u32; // GPA high 32 bits
                    ecx = pages; // region size in pages
                    edx = 0;
                }
                (0x40000003, _) => {
                    eax = 256; // max VPs per partition
                    ebx = 1024; // max partitions
                    ecx = 4096; // max memory regions
                    edx = 0;
                }
                (0x40000000..=0x4FFFFFFF, _) => {
                    eax = 0;
                    ebx = 0;
                    ecx = 0;
                    edx = 0;
                }
                (0xDEAD0000..=0xDEADFFFF, _) => {
                    eax = 0;
                    ebx = 0;
                    ecx = 0;
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

        EXIT_REASON_HLT => {
            next_instruction(vcpu);
        }

        EXIT_REASON_RDMSR => {
            let ecx = vcpu.reg(Reg::Rcx) as u32;
            if ecx == msr::IA32_EFER {
                let value = vcpu.get(vmcs::guest::IA32_EFER_FULL);
                vcpu.set_reg(Reg::Rax, value & 0xFFFF_FFFF);
                vcpu.set_reg(Reg::Rdx, (value >> 32) & 0xFFFF_FFFF);
                next_instruction(vcpu);
            } else {
                match crate::msr_virt::handle_rdmsr(ecx) {
                    crate::msr_virt::MsrResult::Emulated(v) => {
                        vcpu.set_reg(Reg::Rax, v & 0xFFFF_FFFF);
                        vcpu.set_reg(Reg::Rdx, (v >> 32) & 0xFFFF_FFFF);
                        next_instruction(vcpu);
                    }
                    crate::msr_virt::MsrResult::Passthrough => {
                        if crate::msr_virt::in_bitmap_range(ecx) {
                            let value = msr::rdmsr(ecx);
                            vcpu.set_reg(Reg::Rax, value & 0xFFFF_FFFF);
                            vcpu.set_reg(Reg::Rdx, (value >> 32) & 0xFFFF_FFFF);
                            next_instruction(vcpu);
                        } else {
                            inject_gp(vcpu);
                        }
                    }
                    crate::msr_virt::MsrResult::GpFault => {
                        inject_gp(vcpu);
                    }
                }
            }
        }

        EXIT_REASON_WRMSR => {
            let ecx = vcpu.reg(Reg::Rcx) as u32;
            let value =
                ((vcpu.reg(Reg::Rdx) & 0xFFFF_FFFF) << 32) | (vcpu.reg(Reg::Rax) & 0xFFFF_FFFF);
            if ecx == msr::IA32_EFER {
                vcpu.set(vmcs::guest::IA32_EFER_FULL, value);
                next_instruction(vcpu);
            } else {
                match crate::msr_virt::handle_wrmsr(ecx, value) {
                    crate::msr_virt::MsrResult::Emulated(_) => {
                        next_instruction(vcpu);
                    }
                    crate::msr_virt::MsrResult::Passthrough => {
                        if crate::msr_virt::in_bitmap_range(ecx) {
                            msr::wrmsr(ecx, value);
                            next_instruction(vcpu);
                        } else {
                            inject_gp(vcpu);
                        }
                    }
                    crate::msr_virt::MsrResult::GpFault => {
                        inject_gp(vcpu);
                    }
                }
            }
        }

        EXIT_REASON_IO_INSTRUCTION => {
            next_instruction(vcpu);
        }

        EXIT_REASON_VMENTRY_INVALID_GUEST => {
            while crate::SERIAL_LOCK.swap(true, core::sync::atomic::Ordering::Acquire) {
                core::hint::spin_loop();
            }
            let qual = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
            let rip = vcpu.get(vmcs::guest::RIP);
            let rsp = vcpu.get(vmcs::guest::RSP);
            let cr0 = vcpu.get(vmcs::guest::CR0);
            let cr3 = vcpu.get(vmcs::guest::CR3);
            let cr4 = vcpu.get(vmcs::guest::CR4);
            let efer = vcpu.get(vmcs::guest::IA32_EFER_FULL);
            let rflags = vcpu.get(vmcs::guest::RFLAGS);
            let cs_ar = vcpu.get(vmcs::guest::CS_ACCESS_RIGHTS);
            let entry_ctl = vcpu.get(control::VMENTRY_CONTROLS);
            serial_println!("===== VM-ENTRY FAILURE (vpid={}) =====", vcpu.vpid());
            serial_println!("  qual={:#018x}", qual);
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
            serial_println!("  CS_AR={:#06x}  entry_ctl={:#010x}", cs_ar, entry_ctl);
            serial_println!(
                "  RAX={:#018x}  RBX={:#018x}  RCX={:#018x}",
                vcpu.reg(Reg::Rax),
                vcpu.reg(Reg::Rbx),
                vcpu.reg(Reg::Rcx)
            );
            serial_println!("==========================================");
            crate::SERIAL_LOCK.store(false, core::sync::atomic::Ordering::Release);
            halt_forever();
        }

        EXIT_REASON_VMCALL => {
            if let Some(result) = crate::hypercall::handle_vmcall(vcpu) {
                vcpu.set_reg(Reg::Rax, result.rax);
                vcpu.set_reg(Reg::Rdi, result.rdi);
                vcpu.set_reg(Reg::Rsi, result.rsi);
                vcpu.set_reg(Reg::Rdx, result.rdx);
                next_instruction(vcpu);
            }
            // None → SWITCH swapped the vcpu; skip writeback + RIP advance.
        }

        EXIT_REASON_XSETBV => {
            handle_xsetbv(vcpu);
        }

        EXIT_REASON_CR_ACCESS => {
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

        EXIT_REASON_TRIPLE_FAULT => {
            // Acquire serial lock to prevent garbled output from concurrent cores.
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
            halt_forever();
        }

        //TODO(aghosn): not sure about this.
        EXIT_REASON_EPT_VIOLATION => {
            let gpa = vcpu.get(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL);
            let qual = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);

            // Check for doorbell fast-path: look up GPA in child domain's table.
            // If matched: write DoorbellNotify to parent's DomainComm RX ring,
            // advance child RIP, and VMRESUME child without stopping it.
            // If no match: forward to the parent via forward_child_exit.
            let platform_ptr = crate::PLATFORM_PTR.load(core::sync::atomic::Ordering::Acquire);
            if !platform_ptr.is_null() {
                let platform = unsafe { &*platform_ptr };
                if let Some(true) = handle_ept_doorbell(platform, vcpu, gpa, qual) {
                    // Fast-path: child resumes immediately.
                    return;
                }
            }

            // No doorbell match (or platform not ready) — full intercept path.
            crate::hypercall::forward_child_exit(vcpu, EXIT_REASON_EPT_VIOLATION);
        }

        EXIT_REASON_EPT_MISCONFIG => {
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
            halt_forever();
        }

        EXIT_REASON_EXCEPTION_NMI => {
            let info = vcpu.get(vmcs::ro::VMEXIT_INTERRUPTION_INFO);
            let vector = (info & 0xFF) as u8;
            let exc_type = ((info >> 8) & 0x7) as u8;
            let has_error_code = (info >> 11) & 1;
            let rip = vcpu.get(vmcs::guest::RIP);

            let name = match vector {
                0 => "#DE",
                1 => "#DB",
                2 => "NMI",
                3 => "#BP",
                6 => "#UD",
                8 => "#DF",
                13 => "#GP",
                14 => "#PF",
                _ => "??",
            };

            if vector == 6 || vector == 8 {
                serial_println!("[VMEXIT] exception {} at RIP={:#018x}", name, rip);
                let rsp = vcpu.get(vmcs::guest::RSP);
                let cr3 = vcpu.get(vmcs::guest::CR3);
                let cr4 = vcpu.get(vmcs::guest::CR4);
                serial_println!("  RSP={:#018x}  CR3={:#010x}  CR4={:#010x}", rsp, cr3, cr4);
                serial_println!(
                    "  RAX={:#018x}  RCX={:#018x}  RDX={:#018x}",
                    vcpu.reg(Reg::Rax),
                    vcpu.reg(Reg::Rcx),
                    vcpu.reg(Reg::Rdx)
                );
            }

            // Re-inject the exception into the guest.
            let inject =
                (1u64 << 31) | ((exc_type as u64) << 8) | (vector as u64) | (has_error_code << 11);
            vcpu.set(control::VMENTRY_INTERRUPTION_INFO_FIELD, inject);
            if has_error_code == 1 {
                let err = vcpu.get(vmcs::ro::VMEXIT_INTERRUPTION_ERR_CODE);
                vcpu.set(control::VMENTRY_EXCEPTION_ERR_CODE, err);
            }
            vcpu.set(control::VMENTRY_INSTRUCTION_LEN, 0);
        }

        EXIT_REASON_VMX_PREEMPTION_TIMER => {
            let _rip = vcpu.get(vmcs::guest::RIP);
            let _rsp = vcpu.get(vmcs::guest::RSP);
            let _rflags = vcpu.get(vmcs::guest::RFLAGS);
            let _cs = vcpu.get(vmcs::guest::CS_SELECTOR);
            let _cr3 = vcpu.get(vmcs::guest::CR3);
            let _ifl = if _rflags & (1 << 9) != 0 { 1 } else { 0 };
            // serial_println!("[HEARTBEAT] CS={:#06x} RIP={:#018x} RSP={:#018x} IF={} CR3={:#x}",
            //                _cs, _rip, _rsp, _ifl, _cr3);
            vcpu.set(
                vmcs::guest::VMX_PREEMPTION_TIMER_VALUE,
                PREEMPTION_TIMER_TICKS,
            );
        }

        EXIT_REASON_APIC_ACCESS => {
            handle_apic_access_exit(vcpu);
        }

        EXIT_REASON_EOI_INDUCED => {
            // Exit qualification bits[7:0] = vector whose EOI caused the exit.
            // Fires only when VID=1 and the vector's bit is set in the EOI-exit
            // bitmap (currently all zero → this exit never fires in practice).
            // When REPORT-visibility interrupt delivery to child domains is added,
            // set the relevant bitmap bits and implement parent-chain notification here.
            let qual = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
            let _vector = (qual & 0xFF) as u8;
        }

        _other => {
            halt_forever();
        }
    }

    sync_ia32e_mode_guest(vcpu);
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
fn handle_apic_access_exit(vcpu: &mut ActiveVcpu) {
    let qual = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
    let offset = (qual & 0xFFF) as usize; // byte offset within APIC page
    let acc_type = (qual >> 12) & 0xF;

    // Log LAPIC timer-related register accesses (LVT Timer, Initial Count,
    // Current Count, Divide Config) to diagnose timer mode selection.
    const APIC_LVT_TIMER: usize = 0x320;
    const APIC_TMICT: usize     = 0x380;
    const APIC_TMCCT: usize     = 0x390;
    const APIC_TDCR: usize      = 0x3E0;
    if matches!(offset, APIC_LVT_TIMER | APIC_TMICT | APIC_TMCCT | APIC_TDCR) {
    }

    let platform_ptr = crate::PLATFORM_PTR.load(core::sync::atomic::Ordering::Acquire);
    if platform_ptr.is_null() {
        next_instruction(vcpu);
        return;
    }
    let hhdm = unsafe { (*platform_ptr).hhdm_offset() };

    let vapic_phys = vcpu.vapic_phys();
    let vapic_virt = (vapic_phys + hhdm) as *mut u32;

    match acc_type {
        0 | 3 => {
            // Data read or read during event delivery: return VAPIC page value.
            // APIC registers are 32-bit aligned; offset / 4 gives the word index.
            let word_idx = offset / 4;
            let val = unsafe { vapic_virt.add(word_idx).read_volatile() };
            vcpu.set_reg(Reg::Rax, val as u64);
        }
        1 => {
            // Data write: mirror into VAPIC page.
            let word_idx = offset / 4;
            let val = vcpu.reg(Reg::Rax) as u32;
            unsafe { vapic_virt.add(word_idx).write_volatile(val) };
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
pub unsafe fn inject_virtual_interrupt(vapic_virt: *mut u32, vector: u8, vcpu: &mut ActiveVcpu) {
    // VAPIC VIRR layout mirrors xAPIC IRR: 8 × 32-bit words starting at 0x200.
    // Byte offset for this vector:  0x200 + (vector / 32) * 4
    // Bit position within the word: vector % 32
    let word_idx = (vector / 32) as usize; // 0..7
    let bit = vector % 32;
    let virr_ptr = unsafe { vapic_virt.add(0x200 / 4 + word_idx) };
    unsafe { virr_ptr.write_volatile(virr_ptr.read_volatile() | (1u32 << bit)) };

    // Update RVI (bits[7:0] of guest interrupt-status) if this vector is higher.
    let status = vcpu.get(vmcs::guest::INTERRUPT_STATUS);
    let rvi = (status & 0xFF) as u8;
    if vector > rvi {
        let new_status = (status & !0xFF) | (vector as u64);
        vcpu.set(vmcs::guest::INTERRUPT_STATUS, new_status);
    }
}

/// Inject #GP(0) into the guest.
fn inject_gp(vcpu: &mut ActiveVcpu) {
    let info: u64 = (1 << 31) | (3 << 8) | 13 | (1 << 11);
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

/// Halt the current core forever.
fn halt_forever() -> ! {
    loop {
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
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

    serial_rtdbg!("[DOORBELL] EPT gpa={:#x} sz={} val={:#x} #db={}",
        gpa, write_size, written_value, child_pd.doorbells.len());

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
    serial_rtdbg!("[DOORBELL] match db_id={} → parent enq={}", doorbell_id, enqueued);

    drop(parent_pd);

    next_instruction(vcpu);

    Some(true)
}
