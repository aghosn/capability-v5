//! VMEXIT handler and monitor loop.
//!
//! After R1 refactoring, the naked `vmexit_trampoline` has been replaced by
//! `ActiveVcpu::run()`, which enters/exits the guest as a function call.
//! `monitor_loop` calls `run()` in a loop and dispatches exits through
//! `handle_vmexit`.

use x86::msr;
use x86::vmx::vmcs;
use x86::vmx::vmcs::control;

use crate::serial_println;
use crate::vcpu::{ActiveVcpu, Reg, VmxError};

use capability_engine::Platform;

// ── DomainComm discovery statics (written once at boot, read by CPUID handler) ─ //
use core::sync::atomic::AtomicU64;
use core::sync::atomic::AtomicU32;

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
const X2APIC_MSR_END: u32  = 0x840; // exclusive

// Notable x2APIC register offsets (MSR = BASE + offset/16).
#[allow(dead_code)]
const X2APIC_ID:      u32 = 0x802;
#[allow(dead_code)]
const X2APIC_VER:     u32 = 0x803;
#[allow(dead_code)]
const X2APIC_TPR:     u32 = 0x808;
#[allow(dead_code)]
const X2APIC_PPR:     u32 = 0x80A;
#[allow(dead_code)]
const X2APIC_EOI:     u32 = 0x80B;
#[allow(dead_code)]
const X2APIC_LDR:     u32 = 0x80D;
#[allow(dead_code)]
const X2APIC_SVR:     u32 = 0x80F;
#[allow(dead_code)]
const X2APIC_ISR0:    u32 = 0x810;
#[allow(dead_code)]
const X2APIC_TMR0:    u32 = 0x818;
#[allow(dead_code)]
const X2APIC_IRR0:    u32 = 0x820;
#[allow(dead_code)]
const X2APIC_ESR:     u32 = 0x828;
#[allow(dead_code)]
const X2APIC_ICR:     u32 = 0x830;
#[allow(dead_code)]
const X2APIC_LVT_TIMER:   u32 = 0x832;
#[allow(dead_code)]
const X2APIC_LVT_THERMAL: u32 = 0x833;
#[allow(dead_code)]
const X2APIC_LVT_PERF:    u32 = 0x834;
#[allow(dead_code)]
const X2APIC_LVT_LINT0:   u32 = 0x835;
#[allow(dead_code)]
const X2APIC_LVT_LINT1:   u32 = 0x836;
#[allow(dead_code)]
const X2APIC_LVT_ERROR:   u32 = 0x837;
#[allow(dead_code)]
const X2APIC_TIMER_ICR:   u32 = 0x838;
#[allow(dead_code)]
const X2APIC_TIMER_CCR:   u32 = 0x839;
#[allow(dead_code)]
const X2APIC_TIMER_DCR:   u32 = 0x83E;
#[allow(dead_code)]
const X2APIC_SELF_IPI:    u32 = 0x83F;

// ── Exit reason constants (Intel SDM Vol 3C §27.9.1) ─────────────────────── //

// VMX preemption timer: ~2 seconds at 3 GHz with TSC rate divisor = 5.
// Timer ticks = desired_ns / (2^N * TSC_period_ns), where N = 5 (typical).
// For ~2s at 3GHz: 2e9 / 2^5 ≈ 62.5M. Use a round value.
pub const PREEMPTION_TIMER_TICKS: u64 = 60_000_000;

pub const EXIT_REASON_EXCEPTION_NMI: u32 = 0;
pub const EXIT_REASON_EXTERNAL_INTERRUPT: u32 = 1;
pub const EXIT_REASON_TRIPLE_FAULT: u32 = 2;
pub const EXIT_REASON_INIT_SIGNAL: u32 = 3;
pub const EXIT_REASON_SIPI: u32 = 4;
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

// ── HOST_RIP stub ─────────────────────────────────────────────────────────── //

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
        unsafe { handle_vmexit(vcpu, exit_reason); }
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
    use core::sync::atomic::{AtomicU64, Ordering};
    static EXIT_COUNT: AtomicU64 = AtomicU64::new(0);
    static LAST_REASON: AtomicU64 = AtomicU64::new(0);

    let _count = EXIT_COUNT.fetch_add(1, Ordering::Relaxed);
    LAST_REASON.store(basic_reason as u64, Ordering::Relaxed);

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
                    match basic_reason {
                        EXIT_REASON_EXTERNAL_INTERRUPT => {
                            // Physical interrupt fired while child was running.
                            // ACKNOWLEDGE_INTERRUPT_ON_EXIT already sent EOI to the LAPIC.
                            // Read the acknowledged vector and forward it to the handler domain
                            // (dom0 in Phase 1) via lazy-unwind + VMENTRY injection.
                            let intr_info = vcpu.get(vmcs::ro::VMEXIT_INTERRUPTION_INFO);
                            let vector = (intr_info & 0xFF) as u8;
                            crate::hypercall::forward_interrupt_to_handler(vcpu, vector);
                            return;
                        }
                        EXIT_REASON_VMX_PREEMPTION_TIMER => {
                            vcpu.set(vmcs::guest::VMX_PREEMPTION_TIMER_VALUE,
                                     PREEMPTION_TIMER_TICKS);
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
            let qual   = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
            let vector = qual & 0xFF;
            let cs_base     = vector << 12;
            let cs_selector = vector << 8;

            vcpu.set(vmcs::guest::CS_SELECTOR,      cs_selector);
            vcpu.set(vmcs::guest::CS_BASE,           cs_base);
            vcpu.set(vmcs::guest::CS_LIMIT,          0xFFFF);
            vcpu.set(vmcs::guest::CS_ACCESS_RIGHTS,  0x009B);
            vcpu.set(vmcs::guest::RIP,               0);
            vcpu.set(vmcs::guest::CR0,               0x30);
            vcpu.set(vmcs::guest::ACTIVITY_STATE,    0);
            vcpu.set(vmcs::guest::VMX_PREEMPTION_TIMER_VALUE, PREEMPTION_TIMER_TICKS);

            serial_println!(
                "[VMEXIT] SIPI vector={:#x} startup={:#x} — AP activated",
                vector, cs_base,
            );
        }

        EXIT_REASON_EXTERNAL_INTERRUPT => {
            // With EXTERNAL_INTERRUPT_EXITING=0 for dom0, this should not
            // fire.  If it does (forced by must_be_1 on this hardware),
            // just VMRESUME — the interrupt is pending and will be delivered
            // to the guest on VM entry.
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
                    ecx &= !(1u32 << 31);
                }
                (0x7, 0) => {
                    // Hide WAITPKG (tpause/umonitor/umwait): ECX bit 5.
                    ecx &= !(1u32 << 5);
                }
                (0xD, 1) => {
                    // XSAVES (bit 3): passed through — ENABLE_XSAVES is
                    // set in secondary proc-based controls.
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
                    ebx = 0; ecx = 0; edx = 0;
                }
                (0x40000002, _) => {
                    // DomainComm discovery: GPA and page count.
                    // Set by init_themis → bootstrap_init_domcomm.
                    let gpa = DOMCOMM_GPA.load(Ordering::Relaxed);
                    let pages = DOMCOMM_PAGES.load(Ordering::Relaxed);
                    eax = gpa as u32;          // GPA low 32 bits
                    ebx = (gpa >> 32) as u32;  // GPA high 32 bits
                    ecx = pages;               // region size in pages
                    edx = 0;
                }
                (0x40000003, _) => {
                    eax = 256;  // max VPs per partition
                    ebx = 1024; // max partitions
                    ecx = 4096; // max memory regions
                    edx = 0;
                }
                (0x40000000..=0x4FFFFFFF, _) => {
                    eax = 0; ebx = 0; ecx = 0; edx = 0;
                }
                (0xDEAD0000..=0xDEADFFFF, _) => {
                    let code = leaf & 0xFFFF;
                    serial_println!("[TRACE] code={:#x}", code);
                    eax = 0; ebx = 0; ecx = 0; edx = 0;
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
            let value = ((vcpu.reg(Reg::Rdx) & 0xFFFF_FFFF) << 32)
                      | (vcpu.reg(Reg::Rax) & 0xFFFF_FFFF);
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
            let qual   = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
            let rip    = vcpu.get(vmcs::guest::RIP);
            let rsp    = vcpu.get(vmcs::guest::RSP);
            let cr0    = vcpu.get(vmcs::guest::CR0);
            let cr3    = vcpu.get(vmcs::guest::CR3);
            let cr4    = vcpu.get(vmcs::guest::CR4);
            let efer   = vcpu.get(vmcs::guest::IA32_EFER_FULL);
            let rflags = vcpu.get(vmcs::guest::RFLAGS);
            let cs_ar  = vcpu.get(vmcs::guest::CS_ACCESS_RIGHTS);
            let entry_ctl = vcpu.get(control::VMENTRY_CONTROLS);
            serial_println!("===== VM-ENTRY FAILURE (vpid={}) =====", vcpu.vpid());
            serial_println!("  qual={:#018x}", qual);
            serial_println!("  RIP={:#018x}  RSP={:#018x}  RFLAGS={:#010x}", rip, rsp, rflags);
            serial_println!("  CR0={:#010x}  CR3={:#010x}  CR4={:#010x}  EFER={:#010x}", cr0, cr3, cr4, efer);
            serial_println!("  CS_AR={:#06x}  entry_ctl={:#010x}", cs_ar, entry_ctl);
            serial_println!("  RAX={:#018x}  RBX={:#018x}  RCX={:#018x}",
                vcpu.reg(Reg::Rax), vcpu.reg(Reg::Rbx), vcpu.reg(Reg::Rcx));
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
            let xcr = vcpu.reg(Reg::Rcx) as u32;
            let val = (vcpu.reg(Reg::Rdx) << 32) | (vcpu.reg(Reg::Rax) & 0xFFFF_FFFF);
            if xcr == 0 {
                let host_xcr0: u64;
                let lo: u32;
                let hi: u32;
                core::arch::asm!(
                    "xgetbv",
                    in("ecx") 0u32,
                    out("eax") lo,
                    out("edx") hi,
                    options(nomem, nostack),
                );
                host_xcr0 = ((hi as u64) << 32) | (lo as u64);
                let safe_val = (val & host_xcr0) | 1;
                serial_println!("[XSETBV] guest={:#x} host_xcr0={:#x} safe={:#x}", val, host_xcr0, safe_val);
                core::arch::asm!(
                    "xsetbv",
                    in("ecx") 0u32,
                    in("eax") safe_val as u32,
                    in("edx") (safe_val >> 32) as u32,
                    options(nomem, nostack),
                );
            }
            next_instruction(vcpu);
        }

        EXIT_REASON_CR_ACCESS => {
            let qual    = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
            let cr_num  = (qual & 0xF) as u32;
            let acc     = (qual >> 4) & 0x3;
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
                    _ => { serial_println!("[VMEXIT] MOV to CR{} val={:#x} (unexpected)", cr_num, val); }
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

            let rip    = vcpu.get(vmcs::guest::RIP);
            let rsp    = vcpu.get(vmcs::guest::RSP);
            let cr0    = vcpu.get(vmcs::guest::CR0);
            let cr3    = vcpu.get(vmcs::guest::CR3);
            let cr4    = vcpu.get(vmcs::guest::CR4);
            let efer   = vcpu.get(vmcs::guest::IA32_EFER_FULL);
            let rflags = vcpu.get(vmcs::guest::RFLAGS);
            let cs_sel = vcpu.get(vmcs::guest::CS_SELECTOR);
            let cs_base = vcpu.get(vmcs::guest::CS_BASE);
            let cs_ar  = vcpu.get(vmcs::guest::CS_ACCESS_RIGHTS);
            let ss_sel = vcpu.get(vmcs::guest::SS_SELECTOR);
            let ss_ar  = vcpu.get(vmcs::guest::SS_ACCESS_RIGHTS);
            let entry_ctl = vcpu.get(control::VMENTRY_CONTROLS);
            let act    = vcpu.get(vmcs::guest::ACTIVITY_STATE);
            let interruptibility = vcpu.get(vmcs::guest::INTERRUPTIBILITY_STATE);
            let idtr_base = vcpu.get(vmcs::guest::IDTR_BASE);
            let idtr_limit = vcpu.get(vmcs::guest::IDTR_LIMIT);

            serial_println!("===== TRIPLE FAULT (vpid={}) =====", vcpu.vpid());
            serial_println!("  RIP={:#018x}  RSP={:#018x}  RFLAGS={:#010x}", rip, rsp, rflags);
            serial_println!("  CR0={:#010x}  CR3={:#010x}  CR4={:#010x}  EFER={:#010x}", cr0, cr3, cr4, efer);
            serial_println!("  CS: sel={:#06x} base={:#010x} ar={:#06x}  SS: sel={:#06x} ar={:#06x}",
                cs_sel, cs_base, cs_ar, ss_sel, ss_ar);
            serial_println!("  IDTR: base={:#018x} limit={:#06x}", idtr_base, idtr_limit);
            serial_println!("  entry_ctl={:#010x}  activity={} interruptibility={:#x}",
                entry_ctl, act, interruptibility);
            serial_println!("  RAX={:#018x}  RBX={:#018x}  RCX={:#018x}",
                vcpu.reg(Reg::Rax), vcpu.reg(Reg::Rbx), vcpu.reg(Reg::Rcx));
            serial_println!("  RDX={:#018x}  RSI={:#018x}  RDI={:#018x}",
                vcpu.reg(Reg::Rdx), vcpu.reg(Reg::Rsi), vcpu.reg(Reg::Rdi));
            serial_println!("  R8 ={:#018x}  R9 ={:#018x}  R10={:#018x}",
                vcpu.reg(Reg::R8), vcpu.reg(Reg::R9), vcpu.reg(Reg::R10));
            serial_println!("  RBP={:#018x}  R12={:#018x}  R13={:#018x}",
                vcpu.reg(Reg::Rbp), vcpu.reg(Reg::R12), vcpu.reg(Reg::R13));
            serial_println!("=================================");

            crate::SERIAL_LOCK.store(false, core::sync::atomic::Ordering::Release);
            halt_forever();
        }

        EXIT_REASON_EPT_VIOLATION => {
            while crate::SERIAL_LOCK.swap(true, core::sync::atomic::Ordering::Acquire) {
                core::hint::spin_loop();
            }
            let gpa = vcpu.get(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL);
            let qual = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
            let rip = vcpu.get(vmcs::guest::RIP);
            let cr3 = vcpu.get(vmcs::guest::CR3);
            let domain_str: &str = {
                let platform_ptr = crate::PLATFORM_PTR.load(core::sync::atomic::Ordering::Acquire);
                if !platform_ptr.is_null() {
                    let platform = unsafe { &*platform_ptr };
                    if let Some(core_id) = platform.get_current_core() {
                        let did = platform.core_domain_id(core_id as usize);
                        serial_println!(
                            "[VMEXIT] EPT violation core={} domain={} vpid={} GPA={:#x} qual={:#x} RIP={:#x} CR3={:#x}",
                            core_id, did, vcpu.vpid(), gpa, qual, rip, cr3
                        );
                        "done"
                    } else {
                        "skip"
                    }
                } else {
                    "skip"
                }
            };
            if domain_str == "skip" {
                serial_println!(
                    "[VMEXIT] EPT violation vpid={} GPA={:#x} qual={:#x} RIP={:#x} CR3={:#x}",
                    vcpu.vpid(), gpa, qual, rip, cr3
                );
            }
            crate::SERIAL_LOCK.store(false, core::sync::atomic::Ordering::Release);
            halt_forever();
        }

        EXIT_REASON_EPT_MISCONFIG => {
            while crate::SERIAL_LOCK.swap(true, core::sync::atomic::Ordering::Acquire) {
                core::hint::spin_loop();
            }
            let gpa = vcpu.get(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL);
            let rip = vcpu.get(vmcs::guest::RIP);
            serial_println!("[VMEXIT] EPT misconfig vpid={} GPA={:#x} RIP={:#x}",
                vcpu.vpid(), gpa, rip);
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
                0 => "#DE", 1 => "#DB", 2 => "NMI", 3 => "#BP",
                6 => "#UD", 8 => "#DF", 13 => "#GP", 14 => "#PF",
                _ => "??",
            };

            if vector == 6 || vector == 8 {
                serial_println!("[VMEXIT] exception {} at RIP={:#018x}", name, rip);
                let rsp = vcpu.get(vmcs::guest::RSP);
                let cr3 = vcpu.get(vmcs::guest::CR3);
                let cr4 = vcpu.get(vmcs::guest::CR4);
                serial_println!("  RSP={:#018x}  CR3={:#010x}  CR4={:#010x}", rsp, cr3, cr4);
                serial_println!("  RAX={:#018x}  RCX={:#018x}  RDX={:#018x}",
                    vcpu.reg(Reg::Rax), vcpu.reg(Reg::Rcx), vcpu.reg(Reg::Rdx));
            }

            // Re-inject the exception into the guest.
            let inject = (1u64 << 31)
                       | ((exc_type as u64) << 8)
                       | (vector as u64)
                       | (has_error_code << 11);
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
            vcpu.set(vmcs::guest::VMX_PREEMPTION_TIMER_VALUE, PREEMPTION_TIMER_TICKS);
        }

        other => {
            serial_println!("[VMEXIT] unhandled exit reason {} — halting", other);
            halt_forever();
        }
    }

    sync_ia32e_mode_guest(vcpu);
}

// ── Helpers ───────────────────────────────────────────────────────────────── //

/// Inject #GP(0) into the guest.
fn inject_gp(vcpu: &mut ActiveVcpu) {
    let info: u64 = (1 << 31) | (3 << 8) | 13 | (1 << 11);
    vcpu.set(control::VMENTRY_INTERRUPTION_INFO_FIELD, info);
    vcpu.set(control::VMENTRY_EXCEPTION_ERR_CODE, 0);
    vcpu.set(control::VMENTRY_INSTRUCTION_LEN, 0);
}

/// Advance guest RIP by the instruction length that caused the VMEXIT.
fn next_instruction(vcpu: &mut ActiveVcpu) {
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
        8  => vcpu.reg(Reg::R8),
        9  => vcpu.reg(Reg::R9),
        10 => vcpu.reg(Reg::R10),
        11 => vcpu.reg(Reg::R11),
        12 => vcpu.reg(Reg::R12),
        13 => vcpu.reg(Reg::R13),
        14 => vcpu.reg(Reg::R14),
        15 => vcpu.reg(Reg::R15),
        _  => 0,
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
        8  => vcpu.set_reg(Reg::R8,  val),
        9  => vcpu.set_reg(Reg::R9,  val),
        10 => vcpu.set_reg(Reg::R10, val),
        11 => vcpu.set_reg(Reg::R11, val),
        12 => vcpu.set_reg(Reg::R12, val),
        13 => vcpu.set_reg(Reg::R13, val),
        14 => vcpu.set_reg(Reg::R14, val),
        15 => vcpu.set_reg(Reg::R15, val),
        _  => {}
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
