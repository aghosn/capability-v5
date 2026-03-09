//! VMEXIT handler — Phase P2e.
//!
//! The `vmexit_trampoline` naked function is the host RIP written into every VMCS.
//! It saves all guest GPRs onto the host stack, calls `handle_vmexit`, then
//! restores GPRs and executes VMRESUME.
//!
//! RSP and RIP are not saved here; they live in the VMCS guest-state fields.

use x86::bits64::vmx;
use x86::msr;
use x86::vmx::vmcs;
use x86::vmx::vmcs::control;

use crate::{serial_println};

// ── x2APIC MSR range (SDM Vol 3 §10.12.1) ──────────────────────────────── //
// In x2APIC mode every APIC register is accessed via MSRs 0x800–0x83F.
// We virtualise these through the VAPIC page rather than letting the guest
// touch the real LAPIC.
const X2APIC_MSR_BASE: u32 = 0x800;
const X2APIC_MSR_END: u32  = 0x840; // exclusive

// Notable x2APIC register offsets (MSR = BASE + offset/16).
const X2APIC_ID:      u32 = 0x802;
const X2APIC_VER:     u32 = 0x803;
const X2APIC_TPR:     u32 = 0x808;
const X2APIC_PPR:     u32 = 0x80A;
const X2APIC_EOI:     u32 = 0x80B;
const X2APIC_LDR:     u32 = 0x80D;
const X2APIC_SVR:     u32 = 0x80F;
const X2APIC_ISR0:    u32 = 0x810;
const X2APIC_TMR0:    u32 = 0x818;
const X2APIC_IRR0:    u32 = 0x820;
const X2APIC_ESR:     u32 = 0x828;
const X2APIC_ICR:     u32 = 0x830;
const X2APIC_LVT_TIMER:   u32 = 0x832;
const X2APIC_LVT_THERMAL: u32 = 0x833;
const X2APIC_LVT_PERF:    u32 = 0x834;
const X2APIC_LVT_LINT0:   u32 = 0x835;
const X2APIC_LVT_LINT1:   u32 = 0x836;
const X2APIC_LVT_ERROR:   u32 = 0x837;
const X2APIC_TIMER_ICR:   u32 = 0x838;
const X2APIC_TIMER_CCR:   u32 = 0x839;
const X2APIC_TIMER_DCR:   u32 = 0x83E;
const X2APIC_SELF_IPI:    u32 = 0x83F;

// ── Exit reason constants (Intel SDM Vol 3C §27.9.1) ─────────────────────── //

// VMX preemption timer: ~2 seconds at 3 GHz with TSC rate divisor = 5.
// Timer ticks = desired_ns / (2^N * TSC_period_ns), where N = 5 (typical).
// For ~2s at 3GHz: 2e9 / 2^5 ≈ 62.5M. Use a round value.
pub const PREEMPTION_TIMER_TICKS: u64 = 60_000_000;

pub const EXIT_REASON_EXCEPTION_NMI: u32 = 0;
pub const EXIT_REASON_EXTERNAL_INTERRUPT: u32 = 1;
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
pub const EXIT_REASON_TRIPLE_FAULT: u32 = 2;

// ── Saved guest GPR layout (matches push order in trampoline) ─────────────── //

/// All guest GPRs saved on the host stack at VMEXIT, in push order.
///
/// RSP and RIP are NOT here — they are read from VMCS when needed.
#[derive(Debug, Default)]
#[repr(C)]
pub struct GuestRegs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9:  u64,
    pub r8:  u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
}

// ── VMEXIT trampoline (naked — no Rust prologue/epilogue) ─────────────────── //

/// Host RIP target for VMEXIT.
///
/// Saves all guest GPRs, calls `handle_vmexit`, restores GPRs, then VMRESUMEs.
/// If VMRESUME fails (shouldn't happen in normal operation), we halt the core.
#[unsafe(naked)]
pub unsafe extern "C" fn vmexit_trampoline() -> ! {
    core::arch::naked_asm!(
        // Save guest GPRs in the order GuestRegs is laid out (reversed stack order).
        "push rax",
        "push rcx",
        "push rdx",
        "push rbx",
        "push rbp",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // rdi = &GuestRegs (first argument per System V ABI)
        "mov rdi, rsp",
        "call {handler}",
        // Restore guest GPRs
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rbp",
        "pop rbx",
        "pop rdx",
        "pop rcx",
        "pop rax",
        // VMRESUME to return to the guest
        "vmresume",
        // vmresume failed — diagnose the failure
        "jc 3f",          // CF=1: VM_FAIL_INVALID (no current VMCS)
        "jz 4f",          // ZF=1: VM_FAIL_VALID (error code in VMCS)
        // Neither flag set — shouldn't happen
        "mov rdi, 0",
        "call {fail}",
        "3:",
        "mov rdi, 1",
        "call {fail}",
        "4:",
        "mov rdi, 2",
        "call {fail}",
        "2:",
        "hlt",
        "jmp 2b",
        handler = sym handle_vmexit,
        fail = sym vmresume_failed,
    );
}

// ── Rust VMEXIT handler ───────────────────────────────────────────────────── //

/// Called from `vmexit_trampoline` with a pointer to the saved GPRs.
///
/// Reads the exit reason from the VMCS, dispatches, and returns.
/// After returning the trampoline pops GPRs and executes VMRESUME.
///
/// # Safety
/// Must only be called from `vmexit_trampoline` with a valid VMCS loaded.
#[no_mangle]
unsafe extern "C" fn handle_vmexit(regs: &mut GuestRegs) {
    use core::sync::atomic::{AtomicU64, Ordering};
    static EXIT_COUNT: AtomicU64 = AtomicU64::new(0);
    static LAST_REASON: AtomicU64 = AtomicU64::new(0);

    let exit_reason = vmx::vmread(vmcs::ro::EXIT_REASON)
        .expect("vmread EXIT_REASON failed") as u32;

    // Bits[15:0] hold the basic exit reason; bits[31:16] hold flags.
    let basic_reason = exit_reason & 0xFFFF;

    let count = EXIT_COUNT.fetch_add(1, Ordering::Relaxed);
    LAST_REASON.store(basic_reason as u64, Ordering::Relaxed);


    match basic_reason {
        EXIT_REASON_SIPI => {
            // Linux AP startup: BSP sent SIPI to wake this AP.
            // The 8-bit vector V in exit qualification specifies the startup
            // address: physical = V × 0x1000, CS.selector = V × 0x100,
            // CS.base = V × 0x1000, RIP = 0.
            let qual   = vmx::vmread(vmcs::ro::EXIT_QUALIFICATION).unwrap_or(0);
            let vector = qual & 0xFF;
            let cs_base     = vector << 12;
            let cs_selector = vector << 8;

            // Real-mode CS: present, code, 16-bit, byte-granular (0x009B).
            vmx::vmwrite(vmcs::guest::CS_SELECTOR,     cs_selector).expect("vmwrite CS_SELECTOR");
            vmx::vmwrite(vmcs::guest::CS_BASE,         cs_base).expect("vmwrite CS_BASE");
            vmx::vmwrite(vmcs::guest::CS_LIMIT,        0xFFFF).expect("vmwrite CS_LIMIT");
            vmx::vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, 0x009B).expect("vmwrite CS_ACCESS_RIGHTS");
            vmx::vmwrite(vmcs::guest::RIP,             0).expect("vmwrite guest RIP");
            // Switch guest to real mode (PE=0, ET=1, NE=1).
            // NE must remain set to satisfy IA32_VMX_CR0_FIXED0.
            vmx::vmwrite(vmcs::guest::CR0,             0x30).expect("vmwrite guest CR0");
            // Activate the AP (leave wait-for-SIPI).
            vmx::vmwrite(vmcs::guest::ACTIVITY_STATE, 0).expect("vmwrite ACTIVITY_STATE");
            // Reload the preemption timer now that the AP is active.
            vmx::vmwrite(vmcs::guest::VMX_PREEMPTION_TIMER_VALUE, PREEMPTION_TIMER_TICKS)
                .expect("SIPI reload preemption timer");

            serial_println!(
                "[VMEXIT] SIPI vector={:#x} startup={:#x} — AP activated",
                vector, cs_base,
            );
            // Do NOT call next_instruction() — SIPI is not an executed instruction.
        }

        EXIT_REASON_EXTERNAL_INTERRUPT => {
            // With EXTERNAL_INTERRUPT_EXITING=0 for dom0, this should not
            // fire.  If it does (forced by must_be_1 on this hardware),
            // just VMRESUME — the interrupt is pending and will be delivered
            // to the guest on VM entry.
        }

        EXIT_REASON_CPUID => {
            // Execute host CPUID and pass result to guest.
            // Passthrough hypervisor: expose real hardware capabilities.
            // Only mask hypervisor-presence bits to prevent L0 signature leaking.
            let leaf = regs.rax as u32;
            let sub_leaf = regs.rcx as u32;
            let result = core::arch::x86_64::__cpuid_count(leaf, sub_leaf);
            let mut eax = result.eax;
            let mut ebx = result.ebx;
            let mut ecx = result.ecx;
            let mut edx = result.edx;

            match (leaf, sub_leaf) {
                // Leaf 1: clear hypervisor-present bit (ECX bit 31).
                // In nested VMX, L0 sets this; clearing it tells the guest
                // it runs on bare metal, stopping the 0x4000xxxx scan loop.
                (0x1, _) => {
                    ecx &= !(1u32 << 31);
                }
                // Leaf 0xD sub-leaf 1: clear XSAVES/XRSTORS (bit 3).
                // These require secondary exec control bit 20 which we
                // have not enabled; the kernel falls back to XSAVEOPT/XSAVEC.
                (0xD, 1) => {
                    eax &= !(1 << 3);
                }
                // Hide ALL hypervisor CPUID leaves.  In nested VMX
                // (L0=KVM on Hyper-V), pass-through exposes L0 signatures
                // that trigger infinite init retry loops.  The guest boots
                // as bare metal; nopv cmdline disables paravirt too.
                (0x40000000..=0x4FFFFFFF, _) => {
                    eax = 0; ebx = 0; ecx = 0; edx = 0;
                }
                // Themis trace: guest writes CPUID leaf 0xDEADxxxx to signal
                // progress.  The low 16 bits are a trace code.
                (0xDEAD0000..=0xDEADFFFF, _) => {
                    let code = leaf & 0xFFFF;
                    serial_println!("[TRACE] code={:#x}", code);
                    eax = 0; ebx = 0; ecx = 0; edx = 0;
                }
                _ => {}
            }

            regs.rax = eax as u64;
            regs.rbx = ebx as u64;
            regs.rcx = ecx as u64;
            regs.rdx = edx as u64;
            next_instruction();
        }

        EXIT_REASON_HLT => {
            // Guest issued HLT — waiting for an interrupt.
            // Re-enter the guest immediately: if an interrupt is pending the
            // processor will deliver it on VM entry; if not, the guest will
            // re-execute HLT.  A proper implementation would block the VP.
            next_instruction();
        }

        EXIT_REASON_RDMSR => {
            let ecx = regs.rcx as u32;
            if ecx == msr::IA32_EFER {
                // Return the guest EFER from VMCS, not the host MSR.
                let value = vmx::vmread(vmcs::guest::IA32_EFER_FULL).unwrap_or(0);
                regs.rax = value & 0xFFFF_FFFF;
                regs.rdx = (value >> 32) & 0xFFFF_FFFF;
                next_instruction();
            } else if msr_in_bitmap_range(ecx) {
                // MSR is in the bitmap-covered range — safe to pass through.
                let value = unsafe { msr::rdmsr(ecx) };
                regs.rax = value & 0xFFFF_FFFF;
                regs.rdx = (value >> 32) & 0xFFFF_FFFF;
                next_instruction();
            } else {
                // MSR outside bitmap range (always causes VMEXIT).
                // Inject #GP(0) — same as real hardware for nonexistent MSRs.
                inject_gp();
            }
        }

        EXIT_REASON_WRMSR => {
            let ecx = regs.rcx as u32;
            let value = ((regs.rdx & 0xFFFF_FFFF) << 32) | (regs.rax & 0xFFFF_FFFF);
            if ecx == msr::IA32_EFER {
                // Update the VMCS guest EFER field — do NOT write the host MSR.
                // LOAD_IA32_EFER on VM entry will apply this to the real MSR.
                vmx::vmwrite(vmcs::guest::IA32_EFER_FULL, value)
                    .expect("vmwrite guest EFER");
                next_instruction();
            } else if msr_in_bitmap_range(ecx) {
                // MSR is in the bitmap-covered range — safe to pass through.
                unsafe { msr::wrmsr(ecx, value) };
                next_instruction();
            } else {
                // MSR outside bitmap range — inject #GP(0).
                inject_gp();
            }
        }

        EXIT_REASON_IO_INSTRUCTION => {
            // I/O instruction exit: USE_IO_BITMAPS is off, so this should
            // only fire if UNCONDITIONAL_IO_EXITING is forced by must_be_1.
            // Skip the instruction — dom0 gets direct I/O access.
            next_instruction();
        }

        EXIT_REASON_VMENTRY_INVALID_GUEST => {
            // VM-entry failure: guest state was invalid at entry (after pre-checks).
            let qual   = vmx::vmread(vmcs::ro::EXIT_QUALIFICATION).unwrap_or(0);
            let rip    = vmx::vmread(vmcs::guest::RIP).unwrap_or(0);
            let rsp    = vmx::vmread(vmcs::guest::RSP).unwrap_or(0);
            let cr0    = vmx::vmread(vmcs::guest::CR0).unwrap_or(0);
            let cr3    = vmx::vmread(vmcs::guest::CR3).unwrap_or(0);
            let cr4    = vmx::vmread(vmcs::guest::CR4).unwrap_or(0);
            let efer   = vmx::vmread(vmcs::guest::IA32_EFER_FULL).unwrap_or(0);
            let rflags = vmx::vmread(vmcs::guest::RFLAGS).unwrap_or(0);
            serial_println!("[VMEXIT] EXIT REASON 33: VM-entry failure (invalid guest state)");
            serial_println!("  qual(IA32_DEBUGCTL)={:#018x}", qual);
            serial_println!("  RIP={:#018x}  RSP={:#018x}  RFLAGS={:#010x}", rip, rsp, rflags);
            serial_println!("  CR0={:#010x}  CR3={:#010x}  CR4={:#010x}  EFER={:#010x}", cr0, cr3, cr4, efer);
            serial_println!("  RAX={:#018x}  RBX={:#018x}  RCX={:#018x}", regs.rax, regs.rbx, regs.rcx);
            halt_forever();
        }

        EXIT_REASON_VMCALL => {
            // KVM paravirtual hypercall.  We don't implement any, so return
            // -ENOSYS (= -38 as i64 sign-extended to u64) to make the guest
            // fall back to native paths (e.g. direct LAPIC IPI instead of
            // KVM_HC_SEND_IPI).  Returning 0 (success) without performing the
            // action causes silent hangs.
            let opcode = regs.rax;
            regs.rax = (-38_i64) as u64; // -ENOSYS
            next_instruction();
        }

        EXIT_REASON_XSETBV => {
            // Guest is writing XCR0 (ECX=0) to enable XSAVE feature bits.
            // XSETBV unconditionally causes a VM exit (SDM §25.1.1).
            //
            // In nested VMX (L0=KVM), doing a real XSETBV here only changes
            // L1's XCR0.  L2's XCR0 was set before VMLAUNCH and is saved/
            // restored by L0 across exits.  We still do the real XSETBV to
            // keep L1's XCR0 in sync (so our exit handler context has the
            // right feature set for any XSAVE/XRSTOR we might do).
            let xcr = regs.rcx as u32;
            let val = (regs.rdx << 32) | (regs.rax & 0xFFFF_FFFF);
            if xcr == 0 {
                // Read current host XCR0 for comparison/fallback.
                let host_xcr0: u64;
                unsafe {
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
                }
                // Mask guest value to only include bits the host supports.
                let safe_val = val & host_xcr0;
                // Bit 0 (x87) must always be 1 in XCR0.
                let safe_val = safe_val | 1;
                serial_println!("[XSETBV] guest={:#x} host_xcr0={:#x} safe={:#x}", val, host_xcr0, safe_val);
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
            next_instruction();
        }

        EXIT_REASON_CR_ACCESS => {
            // Decode exit qualification (SDM §27.2.1, Table 27-3).
            //   bits[3:0]  = CR number (0, 3, 4, 8)
            //   bits[5:4]  = access type (0=MOV to CR, 1=MOV from CR, 2=CLTS, 3=LMSW)
            //   bits[11:8] = source/dest register index (0=RAX,1=RCX,…)
            let qual    = vmx::vmread(vmcs::ro::EXIT_QUALIFICATION).unwrap_or(0);
            let cr_num  = (qual & 0xF) as u32;
            let acc     = (qual >> 4) & 0x3;
            let reg_idx = (qual >> 8) & 0xF;

            if acc == 0 {
                // MOV to CR — read the value from the saved guest GPR
                let val = gpr_by_index(regs, reg_idx);
                match cr_num {
                    0 => {
                        // Force FIXED0 bits that we own via the mask (NE, etc.).
                        let cr0_mask = vmx::vmread(control::CR0_GUEST_HOST_MASK).unwrap_or(0);
                        let old_cr0 = vmx::vmread(vmcs::guest::CR0).unwrap_or(0);
                        let new_cr0 = (old_cr0 & cr0_mask) | (val & !cr0_mask);
                        vmx::vmwrite(vmcs::guest::CR0, new_cr0).expect("vmwrite guest CR0");

                        // Detect long-mode activation: PG going 0→1 with EFER.LME=1.
                        let pg = 1u64 << 31;
                        if (old_cr0 & pg) == 0 && (new_cr0 & pg) != 0 {
                            let efer = vmx::vmread(vmcs::guest::IA32_EFER_FULL).unwrap_or(0);
                            if efer & (1 << 8) != 0 { // LME set
                                vmx::vmwrite(vmcs::guest::IA32_EFER_FULL, efer | (1 << 10))
                                    .expect("vmwrite guest EFER LMA");
                            }
                        }
                    }
                    3 => vmx::vmwrite(vmcs::guest::CR3, val).expect("vmwrite guest CR3"),
                    4 => {
                        // Always keep VMXE (bit 13): the SDM forbids clearing it
                        // in non-root mode — doing so would cause #GP(0).
                        let val = val | (1u64 << 13);
                        vmx::vmwrite(vmcs::guest::CR4, val).expect("vmwrite guest CR4");
                    }
                    8 => { /* CR8 / TPR — ignore for now */ }
                    _ => { serial_println!("[VMEXIT] MOV to CR{} val={:#x} (unexpected)", cr_num, val); }
                }
            } else if acc == 1 {
                // MOV from CR — write the VMCS value back to the guest GPR
                let val = match cr_num {
                    0 => vmx::vmread(vmcs::guest::CR0).unwrap_or(0),
                    3 => vmx::vmread(vmcs::guest::CR3).unwrap_or(0),
                    4 => vmx::vmread(vmcs::guest::CR4).unwrap_or(0),
                    _ => 0,
                };
                set_gpr_by_index(regs, reg_idx, val);
            }
            // CLTS (acc=2) and LMSW (acc=3) are not expected in our guest.
            next_instruction();
        }

        EXIT_REASON_TRIPLE_FAULT => {
            // Triple fault: guest hit a fault it could not deliver.
            // Dump guest state for debugging.
            let rip  = vmx::vmread(vmcs::guest::RIP).unwrap_or(0);
            let rsp  = vmx::vmread(vmcs::guest::RSP).unwrap_or(0);
            let cr0  = vmx::vmread(vmcs::guest::CR0).unwrap_or(0);
            let cr3  = vmx::vmread(vmcs::guest::CR3).unwrap_or(0);
            let cr4  = vmx::vmread(vmcs::guest::CR4).unwrap_or(0);
            let efer = vmx::vmread(vmcs::guest::IA32_EFER_FULL).unwrap_or(0);
            let rflags = vmx::vmread(vmcs::guest::RFLAGS).unwrap_or(0);
            serial_println!("[VMEXIT] TRIPLE FAULT — guest state at fault:");
            serial_println!("  RIP={:#018x}  RSP={:#018x}  RFLAGS={:#010x}", rip, rsp, rflags);
            serial_println!("  CR0={:#010x}  CR3={:#010x}  CR4={:#010x}  EFER={:#010x}", cr0, cr3, cr4, efer);
            serial_println!("  RAX={:#018x}  RBX={:#018x}  RCX={:#018x}", regs.rax, regs.rbx, regs.rcx);
            serial_println!("  RDX={:#018x}  RSI={:#018x}  RDI={:#018x}", regs.rdx, regs.rsi, regs.rdi);
            halt_forever();
        }

        EXIT_REASON_EPT_VIOLATION => {
            let gpa = vmx::vmread(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL).unwrap_or(0);
            let qual = vmx::vmread(vmcs::ro::EXIT_QUALIFICATION).unwrap_or(0);
            serial_println!(
                "[VMEXIT] EPT violation GPA={:#x} qual={:#x} — halting",
                gpa, qual
            );
            halt_forever();
        }

        EXIT_REASON_EPT_MISCONFIG => {
            let gpa = vmx::vmread(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL).unwrap_or(0);
            serial_println!("[VMEXIT] EPT misconfig GPA={:#x} — halting", gpa);
            halt_forever();
        }

        EXIT_REASON_EXCEPTION_NMI => {
            let info = vmx::vmread(vmcs::ro::VMEXIT_INTERRUPTION_INFO).unwrap_or(0);
            let vector = (info & 0xFF) as u8;
            let exc_type = ((info >> 8) & 0x7) as u8;  // 3 = hardware exception
            let has_error_code = (info >> 11) & 1;
            let rip = vmx::vmread(vmcs::guest::RIP).unwrap_or(0);

            let name = match vector {
                0 => "#DE", 1 => "#DB", 2 => "NMI", 3 => "#BP",
                6 => "#UD", 8 => "#DF", 13 => "#GP", 14 => "#PF",
                _ => "??",
            };

            // Only verbose dump for #UD and #DF (unexpected); #GP on MSR
            // access is routine — one-liner only.
            if vector == 6 || vector == 8 {
                serial_println!("[VMEXIT] exception {} at RIP={:#018x}", name, rip);
                let rsp = vmx::vmread(vmcs::guest::RSP).unwrap_or(0);
                let cr3 = vmx::vmread(vmcs::guest::CR3).unwrap_or(0);
                let cr4 = vmx::vmread(vmcs::guest::CR4).unwrap_or(0);
                serial_println!("  RSP={:#018x}  CR3={:#010x}  CR4={:#010x}", rsp, cr3, cr4);
                serial_println!("  RAX={:#018x}  RCX={:#018x}  RDX={:#018x}", regs.rax, regs.rcx, regs.rdx);
            }

            // Re-inject the exception into the guest so its own handler runs.
            let inject = (1u64 << 31)
                       | ((exc_type as u64) << 8)
                       | (vector as u64)
                       | (has_error_code << 11);
            vmx::vmwrite(control::VMENTRY_INTERRUPTION_INFO_FIELD, inject)
                .expect("vmwrite inject exception");
            if has_error_code == 1 {
                let err = vmx::vmread(vmcs::ro::VMEXIT_INTERRUPTION_ERR_CODE).unwrap_or(0);
                vmx::vmwrite(control::VMENTRY_EXCEPTION_ERR_CODE, err)
                    .expect("vmwrite inject error code");
            }
            vmx::vmwrite(control::VMENTRY_INSTRUCTION_LEN, 0)
                .expect("vmwrite inject instr len");
        }

        EXIT_REASON_VMX_PREEMPTION_TIMER => {
            // Diagnostic: periodically sample guest RIP/RSP to detect hangs.
            let _rip = vmx::vmread(vmcs::guest::RIP).unwrap_or(0);
            let _rsp = vmx::vmread(vmcs::guest::RSP).unwrap_or(0);
            let _rflags = vmx::vmread(vmcs::guest::RFLAGS).unwrap_or(0);
            let _cs = vmx::vmread(vmcs::guest::CS_SELECTOR as u32).unwrap_or(0);
            let _cr3 = vmx::vmread(vmcs::guest::CR3).unwrap_or(0);
            let _ifl = if _rflags & (1 << 9) != 0 { 1 } else { 0 };
            // serial_println!("[HEARTBEAT] CS={:#06x} RIP={:#018x} RSP={:#018x} IF={} CR3={:#x}",
            //                _cs, _rip, _rsp, _ifl, _cr3);
            // Reload the preemption timer for the next sample.
            vmx::vmwrite(vmcs::guest::VMX_PREEMPTION_TIMER_VALUE, PREEMPTION_TIMER_TICKS)
                .expect("reload preemption timer");
        }

        other => {
            serial_println!("[VMEXIT] unhandled exit reason {} — halting", other);
            halt_forever();
        }
    }

    // ── Synchronize IA32E_MODE_GUEST with guest EFER.LMA before VMRESUME ── //
    // When the guest transitions to long mode (CR0.PG=1 + EFER.LME=1), the
    // processor sets LMA=1 in the real MSR.  On VM exit, SAVE_IA32_EFER
    // captures LMA=1 into the VMCS guest EFER.  We must update the entry
    // control bit IA32E_MODE_GUEST to match, otherwise the next VM entry
    // fails consistency checks (SDM §26.3.1.5: LMA must match the control).
    // Also update CS access rights: IA32E_MODE_GUEST=1 requires CS.L=1.
    sync_ia32e_mode_guest();
}

// ── Helpers ───────────────────────────────────────────────────────────────── //

/// Check whether an MSR index is within the MSR-bitmap–covered ranges.
/// The bitmap covers 0x00000000–0x00001FFF and 0xC0000000–0xC0001FFF.
/// MSRs outside these ranges always cause VMEXITs regardless of the bitmap.
fn msr_in_bitmap_range(ecx: u32) -> bool {
    ecx <= 0x1FFF || (0xC000_0000..=0xC000_1FFF).contains(&ecx)
}

/// Inject #GP(0) into the guest.  Used when the guest accesses a nonexistent
/// or out-of-range MSR — the real CPU would #GP, so we emulate that.
/// Does NOT advance RIP; the #GP handler in the guest IDT will run at the
/// faulting instruction.
unsafe fn inject_gp() {
    // VM-entry interruption-info: valid=1, type=3 (hw exception), vector=13, error_code=1
    let info: u64 = (1 << 31) | (3 << 8) | 13 | (1 << 11);
    vmx::vmwrite(control::VMENTRY_INTERRUPTION_INFO_FIELD, info)
        .expect("vmwrite inject #GP info");
    vmx::vmwrite(control::VMENTRY_EXCEPTION_ERR_CODE, 0)
        .expect("vmwrite inject #GP error code");
    vmx::vmwrite(control::VMENTRY_INSTRUCTION_LEN, 0)
        .expect("vmwrite inject #GP instr len");
}

/// Advance guest RIP by the length of the instruction that caused the VMEXIT.
///
/// The hardware records the instruction length in `VMEXIT_INSTRUCTION_LEN` for
/// all instruction-based exits (CPUID, VMCALL, HLT, MOV CRn, …).  This mirrors
/// vmxvmm's `VmxState::next_instruction()`.
///
/// # Safety
/// A VMCS must be loaded on the current core.
unsafe fn next_instruction() {
    let len = vmx::vmread(vmcs::ro::VMEXIT_INSTRUCTION_LEN)
        .expect("vmread VMEXIT_INSTRUCTION_LEN");
    let rip = vmx::vmread(vmcs::guest::RIP)
        .expect("vmread guest RIP");
    vmx::vmwrite(vmcs::guest::RIP, rip + len)
        .expect("vmwrite guest RIP");
}

/// Halt the current core forever.
fn halt_forever() -> ! {
    loop {
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}

/// Called from the trampoline when VMRESUME fails.
/// `kind`: 0 = neither CF nor ZF (impossible), 1 = CF (INVALID), 2 = ZF (VALID).
unsafe extern "C" fn vmresume_failed(kind: u64) -> ! {
    match kind {
        1 => { serial_println!("[VMRESUME FAIL] VM_FAIL_INVALID (CF=1) — no current VMCS"); }
        2 => {
            let err = vmx::vmread(vmcs::ro::VM_INSTRUCTION_ERROR).unwrap_or(0xdead);
            let rip = vmx::vmread(vmcs::guest::RIP).unwrap_or(0);
            let rsp = vmx::vmread(vmcs::guest::RSP).unwrap_or(0);
            let cr0 = vmx::vmread(vmcs::guest::CR0).unwrap_or(0);
            let cr3 = vmx::vmread(vmcs::guest::CR3).unwrap_or(0);
            let cr4 = vmx::vmread(vmcs::guest::CR4).unwrap_or(0);
            let efer = vmx::vmread(vmcs::guest::IA32_EFER_FULL).unwrap_or(0);
            let entry_ctl = vmx::vmread(control::VMENTRY_CONTROLS).unwrap_or(0);
            let cs_ar = vmx::vmread(vmcs::guest::CS_ACCESS_RIGHTS).unwrap_or(0);
            let cs_sel = vmx::vmread(vmcs::guest::CS_SELECTOR as u32).unwrap_or(0);
            serial_println!("[VMRESUME FAIL] VM_FAIL_VALID (ZF=1) — VM_INSTRUCTION_ERROR={}", err);
            serial_println!("  guest RIP={:#018x}  RSP={:#018x}", rip, rsp);
            serial_println!("  CR0={:#010x}  CR3={:#010x}  CR4={:#010x}  EFER={:#010x}", cr0, cr3, cr4, efer);
            serial_println!("  ENTRY_CTL={:#010x}  CS_SEL={:#06x}  CS_AR={:#06x}", entry_ctl, cs_sel, cs_ar);
        }
        _ => { serial_println!("[VMRESUME FAIL] unexpected flags (kind={})", kind); }
    }
    halt_forever();
}

/// Read a guest GPR by the register index encoded in the CR-access exit
/// qualification (SDM Table 27-3: 0=RAX,1=RCX,2=RDX,3=RBX,4=RSP,5=RBP,
/// 6=RSI,7=RDI,8–15=R8–R15).
fn gpr_by_index(regs: &GuestRegs, idx: u64) -> u64 {
    match idx {
        0 => regs.rax,
        1 => regs.rcx,
        2 => regs.rdx,
        3 => regs.rbx,
        4 => unsafe { vmx::vmread(vmcs::guest::RSP).unwrap_or(0) }, // RSP in VMCS
        5 => regs.rbp,
        6 => regs.rsi,
        7 => regs.rdi,
        8  => regs.r8,
        9  => regs.r9,
        10 => regs.r10,
        11 => regs.r11,
        12 => regs.r12,
        13 => regs.r13,
        14 => regs.r14,
        15 => regs.r15,
        _  => 0,
    }
}

/// Write a guest GPR by the register index (same encoding as `gpr_by_index`).
fn set_gpr_by_index(regs: &mut GuestRegs, idx: u64, val: u64) {
    match idx {
        0 => regs.rax = val,
        1 => regs.rcx = val,
        2 => regs.rdx = val,
        3 => regs.rbx = val,
        4 => unsafe { vmx::vmwrite(vmcs::guest::RSP, val).expect("vmwrite RSP"); },
        5 => regs.rbp = val,
        6 => regs.rsi = val,
        7 => regs.rdi = val,
        8  => regs.r8  = val,
        9  => regs.r9  = val,
        10 => regs.r10 = val,
        11 => regs.r11 = val,
        12 => regs.r12 = val,
        13 => regs.r13 = val,
        14 => regs.r14 = val,
        15 => regs.r15 = val,
        _  => {}
    }
}

/// Keep the IA32E_MODE_GUEST entry control in sync with guest EFER.LMA.
///
/// After the guest transitions to long mode (sets CR0.PG with EFER.LME=1),
/// the processor sets LMA=1 and SAVE_IA32_EFER captures it on VM exit.
/// Before the next VMRESUME, the entry control must match:
///   - IA32E_MODE_GUEST=1 requires guest EFER.LMA=1 AND CS.L=1
///   - IA32E_MODE_GUEST=0 requires guest EFER.LMA=0 (when LOAD_IA32_EFER=1)
unsafe fn sync_ia32e_mode_guest() {
    let efer = vmx::vmread(vmcs::guest::IA32_EFER_FULL).unwrap_or(0);
    let lma = (efer >> 10) & 1; // bit 10 = LMA

    let entry = vmx::vmread(control::VMENTRY_CONTROLS).unwrap_or(0);
    let ia32e_bit = 1u64 << 9;
    let current = (entry >> 9) & 1;

    if lma != current {
        let new_entry = if lma == 1 {
            entry | ia32e_bit
        } else {
            entry & !ia32e_bit
        };
        vmx::vmwrite(control::VMENTRY_CONTROLS, new_entry)
            .expect("vmwrite entry controls (IA32E sync)");

        // When switching to IA32E_MODE_GUEST=1, the VM entry check requires
        // CS.L=1 and CS.D=0.  Update CS access rights to match.
        if lma == 1 {
            let cs_ar = vmx::vmread(vmcs::guest::CS_ACCESS_RIGHTS).unwrap_or(0);
            let cs_l = (cs_ar >> 13) & 1;
            if cs_l == 0 {
                // Set L=1 (bit 13), clear D=0 (bit 14) for 64-bit code segment.
                let new_ar = (cs_ar | (1 << 13)) & !(1 << 14);
                vmx::vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, new_ar)
                    .expect("vmwrite CS access rights (64-bit)");
            }
        }
    }
}
