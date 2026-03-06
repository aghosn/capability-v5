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

// ── Exit reason constants (Intel SDM Vol 3C §27.9.1) ─────────────────────── //

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
        // vmresume failed — advance past any instruction and halt
        "2:",
        "hlt",
        "jmp 2b",
        handler = sym handle_vmexit,
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
    let exit_reason = vmx::vmread(vmcs::ro::EXIT_REASON)
        .expect("vmread EXIT_REASON failed") as u32;

    // Bits[15:0] hold the basic exit reason; bits[31:16] hold flags.
    let basic_reason = exit_reason & 0xFFFF;

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

            serial_println!(
                "[VMEXIT] SIPI vector={:#x} startup={:#x} — AP activated",
                vector, cs_base,
            );
            // Do NOT call next_instruction() — SIPI is not an executed instruction.
        }

        EXIT_REASON_EXTERNAL_INTERRUPT => {
            // Physical interrupt delivered to host. Nothing to do here —
            // the interrupt was already handled by the host IDT before
            // the VMEXIT was reflected to us. VMRESUME to continue guest.
        }

        EXIT_REASON_CPUID => {
            // Execute host CPUID and pass result to guest.
            let leaf = regs.rax as u32;
            let sub_leaf = regs.rcx as u32;
            let result = core::arch::x86_64::__cpuid_count(leaf, sub_leaf);
            regs.rax = result.eax as u64;
            regs.rbx = result.ebx as u64;
            regs.rcx = result.ecx as u64;
            regs.rdx = result.edx as u64;
            next_instruction();
        }

        EXIT_REASON_HLT => {
            // Guest issued HLT — spin here until an interrupt arrives.
            // For the minimal P2e implementation: just spin (no WFI).
            // A proper implementation would block the VP and schedule another.
            loop {
                core::arch::asm!("pause", options(nomem, nostack));
            }
        }

        EXIT_REASON_RDMSR => {
            let ecx = regs.rcx as u32;
            if ecx == msr::IA32_EFER {
                // Return the guest EFER from VMCS, not the host MSR.
                let value = vmx::vmread(vmcs::guest::IA32_EFER_FULL).unwrap_or(0);
                regs.rax = value & 0xFFFF_FFFF;
                regs.rdx = (value >> 32) & 0xFFFF_FFFF;
            } else {
                // Pass-through: read the hardware MSR, return result in RAX:RDX.
                let value = unsafe { msr::rdmsr(ecx) };
                regs.rax = value & 0xFFFF_FFFF;
                regs.rdx = (value >> 32) & 0xFFFF_FFFF;
            }
            next_instruction();
        }

        EXIT_REASON_WRMSR => {
            let ecx = regs.rcx as u32;
            let value = ((regs.rdx & 0xFFFF_FFFF) << 32) | (regs.rax & 0xFFFF_FFFF);
            if ecx == msr::IA32_EFER {
                // Update the VMCS guest EFER field — do NOT write the host MSR.
                // LOAD_IA32_EFER on VM entry will apply this to the real MSR.
                vmx::vmwrite(vmcs::guest::IA32_EFER_FULL, value)
                    .expect("vmwrite guest EFER");
            } else {
                // Pass-through: write RAX:RDX to the hardware MSR.
                unsafe { msr::wrmsr(ecx, value) };
            }
            next_instruction();
        }

        EXIT_REASON_IO_INSTRUCTION => {
            // I/O instruction exit: with USE_IO_BITMAPS cleared in primary
            // controls this should not occur; if it does (forced by must_be_1),
            // skip the instruction and continue — dom0 gets direct I/O access.
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
            // Stub: log the hypercall opcode and return 0 in RAX.
            let opcode = regs.rax;
            serial_println!("[VMEXIT] VMCALL opcode={:#x} (stub — returning 0)", opcode);
            regs.rax = 0;
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

        2 => {
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
            serial_println!("[VMEXIT] exception/NMI info={:#x} — halting", info);
            halt_forever();
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
