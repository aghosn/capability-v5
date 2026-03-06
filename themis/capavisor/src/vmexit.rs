//! VMEXIT handler — Phase P2e.
//!
//! The `vmexit_trampoline` naked function is the host RIP written into every VMCS.
//! It saves all guest GPRs onto the host stack, calls `handle_vmexit`, then
//! restores GPRs and executes VMRESUME.
//!
//! RSP and RIP are not saved here; they live in the VMCS guest-state fields.

use x86::bits64::vmx;
use x86::vmx::vmcs;

use crate::{serial_println};

// ── Exit reason constants (Intel SDM Vol 3C §27.9.1) ─────────────────────── //

pub const EXIT_REASON_EXCEPTION_NMI: u32 = 0;
pub const EXIT_REASON_EXTERNAL_INTERRUPT: u32 = 1;
pub const EXIT_REASON_CPUID: u32 = 10;
pub const EXIT_REASON_HLT: u32 = 12;
pub const EXIT_REASON_VMCALL: u32 = 18;
pub const EXIT_REASON_CR_ACCESS: u32 = 28;
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
            // Advance guest RIP past the CPUID instruction (2 bytes).
            advance_rip(2);
        }

        EXIT_REASON_HLT => {
            // Guest issued HLT — spin here until an interrupt arrives.
            // For the minimal P2e implementation: just spin (no WFI).
            // A proper implementation would block the VP and schedule another.
            loop {
                core::arch::asm!("pause", options(nomem, nostack));
            }
        }

        EXIT_REASON_VMCALL => {
            // Stub: log the hypercall opcode and return 0 in RAX.
            let opcode = regs.rax;
            serial_println!("[VMEXIT] VMCALL opcode={:#x} (stub — returning 0)", opcode);
            regs.rax = 0;
            advance_rip(3); // VMCALL is 3 bytes (0F 01 C1)
        }

        EXIT_REASON_CR_ACCESS => {
            // CR-access exits are handled by read/write shadow in the VMCS;
            // for now just log and continue.
            let qual = vmx::vmread(vmcs::ro::EXIT_QUALIFICATION)
                .unwrap_or(0);
            serial_println!("[VMEXIT] CR access qualification={:#x} (stub)", qual);
            advance_rip(3); // MOV CR instructions vary; 3-byte estimate
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
}

// ── Helpers ───────────────────────────────────────────────────────────────── //

/// Advance guest RIP by `n` bytes (skip an instruction that caused the exit).
///
/// # Safety
/// A VMCS must be loaded on the current core.
unsafe fn advance_rip(n: u64) {
    let rip = vmx::vmread(vmcs::guest::RIP).expect("vmread guest RIP");
    vmx::vmwrite(vmcs::guest::RIP, rip + n).expect("vmwrite guest RIP");
}

/// Halt the current core forever.
fn halt_forever() -> ! {
    loop {
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}
