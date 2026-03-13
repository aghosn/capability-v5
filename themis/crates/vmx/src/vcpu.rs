//! VCPU abstraction — type-state ActiveVcpu / InactiveVcpu.
//!
//! Enforces the VMCS lifecycle at compile time:
//!   InactiveVcpu ──activate()──▶ ActiveVcpu ──deactivate()──▶ InactiveVcpu
//!
//! `ActiveVcpu` provides vmread/vmwrite as methods and `run()` as a
//! function-call abstraction: each call enters the guest and returns
//! after the next VMEXIT.

use core::marker::PhantomData;
use x86::bits64::vmx;
use x86::vmx::vmcs;

// ── VMCS field encodings used in inline asm ──────────────────────────────── //
const HOST_RSP_ENCODING: u64 = vmcs::host::RSP as u64; // 0x6C14
const HOST_RIP_ENCODING: u64 = vmcs::host::RIP as u64; // 0x6C16

// ── Guest register file ──────────────────────────────────────────────────── //

/// Indices into the guest general-purpose register file.
/// RSP and RIP are not stored here — they live in the VMCS guest-state fields.
#[repr(usize)]
#[derive(Clone, Copy, Debug)]
pub enum Reg {
    Rax = 0,
    Rbx = 1,
    Rcx = 2,
    Rdx = 3,
    Rbp = 4,
    Rsi = 5,
    Rdi = 6,
    R8 = 7,
    R9 = 8,
    R10 = 9,
    R11 = 10,
    R12 = 11,
    R13 = 12,
    R14 = 13,
    R15 = 14,
}

/// Number of entries in the register file.
pub const REGFILE_SIZE: usize = 16; // 15 GPRs + 1 reserved slot

// ── Errors ───────────────────────────────────────────────────────────────── //

#[derive(Debug)]
pub enum VmxError {
    /// CF=1 after VMLAUNCH/VMRESUME — no current VMCS loaded.
    VmFailInvalid,
    /// ZF=1 after VMLAUNCH/VMRESUME — check VM_INSTRUCTION_ERROR in VMCS.
    VmFailValid,
    /// vmclear or vmptrld failed.
    VmcsOperationFailed(&'static str),
}

// ── InactiveVcpu ─────────────────────────────────────────────────────────── //

/// An inactive VCPU.  The VMCS has been vmclear'd and is safe to store,
/// transfer between data structures, or migrate to a different physical core.
///
/// Cannot vmread/vmwrite — must be activated first.
///
/// `Send` because a VMCLEAR'd VMCS is not bound to any core and can be
/// safely transferred.  `!Sync` because concurrent access is not safe.
pub struct InactiveVcpu {
    vmcs_phys: u64,
    vapic_phys: u64,
    msr_bitmap_phys: u64,
    pid_phys: u64,
    vpid: u16,
    launched: bool,
    regs: [u64; REGFILE_SIZE],
}

// SAFETY: After VMCLEAR, the VMCS is flushed to memory and not bound to any
// core.  It is safe to move an InactiveVcpu to another thread/core for
// subsequent VMPTRLD there.
unsafe impl Send for InactiveVcpu {}

impl InactiveVcpu {
    /// Create a new inactive VCPU from freshly-allocated VMCS/VAPIC pages.
    /// The VMCS must have been vmclear'd by the caller.
    pub fn new(vmcs_phys: u64, vapic_phys: u64, msr_bitmap_phys: u64, pid_phys: u64, vpid: u16) -> Self {
        Self {
            vmcs_phys,
            vapic_phys,
            msr_bitmap_phys,
            pid_phys,
            vpid,
            launched: false,
            regs: [0u64; REGFILE_SIZE],
        }
    }

    /// Load this VCPU's VMCS onto the current core (VMPTRLD) and return
    /// an `ActiveVcpu` that can vmread/vmwrite and run the guest.
    pub fn activate(self) -> Result<ActiveVcpu, VmxError> {
        unsafe {
            vmx::vmptrld(self.vmcs_phys)
                .map_err(|_| VmxError::VmcsOperationFailed("vmptrld"))?;
        }
        Ok(ActiveVcpu {
            vmcs_phys: self.vmcs_phys,
            vapic_phys: self.vapic_phys,
            msr_bitmap_phys: self.msr_bitmap_phys,
            pid_phys: self.pid_phys,
            vpid: self.vpid,
            launched: self.launched,
            regs: self.regs,
            _not_send: PhantomData,
        })
    }

    pub fn vmcs_phys(&self) -> u64 { self.vmcs_phys }
    pub fn vapic_phys(&self) -> u64 { self.vapic_phys }
    pub fn msr_bitmap_phys(&self) -> u64 { self.msr_bitmap_phys }
    pub fn pid_phys(&self) -> u64 { self.pid_phys }
    pub fn vpid(&self) -> u16 { self.vpid }

    /// Read a guest GPR value.
    pub fn reg(&self, r: Reg) -> u64 {
        self.regs[r as usize]
    }

    /// Write a guest GPR value.
    pub fn set_reg(&mut self, r: Reg, val: u64) {
        self.regs[r as usize] = val;
    }
}

// ── ActiveVcpu ───────────────────────────────────────────────────────────── //

/// An active VCPU — the VMCS is loaded (via VMPTRLD) on the current core.
/// Provides vmread/vmwrite methods and `run()` to enter/exit the guest.
///
/// Only one ActiveVcpu may exist per physical core at a time.
/// `!Send` — bound to the core where VMPTRLD was issued.
pub struct ActiveVcpu {
    vmcs_phys: u64,
    vapic_phys: u64,
    msr_bitmap_phys: u64,
    pid_phys: u64,
    vpid: u16,
    launched: bool,
    regs: [u64; REGFILE_SIZE],
    _not_send: PhantomData<*const ()>,
}

impl ActiveVcpu {
    // ── VMCS field access ────────────────────────────────────────────── //

    /// Read a VMCS field.  Panics on failure (use `try_get` for fallible).
    pub fn get(&self, field: u32) -> u64 {
        unsafe { vmx::vmread(field).expect("vmread failed") }
    }

    /// Write a VMCS field.  Panics on failure (use `try_set` for fallible).
    pub fn set(&mut self, field: u32, value: u64) {
        unsafe { vmx::vmwrite(field, value).expect("vmwrite failed") }
    }

    /// Read a VMCS field (fallible).
    pub fn try_get(&self, field: u32) -> Result<u64, VmxError> {
        unsafe {
            vmx::vmread(field).map_err(|_| VmxError::VmcsOperationFailed("vmread"))
        }
    }

    /// Write a VMCS field (fallible).
    pub fn try_set(&mut self, field: u32, value: u64) -> Result<(), VmxError> {
        unsafe {
            vmx::vmwrite(field, value)
                .map_err(|_| VmxError::VmcsOperationFailed("vmwrite"))
        }
    }

    // ── Guest GPR access ─────────────────────────────────────────────── //

    /// Read a guest GPR value.
    pub fn reg(&self, r: Reg) -> u64 {
        self.regs[r as usize]
    }

    /// Write a guest GPR value.
    pub fn set_reg(&mut self, r: Reg, val: u64) {
        self.regs[r as usize] = val;
    }

    /// Mutable reference to the full register file (for the asm trampoline).
    pub fn regs_mut(&mut self) -> &mut [u64; REGFILE_SIZE] {
        &mut self.regs
    }

    // ── VCPU identity ────────────────────────────────────────────────── //

    pub fn vmcs_phys(&self) -> u64 { self.vmcs_phys }
    pub fn vapic_phys(&self) -> u64 { self.vapic_phys }
    pub fn msr_bitmap_phys(&self) -> u64 { self.msr_bitmap_phys }
    pub fn pid_phys(&self) -> u64 { self.pid_phys }
    pub fn vpid(&self) -> u16 { self.vpid }

    // ── Lifecycle ────────────────────────────────────────────────────── //

    /// Deactivate this VCPU: VMCLEAR the VMCS and return an InactiveVcpu.
    /// After this call, the VMCS is no longer loaded on any core and the
    /// launch state is reset (next `run()` will VMLAUNCH, not VMRESUME).
    pub fn deactivate(self) -> Result<InactiveVcpu, VmxError> {
        unsafe {
            vmx::vmclear(self.vmcs_phys)
                .map_err(|_| VmxError::VmcsOperationFailed("vmclear"))?;
        }
        Ok(InactiveVcpu {
            vmcs_phys: self.vmcs_phys,
            vapic_phys: self.vapic_phys,
            msr_bitmap_phys: self.msr_bitmap_phys,
            pid_phys: self.pid_phys,
            vpid: self.vpid,
            launched: false, // VMCLEAR resets the launch state
            regs: self.regs,
        })
    }

    // ── Guest entry ──────────────────────────────────────────────────── //

    /// Enter the guest and return after the next VMEXIT.
    ///
    /// On the first call, issues VMLAUNCH; subsequent calls use VMRESUME.
    /// Returns the basic exit reason (bits 15:0 of EXIT_REASON).
    ///
    /// # Safety
    /// The VMCS must be fully configured (guest state, host state, controls)
    /// before the first call.  The caller's stack becomes the host stack
    /// (HOST_RSP is set to the current RSP inside the asm block).
    pub unsafe fn run(&mut self) -> Result<u32, VmxError> {
        if self.launched {
            Self::vmresume_asm(&mut self.regs)?;
        } else {
            Self::vmlaunch_asm(&mut self.regs)?;
            self.launched = true;
        }
        let reason = vmx::vmread(vmcs::ro::EXIT_REASON)
            .map_err(|_| VmxError::VmcsOperationFailed("vmread EXIT_REASON"))?
            as u32 & 0xFFFF;
        Ok(reason)
    }

    /// Has VMLAUNCH been issued on this VCPU?
    pub fn is_launched(&self) -> bool {
        self.launched
    }
}

// ── Naked VM-enter / VM-exit functions ───────────────────────────────────── //
//
// Two naked functions (`vmlaunch_with_regs` / `vmresume_with_regs`) handle
// the full guest-entry/exit cycle.  Using naked functions avoids issues with
// inline asm labels and LTO (local labels in inline asm create anonymous
// symbols that fail to link with LTO + codegen-units=1).
//
// Calling convention (System V x86_64):
//   RDI = pointer to [u64; REGFILE_SIZE] (guest register file)
//   RSI = HOST_RSP VMCS field encoding
//   RDX = HOST_RIP VMCS field encoding
//
// Return value:
//   RAX = RFLAGS captured after VMLAUNCH/VMRESUME (caller checks CF/ZF)
//
// Stack layout at vm-enter (grows downward):
//   [rsp+0]   regs_ptr (saved RDI)
//   [rsp+8]   host RBP (callee-save)
//   [rsp+16]  host RBX (callee-save)
//   [rsp+24]  host R12 (callee-save)
//   [rsp+32]  host R13 (callee-save)
//   [rsp+40]  host R14 (callee-save)
//   [rsp+48]  host R15 (callee-save)
//   [rsp+56]  return address (from call instruction)
//
// HOST_RSP is set to current RSP (after pushes).  On VMEXIT, the CPU
// restores RSP to this value and jumps to HOST_RIP (vmexit_return_point),
// which saves guest GPRs to the regs array, captures RFLAGS, restores
// host callee-saves, and returns to the Rust caller.

/// Shared VMEXIT return point — HOST_RIP target for both VMLAUNCH and VMRESUME.
///
/// On VMEXIT, all GPRs contain guest values.  The stack is at HOST_RSP
/// with the layout described above.
#[unsafe(naked)]
unsafe extern "C" fn vmexit_return_point() {
    core::arch::naked_asm!(
        // Save guest RDI (need it as scratch to access regs_ptr)
        "push rdi",
        // regs_ptr was at [rsp+0] before we pushed; now at [rsp+8]
        "mov rdi, [rsp + 8]",
        // Save all guest GPRs to the register file
        "mov [rdi + {rax_off}], rax",
        "mov [rdi + {rbx_off}], rbx",
        "mov [rdi + {rcx_off}], rcx",
        "mov [rdi + {rdx_off}], rdx",
        "mov [rdi + {rbp_off}], rbp",
        "mov [rdi + {rsi_off}], rsi",
        "mov [rdi + {r8_off}],  r8",
        "mov [rdi + {r9_off}],  r9",
        "mov [rdi + {r10_off}], r10",
        "mov [rdi + {r11_off}], r11",
        "mov [rdi + {r12_off}], r12",
        "mov [rdi + {r13_off}], r13",
        "mov [rdi + {r14_off}], r14",
        "mov [rdi + {r15_off}], r15",
        // Save guest RDI (currently on the stack)
        "pop rax",
        "mov [rdi + {rdi_off}], rax",
        // Capture RFLAGS into RAX (return value).
        // push/pop/mov don't modify flags, so CF/ZF are still intact.
        "pushfq",
        "pop rax",
        // Restore host callee-saved registers + regs_ptr
        "pop rdi",                          // discard regs_ptr
        "pop rbp",
        "pop rbx",
        "pop r12",
        "pop r13",
        "pop r14",
        "pop r15",
        "ret",
        rax_off = const (Reg::Rax as usize) * 8,
        rbx_off = const (Reg::Rbx as usize) * 8,
        rcx_off = const (Reg::Rcx as usize) * 8,
        rdx_off = const (Reg::Rdx as usize) * 8,
        rbp_off = const (Reg::Rbp as usize) * 8,
        rsi_off = const (Reg::Rsi as usize) * 8,
        rdi_off = const (Reg::Rdi as usize) * 8,
        r8_off  = const (Reg::R8  as usize) * 8,
        r9_off  = const (Reg::R9  as usize) * 8,
        r10_off = const (Reg::R10 as usize) * 8,
        r11_off = const (Reg::R11 as usize) * 8,
        r12_off = const (Reg::R12 as usize) * 8,
        r13_off = const (Reg::R13 as usize) * 8,
        r14_off = const (Reg::R14 as usize) * 8,
        r15_off = const (Reg::R15 as usize) * 8,
    );
}

/// Macro to stamp out the VMLAUNCH / VMRESUME naked functions.
/// The only difference between them is the final VM-enter instruction.
macro_rules! naked_vm_enter {
    ($fn_name:ident, $enter_insn:literal) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $fn_name(
            _regs: *mut u64,       // RDI
            _host_rsp_field: u64,  // RSI  (HOST_RSP encoding)
            _host_rip_field: u64,  // RDX  (HOST_RIP encoding)
        ) -> u64 {
            core::arch::naked_asm!(
                // ── Save host callee-saved registers ──
                "push r15",
                "push r14",
                "push r13",
                "push r12",
                "push rbx",
                "push rbp",
                "push rdi",                         // save regs_ptr

                // ── Set HOST_RSP = current RSP ──
                "vmwrite rsi, rsp",

                // ── Set HOST_RIP = vmexit_return_point ──
                "lea rax, [{vmexit_ret}]",
                "vmwrite rdx, rax",

                // ── Load all guest GPRs from the register file ──
                "mov rax, [rdi + {rax_off}]",
                "mov rbx, [rdi + {rbx_off}]",
                "mov rcx, [rdi + {rcx_off}]",
                "mov rdx, [rdi + {rdx_off}]",
                "mov rbp, [rdi + {rbp_off}]",
                "mov rsi, [rdi + {rsi_off}]",
                "mov r8,  [rdi + {r8_off}]",
                "mov r9,  [rdi + {r9_off}]",
                "mov r10, [rdi + {r10_off}]",
                "mov r11, [rdi + {r11_off}]",
                "mov r12, [rdi + {r12_off}]",
                "mov r13, [rdi + {r13_off}]",
                "mov r14, [rdi + {r14_off}]",
                "mov r15, [rdi + {r15_off}]",
                // RDI must be loaded last (it holds the regs pointer)
                "mov rdi, [rdi + {rdi_off}]",

                // ── Enter guest ──
                $enter_insn,

                // ── VMLAUNCH/VMRESUME failed (didn't enter guest) ──
                // CPU did not enter guest mode.  CF or ZF is set.
                // All GPRs still hold guest values we loaded above.
                // Jump to the shared return point to save state and return.
                "jmp {vmexit_ret}",

                vmexit_ret = sym vmexit_return_point,
                rax_off = const (Reg::Rax as usize) * 8,
                rbx_off = const (Reg::Rbx as usize) * 8,
                rcx_off = const (Reg::Rcx as usize) * 8,
                rdx_off = const (Reg::Rdx as usize) * 8,
                rbp_off = const (Reg::Rbp as usize) * 8,
                rsi_off = const (Reg::Rsi as usize) * 8,
                rdi_off = const (Reg::Rdi as usize) * 8,
                r8_off  = const (Reg::R8  as usize) * 8,
                r9_off  = const (Reg::R9  as usize) * 8,
                r10_off = const (Reg::R10 as usize) * 8,
                r11_off = const (Reg::R11 as usize) * 8,
                r12_off = const (Reg::R12 as usize) * 8,
                r13_off = const (Reg::R13 as usize) * 8,
                r14_off = const (Reg::R14 as usize) * 8,
                r15_off = const (Reg::R15 as usize) * 8,
            );
        }
    };
}

naked_vm_enter!(vmlaunch_with_regs, "vmlaunch");
naked_vm_enter!(vmresume_with_regs, "vmresume");

impl ActiveVcpu {
    unsafe fn vmlaunch_asm(regs: &mut [u64; REGFILE_SIZE]) -> Result<(), VmxError> {
        let flags = vmlaunch_with_regs(
            regs.as_mut_ptr(),
            HOST_RSP_ENCODING,
            HOST_RIP_ENCODING,
        );
        check_vm_flags(flags)
    }

    unsafe fn vmresume_asm(regs: &mut [u64; REGFILE_SIZE]) -> Result<(), VmxError> {
        let flags = vmresume_with_regs(
            regs.as_mut_ptr(),
            HOST_RSP_ENCODING,
            HOST_RIP_ENCODING,
        );
        check_vm_flags(flags)
    }
}

fn check_vm_flags(flags: u64) -> Result<(), VmxError> {
    if flags & 1 != 0 {
        Err(VmxError::VmFailInvalid)
    } else if flags & 0x40 != 0 {
        Err(VmxError::VmFailValid)
    } else {
        Ok(())
    }
}
