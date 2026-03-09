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
/// transfer between data structures, or (after appropriate flush) migrate
/// to a different physical core.
///
/// Cannot vmread/vmwrite — must be activated first.
pub struct InactiveVcpu {
    vmcs_phys: u64,
    vapic_phys: u64,
    vpid: u16,
    launched: bool,
    regs: [u64; REGFILE_SIZE],
    /// !Send + !Sync — tied to the core that last ran it until explicitly
    /// migrated (which requires VMCLEAR on the old core first).
    _not_send: PhantomData<*const ()>,
}

impl InactiveVcpu {
    /// Create a new inactive VCPU from freshly-allocated VMCS/VAPIC pages.
    /// The VMCS must have been vmclear'd by the caller.
    pub fn new(vmcs_phys: u64, vapic_phys: u64, vpid: u16) -> Self {
        Self {
            vmcs_phys,
            vapic_phys,
            vpid,
            launched: false,
            regs: [0u64; REGFILE_SIZE],
            _not_send: PhantomData,
        }
    }

    /// Load this VCPU's VMCS onto the current core (VMPTRLD) and return
    /// an `ActiveVcpu` that can vmread/vmwrite and run the guest.
    pub fn activate(self) -> Result<ActiveVcpu, VmxError> {
        // SAFETY: caller must ensure the VMCS page is valid and was
        // vmclear'd (or is being loaded on the same core it was last
        // active on without an intervening vmclear — a "current" VMCS).
        unsafe {
            vmx::vmptrld(self.vmcs_phys)
                .map_err(|_| VmxError::VmcsOperationFailed("vmptrld"))?;
        }
        Ok(ActiveVcpu {
            vmcs_phys: self.vmcs_phys,
            vapic_phys: self.vapic_phys,
            vpid: self.vpid,
            launched: self.launched,
            regs: self.regs,
            _not_send: PhantomData,
        })
    }

    /// Physical address of the VMCS page.
    pub fn vmcs_phys(&self) -> u64 {
        self.vmcs_phys
    }

    /// Physical address of the virtual-APIC page.
    pub fn vapic_phys(&self) -> u64 {
        self.vapic_phys
    }

    /// VPID assigned to this VCPU.
    pub fn vpid(&self) -> u16 {
        self.vpid
    }

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
pub struct ActiveVcpu {
    vmcs_phys: u64,
    vapic_phys: u64,
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

    pub fn vmcs_phys(&self) -> u64 {
        self.vmcs_phys
    }

    pub fn vapic_phys(&self) -> u64 {
        self.vapic_phys
    }

    pub fn vpid(&self) -> u16 {
        self.vpid
    }

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
            vpid: self.vpid,
            launched: false, // VMCLEAR resets the launch state
            regs: self.regs,
            _not_send: PhantomData,
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

// ── Inline asm for guest entry ───────────────────────────────────────────── //
//
// The macro stamps out the trampoline for both VMLAUNCH and VMRESUME.
// The only difference is the final instruction.
//
// Register allocation inside the asm block:
//   RAX — regs pointer (in), guest RAX (saved manually), RFLAGS (out)
//   RCX — HOST_RSP field encoding (in), guest RCX (out via inout)
//   RDX — HOST_RIP field encoding (in), guest RDX (out via inout)
//   RBX — host callee-save / temp for guest save
//   RBP — host callee-save / temp for HOST_RIP address
//   RSI,RDI,R8–R15 — guest values (via inout constraints)
//
// HOST_RSP is set to the current RSP (caller's stack).
// HOST_RIP is set to the VMEXIT return label inside the asm block.
// After VMEXIT, execution resumes at that label and the function returns
// normally — making vmlaunch/vmresume behave like a function call.

macro_rules! vm_enter_asm {
    ($regs:expr, $enter_insn:literal) => {{
        let regs_ptr: u64 = $regs.as_mut_ptr() as u64;
        let host_rsp_field: u64 = HOST_RSP_ENCODING;
        let host_rip_field: u64 = HOST_RIP_ENCODING;
        let flags_out: u64;

        core::arch::asm!(
            // ── Save host callee-saved registers ──
            "push rbx",
            "push rbp",
            "push rax",                         // save regs_ptr for post-exit

            // ── Set HOST_RSP = current RSP ──
            "vmwrite rcx, rsp",

            // ── Set HOST_RIP = VMEXIT return label ──
            // RIP after lea points to label 1f.  Adding the distance
            // (2f − 1f) gives the address of label 2f.
            "lea rbp, [rip + 9f - 8f]",
            "8:",
            "vmwrite rdx, rbp",

            // ── Load guest GPRs that are clobbered by our register use ──
            "mov rbx, [rax + {rbx_off}]",       // guest RBX
            "mov rcx, [rax + {rcx_off}]",       // guest RCX
            "mov rdx, [rax + {rdx_off}]",       // guest RDX
            "mov rbp, [rax + {rbp_off}]",       // guest RBP
            "mov rax, [rax + {rax_off}]",       // guest RAX (last — clobbers ptr)

            // ── Enter guest ──
            $enter_insn,

            // ── VMEXIT return point ──
            "9:",

            // ── Save guest GPRs that aren't covered by inout constraints ──
            // At this point: RAX=guest, RBX=guest, RBP=guest, RCX=guest, RDX=guest
            // RSI..R15 are captured by inout constraints.
            // The regs_ptr is on the stack (third push).
            "push rbx",                         // save guest RBX
            "mov rbx, [rsp + 8]",               // reload regs_ptr from stack
            "mov [rbx + {rbp_off}], rbp",       // save guest RBP
            "mov [rbx + {rax_off}], rax",       // save guest RAX
            "pop rbp",                          // pop guest RBX into RBP
            "mov [rbx + {rbx_off}], rbp",       // save guest RBX

            // ── Capture RFLAGS before any flag-modifying instruction ──
            // push/pop/mov do NOT modify flags, so CF/ZF from a failed
            // VMLAUNCH/VMRESUME are still intact here.
            "pushfq",
            "pop rax",                          // RAX = RFLAGS

            // ── Restore host callee-saved registers ──
            "pop rbx",                          // discard regs_ptr
            "pop rbp",                          // restore host RBP
            "pop rbx",                          // restore host RBX

            // ── Register constraints ──
            // IN:  regs_ptr / HOST_RSP field / HOST_RIP field
            // OUT: RFLAGS (via RAX) / guest RCX / guest RDX
            inout("rax") regs_ptr => flags_out,
            inout("rcx") host_rsp_field => $regs[Reg::Rcx as usize],
            inout("rdx") host_rip_field => $regs[Reg::Rdx as usize],

            // Guest RSI, RDI, R8–R15: loaded on entry, captured on exit.
            inout("rsi") $regs[Reg::Rsi as usize],
            inout("rdi") $regs[Reg::Rdi as usize],
            inout("r8")  $regs[Reg::R8  as usize],
            inout("r9")  $regs[Reg::R9  as usize],
            inout("r10") $regs[Reg::R10 as usize],
            inout("r11") $regs[Reg::R11 as usize],
            inout("r12") $regs[Reg::R12 as usize],
            inout("r13") $regs[Reg::R13 as usize],
            inout("r14") $regs[Reg::R14 as usize],
            inout("r15") $regs[Reg::R15 as usize],

            // Const offsets into the [u64; 16] register file.
            rax_off = const (Reg::Rax as usize) * 8,
            rbx_off = const (Reg::Rbx as usize) * 8,
            rcx_off = const (Reg::Rcx as usize) * 8,
            rdx_off = const (Reg::Rdx as usize) * 8,
            rbp_off = const (Reg::Rbp as usize) * 8,
        );

        // Check RFLAGS: CF (bit 0) = VmFailInvalid, ZF (bit 6) = VmFailValid.
        if flags_out & 1 != 0 {
            Err(VmxError::VmFailInvalid)
        } else if flags_out & 0x40 != 0 {
            Err(VmxError::VmFailValid)
        } else {
            Ok(())
        }
    }};
}

impl ActiveVcpu {
    unsafe fn vmlaunch_asm(regs: &mut [u64; REGFILE_SIZE]) -> Result<(), VmxError> {
        vm_enter_asm!(regs, "vmlaunch")
    }

    unsafe fn vmresume_asm(regs: &mut [u64; REGFILE_SIZE]) -> Result<(), VmxError> {
        vm_enter_asm!(regs, "vmresume")
    }
}
