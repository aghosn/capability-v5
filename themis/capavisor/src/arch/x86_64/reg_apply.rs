//! `VpRegister` → VMX backing translation and apply.
//!
//! Bridges the arch-independent `themis_abi::regs::VpRegister` enum (the
//! Application Binary Interface (ABI) surface exposed to monitors via
//! `GET_REG`/`SET_REG` and the dirty-COMM register-staging path) to the
//! underlying VMX storage:
//!
//!  - General-Purpose Registers (GPRs) live in the software register file
//!    on `ActiveVcpu` (`set_reg`/`get_reg`).
//!  - System registers live in Virtual Machine Control Structure (VMCS)
//!    guest-state fields; some require hardware-mandated fix-ups (CR0/CR4
//!    reserved bits, Local Descriptor Table Register (LDTR) null Access-
//!    Rights (AR), Extended Feature Enable Register (EFER) Long-Mode-
//!    Active (LMA) → `VMENTRY_CONTROLS.IA32E_MODE_GUEST` mirror).
//!
//! All public entry points are `pub(crate)` because they are consumed by
//! the hypercall layer and the VMCS bring-up code; nothing outside the
//! crate should be touching raw VMCS fields by name.

use themis_abi::regs::VpRegister;
use x86::vmx::vmcs::guest;

use crate::arch::x86_64::vcpu_ext::ActiveVcpuExt;
use crate::vcpu::{ActiveVcpu, Reg};

/// Map a `VpRegister` to a VMCS guest-state field encoding.
/// Returns `None` for GPRs and registers without a direct VMCS backing.
pub(crate) fn vp_reg_to_vmcs_field(reg: VpRegister) -> Option<u32> {
    Some(match reg {
        VpRegister::Rsp => guest::RSP,
        VpRegister::Rip => guest::RIP,
        VpRegister::Rflags => guest::RFLAGS,
        VpRegister::Cr0 => guest::CR0,
        VpRegister::Cr3 => guest::CR3,
        VpRegister::Cr4 => guest::CR4,
        VpRegister::Efer => guest::IA32_EFER_FULL,
        VpRegister::Dr7 => guest::DR7,
        VpRegister::CsSelector => guest::CS_SELECTOR,
        VpRegister::DsSelector => guest::DS_SELECTOR,
        VpRegister::EsSelector => guest::ES_SELECTOR,
        VpRegister::FsSelector => guest::FS_SELECTOR,
        VpRegister::GsSelector => guest::GS_SELECTOR,
        VpRegister::SsSelector => guest::SS_SELECTOR,
        VpRegister::TrSelector => guest::TR_SELECTOR,
        VpRegister::LdtrSelector => guest::LDTR_SELECTOR,
        VpRegister::CsBase => guest::CS_BASE,
        VpRegister::DsBase => guest::DS_BASE,
        VpRegister::EsBase => guest::ES_BASE,
        VpRegister::FsBase => guest::FS_BASE,
        VpRegister::GsBase => guest::GS_BASE,
        VpRegister::SsBase => guest::SS_BASE,
        VpRegister::TrBase => guest::TR_BASE,
        VpRegister::LdtrBase => guest::LDTR_BASE,
        VpRegister::CsLimit => guest::CS_LIMIT,
        VpRegister::DsLimit => guest::DS_LIMIT,
        VpRegister::EsLimit => guest::ES_LIMIT,
        VpRegister::FsLimit => guest::FS_LIMIT,
        VpRegister::GsLimit => guest::GS_LIMIT,
        VpRegister::SsLimit => guest::SS_LIMIT,
        VpRegister::TrLimit => guest::TR_LIMIT,
        VpRegister::LdtrLimit => guest::LDTR_LIMIT,
        VpRegister::CsAccessRights => guest::CS_ACCESS_RIGHTS,
        VpRegister::DsAccessRights => guest::DS_ACCESS_RIGHTS,
        VpRegister::EsAccessRights => guest::ES_ACCESS_RIGHTS,
        VpRegister::FsAccessRights => guest::FS_ACCESS_RIGHTS,
        VpRegister::GsAccessRights => guest::GS_ACCESS_RIGHTS,
        VpRegister::SsAccessRights => guest::SS_ACCESS_RIGHTS,
        VpRegister::TrAccessRights => guest::TR_ACCESS_RIGHTS,
        VpRegister::LdtrAccessRights => guest::LDTR_ACCESS_RIGHTS,
        VpRegister::GdtrBase => guest::GDTR_BASE,
        VpRegister::GdtrLimit => guest::GDTR_LIMIT,
        VpRegister::IdtrBase => guest::IDTR_BASE,
        VpRegister::IdtrLimit => guest::IDTR_LIMIT,
        VpRegister::SysenterCs => guest::IA32_SYSENTER_CS,
        VpRegister::SysenterEsp => guest::IA32_SYSENTER_ESP,
        VpRegister::SysenterEip => guest::IA32_SYSENTER_EIP,
        VpRegister::FsBaseMsr => guest::FS_BASE,
        VpRegister::GsBaseMsr => guest::GS_BASE,
        VpRegister::ActivityState => guest::ACTIVITY_STATE,
        VpRegister::InterruptibilityState => guest::INTERRUPTIBILITY_STATE,
        VpRegister::Pat => guest::IA32_PAT_FULL,
        // No VMCS mapping.
        _ => return None,
    })
}

/// Map a `VpRegister` to a GPR index (`Reg`).
/// Returns `None` for non-GPR registers.
pub(crate) fn vp_reg_to_gpr(reg: VpRegister) -> Option<Reg> {
    Some(match reg {
        VpRegister::Rax => Reg::Rax,
        VpRegister::Rbx => Reg::Rbx,
        VpRegister::Rcx => Reg::Rcx,
        VpRegister::Rdx => Reg::Rdx,
        VpRegister::Rsi => Reg::Rsi,
        VpRegister::Rdi => Reg::Rdi,
        VpRegister::Rbp => Reg::Rbp,
        VpRegister::R8 => Reg::R8,
        VpRegister::R9 => Reg::R9,
        VpRegister::R10 => Reg::R10,
        VpRegister::R11 => Reg::R11,
        VpRegister::R12 => Reg::R12,
        VpRegister::R13 => Reg::R13,
        VpRegister::R14 => Reg::R14,
        VpRegister::R15 => Reg::R15,
        _ => return None,
    })
}

/// Apply a pending register value to a currently-active VCPU.
///
/// Dispatches by register kind:
///  - GPRs go to the software register file via `ActiveVcpu::set_reg`.
///  - VMCS-backed fields go through [`apply_vmcs_reg`], which handles
///    CR0/CR4 reserved-bit adjustment, the LDTR null-AR fix-up, and the
///    EFER.LMA → `VMENTRY_CONTROLS.IA32E_MODE_GUEST` mirror.
pub(crate) fn apply_pending_reg(vcpu: &mut ActiveVcpu, reg: VpRegister, val: u64) {
    if let Some(gpr) = vp_reg_to_gpr(reg) {
        vcpu.set_reg(gpr, val);
    } else {
        apply_vmcs_reg(vcpu, reg, val);
    }
}

/// Apply a VMCS-field register to an active VCPU via `ActiveVcpu::set()`.
pub(crate) fn apply_vmcs_reg(vcpu: &mut ActiveVcpu, reg: VpRegister, val: u64) {
    let adjusted = match reg {
        VpRegister::Cr0 => unsafe { crate::arch::vmcs::vmcs_adjust_cr0(val) },
        VpRegister::Cr4 => crate::arch::vmcs::vmcs_adjust_cr4(val),
        // VMCS LDTR AR: if usable (bit 16=0), type must be 2 (LDT).
        // KVM/CHV represents a null LDTR as AR=0 (usable + type=0), which
        // violates SDM 26.3.1.2. Force to unusable.
        VpRegister::LdtrAccessRights => {
            if val & 0x10000 == 0 && (val & 0xf) != 2 {
                0x10000
            } else {
                val
            }
        }
        _ => val,
    };
    if let Some(field) = vp_reg_to_vmcs_field(reg) {
        vcpu.set(field, adjusted);
    }
    // VMENTRY_CONTROLS.IA32E_MODE_GUEST (bit 9) must track EFER.LMA (bit 10).
    // Without this, writing EFER.LMA=1 via the dirty-COMM path leaves the VM
    // in 32-bit compatibility mode on re-entry → 64-bit code decoded as 32-bit
    // → triple fault.
    if reg == VpRegister::Efer {
        vcpu.set_long_mode_guest((val >> 10) & 1 == 1);
    }
}
