//! VMCS allocation and setup — Phase P2d.
//!
//! One VMCS page is set up per VP (one per physical core for dom0).
//! After `setup_vmcs_for_vp` returns, the VMCS is loaded (VMPTRLD) and
//! all fields are written.  The caller can then execute VMLAUNCH.
//!
//! # Layout
//!
//! - Host state  : captured from the current CPU (CR0/CR3/CR4, segments, EFER,
//!                 GDTR/IDTR base, TR base).  Host RSP → per-VP stack top.
//!                 Host RIP → `host_rip_stub` (overwritten by `ActiveVcpu::run()`).
//! - Guest state : protected mode stub (UNRESTRICTED_GUEST, no paging, PE only).
//!                 RIP/RSP/CR3 left at 0; will be overwritten at P7f with Linux
//!                 boot parameters.
//! - Controls    : EPT + VPID + UNRESTRICTED_GUEST; intercept VMCALL (always),
//!                 CPUID (always), NMI, external interrupts, CR0/CR4 changes.
//!
//! # Submodules
//!
//! - [`controls`] — pin/proc/exit/entry control fields, EPTP/VPID, bitmaps,
//!   posted-interrupt fields.
//! - [`host`]     — host segment selectors, control registers, MSRs, RIP/RSP.
//! - [`guest`]    — guest state stub (segments, CR0/CR3/CR4, EFER/PAT, etc.).

use x86::bits64::vmx;
use x86::controlregs::{Cr0, Cr4};
use x86::msr;

use crate::serial_println;

mod controls;
mod guest;
mod host;

// ── VMCS constraint helpers (public — used by hypercall.rs apply_vmcs_reg) ── //

/// Return the CR0 bits that must always be 1 in the guest VMCS field.
///
/// IA32_VMX_CR0_FIXED0 lists bits that VMX non-root operation requires.
/// UNRESTRICTED_GUEST exempts PE (bit 0) and PG (bit 31), so we exclude them.
/// The remaining mandatory bits (typically ET=4, NE=5) must be set in
/// guest::CR0 before VMLAUNCH or the VMCS consistency check fails (exit 33).
pub unsafe fn cr0_required_bits() -> u64 {
    let fixed0 = msr::rdmsr(msr::IA32_VMX_CR0_FIXED0);
    let exempt = (Cr0::CR0_PROTECTED_MODE | Cr0::CR0_ENABLE_PAGING).bits() as u64;
    fixed0 & !exempt
}

/// Adjust a guest CR0 value so it satisfies IA32_VMX_CR0_FIXED0.
///
/// OR in the required bits (typically ET=bit4, NE=bit5); other bits are
/// left as requested.  PE/PG are exempted and not forced.
pub unsafe fn vmcs_adjust_cr0(val: u64) -> u64 {
    val | cr0_required_bits()
}

/// Adjust a guest CR4 value so it satisfies IA32_VMX_CR4_FIXED0.
///
/// CR4.VMXE (bit 13) is required on all Intel VMX-capable CPUs.
/// The CR4 guest/host mask owns this bit, so the guest never clears it,
/// but the VMCS field must have it set for the consistency check.
pub fn vmcs_adjust_cr4(val: u64) -> u64 {
    val | Cr4::CR4_ENABLE_VMX.bits() as u64
}

// ── Posted Interrupt constants ───────────────────────────────────────────── //

/// Notification vector used for Posted Interrupt IPIs.
///
/// When a VP running on another core has a posted interrupt delivered, the
/// capavisor sends an IPI with this vector. Hardware then moves PIR → vIRR on
/// the receiving core without a VM exit.
///
/// 0xF2 is chosen to avoid conflicts with Linux's per-CPU IPI vectors
/// (0xF0=RESCHEDULE, 0xF1=CALL_FUNCTION_SINGLE, 0xFF=LOCAL_TIMER in common
/// kernels). Validated at capavisor init against the running kernel's IDT.
pub const POSTED_INTR_NOTIFY_VEC: u8 = 0xF2;

// ── VMCS setup ────────────────────────────────────────────────────────────── //

/// Set up the VMCS for VP `vp_index` of dom0.
///
/// # Arguments
/// * `vmcs_phys`  — physical address of the (already-initialised) VMCS page
/// * `vapic_phys` — physical address of the VAPIC page for this VP
/// * `eptp`       — EPT pointer value from `EptMapper::eptp()`
/// * `vp_index`   — VP index (0-based; VPID written as vp_index + 1)
///
/// HOST_RSP is set to 0 here (placeholder).  `ActiveVcpu::run()` overwrites it
/// with the caller's RSP before every VMLAUNCH/VMRESUME.
///
/// # Safety
/// VMXON must already be active on this core.
pub unsafe fn setup_vmcs_for_vp(
    vmcs_phys: u64,
    vapic_phys: u64,
    msr_bitmap_phys: u64,
    eptp: u64,
    vp_index: usize,
) {
    vmx::vmclear(vmcs_phys).expect("vmclear failed");
    vmx::vmptrld(vmcs_phys).expect("vmptrld failed");

    // dom0 keeps its xAPIC MMIO EPT passthrough — no APIC access page.
    controls::write_control_fields(
        eptp,
        vapic_phys,
        msr_bitmap_phys,
        0,
        0,
        0,
        0,
        (vp_index + 1) as u16,
        false,
    );
    host::write_host_state();
    guest::write_guest_state();

    serial_println!(
        "  VMCS VP{}: phys={:#x} VAPIC={:#x} EPTP={:#x} VPID={}",
        vp_index,
        vmcs_phys,
        vapic_phys,
        eptp,
        vp_index + 1,
    );
}

/// Set up a child domain's VMCS with intercept-heavy controls.
///
/// Differs from dom0 VMCS setup:
/// - EXTERNAL_INTERRUPT_EXITING: external interrupts cause VMEXIT to parent
/// - HLT_EXITING: HLT causes VMEXIT to parent
/// - Guest state is left at zeroes (parent populates via COMM page)
///
/// # Safety
/// VMXON must already be active on this core. Clobbers current VMPTRLD.
pub unsafe fn setup_child_vmcs(
    vmcs_phys: u64,
    vapic_phys: u64,
    msr_bitmap_phys: u64,
    pid_phys: u64,
    apic_access_phys: u64,
    io_bitmap_a_phys: u64,
    io_bitmap_b_phys: u64,
    eptp: u64,
    vpid: u16,
) {
    vmx::vmclear(vmcs_phys).expect("child vmclear failed");
    vmx::vmptrld(vmcs_phys).expect("child vmptrld failed");

    controls::write_control_fields(
        eptp,
        vapic_phys,
        msr_bitmap_phys,
        pid_phys,
        apic_access_phys,
        io_bitmap_a_phys,
        io_bitmap_b_phys,
        vpid,
        true,
    );
    host::write_host_state();
    guest::write_guest_state();

    serial_println!(
        "  child VMCS: phys={:#x} VAPIC={:#x} PID={:#x} APIC_ACC={:#x} EPTP={:#x} VPID={}",
        vmcs_phys,
        vapic_phys,
        pid_phys,
        apic_access_phys,
        eptp,
        vpid,
    );
}
