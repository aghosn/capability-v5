//! VMX MSR VM-entry load / VM-exit store lists (SDM Vol 3C §26.4 & §27.4).
//!
//! Hardware fast-path for the per-VP MSR state the VMCS does *not*
//! auto-manage (STAR/LSTAR/CSTAR/FMASK/KERNEL_GS_BASE/TSC_AUX).
//!
//! Both `VMENTRY_MSR_LOAD` and `VMEXIT_MSR_STORE` point at the SAME page
//! per VMCS: on VMEXIT hardware captures the guest's last value into a
//! slot; on the next VMENTRY it restores it. No software save/restore
//! and no MSR-bitmap intercepts needed — the guest owns those MSRs for
//! as long as its VMCS is loaded, and each VMCS has its own list page
//! so switching between VMCSes is automatic.

/// One entry, 16 bytes (SDM Vol 3C §26.4.1).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
struct Entry {
    index: u32,
    reserved: u32,
    data: u64,
}

const _SIZE_CHECK: () = assert!(core::mem::size_of::<Entry>() == 16);

/// MSRs installed by `init` for every guest VMCS.
///
/// Single source of truth: capavisor never uses these MSRs itself
/// (no SYSCALL from ring 0, no SWAPGS, no RDTSCP), so per-VP state
/// is safe to leave in the physical MSRs between VMEXIT and the next
/// VMENTRY without a host-load list.
pub const SYSCALL_MSRS: &[u32] = &[
    0xC000_0081, // IA32_STAR
    0xC000_0082, // IA32_LSTAR
    0xC000_0083, // IA32_CSTAR
    0xC000_0084, // IA32_FMASK
    0xC000_0102, // IA32_KERNEL_GS_BASE
    0xC000_0103, // IA32_TSC_AUX
];

/// Initialise a freshly-allocated 4 KiB META page with the `SYSCALL_MSRS`
/// entries and return the entry count for the VMCS COUNT fields.
///
/// # Safety
/// `list_phys` must reference a live 4 KiB META frame mapped in the HHDM
/// and not concurrently loaded via any VMCS.
pub unsafe fn init(list_phys: u64, hhdm: u64) -> u32 {
    let entries = core::slice::from_raw_parts_mut(
        (list_phys + hhdm) as *mut Entry,
        SYSCALL_MSRS.len(),
    );
    for (slot, &msr) in entries.iter_mut().zip(SYSCALL_MSRS.iter()) {
        *slot = Entry { index: msr, reserved: 0, data: 0 };
    }
    SYSCALL_MSRS.len() as u32
}
