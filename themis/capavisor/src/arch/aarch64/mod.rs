//! AArch64 (ARMv8-A EL2) architecture backend.
//!
//! **Status**: M2 — memory partitioning + ThemisPlatform init on QEMU aarch64.
//! VP lifecycle traits still stubs.

pub mod aarch64_platform;
pub mod arch_state;
pub mod boot;
pub mod boot_descriptor;
pub mod el2_regs;
pub mod fdt_patch;
pub mod gicv3;
pub mod mmu;
pub mod paging;
pub mod serial;
pub mod stage2;
pub mod vcpu;
pub mod vectors;

// Re-export arch-opaque types for uniform access via `crate::arch::*`.
pub use arch_state::{complete_revoke_switch, flush_tlb_handle, ArchDomainState, ArchPlatformState};

// IOMMU device-assignment stubs (no SMMU yet).
#[allow(unused_variables)]
pub fn assign_device(_p: &crate::platform::ThemisPlatform, bdf: u16, domain_id: capability_engine::DomainId) {}
#[allow(unused_variables)]
pub fn release_device(_p: &crate::platform::ThemisPlatform, bdf: u16) {}

// IOMMU interrupt-remapping stubs (VT-d only on x86; SMMU MSI-translation TBD).
#[allow(unused_variables)]
pub fn program_domain_irtes(
    _p: &crate::platform::ThemisPlatform,
    child_id: capability_engine::DomainId,
    intr_policy: &capability_engine::InterruptPolicy,
) {
}
#[allow(unused_variables)]
pub fn invalidate_domain_irtes(_p: &crate::platform::ThemisPlatform, domain_id: capability_engine::DomainId) {}
