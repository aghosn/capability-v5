//! x86-64 (Intel VT-x) architecture backend.
//!
//! This module contains all x86-specific code: VMCS management, VMX exit
//! handling, GDT/TSS, MSR virtualization, ACPI/PCI firmware parsing, VT-d
//! IOMMU, and the boot sequence (VMXON, bzImage loading).

pub mod acpi;
pub mod apic;
pub mod arch_state;
pub mod boot;
pub mod gdt;
pub mod iommu_ir;
pub mod iommu_dev;
pub mod layout;
pub mod msr_bitmap;
pub mod msr_emulator;
pub mod page_walk;
pub mod paging;
pub mod pci;
pub mod pid;
pub mod reg_apply;
pub mod vcpu_ext;
pub mod vcpu_switch;
pub mod vmcs;
pub mod vmexit;
pub mod vmexit_decode;
pub mod x86_platform;
pub mod hypercall;

// Re-export arch-opaque types for uniform access via `crate::arch::*`.
pub use arch_state::{flush_tlb_handle, ArchDomainState, ArchPlatformState};
pub use iommu_dev::{assign_device, release_device};
pub use iommu_ir::{invalidate_domain_irtes, program_domain_irtes};
pub(crate) use vcpu_switch::complete_revoke_switch;
