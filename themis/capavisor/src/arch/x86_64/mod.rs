//! x86-64 (Intel VT-x) architecture backend.
//!
//! This module contains all x86-specific code: VMCS management, VMX exit
//! handling, GDT/TSS, MSR virtualization, ACPI/PCI firmware parsing, VT-d
//! IOMMU, and the boot sequence (VMXON, bzImage loading).

pub mod acpi;
pub mod boot;
pub mod gdt;
pub mod iommu_ir;
pub mod msr_virt;
pub mod pci;
pub mod vmcs;
pub mod vmexit;
pub mod x86_platform;
