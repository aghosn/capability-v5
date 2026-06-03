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
pub use arch_state::{flush_tlb_handle, ArchDomainState, ArchPlatformState};
