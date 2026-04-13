//! AArch64 (ARMv8-A EL2) architecture backend.
//!
//! This module provides stub implementations of the arch-backend traits for
//! AArch64. It validates that the trait boundaries are correctly portable
//! without x86 assumptions.
//!
//! **Status**: Skeleton — all methods panic with `unimplemented!()`.
//! A real implementation would use EL2 trap handling (vbar_el2),
//! Stage-2 translation tables (VTTBR_EL2), and GICv3 for interrupts.

pub mod aarch64_platform;
pub mod arch_state;

// Re-export arch-opaque types for uniform access via `crate::arch::*`.
pub use arch_state::{ArchDomainState, ArchPlatformState};
