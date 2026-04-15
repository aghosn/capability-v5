//! AArch64 (ARMv8-A EL2) architecture backend.
//!
//! This module provides stub implementations of the arch-backend traits for
//! AArch64. It validates that the trait boundaries are correctly portable
//! without x86 assumptions.
//!
//! **Status**: M1 bringup — PL011 serial works. Trait methods still stubs.

pub mod aarch64_platform;
pub mod arch_state;
pub mod serial;

// Re-export arch-opaque types for uniform access via `crate::arch::*`.
pub use arch_state::{ArchDomainState, ArchPlatformState};
