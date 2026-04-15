//! AArch64 (ARMv8-A EL2) architecture backend.
//!
//! **Status**: M2 — memory partitioning + ThemisPlatform init on QEMU aarch64.
//! VP lifecycle traits still stubs.

pub mod aarch64_platform;
pub mod arch_state;
pub mod boot;
pub mod serial;

// Re-export arch-opaque types for uniform access via `crate::arch::*`.
pub use arch_state::{ArchDomainState, ArchPlatformState};
