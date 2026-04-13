//! Architecture-specific backend selection.
//!
//! On x86-64, re-exports from `arch::x86_64`. On AArch64, from `arch::aarch64`.
//! The active arch is selected at compile time via `cfg(target_arch)`.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

// Re-export the active arch so callers can use `crate::arch::*`.
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
pub use aarch64::*;
