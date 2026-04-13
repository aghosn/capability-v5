//! Architecture-specific backend selection.
//!
//! On x86-64, re-exports from `arch::x86_64`. A future ARM AArch64 port would
//! add `arch::aarch64` and conditionally select it here.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

// Re-export the active arch so callers can use `crate::arch::*`.
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;
