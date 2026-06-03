//! Platform-agnostic trait definitions and shared types for the capavisor.
//!
//! This module defines the arch-backend traits and shared types that allow
//! the capavisor's policy logic (domain lifecycle, hypercall dispatch,
//! capability-engine integration) to be independent of the underlying ISA.
//!
//! Architecture-specific implementations live under `crate::arch::`.
//!
//! Many types and trait methods here define the API boundary for future
//! arch backends (e.g., ARM AArch64) and are not yet fully wired.

pub mod domain;
pub mod platform;
pub mod traits;
pub mod types;

pub use domain::{ArchDomain, ChangeRightsCtx};
pub use platform::ArchPlatform;
