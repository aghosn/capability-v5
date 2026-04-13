//! Platform-agnostic trait definitions and shared types for the capavisor.
//!
//! This module defines the arch-backend traits and shared types that allow
//! the capavisor's policy logic (domain lifecycle, hypercall dispatch,
//! capability-engine integration) to be independent of the underlying ISA.
//!
//! Architecture-specific implementations live under `crate::arch::`.

pub mod traits;
pub mod types;
