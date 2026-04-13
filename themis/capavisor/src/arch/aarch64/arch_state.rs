//! AArch64 architecture-specific state types (stubs).
//!
//! Mirrors the API of `arch::x86_64::arch_state` with empty implementations.
//! A real port would hold Stage-2 page table state, GIC config, etc.

extern crate alloc;
use alloc::vec::Vec;

// ── Per-domain hardware state ────────────────────────────────────────────── //

/// AArch64 per-domain hardware state (stub).
///
/// A real implementation would hold:
/// - Stage-2 translation table root (VTTBR_EL2 value)
/// - SMMU stream table entries
/// - Per-VP saved EL1/EL0 register state
pub struct ArchDomainState {
    /// Per-VP COMM HPAs (placeholder, matching x86 layout).
    _placeholder: u8,
}

impl ArchDomainState {
    pub fn new() -> Self {
        Self { _placeholder: 0 }
    }
}

// ── Per-platform hardware state ──────────────────────────────────────────── //

/// AArch64 platform-level hardware state (stub).
///
/// A real implementation would hold:
/// - GICv3 distributor/redistributor base addresses
/// - SMMU base address and stream table
/// - Device tree or ACPI table references
pub struct ArchPlatformState {
    _placeholder: u8,
}

impl ArchPlatformState {
    pub fn new() -> Self {
        Self { _placeholder: 0 }
    }
}
