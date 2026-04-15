//! AArch64 architecture-specific state types.

extern crate alloc;
use alloc::vec::Vec;

// ── Per-domain hardware state ────────────────────────────────────────────── //

/// AArch64 per-domain hardware state.
///
/// Will eventually hold:
/// - Stage-2 translation table root (VTTBR_EL2 value)
/// - Per-VP saved EL1/EL0 register state
/// - SMMU stream table entries
pub struct ArchDomainState {
    _placeholder: u8,
}

impl ArchDomainState {
    pub fn new() -> Self {
        Self { _placeholder: 0 }
    }
}

// ── Per-platform hardware state ──────────────────────────────────────────── //

/// AArch64 platform-level hardware state.
///
/// Holds GICv3 addresses and per-CPU MPIDR values discovered at boot.
pub struct ArchPlatformState {
    /// GIC Distributor base address (GICD).
    pub gicd_base: u64,
    /// GIC Redistributor base address (GICR) — first CPU's region.
    pub gicr_base: u64,
    /// Per-CPU redistributor region stride (typically 0x20000 for GICv3).
    pub gicr_stride: u64,
    /// MPIDR values for each CPU, indexed by logical core ID.
    pub cpu_mpidrs: Vec<u64>,
}

impl ArchPlatformState {
    /// Create a default (uninitialized) platform state.
    pub fn new() -> Self {
        Self {
            gicd_base: 0,
            gicr_base: 0,
            gicr_stride: 0,
            cpu_mpidrs: Vec::new(),
        }
    }
}
