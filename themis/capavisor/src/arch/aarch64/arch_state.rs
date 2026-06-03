//! AArch64 architecture-specific state types.

extern crate alloc;
use alloc::vec::Vec;

use capability_engine::{CoreId, Rights};

use crate::arch_traits::{ArchDomain, ArchPlatform, ChangeRightsCtx};
use crate::mem::MetaAllocator;

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

impl ArchPlatform for ArchPlatformState {
    fn send_ipi(&self, _core_id: CoreId, _hhdm_offset: u64) {
        // TODO(arm): GICv3 SGI delivery.
        unimplemented!("send_ipi: aarch64 backend not yet implemented")
    }

    fn current_core_id(&self) -> Option<CoreId> {
        // TODO(arm): read MPIDR_EL1 + look up in cpu_mpidrs.
        unimplemented!("current_core_id: aarch64 backend not yet implemented")
    }
}

impl ArchDomain for ArchDomainState {
    fn change_rights(
        &mut self,
        _arch_plat: &ArchPlatformState,
        _gpa: u64,
        _hpa: u64,
        _size: usize,
        _rights: &Rights,
        _ctx: &mut ChangeRightsCtx<'_>,
    ) {
        // TODO(arm): Stage-2 + SMMU programming.
        unimplemented!("change_rights: aarch64 backend not yet implemented")
    }

    fn destroy(&mut self, _meta: &mut MetaAllocator, _root_meta: Option<&mut MetaAllocator>) {
        // TODO(arm): free Stage-2 + SMMU page-tables.
        unimplemented!("destroy: aarch64 backend not yet implemented")
    }
}
