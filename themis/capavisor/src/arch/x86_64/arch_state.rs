//! x86-64 architecture-specific state types.
//!
//! These opaque types encapsulate all x86-specific per-domain and
//! per-platform hardware state. Generic code (platform.rs, hypercall.rs)
//! imports them via `crate::arch::{ArchDomainState, ArchPlatformState}`
//! and interacts through methods — never touching internal fields.

extern crate alloc;
use alloc::vec::Vec;

use ept::EptMapper;

use crate::platform::VcpuSlot;

use super::acpi::DhrdUnit;

// ── Per-domain hardware state ────────────────────────────────────────────── //

/// x86-64 per-domain hardware state.
///
/// Wraps EPT roots, IOMMU second-level page tables, VP slots (VMCS holders),
/// and page addresses for MSR/IO bitmaps and APIC virtualization.
/// Fields are private — accessed only through methods.
pub struct ArchDomainState {
    /// EPT root mapper, allocated lazily on first ChangeRights.
    ept: Option<EptMapper>,
    /// IOMMU second-level page table (VT-d SLPT, bit-compatible with EPT).
    iommu_pt: Option<EptMapper>,
    /// Per-VP slots holding InactiveVcpu when not running.
    vps: Vec<VcpuSlot>,
    /// MSR bitmap page physical address (allocated from META at seal time).
    msr_bitmap_phys: u64,
    /// I/O bitmap A (ports 0x0000–0x7FFF) physical address.
    io_bitmap_a_phys: u64,
    /// I/O bitmap B (ports 0x8000–0xFFFF) physical address.
    io_bitmap_b_phys: u64,
    /// APIC access page physical address (for VIRTUALIZE_APIC_ACCESSES).
    apic_access_phys: u64,
}

impl ArchDomainState {
    /// Create default (empty) arch state for a new domain.
    pub fn new() -> Self {
        Self {
            ept: None,
            iommu_pt: None,
            vps: Vec::new(),
            msr_bitmap_phys: 0,
            io_bitmap_a_phys: 0,
            io_bitmap_b_phys: 0,
            apic_access_phys: 0,
        }
    }

    // ── EPT accessors ────────────────────────────────────────────────────── //

    pub fn ept(&self) -> Option<&EptMapper> {
        self.ept.as_ref()
    }

    pub fn ept_mut(&mut self) -> Option<&mut EptMapper> {
        self.ept.as_mut()
    }

    pub fn take_ept(&mut self) -> Option<EptMapper> {
        self.ept.take()
    }

    /// Ensure EPT root exists, allocating from the given allocator if needed.
    pub fn ensure_ept(&mut self, alloc: &mut impl ept::FrameAllocator, hhdm_offset: u64) {
        if self.ept.is_none() {
            self.ept = Some(EptMapper::alloc_root(alloc, hhdm_offset));
        }
    }

    // ── IOMMU SLPT accessors ────────────────────────────────────────────── //

    pub fn iommu_pt(&self) -> Option<&EptMapper> {
        self.iommu_pt.as_ref()
    }

    pub fn iommu_pt_mut(&mut self) -> Option<&mut EptMapper> {
        self.iommu_pt.as_mut()
    }

    pub fn take_iommu_pt(&mut self) -> Option<EptMapper> {
        self.iommu_pt.take()
    }

    /// Ensure IOMMU SLPT root exists at the given level.
    pub fn ensure_iommu_pt(
        &mut self,
        level: ept::Level,
        alloc: &mut impl ept::FrameAllocator,
        hhdm_offset: u64,
    ) {
        if self.iommu_pt.is_none() {
            self.iommu_pt = Some(EptMapper::alloc_root_at_level(alloc, hhdm_offset, level));
        }
    }

    // ── VP slot accessors ────────────────────────────────────────────────── //

    pub fn vps(&self) -> &[VcpuSlot] {
        &self.vps
    }

    pub fn vps_mut(&mut self) -> &mut Vec<VcpuSlot> {
        &mut self.vps
    }

    // ── Bitmap / APIC accessors ──────────────────────────────────────────── //

    pub fn msr_bitmap_phys(&self) -> u64 {
        self.msr_bitmap_phys
    }

    pub fn set_msr_bitmap_phys(&mut self, phys: u64) {
        self.msr_bitmap_phys = phys;
    }

    pub fn io_bitmap_a_phys(&self) -> u64 {
        self.io_bitmap_a_phys
    }

    pub fn set_io_bitmap_a_phys(&mut self, phys: u64) {
        self.io_bitmap_a_phys = phys;
    }

    pub fn io_bitmap_b_phys(&self) -> u64 {
        self.io_bitmap_b_phys
    }

    pub fn set_io_bitmap_b_phys(&mut self, phys: u64) {
        self.io_bitmap_b_phys = phys;
    }

    pub fn apic_access_phys(&self) -> u64 {
        self.apic_access_phys
    }

    pub fn set_apic_access_phys(&mut self, phys: u64) {
        self.apic_access_phys = phys;
    }
}

// ── Per-platform hardware state ──────────────────────────────────────────── //

/// x86-64 platform-level hardware state.
///
/// Wraps VMXON region addresses and VT-d DRHD units.
/// Generic code accesses this through methods only.
pub struct ArchPlatformState {
    /// Per-core VMXON region physical addresses.
    vmxon_phys: Vec<u64>,
    /// VT-d DRHD units (IOMMU hardware units).
    drhd_units: Vec<DhrdUnit>,
}

impl ArchPlatformState {
    pub fn new() -> Self {
        Self {
            vmxon_phys: Vec::new(),
            drhd_units: Vec::new(),
        }
    }

    pub fn set_vmxon_phys(&mut self, phys: Vec<u64>) {
        self.vmxon_phys = phys;
    }

    pub fn vmxon_phys(&self, core_index: usize) -> u64 {
        self.vmxon_phys[core_index]
    }

    pub fn drhd_units(&self) -> &[DhrdUnit] {
        &self.drhd_units
    }

    pub fn drhd_units_mut(&mut self) -> &mut Vec<DhrdUnit> {
        &mut self.drhd_units
    }
}
