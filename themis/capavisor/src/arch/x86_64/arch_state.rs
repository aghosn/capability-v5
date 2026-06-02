//! x86-64 architecture-specific state types.
//!
//! These opaque types encapsulate all x86-specific per-domain and
//! per-platform hardware state. Generic code (platform.rs, hypercall.rs)
//! imports them via `crate::arch::{ArchDomainState, ArchPlatformState}`
//! and interacts through methods — never touching internal fields.

extern crate alloc;
use alloc::vec::Vec;

use core::cell::UnsafeCell;

use capability_engine::CoreId;
use ept::EptMapper;

use crate::arch::x86_64::layout::{APIC_REG_ICR_HIGH, APIC_REG_ICR_LOW, LAPIC_MMIO_BASE};
use crate::arch_traits::ArchPlatform;
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
/// Wraps VMXON region addresses, VT-d DRHD units, and per-core LAPIC IDs.
/// Generic code accesses this through [`ArchPlatform`] (cross-arch contract)
/// and inherent methods (x86-only data such as DRHD units / VMXON regions).
pub struct ArchPlatformState {
    /// Per-core VMXON region physical addresses.
    vmxon_phys: Vec<u64>,
    /// VT-d DRHD units (IOMMU hardware units).
    drhd_units: Vec<DhrdUnit>,
    /// Per-core LAPIC IDs, indexed by logical core ID.
    ///
    /// Written once at boot (single-threaded, before APs come online) via
    /// [`set_lapic_ids`](Self::set_lapic_ids); read-only afterwards. The
    /// `UnsafeCell` lets us write without `&mut self` during the boot
    /// orchestrator's set-up sequence.
    lapic_ids: UnsafeCell<Vec<u32>>,
}

// SAFETY: `lapic_ids` is written exactly once during single-threaded boot
// (before APs are launched) and read-only afterwards. All other fields are
// already Sync.
unsafe impl Sync for ArchPlatformState {}

impl ArchPlatformState {
    pub fn new() -> Self {
        Self {
            vmxon_phys: Vec::new(),
            drhd_units: Vec::new(),
            lapic_ids: UnsafeCell::new(Vec::new()),
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

    /// Install the per-core LAPIC ID table. Called once by the BSP during
    /// boot, before APs are launched.
    pub fn set_lapic_ids(&self, ids: Vec<u32>) {
        // SAFETY: single-threaded boot context (see struct docs).
        unsafe { *self.lapic_ids.get() = ids };
    }

    /// Physical LAPIC ID of the BSP (core 0). Used as the IRTE destination
    /// for capavisor-owned vectors (Report / NotReport).
    pub fn bsp_lapic_id(&self) -> u32 {
        // SAFETY: read-only after boot (see struct docs).
        unsafe { &*self.lapic_ids.get() }
            .first()
            .copied()
            .unwrap_or(0)
    }
}

impl ArchPlatform for ArchPlatformState {
    fn send_ipi(&self, core_id: CoreId, hhdm_offset: u64) {
        // SAFETY: `lapic_ids` is read-only after boot.
        let lapic_id = unsafe {
            let ids = &*self.lapic_ids.get();
            *ids.get(core_id as usize)
                .unwrap_or_else(|| panic!("send_ipi: unknown core {}", core_id))
        };

        // INIT-IPI via xAPIC MMIO (the capavisor never enables x2APIC mode).
        // INIT always causes EXIT_REASON_INIT_SIGNAL (3) from non-root mode,
        // regardless of pin-based controls — exactly the wakeup semantics
        // we want here.
        let apic_base = hhdm_offset + LAPIC_MMIO_BASE;
        // SAFETY: HHDM-mapped LAPIC MMIO; capavisor owns it exclusively.
        unsafe {
            // ICR high: destination APIC ID in bits 24-31.
            let icr_hi = (apic_base + APIC_REG_ICR_HIGH) as *mut u32;
            core::ptr::write_volatile(icr_hi, lapic_id << 24);
            // ICR low: delivery=INIT (0x5<<8), level=assert (1<<14), edge.
            let icr_lo = (apic_base + APIC_REG_ICR_LOW) as *mut u32;
            core::ptr::write_volatile(icr_lo, (1u32 << 14) | (0x5u32 << 8));
        }
    }

    fn current_core_id(&self) -> Option<CoreId> {
        // CPUID.01h:EBX[31:24] = initial APIC ID. Works in both xAPIC and
        // x2APIC modes.
        let cpuid = core::arch::x86_64::__cpuid(1);
        let lapic_id = (cpuid.ebx >> 24) as u32;
        // SAFETY: read-only after boot.
        let ids = unsafe { &*self.lapic_ids.get() };
        ids.iter()
            .position(|&id| id == lapic_id)
            .map(|i| i as CoreId)
    }
}
