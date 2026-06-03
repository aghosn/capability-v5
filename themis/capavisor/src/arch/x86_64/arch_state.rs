//! x86-64 architecture-specific state types.
//!
//! These opaque types encapsulate all x86-specific per-domain and
//! per-platform hardware state. Generic code (platform.rs, hypercall.rs)
//! imports them via `crate::arch::{ArchDomainState, ArchPlatformState}`
//! and interacts through methods — never touching internal fields.

extern crate alloc;
use alloc::vec::Vec;

use core::cell::UnsafeCell;

use capability_engine::{CoreId, Rights};
use ept::{EptEntryFlags, EptMapper, EptMemoryType, Level};

use crate::arch::x86_64::layout::{APIC_REG_ICR_HIGH, APIC_REG_ICR_LOW, LAPIC_MMIO_BASE, MMIO_PAGE_SIZE};
use crate::arch_traits::{ArchDomain, ArchPlatform, ChangeRightsCtx};
use crate::mem::{MetaAllocator, UncacheableRanges};
use crate::platform::vcpu_slot::VcpuSlot;
use crate::serial_println;

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

    // ── VP slot accessors ────────────────────────────────────────────────── //

    pub fn vps(&self) -> &[VcpuSlot] {
        &self.vps
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

    /// Return the [`Level`] to use for IOMMU second-level page tables.
    ///
    /// Derived from the minimum AW (adjusted guest-address width) across all
    /// DRHD units: AW=1 → `Level::L3` (39-bit), AW=2 → `Level::L4` (48-bit).
    /// Falls back to `Level::L3` if no DRHD units are present.
    pub fn iommu_pt_level(&self) -> Level {
        let min_aw = self
            .drhd_units
            .iter()
            .filter(|u| u.aw > 0)
            .map(|u| u.aw)
            .min()
            .unwrap_or(1);
        if min_aw >= 2 {
            Level::L4
        } else {
            Level::L3
        }
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

// ── ArchDomain impl (per-domain second-stage / IOMMU operations) ────────── //

impl ArchDomain for ArchDomainState {
    fn change_rights(
        &mut self,
        arch_plat: &ArchPlatformState,
        gpa: u64,
        hpa: u64,
        size: usize,
        rights: &Rights,
        ctx: &mut ChangeRightsCtx<'_>,
    ) {
        // LAPIC MMIO mapping in a child domain: record the HPA so ADD_VP can
        // set APIC_ACCESS_ADDR in the child VMCS, enabling
        // VIRTUALIZE_APIC_ACCESSES instead of forwarding EPT violations.
        if ctx.is_child && gpa == LAPIC_MMIO_BASE && size as u64 == MMIO_PAGE_SIZE {
            self.set_apic_access_phys(hpa);

            // When hardware does not support VIRTUALIZE_APIC_ACCESSES (bit 0
            // of IA32_VMX_PROCBASED_CTLS2 allowed-1 field), skip the EPT
            // mapping so LAPIC MMIO accesses cause EPT violations forwarded
            // to CHV for emulation.
            let secondary_msr = unsafe { x86::msr::rdmsr(x86::msr::IA32_VMX_PROCBASED_CTLS2) };
            let virt_apic_supported = ((secondary_msr >> 32) & 1) != 0;
            if !virt_apic_supported {
                serial_println!(
                    "[APIC] VIRTUALIZE_APIC_ACCESSES not supported — \
                     skipping EPT map for {:#x} (LAPIC via EPT violations)",
                    gpa
                );
                return;
            }
        }

        if rights.bits() == 0 {
            // Unmap.
            if let Some(ept) = self.ept.as_mut() {
                ept.unmap_range(ctx.meta, gpa, size);
            }
            if ctx.is_child {
                if let (Some(slpt), Some(root_meta)) =
                    (self.iommu_pt.as_mut(), ctx.root_meta.as_deref_mut())
                {
                    slpt.unmap_range(root_meta, gpa, size);
                }
            }
        } else {
            // Map. Lazily allocate EPT and SLPT roots.
            if self.ept.is_none() {
                self.ept = Some(EptMapper::alloc_root(ctx.meta, ctx.hhdm_offset));
            }
            if ctx.is_child && self.iommu_pt.is_none() {
                let level = arch_plat.iommu_pt_level();
                let root_meta = ctx
                    .root_meta
                    .as_deref_mut()
                    .expect("ChangeRights on child requires root_meta for IOMMU SLPT");
                self.iommu_pt =
                    Some(EptMapper::alloc_root_at_level(root_meta, ctx.hhdm_offset, level));
            }

            let flags = rights_to_ept_flags(rights);
            let ept = self.ept.as_mut().unwrap();
            map_range_typed(ept, ctx.meta, gpa, hpa, size, flags, ctx.uc_ranges);
            if ctx.is_child {
                if let (Some(slpt), Some(root_meta)) =
                    (self.iommu_pt.as_mut(), ctx.root_meta.as_deref_mut())
                {
                    // VT-d SLPT: same GPA→HPA mapping; no memory-type bits needed.
                    slpt.map_range(root_meta, gpa, hpa, size, flags, EptMemoryType::WB);
                }
            }
        }
    }

    fn destroy(&mut self, meta: &mut MetaAllocator, root_meta: Option<&mut MetaAllocator>) {
        if let Some(ept) = self.ept.take() {
            ept.free_all(meta);
        }
        if let Some(slpt) = self.iommu_pt.take() {
            // SLPT pages were allocated from root's META; return them there.
            let root_meta = root_meta.expect("destroy(): child domain requires root_meta");
            slpt.free_all(root_meta);
        }
    }

    fn slat(&self) -> Option<u64> {
        self.ept.as_ref().map(|e| e.eptp())
    }

    fn flush_tlb(&self) {
        if let Some(ept) = self.ept.as_ref() {
            unsafe {
                crate::vmx::invept(crate::vmx::INVEPT_SINGLE_CONTEXT, ept.eptp());
            }
        }
    }

    type InactiveVp = crate::vcpu::InactiveVcpu;

    fn store_inactive_vp(&mut self, vp_id: usize, vcpu: Self::InactiveVp) {
        if self.vps.len() <= vp_id {
            self.vps.resize_with(vp_id + 1, VcpuSlot::empty);
        }
        self.vps[vp_id].put(vcpu);
    }

    fn take_inactive_vp(&self, vp_id: usize) -> Option<Self::InactiveVp> {
        self.vps.get(vp_id).and_then(|slot| slot.take())
    }

    fn return_inactive_vp(&mut self, vp_id: usize, vcpu: Self::InactiveVp) {
        assert!(
            vp_id < self.vps.len(),
            "return_inactive_vp: vp_id {} out of range (vps.len() = {})",
            vp_id,
            self.vps.len()
        );
        self.vps[vp_id].put(vcpu);
    }
}

/// Apply an INVEPT(single-context) on the *current* CPU using a previously
/// snapshotted EPTP handle.  Handle must come from
/// [`ArchDomain::slat`] (or zero, in which case this is a no-op).
///
/// Used by the cross-core `TlbShootdown` handler so the receiver can flush
/// without holding any reference to the originating (possibly-revoked)
/// `PlatformDomain`.
pub fn flush_tlb_handle(handle: u64) {
    if handle != 0 {
        unsafe {
            crate::vmx::invept(crate::vmx::INVEPT_SINGLE_CONTEXT, handle);
        }
    }
}

// ── Private EPT helpers (formerly platform/helpers.rs) ──────────────────── //

/// Map `[gpa, gpa+size)` → `[hpa, hpa+size)` into `ept`, splitting the range
/// at UC boundaries so that MMIO sub-ranges use [`EptMemoryType::UC`] and all
/// other sub-ranges use [`EptMemoryType::WB`].
fn map_range_typed(
    ept: &mut EptMapper,
    meta: &mut MetaAllocator,
    gpa: u64,
    hpa: u64,
    size: usize,
    flags: EptEntryFlags,
    uc_ranges: &UncacheableRanges,
) {
    let mut cur_gpa = gpa;
    let mut cur_hpa = hpa;
    let mut remaining = size;

    while remaining > 0 {
        match uc_ranges.first_overlap(cur_hpa, remaining as u64) {
            None => {
                ept.map_range(meta, cur_gpa, cur_hpa, remaining, flags, EptMemoryType::WB);
                return;
            }
            Some((ov_start, ov_end)) => {
                if ov_start > cur_hpa {
                    let wb_size = (ov_start - cur_hpa) as usize;
                    ept.map_range(meta, cur_gpa, cur_hpa, wb_size, flags, EptMemoryType::WB);
                    cur_gpa += wb_size as u64;
                    cur_hpa += wb_size as u64;
                    remaining -= wb_size;
                }
                let uc_size = ((ov_end - cur_hpa) as usize).min(remaining);
                ept.map_range(meta, cur_gpa, cur_hpa, uc_size, flags, EptMemoryType::UC);
                cur_gpa += uc_size as u64;
                cur_hpa += uc_size as u64;
                remaining -= uc_size;
            }
        }
    }
}

/// Convert capability-engine `Rights` to EPT entry permission flags.
fn rights_to_ept_flags(rights: &Rights) -> EptEntryFlags {
    let mut flags = EptEntryFlags::empty();
    if rights.read() {
        flags |= EptEntryFlags::READ;
    }
    if rights.write() {
        flags |= EptEntryFlags::WRITE;
    }
    if rights.execute() {
        flags |= EptEntryFlags::SUPERVISOR_EXECUTE | EptEntryFlags::USER_EXECUTE;
    }
    flags
}
