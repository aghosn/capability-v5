//! Boot phase functions.
//!
//! `_start()` in `main.rs` is the orchestrator; the logic for each phase lives
//! here so the entry point stays readable.
//!
//! Phase flow (each phase is its own submodule):
//!   [`platform`]     → [`PlatformInfo`]   (memory, SMP, ACPI, PCI)
//!   [`themis`]       → `ThemisPlatform`   (register domain 0, give full META pool)
//!   [`vmx`]          → [`VmxState`]       (feature detect, VMXON)
//!   [`capa`]         → [`CapaState`]      (capability engine, EPT)
//!   [`vmcs`]         →                    (per-VP VMCS allocation/setup)
//!   [`linux`]        → [`LinuxState`]     (kernel + initrd load via PVH)
//!   [`launch`]       →                    (signal APs, VMLAUNCH)
//!
//! Public entry points are re-exported at this module level so call sites
//! (`crate::arch::boot::platform`, `crate::arch::boot::vmx`, …) are unaffected
//! by the internal split.

extern crate alloc;
use alloc::vec::Vec;

use crate::arch::acpi::AcpiInfo;
use crate::arch::pci::PciDevice;
use crate::domain::Domain;
use crate::guest::linux::E820Entry;
use crate::mem::{MemoryPartition, PhysRegion, UncacheableRanges};
use crate::vmx::CpuFeatures;

mod capa;
mod launch;
mod linux;
mod platform;
mod themis;
mod vmcs;
mod vmx;

pub use capa::capa;
pub use launch::launch;
pub use linux::linux;
pub use platform::platform;
pub use themis::init_themis;
pub use vmcs::vmcs;
pub use vmx::vmx;

// ── Output structs ────────────────────────────────────────────────────────── //

/// Everything discovered during platform init (Phase 1a–1e).
pub struct PlatformInfo {
    pub hhdm_offset: u64,
    pub partition: MemoryPartition,
    pub num_cores: usize,
    pub bsp_lapic_id: u32,
    /// LAPIC IDs for all cores, indexed by Limine cpu.id.
    pub cpu_lapic_ids: Vec<u32>,
    pub acpi: AcpiInfo,
    #[allow(dead_code)]
    pub pci_devices: Option<Vec<PciDevice>>,
    /// Physical ranges that must be mapped UC in any EPT (MMIO regions).
    /// Built from Limine RESERVED + FRAMEBUFFER entries during Phase 1a.
    /// Shared with `ThemisPlatform` via Arc to avoid copying.
    pub uc_ranges: alloc::sync::Arc<UncacheableRanges>,
    /// Non-RAM regions to map in dom0's EPT for device/ACPI passthrough.
    /// Includes RESERVED, FRAMEBUFFER (device MMIO, mapped UC via map_range_typed),
    /// ACPI_RECLAIMABLE, and ACPI_NVS (mapped WB — regular DRAM holding ACPI tables).
    /// Excludes BOOTLOADER_RECLAIMABLE and KERNEL_AND_MODULES (capavisor memory —
    /// must not be accessible to dom0 at the hardware level).
    pub passthrough_regions: Vec<PhysRegion>,
    /// Non-RAM e820 entries for the complete Linux e820 table.
    /// Passed to `load_linux()`; combined with dom0_owned (RAM) and
    /// meta_regions (RESERVED holes) to build boot_params.e820_table.
    pub non_ram_e820: Vec<E820Entry>,
    /// Physical ranges mapped into the capavisor page tables for ACPI access.
    #[allow(dead_code)]
    pub acpi_mapped: Vec<(u64, u64)>, // (base, length)
}

/// State after VMX init (Phase 2a–2b).
pub struct VmxState {
    pub features: CpuFeatures,
    /// dom0 Domain with VMXON regions allocated from META, BSP already in VMX root mode.
    pub dom0: Domain,
    /// Index into cpu_lapic_ids of the BSP.
    pub bsp_index: usize,
}

/// State produced by capability engine initialisation (Phase P2c).
///
/// Holds the platform, the root domain capability, and the initial set of
/// memory capabilities.  These are kept alive for the lifetime of the
/// capavisor so that capability-tree operations remain valid.
pub struct CapaState {
    pub platform: crate::platform::ThemisPlatform,
    pub root_domain: capability_engine::CapabilityRef<capability_engine::Domain>,
    #[allow(dead_code)]
    pub mem_caps: Vec<capability_engine::CapabilityRef<capability_engine::MemoryRegion>>,
    /// META capabilities for dom0: one per disjoint META physical region.
    #[allow(dead_code)]
    pub meta_caps: Vec<capability_engine::CapabilityRef<capability_engine::MemoryRegion>>,
}

/// State produced by Linux kernel loading (Phase P7f).
pub struct LinuxState {
    /// Physical address of the kernel's protected-mode entry (`code32_start`).
    /// Written to VMCS `guest::RIP`.
    #[allow(dead_code)]
    pub kernel_entry_phys: u64,
    /// Physical address of `struct boot_params`.
    /// Must be placed in **ESI** immediately before VMLAUNCH (P7g) — ESI is a
    /// general-purpose register, not a VMCS field, so it cannot be vmwrite'd here.
    pub boot_params_phys: u64,
}
