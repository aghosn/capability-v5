//! AArch64 boot phase functions.
//!
//! Mirrors the x86 `arch::x86_64::boot` module but for ARM:
//!   platform()     → PlatformInfo   (memory, SMP, GIC discovery)
//!   init_themis()  → ThemisPlatform (register domain 0, give META pool)
//!
//! EL2/Stage-2/GIC runtime setup will be added in M3/M4.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use limine::memory_map::Entry;
use limine::mp::Cpu;

use crate::mem::{MemoryPartition, MetaBreakdown, PhysRegion, PhysicalInventory, UncacheableRanges};
use crate::serial_println;

// ── QEMU virt machine GIC addresses (temporary bringup constants) ────────── //
// These are fixed for `qemu-system-aarch64 -machine virt,gic-version=3`.
// TODO: Discover from ACPI MADT or device tree.
const QEMU_VIRT_GICD_BASE: u64 = 0x0800_0000;
const QEMU_VIRT_GICR_BASE: u64 = 0x080A_0000;
const QEMU_VIRT_GICR_STRIDE: u64 = 0x0002_0000; // 128 KiB per redistributor

// ── Output struct ─────────────────────────────────────────────────────────── //

/// Everything discovered during platform init.
pub struct PlatformInfo {
    pub hhdm_offset: u64,
    pub partition: MemoryPartition,
    pub num_cores: usize,
    pub bsp_mpidr: u64,
    /// MPIDR values for all cores, indexed by Limine cpu order.
    pub cpu_mpidrs: Vec<u64>,
    /// Physical ranges that must be mapped UC in Stage-2 (device MMIO).
    pub uc_ranges: Arc<UncacheableRanges>,
    /// Non-RAM regions to map in dom0's Stage-2 for device passthrough.
    pub passthrough_regions: Vec<PhysRegion>,
}

/// Format a byte count as a human-readable string.
fn fmt_kib(bytes: u64) -> alloc::string::String {
    if bytes >= 1024 * 1024 {
        alloc::format!("{} MiB", bytes / (1024 * 1024))
    } else {
        alloc::format!("{} KiB", bytes / 1024)
    }
}

// ── Phase 1: Platform discovery ───────────────────────────────────────────── //

pub fn platform(
    entries: &[&Entry],
    hhdm_offset: u64,
    cpus: &[&Cpu],
    bsp_mpidr: u64,
) -> PlatformInfo {
    // ── Phase 1a: Memory map + inventory ────────────────────────────────── //

    let inventory = PhysicalInventory::from_limine(entries);
    serial_println!(
        "Total usable RAM:  {} MiB ({} regions)",
        inventory.total_usable / (1024 * 1024),
        inventory.usable_regions().len()
    );

    // Build UC range table from RESERVED + FRAMEBUFFER entries.
    let uc_ranges = Arc::new(UncacheableRanges::new());
    for entry in entries.iter() {
        match entry.entry_type {
            limine::memory_map::EntryType::RESERVED
            | limine::memory_map::EntryType::FRAMEBUFFER => {
                uc_ranges.add(entry.base, entry.length);
            }
            _ => {}
        }
    }
    serial_println!(
        "UC ranges:         {} MMIO region(s)",
        uc_ranges.len()
    );

    // Build passthrough regions (device MMIO mapped in dom0's Stage-2).
    let mut passthrough_regions: Vec<PhysRegion> = Vec::new();
    for entry in entries.iter() {
        match entry.entry_type {
            limine::memory_map::EntryType::ACPI_RECLAIMABLE
            | limine::memory_map::EntryType::ACPI_NVS
            | limine::memory_map::EntryType::RESERVED
            | limine::memory_map::EntryType::FRAMEBUFFER
            | limine::memory_map::EntryType::BOOTLOADER_RECLAIMABLE => {
                passthrough_regions.push(PhysRegion {
                    base: entry.base,
                    length: entry.length,
                });
            }
            _ => {}
        }
    }

    // ── Phase 1b: Memory partitioning ───────────────────────────────────── //

    let num_cores = cpus.len();
    // AArch64 M2: minimal fixed META pages — just Stage-2 root (1 page per domain).
    // No VMXON, no VMCS, no VAPIC, no IRT.
    let arch_fixed_pages = 1u64; // Stage-2 root table
    let iommu_pages = 0u64; // No SMMU yet

    let partition = inventory.partition(num_cores as u64, arch_fixed_pages, iommu_pages);

    serial_println!();
    serial_println!("Memory partition:");
    serial_println!(
        "  dom0 RAM:  {} ({} regions)",
        fmt_kib(
            partition.dom0_owned[..partition.dom0_owned_count]
                .iter()
                .map(|r| r.length)
                .sum::<u64>()
        ),
        partition.dom0_owned_count
    );
    serial_println!(
        "  META pool: {} ({} regions, {} pages)",
        fmt_kib(
            partition.meta_regions[..partition.meta_count]
                .iter()
                .map(|r| r.length)
                .sum::<u64>()
        ),
        partition.meta_count,
        partition.meta_breakdown.total_pages,
    );
    serial_println!(
        "  breakdown: {} arch-fixed + {} page-table + {} IOMMU pages",
        partition.meta_breakdown.arch_fixed_pages,
        partition.meta_breakdown.pt_pages,
        partition.meta_breakdown.iommu_pages,
    );
    serial_println!(
        "  COMM:      {} KiB @ {:#x}",
        partition.comm_region.length / 1024,
        partition.comm_region.base
    );

    // ── Phase 1c: CPU info ──────────────────────────────────────────────── //

    let cpu_mpidrs: Vec<u64> = cpus.iter().map(|c| c.mpidr).collect();
    serial_println!();
    serial_println!(
        "CPUs: {} (BSP MPIDR={:#x})",
        num_cores,
        bsp_mpidr
    );
    for (i, mpidr) in cpu_mpidrs.iter().enumerate() {
        serial_println!("  CPU {}: MPIDR={:#x}", i, mpidr);
    }

    // ── Phase 1d: GIC discovery (hardcoded for QEMU virt) ───────────────── //

    serial_println!();
    serial_println!(
        "GIC (QEMU virt): GICD={:#x} GICR={:#x} stride={:#x}",
        QEMU_VIRT_GICD_BASE,
        QEMU_VIRT_GICR_BASE,
        QEMU_VIRT_GICR_STRIDE
    );

    PlatformInfo {
        hhdm_offset,
        partition,
        num_cores,
        bsp_mpidr,
        cpu_mpidrs,
        uc_ranges,
        passthrough_regions,
    }
}

// ── Phase 2a: ThemisPlatform bootstrap ────────────────────────────────────── //

pub fn init_themis(info: &PlatformInfo) -> crate::platform::ThemisPlatform {
    use crate::platform::ThemisPlatform;
    use capability_engine::DomainId;

    const ROOT_ID: DomainId = 0;

    let mut platform = ThemisPlatform::new(Arc::clone(&info.uc_ranges), info.num_cores);

    // Store GIC addresses and CPU MPIDRs in arch-specific platform state.
    platform.arch.gicd_base = QEMU_VIRT_GICD_BASE;
    platform.arch.gicr_base = QEMU_VIRT_GICR_BASE;
    platform.arch.gicr_stride = QEMU_VIRT_GICR_STRIDE;
    platform.arch.cpu_mpidrs = info.cpu_mpidrs.clone();

    // Register dom0 in the domain table.
    platform.bootstrap_register_domain(ROOT_ID, None, info.hhdm_offset);

    // Map META regions into HHDM and give them to the platform.
    for i in 0..info.partition.meta_count {
        let r = info.partition.meta_regions[i];
        crate::mem::map_phys_range(r.base, r.length, info.hhdm_offset);
        platform.bootstrap_give_meta(ROOT_ID, r);
    }

    // Map and init COMM region.
    let cr = &info.partition.comm_region;
    crate::mem::map_phys_range(cr.base, cr.length, info.hhdm_offset);
    platform.bootstrap_init_domcomm(ROOT_ID, cr.base, cr.base, 4);

    let meta_total: u64 = info.partition.meta_regions[..info.partition.meta_count]
        .iter()
        .map(|r| r.length)
        .sum();

    serial_println!();
    serial_println!(
        "ThemisPlatform: META pool {} KiB across {} region(s):",
        meta_total / 1024,
        info.partition.meta_count
    );
    for i in 0..info.partition.meta_count {
        let r = &info.partition.meta_regions[i];
        serial_println!(
            "  [{:#011x}..{:#011x})  {} KiB",
            r.base,
            r.base + r.length,
            r.length / 1024
        );
    }
    serial_println!(
        "  COMM: [{:#011x}..{:#011x})  {} KiB",
        cr.base,
        cr.base + cr.length,
        cr.length / 1024
    );

    platform
}
