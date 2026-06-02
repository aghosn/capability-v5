//! Phase 1: platform discovery — Limine memmap, ACPI, CPU topology, PCI.

extern crate alloc;
use alloc::vec::Vec;

use limine::memory_map::Entry;
use limine::mp::Cpu;

use crate::arch::acpi::AcpiInfo;
use crate::arch::x86_64::layout::{
    HPET_MMIO_BASE, IOAPIC_MMIO_BASE, ISA_HOLE_BASE, ISA_HOLE_LEN, LAPIC_MMIO_BASE,
    MMIO_PAGE_SIZE,
};
use crate::guest::linux::E820Entry;
use crate::mem::{PhysRegion, PhysicalInventory, UncacheableRanges};
use crate::util::fmt_kib;
use crate::{serial_println, AP_READY_COUNT};

use core::sync::atomic::Ordering;

use super::PlatformInfo;

// ── Phase 1: Platform discovery ───────────────────────────────────────────── //

/// Phase 1a–1e: memory map, heap, SMP, ACPI, PCI.
///
/// # Arguments
/// * `entries` — Limine memory map entries
/// * `hhdm_offset` — HHDM offset from Limine
/// * `rsdp_phys` — physical address of the RSDP (base revision 3 = physical)
/// * `cpus` — all CPUs from Limine MP response
/// * `bsp_lapic_id` — BSP LAPIC ID from Limine MP response
pub fn platform(
    entries: &[&Entry],
    hhdm_offset: u64,
    rsdp_phys: u64,
    cpus: &[&Cpu],
    bsp_lapic_id: u32,
) -> PlatformInfo {
    // ── Phase 1a: Memory map + inventory ────────────────────────────────────── //

    serial_println!("HHDM offset: {:#x}", hhdm_offset);

    let inventory = PhysicalInventory::from_limine(entries);
    serial_println!(
        "Total usable RAM:  {} MiB",
        inventory.total_usable / (1024 * 1024)
    );
    serial_println!(
        "Usable regions:    {} MiB ({} regions)",
        inventory.available_bytes() / (1024 * 1024),
        inventory.usable_regions().len()
    );

    {
        let mut v = alloc::vec![1u64, 2, 3];
        v.push(4);
        serial_println!(
            "Heap check:        alloc::vec![1,2,3,4] → len={} ✓",
            v.len()
        );
    }

    // ── Build UC range table from RESERVED + FRAMEBUFFER entries ─────────── //
    // These are device MMIO regions that must be mapped uncacheable in the EPT.
    // BOOTLOADER_RECLAIMABLE and EXECUTABLE_AND_MODULES are capavisor-internal and
    // must NOT be mapped in the EPT at all (not UC, just absent).
    let uc_ranges = alloc::sync::Arc::new(UncacheableRanges::new());
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
        "UC ranges:         {} MMIO region(s) registered",
        uc_ranges.len()
    );

    // ── Build non-RAM e820 entries and EPT passthrough region list ────────── //
    // USABLE entries are skipped here — they are replaced by explicit entries in
    // load_linux(): dom0_owned as TYPE_RAM, meta_regions as TYPE_RESERVED.
    // All other Limine entry types are translated directly to e820 types.
    let mut non_ram_e820: Vec<E820Entry> = Vec::new();
    let mut passthrough_regions: Vec<PhysRegion> = Vec::new();
    for entry in entries.iter() {
        let e820_type = match entry.entry_type {
            limine::memory_map::EntryType::ACPI_RECLAIMABLE => E820Entry::TYPE_ACPI,
            limine::memory_map::EntryType::ACPI_NVS => E820Entry::TYPE_NVS,
            limine::memory_map::EntryType::RESERVED
            | limine::memory_map::EntryType::FRAMEBUFFER
            | limine::memory_map::EntryType::BOOTLOADER_RECLAIMABLE => E820Entry::TYPE_RESERVED,
            // EXECUTABLE_AND_MODULES: capavisor binary — do NOT report in e820
            // and do NOT map in EPT.  Gaps in the e820 map are normal; Linux
            // handles them by not creating direct mappings for those addresses.
            // USABLE and BAD_MEMORY handled separately; skip all others.
            _ => continue,
        };
        non_ram_e820.push(E820Entry {
            addr: entry.base,
            size: entry.length,
            entry_type: e820_type,
        });

        // EPT passthrough: map regions that appear in e820 and may be touched
        // by Linux's direct physical mapping (page-table walks, firmware reads).
        //
        // BOOTLOADER_RECLAIMABLE: stale Limine data + ramdisk fragments.  The
        // capavisor does NOT reuse these (META comes from USABLE only).  Safe to
        // identity-map — Linux's GB-page direct mapping spans these addresses
        // and page-table walks will fault without EPT entries.
        //
        // EXECUTABLE_AND_MODULES: the capavisor binary.  Must NOT be mapped in
        // dom0's EPT — that would leak capavisor code/data.  Instead, omit from
        // e820 entirely so Linux doesn't know about these address ranges.
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
            // EXECUTABLE_AND_MODULES: capavisor memory, must not be accessible
            // to dom0 at the hardware level.
            _ => {}
        }
    }

    // ── Legacy ISA memory hole (0xA0000–0x100000) ────────────────────────── //
    // Firmware typically does not report the legacy VGA/BIOS area in the memory
    // map.  The guest's identity-mapped page tables cover this range, so the EPT
    // must map it — otherwise page-table walks that touch GPA 0xC0000 (VGA BIOS)
    // cause an EPT violation.  Also add it to e820 as RESERVED so Linux knows.
    {
        // Only add if not already covered by an existing region.
        let covered = passthrough_regions
            .iter()
            .any(|r| r.base <= ISA_HOLE_BASE && r.base + r.length >= ISA_HOLE_BASE + ISA_HOLE_LEN);
        if !covered {
            passthrough_regions.push(PhysRegion {
                base: ISA_HOLE_BASE,
                length: ISA_HOLE_LEN,
            });
            non_ram_e820.push(E820Entry {
                addr: ISA_HOLE_BASE,
                size: ISA_HOLE_LEN,
                entry_type: E820Entry::TYPE_RESERVED,
            });
        }
    }

    // ── Local APIC + I/O APIC + HPET MMIO ─────────────────────────────── //
    // Fixed-address MMIO regions that firmware does not report in the memory
    // map.  Linux accesses these directly; without EPT mappings the accesses
    // cause EPT violations.  Map them as passthrough.
    for &(base, len) in &[
        (IOAPIC_MMIO_BASE, MMIO_PAGE_SIZE),
        (HPET_MMIO_BASE, MMIO_PAGE_SIZE),
        (LAPIC_MMIO_BASE, MMIO_PAGE_SIZE),
    ] {
        let covered = passthrough_regions
            .iter()
            .any(|r| r.base <= base && r.base + r.length >= base + len);
        if !covered {
            passthrough_regions.push(PhysRegion { base, length: len });
        }
    }

    serial_println!(
        "Non-RAM e820:      {} entries (ACPI/NVS/RESERVED)",
        non_ram_e820.len()
    );
    serial_println!(
        "EPT passthrough:   {} regions (ACPI/NVS/MMIO)",
        passthrough_regions.len()
    );

    // ── Phase 1b: Memory partitioning ────────────────────────────────────── //

    let num_cores = cpus.len();
    serial_println!();
    serial_println!("CPUs: {} cores (BSP + {} APs)", num_cores, num_cores - 1);

    // ACPI must be parsed before partition() so we can compute the exact
    // number of IOMMU table pages (root + context tables) to reserve.
    // Map ACPI/reserved regions first (Limine base revision 3 leaves them unmapped).
    let mut acpi_mapped: Vec<(u64, u64)> = Vec::new();
    for entry in entries.iter() {
        match entry.entry_type {
            limine::memory_map::EntryType::ACPI_RECLAIMABLE
            | limine::memory_map::EntryType::ACPI_NVS
            | limine::memory_map::EntryType::RESERVED => {
                crate::mem::map_phys_range(entry.base, entry.length, hhdm_offset);
                acpi_mapped.push((entry.base, entry.length));
            }
            _ => {}
        }
    }

    serial_println!("ACPI: RSDP at phys {:#x}", rsdp_phys);
    let acpi = AcpiInfo::parse(rsdp_phys, hhdm_offset);

    serial_println!(
        "ACPI: {} processors, {} I/O APICs, VT-d: {}",
        acpi.processors.len(),
        acpi.io_apics.len(),
        if acpi.has_dmar { "present" } else { "absent" }
    );

    if let Some(ref regions) = acpi.pci_config_regions {
        serial_println!("ACPI: {} PCIe ECAM region(s)", regions.regions.len());
    } else {
        serial_println!("ACPI: no MCFG (no PCIe ECAM)");
    }

    let iommu_counts = acpi.iommu_page_counts();
    let (iommu_root_pages, iommu_ctx_pages) = iommu_counts;
    let iommu_pages = iommu_root_pages + iommu_ctx_pages;
    // x86-specific fixed META pages: VMXON + VMCS + VAPIC (3 per core) + IRT (4 max).
    let arch_fixed = num_cores as u64 * 3 + 4;
    let partition = inventory.partition(num_cores as u64, arch_fixed, iommu_pages);
    // META regions are NOT added to non_ram_e820 here — load_linux() receives
    // them via its `meta_regions` parameter and writes the TYPE_RESERVED entries
    // directly into boot_params.e820_table.  Adding them here too would produce
    // duplicate entries in the e820 table seen by Linux.

    // ── Phase 1c: SMP bootstrap ───────────────────────────────────────────── //

    serial_println!();
    let num_aps = num_cores as u64 - 1;
    serial_println!(
        "SMP: BSP LAPIC {} — waking {} APs ...",
        bsp_lapic_id,
        num_aps
    );

    for cpu in cpus.iter() {
        if cpu.lapic_id != bsp_lapic_id {
            cpu.goto_address.write(crate::ap_entry);
        }
    }

    if num_aps > 0 {
        while AP_READY_COUNT.load(Ordering::Acquire) < num_aps {
            core::hint::spin_loop();
        }
    }
    serial_println!("SMP: all {} APs parked ✓", num_aps);

    // ── Phase 1d: ACPI already parsed above (moved before partition) ──────── //
    serial_println!();

    // ── Phase 1e: PCI enumeration ─────────────────────────────────────────── //

    serial_println!();
    let pci_result = crate::arch::pci::enumerate(&acpi, hhdm_offset);
    let pci_devices;
    let _pci_bar_regions;
    if let Some((devices, bars)) = pci_result {
        serial_println!(
            "PCI: {} device(s) found, {} memory BAR(s)",
            devices.len(),
            bars.len()
        );
        for dev in &devices {
            let a = dev.address;
            serial_println!(
                "  {:02x}:{:02x}.{}  {:04x}:{:04x}  class={:02x}.{:02x}.{:02x}",
                a.bus(),
                a.device(),
                a.function(),
                dev.vendor_id,
                dev.device_id,
                dev.class,
                dev.subclass,
                dev.interface
            );
        }
        for bar in &bars {
            serial_println!(
                "  BAR: {:#x}+{:#x} ({} KiB)",
                bar.base,
                bar.size,
                bar.size / 1024
            );
        }
        // Add PCI memory BARs to passthrough regions so they are mapped in
        // the EPT.  Firmware (OVMF) assigned these addresses; dom0 needs
        // direct MMIO access to drive devices.
        // Merge with any existing passthrough region that overlaps (e.g. a
        // RESERVED e820 entry spanning part of the PCI MMIO window).
        for bar in &bars {
            let bar_end = bar.base + bar.size;
            let mut merged = false;
            for r in passthrough_regions.iter_mut() {
                let r_end = r.base + r.length;
                // Check for any overlap
                if r.base < bar_end && bar.base < r_end {
                    // Extend existing region to cover the union
                    let new_base = r.base.min(bar.base);
                    let new_end = r_end.max(bar_end);
                    r.base = new_base;
                    r.length = new_end - new_base;
                    merged = true;
                    break;
                }
            }
            if !merged {
                passthrough_regions.push(PhysRegion {
                    base: bar.base,
                    length: bar.size,
                });
            }
        }
        _pci_bar_regions = Some(bars);
        pci_devices = Some(devices);
    } else {
        serial_println!("PCI: no ECAM — skipping enumeration");
        pci_devices = None;
        _pci_bar_regions = None;
    }

    // ── Comprehensive memory layout report ──────────────────────────────── //

    // Get capavisor binary location from Limine KernelAddressRequest.
    let (kernel_phys_base, kernel_virt_base) =
        if let Some(r) = crate::KERNEL_ADDR_REQUEST.get_response() {
            (r.physical_base(), r.virtual_base())
        } else {
            (0u64, 0u64)
        };

    // Compute HEAP virt/phys range.
    let heap_virt_base = core::ptr::addr_of!(crate::HEAP) as u64;
    let heap_virt_end = heap_virt_base + crate::HEAP_SIZE as u64;
    let heap_phys_base = if kernel_virt_base != 0 {
        heap_virt_base - kernel_virt_base + kernel_phys_base
    } else {
        0
    };
    let heap_phys_end = heap_phys_base + crate::HEAP_SIZE as u64;

    serial_println!("=== P1: Physical memory layout ===");
    serial_println!();

    // 1. Capavisor layout
    serial_println!("Capavisor layout:");
    if kernel_phys_base != 0 {
        serial_println!(
            "  Binary:  virt [{:#018x}..{:#018x})",
            kernel_virt_base,
            kernel_virt_base + (heap_virt_base - kernel_virt_base)
        );
        serial_println!(
            "           phys [{:#011x}..{:#011x})  [KERNEL_AND_MODULES]",
            kernel_phys_base,
            heap_phys_base
        );
        serial_println!(
            "  Heap:    virt [{:#018x}..{:#018x})  64 MiB BSS",
            heap_virt_base,
            heap_virt_end
        );
        serial_println!(
            "           phys [{:#011x}..{:#011x})  [excluded from dom0]",
            heap_phys_base,
            heap_phys_end
        );
    } else {
        serial_println!("  (KernelAddressRequest unavailable)");
    }
    serial_println!();

    // 2. Original Limine memory map with META markers
    serial_println!("Limine memory map ({} entries):", entries.len());
    for entry in entries.iter() {
        let type_str = match entry.entry_type {
            limine::memory_map::EntryType::USABLE => "usable      ",
            limine::memory_map::EntryType::RESERVED => "reserved    ",
            limine::memory_map::EntryType::ACPI_RECLAIMABLE => "acpi-reclaim",
            limine::memory_map::EntryType::ACPI_NVS => "acpi-nvs    ",
            limine::memory_map::EntryType::BAD_MEMORY => "bad-memory  ",
            limine::memory_map::EntryType::BOOTLOADER_RECLAIMABLE => "bootloader  ",
            limine::memory_map::EntryType::EXECUTABLE_AND_MODULES => "kernel+mods ",
            limine::memory_map::EntryType::FRAMEBUFFER => "framebuffer ",
            _ => "other       ",
        };
        let entry_end = entry.base + entry.length;
        // Check if this entry overlaps with any META region.
        let mut marker = "";
        'outer: for i in 0..partition.meta_count {
            let m = &partition.meta_regions[i];
            let m_end = m.base + m.length;
            if m.base < entry_end && m_end > entry.base {
                if m.base == entry.base && m_end == entry_end {
                    marker = "  ← META [full]";
                } else {
                    marker = "  ← META [partial]";
                }
                break 'outer;
            }
        }
        // Mark capavisor binary/heap entries.
        let capa_marker = if kernel_phys_base != 0 {
            let is_binary = entry.base < heap_phys_base
                && entry_end > kernel_phys_base
                && entry.base >= kernel_phys_base;
            let is_heap = heap_phys_base > 0
                && entry.base >= heap_phys_base
                && entry_end <= heap_phys_end + 0x1000;
            if is_binary {
                "  ← capavisor binary"
            } else if is_heap {
                "  ← capavisor heap (BSS)"
            } else {
                ""
            }
        } else {
            ""
        };
        serial_println!(
            "  [{:#011x}..{:#011x})  {:>8}  {}{}{}",
            entry.base,
            entry_end,
            fmt_kib(entry.length),
            type_str,
            marker,
            capa_marker,
        );
    }
    serial_println!();

    // 3. META pool summary
    let meta_total_bytes: u64 = partition.meta_regions[..partition.meta_count]
        .iter()
        .map(|r| r.length)
        .sum();
    serial_println!(
        "META pool: {} KiB across {} physical region(s):",
        meta_total_bytes / 1024,
        partition.meta_count
    );
    for i in 0..partition.meta_count {
        let r = &partition.meta_regions[i];
        serial_println!(
            "  region [{}]: phys [{:#011x}..{:#011x})  {} KiB",
            i,
            r.base,
            r.base + r.length,
            r.length / 1024
        );
    }
    serial_println!(
        "  breakdown:  {} arch-fixed + {} page-table + {} IOMMU  ({} pages = {} KiB)",
        partition.meta_breakdown.arch_fixed_pages,
        partition.meta_breakdown.pt_pages,
        partition.meta_breakdown.iommu_pages,
        partition.meta_breakdown.total_pages,
        partition.meta_breakdown.total_bytes() / 1024,
    );
    serial_println!();

    // 4. ACPI regions mapped into capavisor page tables
    serial_println!(
        "ACPI/reserved regions mapped into capavisor PTs ({} entries):",
        acpi_mapped.len()
    );
    for (base, len) in &acpi_mapped {
        serial_println!(
            "  [{:#011x}..{:#011x})  {} KiB",
            base,
            base + len,
            len / 1024
        );
    }
    serial_println!();

    // 5. dom0 RAM regions
    serial_println!(
        "dom0 RAM regions ({} entries, {} MiB total):",
        partition.dom0_owned_count,
        partition.dom0_owned[..partition.dom0_owned_count]
            .iter()
            .map(|r| r.length)
            .sum::<u64>()
            / (1024 * 1024)
    );
    for r in &partition.dom0_owned[..partition.dom0_owned_count] {
        serial_println!(
            "  [{:#011x}..{:#011x})  {} KiB",
            r.base,
            r.base + r.length,
            r.length / 1024
        );
    }
    serial_println!();

    // 5b. COMM region
    serial_println!(
        "DomainComm region: [{:#011x}..{:#011x})  {} KiB  ({} pages)",
        partition.comm_region.base,
        partition.comm_region.base + partition.comm_region.length,
        partition.comm_region.length / 1024,
        partition.comm_region.length / 4096,
    );
    serial_println!();

    // 6. Final dom0 e820 (what Linux will see): dom0 RAM + META RESERVED + non_ram_e820, sorted.
    //    This mirrors exactly what load_linux() will write into boot_params.e820_table.
    {
        let mut e820_all: alloc::vec::Vec<(u64, u64, u32)> = alloc::vec::Vec::new();
        for r in &partition.dom0_owned[..partition.dom0_owned_count] {
            if r.length > 0 {
                e820_all.push((r.base, r.length, 1));
            }
        }
        for i in 0..partition.meta_count {
            let r = &partition.meta_regions[i];
            if r.length > 0 {
                e820_all.push((r.base, r.length, 2));
            }
        }
        for e in &non_ram_e820 {
            if e.size > 0 {
                e820_all.push((e.addr, e.size, e.entry_type));
            }
        }
        // COMM region (TYPE_RESERVED)
        e820_all.push((partition.comm_region.base, partition.comm_region.length, 2));
        e820_all.sort_by_key(|e| e.0);
        serial_println!(
            "dom0 e820 table ({} entries, as seen by Linux):",
            e820_all.len()
        );
        for (base, size, typ) in &e820_all {
            let type_str = match *typ {
                1 => "RAM     ",
                2 => "RESERVED",
                3 => "ACPI    ",
                4 => "NVS     ",
                _ => "OTHER   ",
            };
            serial_println!(
                "  type={} ({})  [{:#011x}..{:#011x})  {} KiB",
                typ,
                type_str,
                base,
                base + size,
                size / 1024
            );
        }
        serial_println!();
    }

    let cpu_lapic_ids: Vec<u32> = cpus.iter().map(|c| c.lapic_id).collect();

    // ── Exclude TPM MMIO from dom0 passthrough ──────────────────────────── //
    // If an ACPI TPM2 table was found, the TPM's TIS MMIO region must not be
    // mapped in dom0's EPT — it is capavisor-exclusive (like META, per A5).
    // The TIS base (0xFED40000, 5 pages) might overlap a RESERVED e820 region
    // that was added to passthrough_regions above.  Carve it out.
    if acpi.tpm.is_some() {
        let tpm_base = tpm2::TIS_BASE;
        let tpm_end = tpm_base + 0x5000; // 5 × 4 KiB (localities 0–4)
        let before = passthrough_regions.len();
        passthrough_regions.retain(|r| {
            let r_end = r.base + r.length;
            // Keep regions that don't overlap the TPM range at all.
            r_end <= tpm_base || r.base >= tpm_end
        });
        // TODO: If a passthrough region partially overlaps the TPM range, we
        // should split it rather than dropping it entirely.  In practice the
        // TPM's 5-page region is unlikely to partially overlap a larger
        // RESERVED entry, but this is a correctness gap to address later.
        let removed = before - passthrough_regions.len();
        if removed > 0 {
            serial_println!(
                "TPM exclusion:     removed {} passthrough region(s) overlapping {:#x}..{:#x}",
                removed,
                tpm_base,
                tpm_end,
            );
        }
    }

    PlatformInfo {
        hhdm_offset,
        partition,
        num_cores,
        bsp_lapic_id,
        cpu_lapic_ids,
        acpi,
        pci_devices,
        uc_ranges,
        non_ram_e820,
        passthrough_regions,
        acpi_mapped,
    }
}
