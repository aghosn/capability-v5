//! Boot phase functions.
//!
//! `_start()` in `main.rs` is the orchestrator; the logic for each phase lives
//! here so the entry point stays readable.
//!
//! Phase flow:
//!   platform()     → PlatformInfo   (memory, SMP, ACPI, PCI)
//!   init_themis()  → ThemisPlatform (register domain 0, give full META pool)
//!   vmx()          → VmxState       (feature detect, VMXON — allocates from ThemisPlatform)
//!   capa()         → CapaState      (capability engine, EPT — also uses ThemisPlatform)
//!   vmcs()         → VmcsState      (VMCS setup — also uses ThemisPlatform)

extern crate alloc;
use alloc::vec::Vec;

use limine::memory_map::Entry;
use limine::mp::Cpu;

use crate::acpi::AcpiInfo;
use crate::domain::Domain;
use crate::guest::linux::E820Entry;
use crate::mem::{MemoryPartition, PhysRegion, PhysicalInventory, UncacheableRanges};
use crate::pci::PciDevice;
use crate::vmx::CpuFeatures;
use crate::{serial_println, AP_READY_COUNT};

use core::sync::atomic::Ordering;

/// Format a byte count as a human-readable KiB string.
fn fmt_kib(bytes: u64) -> alloc::string::String {
    if bytes >= 1024 * 1024 {
        alloc::format!("{} MiB", bytes / (1024 * 1024))
    } else {
        alloc::format!("{} KiB", bytes / 1024)
    }
}

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
        const ISA_HOLE_BASE: u64 = 0xA0000;
        const ISA_HOLE_LEN: u64 = 0x100000 - 0xA0000; // 384 KiB
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
        (0xFEC0_0000u64, 0x1000u64), // I/O APIC (4 KiB)
        (0xFED0_0000u64, 0x1000u64), // HPET (4 KiB)
        (0xFEE0_0000u64, 0x1000u64), // Local APIC (4 KiB)
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

    let partition = inventory.partition(num_cores as u64);
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

    // ── Phase 1d: ACPI parsing ────────────────────────────────────────────── //

    serial_println!();
    // Map ACPI/reserved regions that Limine base revision 3 leaves unmapped.
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

    // ── Phase 1e: PCI enumeration ─────────────────────────────────────────── //

    serial_println!();
    let pci_result = crate::pci::enumerate(&acpi, hhdm_offset);
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
        for bar in &bars {
            passthrough_regions.push(PhysRegion {
                base: bar.base,
                length: bar.size,
            });
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
        "  breakdown:  {} VMXON + {} VMCS + {} VAPIC + {} EPT + {} IRT  ({} pages = {} KiB)",
        partition.meta_breakdown.vmxon_pages,
        partition.meta_breakdown.vmcs_pages,
        partition.meta_breakdown.vapic_pages,
        partition.meta_breakdown.ept_pages,
        partition.meta_breakdown.irt_pages,
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

// ── Phase 2a-b: VMX init ─────────────────────────────────────────────────── //

/// Phase 2a–2b: detect VMX features, allocate VMXON regions from the platform's
/// META pool, and execute VMXON on the BSP.
///
/// `platform` must already have domain 0 registered and its META pool populated
/// (call `init_themis` first).
pub fn vmx(info: &PlatformInfo, platform: &mut crate::platform::ThemisPlatform) -> VmxState {
    // P2a — CPU feature detection.
    let features = crate::vmx::detect_features(info.acpi.has_dmar);

    serial_println!();
    serial_println!("CPU features:");
    serial_println!(
        "  VMX: {}  x2APIC: {}  APICv: {}  VT-d: {}",
        if features.vmx { "yes" } else { "NO" },
        if features.x2apic { "yes" } else { "no" },
        if features.has_apicv() {
            "full"
        } else {
            "partial/none"
        },
        if features.vtd { "yes" } else { "no" }
    );
    serial_println!(
        "  VMCS rev: {:#x}  phys bits: {}  region size: {} B",
        features.vmcs_revision_id,
        features.phys_addr_bits,
        features.vmx_region_size
    );

    assert!(features.vmx, "VMX not supported — cannot continue");

    // P2b — Allocate VMXON regions and store in the platform.
    // VMXON is a per-physical-core resource, not per-domain.
    let hhdm = info.hhdm_offset;
    let rev_id = features.vmcs_revision_id;
    let mut vmxon_addrs = Vec::with_capacity(info.num_cores);
    for _i in 0..info.num_cores {
        let phys = platform.alloc_meta_frame(0); // domain 0
        let virt = (phys + hhdm) as *mut u32;
        unsafe { virt.write_volatile(rev_id & 0x7FFF_FFFF) };
        vmxon_addrs.push(phys);
    }

    // Create dom0 Domain (VMCS/VAPIC/bitmaps allocated later in vmcs()).
    let dom0 = Domain::new(0, info.hhdm_offset);

    serial_println!();
    serial_println!(
        "dom0: allocated {} VMXON pages from META pool",
        info.num_cores
    );

    let bsp_index = info
        .cpu_lapic_ids
        .iter()
        .position(|&id| id == info.bsp_lapic_id)
        .expect("BSP LAPIC ID not found in CPU list");

    let bsp_vmxon = vmxon_addrs[bsp_index];
    platform.bootstrap_set_vmxon_phys(vmxon_addrs);

    crate::vmx::enable_vmx_on_core(bsp_vmxon).expect("VMXON failed on BSP");
    serial_println!(
        "VMX: VMXON on BSP (LAPIC {}, index {}) ✓",
        info.bsp_lapic_id,
        bsp_index
    );

    VmxState {
        features,
        dom0,
        bsp_index,
    }
}

// ── ThemisPlatform init ───────────────────────────────────────────────────── //

/// Create and bootstrap `ThemisPlatform` for dom0.
///
/// Registers domain 0 and hands it the **full** META pool.  All subsequent
/// allocations (VMXON, VMCS, VAPIC, EPT page-table pages) come from this single
/// pool via `ThemisPlatform::alloc_meta_frame()` or the EPT walker.
///
/// Must be called before `vmx()`.
pub fn init_themis(info: &PlatformInfo) -> crate::platform::ThemisPlatform {
    use crate::platform::ThemisPlatform;
    use capability_engine::DomainId;

    const ROOT_ID: DomainId = 0;

    let mut platform = ThemisPlatform::new(alloc::sync::Arc::clone(&info.uc_ranges), info.num_cores);
    platform.bootstrap_set_lapic_ids(info.cpu_lapic_ids.clone());
    platform.bootstrap_register_domain(ROOT_ID, None, info.hhdm_offset);

    // Map META regions into HHDM and give them to the platform.
    for i in 0..info.partition.meta_count {
        let r = info.partition.meta_regions[i];
        crate::mem::map_phys_range(r.base, r.length, info.hhdm_offset);
        platform.bootstrap_give_meta(ROOT_ID, r);
    }

    serial_println!(
        "ThemisPlatform: META pool {} KiB across {} region(s):",
        info.partition.meta_regions[..info.partition.meta_count]
            .iter()
            .map(|r| r.length)
            .sum::<u64>()
            / 1024,
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
        "  breakdown: {} VMXON + {} VMCS + {} VAPIC + {} EPT + {} IRT pages",
        info.partition.meta_breakdown.vmxon_pages,
        info.partition.meta_breakdown.vmcs_pages,
        info.partition.meta_breakdown.vapic_pages,
        info.partition.meta_breakdown.ept_pages,
        info.partition.meta_breakdown.irt_pages,
    );

    // ── IRT allocation for VT-d interrupt remapping (intr-p3b) ───────────── //
    //
    // One 4 KiB page per IR-capable DRHD unit, allocated from the META pool.
    // Pages are machine-global hardware tables written by the IOMMU; they are
    // never visible to any domain (absent from EPT like all META pages).
    //
    // We must map each DRHD's MMIO region before accessing its registers:
    // Limine only HHDM-maps usable RAM; IOMMU MMIO holes need explicit mapping.
    // IRTA_REG is written here; GCMD.SIRTP/IRE are issued in intr-p3c.
    if info.acpi.has_dmar {
        // VT-d spec §10.4.28: IRTA_REG layout
        //   bits[63:12]  IRT physical base (4 KiB-aligned)
        //   bits[11]     Extended Interrupt Mode (X2APIC); 0 for now
        //   bits[3:0]    Size = log2(entries) - 1; 0 = 256 entries (minimum)
        const IRTA_REG_OFFSET: usize = 0xB8;
        const IRTA_SIZE_256:   u64   = 0;
        // CAP register (offset 0x08): bit 16 = IR capable.
        const CAP_OFFSET:  usize = 0x08;
        const CAP_IR_BIT:  u64   = 1 << 16;
        // ECAP register (offset 0x10): bit 3 = IR.
        const ECAP_OFFSET: usize = 0x10;
        const ECAP_IR_BIT: u64   = 1 << 3;

        let mut units = info.acpi.drhd_units.clone();
        for unit in units.iter_mut() {
            // Map the DRHD MMIO register page before any register access.
            crate::mem::map_phys_range(unit.register_base, 0x1000, info.hhdm_offset);

            // Read CAP/ECAP now that the page is mapped.
            let reg_virt = (unit.register_base + info.hhdm_offset) as *const u64;
            let cap  = unsafe { reg_virt.add(CAP_OFFSET  / 8).read_volatile() };
            let ecap = unsafe { reg_virt.add(ECAP_OFFSET / 8).read_volatile() };
            unit.ir_supported = (cap & CAP_IR_BIT != 0) || (ecap & ECAP_IR_BIT != 0);

            if !unit.ir_supported {
                serial_println!(
                    "  DRHD seg={} base={:#x}: IR not supported (cap={:#x} ecap={:#x}) — skipping",
                    unit.segment, unit.register_base, cap, ecap,
                );
                continue;
            }

            let irt_phys = platform.alloc_meta_frame(ROOT_ID);
            unit.irt_phys = irt_phys;

            // Write IRTA_REG: base | size_encoding (EIM=0, 256 entries).
            let irta_virt = (unit.register_base + info.hhdm_offset + IRTA_REG_OFFSET as u64)
                as *mut u64;
            unsafe { core::ptr::write_volatile(irta_virt, irt_phys | IRTA_SIZE_256) };

            serial_println!(
                "  DRHD seg={} base={:#x}: cap={:#x} ecap={:#x} IRT @ {:#x} IRTA_REG written",
                unit.segment, unit.register_base, cap, ecap, irt_phys,
            );
        }
        platform.drhd_units = units;
    }

    // ── DomainComm header init for dom0 ──────────────────────────────────── //
    //
    // The COMM region was reserved during partition() (separate from META).
    // Write the DomainComm header and ring metadata.  Identity mapping:
    // base HPA == GPA for dom0.  The binary attestation message is written
    // later in capa() after the capability engine is initialized.
    {
        let cr = &info.partition.comm_region;
        let nr_pages = (cr.length / 4096) as u32;

        // Ensure the pages are HHDM-mapped so init_domcomm can write to them.
        crate::mem::map_phys_range(cr.base, cr.length, info.hhdm_offset);

        // Dom0 uses identity mapping: base HPA == GPA.
        platform.bootstrap_init_domcomm(ROOT_ID, cr.base, cr.base, nr_pages);

        // Set CPUID statics for the vmexit handler.
        crate::vmexit::DOMCOMM_GPA.store(cr.base, core::sync::atomic::Ordering::Relaxed);
        crate::vmexit::DOMCOMM_PAGES.store(nr_pages, core::sync::atomic::Ordering::Relaxed);

        serial_println!(
            "  DomainComm: {} pages at {:#x} (e820 reserved, CPUID 0x40000002)",
            nr_pages, cr.base,
        );
    }

    platform
}

// ── Phase 2c output ───────────────────────────────────────────────────────── //

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

// ── Phase 2c: Capability engine + EPT ────────────────────────────────────── //

/// Phase P2c: initialise the capability engine for dom0.
///
/// Receives the already-bootstrapped `ThemisPlatform` (domain 0 registered, full
/// META pool given).  Builds the capability tree and drives `UpdateBatch`es of
/// `ChangeRights` to map dom0's memory into the EPT.
///
/// # Bootstrap inversion
///
/// During normal operation the capability engine drives hardware state: a
/// capability is created first, then `ChangeRights` propagates it to the EPT.
/// Bootstrap inverts this order — hardware structures (VMXON, META allocator, EPT
/// root) are set up before the capability records exist.  The end result must be
/// strictly equivalent: every region accessible to dom0 in the EPT has exactly
/// one corresponding capability record, and every capability record has exactly
/// one EPT mapping.  Any divergence is a security bug.
///
/// # Capability forest
///
/// dom0's memory capability tree is a **forest** of independent roots, one per
/// disjoint physical region:
/// - one root per `dom0_owned` RAM region
/// - one root per passthrough region (MMIO / ACPI / NVS)
/// - one META-flagged root for the META pool
///
/// There is no single root that covers all memory.  Attestation must walk every
/// root; delegation produces sub-capabilities bounded by a single root's extent;
/// revocation only affects the subtree of the revoked root.
pub fn capa(info: &PlatformInfo, platform: crate::platform::ThemisPlatform) -> CapaState {
    use alloc::sync::Arc;
    use capability_engine::{
        Attributes, Capability, Domain as CapaDomain, DomainId, MemoryRegion, Rights, UpdateBatch,
    };

    const ROOT_ID: DomainId = 0;

    serial_println!();
    serial_println!("=== P2c: capability engine init ===");

    // ── Root domain capability ─────────────────────────────────────────── //

    let root_domain = Capability::new_root(ROOT_ID, 0, CapaDomain::new_root(info.num_cores));

    // ── Memory capabilities ────────────────────────────────────────────── //

    let mut mem_caps: Vec<capability_engine::CapabilityRef<MemoryRegion>> = Vec::new();
    let meta_caps;
    let comm_root_handle: u64;
    let self_domain_cap_handle: u64;
    {
        let mut dom = root_domain.write();
        let mut sub = 1u64;

        for region in &info.partition.dom0_owned[..info.partition.dom0_owned_count] {
            if region.length == 0 {
                continue;
            }
            let mem_cap = Capability::new_root(
                ROOT_ID,
                sub,
                MemoryRegion::new_root(region.base, region.length),
            );
            dom.data
                .add_memory_capability(sub, Arc::downgrade(&mem_cap));
            serial_println!(
                "  mem cap #{}: {:#x}+{:#x} ({} KiB)",
                sub,
                region.base,
                region.length,
                region.length / 1024,
            );
            mem_caps.push(mem_cap);
            sub += 1;
        }

        // ── Passthrough capabilities (MMIO / ACPI / NVS) ─────────────────── //
        //
        // Every non-RAM region mapped in dom0's EPT must have a corresponding
        // capability record so that the capability state fully reflects what
        // dom0 can access.  Without these, attestation would be blind to all
        // device MMIO and firmware table regions.
        //
        // These are regular (non-META) capabilities — MMIO regions ARE mapped
        // in the EPT and are therefore visible to dom0, unlike META pages.
        for region in &info.passthrough_regions {
            if region.length == 0 {
                continue;
            }
            let mem_cap = Capability::new_root(
                ROOT_ID,
                sub,
                MemoryRegion::new_root(region.base, region.length),
            );
            dom.data
                .add_memory_capability(sub, Arc::downgrade(&mem_cap));
            serial_println!(
                "  passthrough cap #{}: {:#x}+{:#x} ({} KiB)",
                sub,
                region.base,
                region.length,
                region.length / 1024,
            );
            mem_caps.push(mem_cap);
            sub += 1;
        }

        // ── META capabilities ─────────────────────────────────────────────── //
        //
        // The META regions were already handed to the platform allocator in
        // bootstrap_give_meta().  Here we create the matching capability
        // records so that dom0's capability state reflects ownership of those
        // pages.  One META-flagged MemoryRegion capability per physical META region.
        let mut meta_caps_local: Vec<capability_engine::CapabilityRef<MemoryRegion>> = Vec::new();
        for i in 0..info.partition.meta_count {
            let r = &info.partition.meta_regions[i];
            let cap = Capability::new_root(ROOT_ID, sub, MemoryRegion::new_root(r.base, r.length));
            {
                let mut c = cap.write();
                c.owned.attributes = Attributes::from_bits(Attributes::META).canonicalize();
            }
            dom.data.add_memory_capability(sub, Arc::downgrade(&cap));
            serial_println!(
                "  meta cap #{}: [{:#011x}..{:#011x})  {} KiB  {} pages",
                sub,
                r.base,
                r.base + r.length,
                r.length / 1024,
                r.length / 4096,
            );
            meta_caps_local.push(cap);
            sub += 1;
        }
        meta_caps = meta_caps_local;

        // ── COMM root capability ──────────────────────────────────────────── //
        //
        // The COMM region is a contiguous block carved out during partition().
        // We create a root capability as the tree anchor; the actual COMM
        // capability will be obtained by carving from this root (see below).
        let cr = &info.partition.comm_region;
        let comm_root = Capability::new_root(
            ROOT_ID,
            sub,
            MemoryRegion::new_root(cr.base, cr.length),
        );
        comm_root_handle = sub;
        dom.data
            .add_memory_capability(sub, Arc::downgrade(&comm_root));
        serial_println!(
            "  comm root cap #{}: {:#x}+{:#x} ({} KiB)",
            sub, cr.base, cr.length, cr.length / 1024,
        );
        // Keep the Arc alive past this block so CARVE can find it.
        mem_caps.push(comm_root);
        sub += 1;

        // ── Self-referencing domain capability ────────────────────────────── //
        //
        // dom0 needs a domain capability pointing to itself so that
        // register_comm() can resolve the child_domain_handle.  For dom0's
        // DomainComm, target_domain_id == owner_id (self-referential).
        self_domain_cap_handle = sub;
        dom.data.add_domain_capability(
            self_domain_cap_handle,
            Arc::downgrade(&root_domain),
        );
        serial_println!("  self domain cap #{}: dom0 → dom0", sub);
        // sub += 1; // not needed — last handle allocation in this block
    }

    // ── Build EPT via UpdateBatch ──────────────────────────────────────── //
    //
    // Emit one ChangeRights per dom0-owned region (identity GPA = HPA, RWX).
    // execute() calls apply_update() for each entry; ThemisPlatform lazily
    // allocates the EPT root page from the META pool on the first call.

    let batch = {
        let mut b = UpdateBatch::new();
        for region in &info.partition.dom0_owned[..info.partition.dom0_owned_count] {
            if region.length == 0 {
                continue;
            }
            b.add_change_rights(
                ROOT_ID,
                region.base, // GPA (identity)
                region.length,
                region.base, // HPA
                Rights::RWX,
                false,
            );
        }
        // COMM region is also identity-mapped — dom0 needs read/write access.
        let cr = &info.partition.comm_region;
        b.add_change_rights(ROOT_ID, cr.base, cr.length, cr.base, Rights::RW, false);
        b
    };

    capability_engine::execute(&platform, false, || Ok(((), batch)))
        .expect("P2c: capability engine execute failed");

    let eptp = platform
        .eptp(ROOT_ID)
        .expect("P2c: EPT root not allocated after execute");

    serial_println!(
        "  EPT built for dom0: {} RAM regions, EPTP = {:#x}",
        info.partition.dom0_owned_count,
        eptp,
    );

    // ── EPT passthrough: map non-RAM regions for device/ACPI access ───────── //
    //
    // RESERVED + FRAMEBUFFER regions are device MMIO (PCI BARs, LAPIC, IOAPIC,
    // HPET, etc.) and are mapped UC by map_range_typed() via UncacheableRanges.
    // ACPI_RECLAIMABLE + ACPI_NVS are normal DRAM (WB) holding firmware tables.
    // BOOTLOADER_RECLAIMABLE and KERNEL_AND_MODULES are NOT mapped — capavisor
    // memory is invisible to dom0 at the hardware level.
    let passthrough_batch = {
        let mut b = UpdateBatch::new();
        for region in &info.passthrough_regions {
            if region.length == 0 {
                continue;
            }
            b.add_change_rights(
                ROOT_ID,
                region.base, // GPA (identity)
                region.length,
                region.base, // HPA
                Rights::RW,  // no execute for MMIO/firmware regions
                false,
            );
        }
        b
    };

    capability_engine::execute(&platform, false, || Ok(((), passthrough_batch)))
        .expect("P2c: passthrough EPT execute failed");

    serial_println!(
        "  EPT passthrough: {} non-RAM regions mapped (ACPI/NVS/MMIO)",
        info.passthrough_regions.len(),
    );

    // ── COMM capability: CARVE + REGISTER_COMM ────────────────────────────── //
    //
    // The COMM root capability is the tree anchor.  We carve a child covering
    // the entire region so it satisfies register_comm's "must be a Carve"
    // precondition.  Then register_comm binds it as dom0's DomainComm page
    // (target_domain == self, vp_id = 0 by convention for domain-level COMM).
    let _comm_child_handle = {
        use capability_engine::Access;
        let cr = &info.partition.comm_region;
        let access = Access::new(cr.base, cr.length, Rights::RW);

        let ((child_handle, _sub_handle), carve_batch) = capability_engine::execute(
            &platform, false, || {
                Capability::carve(&root_domain, comm_root_handle, access)
                    .map(|(h, s, batch)| ((h, s), batch))
            },
        )
        .expect("P2c: COMM carve failed");

        serial_println!(
            "  COMM carve: child handle {} from root {}",
            child_handle, comm_root_handle,
        );

        let _ = carve_batch; // EPT already mapped in the RAM batch above.

        // register_comm: bind to dom0 itself (self-referential DomainComm).
        capability_engine::execute(&platform, false, || {
            Capability::register_comm(
                &root_domain,
                child_handle,
                self_domain_cap_handle,
                0, // vp_id 0 = domain-level COMM
            )
            .map(|batch| ((), batch))
        })
        .expect("P2c: COMM register failed");

        serial_println!(
            "  COMM registered: handle {} → dom0 DomainComm at {:#x}",
            child_handle, cr.base,
        );
        child_handle
    };

    // ── Write binary attestation to dom0's DomainComm RX ring ────────────── //
    //
    // Now that the capability engine is initialized, we know dom0's capability
    // handles and memory ranges.  Serialize a binary attestation report and
    // enqueue it to the pre-allocated DomainComm RX ring so the thhv driver
    // can parse it at init time.
    {
        use themis_abi::domcomm;

        let mut payload = Vec::new();

        // Build the attestation header.
        let nr_mem_caps = mem_caps.len() as u32 + meta_caps.len() as u32;
        let nr_pa_entries = info.partition.dom0_owned_count as u32;
        let report = domcomm::AttestReport {
            domain_id: ROOT_ID,
            flags: 0, // dom0 is not sealed at boot
            num_vps: info.num_cores as u32,
            api_flags: u32::MAX, // dom0 has all API flags
            nr_mem_caps,
            nr_dom_caps: 1, // self-referencing domain capability for REGISTER_COMM
            nr_pa_entries,
            chunk_index: 0,
            total_chunks: 1,
            reserved: 0,
        };

        // Write report header.
        let report_bytes = unsafe {
            core::slice::from_raw_parts(
                &report as *const domcomm::AttestReport as *const u8,
                core::mem::size_of::<domcomm::AttestReport>(),
            )
        };
        payload.extend_from_slice(report_bytes);

        // Write memory capability entries (dom0-owned RAM + passthrough).
        for cap_ref in mem_caps.iter() {
            let c = cap_ref.read();
            let entry = domcomm::MemCapEntry {
                handle: c.sub_handle,
                gpa_start: c.data.access.start,  // identity mapping: GPA == HPA
                size: c.data.access.size,
                rights: c.data.access.rights.bits() as u32,
                attributes: c.owned.attributes.bits() as u32,
                hpa_start: c.data.access.start,  // identity for dom0
            };
            let entry_bytes = unsafe {
                core::slice::from_raw_parts(
                    &entry as *const domcomm::MemCapEntry as *const u8,
                    core::mem::size_of::<domcomm::MemCapEntry>(),
                )
            };
            payload.extend_from_slice(entry_bytes);
        }

        // Write META capability entries.
        for cap_ref in meta_caps.iter() {
            let c = cap_ref.read();
            let entry = domcomm::MemCapEntry {
                handle: c.sub_handle,
                gpa_start: c.data.access.start,
                size: c.data.access.size,
                rights: c.data.access.rights.bits() as u32,
                attributes: c.owned.attributes.bits() as u32,
                hpa_start: c.data.access.start,
            };
            let entry_bytes = unsafe {
                core::slice::from_raw_parts(
                    &entry as *const domcomm::MemCapEntry as *const u8,
                    core::mem::size_of::<domcomm::MemCapEntry>(),
                )
            };
            payload.extend_from_slice(entry_bytes);
        }

        // Write self-referencing domain capability entry.
        // The driver needs this handle to call REGISTER_COMM(cap, self, 0)
        // for ring growth pages (self-ref COMM).
        {
            let entry = domcomm::DomCapEntry {
                handle: self_domain_cap_handle,
                domain_id: ROOT_ID,
            };
            let entry_bytes = unsafe {
                core::slice::from_raw_parts(
                    &entry as *const domcomm::DomCapEntry as *const u8,
                    core::mem::size_of::<domcomm::DomCapEntry>(),
                )
            };
            payload.extend_from_slice(entry_bytes);
        }

        // Write PA map entries (identity mapping for dom0: GPA == HPA).
        for region in &info.partition.dom0_owned[..info.partition.dom0_owned_count] {
            if region.length == 0 {
                continue;
            }
            let entry = domcomm::PaMapEntry {
                gpa_start: region.base,
                hpa_start: region.base,  // identity
                size: region.length,
            };
            let entry_bytes = unsafe {
                core::slice::from_raw_parts(
                    &entry as *const domcomm::PaMapEntry as *const u8,
                    core::mem::size_of::<domcomm::PaMapEntry>(),
                )
            };
            payload.extend_from_slice(entry_bytes);
        }

        platform.bootstrap_write_attestation(ROOT_ID, &payload);
        serial_println!(
            "  DomainComm: attestation written ({} bytes, {} mem_caps, 1 dom_cap, {} pa_entries)",
            payload.len(), nr_mem_caps, nr_pa_entries,
        );
    }

    serial_println!("=== P2c: done ===");

    CapaState {
        platform,
        root_domain,
        mem_caps,
        meta_caps,
    }
}

// ── Phase 2d: VMCS allocation and setup ──────────────────────────────────── //

/// Phase P2d: allocate and initialise a VMCS for each dom0 VP.
///
/// - Allocates VMCS and VAPIC pages from `vmx.dom0.meta` (the VMX-fixed sub-pool).
/// - Sets up the BSP VMCS fully; sets up AP VMCS with wait-for-SIPI activity state.
/// - Stores AP InactiveVcpus directly into the ThemisPlatform's dom0 PlatformDomain.
/// - BSP InactiveVcpu is created later in `launch()` after P7f patches RIP/RSP.
/// - After return, BSP VMCS is the current VMCS on this core (P7f will patch RIP/RSP).
/// - HOST_RSP is not set here — `vcpu.run()` sets it dynamically to the caller's stack.
pub fn vmcs(info: &PlatformInfo, vmx: &mut VmxState, capa: &CapaState) {
    use crate::vmcs::setup_vmcs_for_vp;
    use x86::bits64::vmx;
    use x86::vmx::vmcs;

    serial_println!();
    serial_println!("=== P2d: VMCS setup ===");

    // Set up our own GDT (null + code64 + data + per-core TSS) and load TR.
    // Limine does not set TR, so `str` would return 0 without this step,
    // causing VMLAUNCH error 8 ("VM entry with invalid host-state field(s)").
    crate::gdt::init();
    crate::gdt::load_for_core(0); // BSP = core 0
    serial_println!(
        "  GDT loaded: base={:#x}  TR selector={:#06x}  TR base={:#x}",
        crate::gdt::gdtr_base(),
        crate::gdt::tss_selector(0),
        crate::gdt::tss_base(0)
    );

    let num_vps = info.num_cores;
    let eptp = capa
        .platform
        .eptp(0)
        .expect("P2d: EPT root not set up — run boot::capa() first");

    // Allocate VMCS, VAPIC, and MSR bitmap pages from the META pool via ThemisPlatform.
    vmx.dom0
        .alloc_vmcs_regions(&capa.platform, num_vps, vmx.features.vmcs_revision_id);
    vmx.dom0.alloc_vapic_regions(&capa.platform, num_vps);
    vmx.dom0.alloc_msr_bitmap(&capa.platform);

    serial_println!(
        "  Allocated {} VMCS + {} VAPIC + 1 MSR-bitmap pages from META pool",
        num_vps,
        num_vps,
    );

    // Set up the VMCS for the BSP VP (vp_index = bsp_index).
    // BSP's InactiveVcpu is created later in launch() after P7f patches RIP/RSP.
    let vp = vmx.bsp_index;

    unsafe {
        setup_vmcs_for_vp(
            vmx.dom0.vmcs_phys(vp),
            vmx.dom0.vapic_phys(vp),
            vmx.dom0.msr_bitmap_phys(),
            eptp,
            vp,
        );
    }

    serial_println!(
        "  BSP VMCS ready: vp={} vmcs={:#x}",
        vp,
        vmx.dom0.vmcs_phys(vp),
    );

    // Set up VMCS for each AP VP.
    // Each AP is configured with activity state = wait-for-SIPI (3) so it sits
    // dormant until Linux sends INIT/SIPI.  After setup, the VMCS is stored
    // to memory with VMCLEAR so the AP can load it with VMPTRLD at launch time.
    // AP InactiveVcpus are stored directly in the PlatformDomain.
    let msr_bitmap_phys = vmx.dom0.msr_bitmap_phys();

    for ap_vp in 0..num_vps {
        if ap_vp == vmx.bsp_index {
            continue;
        }
        unsafe {
            setup_vmcs_for_vp(
                vmx.dom0.vmcs_phys(ap_vp),
                vmx.dom0.vapic_phys(ap_vp),
                vmx.dom0.msr_bitmap_phys(),
                eptp,
                ap_vp,
            );
            // Override activity state: AP must not enter the kernel entry point
            // directly — it waits for a SIPI from the Linux BSP.
            vmx::vmwrite(vmcs::guest::ACTIVITY_STATE, 3).expect("AP vmwrite ACTIVITY_STATE");
            // Disable the preemption timer for wait-for-SIPI APs.
            vmx::vmwrite(vmcs::guest::VMX_PREEMPTION_TIMER_VALUE, u64::MAX >> 32)
                .expect("AP vmwrite preemption timer max");
            // Save VMCS state to memory and deactivate.
            vmx::vmclear(vmx.dom0.vmcs_phys(ap_vp)).expect("AP vmclear");
        }
        // Create InactiveVcpu and store directly in PlatformDomain (dom0, vp_id = ap_vp).
        let vcpu = crate::vcpu::InactiveVcpu::new(
            vmx.dom0.vmcs_phys(ap_vp),
            vmx.dom0.vapic_phys(ap_vp),
            msr_bitmap_phys,
            0, // dom0 VPs have no Posted-Interrupt Descriptor
            (ap_vp + 1) as u16,
        );
        capa.platform.bootstrap_store_vcpu(0, ap_vp, vcpu);
        serial_println!(
            "  AP VMCS ready:  vp={} vmcs={:#x} (wait-for-SIPI)",
            ap_vp,
            vmx.dom0.vmcs_phys(ap_vp),
        );
    }

    // Restore BSP VMCS as the current VMCS on this core so that P7f can
    // vmwrite guest RIP/RSP into the correct VMCS.
    if num_vps > 1 {
        unsafe {
            vmx::vmptrld(vmx.dom0.vmcs_phys(vmx.bsp_index)).expect("BSP vmptrld restore");
        }
    }
    serial_println!("=== P2d: done ===");
}

// ── Phase 7f output ───────────────────────────────────────────────────────── //

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

// ── Phase 7f: Linux kernel loading ───────────────────────────────────────── //

/// Phase P7f: load a Linux bzImage into dom0 physical memory, write
/// `struct boot_params`, and patch the VMCS guest `RIP`/`RSP`.
///
/// Entry model: **32-bit protected-mode via the decompressor** (UNRESTRICTED_GUEST,
/// PE=1, no paging).  dom0's page tables are allocated from its own normal memory
/// by the Linux decompressor — Themis has no involvement in CR3 setup.
///
/// The [`LinuxState`] returned carries `boot_params_phys` for use by P7g, which
/// must load it into ESI before executing VMLAUNCH.
pub fn linux(info: &PlatformInfo, modules: &[crate::guest::ModuleInfo]) -> LinuxState {
    use crate::guest::{find_module, linux as lx};
    use x86::bits64::vmx;
    use x86::vmx::vmcs::guest;

    serial_println!();
    serial_println!("=== P7f: Linux kernel load ===");

    // ── Locate modules ───────────────────────────────────────────────────── //
    let kernel_mod = find_module(modules, "dom0-kernel")
        .expect("P7f: 'dom0-kernel' module not found — check limine.conf");
    let initrd_mod = find_module(modules, "dom0-initrd");
    if initrd_mod.is_none() {
        serial_println!("  (no dom0-initrd module)");
    }

    // ── Strip DMAR from ACPI tables exposed to dom0 ──────────────────────── //
    // Write DMAR-stripped RSDP + XSDT copies into dom0 memory so Linux never
    // discovers VT-d hardware.  Falls back to 0 (Linux scans for RSDP) if there
    // is no DMAR table or the platform uses ACPI 1.0.
    let acpi_rsdp_addr =
        crate::acpi::strip_dmar(info.acpi.rsdp_phys, lx::ACPI_COPY_PHYS, info.hhdm_offset)
            .unwrap_or(0);

    // ── Load kernel + initrd, write boot_params ──────────────────────────── //
    let load = lx::load_linux(
        kernel_mod,
        initrd_mod,
        info.hhdm_offset,
        &info.partition.dom0_owned[..info.partition.dom0_owned_count],
        &info.partition.meta_regions[..info.partition.meta_count],
        &info.partition.comm_region,
        &info.non_ram_e820,
        acpi_rsdp_addr,
        // intel_iommu=off kept as belt-and-suspenders in case DMAR stripping
        // is incomplete; can be removed once P7f-dmar is fully verified.
        // systemd.mask=boot-efi.mount: the EFI partition (vda15) fails because
        // the custom kernel lacks NLS iso8859-1; masking it avoids emergency mode.
        "console=ttyS0,115200 earlyprintk=serial,ttyS0,115200 keep_bootcon intel_iommu=off nokaslr nopv root=/dev/vda1 rw loglevel=8 ignore_loglevel systemd.mask=boot-efi.mount systemd.mask=multipathd.service",
    );

    // ── Patch VMCS guest RIP and RSP ─────────────────────────────────────── //
    // The VMCS for the BSP VP is still loaded (VMPTRLD'd) from P2d.
    // RSI (boot_params address) is a GPR — it cannot be vmwrite'd; P7g sets it
    // in the inline asm immediately before VMLAUNCH.
    unsafe {
        vmx::vmwrite(guest::RIP, load.kernel_entry_phys).expect("P7f: vmwrite guest RIP");
        vmx::vmwrite(guest::RSP, lx::INITIAL_RSP_PHYS).expect("P7f: vmwrite guest RSP");
    }

    serial_println!(
        "  VMCS patched: RIP={:#x} RSP={:#x}  (RSI={:#x} set at VMLAUNCH)",
        load.kernel_entry_phys,
        lx::INITIAL_RSP_PHYS,
        load.boot_params_phys,
    );
    serial_println!("=== P7f: done ===");

    LinuxState {
        kernel_entry_phys: load.kernel_entry_phys,
        boot_params_phys: load.boot_params_phys,
    }
}

// ── Phase 7g: VMLAUNCH ────────────────────────────────────────────────────── //

/// Phase P7g: signal APs and execute VMLAUNCH on the BSP.
///
/// 1. Sets `AP_LAUNCH_READY` (Release) so each AP wakes up, enables VMX,
///    loads its VMCS, and enters the monitor loop.
/// 2. BSP creates an `ActiveVcpu` from the loaded VMCS, sets RSI to
///    `boot_params_phys`, and enters the monitor loop.
///
/// This function never returns.
pub fn launch(linux: &LinuxState, vmx: &VmxState, platform: &crate::platform::ThemisPlatform) -> ! {
    use crate::AP_LAUNCH_READY;
    use crate::vcpu::{InactiveVcpu, Reg};
    use crate::vmexit::monitor_loop;
    use core::sync::atomic::Ordering;

    serial_println!();
    serial_println!("=== P7g: VMLAUNCH ===");

    // Release store: PLATFORM_PTR writes (including vmxon_phys inside the
    // platform) are visible to any core that loads AP_LAUNCH_READY with
    // Acquire ordering.
    AP_LAUNCH_READY.store(true, Ordering::Release);
    serial_println!("  APs signaled");

    // ── Set XCR0 before VMLAUNCH ────────────────────────────────────────── //
    unsafe {
        let cpuid_d = core::arch::x86_64::__cpuid_count(0xD, 0);
        let max_xcr0 = ((cpuid_d.edx as u64) << 32) | (cpuid_d.eax as u64);
        let max_xcr0 = max_xcr0 | 1;
        serial_println!("  BSP: setting XCR0={:#x} before VMLAUNCH", max_xcr0);
        core::arch::asm!(
            "xsetbv",
            in("ecx") 0u32,
            in("eax") max_xcr0 as u32,
            in("edx") (max_xcr0 >> 32) as u32,
            options(nomem, nostack),
        );
    }

    // ── Create BSP InactiveVcpu, store in PlatformDomain, then take it ─── //
    let bsp_vmcs_phys = vmx.dom0.vmcs_phys(vmx.bsp_index);
    let bsp_vapic_phys = vmx.dom0.vapic_phys(vmx.bsp_index);
    let bsp_msr_bitmap_phys = vmx.dom0.msr_bitmap_phys();
    let bsp_vpid = (vmx.bsp_index + 1) as u16;

    // VMCLEAR the currently-loaded BSP VMCS so we can wrap it in InactiveVcpu.
    // InactiveVcpu::activate() will VMPTRLD it back.
    unsafe {
        x86::bits64::vmx::vmclear(bsp_vmcs_phys).expect("BSP vmclear for vcpu");
    }

    let mut inactive = InactiveVcpu::new(bsp_vmcs_phys, bsp_vapic_phys, bsp_msr_bitmap_phys, 0, bsp_vpid);

    // Set RSI = boot_params_phys (Linux boot protocol requirement).
    inactive.set_reg(Reg::Rsi, linux.boot_params_phys);

    // Store BSP vcpu in PlatformDomain, then immediately take it.
    // This ensures the PlatformDomain has a complete VP table (all VP IDs
    // are registered) even though the BSP VP is immediately active.
    platform.bootstrap_store_vcpu(0, vmx.bsp_index, inactive);
    let inactive = platform.take_vcpu(0, vmx.bsp_index)
        .expect("BSP: failed to take vcpu from PlatformDomain");

    serial_println!("  BSP: RSI={:#x} → monitor_loop", linux.boot_params_phys);

    let mut vcpu = inactive.activate().expect("BSP activate failed");

    // Enter the monitor loop — never returns.
    monitor_loop(&mut vcpu);
}
