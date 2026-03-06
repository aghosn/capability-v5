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
use crate::mem::{MemoryPartition, PhysRegion, PhysicalInventory};
use crate::pci::PciDevice;
use crate::vmx::CpuFeatures;
use crate::{serial_print, serial_println, AP_READY_COUNT, SERIAL_LOCK};

use core::sync::atomic::Ordering;

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
    pub pci_devices: Option<Vec<PciDevice>>,
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
    // ── Phase 1a: Memory map + heap ──────────────────────────────────────── //

    serial_println!("HHDM offset: {:#x}", hhdm_offset);
    serial_println!("Memory map: {} entries", entries.len());

    for entry in entries.iter() {
        let kind = match entry.entry_type {
            limine::memory_map::EntryType::USABLE              => "usable",
            limine::memory_map::EntryType::RESERVED            => "reserved",
            limine::memory_map::EntryType::ACPI_RECLAIMABLE    => "acpi-reclaim",
            limine::memory_map::EntryType::ACPI_NVS            => "acpi-nvs",
            limine::memory_map::EntryType::BAD_MEMORY          => "bad",
            limine::memory_map::EntryType::BOOTLOADER_RECLAIMABLE => "bootloader",
            limine::memory_map::EntryType::EXECUTABLE_AND_MODULES => "kernel+modules",
            limine::memory_map::EntryType::FRAMEBUFFER         => "framebuffer",
            _ => "unknown",
        };
        serial_println!("  {:#012x}–{:#012x}  {:>8} KiB  {}",
            entry.base, entry.base + entry.length, entry.length / 1024, kind);
    }

    let inventory = PhysicalInventory::from_limine(entries, hhdm_offset);
    serial_println!();
    serial_println!("Total usable RAM:  {} MiB", inventory.total_usable / (1024 * 1024));
    serial_println!("Heap carved at:    {:#x} ({} MiB)",
        inventory.heap_phys, inventory.heap_size / (1024 * 1024));
    serial_println!("Remaining usable:  {} MiB ({} regions)",
        inventory.available_bytes() / (1024 * 1024),
        inventory.usable_regions().len());

    {
        let mut v = alloc::vec![1u64, 2, 3];
        v.push(4);
        serial_println!("Heap check:        alloc::vec![1,2,3,4] → len={} ✓", v.len());
    }

    // ── Phase 1b: Memory partitioning ────────────────────────────────────── //

    let num_cores = cpus.len();
    serial_println!();
    serial_println!("CPUs: {} cores (BSP + {} APs)", num_cores, num_cores - 1);

    let partition = inventory.partition(num_cores as u64);

    serial_println!();
    serial_println!("Memory partitioning:");
    serial_println!("  META pool:  {:#x}–{:#x}  ({} KiB, {} pages)",
        partition.meta_pool.base,
        partition.meta_pool.base + partition.meta_pool.length,
        partition.meta_pool.length / 1024,
        partition.meta_breakdown.total_pages);
    serial_println!("    VMXON: {} pages  VMCS: {} pages  VAPIC: {} pages  EPT: {} pages",
        partition.meta_breakdown.vmxon_pages,
        partition.meta_breakdown.vmcs_pages,
        partition.meta_breakdown.vapic_pages,
        partition.meta_breakdown.ept_pages);

    let dom0_total: u64 = partition.dom0_owned[..partition.dom0_owned_count]
        .iter().map(|r| r.length).sum();
    serial_println!("  dom0 owned: {} MiB ({} regions)",
        dom0_total / (1024 * 1024), partition.dom0_owned_count);

    // ── Phase 1c: SMP bootstrap ───────────────────────────────────────────── //

    serial_println!();
    let num_aps = num_cores as u64 - 1;
    serial_println!("SMP: BSP LAPIC {} — waking {} APs ...", bsp_lapic_id, num_aps);

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
    for entry in entries.iter() {
        match entry.entry_type {
            limine::memory_map::EntryType::ACPI_RECLAIMABLE
            | limine::memory_map::EntryType::ACPI_NVS
            | limine::memory_map::EntryType::RESERVED => {
                crate::mem::map_phys_range(entry.base, entry.length, hhdm_offset);
            }
            _ => {}
        }
    }

    serial_println!("ACPI: RSDP at phys {:#x}", rsdp_phys);
    let acpi = AcpiInfo::parse(rsdp_phys, hhdm_offset);

    serial_println!("ACPI: {} processors, {} I/O APICs, VT-d: {}",
        acpi.processors.len(), acpi.io_apics.len(),
        if acpi.has_dmar { "present" } else { "absent" });

    if let Some(ref regions) = acpi.pci_config_regions {
        serial_println!("ACPI: {} PCIe ECAM region(s)", regions.regions.len());
    } else {
        serial_println!("ACPI: no MCFG (no PCIe ECAM)");
    }

    // ── Phase 1e: PCI enumeration ─────────────────────────────────────────── //

    serial_println!();
    let pci_devices = crate::pci::enumerate(&acpi, hhdm_offset);
    if let Some(ref devices) = pci_devices {
        serial_println!("PCI: {} device(s) found", devices.len());
        for dev in devices {
            let a = dev.address;
            serial_println!("  {:02x}:{:02x}.{}  {:04x}:{:04x}  class={:02x}.{:02x}.{:02x}",
                a.bus(), a.device(), a.function(),
                dev.vendor_id, dev.device_id,
                dev.class, dev.subclass, dev.interface);
        }
    } else {
        serial_println!("PCI: no ECAM — skipping enumeration");
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
    }
}

// ── Phase 2a-b: VMX init ─────────────────────────────────────────────────── //

/// Phase 2a–2b: detect VMX features, allocate VMXON regions from the platform's
/// META pool, and execute VMXON on the BSP.
///
/// `platform` must already have domain 0 registered and its META pool populated
/// (call `init_themis` first).
pub fn vmx(info: &PlatformInfo, platform: &crate::platform::ThemisPlatform) -> VmxState {
    // P2a — CPU feature detection.
    let features = crate::vmx::detect_features(info.acpi.has_dmar);

    serial_println!();
    serial_println!("CPU features:");
    serial_println!("  VMX: {}  x2APIC: {}  APICv: {}  VT-d: {}",
        if features.vmx { "yes" } else { "NO" },
        if features.x2apic { "yes" } else { "no" },
        if features.has_apicv() { "full" } else { "partial/none" },
        if features.vtd { "yes" } else { "no" });
    serial_println!("  VMCS rev: {:#x}  phys bits: {}  region size: {} B",
        features.vmcs_revision_id, features.phys_addr_bits, features.vmx_region_size);

    assert!(features.vmx, "VMX not supported — cannot continue");

    // P2b — Allocate VMXON regions from ThemisPlatform META and run VMXON on BSP.
    let mut dom0 = Domain::new(0, info.hhdm_offset);
    dom0.alloc_vmxon_regions(platform, info.num_cores, features.vmcs_revision_id);

    serial_println!();
    serial_println!("dom0: allocated {} VMXON pages from META pool",
        info.num_cores);

    let bsp_index = info.cpu_lapic_ids.iter()
        .position(|&id| id == info.bsp_lapic_id)
        .expect("BSP LAPIC ID not found in CPU list");

    crate::vmx::enable_vmx_on_core(dom0.vmxon_phys(bsp_index))
        .expect("VMXON failed on BSP");
    serial_println!("VMX: VMXON on BSP (LAPIC {}, index {}) ✓",
        info.bsp_lapic_id, bsp_index);

    VmxState { features, dom0, bsp_index }
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

    // Map the META pool into the HHDM before any allocations touch it.
    crate::mem::map_phys_range(
        info.partition.meta_pool.base,
        info.partition.meta_pool.length,
        info.hhdm_offset,
    );

    let platform = ThemisPlatform::new();
    platform.bootstrap_set_lapic_ids(info.cpu_lapic_ids.clone());
    platform.bootstrap_register_domain(ROOT_ID, None, info.hhdm_offset);
    // Hand the FULL meta_pool to the platform — all hardware allocations
    // (VMXON, VMCS, VAPIC, EPT) come from this single pool.
    platform.bootstrap_give_meta(ROOT_ID, info.partition.meta_pool);

    serial_println!(
        "ThemisPlatform: META pool {:#x}+{:#x} ({} KiB, {} pages total)",
        info.partition.meta_pool.base,
        info.partition.meta_pool.length,
        info.partition.meta_pool.length / 1024,
        info.partition.meta_pool.length / 4096,
    );
    serial_println!(
        "  breakdown: {} VMXON + {} VMCS + {} VAPIC + {} EPT pages",
        info.partition.meta_breakdown.vmxon_pages,
        info.partition.meta_breakdown.vmcs_pages,
        info.partition.meta_breakdown.vapic_pages,
        info.partition.meta_breakdown.ept_pages,
    );

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
    pub mem_caps: Vec<capability_engine::CapabilityRef<capability_engine::MemoryRegion>>,
}

// ── Phase 2c: Capability engine + EPT ────────────────────────────────────── //

/// Phase P2c: initialise the capability engine for dom0.
///
/// Receives the already-bootstrapped `ThemisPlatform` (domain 0 registered, full
/// META pool given).  Builds the capability tree and drives an `UpdateBatch` of
/// `ChangeRights` to map every dom0-owned region into the EPT.
pub fn capa(info: &PlatformInfo, platform: crate::platform::ThemisPlatform) -> CapaState {
    use alloc::sync::Arc;
    use capability_engine::{
        Capability, Domain as CapaDomain, DomainId, MemoryRegion, Rights, UpdateBatch,
    };

    const ROOT_ID: DomainId = 0;

    serial_println!();
    serial_println!("=== P2c: capability engine init ===");

    // ── Root domain capability ─────────────────────────────────────────── //

    let root_domain = Capability::new_root(
        ROOT_ID,
        0,
        CapaDomain::new_root(info.num_cores),
    );

    // ── Memory capabilities ────────────────────────────────────────────── //

    let mut mem_caps: Vec<capability_engine::CapabilityRef<MemoryRegion>> = Vec::new();
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
            dom.data.add_memory_capability(sub, Arc::downgrade(&mem_cap));
            serial_println!(
                "  mem cap #{}: {:#x}+{:#x} ({} KiB)",
                sub, region.base, region.length, region.length / 1024,
            );
            mem_caps.push(mem_cap);
            sub += 1;
        }
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
                region.base,  // GPA (identity)
                region.length,
                region.base,  // HPA
                Rights::RWX,
                false,
            );
        }
        b
    };

    capability_engine::execute(&platform, false, || Ok(((), batch)))
        .expect("P2c: capability engine execute failed");

    let eptp = platform.eptp(ROOT_ID)
        .expect("P2c: EPT root not allocated after execute");

    serial_println!(
        "  EPT built for dom0: {} regions, EPTP = {:#x}",
        info.partition.dom0_owned_count, eptp,
    );
    serial_println!("=== P2c: done ===");

    CapaState { platform, root_domain, mem_caps }
}

// ── Phase 2d output ───────────────────────────────────────────────────────── //

/// State produced by VMCS setup (Phase P2d).
pub struct VmcsState {
    /// Per-VP host stacks (heap-allocated, one per VP).
    /// Kept alive here to prevent deallocation.
    pub host_stacks: Vec<alloc::boxed::Box<[u8; HOST_STACK_BYTES]>>,
}

/// Size of each per-VP host VMX stack in bytes.
pub const HOST_STACK_BYTES: usize = 4096 * 4; // 16 KiB

// ── Phase 2d: VMCS allocation and setup ──────────────────────────────────── //

/// Phase P2d: allocate and initialise a VMCS for each dom0 VP.
///
/// - Allocates VMCS and VAPIC pages from `vmx.dom0.meta` (the VMX-fixed sub-pool).
/// - Allocates per-VP host stacks from the heap.
/// - Calls [`crate::vmcs::setup_vmcs_for_vp`] for each VP (BSP VP only for now).
/// - Records all per-VP state in `VmcsState`.
pub fn vmcs(info: &PlatformInfo, vmx: &mut VmxState, capa: &CapaState) -> VmcsState {
    use alloc::boxed::Box;
    use crate::vmcs::setup_vmcs_for_vp;

    serial_println!();
    serial_println!("=== P2d: VMCS setup ===");

    let num_vps = info.num_cores;
    let eptp = capa.platform.eptp(0)
        .expect("P2d: EPT root not set up — run boot::capa() first");

    // Allocate VMCS and VAPIC pages from the META pool via ThemisPlatform.
    vmx.dom0.alloc_vmcs_regions(&capa.platform, num_vps, vmx.features.vmcs_revision_id);
    vmx.dom0.alloc_vapic_regions(&capa.platform, num_vps);

    serial_println!(
        "  Allocated {} VMCS + {} VAPIC pages from META pool",
        num_vps, num_vps,
    );

    // Per-VP host stacks (heap, not META — stacks need no physical-contiguity).
    let mut host_stacks: Vec<Box<[u8; HOST_STACK_BYTES]>> = Vec::with_capacity(num_vps);
    for _ in 0..num_vps {
        host_stacks.push(Box::new([0u8; HOST_STACK_BYTES]));
    }

    // Set up the VMCS for the BSP VP (vp_index = bsp_index).
    // APs get their VMCS loaded at VMLAUNCH time (P7g mailbox).
    let vp = vmx.bsp_index;
    let stack = &host_stacks[vp];
    let stack_top = stack.as_ptr() as u64 + HOST_STACK_BYTES as u64;
    // Align to 16 bytes (required by System V ABI for CALL).
    let stack_top_aligned = stack_top & !0xF;

    unsafe {
        setup_vmcs_for_vp(
            vmx.dom0.vmcs_phys(vp),
            vmx.dom0.vapic_phys(vp),
            stack_top_aligned,
            eptp,
            vp,
        );
    }

    serial_println!(
        "  BSP VMCS ready: vp={} vmcs={:#x} stack_top={:#x}",
        vp, vmx.dom0.vmcs_phys(vp), stack_top_aligned,
    );
    serial_println!("=== P2d: done ===");

    VmcsState { host_stacks }
}
