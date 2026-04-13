//! ACPI table discovery and parsing.
//!
//! Implements the `acpi::Handler` trait using the Limine HHDM (Higher-Half
//! Direct Map) to translate physical addresses to virtual ones.  Extracts:
//!
//! - **MADT**: processor topology (LAPIC IDs, I/O APIC addresses, ISO overrides)
//! - **MCFG**: PCIe ECAM base addresses per segment/bus range
//! - **DMAR**: VT-d remapping table — DRHD unit enumeration + IR capability check

use alloc::vec::Vec;
use core::ptr::NonNull;

use acpi::{
    aml::AmlError,
    platform::PciConfigRegions,
    sdt::{
        madt::{Madt, MadtEntry},
        mcfg::Mcfg,
    },
    AcpiTables, Handle, Handler, PhysicalMapping,
};

// ── HHDM-based ACPI handler ────────────────────────────────────────────── //

/// ACPI handler that translates physical → virtual via the Limine HHDM offset.
#[derive(Clone)]
pub struct HhdmHandler {
    hhdm_offset: u64,
}

impl HhdmHandler {
    pub fn new(hhdm_offset: u64) -> Self {
        Self { hhdm_offset }
    }

    fn phys_to_virt(&self, phys: usize) -> usize {
        phys + self.hhdm_offset as usize
    }
}

impl Handler for HhdmHandler {
    unsafe fn map_physical_region<T>(
        &self,
        physical_address: usize,
        size: usize,
    ) -> PhysicalMapping<Self, T> {
        let virt = self.phys_to_virt(physical_address);
        PhysicalMapping {
            physical_start: physical_address,
            virtual_start: NonNull::new(virt as *mut T).unwrap(),
            region_length: size,
            mapped_length: size,
            handler: self.clone(),
        }
    }

    fn unmap_physical_region<T>(_region: &PhysicalMapping<Self, T>) {
        // HHDM is identity-mapped at boot — nothing to unmap.
    }

    fn read_u8(&self, address: usize) -> u8 {
        unsafe { core::ptr::read_volatile(self.phys_to_virt(address) as *const u8) }
    }
    fn read_u16(&self, address: usize) -> u16 {
        unsafe { core::ptr::read_volatile(self.phys_to_virt(address) as *const u16) }
    }
    fn read_u32(&self, address: usize) -> u32 {
        unsafe { core::ptr::read_volatile(self.phys_to_virt(address) as *const u32) }
    }
    fn read_u64(&self, address: usize) -> u64 {
        unsafe { core::ptr::read_volatile(self.phys_to_virt(address) as *const u64) }
    }

    fn write_u8(&self, address: usize, value: u8) {
        unsafe { core::ptr::write_volatile(self.phys_to_virt(address) as *mut u8, value) }
    }
    fn write_u16(&self, address: usize, value: u16) {
        unsafe { core::ptr::write_volatile(self.phys_to_virt(address) as *mut u16, value) }
    }
    fn write_u32(&self, address: usize, value: u32) {
        unsafe { core::ptr::write_volatile(self.phys_to_virt(address) as *mut u32, value) }
    }
    fn write_u64(&self, address: usize, value: u64) {
        unsafe { core::ptr::write_volatile(self.phys_to_virt(address) as *mut u64, value) }
    }

    fn read_io_u8(&self, port: u16) -> u8 {
        let val: u8;
        unsafe {
            core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack))
        };
        val
    }
    fn read_io_u16(&self, port: u16) -> u16 {
        let val: u16;
        unsafe {
            core::arch::asm!("in ax, dx", out("ax") val, in("dx") port, options(nomem, nostack))
        };
        val
    }
    fn read_io_u32(&self, port: u16) -> u32 {
        let val: u32;
        unsafe {
            core::arch::asm!("in eax, dx", out("eax") val, in("dx") port, options(nomem, nostack))
        };
        val
    }

    fn write_io_u8(&self, port: u16, value: u8) {
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack))
        };
    }
    fn write_io_u16(&self, port: u16, value: u16) {
        unsafe {
            core::arch::asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack))
        };
    }
    fn write_io_u32(&self, port: u16, value: u32) {
        unsafe {
            core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack))
        };
    }

    fn read_pci_u8(&self, _address: acpi::PciAddress, _offset: u16) -> u8 {
        // TODO: PCI config space reads via ECAM MMIO (needed for full ACPI parsing).
        0
    }
    fn read_pci_u16(&self, _address: acpi::PciAddress, _offset: u16) -> u16 {
        0
    }
    fn read_pci_u32(&self, _address: acpi::PciAddress, _offset: u16) -> u32 {
        0
    }

    fn write_pci_u8(&self, _address: acpi::PciAddress, _offset: u16, _value: u8) {}
    fn write_pci_u16(&self, _address: acpi::PciAddress, _offset: u16, _value: u16) {}
    fn write_pci_u32(&self, _address: acpi::PciAddress, _offset: u16, _value: u32) {}

    fn nanos_since_boot(&self) -> u64 {
        // Read TSC as a rough monotonic clock.
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    fn stall(&self, microseconds: u64) {
        // Busy-wait using TSC.  ~1 GHz ≈ 1000 ticks/µs; good enough for ACPI stalls.
        let start = unsafe { core::arch::x86_64::_rdtsc() };
        let ticks = microseconds * 1000;
        while unsafe { core::arch::x86_64::_rdtsc() } - start < ticks {
            core::hint::spin_loop();
        }
    }

    fn sleep(&self, milliseconds: u64) {
        self.stall(milliseconds * 1000);
    }

    fn create_mutex(&self) -> Handle {
        // We don't use AML interpretation at boot; return a dummy handle.
        Handle(0)
    }

    fn acquire(&self, _mutex: Handle, _timeout: u16) -> Result<(), AmlError> {
        // Single-threaded during ACPI parsing — no contention.
        Ok(())
    }

    fn release(&self, _mutex: Handle) {}
}

// ── Parsed ACPI info ────────────────────────────────────────────────────── //

/// Processor descriptor extracted from the MADT.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessorInfo {
    pub processor_uid: u32,
    pub local_apic_id: u32,
}

/// I/O APIC descriptor extracted from the MADT.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct IoApic {
    pub id: u8,
    pub address: u32,
    pub gsi_base: u32,
}

/// Interrupt Source Override from the MADT.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct Iso {
    pub bus: u8,
    pub irq: u8,
    pub gsi: u32,
    pub flags: u16,
}

// ── VT-d / DMAR structures ─────────────────────────────────────────────── //

// ── TPM 2.0 ACPI table ────────────────────────────────────────────────── //

/// TPM 2.0 information extracted from the ACPI TPM2 table.
///
/// The TPM2 table confirms device presence and provides the start method.
/// On x86, the TIS MMIO base is always `0xFED4_0000` (TCG PC Client spec);
/// for CRB, the control area address gives the CRB register base.
#[derive(Debug, Clone, Copy)]
pub struct TpmInfo {
    /// Address of the CRB control area (u64).
    /// For TIS: typically 0.  For CRB: e.g. `0xFED4_0040`.
    pub control_area: u64,
    /// Start method from the TPM2 table.
    /// 6 = Memory-mapped I/O, 7 = CRB, 8 = CRB with ACPI start.
    pub start_method: u32,
}

// ── VT-d / DMAR structures (continued) ─────────────────────────────────── //

/// One PCIe ECAM (Enhanced Configuration Access Mechanism) region from MCFG.
///
/// Covers a contiguous range of PCI buses on a single PCI segment.
#[derive(Debug, Clone)]
pub struct EcamRegion {
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
    /// ECAM base address (used when PCI passthrough is wired).
    #[allow(dead_code)]
    pub base_phys: u64,
}

impl EcamRegion {
    /// Number of PCI buses covered by this region.
    pub fn bus_count(&self) -> u64 {
        (self.end_bus as u64).saturating_sub(self.start_bus as u64) + 1
    }
}

/// VT-d Specification §8.3 — DMA Remapping Hardware Unit Definition.
///
/// One `DhrdUnit` corresponds to one DRHD structure in the DMAR table.
/// Each unit has its own MMIO register block and its own Interrupt
/// Remapping Table (IRT) allocated in intr-p3b.
#[derive(Debug, Clone)]
pub struct DhrdUnit {
    /// Physical base address of the DRHD MMIO register block.
    pub register_base: u64,
    /// PCI segment number (usually 0).
    pub segment: u16,
    /// DRHD flags byte (bit 0 = INCLUDE_PCI_ALL).
    pub flags: u8,
    /// Whether this unit supports interrupt remapping (CAP register bit 16 / ECAP[3]).
    pub ir_supported: bool,
    /// Physical address of the 4 KiB IRT page allocated for this unit (intr-p3b).
    /// Zero until `init_themis` allocates the page from the META pool.
    pub irt_phys: u64,
    /// Physical address of the 4 KiB root table page for DMA remapping (P4b).
    /// Zero until `init_themis` allocates it from the META pool.
    pub root_phys: u64,
    /// Adjusted guest-address width for second-level page tables (from CAP.SAGAW).
    /// 1 = 39-bit / 3-level; 2 = 48-bit / 4-level.  Set by P4b init.
    pub aw: u64,
    /// Context table pages keyed by bus number: `(bus, ctx_page_phys)`.
    /// Populated in `init_themis` for every bus in this unit's PCI segment.
    pub ctx_tables: Vec<(u8, u64)>,
}

/// Summary of all ACPI information needed by Themis.
pub struct AcpiInfo {
    /// Physical address of the RSDP as given by Limine.
    pub rsdp_phys: u64,
    /// Processor topology from MADT (BSP + APs with LAPIC IDs).
    pub processors: Vec<ProcessorInfo>,
    /// I/O APICs from MADT.
    pub io_apics: Vec<IoApic>,
    /// Interrupt source overrides from MADT.
    #[allow(dead_code)]
    pub isos: Vec<Iso>,
    /// Whether the platform has legacy 8259 PICs.
    #[allow(dead_code)]
    pub has_legacy_pics: bool,
    /// PCIe ECAM regions from MCFG (segment → base address + bus range).
    pub pci_config_regions: Option<PciConfigRegions>,
    /// Flat list of ECAM regions for IOMMU table sizing (same data as
    /// `pci_config_regions` but in a simpler form for boot-time computation).
    pub ecam_regions: Vec<EcamRegion>,
    /// TPM 2.0 information from the ACPI TPM2 table (if present).
    pub tpm: Option<TpmInfo>,
    /// Whether a DMAR table was found (VT-d available).
    pub has_dmar: bool,
    /// DRHD units from the DMAR table (populated only when `has_dmar` is true).
    /// Shared between interrupt remapping (intr-p3) and DMA remapping (Phase 4).
    pub drhd_units: Vec<DhrdUnit>,
}

impl AcpiInfo {
    /// Parse ACPI tables starting from the RSDP physical address (from Limine).
    pub fn parse(rsdp_phys: u64, hhdm_offset: u64) -> Self {
        let handler = HhdmHandler::new(hhdm_offset);
        let tables = unsafe {
            AcpiTables::from_rsdp(handler.clone(), rsdp_phys as usize)
                .expect("failed to parse ACPI tables from RSDP")
        };

        // ── MADT: processor topology + I/O APICs + ISOs ──────────────── //
        let mut processors = Vec::new();
        let mut io_apics = Vec::new();
        let mut isos = Vec::new();
        let mut has_legacy_pics = false;

        if let Some(madt_mapping) = tables.find_table::<Madt>() {
            let madt = madt_mapping.get();
            has_legacy_pics = madt.supports_8259();

            for entry in madt.entries() {
                match entry {
                    MadtEntry::LocalApic(e) => {
                        let flags = e.flags;
                        // Bit 0: enabled, bit 1: online-capable
                        if flags & 0x1 != 0 || flags & 0x2 != 0 {
                            processors.push(ProcessorInfo {
                                processor_uid: e.processor_id as u32,
                                local_apic_id: e.apic_id as u32,
                            });
                        }
                    }
                    MadtEntry::LocalX2Apic(e) => {
                        let flags = e.flags;
                        if flags & 0x1 != 0 || flags & 0x2 != 0 {
                            processors.push(ProcessorInfo {
                                processor_uid: e.processor_uid,
                                local_apic_id: e.x2apic_id,
                            });
                        }
                    }
                    MadtEntry::IoApic(e) => {
                        io_apics.push(IoApic {
                            id: e.io_apic_id,
                            address: e.io_apic_address,
                            gsi_base: e.global_system_interrupt_base,
                        });
                    }
                    MadtEntry::InterruptSourceOverride(e) => {
                        isos.push(Iso {
                            bus: e.bus,
                            irq: e.irq,
                            gsi: e.global_system_interrupt,
                            flags: e.flags,
                        });
                    }
                    _ => {}
                }
            }
        }

        // ── MCFG: PCIe ECAM config regions ───────────────────────────── //
        let pci_config_regions = PciConfigRegions::new(&tables).ok();

        // Build a flat EcamRegion list from the raw MCFG table for IOMMU sizing.
        let ecam_regions: Vec<EcamRegion> = tables
            .find_table::<Mcfg>()
            .map(|m| {
                m.get()
                    .entries()
                    .iter()
                    .map(|e| EcamRegion {
                        segment: e.pci_segment_group,
                        start_bus: e.bus_number_start,
                        end_bus: e.bus_number_end,
                        base_phys: e.base_address,
                    })
                    .collect()
            })
            .unwrap_or_default();

        // ── DMAR: check presence and enumerate DRHD units ────────────── //
        let (has_dmar, drhd_units) = parse_dmar(&tables, hhdm_offset);

        // ── TPM2: check for TPM 2.0 device ──────────────────────────── //
        let tpm = parse_tpm2(&tables, hhdm_offset);

        Self {
            rsdp_phys,
            processors,
            io_apics,
            isos,
            has_legacy_pics,
            pci_config_regions,
            ecam_regions,
            tpm,
            has_dmar,
            drhd_units,
        }
    }

    /// Compute the exact number of META pages to reserve for IOMMU DMA tables.
    ///
    /// Returns `(root_pages, ctx_pages)`:
    /// - `root_pages`: one 4 KiB page per DRHD unit (for the root table).
    /// - `ctx_pages`: one 4 KiB page per PCI bus covered by each
    ///   INCLUDE_PCI_ALL DRHD, matching ECAM bus ranges by PCI segment.
    ///   Scoped DRHDs contribute 0 context table pages (deferred).
    ///
    /// This is called before `partition()` so the META pool is sized exactly.
    pub fn iommu_page_counts(&self) -> (u64, u64) {
        if !self.has_dmar {
            return (0, 0);
        }
        let root_pages = self.drhd_units.len() as u64;
        let mut ctx_pages: u64 = 0;
        for unit in &self.drhd_units {
            // Allocate context tables for all buses in the matching ECAM segment,
            // regardless of INCLUDE_PCI_ALL.  A DRHD with flags=0x0 routes DMA
            // for specific devices but we still need passthrough entries for every
            // possible source-id; an absent (P=0) root entry is a DMA fault.
            ctx_pages += self
                .ecam_regions
                .iter()
                .filter(|r| r.segment == unit.segment)
                .map(|r| r.bus_count())
                .sum::<u64>();
        }
        (root_pages, ctx_pages)
    }
}

// ── TPM2 parsing ───────────────────────────────────────────────────────── //

/// Parse the ACPI TPM2 table to discover a TPM 2.0 device.
///
/// Returns `Some(TpmInfo)` if the TPM2 table is present.
///
/// TPM2 table layout (TCG PC Client Platform TPM Profile, rev 4):
/// ```text
/// Offset  Size  Field
///    0     36   Standard ACPI SDT header ("TPM2" signature)
///   36      2   Platform Class (0 = client, 1 = server)
///   38      2   Reserved
///   40      8   Address of Control Area (u64)
///   48      4   Start Method
///   52     12   Start Method Specific Parameters (optional)
/// ```
fn parse_tpm2<H: acpi::Handler + Clone>(
    tables: &AcpiTables<H>,
    hhdm_offset: u64,
) -> Option<TpmInfo> {
    use crate::serial_println;

    const TPM2_MIN_SIZE: usize = 52; // 36 (SDT) + 2 + 2 + 8 + 4

    let tpm2_phys = tables
        .table_headers()
        .find(|(_, hdr)| hdr.signature == acpi::sdt::Signature::TPM2)
        .map(|(phys, _)| phys as u64);

    let Some(tpm2_phys) = tpm2_phys else {
        serial_println!("ACPI: no TPM2 table found");
        return None;
    };

    let tpm2_virt = (tpm2_phys + hhdm_offset) as *const u8;
    let table_len = unsafe { (tpm2_virt.add(4) as *const u32).read_unaligned() as usize };

    if table_len < TPM2_MIN_SIZE {
        serial_println!(
            "ACPI TPM2: table too short ({} bytes) — skipping",
            table_len
        );
        return None;
    }

    let control_area = unsafe { (tpm2_virt.add(40) as *const u64).read_unaligned() };
    let start_method = unsafe { (tpm2_virt.add(48) as *const u32).read_unaligned() };

    serial_println!(
        "ACPI TPM2: control_area={:#x} start_method={} (table at phys {:#x}, {} bytes)",
        control_area,
        start_method,
        tpm2_phys,
        table_len,
    );

    Some(TpmInfo {
        control_area,
        start_method,
    })
}

// ── DMAR parsing ───────────────────────────────────────────────────────── //

/// Walk the DMAR ACPI table and enumerate DRHD units.
///
/// Returns `(has_dmar, Vec<DhrdUnit>)`.  If no DMAR table is present the
/// vector is empty.  For each DRHD unit found, the CAP register's IR bit
/// (bit 16) and the ECAP register's EIM bit (bit 4) / IR bit (bit 3) are
/// checked to set `DhrdUnit::ir_supported`.
///
/// DMAR table layout (VT-d spec §8.1):
/// ```text
/// Offset  Size  Field
///    0     36   Standard ACPI SDT header ("DMAR" signature)
///   36      1   Host Address Width
///   37      1   Flags (bit 0 = INTR_REMAP capable at DMAR level)
///   38     10   Reserved
///   48+    var  Remapping Structure entries
/// ```
/// Each entry: `[type u16][length u16][...]`
/// DRHD (type 0):  `[0 u16][len u16][flags u8][rsvd u8][segment u16][regbase u64]`
fn parse_dmar<H: acpi::Handler + Clone>(
    tables: &AcpiTables<H>,
    hhdm_offset: u64,
) -> (bool, Vec<DhrdUnit>) {
    use crate::serial_println;

    const DMAR_HEADER_SIZE: usize = 48; // 36 (SDT) + 2 (HAW) + 1 (flags) + 9 (rsvd)
    const DRHD_TYPE: u16 = 0;

    // Find the DMAR table physical address via the SDT header scan.
    let dmar_phys = tables
        .table_headers()
        .find(|(_, hdr)| hdr.signature == acpi::sdt::Signature::DMAR)
        .map(|(phys, _)| phys as u64);

    let Some(dmar_phys) = dmar_phys else {
        return (false, Vec::new());
    };

    // Read DMAR table length from the standard SDT header (offset 4, u32).
    let dmar_virt = (dmar_phys + hhdm_offset) as *const u8;
    let dmar_len = unsafe { (dmar_virt.add(4) as *const u32).read_unaligned() as usize };

    if dmar_len < DMAR_HEADER_SIZE {
        serial_println!("ACPI DMAR: table too short ({} bytes) — skipping", dmar_len);
        return (true, Vec::new());
    }

    // Walk remapping structure entries starting at offset 48.
    let mut offset = DMAR_HEADER_SIZE;
    let mut units = Vec::new();

    while offset + 4 <= dmar_len {
        let entry_ptr = unsafe { dmar_virt.add(offset) };

        let entry_type = unsafe { (entry_ptr as *const u16).read_unaligned() };
        let entry_len = unsafe { (entry_ptr.add(2) as *const u16).read_unaligned() } as usize;

        if entry_len < 4 || offset + entry_len > dmar_len {
            serial_println!(
                "ACPI DMAR: malformed entry at offset {} (len {}) — stopping",
                offset,
                entry_len
            );
            break;
        }

        if entry_type == DRHD_TYPE {
            // DRHD: [type u16][len u16][flags u8][rsvd u8][segment u16][regbase u64]
            if entry_len < 16 {
                serial_println!(
                    "ACPI DMAR: DRHD entry too short ({}) at offset {}",
                    entry_len,
                    offset
                );
            } else {
                let drhd_flags = unsafe { entry_ptr.add(4).read() };
                let segment = unsafe { (entry_ptr.add(6) as *const u16).read_unaligned() };
                let register_base = unsafe { (entry_ptr.add(8) as *const u64).read_unaligned() };

                // CAP/ECAP reads deferred to init_themis() after the MMIO region
                // is explicitly mapped.  Mark ir_supported=false here; init_themis
                // will update it once it can safely access the registers.
                serial_println!(
                    "ACPI DMAR: DRHD seg={} base={:#x} flags={:#x} (IR check deferred)",
                    segment,
                    register_base,
                    drhd_flags,
                );

                units.push(DhrdUnit {
                    register_base,
                    segment,
                    flags: drhd_flags,
                    ir_supported: false,
                    irt_phys: 0,
                    root_phys: 0,
                    aw: 0,
                    ctx_tables: Vec::new(),
                });
            }
        }

        offset += entry_len;
    }

    serial_println!("ACPI DMAR: found {} DRHD unit(s)", units.len());
    (true, units)
}

// ── ACPI table stripping ───────────────────────────────────────────────── //

/// Copy the RSDP and XSDT into `dest_phys` in dom0 memory, removing
/// capavisor-exclusive table pointers so Linux never discovers them.
///
/// Currently strips:
/// - **DMAR** — VT-d hardware (capavisor manages IOMMU directly)
/// - **TPM2** — TPM device (capavisor-exclusive, MMIO excluded from EPT)
///
/// Layout at `dest_phys` after the call:
/// ```text
/// dest_phys + 0x000 : modified RSDP copy  (36 bytes, ACPI 2.0)
/// dest_phys + 0x100 : modified XSDT copy  (≤ 3840 bytes)
/// ```
///
/// Returns `Some(dest_phys)` on success (caller passes this to
/// `boot_params.acpi_rsdp_addr`).  Returns `None` if neither table is
/// found (nothing to strip) or if the RSDP is ACPI 1.0-only (no XSDT).
///
/// # Safety
/// `dest_phys` must be a valid, writable dom0-owned physical page accessible
/// via HHDM.  `rsdp_phys` must point to a valid ACPI RSDP.
pub fn strip_dmar(rsdp_phys: u64, dest_phys: u64, hhdm_offset: u64) -> Option<u64> {
    use crate::serial_println;

    // ── Read and validate the RSDP ───────────────────────────────────────── //
    // ACPI 2.0 RSDP is exactly 36 bytes.
    const RSDP_LEN: usize = 36;
    const SDT_HDR: usize = 36; // SDT header size (same 36 bytes)
    const XSDT_MAX: usize = 4096 - 0x100; // max XSDT size we'll handle

    let rsdp_virt = (rsdp_phys + hhdm_offset) as *const u8;
    let mut rsdp_buf = [0u8; RSDP_LEN];
    unsafe {
        core::ptr::copy_nonoverlapping(rsdp_virt, rsdp_buf.as_mut_ptr(), RSDP_LEN);
    }

    if &rsdp_buf[..8] != b"RSD PTR " {
        serial_println!("ACPI strip_dmar: bad RSDP signature — skipping");
        return None;
    }
    let revision = rsdp_buf[15];
    if revision < 2 {
        // ACPI 1.0 has no XSDT; RSDT stripping is not implemented.
        serial_println!("ACPI strip_dmar: ACPI 1.0 RSDP (no XSDT) — skipping");
        return None;
    }

    // ── Read and validate the XSDT ───────────────────────────────────────── //
    let xsdt_phys = unsafe { (rsdp_virt.add(24) as *const u64).read_unaligned() };
    if xsdt_phys == 0 {
        return None;
    }

    let xsdt_virt = (xsdt_phys + hhdm_offset) as *const u8;
    let xsdt_len = unsafe { (xsdt_virt.add(4) as *const u32).read_unaligned() as usize };
    if xsdt_len < SDT_HDR || xsdt_len > XSDT_MAX {
        serial_println!(
            "ACPI strip_dmar: XSDT length {} out of range — skipping",
            xsdt_len
        );
        return None;
    }

    // Verify XSDT signature.
    let xsdt_sig = unsafe { core::slice::from_raw_parts(xsdt_virt, 4) };
    if xsdt_sig != b"XSDT" {
        serial_println!("ACPI strip_dmar: unexpected XSDT signature — skipping");
        return None;
    }

    // ── Copy XSDT into a stack buffer and strip DMAR ─────────────────────── //
    let mut xsdt_buf = [0u8; XSDT_MAX];
    unsafe {
        core::ptr::copy_nonoverlapping(xsdt_virt, xsdt_buf.as_mut_ptr(), xsdt_len);
    }

    let num_entries = (xsdt_len - SDT_HDR) / 8;
    let mut write_idx = 0usize;
    let mut found_dmar = false;

    for i in 0..num_entries {
        let src_off = SDT_HDR + i * 8;
        let table_phys = unsafe { (xsdt_buf.as_ptr().add(src_off) as *const u64).read_unaligned() };
        if table_phys == 0 {
            continue;
        }
        // Peek at the 4-byte signature of the pointed-to table.
        let table_virt = (table_phys + hhdm_offset) as *const u8;
        let sig = unsafe { core::slice::from_raw_parts(table_virt, 4) };
        if sig == b"DMAR" || sig == b"TPM2" {
            found_dmar = true;
            continue; // drop this entry
        }
        // Keep the entry, compacting the array.
        let dst_off = SDT_HDR + write_idx * 8;
        unsafe {
            (xsdt_buf.as_mut_ptr().add(dst_off) as *mut u64).write_unaligned(table_phys);
        }
        write_idx += 1;
    }

    if !found_dmar {
        return None; // no DMAR or TPM2 present — nothing to strip
    }

    // ── Update XSDT length and recompute checksum ────────────────────────── //
    let new_xsdt_len = SDT_HDR + write_idx * 8;
    // Zero the removed tail.
    for b in &mut xsdt_buf[new_xsdt_len..xsdt_len] {
        *b = 0;
    }
    // Write new length.
    unsafe {
        (xsdt_buf.as_mut_ptr().add(4) as *mut u32).write_unaligned(new_xsdt_len as u32);
    }
    // Recompute checksum (byte 9): sum of all table bytes must be 0 mod 256.
    xsdt_buf[9] = 0;
    let sum = xsdt_buf[..new_xsdt_len]
        .iter()
        .fold(0u8, |a, &b| a.wrapping_add(b));
    xsdt_buf[9] = sum.wrapping_neg();

    // ── Write XSDT copy to dest_phys + 0x100 ────────────────────────────── //
    let xsdt_dest_phys = dest_phys + 0x100;
    let xsdt_dest_virt = (xsdt_dest_phys + hhdm_offset) as *mut u8;
    unsafe {
        core::ptr::copy_nonoverlapping(xsdt_buf.as_ptr(), xsdt_dest_virt, new_xsdt_len);
    }

    // ── Update RSDP copy: new XSDT address + extended checksum ───────────── //
    unsafe {
        (rsdp_buf.as_mut_ptr().add(24) as *mut u64).write_unaligned(xsdt_dest_phys);
    }
    // extended_checksum (offset 32) covers all 36 RSDP bytes.
    rsdp_buf[32] = 0;
    let sum = rsdp_buf.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    rsdp_buf[32] = sum.wrapping_neg();

    // Write RSDP copy to dest_phys.
    let rsdp_dest_virt = (dest_phys + hhdm_offset) as *mut u8;
    unsafe {
        core::ptr::copy_nonoverlapping(rsdp_buf.as_ptr(), rsdp_dest_virt, RSDP_LEN);
    }

    serial_println!(
        "ACPI: DMAR stripped — RSDP copy @ {:#x}, XSDT @ {:#x} ({} tables → {})",
        dest_phys,
        xsdt_dest_phys,
        num_entries,
        write_idx,
    );

    Some(dest_phys)
}
