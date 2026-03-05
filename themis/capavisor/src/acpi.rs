//! ACPI table discovery and parsing.
//!
//! Implements the `acpi::Handler` trait using the Limine HHDM (Higher-Half
//! Direct Map) to translate physical addresses to virtual ones.  Extracts:
//!
//! - **MADT**: processor topology (LAPIC IDs, I/O APIC addresses, ISO overrides)
//! - **MCFG**: PCIe ECAM base addresses per segment/bus range
//! - **DMAR**: raw VT-d remapping table (parsed later in Phase 4)

use alloc::vec::Vec;
use core::ptr::NonNull;

use acpi::{
    AcpiTables, Handler, Handle, PhysicalMapping,
    aml::AmlError,
    platform::PciConfigRegions,
    sdt::{Signature, madt::{MadtEntry, Madt}},
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
        unsafe { core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack)) };
        val
    }
    fn read_io_u16(&self, port: u16) -> u16 {
        let val: u16;
        unsafe { core::arch::asm!("in ax, dx", out("ax") val, in("dx") port, options(nomem, nostack)) };
        val
    }
    fn read_io_u32(&self, port: u16) -> u32 {
        let val: u32;
        unsafe { core::arch::asm!("in eax, dx", out("eax") val, in("dx") port, options(nomem, nostack)) };
        val
    }

    fn write_io_u8(&self, port: u16, value: u8) {
        unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack)) };
    }
    fn write_io_u16(&self, port: u16, value: u16) {
        unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack)) };
    }
    fn write_io_u32(&self, port: u16, value: u32) {
        unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack)) };
    }

    fn read_pci_u8(&self, _address: acpi::PciAddress, _offset: u16) -> u8 {
        // PCI config space reads via ECAM MMIO will be implemented in P1e.
        0
    }
    fn read_pci_u16(&self, _address: acpi::PciAddress, _offset: u16) -> u16 { 0 }
    fn read_pci_u32(&self, _address: acpi::PciAddress, _offset: u16) -> u32 { 0 }

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
#[derive(Debug, Clone, Copy)]
pub struct ProcessorInfo {
    pub processor_uid: u32,
    pub local_apic_id: u32,
}

/// I/O APIC descriptor extracted from the MADT.
#[derive(Debug, Clone, Copy)]
pub struct IoApic {
    pub id: u8,
    pub address: u32,
    pub gsi_base: u32,
}

/// Interrupt Source Override from the MADT.
#[derive(Debug, Clone, Copy)]
pub struct Iso {
    pub bus: u8,
    pub irq: u8,
    pub gsi: u32,
    pub flags: u16,
}

/// Summary of all ACPI information needed by Themis.
pub struct AcpiInfo {
    /// Processor topology from MADT (BSP + APs with LAPIC IDs).
    pub processors: Vec<ProcessorInfo>,
    /// I/O APICs from MADT.
    pub io_apics: Vec<IoApic>,
    /// Interrupt source overrides from MADT.
    pub isos: Vec<Iso>,
    /// Whether the platform has legacy 8259 PICs.
    pub has_legacy_pics: bool,
    /// PCIe ECAM regions from MCFG (segment → base address + bus range).
    pub pci_config_regions: Option<PciConfigRegions>,
    /// Whether a DMAR table was found (VT-d available).
    pub has_dmar: bool,
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

        // ── DMAR: check presence (full parse in Phase 4) ─────────────── //
        let has_dmar = tables
            .table_headers()
            .any(|(_, hdr)| hdr.signature == Signature::DMAR);

        Self {
            processors,
            io_apics,
            isos,
            has_legacy_pics,
            pci_config_regions,
            has_dmar,
        }
    }
}
