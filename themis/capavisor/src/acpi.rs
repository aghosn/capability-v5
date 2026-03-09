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
            rsdp_phys,
            processors,
            io_apics,
            isos,
            has_legacy_pics,
            pci_config_regions,
            has_dmar,
        }
    }
}

// ── DMAR stripping ─────────────────────────────────────────────────────── //

/// Copy the RSDP and XSDT into `dest_phys` in dom0 memory, removing the DMAR
/// table pointer so Linux never discovers VT-d hardware.
///
/// Layout at `dest_phys` after the call:
/// ```text
/// dest_phys + 0x000 : modified RSDP copy  (36 bytes, ACPI 2.0)
/// dest_phys + 0x100 : modified XSDT copy  (≤ 3840 bytes)
/// ```
///
/// Returns `Some(dest_phys)` on success (caller passes this to
/// `boot_params.acpi_rsdp_addr`).  Returns `None` if there is no DMAR entry
/// (nothing to strip) or if the RSDP is ACPI 1.0-only (no XSDT).
///
/// # Safety
/// `dest_phys` must be a valid, writable dom0-owned physical page accessible
/// via HHDM.  `rsdp_phys` must point to a valid ACPI RSDP.
pub fn strip_dmar(rsdp_phys: u64, dest_phys: u64, hhdm_offset: u64) -> Option<u64> {
    use crate::serial_println;

    // ── Read and validate the RSDP ───────────────────────────────────────── //
    // ACPI 2.0 RSDP is exactly 36 bytes.
    const RSDP_LEN:  usize = 36;
    const SDT_HDR:   usize = 36; // SDT header size (same 36 bytes)
    const XSDT_MAX:  usize = 4096 - 0x100; // max XSDT size we'll handle

    let rsdp_virt = (rsdp_phys + hhdm_offset) as *const u8;
    let mut rsdp_buf = [0u8; RSDP_LEN];
    unsafe { core::ptr::copy_nonoverlapping(rsdp_virt, rsdp_buf.as_mut_ptr(), RSDP_LEN); }

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
    let xsdt_phys = unsafe {
        (rsdp_virt.add(24) as *const u64).read_unaligned()
    };
    if xsdt_phys == 0 {
        return None;
    }

    let xsdt_virt = (xsdt_phys + hhdm_offset) as *const u8;
    let xsdt_len = unsafe {
        (xsdt_virt.add(4) as *const u32).read_unaligned() as usize
    };
    if xsdt_len < SDT_HDR || xsdt_len > XSDT_MAX {
        serial_println!("ACPI strip_dmar: XSDT length {} out of range — skipping", xsdt_len);
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
    unsafe { core::ptr::copy_nonoverlapping(xsdt_virt, xsdt_buf.as_mut_ptr(), xsdt_len); }

    let num_entries = (xsdt_len - SDT_HDR) / 8;
    let mut write_idx = 0usize;
    let mut found_dmar = false;

    for i in 0..num_entries {
        let src_off = SDT_HDR + i * 8;
        let table_phys = unsafe {
            (xsdt_buf.as_ptr().add(src_off) as *const u64).read_unaligned()
        };
        if table_phys == 0 {
            continue;
        }
        // Peek at the 4-byte signature of the pointed-to table.
        let table_virt = (table_phys + hhdm_offset) as *const u8;
        let sig = unsafe { core::slice::from_raw_parts(table_virt, 4) };
        if sig == b"DMAR" {
            found_dmar = true;
            continue; // drop this entry
        }
        // Keep the entry, compacting the array.
        let dst_off = SDT_HDR + write_idx * 8;
        unsafe {
            (xsdt_buf.as_mut_ptr().add(dst_off) as *mut u64)
                .write_unaligned(table_phys);
        }
        write_idx += 1;
    }

    if !found_dmar {
        return None; // no DMAR present — nothing to strip
    }

    // ── Update XSDT length and recompute checksum ────────────────────────── //
    let new_xsdt_len = SDT_HDR + write_idx * 8;
    // Zero the removed tail.
    for b in &mut xsdt_buf[new_xsdt_len..xsdt_len] { *b = 0; }
    // Write new length.
    unsafe {
        (xsdt_buf.as_mut_ptr().add(4) as *mut u32).write_unaligned(new_xsdt_len as u32);
    }
    // Recompute checksum (byte 9): sum of all table bytes must be 0 mod 256.
    xsdt_buf[9] = 0;
    let sum = xsdt_buf[..new_xsdt_len].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    xsdt_buf[9] = sum.wrapping_neg();

    // ── Write XSDT copy to dest_phys + 0x100 ────────────────────────────── //
    let xsdt_dest_phys = dest_phys + 0x100;
    let xsdt_dest_virt = (xsdt_dest_phys + hhdm_offset) as *mut u8;
    unsafe { core::ptr::copy_nonoverlapping(xsdt_buf.as_ptr(), xsdt_dest_virt, new_xsdt_len); }

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
    unsafe { core::ptr::copy_nonoverlapping(rsdp_buf.as_ptr(), rsdp_dest_virt, RSDP_LEN); }

    serial_println!(
        "ACPI: DMAR stripped — RSDP copy @ {:#x}, XSDT @ {:#x} ({} tables → {})",
        dest_phys, xsdt_dest_phys, num_entries, write_idx,
    );

    Some(dest_phys)
}
