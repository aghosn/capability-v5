//! PCI/PCIe device enumeration via ECAM (Enhanced Configuration Access Mechanism).
//!
//! Implements `pci_types::ConfigRegionAccess` over the ECAM MMIO window
//! whose base address comes from the ACPI MCFG table.  Walks all
//! bus/device/function triples and builds a device table.

use alloc::vec::Vec;
use core::ptr;

use pci_types::{ConfigRegionAccess, PciAddress, PciHeader, HeaderType, EndpointHeader, Bar};

use crate::acpi::AcpiInfo;

// ── ECAM config-space accessor ──────────────────────────────────────────── //

/// MMIO-based PCIe ECAM config-space access.
pub struct EcamAccess {
    /// Virtual base address of the ECAM region (HHDM-mapped).
    base_virt: u64,
}

impl EcamAccess {
    /// Create a new ECAM accessor.
    ///
    /// `ecam_phys` is the physical base from MCFG; `hhdm_offset` translates
    /// it to a virtual address.  The caller must ensure the ECAM region is
    /// mapped (reserved memory regions are mapped by `mem::map_phys_range`).
    pub fn new(ecam_phys: u64, hhdm_offset: u64) -> Self {
        Self {
            base_virt: ecam_phys + hhdm_offset,
        }
    }

    /// Compute the virtual address for a BDF + offset within the ECAM window.
    /// Each function gets 4 KiB of config space:
    ///   addr = base + (bus << 20) | (dev << 15) | (func << 12) | offset
    fn config_addr(&self, address: PciAddress, offset: u16) -> *mut u32 {
        let bdf = ((address.bus() as u64) << 20)
            | ((address.device() as u64) << 15)
            | ((address.function() as u64) << 12)
            | (offset as u64 & 0xFFC); // 4-byte aligned
        (self.base_virt + bdf) as *mut u32
    }
}

impl ConfigRegionAccess for EcamAccess {
    unsafe fn read(&self, address: PciAddress, offset: u16) -> u32 {
        ptr::read_volatile(self.config_addr(address, offset))
    }

    unsafe fn write(&self, address: PciAddress, offset: u16, value: u32) {
        ptr::write_volatile(self.config_addr(address, offset), value);
    }
}

// ── Device table ────────────────────────────────────────────────────────── //

/// Summary of a discovered PCI device.
#[derive(Debug, Clone)]
pub struct PciDevice {
    pub address: PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub interface: u8,
    pub revision: u8,
    pub header_type: HeaderType,
}

/// A PCI memory BAR region (address + size) for EPT mapping.
#[derive(Debug, Clone, Copy)]
pub struct PciBarRegion {
    pub base: u64,
    pub size: u64,
}

/// Enumerate all PCI devices on bus 0..255 using the ECAM window.
///
/// Returns `None` if no MCFG table was found (no PCIe ECAM available).
/// On success, returns `(devices, bar_regions)` — the BAR regions are the
/// physical memory ranges of all discovered memory BARs, suitable for EPT
/// passthrough mapping.
pub fn enumerate(acpi_info: &AcpiInfo, hhdm_offset: u64) -> Option<(Vec<PciDevice>, Vec<PciBarRegion>)> {
    let regions = acpi_info.pci_config_regions.as_ref()?;
    if regions.regions.is_empty() {
        return None;
    }

    // Use the first ECAM region (segment 0).
    let base_phys = { regions.regions[0].base_address };
    let bus_start = { regions.regions[0].bus_number_start };
    let bus_end = { regions.regions[0].bus_number_end };

    // Map the ECAM MMIO region into the HHDM.
    // ECAM size = (bus_end - bus_start + 1) * 256 devices/bus * 4 KiB/function
    let ecam_size = ((bus_end as u64 - bus_start as u64 + 1) * 256 * 8) * 4096;
    crate::mem::map_phys_range(base_phys, ecam_size, hhdm_offset);

    let access = EcamAccess::new(base_phys, hhdm_offset);
    let mut devices = Vec::new();
    let mut bar_regions = Vec::new();

    for bus in bus_start..=bus_end {
        for device in 0..32u8 {
            let addr = PciAddress::new(0, bus, device, 0);
            let header = PciHeader::new(addr);

            let (vendor, _) = header.id(&access);
            if vendor == 0xFFFF {
                continue; // No device
            }

            let multi = header.has_multiple_functions(&access);
            let max_func = if multi { 8 } else { 1 };

            for function in 0..max_func {
                let addr = PciAddress::new(0, bus, device, function);
                let header = PciHeader::new(addr);

                let (vendor, dev_id) = header.id(&access);
                if vendor == 0xFFFF {
                    continue;
                }

                let (rev, class, subclass, interface) =
                    header.revision_and_class(&access);
                let hdr_type = header.header_type(&access);

                devices.push(PciDevice {
                    address: addr,
                    vendor_id: vendor,
                    device_id: dev_id,
                    class,
                    subclass,
                    interface,
                    revision: rev,
                    header_type: hdr_type,
                });

                // Read memory BARs from endpoint (Type 0) headers.
                if let Some(ep) = EndpointHeader::from_header(header, &access) {
                    let mut slot = 0u8;
                    while slot < 6 {
                        match ep.bar(slot, &access) {
                            Some(Bar::Memory32 { address, size, .. }) => {
                                if address != 0 && size != 0 {
                                    bar_regions.push(PciBarRegion {
                                        base: address as u64,
                                        size: size as u64,
                                    });
                                }
                                slot += 1;
                            }
                            Some(Bar::Memory64 { address, size, .. }) => {
                                if address != 0 && size != 0 {
                                    bar_regions.push(PciBarRegion {
                                        base: address,
                                        size: size,
                                    });
                                }
                                slot += 2; // 64-bit BARs consume two slots
                            }
                            Some(Bar::Io { .. }) => {
                                slot += 1; // I/O BARs don't need EPT mapping
                            }
                            None => {
                                slot += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    Some((devices, bar_regions))
}
