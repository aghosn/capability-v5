//! ivshmem device discovery via Themis CPUID leaf `0x40000004`.
//!
//! Discovers capability-backed ivshmem devices provisioned by CHV.
//! The CPUID leaf reports BAR0 (doorbell registers) and BAR2 (shared
//! data region) GPAs for each device.  Eunomia identity-maps these
//! regions so they are directly accessible.
//!
//! This discovery mechanism is shared with the Linux CoCo driver for
//! Themis — both use the same CPUID leaf layout defined in `themis_abi::cpuid`.
//!
//! # Prerequisites
//!
//! - Must be running under Themis (check `themis_abi::cpuid::is_themis()`).
//! - CHV must have provisioned `--ivshmem` devices with `mode=...`.
//! - The capavisor serves CPUID `0x40000004` with CHV-pushed Emulate
//!   overrides containing the BAR addresses.

use themis_abi::cpuid;

/// Descriptor for a discovered ivshmem device.
#[derive(Debug, Clone, Copy)]
pub struct IvshmemDevice {
    /// Device index (subleaf used for discovery).
    pub index: u32,
    /// BAR0 GPA — doorbell register MMIO (256 bytes, always < 4 GiB).
    pub bar0_gpa: u64,
    /// BAR2 GPA — shared data region (may be above 4 GiB for 64-bit BAR).
    pub bar2_gpa: u64,
}

/// ivshmem BAR0 register offsets (ivshmem spec).
pub mod bar0 {
    /// Interrupt Mask Register (read/write).
    pub const REG_INTRMASK: u64 = 0x00;
    /// Interrupt Status Register (read-only).
    pub const REG_INTRSTATUS: u64 = 0x04;
    /// IV Position Register (read-only, peer ID).
    pub const REG_IVPOSITION: u64 = 0x08;
    /// Doorbell Register (write-only, triggers notification).
    pub const REG_DOORBELL: u64 = 0x0C;
}

#[derive(Debug)]
pub enum IvshmemError {
    /// Not running under Themis hypervisor.
    NotThemis,
    /// No ivshmem devices provisioned (CPUID returned count=0).
    NoDevices,
    /// Failed to map BAR2 region into page tables.
    MapFailed(u32),
}

/// CPUID with subleaf support.
#[inline(always)]
fn cpuid_subleaf(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let r = core::arch::x86_64::__cpuid_count(leaf, subleaf);
    (r.eax, r.ebx, r.ecx, r.edx)
}

/// Discover all ivshmem devices via CPUID.
///
/// Returns a list of discovered devices.  Each device's BAR2 is
/// identity-mapped if it falls outside the boot identity map (> 4 GiB).
/// BAR0 is always in 32-bit MMIO space and covered by the boot map.
///
/// Must be called after `paging` and `mm` are initialized.
pub fn discover() -> Result<alloc::vec::Vec<IvshmemDevice>, IvshmemError> {
    // Gate on Themis hypervisor detection.
    if !cpuid::is_themis() {
        return Err(IvshmemError::NotThemis);
    }

    // Read subleaf 0 to get the device count.
    let (bar0_lo, count, _bar2_lo, _bar2_hi) = cpuid_subleaf(cpuid::LEAF_IVSHMEM, 0);

    if count == 0 || bar0_lo == 0 {
        return Err(IvshmemError::NoDevices);
    }

    let mut devices = alloc::vec::Vec::with_capacity(count as usize);

    for i in 0..count {
        let (bar0_lo, _count, bar2_lo, bar2_hi) = cpuid_subleaf(cpuid::LEAF_IVSHMEM, i);

        let bar0_gpa = bar0_lo as u64;
        let bar2_gpa = (bar2_lo as u64) | ((bar2_hi as u64) << 32);

        let dev = IvshmemDevice {
            index: i,
            bar0_gpa,
            bar2_gpa,
        };

        // BAR0 is 32-bit MMIO (< 4 GiB) — covered by boot identity map.
        // BAR2 may be above 4 GiB — map it if needed.
        // Note: we don't know the BAR2 size from CPUID alone; the workload
        // knows its expected ivshmem size from configuration.  For now we
        // just record the GPA — the workload maps it with map_range().

        crate::println!(
            "[ivshmem] device {}: bar0=0x{:x} bar2=0x{:x}",
            i, bar0_gpa, bar2_gpa,
        );

        devices.push(dev);
    }

    Ok(devices)
}

impl IvshmemDevice {
    /// Map the shared data region (BAR2) into Eunomia's page tables.
    ///
    /// `size` must be the expected region size (must match `--ivshmem size=`).
    /// Returns a raw pointer to the mapped region on success.
    pub fn map_bar2(&self, size: u64) -> Result<*mut u8, IvshmemError> {
        if !crate::paging::map_range(self.bar2_gpa, size) {
            return Err(IvshmemError::MapFailed(self.index));
        }
        Ok(self.bar2_gpa as *mut u8)
    }

    /// Ring the doorbell by writing to BAR0 + 0xC.
    ///
    /// Ring the doorbell register in BAR0 via a VMCALL to the capavisor.
    ///
    /// The capavisor matches the GPA against the caller's doorbell list and
    /// enqueues a notification to the parent domain's DomainComm RX ring.
    pub fn ring_doorbell(&self, value: u32) {
        let gpa = self.bar0_gpa + bar0::REG_DOORBELL;
        unsafe {
            libthemis::raw_vmcall(
                themis_abi::opcodes::THEMIS_RING_DOORBELL,
                gpa as u64,
                value as u64,
                0, 0, 0,
            );
        }
    }

    /// Read the IV Position register (peer ID assigned by the VMM).
    ///
    /// # Safety
    /// BAR0 must be identity-mapped.
    pub unsafe fn peer_id(&self) -> u32 {
        let addr = (self.bar0_gpa + bar0::REG_IVPOSITION) as *const u32;
        core::ptr::read_volatile(addr)
    }
}
