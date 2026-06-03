//! VT-d device-assignment plumbing: rewrite a PCI device's context entry
//! to point at a domain's IOMMU page table (or back to the dom0
//! pass-through entry on revocation).
//!
//! Architecture-neutral wrappers live in [`crate::platform::ThemisPlatform`]
//! (`assign_device` / `release_device`); the actual register pokes are
//! VT-d-specific and live here.  An SMMU equivalent will land beside
//! this module on aarch64.

use crate::platform::ThemisPlatform;
use crate::serial_println;
use capability_engine::DomainId;

/// Reprogram a PCI device's IOMMU context entry to use `domain_id`'s
/// second-level page table (SLPT), replacing the dom0 passthrough entry.
///
/// `bdf` is the 16-bit source ID: `bus[15:8] | device[7:3] | function[2:0]`.
///
/// # Panics
/// Panics if `domain_id` has no IOMMU PT yet (no memory has been mapped for
/// it), or if no DRHD unit covers the bus encoded in `bdf`.
pub fn assign_device(p: &ThemisPlatform, bdf: u16, domain_id: DomainId) {
    let hhdm = p.hhdm_offset();
    let bus = (bdf >> 8) as u8;
    let devfn = (bdf & 0xFF) as usize;

    let slptptr = p
        .domain_arc(domain_id)
        .unwrap_or_else(|| panic!("assign_device: unknown domain {}", domain_id))
        .lock()
        .arch
        .iommu_pt()
        .unwrap_or_else(|| panic!("assign_device: domain {} has no IOMMU PT", domain_id))
        .root_phys();

    for unit in p.arch.drhd_units() {
        if let Some(&(_, ctx_phys)) = unit.ctx_tables.iter().find(|(b, _)| *b == bus) {
            let ctx_virt = (ctx_phys + hhdm) as *mut u64;
            let entry = unsafe { ctx_virt.add(devfn * 2) };
            // Write high word first (DID, AW), then low word with P=1 last.
            // TT=00 (multi-level second-level translation).
            let ctx_hi = (domain_id << 8) | unit.aw;
            let ctx_lo = slptptr | 0x1; // P=1, TT=00, SLPTPTR
            unsafe {
                entry.add(1).write_volatile(ctx_hi);
                entry.write_volatile(ctx_lo);
            }
            flush_ctx_and_iotlb(unit, bdf, hhdm);
            serial_println!(
                "  IOMMU: BDF {:#06x} assigned to domain {} (slptptr={:#x})",
                bdf,
                domain_id,
                slptptr
            );
            return;
        }
    }
    panic!(
        "assign_device: no DRHD covers bus {} for BDF {:#06x}",
        bus, bdf
    );
}

/// Restore the passthrough context entry for a PCI device, returning it to
/// dom0 (DID=1, TT=10b pass-through).  Called on child-domain revocation.
///
/// No-ops silently if no DRHD covers the bus.
pub fn release_device(p: &ThemisPlatform, bdf: u16) {
    let hhdm = p.hhdm_offset();
    let bus = (bdf >> 8) as u8;
    let devfn = (bdf & 0xFF) as usize;

    for unit in p.arch.drhd_units() {
        if let Some(&(_, ctx_phys)) = unit.ctx_tables.iter().find(|(b, _)| *b == bus) {
            let ctx_virt = (ctx_phys + hhdm) as *mut u64;
            let entry = unsafe { ctx_virt.add(devfn * 2) };
            // Restore dom0 passthrough: high=(DID=1<<8)|AW, low=0x9 (P=1, TT=10b).
            let ctx_hi = (1u64 << 8) | unit.aw;
            let ctx_lo = 0x9u64;
            unsafe {
                entry.add(1).write_volatile(ctx_hi);
                entry.write_volatile(ctx_lo);
            }
            flush_ctx_and_iotlb(unit, bdf, hhdm);
            serial_println!("  IOMMU: BDF {:#06x} released to dom0 passthrough", bdf);
            return;
        }
    }
}

/// Flush context-cache (device-selective) and IOTLB (global) for a DRHD unit.
fn flush_ctx_and_iotlb(unit: &crate::arch::acpi::DhrdUnit, bdf: u16, hhdm: u64) {
    const CCMD_OFFSET: u64 = 0x28;
    const ECAP_OFFSET: u64 = 0x10;
    const POLL_LIMIT: usize = 100_000;

    let base = unit.register_base + hhdm;
    let ccmd = (base + CCMD_OFFSET) as *mut u64;

    // Context-cache invalidation: device-selective (CIRG=11b=bits[62:61]),
    // SID=bdf in bits[47:32], ICC=bit[63].
    let ccmd_val = (1u64 << 63)          // ICC
        | (3u64 << 61)                   // CIRG = device-selective
        | ((bdf as u64) << 32); // SID
    unsafe { ccmd.write_volatile(ccmd_val) };
    for _ in 0..POLL_LIMIT {
        core::hint::spin_loop();
        if unsafe { ccmd.read_volatile() } & (1u64 << 63) == 0 {
            break;
        }
    }

    // IOTLB global invalidation.
    let ecap = unsafe { ((base + ECAP_OFFSET) as *const u64).read_volatile() };
    let iro = ((ecap >> 8) & 0x3f) as u64;
    let iotlb_reg = (base + iro * 16 + 8) as *mut u64;
    unsafe { iotlb_reg.write_volatile((1u64 << 63) | (1u64 << 60)) };
    for _ in 0..POLL_LIMIT {
        core::hint::spin_loop();
        if unsafe { iotlb_reg.read_volatile() } & (1u64 << 63) == 0 {
            break;
        }
    }
}
