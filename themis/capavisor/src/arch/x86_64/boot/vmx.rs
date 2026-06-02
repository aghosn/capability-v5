//! Phase 2a-b: VMX feature detection and VMXON.

extern crate alloc;
use alloc::vec::Vec;

use crate::domain::Domain;
use crate::serial_println;

use super::{PlatformInfo, VmxState};

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
