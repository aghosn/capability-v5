//! Phase 2d: per-VP VMCS allocation and setup.

use crate::serial_println;

use super::{CapaState, PlatformInfo, VmxState};

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
    use crate::arch::vmcs::setup_vmcs_for_vp;
    use x86::bits64::vmx;
    use x86::vmx::vmcs;

    serial_println!();
    serial_println!("=== P2d: VMCS setup ===");

    // Set up our own GDT (null + code64 + data + per-core TSS) and load TR.
    // Limine does not set TR, so `str` would return 0 without this step,
    // causing VMLAUNCH error 8 ("VM entry with invalid host-state field(s)").
    crate::arch::gdt::init();
    crate::arch::gdt::load_for_core(0); // BSP = core 0
    serial_println!(
        "  GDT loaded: base={:#x}  TR selector={:#06x}  TR base={:#x}",
        crate::arch::gdt::gdtr_base(),
        crate::arch::gdt::tss_selector(0),
        crate::arch::gdt::tss_base(0)
    );

    let num_vps = info.num_cores;
    let eptp = capa
        .platform
        .slat(0)
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
