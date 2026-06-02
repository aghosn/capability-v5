//! Phase 7g: signal APs and execute VMLAUNCH on the BSP.

use crate::serial_println;

use super::{LinuxState, VmxState};

// ── Phase 7g: VMLAUNCH ────────────────────────────────────────────────────── //

/// Phase P7g: signal APs and execute VMLAUNCH on the BSP.
///
/// 1. Sets `AP_LAUNCH_READY` (Release) so each AP wakes up, enables VMX,
///    loads its VMCS, and enters the monitor loop.
/// 2. BSP creates an `ActiveVcpu` from the loaded VMCS, sets RSI to
///    `boot_params_phys`, and enters the monitor loop.
///
/// This function never returns.
pub fn launch(
    linux: &LinuxState,
    vmx: &VmxState,
    platform: &crate::platform::ThemisPlatform,
) -> crate::arch_traits::types::Vp<crate::arch::x86_64::x86_platform::X86Platform> {
    use crate::vcpu::{InactiveVcpu, Reg};
    use crate::AP_LAUNCH_READY;
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

    let mut inactive = InactiveVcpu::new(
        bsp_vmcs_phys,
        bsp_vapic_phys,
        bsp_msr_bitmap_phys,
        0,
        bsp_vpid,
    );

    // Set RSI = boot_params_phys (Linux boot protocol requirement).
    inactive.set_reg(Reg::Rsi, linux.boot_params_phys);

    // Store BSP vcpu in PlatformDomain, then immediately take it.
    // This ensures the PlatformDomain has a complete VP table (all VP IDs
    // are registered) even though the BSP VP is immediately active.
    platform.bootstrap_store_vcpu(0, vmx.bsp_index, inactive);
    let inactive = platform
        .take_vcpu(0, vmx.bsp_index)
        .expect("BSP: failed to take vcpu from PlatformDomain");

    serial_println!("  BSP: RSI={:#x} → monitor_loop", linux.boot_params_phys);

    let vcpu = inactive.activate().expect("BSP activate failed");

    // Return the platform-agnostic VP. The caller (main.rs) enters the
    // monitor loop — this fixes the layering: arch code returns to generic.
    let arch = unsafe {
        crate::arch::x86_64::x86_platform::X86Platform::new(platform as *const _)
    };
    crate::arch_traits::types::Vp::new(arch, vcpu)
}
