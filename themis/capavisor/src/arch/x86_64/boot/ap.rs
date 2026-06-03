//! Application Processor (AP) entry path for x86-64.
//!
//! Limine spawns each AP at [`crate::ap_entry`] in `main.rs`, which delegates
//! straight here.  All work that follows — VMX-on, XCR0/XSAVE setup, picking
//! up the BSP-allocated [`InactiveVcpu`], activating it, and entering the
//! generic [`monitor::monitor_loop`] — is x86-specific platform init and
//! lives under `arch/x86_64/`.

use core::sync::atomic::Ordering;

use crate::arch::x86_64::x86_platform::X86Platform;
use crate::arch_traits::types::Vp;
use crate::monitor;
use crate::platform::ThemisPlatform;
use crate::serial_println;
use crate::{AP_LAUNCH_READY, AP_READY_COUNT, PLATFORM_PTR, SERIAL_LOCK};

/// Bring up an AP and hand it to the monitor loop.  Never returns.
///
/// # Safety
/// Called exactly once per AP from Limine's MP entry trampoline.  Assumes
/// the BSP has installed `PLATFORM_PTR` and signalled `AP_LAUNCH_READY`.
pub unsafe fn run(cpu: &limine::mp::Cpu) -> ! {
    while SERIAL_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    serial_println!("  AP {} (LAPIC {}) ready", cpu.id, cpu.lapic_id);
    SERIAL_LOCK.store(false, Ordering::Release);

    AP_READY_COUNT.fetch_add(1, Ordering::Release);

    // Spin until BSP signals AP_LAUNCH_READY.
    while !AP_LAUNCH_READY.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }

    let id = cpu.id as usize;
    let platform_ptr = PLATFORM_PTR.load(Ordering::Relaxed);
    assert!(!platform_ptr.is_null(), "AP{}: PLATFORM_PTR is null", id);
    let platform = unsafe { &*platform_ptr };

    enable_root_mode(platform, id);

    let inactive = platform
        .take_vcpu(0, id)
        .unwrap_or_else(|| panic!("AP{}: no InactiveVcpu in PlatformDomain", id));

    let active = inactive.activate().expect("AP activate failed");

    let arch = X86Platform::new(platform as *const _);
    let mut vp = Vp::new(arch, active);
    monitor::monitor_loop(&mut vp);
}

/// Enable VMX root mode on this AP and configure XSAVE so guest XSTATE
/// management works after VMLAUNCH.
fn enable_root_mode(platform: &ThemisPlatform, core_id: usize) {
    let vmxon_phys = platform.arch.vmxon_phys(core_id);
    crate::vmx::enable_vmx_on_core(vmxon_phys).expect("AP VMXON failed");

    unsafe {
        let cr4 = x86::controlregs::cr4();
        x86::controlregs::cr4_write(cr4 | x86::controlregs::Cr4::CR4_ENABLE_OS_XSAVE);

        let cpuid_d = core::arch::x86_64::__cpuid_count(0xD, 0);
        let max_xcr0 = (((cpuid_d.edx as u64) << 32) | (cpuid_d.eax as u64)) | 1;
        core::arch::asm!(
            "xsetbv",
            in("ecx") 0u32,
            in("eax") max_xcr0 as u32,
            in("edx") (max_xcr0 >> 32) as u32,
            options(nomem, nostack),
        );
    }
}
