//! Smoke test workload — basic sanity checks for Eunomia.

#![no_std]
#![no_main]

use eunomia::test_harness::TestCase;

// Pull in the eunomia boot runtime (PVH entry, GDT, IDT, heap, panic handler).
extern crate eunomia;

static TESTS: &[TestCase] = &[
    TestCase { name: "serial_output", func: test_serial_output },
    TestCase { name: "gdt_loaded", func: test_gdt_loaded },
    TestCase { name: "idt_loaded", func: test_idt_loaded },
    TestCase { name: "stack_sanity", func: test_stack_sanity },
    TestCase { name: "bootstrap_cpu", func: test_bootstrap_cpu },
    TestCase { name: "pku_xsave_consistent", func: test_pku_xsave_consistent },
];

#[no_mangle]
pub fn app_main(_services: &eunomia::KernelServices) -> ! {
    eunomia::test_harness::run(TESTS);
}

fn test_serial_output() -> Result<(), &'static str> {
    eunomia::println!("  (serial works)");
    Ok(())
}

fn test_gdt_loaded() -> Result<(), &'static str> {
    let mut gdtr: [u8; 10] = [0; 10];
    unsafe {
        core::arch::asm!("sgdt [{}]", in(reg) &mut gdtr, options(nostack));
    }
    let limit = u16::from_le_bytes([gdtr[0], gdtr[1]]);
    // 5-entry GDT (NULL + Code64 + Data64 + TSS_lo + TSS_hi) → limit = 39 = 0x27
    if limit < 0x27 {
        return Err("GDT limit too small (no TSS?)");
    }
    Ok(())
}

fn test_idt_loaded() -> Result<(), &'static str> {
    let mut idtr: [u8; 10] = [0; 10];
    unsafe {
        core::arch::asm!("sidt [{}]", in(reg) &mut idtr, options(nostack));
    }
    let limit = u16::from_le_bytes([idtr[0], idtr[1]]);
    if limit < 0xFFF {
        return Err("IDT limit too small");
    }
    Ok(())
}

fn test_stack_sanity() -> Result<(), &'static str> {
    let rsp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack));
    }
    if rsp < 0x100000 || rsp > 0x200000 {
        return Err("RSP outside expected range");
    }
    Ok(())
}

fn test_bootstrap_cpu() -> Result<(), &'static str> {
    let apic_base: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") 0x1Bu32,
            out("eax") apic_base,
            out("edx") _,
            options(nomem, nostack),
        );
    }
    if apic_base & (1 << 8) == 0 {
        return Err("boot CPU is not marked as BSP in IA32_APIC_BASE");
    }
    Ok(())
}

fn test_pku_xsave_consistent() -> Result<(), &'static str> {
    let features = core::arch::x86_64::__cpuid_count(7, 0);
    let xsave = core::arch::x86_64::__cpuid_count(0xD, 0);
    if features.ecx & (1 << 3) != 0 && xsave.eax & (1 << 9) == 0 {
        return Err("PKU advertised without PKRU XSAVE state");
    }
    Ok(())
}
