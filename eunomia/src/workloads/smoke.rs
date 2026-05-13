//! Smoke test workload — basic sanity checks.

use eunomia::test_harness::TestCase;

static TESTS: &[TestCase] = &[
    TestCase { name: "serial_output", func: test_serial_output },
    TestCase { name: "gdt_loaded", func: test_gdt_loaded },
    TestCase { name: "idt_loaded", func: test_idt_loaded },
    TestCase { name: "stack_sanity", func: test_stack_sanity },
];

pub fn app_main(_services: &eunomia::KernelServices) -> ! {
    eunomia::test_harness::run(TESTS);
}

fn test_serial_output() -> Result<(), &'static str> {
    Ok(())
}

fn test_gdt_loaded() -> Result<(), &'static str> {
    #[repr(C, packed)]
    struct GdtPtr { limit: u16, base: u64 }
    let mut ptr = GdtPtr { limit: 0, base: 0 };
    unsafe { core::arch::asm!("sgdt [{}]", in(reg) &mut ptr); }
    if ptr.limit < 39 {
        return Err("GDT limit too small");
    }
    Ok(())
}

fn test_idt_loaded() -> Result<(), &'static str> {
    #[repr(C, packed)]
    struct IdtPtr { limit: u16, base: u64 }
    let mut ptr = IdtPtr { limit: 0, base: 0 };
    unsafe { core::arch::asm!("sidt [{}]", in(reg) &mut ptr); }
    if ptr.limit != 4095 {
        return Err("IDT limit unexpected");
    }
    Ok(())
}

fn test_stack_sanity() -> Result<(), &'static str> {
    let rsp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp); }
    if rsp < 0x100000 || rsp > 0x200000 {
        return Err("RSP out of expected range");
    }
    Ok(())
}
