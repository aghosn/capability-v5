//! Smoke tests — basic sanity checks that the kernel is alive.

pub fn test_serial_output() -> Result<(), &'static str> {
    // If we got here, serial is working (the harness printed "test ...").
    Ok(())
}

pub fn test_gdt_loaded() -> Result<(), &'static str> {
    let limit: u16;
    let mut _base: u64 = 0;

    // SGDT stores the current GDT pointer.
    #[repr(C, packed)]
    struct GdtPtr {
        limit: u16,
        base: u64,
    }
    let mut ptr = GdtPtr { limit: 0, base: 0 };

    unsafe {
        core::arch::asm!("sgdt [{}]", in(reg) &mut ptr);
    }
    limit = ptr.limit;

    // Our GDT has 5 entries (NULL + Code64 + Data64 + TSS[2]) = 40 bytes.
    // Limit = size - 1 = 39.
    if limit < 39 {
        return Err("GDT limit too small");
    }
    Ok(())
}

pub fn test_idt_loaded() -> Result<(), &'static str> {
    #[repr(C, packed)]
    struct IdtPtr {
        limit: u16,
        base: u64,
    }
    let mut ptr = IdtPtr { limit: 0, base: 0 };

    unsafe {
        core::arch::asm!("sidt [{}]", in(reg) &mut ptr);
    }

    // 256 entries × 16 bytes = 4096 bytes.  Limit = 4095.
    if ptr.limit != 4095 {
        return Err("IDT limit unexpected");
    }
    Ok(())
}

pub fn test_stack_sanity() -> Result<(), &'static str> {
    // Verify RSP is in a reasonable range (between 0x100000 and 0x200000).
    let rsp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp);
    }
    if rsp < 0x100000 || rsp > 0x200000 {
        return Err("RSP out of expected range");
    }
    Ok(())
}
