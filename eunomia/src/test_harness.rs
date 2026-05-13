//! Test harness — declarative test registration and sequential runner.
//!
//! Tests are collected in a static array, run sequentially, and results
//! are reported over serial.  The kernel exits via the best available
//! mechanism:
//!   - CHV: ACPI shutdown (port 0x600, SLP_TYP=5)
//!   - QEMU: isa-debug-exit (port 0xF4)
//!   - Fallback: HLT loop

/// A single test case.
pub struct TestCase {
    pub name: &'static str,
    pub func: fn() -> Result<(), &'static str>,
}

/// Exit the guest cleanly.
///
/// Tries CHV ACPI shutdown first (port 0x600), then QEMU debug-exit
/// (port 0xF4), then halts.
pub fn guest_exit(success: bool) -> ! {
    // CHV ACPI shutdown: write SLP_TYP=5 (S5 sleep) + SLP_EN to port 0x600.
    // Value: (5 << 2) | (1 << 5) = 0x34 for shutdown.
    // For failure we still shut down but print the result on serial first.
    const ACPI_SHUTDOWN_PORT: u16 = 0x600;
    const ACPI_S5_SHUTDOWN: u8 = (5 << 2) | (1 << 5); // 0x34
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") ACPI_SHUTDOWN_PORT,
            in("al") ACPI_S5_SHUTDOWN,
            options(nostack, preserves_flags),
        );
    }

    // QEMU isa-debug-exit: port 0xF4, exit code = (val << 1) | 1.
    // 0x00 → exit 1 (success), 0x01 → exit 3 (failure).
    let qemu_code: u8 = if success { 0x00 } else { 0x01 };
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") 0xF4u16,
            in("al") qemu_code,
            options(nostack, preserves_flags),
        );
    }

    // Last resort: halt.
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}

/// Run all tests, print results, and exit.
pub fn run(tests: &[TestCase]) -> ! {
    crate::println!("--- running {} tests ---", tests.len());

    let mut passed = 0usize;
    let mut failed = 0usize;

    for test in tests {
        crate::print!("test {} ... ", test.name);
        match (test.func)() {
            Ok(()) => {
                crate::println!("ok");
                passed += 1;
            }
            Err(msg) => {
                crate::println!("FAILED: {}", msg);
                failed += 1;
            }
        }
    }

    crate::println!("--- results: {} passed, {} failed ---", passed, failed);

    if failed == 0 {
        guest_exit(true);
    } else {
        guest_exit(false);
    }
}
