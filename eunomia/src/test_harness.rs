//! Test harness — declarative test registration and sequential runner.
//!
//! Tests are collected in a static array, run sequentially, and results
//! are reported over serial.  The kernel exits via I/O port 0xF4 (QEMU
//! isa-debug-exit device) with a success/failure exit code.

/// A single test case.
pub struct TestCase {
    pub name: &'static str,
    pub func: fn() -> Result<(), &'static str>,
}

/// Exit codes written to QEMU's isa-debug-exit port (0xF4).
/// QEMU exits with `(value << 1) | 1`, so:
///   0x00 → exit code 1  (success, since 0 is reserved)
///   0x01 → exit code 3  (failure)
const EXIT_SUCCESS: u8 = 0x00;
const EXIT_FAILURE: u8 = 0x01;

fn qemu_exit(code: u8) -> ! {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") 0xF4u16,
            in("al") code,
            options(nostack, noreturn),
        );
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
        qemu_exit(EXIT_SUCCESS);
    } else {
        qemu_exit(EXIT_FAILURE);
    }
}
