//! Built-in test workload.

mod smoke;

use eunomia::test_harness::TestCase;

/// All registered tests.
static TESTS: &[TestCase] = &[
    TestCase { name: "serial_output", func: smoke::test_serial_output },
    TestCase { name: "gdt_loaded", func: smoke::test_gdt_loaded },
    TestCase { name: "idt_loaded", func: smoke::test_idt_loaded },
    TestCase { name: "stack_sanity", func: smoke::test_stack_sanity },
];

/// Workload entry point — runs the test suite and exits.
pub fn app_main(_services: &eunomia::KernelServices) -> ! {
    eunomia::test_harness::run(TESTS);
}
