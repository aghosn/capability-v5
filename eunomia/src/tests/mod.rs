//! Built-in test cases.

mod smoke;

use crate::test_harness::TestCase;

/// All registered tests.
pub static TESTS: &[TestCase] = &[
    TestCase { name: "serial_output", func: smoke::test_serial_output },
    TestCase { name: "gdt_loaded", func: smoke::test_gdt_loaded },
    TestCase { name: "idt_loaded", func: smoke::test_idt_loaded },
    TestCase { name: "stack_sanity", func: smoke::test_stack_sanity },
];
