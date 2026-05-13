//! Hypercall interface test workload.
//!
//! Tests the HypervisorInterface trait with the StubBackend (QEMU mode)
//! and verifies the hypercall constant definitions.

#![no_std]
#![no_main]

extern crate eunomia;

use eunomia::hv::{self, HvError, HypervisorInterface, StubBackend, ThemisBackend};
use eunomia::test_harness::TestCase;

static TESTS: &[TestCase] = &[
    TestCase { name: "stub_not_available", func: test_stub_not_available },
    TestCase { name: "stub_hypercall_fails", func: test_stub_hypercall_fails },
    TestCase { name: "themis_available", func: test_themis_available },
    TestCase { name: "hypercall_constants", func: test_hypercall_constants },
    TestCase { name: "hv_trait_dispatch", func: test_hv_trait_dispatch },
];

#[no_mangle]
pub fn app_main(_services: &eunomia::KernelServices) -> ! {
    eunomia::test_harness::run(TESTS);
}

fn test_stub_not_available() -> Result<(), &'static str> {
    let stub = StubBackend;
    if stub.is_available() {
        return Err("stub should not be available");
    }
    Ok(())
}

fn test_stub_hypercall_fails() -> Result<(), &'static str> {
    let stub = StubBackend;
    match stub.hypercall(hv::HC_ENUMERATE, [0, 0, 0]) {
        Err(HvError::NotSupported) => Ok(()),
        Ok(_) => Err("stub hypercall should fail"),
        Err(_) => Err("wrong error type"),
    }
}

fn test_themis_available() -> Result<(), &'static str> {
    let themis = ThemisBackend;
    // ThemisBackend always reports available (by design).
    if !themis.is_available() {
        return Err("ThemisBackend should report available");
    }
    Ok(())
}

fn test_hypercall_constants() -> Result<(), &'static str> {
    // Verify key constants match thhv.h definitions.
    if hv::HC_CARVE != 0x01 { return Err("HC_CARVE"); }
    if hv::HC_SEND != 0x03 { return Err("HC_SEND"); }
    if hv::HC_SWITCH != 0x0A { return Err("HC_SWITCH"); }
    if hv::HC_ENUMERATE != 0x13 { return Err("HC_ENUMERATE"); }
    if hv::HC_MAP_SELF != 0x1F { return Err("HC_MAP_SELF"); }
    if hv::HC_SET_POLICY != 0x22 { return Err("HC_SET_POLICY"); }
    Ok(())
}

fn test_hv_trait_dispatch() -> Result<(), &'static str> {
    // Test dynamic dispatch through the trait.
    let backend: &dyn HypervisorInterface = &StubBackend;
    match hv::enumerate(backend) {
        Err(HvError::NotSupported) => Ok(()),
        _ => Err("enumerate on stub should be NotSupported"),
    }
}
