//! Memory allocator test workload — verifies heap allocation works.

#![no_std]
#![no_main]

extern crate alloc;
extern crate eunomia;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use eunomia::test_harness::TestCase;

static TESTS: &[TestCase] = &[
    TestCase { name: "box_alloc", func: test_box_alloc },
    TestCase { name: "vec_push", func: test_vec_push },
    TestCase { name: "large_vec", func: test_large_vec },
    TestCase { name: "alignment", func: test_alignment },
    TestCase { name: "heap_stats", func: test_heap_stats },
];

#[no_mangle]
pub fn app_main(_services: &eunomia::KernelServices) -> ! {
    eunomia::test_harness::run(TESTS);
}

fn test_box_alloc() -> Result<(), &'static str> {
    let b = Box::new(42u64);
    if *b != 42 {
        return Err("Box value mismatch");
    }
    let b2 = Box::new([1u8; 128]);
    if b2[0] != 1 || b2[127] != 1 {
        return Err("Box array mismatch");
    }
    Ok(())
}

fn test_vec_push() -> Result<(), &'static str> {
    let mut v: Vec<u32> = Vec::new();
    for i in 0..100 {
        v.push(i);
    }
    if v.len() != 100 {
        return Err("Vec length mismatch");
    }
    if v[99] != 99 {
        return Err("Vec last element mismatch");
    }
    Ok(())
}

fn test_large_vec() -> Result<(), &'static str> {
    let v: Vec<u64> = vec![0xDEAD_BEEF_CAFE_BABE; 8192];
    if v.len() != 8192 {
        return Err("large vec length");
    }
    if v[4096] != 0xDEAD_BEEF_CAFE_BABE {
        return Err("large vec content");
    }
    Ok(())
}

fn test_alignment() -> Result<(), &'static str> {
    let b = Box::new(0u64);
    let addr = &*b as *const u64 as usize;
    if addr % 8 != 0 {
        return Err("u64 not 8-byte aligned");
    }
    let b128 = Box::new(0u128);
    let addr128 = &*b128 as *const u128 as usize;
    if addr128 % 16 != 0 {
        return Err("u128 not 16-byte aligned");
    }
    Ok(())
}

fn test_heap_stats() -> Result<(), &'static str> {
    let alloc = eunomia::mm::allocator();

    if alloc.heap_start() == 0 {
        return Err("heap not initialised");
    }
    if alloc.heap_end() <= alloc.heap_start() {
        return Err("heap end <= heap start");
    }
    if alloc.allocated() == 0 {
        return Err("allocated should be > 0 after prior tests");
    }

    let before = alloc.remaining();
    let v: Vec<u8> = vec![0xAA; 4096];
    core::hint::black_box(&v);
    let after = alloc.remaining();
    if after >= before {
        return Err("remaining did not decrease after 4K alloc");
    }
    Ok(())
}
