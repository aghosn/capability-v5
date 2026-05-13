//! PVH info workload — validates hvm_start_info struct from the VMM.
//!
//! Under CHV (real PVH boot), the struct is properly populated.
//! Under QEMU microvm (Linux boot protocol), the pointer is garbage.

#![no_std]
#![no_main]

use eunomia::test_harness::TestCase;

extern crate eunomia;

// ── hvm_start_info layout (matches Xen PVH ABI) ─────────────────────── //

const HVM_START_MAGIC: u32 = 0x336e_c578;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct HvmStartInfo {
    magic: u32,
    version: u32,
    flags: u32,
    nr_modules: u32,
    modlist_paddr: u64,
    cmdline_paddr: u64,
    rsdp_paddr: u64,
    memmap_paddr: u64,
    memmap_entries: u32,
    _reserved: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct HvmMemmapEntry {
    addr: u64,
    size: u64,
    type_: u32,
    _reserved: u32,
}

/// Stash the hvm_start_info pointer for tests.
static mut HVM_PTR: u64 = 0;

static TESTS: &[TestCase] = &[
    TestCase { name: "pvh_magic",       func: test_pvh_magic },
    TestCase { name: "pvh_version",     func: test_pvh_version },
    TestCase { name: "pvh_memmap",      func: test_pvh_memmap },
    TestCase { name: "pvh_rsdp",        func: test_pvh_rsdp },
    TestCase { name: "pvh_dump",        func: test_pvh_dump },
];

#[no_mangle]
pub fn app_main(services: &eunomia::KernelServices) -> ! {
    unsafe { HVM_PTR = services.hvm_start_info; }
    eunomia::test_harness::run(TESTS);
}

fn info() -> &'static HvmStartInfo {
    let ptr = unsafe { *(&raw const HVM_PTR) };
    unsafe { &*(ptr as *const HvmStartInfo) }
}

fn test_pvh_magic() -> Result<(), &'static str> {
    let si = info();
    if si.magic == HVM_START_MAGIC {
        eunomia::println!("  magic = {:#010x} (valid)", si.magic);
        Ok(())
    } else {
        eunomia::println!("  magic = {:#010x} (expected {:#010x})", si.magic, HVM_START_MAGIC);
        Err("hvm_start_info magic mismatch — not a real PVH boot?")
    }
}

fn test_pvh_version() -> Result<(), &'static str> {
    let si = info();
    if si.version >= 1 {
        eunomia::println!("  version = {}", si.version);
        Ok(())
    } else {
        Err("hvm_start_info version < 1")
    }
}

fn test_pvh_memmap() -> Result<(), &'static str> {
    let si = info();
    if si.memmap_entries == 0 {
        return Err("no memory map entries");
    }
    eunomia::println!("  memmap: {} entries @ {:#x}", si.memmap_entries, si.memmap_paddr);

    let entries = unsafe {
        core::slice::from_raw_parts(
            si.memmap_paddr as *const HvmMemmapEntry,
            si.memmap_entries as usize,
        )
    };

    let mut total_ram: u64 = 0;
    for (i, e) in entries.iter().enumerate() {
        let type_str = match e.type_ {
            1 => "RAM",
            2 => "Reserved",
            3 => "ACPI",
            4 => "NVS",
            _ => "Unknown",
        };
        eunomia::println!("    [{i}] {:#010x}..{:#010x} ({type_str})", e.addr, e.addr + e.size);
        if e.type_ == 1 {
            total_ram += e.size;
        }
    }
    eunomia::println!("  total RAM: {} MiB", total_ram / (1024 * 1024));

    if total_ram == 0 {
        return Err("no RAM entries in memory map");
    }
    Ok(())
}

fn test_pvh_rsdp() -> Result<(), &'static str> {
    let si = info();
    if si.rsdp_paddr == 0 {
        eunomia::println!("  rsdp_paddr = 0 (no ACPI tables)");
        return Ok(()); // acceptable for minimal boot
    }
    // Validate RSDP signature "RSD PTR "
    let sig = unsafe { core::slice::from_raw_parts(si.rsdp_paddr as *const u8, 8) };
    if sig == b"RSD PTR " {
        eunomia::println!("  RSDP @ {:#x} (signature valid)", si.rsdp_paddr);
        Ok(())
    } else {
        eunomia::println!("  RSDP @ {:#x} (bad signature)", si.rsdp_paddr);
        Err("RSDP signature mismatch")
    }
}

fn test_pvh_dump() -> Result<(), &'static str> {
    let si = info();
    eunomia::println!("  flags         = {:#x}", si.flags);
    eunomia::println!("  nr_modules    = {}", si.nr_modules);
    eunomia::println!("  modlist_paddr = {:#x}", si.modlist_paddr);
    eunomia::println!("  cmdline_paddr = {:#x}", si.cmdline_paddr);
    Ok(())
}
