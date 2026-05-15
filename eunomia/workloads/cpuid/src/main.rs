//! CPUID interposition test workload.
//!
//! Validates that CPUID instructions executed inside the guest return
//! the expected values — both for Themis hypervisor leaves (handled
//! directly by the capavisor) and for standard leaves that may be
//! emulated via the CPUID interposition policy.

#![no_std]
#![no_main]

extern crate eunomia;

use eunomia::test_harness::TestCase;

static TESTS: &[TestCase] = &[
    TestCase { name: "cpuid_vendor_string", func: test_cpuid_vendor },
    TestCase { name: "cpuid_leaf1_valid", func: test_cpuid_leaf1 },
    TestCase { name: "cpuid_leaf7_sub0", func: test_cpuid_leaf7_sub0 },
    TestCase { name: "cpuid_leaf7_sub1", func: test_cpuid_leaf7_sub1 },
    TestCase { name: "cpuid_subleaf_discrimination", func: test_subleaf_discrimination },
    TestCase { name: "cpuid_themis_base", func: test_themis_base },
    TestCase { name: "cpuid_themis_features", func: test_themis_features },
    TestCase { name: "cpuid_themis_coco", func: test_themis_coco },
    TestCase { name: "cpuid_max_basic_leaf", func: test_max_basic_leaf },
];

#[no_mangle]
pub fn app_main(_services: &eunomia::KernelServices) -> ! {
    eunomia::test_harness::run(TESTS);
}

/// Raw CPUID wrapper.
#[inline(always)]
fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let (eax, ebx, ecx, edx): (u32, u32, u32, u32);
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inlateout("eax") leaf => eax,
            ebx_out = out(reg) ebx,
            inlateout("ecx") subleaf => ecx,
            out("edx") edx,
            options(nostack),
        );
    }
    (eax, ebx, ecx, edx)
}

/// Leaf 0: vendor string should be "GenuineIntel" or "AuthenticAMD"
/// (or whatever the host CPU reports through emulation).
fn test_cpuid_vendor() -> Result<(), &'static str> {
    let (eax, ebx, ecx, edx) = cpuid(0, 0);
    // eax = max basic leaf, should be at least 1
    if eax < 1 {
        return Err("max basic leaf < 1");
    }
    // Vendor is EBX-EDX-ECX (yes, that order).
    let mut vendor = [0u8; 12];
    vendor[0..4].copy_from_slice(&ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&ecx.to_le_bytes());
    // Just check it's non-zero ASCII.
    if vendor.iter().all(|&b| b == 0) {
        return Err("vendor string is all zeros");
    }
    Ok(())
}

/// Leaf 1: family/model/stepping in EAX, feature flags in ECX/EDX.
fn test_cpuid_leaf1() -> Result<(), &'static str> {
    let (eax, _ebx, ecx, edx) = cpuid(1, 0);
    // EAX should encode a valid family (bits 11:8 + 27:20).
    let family = ((eax >> 8) & 0xF) + ((eax >> 20) & 0xFF);
    if family == 0 {
        return Err("CPUID.1 family is zero");
    }
    // ECX bit 31 = hypervisor present (should be set under Themis).
    if ecx & (1 << 31) == 0 {
        return Err("hypervisor bit not set in CPUID.1.ECX");
    }
    // EDX bit 0 = FPU, should always be present.
    if edx & 1 == 0 {
        return Err("FPU bit not set in CPUID.1.EDX");
    }
    Ok(())
}

/// Leaf 7, subleaf 0: structured extended features.
fn test_cpuid_leaf7_sub0() -> Result<(), &'static str> {
    let (eax, _ebx, _ecx, _edx) = cpuid(7, 0);
    // EAX = max subleaf index for leaf 7; should be at least 0.
    // (On modern CPUs, usually >= 1.)
    // Just verify the call doesn't crash and returns something.
    eunomia::println!("  leaf7.0: max_sub={}", eax);
    Ok(())
}

/// Leaf 7, subleaf 1: extended features (if available).
fn test_cpuid_leaf7_sub1() -> Result<(), &'static str> {
    let (max_sub, _, _, _) = cpuid(7, 0);
    if max_sub < 1 {
        eunomia::println!("  leaf7 max_sub=0, skipping sub1");
        return Ok(());
    }
    let (eax, _ebx, _ecx, _edx) = cpuid(7, 1);
    eunomia::println!("  leaf7.1: eax={:#x}", eax);
    Ok(())
}

/// Key regression test: leaf 7 subleaf 0 and subleaf 1 must return
/// different values (the subleaf bug made them identical).
fn test_subleaf_discrimination() -> Result<(), &'static str> {
    let (max_sub, _, _, _) = cpuid(7, 0);
    if max_sub < 1 {
        eunomia::println!("  leaf7 max_sub=0, cannot test discrimination");
        return Ok(());
    }
    let (eax0, ebx0, ecx0, edx0) = cpuid(7, 0);
    let (eax1, ebx1, ecx1, edx1) = cpuid(7, 1);
    // At minimum, EAX differs (sub0 = max_subleaf count, sub1 = feature bits).
    // If all four registers are identical, the subleaf bug is present.
    if eax0 == eax1 && ebx0 == ebx1 && ecx0 == ecx1 && edx0 == edx1 {
        return Err("leaf7 sub0 == sub1 — subleaf discrimination broken");
    }
    Ok(())
}

/// Leaf 0x40000000: Themis hypervisor signature "ThemisCapa  ".
fn test_themis_base() -> Result<(), &'static str> {
    let (eax, ebx, ecx, edx) = cpuid(0x40000000, 0);
    // EAX = max hypervisor leaf.
    if eax < 0x40000001 {
        return Err("Themis max HV leaf too low");
    }
    // Check signature: EBX="Them", ECX="isCa", EDX="pa  "
    let expected_ebx = u32::from_le_bytes(*b"Them");
    let expected_ecx = u32::from_le_bytes(*b"isCa");
    let expected_edx = u32::from_le_bytes(*b"pa  ");
    if ebx != expected_ebx || ecx != expected_ecx || edx != expected_edx {
        return Err("Themis signature mismatch at leaf 0x40000000");
    }
    Ok(())
}

/// Leaf 0x40000001: Themis feature flags.
fn test_themis_features() -> Result<(), &'static str> {
    let (eax, _ebx, _ecx, _edx) = cpuid(0x40000001, 0);
    // Bit 0 = basic Themis support.
    if eax & 1 == 0 {
        return Err("Themis feature bit 0 not set");
    }
    Ok(())
}

/// Leaf 0x40000100: CoCo detection — should return VTOM bit and signature.
fn test_themis_coco() -> Result<(), &'static str> {
    let (eax, ebx, ecx, edx) = cpuid(0x40000100, 0);
    // EAX = VTOM bit position (39 by default).
    if eax == 0 || eax > 63 {
        return Err("CoCo VTOM bit out of range");
    }
    // Signature: "ThemisCoCo\0\0"
    let expected_ebx = u32::from_le_bytes(*b"Them");
    let expected_ecx = u32::from_le_bytes(*b"isCo");
    let expected_edx = u32::from_le_bytes(*b"Co\0\0");
    if ebx != expected_ebx || ecx != expected_ecx || edx != expected_edx {
        return Err("CoCo signature mismatch at leaf 0x40000100");
    }
    eunomia::println!("  CoCo VTOM bit: {}", eax);
    Ok(())
}

/// Max basic leaf (leaf 0 EAX) should be reasonable.
fn test_max_basic_leaf() -> Result<(), &'static str> {
    let (eax, _, _, _) = cpuid(0, 0);
    if eax < 0x01 || eax > 0xFF {
        return Err("max basic leaf out of expected range");
    }
    eunomia::println!("  max basic leaf: {:#x}", eax);
    Ok(())
}
