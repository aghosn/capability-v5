//! CPUID local handler (exit reason 10).
//!
//! Native cpuid + masking: executes `cpuid` on the physical CPU, applies
//! security masks (AVX-512 hidden, XSAVE area sized for x87+SSE+AVX), and
//! intercepts the Themis hypervisor leaves (LEAF_BASE / LEAF_FEATURES /
//! LEAF_DOMCOMM / LEAF_LIMITS / LEAF_IVSHMEM).

use capability_engine::Platform;

use crate::vcpu::{ActiveVcpu, Reg};
use crate::arch::x86_64::vcpu_ext::ActiveVcpuExt;

use super::{
    CPUID_DEBUG_RANGE_END, CPUID_DEBUG_RANGE_START, CPUID_HV_RANGE_END, CPUID_THEMIS_MAX,
    DOMCOMM_GPA, DOMCOMM_PAGES, THEMIS_MAX_MEM_REGIONS, THEMIS_MAX_PARTITIONS, THEMIS_MAX_VPS,
};

/// Handle CPUID locally: native cpuid + masking (exit reason 10).
///
/// Executes `cpuid` on the physical CPU, applies security masks (AVX-512,
/// XSAVE area), and intercepts Themis hypervisor leaves.
/// Used by both the dom0 path and child domains with `trap=false` for CPUID.
pub(super) fn handle_cpuid_local(vcpu: &mut ActiveVcpu, platform: &crate::platform::ThemisPlatform) {
    let leaf = vcpu.reg(Reg::Rax) as u32;
    let sub_leaf = vcpu.reg(Reg::Rcx) as u32;
    let result = core::arch::x86_64::__cpuid_count(leaf, sub_leaf);
    let mut eax = result.eax;
    let mut ebx = result.ebx;
    let mut ecx = result.ecx;
    let mut edx = result.edx;

    match (leaf, sub_leaf) {
        (0x1, _) => {
            ecx &= !(1u32 << 31); // hide hypervisor-present bit
        }
        (0x7, 0) => {
            // AVX-512 feature bits in CPUID.07H:0H (Intel SDM Vol 2A §3.2).
            // Hiding all of them coerces guests onto AVX2 ISA, avoiding
            // XSAVE-area sizing issues and FPU state corruption risks for
            // domains we don't expose AVX-512 to.
            bitflags::bitflags! {
                struct Avx512Ebx: u32 {
                    const AVX512F          = 1 << 16;
                    const AVX512DQ         = 1 << 17;
                    const AVX512_IFMA      = 1 << 21;
                    const AVX512PF         = 1 << 26;
                    const AVX512ER         = 1 << 27;
                    const AVX512CD         = 1 << 28;
                    const AVX512BW         = 1 << 30;
                    const AVX512VL         = 1 << 31;
                }
                struct Avx512Ecx: u32 {
                    const AVX512_VBMI       = 1 << 1;
                    const AVX512_VBMI2      = 1 << 6;
                    const AVX512_VNNI       = 1 << 11;
                    const AVX512_BITALG     = 1 << 12;
                    const AVX512_VPOPCNTDQ  = 1 << 14;
                    // Bits 4 and 5 in this mask are reserved/AVX-512-adjacent
                    // (kept for parity with the pre-bitflags mask).
                    const RESERVED_BIT_4    = 1 << 4;
                    const RESERVED_BIT_5    = 1 << 5;
                }
                struct Avx512Edx: u32 {
                    const AVX512_4VNNIW       = 1 << 2;
                    const AVX512_4FMAPS       = 1 << 3;
                    const AVX512_VP2INTERSECT = 1 << 8;
                    const AVX512_FP16         = 1 << 23;
                }
            }
            ebx &= !Avx512Ebx::all().bits();
            ecx &= !Avx512Ecx::all().bits();
            edx &= !Avx512Edx::all().bits();
        }
        (0xD, 0) => {
            eax = 0x7; // x87 + SSE + AVX
            ebx = 0x340;
            ecx = 0x340;
            edx = 0;
        }
        (0xD, 1) => {
            ebx = 0x340;
            ecx = 0;
            edx = 0;
        }
        (0xD, sub) if matches!(sub, 5..=7 | 9) => {
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
        (themis_abi::cpuid::LEAF_BASE, _) => {
            eax = CPUID_THEMIS_MAX;
            ebx = themis_abi::cpuid::SIG_EBX;
            ecx = themis_abi::cpuid::SIG_ECX;
            edx = themis_abi::cpuid::SIG_EDX;
        }
        (themis_abi::cpuid::LEAF_FEATURES, _) => {
            eax = 0b00001;
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
        (themis_abi::cpuid::LEAF_DOMCOMM, _) => {
            // Per-domain DomainComm discovery: look up the calling domain's
            // DomainComm header HPA.  Falls back to the global dom0 value
            // for domains that don't have their own DomainComm yet.
            let mut found = false;
            if let Some(core_id) = platform.get_current_core() {
                let dom_id = platform.core_domain_id(core_id as usize);
                if let Some(arc) = platform.domain_arc(dom_id) {
                    let pd = arc.lock();
                    if let Some(ref dc) = pd.domcomm {
                        eax = dc.header_hpa as u32;
                        ebx = (dc.header_hpa >> 32) as u32;
                        ecx = 1 + dc.rx.page_hpas.len() as u32 + dc.tx.page_hpas.len() as u32;
                        edx = 0;
                        found = true;
                    }
                }
            }
            if !found {
                // Fallback: global dom0 values (bootstrap path).
                let gpa = DOMCOMM_GPA.load(core::sync::atomic::Ordering::Relaxed);
                let pages = DOMCOMM_PAGES.load(core::sync::atomic::Ordering::Relaxed);
                eax = gpa as u32;
                ebx = (gpa >> 32) as u32;
                ecx = pages;
                edx = 0;
            }
        }
        (themis_abi::cpuid::LEAF_LIMITS, _) => {
            eax = THEMIS_MAX_VPS;
            ebx = THEMIS_MAX_PARTITIONS;
            ecx = THEMIS_MAX_MEM_REGIONS;
            edx = 0;
        }
        // Leaf 0x40000004: ivshmem device info (subleaf = device index).
        // Values are pushed by CHV as Emulate overrides via SET_POLICY.
        // Native handler returns zeros (no ivshmem when handled locally).
        (themis_abi::cpuid::LEAF_IVSHMEM, _) => {
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
        (themis_abi::cpuid::LEAF_BASE..=CPUID_HV_RANGE_END, _) => {
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
        (CPUID_DEBUG_RANGE_START..=CPUID_DEBUG_RANGE_END, _) => {
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
        // Leaf 0x15: TSC / Core Crystal Clock
        (0x15, _) => {
            eax = 1; // denominator
            ebx = 120; // numerator
            ecx = 25_000_000; // crystal Hz
            edx = 0;
        }
        _ => {}
    }

    vcpu.set_reg(Reg::Rax, eax as u64);
    vcpu.set_reg(Reg::Rbx, ebx as u64);
    vcpu.set_reg(Reg::Rcx, ecx as u64);
    vcpu.set_reg(Reg::Rdx, edx as u64);
    vcpu.next_rip();
}
