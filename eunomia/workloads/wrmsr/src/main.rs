//! WRMSR / RDMSR policy probe workload.
//!
//! Exercises Themis MSR policy actions Native / Trap / Emulate across
//! several scenarios.  A single ELF binary handles every scenario; the
//! `--themis-config` JSON tells the workload which one it is running
//! under by populating a discriminator CPUID leaf.
//!
//! Scenario tag CPUID: leaf `0x40000F00`, subleaf 0.
//!   - EBX = 0x6f6e7545  ("Euno" LE), signature.
//!   - EAX = scenario id  (1..=4, see `SCENARIOS`).
//! The policy JSON pushes this leaf via an `Emulate` cpuid override.
//!
//! Test MSRs (all in HIGH bitmap range `0xC000_0000..=0xC000_1FFF`,
//! safe to WRMSR from ring 0 in eunomia — the kernel never syscalls
//! and does not consume KERNEL_GS_BASE / TSC_AUX / FMASK):
//!   - `0xC000_0103` IA32_TSC_AUX
//!   - `0xC000_0102` IA32_KERNEL_GS_BASE
//!   - `0xC000_0084` IA32_FMASK
//!
//! Verification per MSR (in order):
//!   1. `try_rdmsr(msr)` — matches expected policy:
//!        Native   → Ok(_) (whatever the host reports)
//!        Trap     → Err(())
//!        Emulate  → Ok(seed) (the value the policy declared)
//!   2. `try_wrmsr(msr, magic)`:
//!        Native/Emulate → Ok(())
//!        Trap           → Err(())
//!   3. `try_rdmsr(msr)` readback (only if step 2 succeeded):
//!        Native   → Ok(magic)  (real hardware stored the write)
//!        Emulate  → Ok(magic)  (capavisor's per-VP store)
//!        Trap     → skipped
//!
//! The workload emits structured serial output that `run-eunomia.sh
//! --policy-suite` greps.  On any mismatch the test returns `Err` and
//! the harness prints `FAILED: <msg>` + exits non-zero.

#![no_std]
#![no_main]

extern crate eunomia;

use eunomia::msr::{try_rdmsr, try_wrmsr, CAUGHT_GP_COUNT};
use eunomia::test_harness::{guest_exit, TestCase};
use core::sync::atomic::Ordering;

// ── Scenario discovery ──────────────────────────────────────────────────

const SCENARIO_LEAF: u32 = 0x40000F00;
const EUNOMIA_SIG: u32 = 0x6f6e7545; // b"Euno" LE

// ── Test MSRs ───────────────────────────────────────────────────────────

const MSR_TSC_AUX: u32 = 0xC000_0103;
const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;
const MSR_FMASK: u32 = 0xC000_0084;

// Fresh magic per MSR — distinct so a stray Emulate-to-wrong-MSR
// mistake would show up as an unexpected readback.
//
// Values MUST be hardware-legal for the target MSR, because Native
// policy passes WRMSR straight to silicon and #GPs surface as guest
// exceptions:
//   • TSC_AUX (0xC000_0103) — Intel reserved bits [63:32] must be 0.
//   • KERNEL_GS_BASE (0xC000_0102) — must be canonical (bits [63:48]
//     equal bit 47; sign-extension of the 48-bit address).
//   • FMASK (0xC000_0084) — bits [63:32] reserved / zero on Intel.
// All three magics are kept in the low canonical half (bits [63:47]=0),
// which satisfies every constraint above with a single template.
const MAGIC_TSC_AUX: u64 = 0x0000_0000_CAFE_0001;
const MAGIC_KERNEL_GS_BASE: u64 = 0x0000_0000_CAFE_0002;
const MAGIC_FMASK: u64 = 0x0000_0000_CAFE_0003; // FMASK is 32-bit reserved-high on some CPUs

// ── Expectations ────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum Expect {
    /// Native passthrough — RDMSR returns the current hardware value
    /// (unpredictable); WRMSR succeeds; readback returns the value we
    /// just wrote.
    Native,
    /// #GP on any RDMSR/WRMSR — capavisor injected the fault, our
    /// fixup handler caught it.
    Trap,
    /// Capavisor-stored value.  RDMSR returns `initial` before any
    /// WRMSR; WRMSR succeeds and updates the store; a subsequent
    /// RDMSR returns the last written value.
    Emulate { initial: u64 },
}

struct MsrCase {
    msr: u32,
    magic: u64,
    expect: Expect,
}

struct Scenario {
    id: u32,
    name: &'static str,
    cases: &'static [MsrCase],
}

static SCENARIOS: &[Scenario] = &[
    // 1. default=Native, no overrides — all MSRs Native.
    Scenario {
        id: 1,
        name: "native-default",
        cases: &[
            MsrCase { msr: MSR_TSC_AUX,         magic: MAGIC_TSC_AUX,         expect: Expect::Native },
            MsrCase { msr: MSR_KERNEL_GS_BASE,  magic: MAGIC_KERNEL_GS_BASE,  expect: Expect::Native },
            MsrCase { msr: MSR_FMASK,           magic: MAGIC_FMASK,           expect: Expect::Native },
        ],
    },
    // 2. default=Trap, no overrides — every MSR #GPs.
    Scenario {
        id: 2,
        name: "trap-default",
        cases: &[
            MsrCase { msr: MSR_TSC_AUX,         magic: MAGIC_TSC_AUX,         expect: Expect::Trap },
            MsrCase { msr: MSR_KERNEL_GS_BASE,  magic: MAGIC_KERNEL_GS_BASE,  expect: Expect::Trap },
            MsrCase { msr: MSR_FMASK,           magic: MAGIC_FMASK,           expect: Expect::Trap },
        ],
    },
    // 3. default=Trap, all three overridden Emulate with distinct seeds.
    //    Exercises the pure-Emulate path (no hardware access at all).
    Scenario {
        id: 3,
        name: "emulate-all",
        cases: &[
            MsrCase { msr: MSR_TSC_AUX,         magic: MAGIC_TSC_AUX,         expect: Expect::Emulate { initial: 0x1111 } },
            MsrCase { msr: MSR_KERNEL_GS_BASE,  magic: MAGIC_KERNEL_GS_BASE,  expect: Expect::Emulate { initial: 0x2222 } },
            MsrCase { msr: MSR_FMASK,           magic: MAGIC_FMASK,           expect: Expect::Emulate { initial: 0x3333 } },
        ],
    },
    // 4. default=Trap, one Native override, one Emulate override, one
    //    left to default (Trap).  Exercises the mixed / default path.
    Scenario {
        id: 4,
        name: "mixed-default-trap",
        cases: &[
            MsrCase { msr: MSR_TSC_AUX,         magic: MAGIC_TSC_AUX,         expect: Expect::Native },
            MsrCase { msr: MSR_KERNEL_GS_BASE,  magic: MAGIC_KERNEL_GS_BASE,  expect: Expect::Emulate { initial: 0xCAFE } },
            MsrCase { msr: MSR_FMASK,           magic: MAGIC_FMASK,           expect: Expect::Trap },
        ],
    },
];

// Active scenario chosen at boot from the discriminator CPUID leaf.
// Stored as a raw pointer so the `run(TESTS)` closure can access it
// without needing thread-local plumbing.
static mut ACTIVE: Option<&'static Scenario> = None;

// ── CPUID helper ────────────────────────────────────────────────────────

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

fn current_scenario() -> Option<&'static Scenario> {
    let (eax, ebx, _ecx, _edx) = cpuid(SCENARIO_LEAF, 0);
    if ebx != EUNOMIA_SIG {
        return None;
    }
    SCENARIOS.iter().find(|s| s.id == eax)
}

// ── The one big test that runs the scenario ────────────────────────────

fn policy_matches_expectations() -> Result<(), &'static str> {
    // SAFETY: ACTIVE is set exactly once in `app_main` before `run` is
    // called; no concurrent mutation.
    let sc = unsafe { ACTIVE }.ok_or("no active scenario (setup bug)")?;

    let mut all_ok = true;
    for case in sc.cases {
        let rd1 = try_rdmsr(case.msr);
        // Step 1: initial RDMSR must match expected policy.
        let rd1_ok = match (case.expect, rd1) {
            (Expect::Native, Ok(_)) => true,
            (Expect::Trap, Err(())) => true,
            (Expect::Emulate { initial }, Ok(v)) if v == initial => true,
            _ => false,
        };
        // Step 2: attempt the write.
        let wr = try_wrmsr(case.msr, case.magic);
        let wr_ok = match (case.expect, wr) {
            (Expect::Native, Ok(())) => true,
            (Expect::Emulate { .. }, Ok(())) => true,
            (Expect::Trap, Err(())) => true,
            _ => false,
        };
        // Step 3: readback if write succeeded.
        let (rd2, rd2_ok) = if wr.is_ok() {
            let r = try_rdmsr(case.msr);
            let ok = match (case.expect, r) {
                (Expect::Native, Ok(v)) if v == case.magic => true,
                (Expect::Emulate { .. }, Ok(v)) if v == case.magic => true,
                // Trap can never reach here — wr would have been Err.
                _ => false,
            };
            (r, ok)
        } else {
            (Err(()), true) // n/a
        };

        let case_ok = rd1_ok && wr_ok && rd2_ok;
        if !case_ok {
            all_ok = false;
        }

        // Structured log line: one per MSR, always emitted.
        eunomia::println!(
            "  MSR {:#010x} expect={:?} rd1={} wr={} rd2={} => {}",
            case.msr,
            case.expect,
            fmt_result(rd1),
            fmt_result_unit(wr),
            fmt_result(rd2),
            if case_ok { "OK" } else { "FAIL" },
        );
    }

    if all_ok {
        Ok(())
    } else {
        Err("one or more MSR probes did not match the expected policy")
    }
}

fn fmt_result(r: Result<u64, ()>) -> DisplayResult {
    DisplayResult(r)
}
fn fmt_result_unit(r: Result<(), ()>) -> DisplayResult {
    DisplayResult(r.map(|()| 0))
}
struct DisplayResult(Result<u64, ()>);
impl core::fmt::Display for DisplayResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            Ok(v) => write!(f, "Ok({:#x})", v),
            Err(()) => write!(f, "#GP"),
        }
    }
}

static TESTS: &[TestCase] = &[TestCase {
    name: "wrmsr_policy_matrix",
    func: policy_matches_expectations,
}];

// ── Entry point ─────────────────────────────────────────────────────────

#[no_mangle]
pub fn app_main(_services: &eunomia::KernelServices) -> ! {
    // Install MSR fault fixup handler before any try_rdmsr/try_wrmsr.
    eunomia::fault::install(&eunomia::msr::MSR_FAULT_HANDLER);

    let sc = match current_scenario() {
        Some(sc) => sc,
        None => {
            eunomia::println!(
                "wrmsr: FATAL — no scenario tag at CPUID {:#x} (expected EBX={:#x} 'Euno')",
                SCENARIO_LEAF,
                EUNOMIA_SIG,
            );
            eunomia::println!("wrmsr: check --themis-config policy pushes the discriminator leaf");
            guest_exit(false);
        }
    };
    // SAFETY: single-threaded init phase before test_harness::run().
    unsafe {
        ACTIVE = Some(sc);
    }

    eunomia::println!("wrmsr: scenario id={} name={}", sc.id, sc.name);
    eunomia::println!("wrmsr: caught_gp_before={}", CAUGHT_GP_COUNT.load(Ordering::Relaxed));

    eunomia::test_harness::run(TESTS);
}
