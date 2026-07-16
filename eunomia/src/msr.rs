//! Safe RDMSR / WRMSR helpers with #GP fault fixup.
//!
//! Trapped MSRs under a Themis policy produce a #GP into the guest.
//! Workloads that probe policy behaviour need to catch those faults
//! rather than halt — this module provides `try_rdmsr` / `try_wrmsr`
//! that return `Err(())` on #GP and `Ok(_)` on success.
//!
//! The mechanism is a small fixup table:
//!
//!   * A `global_asm!` block defines two functions (`__try_rdmsr_asm`,
//!     `__try_wrmsr_asm`), each with a named fault label (points at the
//!     rdmsr/wrmsr instruction itself) and an end label (fault-return
//!     path).
//!   * The #GP handler in [`crate::idt`] consults [`fixup_for_rip`]; if
//!     the faulting RIP matches one of the fault labels, it rewrites
//!     `frame.rip` to the corresponding end label and returns.  The
//!     asm callee-return path stores 1 in `rax` to signal "faulted",
//!     so the Rust wrapper sees the fault.

use core::sync::atomic::{AtomicU64, Ordering};

unsafe extern "C" {
    fn __try_rdmsr_asm(msr: u32, out: *mut u64) -> u32;
    fn __try_wrmsr_asm(msr: u32, value: u64) -> u32;

    // Fault labels — addresses of the rdmsr/wrmsr instructions.
    static __try_rdmsr_fault: u8;
    static __try_rdmsr_fixup: u8;
    static __try_wrmsr_fault: u8;
    static __try_wrmsr_fixup: u8;
}

core::arch::global_asm!(
    r#"
    .text

    /* u32 __try_rdmsr_asm(u32 msr, u64 *out)
     *   rdi = msr (only low 32 bits used)
     *   rsi = out pointer
     * Returns 0 on success, 1 on #GP (caught via fixup).
     */
    .globl __try_rdmsr_asm
    __try_rdmsr_asm:
        mov  ecx, edi
        xor  eax, eax
        xor  edx, edx
    .globl __try_rdmsr_fault
    __try_rdmsr_fault:
        rdmsr
        shl  rdx, 32
        or   rdx, rax
        mov  [rsi], rdx
        xor  eax, eax
        ret
    .globl __try_rdmsr_fixup
    __try_rdmsr_fixup:
        mov  eax, 1
        ret

    /* u32 __try_wrmsr_asm(u32 msr, u64 value)
     *   edi = msr
     *   rsi = value
     * Returns 0 on success, 1 on #GP.
     */
    .globl __try_wrmsr_asm
    __try_wrmsr_asm:
        mov  ecx, edi
        mov  rax, rsi
        mov  rdx, rsi
        shr  rdx, 32
        /* eax already low32 of rsi (mov rax,rsi; wrmsr uses eax:edx) */
    .globl __try_wrmsr_fault
    __try_wrmsr_fault:
        wrmsr
        xor  eax, eax
        ret
    .globl __try_wrmsr_fixup
    __try_wrmsr_fixup:
        mov  eax, 1
        ret
    "#
);

/// Try to read `msr`.
///
/// Returns `Ok(value)` if the RDMSR succeeded, `Err(())` if it raised
/// #GP (typically because the MSR is under a `Trap` policy or the guest
/// bitmap for it is closed and no policy override provides a value).
#[inline]
pub fn try_rdmsr(msr: u32) -> Result<u64, ()> {
    let mut out: u64 = 0;
    let rc = unsafe { __try_rdmsr_asm(msr, &mut out) };
    if rc == 0 { Ok(out) } else { Err(()) }
}

/// Try to write `value` to `msr`.
///
/// Returns `Ok(())` on success, `Err(())` if the WRMSR raised #GP.
#[inline]
pub fn try_wrmsr(msr: u32, value: u64) -> Result<(), ()> {
    let rc = unsafe { __try_wrmsr_asm(msr, value) };
    if rc == 0 { Ok(()) } else { Err(()) }
}

/// Counter of #GP faults caught by the fixup mechanism.
///
/// Incremented by [`MsrFaultHandler::on_fault`] each time it redirects
/// a fault.  Useful in tests to detect that a probe genuinely trapped
/// rather than silently succeeded (Native) or returned a bogus value.
pub static CAUGHT_GP_COUNT: AtomicU64 = AtomicU64::new(0);

/// [`crate::fault::FaultHandler`] that resumes past RDMSR/WRMSR
/// instructions raising #GP.
///
/// Workloads install it via
/// `eunomia::fault::install(&eunomia::msr::MSR_FAULT_HANDLER)` before
/// calling [`try_rdmsr`] / [`try_wrmsr`].
pub struct MsrFaultHandler;

/// Static singleton — install once at workload startup.
pub static MSR_FAULT_HANDLER: MsrFaultHandler = MsrFaultHandler;

impl crate::fault::FaultHandler for MsrFaultHandler {
    fn on_fault(&self, frame: &mut crate::idt::InterruptFrame) -> crate::fault::FaultOutcome {
        // Only #GP is our concern.
        if frame.vector != 13 {
            return crate::fault::FaultOutcome::Unhandled;
        }
        let rip = frame.rip;
        let rd_fault = unsafe { &__try_rdmsr_fault as *const u8 as u64 };
        let rd_fixup = unsafe { &__try_rdmsr_fixup as *const u8 as u64 };
        let wr_fault = unsafe { &__try_wrmsr_fault as *const u8 as u64 };
        let wr_fixup = unsafe { &__try_wrmsr_fixup as *const u8 as u64 };
        if rip == rd_fault {
            CAUGHT_GP_COUNT.fetch_add(1, Ordering::Relaxed);
            return crate::fault::FaultOutcome::Resume(rd_fixup);
        }
        if rip == wr_fault {
            CAUGHT_GP_COUNT.fetch_add(1, Ordering::Relaxed);
            return crate::fault::FaultOutcome::Resume(wr_fixup);
        }
        crate::fault::FaultOutcome::Unhandled
    }
}
