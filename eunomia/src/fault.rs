//! Fault handling subsystem — workload-installable exception hooks.
//!
//! Per the eunomia design (§4.1 in `docs/architecture/eunomia.md`), each
//! major subsystem is trait-shaped so workloads can customize behaviour.
//! Exception handling is one such subsystem.
//!
//! The default policy — dump registers and halt — is fine for the smoke
//! tests, but policy-probing workloads (e.g. `wrmsr`, `cpuid_policy`)
//! need to *expect* faults on some instructions and continue.  Rather
//! than baking fixup tables into the IDT, workloads install a
//! [`FaultHandler`] before running tests.  [`crate::idt`] consults it
//! on every exception and, if the handler says [`FaultOutcome::Resume`],
//! rewrites the interrupt-frame RIP and returns (iretq resumes at the
//! new address).
//!
//! ## KISS registration
//!
//! Single global slot.  `install()` replaces the previous handler.  A
//! workload that needs to combine multiple sources (e.g. MSR fixups
//! *and* CPUID fixups) composes them into a single implementation.
//!
//! ## Safety of the resume path
//!
//! `FaultOutcome::Resume(rip)` writes `rip` into `InterruptFrame::rip`
//! before iretq.  The workload is responsible for making sure the
//! resume RIP points at valid, executable code in the same CS.  This
//! is exactly the classic "extable"/`__ex_table` pattern from the
//! Linux kernel.

use crate::idt::InterruptFrame;
use core::sync::atomic::{AtomicPtr, Ordering};

/// Outcome of a fault-handler decision.
#[derive(Debug, Clone, Copy)]
pub enum FaultOutcome {
    /// Handled — resume execution at this RIP.  The IDT dispatch will
    /// overwrite `frame.rip` before returning to the interrupted CS.
    Resume(u64),
    /// This handler doesn't recognise the fault.  IDT falls through to
    /// the default fatal path (register dump + halt).
    Unhandled,
    /// Fatal — same effect as [`FaultOutcome::Unhandled`] but signals
    /// intent (handler saw the fault, wants to escalate).
    Fatal,
}

/// A workload-installable fault hook.
///
/// Implementations must be `Sync` because dispatch happens from an
/// interrupt stack that may run on any core.
pub trait FaultHandler: Sync {
    /// Inspect the fault; optionally direct resume elsewhere.
    ///
    /// The handler may read *and* mutate `frame` (for example to patch
    /// argument registers before resuming).  Only `frame.rip` is
    /// automatically honoured via [`FaultOutcome::Resume`].
    fn on_fault(&self, frame: &mut InterruptFrame) -> FaultOutcome;
}

// Single-slot registry.  We store a `*const dyn FaultHandler`, split
// into (data, vtable) inside an `AtomicPtr` to a thin wrapper.  Simpler:
// keep a raw pointer to a `&'static dyn FaultHandler` (fat pointer) via
// an intermediate `HandlerSlot` box in .data.
struct HandlerSlot {
    inner: &'static dyn FaultHandler,
}

static ACTIVE: AtomicPtr<HandlerSlot> = AtomicPtr::new(core::ptr::null_mut());

/// Install `h` as the active fault handler.  Any prior handler is
/// simply replaced (no chaining) — the caller is responsible for
/// composing multiple sources into one.
///
/// The slot is `'static` because a fault may fire at any time until
/// the guest exits.
pub fn install(h: &'static dyn FaultHandler) {
    // Leak a small slot in the bump allocator; this is a one-time
    // install so leaking is fine (and there is no free in the bump
    // allocator anyway).
    let slot = alloc::boxed::Box::leak(alloc::boxed::Box::new(HandlerSlot { inner: h }));
    ACTIVE.store(slot as *mut HandlerSlot, Ordering::Release);
}

/// Remove any installed handler.  Faults revert to the fatal default.
pub fn uninstall() {
    ACTIVE.store(core::ptr::null_mut(), Ordering::Release);
}

/// Consult the active handler, if any.  Called from
/// [`crate::idt::exception_handler`] on every exception.
pub fn dispatch(frame: &mut InterruptFrame) -> FaultOutcome {
    let p = ACTIVE.load(Ordering::Acquire);
    if p.is_null() {
        return FaultOutcome::Unhandled;
    }
    // SAFETY: only [`install`] writes this pointer, and it always
    // stores a Box-leaked, `'static` slot; the slot is never freed.
    let slot: &HandlerSlot = unsafe { &*p };
    slot.inner.on_fault(frame)
}
