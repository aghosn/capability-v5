//! Synchronisation primitives used by the cross-core `execute()` protocol:
//! a reusable two-phase barrier and `OpLockGuard` wrappers around the
//! `op_lock` RW spinlock.

use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

use capability_engine::OpLockGuard;

// ── Two-phase synchronisation barrier ─────────────────────────────────────── //

/// Reusable two-phase barrier for the cross-core IPI protocol.
///
/// The initiating core calls `wait(participants)` which stores the expected
/// count.  Responding cores call `wait(0)` to read the stored count and wait.
pub(super) struct Barrier {
    /// Total participants expected; written by the initiating core (participants > 0)
    /// before it begins spinning.  Responding cores use the stored value (pass 0).
    expected: AtomicUsize,
    /// How many cores have arrived so far in the current generation.
    arrived: AtomicUsize,
    /// Incremented when all participants arrive, allowing barrier reuse.
    generation: AtomicUsize,
}

impl Barrier {
    pub(super) const fn new() -> Self {
        Barrier {
            expected: AtomicUsize::new(0),
            arrived: AtomicUsize::new(0),
            generation: AtomicUsize::new(0),
        }
    }

    /// Arrive and wait until all expected participants have arrived.
    ///
    /// * `participants > 0` — store as new expected count (initiating core).
    /// * `participants == 0` — use the previously stored count (responding core).
    pub(super) fn wait(&self, participants: usize) {
        if participants > 0 {
            self.expected.store(participants, Ordering::Release);
        }
        // Spin until the initiating core has stored a non-zero expected count.
        let expected = loop {
            let e = self.expected.load(Ordering::Acquire);
            if e > 0 {
                break e;
            }
            core::hint::spin_loop();
        };
        let gen = self.generation.load(Ordering::Acquire);
        let n = self.arrived.fetch_add(1, Ordering::AcqRel) + 1;
        if n >= expected {
            // Last to arrive: reset for the next use, then advance generation.
            self.arrived.store(0, Ordering::Release);
            self.expected.store(0, Ordering::Release);
            self.generation.fetch_add(1, Ordering::Release);
        } else {
            while self.generation.load(Ordering::Acquire) == gen {
                core::hint::spin_loop();
            }
        }
    }
}
// ── RW-spinlock guards ─────────────────────────────────────────────────────── //
//
// `spin::RwLock` guards carry a lifetime tied to the lock reference.  Since
// `ThemisPlatform` is effectively `'static` (created in `_start` and never
// dropped), we transmute the guard lifetime to `'static` so the guards can be
// boxed as `Box<dyn OpLockGuard + Send>`.
//
// `ManuallyDrop` is used so we can implement `Drop` ourselves; the inner guard's
// destructor releases the spinlock when we manually drop it.

/// Guard for a shared (read) capability-tree lock.
pub(super) struct SharedGuard(ManuallyDrop<spin::RwLockReadGuard<'static, ()>>);

impl SharedGuard {
    pub(super) fn new(lock: &RwLock<()>) -> Self {
        // SAFETY: `lock` lives as long as `ThemisPlatform` which outlives
        // any guard it produces ('static in practice).
        let guard: spin::RwLockReadGuard<'static, ()> =
            unsafe { core::mem::transmute(lock.read()) };
        SharedGuard(ManuallyDrop::new(guard))
    }
}
impl Drop for SharedGuard {
    fn drop(&mut self) {
        unsafe { ManuallyDrop::drop(&mut self.0) };
    }
}
impl OpLockGuard for SharedGuard {}
// SAFETY: tied to a 'static platform; moving a guard across logical "threads"
// (monitor entries) on the same physical core is intentional.
unsafe impl Send for SharedGuard {}

/// Guard for an exclusive (write) capability-tree lock.
pub(super) struct ExclusiveGuard(ManuallyDrop<spin::RwLockWriteGuard<'static, ()>>);

impl ExclusiveGuard {
    pub(super) fn new(lock: &RwLock<()>) -> Self {
        let guard: spin::RwLockWriteGuard<'static, ()> =
            unsafe { core::mem::transmute(lock.write()) };
        ExclusiveGuard(ManuallyDrop::new(guard))
    }
}
impl Drop for ExclusiveGuard {
    fn drop(&mut self) {
        unsafe { ManuallyDrop::drop(&mut self.0) };
    }
}
impl OpLockGuard for ExclusiveGuard {}
unsafe impl Send for ExclusiveGuard {}
