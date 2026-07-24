//! Synchronisation primitives used by the cross-core `execute()` protocol:
//! a counting semaphore and `OpLockGuard` wrappers around the `op_lock`
//! RW spinlock.

use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

use capability_engine::{OpLockGuard, Platform, Semaphore as EngineSemaphore};

// ── Counting semaphore ──────────────────────────────────────────────────── //

/// A counting semaphore for one phase of the cross-core IPI protocol.
///
/// `release(n)` adds `n` permits and never blocks. `acquire(n)` blocks the
/// calling core until `n` permits are cumulatively available, atomically
/// consuming them. Unlike the old two-phase reusable `Barrier`, there is no
/// generation/reset logic: each transaction constructs a fresh `Semaphore`
/// per phase (see `CoreSyncPoints`), used exactly once.
pub(super) struct Semaphore {
    permits: AtomicUsize,
}

impl Semaphore {
    pub(super) const fn new() -> Self {
        Semaphore {
            permits: AtomicUsize::new(0),
        }
    }

    /// Add `n` permits. Never blocks.
    fn release(&self, n: usize) {
        if n == 0 {
            return;
        }
        self.permits.fetch_add(n, Ordering::Release);
    }

    /// Block until `n` permits are available, then atomically consume them.
    fn acquire(&self, n: usize) {
        if n == 0 {
            return;
        }
        loop {
            let current = self.permits.load(Ordering::Acquire);
            if current >= n
                && self
                    .permits
                    .compare_exchange_weak(
                        current,
                        current - n,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
            {
                return;
            }
            core::hint::spin_loop();
        }
    }
}

impl EngineSemaphore for Semaphore {
    fn acquire(&self, n: usize) {
        Semaphore::acquire(self, n)
    }
    fn release(&self, n: usize) {
        Semaphore::release(self, n)
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
    /// Acquire the shared lock, polling the cross-core protocol while
    /// waiting.
    ///
    /// Using a plain `lock.read()` here would spin without ever draining
    /// this core's per-core update queue.  If another core is at the
    /// moment holding exclusive (e.g. a revoke initiator sitting at
    /// barrier 0 waiting for us to acknowledge), we would deadlock: it
    /// waits for our poll to arrive, we wait for its exclusive guard to
    /// drop.  Poll-while-spinning breaks that cycle — same reason
    /// `execute()` polls on `try_acquire_update_lock`.
    pub(super) fn new(lock: &RwLock<()>, platform: &super::ThemisPlatform) -> Self {
        loop {
            if let Some(guard) = lock.try_read() {
                // SAFETY: `lock` lives as long as `ThemisPlatform`
                // which outlives any guard it produces ('static in
                // practice).
                let guard: spin::RwLockReadGuard<'static, ()> =
                    unsafe { core::mem::transmute(guard) };
                return SharedGuard(ManuallyDrop::new(guard));
            }
            platform.poll_and_respond_cross_core();
        }
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
    /// Acquire the exclusive lock, polling the cross-core protocol while
    /// waiting.  See `SharedGuard::new` for the deadlock rationale.
    pub(super) fn new(lock: &RwLock<()>, platform: &super::ThemisPlatform) -> Self {
        loop {
            if let Some(guard) = lock.try_write() {
                let guard: spin::RwLockWriteGuard<'static, ()> =
                    unsafe { core::mem::transmute(guard) };
                return ExclusiveGuard(ManuallyDrop::new(guard));
            }
            platform.poll_and_respond_cross_core();
        }
    }
}
impl Drop for ExclusiveGuard {
    fn drop(&mut self) {
        unsafe { ManuallyDrop::drop(&mut self.0) };
    }
}
impl OpLockGuard for ExclusiveGuard {}
unsafe impl Send for ExclusiveGuard {}
