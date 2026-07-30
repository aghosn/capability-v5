//! Synchronisation primitives.
//!
//! Selects the right `RwLock` implementation at compile time:
//!
//! * **`loom` feature** — wrapper around [`loom::sync::RwLock`] with a
//!   `parking_lot`-compatible API (infallible `read()` / `write()`).
//!   Used for exhaustive interleaving tests.
//!
//! * **`hosted` feature** (default) — [`parking_lot::RwLock`].  Uses OS
//!   threading primitives (futex on Linux, etc.).  Appropriate for Linux,
//!   macOS and Windows targets.
//!
//! * **bare-metal / `no_std`** (`--no-default-features`) — [`spin::RwLock`].
//!   Pure-Rust busy-wait; no libc, no syscalls.  Maps directly to a hardware
//!   RW spinlock on bare-metal SMP systems.
//!
//! All internal crate code uses `crate::sync::RwLock` so the choice is
//! invisible to callers.

// ── loom (exhaustive interleaving tests) ─────────────────────────────────────

#[cfg(feature = "loom")]
mod loom_rwlock {
    /// Wrapper around [`loom::sync::RwLock`] that provides a
    /// `parking_lot`-compatible API: `read()` and `write()` return guards
    /// directly instead of `LockResult`.  Panics on poison (acceptable in
    /// loom's deterministic model — poison means a previous iteration panicked).
    pub struct RwLock<T>(loom::sync::RwLock<T>);

    impl<T: core::fmt::Debug> core::fmt::Debug for RwLock<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_tuple("RwLock").field(&"<loom>").finish()
        }
    }

    impl<T> RwLock<T> {
        pub fn new(val: T) -> Self {
            RwLock(loom::sync::RwLock::new(val))
        }

        pub fn read(&self) -> loom::sync::RwLockReadGuard<'_, T> {
            self.0.read().unwrap()
        }

        pub fn write(&self) -> loom::sync::RwLockWriteGuard<'_, T> {
            self.0.write().unwrap()
        }

        pub fn try_read(&self) -> Option<loom::sync::RwLockReadGuard<'_, T>> {
            self.0.try_read().ok()
        }

        pub fn try_write(&self) -> Option<loom::sync::RwLockWriteGuard<'_, T>> {
            self.0.try_write().ok()
        }
    }
}

#[cfg(feature = "loom")]
pub use loom_rwlock::RwLock;

// ── hosted (OS-backed, default) ──────────────────────────────────────────────

#[cfg(all(not(feature = "loom"), feature = "hosted"))]
pub use parking_lot::RwLock;

// ── bare-metal (spin) ────────────────────────────────────────────────────────

#[cfg(all(not(feature = "loom"), not(feature = "hosted")))]
pub use spin::RwLock;

// ── lock-scope discipline ────────────────────────────────────────────────────

/// Marks a block whose only purpose is to acquire capability-tree locks
/// (via `.read()` / `.write()` on a `CapabilityRef`) and extract owned,
/// lock-independent data out of them (ids, `Arc`/`Weak` clones, copies).
///
/// This expands to nothing more than the block itself — every lock guard
/// created inside is already guaranteed by the borrow checker to be dropped
/// at the closing brace, exactly as if this macro were not used. Its entire
/// purpose is to make that boundary *visible and named* at the call site,
/// instead of leaving it implicit in drop-ordering or an explicit
/// `drop(guard)` call: code that runs after a `no_arcs_past_here!` block
/// must never assume a lock from inside it is still held.
///
/// This is documentation, not enforcement — it adds no runtime check and
/// changes no behaviour. Use it to wrap the locked sections of revoke-path
/// code (e.g. in `capability.rs`) so a reader can see at a glance which
/// spans hold domain locks and which run with none held.
macro_rules! no_arcs_past_here {
    ($body:block) => {{ $body }};
}
pub(crate) use no_arcs_past_here;
