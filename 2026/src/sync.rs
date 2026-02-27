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
