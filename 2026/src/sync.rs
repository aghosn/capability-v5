//! Synchronisation primitives.
//!
//! Selects the right `RwLock` implementation at compile time:
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

#[cfg(feature = "hosted")]
pub use parking_lot::RwLock;

#[cfg(not(feature = "hosted"))]
pub use spin::RwLock;
