//! Per-VP atomic-ownership slots and per-core hardware pinning (Tier 1).
//!
//! `VcpuSlot` provides safe atomic take/return semantics for the
//! `InactiveVcpu` shared between cores.  `CoreContext` here holds only the
//! genuinely hardware-specific per-core state capavisor still needs
//! (the pinned `ActiveVcpu` pointer, and the quantum-sched deferred
//! vector) — "which domain/VP is running on this core" itself is no
//! longer tracked here: it is owned exclusively by the capability
//! engine's own `SwitchManager`/`CoreContext` (see `capability_engine::switch`).

extern crate alloc;

use alloc::boxed::Box;
use core::sync::atomic::{AtomicPtr, Ordering};
#[cfg(feature = "quantum-sched")]
use core::sync::atomic::AtomicU16;

#[cfg(target_arch = "x86_64")]
use crate::vcpu::InactiveVcpu;

// ── Per-VP slot (atomic take/return for exclusive access) ──────────────────── //


/// A slot holding an `InactiveVcpu` that can be atomically taken by one core
/// at a time.  When a core wants to run a VP, it `take()`s the InactiveVcpu
/// (leaving the slot empty), activates it, and runs.  When done, it
/// deactivates and `return()`s the InactiveVcpu back to the slot.
///
/// An empty slot (null pointer) means the VP is currently active on some core.
#[cfg(target_arch = "x86_64")]
pub struct VcpuSlot {
    ptr: AtomicPtr<InactiveVcpu>,
    /// Physical address of this VP's Posted Interrupt Descriptor.
    /// Set by `put()` from the InactiveVcpu and never changes afterwards.
    /// Readable without taking the VP — safe because pid_phys is immutable
    /// after the first `put()`.  0 for dom0 VPs (no PID).
    pid_phys: core::sync::atomic::AtomicU64,
}

#[cfg(target_arch = "x86_64")]
impl VcpuSlot {
    /// Create an empty slot (no VP stored).
    pub const fn empty() -> Self {
        VcpuSlot {
            ptr: AtomicPtr::new(core::ptr::null_mut()),
            pid_phys: core::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create a slot holding an InactiveVcpu.
    #[allow(dead_code)]
    pub fn with_vcpu(vcpu: InactiveVcpu) -> Self {
        let pid = vcpu.pid_phys();
        VcpuSlot {
            ptr: AtomicPtr::new(Box::into_raw(Box::new(vcpu))),
            pid_phys: core::sync::atomic::AtomicU64::new(pid),
        }
    }

    /// Atomically take the InactiveVcpu from this slot.
    /// Returns `Some(InactiveVcpu)` if the VP was available, `None` if already
    /// taken by another core.
    pub fn take(&self) -> Option<InactiveVcpu> {
        let ptr = self.ptr.swap(core::ptr::null_mut(), Ordering::Acquire);
        if ptr.is_null() {
            None
        } else {
            Some(*unsafe { Box::from_raw(ptr) })
        }
    }

    /// Return an InactiveVcpu to this slot after deactivation.
    ///
    /// # Panics
    /// Panics if the slot is not empty (double-return bug).
    pub fn put(&self, vcpu: InactiveVcpu) {
        let pid = vcpu.pid_phys();
        let old = self
            .ptr
            .swap(Box::into_raw(Box::new(vcpu)), Ordering::Release);
        assert!(
            old.is_null(),
            "VcpuSlot::put: slot was not empty (double-return bug)"
        );
        // Cache pid_phys so callers can read it without taking the VP.
        self.pid_phys.store(pid, Ordering::Relaxed);
    }

    /// Read the cached pid_phys without taking the VP.
    ///
    /// Returns 0 if the VP has no PID (dom0) or the slot was never populated.
    /// Safe to call concurrently with `take()` / `put()` because pid_phys
    /// is immutable after the first `put()`.
    pub fn peek_pid_phys(&self) -> u64 {
        self.pid_phys.load(Ordering::Relaxed)
    }

    /// Check if the VP is currently available (not taken by any core).
    #[allow(dead_code)]
    pub fn is_available(&self) -> bool {
        !self.ptr.load(Ordering::Relaxed).is_null()
    }
}
// ── Per-core hardware pinning (Tier 1) ────────────────────────────────────── //

/// Per-core hardware state that has no equivalent in the capability engine:
/// the pinned `ActiveVcpu` pointer used for cross-core VMCLEAR/VMPTRLD, and
/// (quantum-sched only) a deferred parent-bound vector.
///
/// "Which domain/VP is scheduled on this core" is **not** tracked here —
/// that fact lives exclusively in `capability_engine::switch::CoreContext`
/// (via `SwitchManager`), the single authoritative source shared by every
/// backend.
pub struct CoreContext {
    /// Raw pointer to this core's `ActiveVcpu` on the monitor-loop stack.
    ///
    /// Set once at the top of `monitor_loop` (never cleared: `monitor_loop`
    /// is divergent and the `Vp<A>` it owns lives at a fixed stack address
    /// forever).  Only the owning core reads it, and only between VMEXITs
    /// (i.e. while no `&mut ActiveVcpu` is otherwise live in the arch code),
    /// so no aliasing violation.
    ///
    /// Used by `Platform::apply_cross_core_switch` to reach the vcpu for a
    /// revoke-driven VMCLEAR/VMPTRLD.  Opaque `u8` here to keep
    /// `CoreContext` arch-neutral; consumers on x86 cast to
    /// `*mut crate::vcpu::ActiveVcpu`.
    pub active_vcpu: AtomicPtr<u8>,
    /// (quantum-sched) Parent-bound vector deferred during child execution.
    /// 0 = no deferred vector; 1–255 = vector number awaiting flush to parent.
    #[cfg(feature = "quantum-sched")]
    pub deferred_vector: AtomicU16,
}

impl CoreContext {
    pub(super) const fn new() -> Self {
        CoreContext {
            active_vcpu: AtomicPtr::new(core::ptr::null_mut()),
            #[cfg(feature = "quantum-sched")]
            deferred_vector: AtomicU16::new(0),
        }
    }
}
