//! Per-VP atomic-ownership slots and per-core scheduling state (Tier 1).
//!
//! `VcpuSlot` provides safe atomic take/return semantics for the
//! `InactiveVcpu` shared between cores.  `CoreContext` is the per-core
//! Tier-1 view of which domain/VP is currently scheduled on each physical
//! core, written only by its owning core.

extern crate alloc;

use alloc::boxed::Box;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};
#[cfg(feature = "quantum-sched")]
use core::sync::atomic::AtomicU16;
use spin::Mutex;

use capability_engine::{CapabilityRef, Domain};

#[cfg(target_arch = "x86_64")]
use crate::vcpu::InactiveVcpu;

const IDLE_DOMAIN: u64 = u64::MAX;
const IDLE_VP: u32 = u32::MAX;

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
    pid_phys: AtomicU64,
}

#[cfg(target_arch = "x86_64")]
impl VcpuSlot {
    /// Create an empty slot (no VP stored).
    pub const fn empty() -> Self {
        VcpuSlot {
            ptr: AtomicPtr::new(core::ptr::null_mut()),
            pid_phys: AtomicU64::new(0),
        }
    }

    /// Create a slot holding an InactiveVcpu.
    #[allow(dead_code)]
    pub fn with_vcpu(vcpu: InactiveVcpu) -> Self {
        let pid = vcpu.pid_phys();
        VcpuSlot {
            ptr: AtomicPtr::new(Box::into_raw(Box::new(vcpu))),
            pid_phys: AtomicU64::new(pid),
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
// ── Per-core scheduling state (Tier 1) ────────────────────────────────────── //

/// Per-core scheduling state: identifies what domain and VP are currently
/// executing on this physical core.
///
/// **Invariants**:
/// - A core only writes to its own `CoreContext`.
/// - Cross-core reads happen under the `execute()` barrier protocol
///   (IPI + sync_barrier), so the `domain_cap` Mutex is never truly contended.
/// - `domain_id` is a cached copy of the domain ID for fast lock-free
///   observational reads (e.g., `domain_cores()` routing lookups).
pub struct CoreContext {
    /// Cached domain ID — lock-free observational reads by other cores.
    pub domain_id: AtomicU64,
    /// Current VP index within the domain (dom0: VP i = core i, fixed).
    pub vp_id: AtomicU32,
    /// Capability reference to the currently-scheduled domain.
    /// The VMCALL handler's entry point into the capability tree.
    /// `None` only during early boot before dom0 is initialised.
    pub domain_cap: Mutex<Option<CapabilityRef<Domain>>>,
    /// (quantum-sched) Parent-bound vector deferred during child execution.
    /// 0 = no deferred vector; 1–255 = vector number awaiting flush to parent.
    #[cfg(feature = "quantum-sched")]
    pub deferred_vector: AtomicU16,
}

impl CoreContext {
    pub(super) const fn new() -> Self {
        CoreContext {
            domain_id: AtomicU64::new(IDLE_DOMAIN),
            vp_id: AtomicU32::new(IDLE_VP),
            domain_cap: Mutex::new(None),
            #[cfg(feature = "quantum-sched")]
            deferred_vector: AtomicU16::new(0),
        }
    }
}
