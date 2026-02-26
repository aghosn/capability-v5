//! Shared test infrastructure: `TestPlatform` — a `Platform` implementation
//! suitable for unit and multi-threaded integration tests.
//!
//! Design principles:
//!
//! * **Two-lock design** to avoid deadlock:
//!   - `op_lock` (`Arc<Mutex<()>>`) is held for the full duration of `execute`.
//!     It serialises conflicting capability operations.
//!   - `inner` (`Arc<Mutex<TestPlatformInner>>`) is locked briefly for each
//!     state read/write (apply_update, on_domain_revoked, register_domain, …).
//!     It is NEVER held at the same time as any other platform's op_lock.
//!
//! * **Memory lifecycle safety**: `op_lock` is `Arc`-wrapped; the guard returned
//!   by `acquire_op_locks` owns an `ArcMutexGuard` (no lifetime param) that
//!   keeps the mutex alive even if the platform drops the domain entry before
//!   the waiting thread acquires the lock.
//!
//! * **TOCTOU protection**: after acquiring `op_lock`, we briefly lock `inner`
//!   and check the `revoked` flag for every domain in the requested set.  If
//!   any domain is revoked we return `CapaError::DomainRevoked`.
//!
//! * **Barriers / IPIs are no-ops** — TestPlatform targets sequential unit
//!   tests.  Cross-core behaviour is validated by the monitor platform.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::{lock_api::ArcMutexGuard, Mutex, RawMutex};

use capability_engine::{
    CapaError, CoreId, DomainId, OpLockGuard, Platform, Result, Update,
};

// ─────────────────────────────────────────────────────────────────────────────
// Internal state
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct TestPlatformInner {
    /// Domain registry: revoked flag + parent for fallback lookup
    domains: BTreeMap<DomainId, DomainEntry>,
    /// Core → domain (which domain a core is currently running)
    core_to_domain: BTreeMap<CoreId, DomainId>,
    /// Domain → core (reverse index)
    domain_to_core: BTreeMap<DomainId, CoreId>,
    /// All updates applied since the last call to `drain_updates`
    pub applied_updates: Vec<Update>,
}

struct DomainEntry {
    revoked: bool,
    parent_id: Option<DomainId>,
}

impl TestPlatformInner {
    fn is_revoked(&self, domain_id: DomainId) -> bool {
        self.domains
            .get(&domain_id)
            .map(|e| e.revoked)
            .unwrap_or(true) // missing domain ≡ already gone
    }

    fn mark_revoked(&mut self, domain_id: DomainId) {
        if let Some(e) = self.domains.get_mut(&domain_id) {
            e.revoked = true;
        }
    }

    fn parent_of(&self, domain_id: DomainId) -> Option<DomainId> {
        self.domains.get(&domain_id)?.parent_id
    }

    /// Redirect any core running `domain_id` to `fallback`.
    /// If `fallback` is None, walk up the parent chain in the registry.
    fn redirect_core_for_revoked(&mut self, domain_id: DomainId, fallback: Option<DomainId>) {
        let Some(&core_id) = self.domain_to_core.get(&domain_id) else {
            return;
        };
        self.core_to_domain.remove(&core_id);
        self.domain_to_core.remove(&domain_id);

        // Determine which domain the core should run next
        let next = fallback.or_else(|| self.parent_of(domain_id));
        if let Some(next_domain) = next {
            self.core_to_domain.insert(core_id, next_domain);
            self.domain_to_core.insert(next_domain, core_id);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OpLockGuard implementation
// ─────────────────────────────────────────────────────────────────────────────

struct TestOpLocks {
    // Owns the Arc<Mutex<()>>; releasing this guard unlocks op_lock.
    _guard: ArcMutexGuard<RawMutex, ()>,
}

// SAFETY: ArcMutexGuard<RawMutex, ()> is Send.
unsafe impl Send for TestOpLocks {}

impl OpLockGuard for TestOpLocks {}

// ─────────────────────────────────────────────────────────────────────────────
// TestPlatform
// ─────────────────────────────────────────────────────────────────────────────

pub struct TestPlatform {
    /// Serialises concurrent capability operations (held for full execute duration).
    op_lock: Arc<Mutex<()>>,
    /// Platform state — locked briefly for individual reads/writes.
    inner: Arc<Mutex<TestPlatformInner>>,
}

impl Default for TestPlatform {
    fn default() -> Self {
        TestPlatform {
            op_lock: Arc::new(Mutex::new(())),
            inner: Arc::new(Mutex::new(TestPlatformInner::default())),
        }
    }
}

impl TestPlatform {
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume all updates recorded since the last drain (useful in assertions).
    pub fn drain_updates(&self) -> Vec<Update> {
        self.inner.lock().applied_updates.drain(..).collect()
    }

    /// Return the domain a core is currently running, if any.
    pub fn get_core_domain(&self, core_id: CoreId) -> Option<DomainId> {
        self.inner.lock().core_to_domain.get(&core_id).copied()
    }

    /// True iff the domain has been marked revoked by `on_domain_revoked`.
    pub fn is_domain_revoked(&self, domain_id: DomainId) -> bool {
        self.inner.lock().is_revoked(domain_id)
    }
}

impl Platform for TestPlatform {
    fn acquire_op_locks(&self, domains: &std::collections::BTreeSet<DomainId>) -> Result<Box<dyn OpLockGuard>> {
        // Acquire the serialisation lock (blocking, no spinloop).
        let guard = self.op_lock.lock_arc();

        // TOCTOU check: briefly inspect inner to detect mid-air revocations.
        {
            let inner = self.inner.lock();
            for &d in domains {
                if inner.is_revoked(d) {
                    return Err(CapaError::DomainRevoked);
                }
            }
        }

        Ok(Box::new(TestOpLocks { _guard: guard }))
    }

    // IPIs and barriers are no-ops in the test platform.
    fn send_ipi(&self, _core_id: CoreId) {}
    fn sync_barrier(&self, _id: u8, _participants: usize) {}

    fn apply_update(&self, update: &Update) {
        self.inner.lock().applied_updates.push(update.clone());
    }

    fn on_domain_revoked(&self, domain_id: DomainId, fallback: Option<DomainId>) {
        let mut inner = self.inner.lock();
        inner.redirect_core_for_revoked(domain_id, fallback);
        inner.mark_revoked(domain_id);
        // Unregister: keep the entry (with revoked=true) so late TOCTOU checks work.
    }

    fn register_domain(&self, domain_id: DomainId, parent_id: Option<DomainId>) {
        self.inner.lock().domains.insert(
            domain_id,
            DomainEntry {
                revoked: false,
                parent_id,
            },
        );
    }

    fn set_core_domain(&self, core_id: CoreId, domain_id: DomainId) {
        let mut inner = self.inner.lock();
        // Remove any old mapping for this core
        if let Some(old_domain) = inner.core_to_domain.remove(&core_id) {
            inner.domain_to_core.remove(&old_domain);
        }
        inner.core_to_domain.insert(core_id, domain_id);
        inner.domain_to_core.insert(domain_id, core_id);
    }

    fn clear_core_domain(&self, core_id: CoreId) {
        let mut inner = self.inner.lock();
        if let Some(domain_id) = inner.core_to_domain.remove(&core_id) {
            inner.domain_to_core.remove(&domain_id);
        }
    }

    fn domain_core(&self, domain_id: DomainId) -> Option<CoreId> {
        self.inner.lock().domain_to_core.get(&domain_id).copied()
    }
}
