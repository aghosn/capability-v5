//! Shared test infrastructure: `TestPlatform` — a `Platform` implementation
//! suitable for unit and multi-threaded integration tests.
//!
//! Design principles:
//!
//! * **RW lock design**: a `parking_lot::RwLock<()>` provides shared access
//!   for non-revoke operations and exclusive access for revoke operations,
//!   mirroring the bare-metal RW spinlock a real platform would use.
//!   Arc-wrapped guards (`ArcRwLockReadGuard` / `ArcRwLockWriteGuard`) are
//!   used so the guard type has no lifetime parameter and can be boxed as
//!   `Box<dyn OpLockGuard>`.
//!
//! * **Two-lock separation**: `op_lock` (the RW lock) is held for the full
//!   `execute()` duration. `inner` (a plain Mutex) is locked briefly for
//!   individual state reads/writes. The two are never held simultaneously.
//!
//! * **No TOCTOU check**: the exclusive lock guarantees that no revocation
//!   can happen concurrently with a shared-lock holder, and vice-versa.
//!   Sequential revocation of a domain and then operating on it will fail
//!   through normal capability-tree errors (e.g. NotFound), not via the lock.
//!
//! * **Barriers / IPIs are no-ops** — TestPlatform targets sequential unit
//!   tests. Cross-core behaviour is validated by the monitor platform.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::{
    lock_api::{ArcRwLockReadGuard, ArcRwLockWriteGuard},
    RawRwLock, RwLock,
};

use capability_engine::{
    CoreId, DomainId, OpLockGuard, Platform, Result, Update,
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
// OpLockGuard implementations
// ─────────────────────────────────────────────────────────────────────────────

struct TestSharedLock {
    _guard: ArcRwLockReadGuard<RawRwLock, ()>,
}
unsafe impl Send for TestSharedLock {}
impl OpLockGuard for TestSharedLock {}

struct TestExclusiveLock {
    _guard: ArcRwLockWriteGuard<RawRwLock, ()>,
}
unsafe impl Send for TestExclusiveLock {}
impl OpLockGuard for TestExclusiveLock {}

// ─────────────────────────────────────────────────────────────────────────────
// TestPlatform
// ─────────────────────────────────────────────────────────────────────────────

pub struct TestPlatform {
    /// RW lock: shared for non-revoke ops, exclusive for revoke ops.
    op_lock: Arc<RwLock<()>>,
    /// Platform state — locked briefly for individual reads/writes.
    inner: Arc<parking_lot::Mutex<TestPlatformInner>>,
    /// Update-application serialisation lock (see Platform::try_acquire_update_lock).
    /// An AtomicBool CAS spinlock: false = unlocked, true = locked.
    update_lock: Arc<AtomicBool>,
}

impl Default for TestPlatform {
    fn default() -> Self {
        TestPlatform {
            op_lock: Arc::new(RwLock::new(())),
            inner: Arc::new(parking_lot::Mutex::new(TestPlatformInner::default())),
            update_lock: Arc::new(AtomicBool::new(false)),
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
    fn acquire_shared_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(TestSharedLock {
            _guard: self.op_lock.read_arc(),
        }))
    }

    fn acquire_exclusive_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(TestExclusiveLock {
            _guard: self.op_lock.write_arc(),
        }))
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

    fn try_acquire_update_lock(&self) -> bool {
        // CAS false → true: succeeds only if the lock was free.
        self.update_lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    fn release_update_lock(&self) {
        self.update_lock.store(false, Ordering::Release);
    }

    // poll_and_respond_cross_core: default no-op is correct for TestPlatform
    // (no real cross-core IPI delivery in tests).
}
