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
use std::sync::mpsc::Sender;
use std::sync::{Arc, Condvar, Mutex as StdMutex};

use parking_lot::{
    lock_api::{ArcRwLockReadGuard, ArcRwLockWriteGuard},
    RawRwLock, RwLock,
};

use capability_engine::{
    Access, Attributes, CapaError, Capability, CapabilityRef, CoreId, Domain, DomainId,
    LocalHandle, MemoryRegion, OpLockGuard, Platform, Result, Semaphore,
    SwitchContext, SwitchManager, Update, VpHandoff,
};

// ─────────────────────────────────────────────────────────────────────────────
// RealSemaphore — a genuinely blocking counting semaphore, opt-in
// ─────────────────────────────────────────────────────────────────────────────

/// A real (non-no-op) [`Semaphore`], for tests that need to prove the
/// cross-core rendezvous protocol's permit counting is actually correct
/// under real concurrency — not just that the right entries get queued
/// (which the default `NoOpSemaphore`-backed `TestPlatform` already covers
/// sequentially). `acquire` genuinely blocks on a condvar until enough
/// permits have accumulated; `release` never blocks (briefly takes the lock
/// only to update the count and notify waiters).
struct RealSemaphore {
    permits: StdMutex<usize>,
    cv: Condvar,
}

impl RealSemaphore {
    fn new() -> Self {
        RealSemaphore {
            permits: StdMutex::new(0),
            cv: Condvar::new(),
        }
    }
}

impl Semaphore for RealSemaphore {
    fn acquire(&self, n: usize) {
        if n == 0 {
            return;
        }
        let mut permits = self.permits.lock().unwrap();
        while *permits < n {
            permits = self.cv.wait(permits).unwrap();
        }
        *permits -= n;
    }

    fn release(&self, n: usize) {
        if n == 0 {
            return;
        }
        *self.permits.lock().unwrap() += n;
        self.cv.notify_all();
    }
}

/// No-op [`Semaphore`] — mirrors the engine's own private `NoOpSemaphore`
/// default, duplicated here so `TestPlatform` can choose between it and
/// [`RealSemaphore`] per-instance (the engine's default impl is not
/// selectable per-instance since it is hardwired into `Platform::new_semaphore`'s
/// default trait method).
struct NoOpTestSemaphore;
impl Semaphore for NoOpTestSemaphore {
    fn acquire(&self, _n: usize) {}
    fn release(&self, _n: usize) {}
}

thread_local! {
    /// The "current core" returned by `get_current_core()`/set via
    /// `set_current_core()`. Deliberately **thread-local**, not a field on
    /// `TestPlatformInner`: real hardware's "current core" is inherently
    /// per-CPU, i.e. per-thread when simulated with real OS threads (see
    /// multi-threaded tests in `tests/concurrency/platform.rs` that use
    /// `TestPlatform::new_with_real_semaphore()` — each background thread
    /// stands in for a distinct core and must have its own independent
    /// `current_core`, or two such threads calling `set_current_core`
    /// concurrently would race on a single shared field and could corrupt
    /// each other's call-stack resolution inside `apply_core_updates`).
    /// Single-threaded tests are unaffected either way, since they only
    /// ever have one thread to begin with.
    static CURRENT_CORE: std::cell::Cell<Option<CoreId>> = const { std::cell::Cell::new(None) };
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal state
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct TestPlatformInner {
    /// Domain registry: revoked flag + parent for fallback lookup
    domains: BTreeMap<DomainId, DomainEntry>,
    /// All updates applied since the last call to `drain_updates`
    pub applied_updates: Vec<Update>,
    /// VP register storage: (domain_id, vp_id, reg_id) → value
    pub registers: BTreeMap<(DomainId, u64, u64), u64>,
    comm_snapshots: Vec<(DomainId, u32, capability_engine::RegBitmap)>,
    comm_snapshot_failure: Option<u32>,
    /// Ordered log of `apply_update` / `on_domain_revoked` calls, in the
    /// exact order the engine invoked them.  Used by ordering tests to
    /// verify that `on_domain_revoked` fires strictly before
    /// `apply_update(RevokeDomain{d})` for the same `d`.
    pub call_log: Vec<CallLogEntry>,
}

/// One entry in the ordered platform-call log; see [`TestPlatformInner::call_log`].
#[derive(Clone, Debug)]
pub enum CallLogEntry {
    /// `apply_update(update)` was invoked.
    ApplyUpdate(Update),
    /// `on_domain_revoked(domain, fallback)` was invoked.
    OnDomainRevoked {
        domain: DomainId,
        fallback: Option<DomainId>,
    },
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
    /// Per-core switch/call-chain authority — a plain field like `op_lock`/
    /// `update_lock` above, never behind `inner`'s coarse mutex (see
    /// `Platform::switch_manager`'s doc comment for why).
    switch_manager: Arc<SwitchManager>,
    /// If true, `new_semaphore()` returns a genuinely blocking
    /// [`RealSemaphore`] instead of the sequential-test default
    /// [`NoOpTestSemaphore`]. Opt-in via [`TestPlatform::new_with_real_semaphore`]
    /// — every other constructor keeps the existing no-op behaviour so no
    /// existing sequential test can be affected (and none can deadlock).
    real_semaphore: bool,
    /// Optional hook so multi-threaded tests can be notified when
    /// `send_ipi` is called, to wake a background thread that simulates the
    /// named core and drains its queue via the real `apply_core_updates`.
    /// `None` (the default) makes `send_ipi` the same no-op it always was.
    ipi_sender: Arc<parking_lot::Mutex<Option<Sender<CoreId>>>>,
    handoff_hook: parking_lot::Mutex<Option<Arc<HandoffHook>>>,
    before_shared_lock: parking_lot::Mutex<Option<Box<dyn FnOnce() + Send>>>,
    pub doorbells: parking_lot::Mutex<Vec<capability_engine::DoorbellNotification>>,
    pub pending_interrupts: parking_lot::Mutex<std::collections::BTreeSet<(DomainId, u64, u8)>>,
    pub notification_full: AtomicBool,
    boot_memory: parking_lot::Mutex<Vec<CapabilityRef<MemoryRegion>>>,
}

type HandoffHook = dyn Fn(&SwitchContext, VpHandoff) + Send + Sync;

/// Initial boot grant; all derived memory and COMM bindings use the mediated API.
pub fn bootstrap_memory(
    root: &CapabilityRef<Domain>,
    start: u64,
    size: u64,
) -> (LocalHandle, CapabilityRef<MemoryRegion>) {
    let mut domain = root.write();
    assert_eq!(domain.data.id, 0);
    assert!(domain.parent.upgrade().is_none());
    let handle = domain.data.allocate_memory_handle();
    let memory = Capability::new_root(0, handle, MemoryRegion::new_root(start, size));
    memory.write().owned.owner_domain = Some(Arc::downgrade(root));
    domain.data.add_memory_capability(handle, Arc::downgrade(&memory));
    (handle, memory)
}

pub fn carve_test_memory(
    platform: &dyn Platform,
    caller: &CapabilityRef<Domain>,
    size: u64,
) -> LocalHandle {
    let (parent, access) = {
        let domain = caller.read();
        domain.data.memory_capabilities.iter().find_map(|(handle, weak)| {
            let memory = weak.upgrade()?;
            let memory = memory.read();
            if memory.owned.attributes != Attributes::NONE {
                return None;
            }
            memory.compute_view().into_iter()
                .find(|range| range.size >= size)
                .map(|range| (*handle, Access::new(range.start, size, range.rights)))
        }).expect("fixture must provision enough memory through SEND")
    };
    Capability::carve(platform, caller, parent, access).unwrap().0
}

pub fn add_test_vps(
    platform: &dyn Platform,
    parent: &CapabilityRef<Domain>,
    child: LocalHandle,
    count: usize,
) {
    for _ in 0..count {
        let comm = carve_test_memory(platform, parent, 0x1000);
        Capability::add_vp(platform, parent, child, comm).unwrap();
    }
}

pub fn delegate_test_memory(
    platform: &dyn Platform,
    parent: &CapabilityRef<Domain>,
    child: LocalHandle,
    size: u64,
) {
    let memory = carve_test_memory(platform, parent, size);
    Capability::send(platform, parent, memory, child, Attributes::NONE).unwrap();
}

/// Fixed core count for the test platform. Tests observed to use core IDs
/// 0/1 only; generous headroom for future multi-core test scenarios.
const TEST_PLATFORM_NUM_CORES: usize = 16;

impl Default for TestPlatform {
    fn default() -> Self {
        TestPlatform {
            op_lock: Arc::new(RwLock::new(())),
            inner: Arc::new(parking_lot::Mutex::new(TestPlatformInner::default())),
            update_lock: Arc::new(AtomicBool::new(false)),
            switch_manager: Arc::new(SwitchManager::new(TEST_PLATFORM_NUM_CORES)),
            real_semaphore: false,
            ipi_sender: Arc::new(parking_lot::Mutex::new(None)),
            handoff_hook: parking_lot::Mutex::new(None),
            before_shared_lock: parking_lot::Mutex::new(None),
            doorbells: parking_lot::Mutex::new(Vec::new()),
            pending_interrupts: parking_lot::Mutex::new(Default::default()),
            notification_full: AtomicBool::new(false),
            boot_memory: parking_lot::Mutex::new(Vec::new()),
        }
    }
}

impl TestPlatform {
    pub fn operation_lock_is_held(&self) -> bool {
        self.op_lock.try_write().is_none()
    }

    pub fn before_next_shared_lock(&self, hook: impl FnOnce() + Send + 'static) {
        *self.before_shared_lock.lock() = Some(Box::new(hook));
    }

    /// Model the initial physical-memory grant to the boot root, retaining its backing tree.
    pub fn ensure_boot_memory(&self, root: &CapabilityRef<Domain>) {
        assert_eq!(root.read().data.id, 0, "only the boot root receives initial memory");
        if root.read().data.memory_capabilities.is_empty() {
            let (_, memory) = bootstrap_memory(root, 0x1000_0000, 0x1000_0000);
            self.boot_memory.lock().push(memory);
        }
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// Like [`TestPlatform::new`], but `new_semaphore()` returns a real
    /// blocking [`RealSemaphore`] instead of the default no-op. For tests
    /// that drive the cross-core rendezvous protocol with actual background
    /// threads (see [`TestPlatform::set_ipi_sender`]) to prove the
    /// `switched`/`applied` permit counts introduced by the semaphore
    /// rework are exactly right — a counting bug would hang or race here,
    /// not just silently pass as it would under the no-op.
    pub fn new_with_real_semaphore() -> Self {
        TestPlatform {
            real_semaphore: true,
            ..Self::default()
        }
    }

    /// Register a channel that receives the target `CoreId` every time
    /// `send_ipi` is called. Used by multi-threaded tests to wake a
    /// background thread standing in for that core, which then calls the
    /// real `apply_core_updates(platform, core_id)` to drain its queue —
    /// exactly what a real platform's IPI handler would do.
    pub fn set_ipi_sender(&self, sender: Sender<CoreId>) {
        *self.ipi_sender.lock() = Some(sender);
    }

    /// Consume all updates recorded since the last drain (useful in assertions).
    pub fn drain_updates(&self) -> Vec<Update> {
        self.inner.lock().applied_updates.drain(..).collect()
    }

    pub fn drain_comm_snapshots(&self) -> Vec<(DomainId, u32, capability_engine::RegBitmap)> {
        self.inner.lock().comm_snapshots.drain(..).collect()
    }

    pub fn set_comm_snapshot_failure(&self, vp_id: Option<u32>) {
        self.inner.lock().comm_snapshot_failure = vp_id;
    }

    pub fn set_handoff_hook(
        &self,
        hook: impl Fn(&SwitchContext, VpHandoff) + Send + Sync + 'static,
    ) {
        *self.handoff_hook.lock() = Some(Arc::new(hook));
    }

    /// Return the domain a core is currently running, if any.
    pub fn get_core_domain(&self, core_id: CoreId) -> Option<DomainId> {
        self.switch_manager
            .get_core(core_id)
            .ok()
            .and_then(|ctx| ctx.current_domain())
    }

    /// Seed a core binding directly for tests that need pre-existing run-state
    /// without going through `Capability::switch`.
    pub fn set_core_context(
        &self,
        core_id: CoreId,
        domain_cap: &CapabilityRef<Domain>,
        vp_id: u64,
    ) {
        self.switch_manager
            .get_core(core_id)
            .expect("test core id must be valid")
            .set_binding(domain_cap.clone(), vp_id);
    }
    /// True iff the domain has been marked revoked by `on_domain_revoked`.
    pub fn is_domain_revoked(&self, domain_id: DomainId) -> bool {
        self.inner.lock().is_revoked(domain_id)
    }

    /// Drain the ordered call log of `apply_update` / `on_domain_revoked`
    /// invocations recorded since the last drain.  Used by ordering tests.
    pub fn drain_call_log(&self) -> Vec<CallLogEntry> {
        self.inner.lock().call_log.drain(..).collect()
    }

    /// Set the "currently executing" core ID for VP-aware operations —
    /// affects only the calling thread (see `CURRENT_CORE`).
    pub fn set_current_core(&self, core: Option<CoreId>) {
        CURRENT_CORE.with(|c| c.set(core));
    }
}

impl Platform for TestPlatform {
    fn commit_doorbell(
        &self,
        notification: &capability_engine::DoorbellNotification,
        commit: &mut dyn FnMut(),
    ) -> Result<()> {
        {
            let mut queue = self.doorbells.lock();
            if self.notification_full.load(Ordering::Acquire) {
                return Err(CapaError::NotificationQueueFull);
            }
            queue.push(*notification);
            self.pending_interrupts.lock().insert((
                notification.doorbell.recipient, notification.recipient_vp,
                notification.doorbell.vector,
            ));
        }
        commit();
        Ok(())
    }

    fn handoff_vp(&self, context: &SwitchContext, handoff: VpHandoff) {
        let hook = self.handoff_hook.lock().clone();
        if let Some(hook) = hook {
            hook(context, handoff);
        }
    }

    fn acquire_shared_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        let hook = self.before_shared_lock.lock().take();
        if let Some(hook) = hook {
            hook();
        }
        Ok(Box::new(TestSharedLock {
            _guard: self.op_lock.read_arc(),
        }))
    }

    fn acquire_exclusive_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(TestExclusiveLock {
            _guard: self.op_lock.write_arc(),
        }))
    }

    // IPIs are no-ops by default in the test platform (send_ipi only does
    // something if a test registered a channel via `set_ipi_sender`).
    // `new_semaphore` returns the real-vs-no-op choice made at construction
    // (see `real_semaphore`); the no-op default (unused permit counts are
    // harmless) is what every purely-sequential test still uses — real
    // cross-core rendezvous behaviour with a genuine blocking semaphore is
    // opt-in via `TestPlatform::new_with_real_semaphore`, additionally to
    // the loom/monitor platforms.
    fn send_ipi(&self, core_id: CoreId) {
        if let Some(sender) = self.ipi_sender.lock().as_ref() {
            let _ = sender.send(core_id);
        }
    }

    fn new_semaphore(&self) -> Arc<dyn Semaphore> {
        if self.real_semaphore {
            Arc::new(RealSemaphore::new())
        } else {
            Arc::new(NoOpTestSemaphore)
        }
    }

    fn apply_update(&self, update: &Update) {
        let mut inner = self.inner.lock();
        inner.applied_updates.push(update.clone());
        inner.call_log.push(CallLogEntry::ApplyUpdate(update.clone()));
    }

    fn on_domain_revoked(&self, domain_id: DomainId, fallback: Option<DomainId>) {
        {
            let mut inner = self.inner.lock();
            inner
                .call_log
                .push(CallLogEntry::OnDomainRevoked { domain: domain_id, fallback });
            inner.mark_revoked(domain_id);
            // Unregister: keep the entry (with revoked=true) so late TOCTOU checks work.
        }

        for core_id in self.switch_manager.cores_running(domain_id) {
            let Ok(core_ctx) = self.switch_manager.get_core(core_id) else {
                continue;
            };
            if core_ctx.top_frame().is_some() {
                continue;
            }
            let Some(binding) = core_ctx.current_binding() else {
                continue;
            };
            if binding.domain.read().data.id != domain_id {
                continue;
            }

            let next_cap = if let Some(target_id) = fallback {
                let mut cursor = binding.domain.read().get_parent();
                let mut found = None;
                while let Some(candidate) = cursor {
                    let next = {
                        let guard = candidate.read();
                        if guard.data.id == target_id {
                            found = Some(candidate.clone());
                            None
                        } else {
                            guard.get_parent()
                        }
                    };
                    if found.is_some() {
                        break;
                    }
                    cursor = next;
                }
                found
            } else {
                binding.domain.read().get_parent()
            };

            if let Some(next_cap) = next_cap {
                core_ctx.set_binding(next_cap, binding.vp_id);
            } else {
                core_ctx.clear_binding();
            }
        }
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

    fn try_acquire_update_lock(&self) -> bool {
        // CAS false → true: succeeds only if the lock was free.
        self.update_lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    fn release_update_lock(&self) {
        self.update_lock.store(false, Ordering::Release);
    }

    fn get_current_core(&self) -> Option<CoreId> {
        CURRENT_CORE.with(|c| c.get())
    }

    // poll_and_respond_cross_core: default no-op is correct for TestPlatform
    // (no real cross-core IPI delivery in tests).

    fn register_count(&self) -> u64 {
        64
    }

    fn snapshot_comm_regs(
        &self,
        domain_id: DomainId,
        vp_id: u32,
        write_set: capability_engine::RegBitmap,
    ) -> Result<()> {
        let mut inner = self.inner.lock();
        inner.comm_snapshots.push((domain_id, vp_id, write_set));
        if inner.comm_snapshot_failure == Some(vp_id) {
            return Err(CapaError::InvalidOperation(
                "test COMM snapshot failure".into(),
            ));
        }
        Ok(())
    }

    fn get_vp_register(
        &self,
        domain_id: DomainId,
        vp_id: u64,
        reg_id: u64,
    ) -> Result<u64> {
        if reg_id >= self.register_count() {
            return Err(CapaError::RegisterOutOfRange);
        }
        Ok(self
            .inner
            .lock()
            .registers
            .get(&(domain_id, vp_id, reg_id))
            .copied()
            .unwrap_or(0))
    }

    fn set_vp_register(
        &self,
        domain_id: DomainId,
        vp_id: u64,
        reg_id: u64,
        value: u64,
    ) -> Result<()> {
        if reg_id >= self.register_count() {
            return Err(CapaError::RegisterOutOfRange);
        }
        self.inner
            .lock()
            .registers
            .insert((domain_id, vp_id, reg_id), value);
        Ok(())
    }

    fn switch_manager(&self) -> &SwitchManager {
        &self.switch_manager
    }
}
