//! CliPlatform: Platform implementation for the CLI simulator.

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::{
    lock_api::{ArcRwLockReadGuard, ArcRwLockWriteGuard},
    Mutex, RawRwLock, RwLock,
};

use capability_engine::{
    CapaError, CoreId, DomainId, OpLockGuard, Platform, Result, SwitchManager, Update,
};
use capability_engine::{CapabilityRef, Domain};

struct CliPlatformInner {
    /// The core ID "currently executing" (set by the CLI before VP-aware calls).
    current_core: Option<CoreId>,
    /// VP register storage: (domain_id, vp_id, reg_id) → value
    registers: BTreeMap<(DomainId, u64, u64), u64>,
}

struct CliSharedLock {
    _guard: ArcRwLockReadGuard<RawRwLock, ()>,
}
unsafe impl Send for CliSharedLock {}
impl OpLockGuard for CliSharedLock {}

struct CliExclusiveLock {
    _guard: ArcRwLockWriteGuard<RawRwLock, ()>,
}
unsafe impl Send for CliExclusiveLock {}
impl OpLockGuard for CliExclusiveLock {}

pub struct CliPlatform {
    op_lock: Arc<RwLock<()>>,
    inner: Arc<Mutex<CliPlatformInner>>,
    /// Per-core switch/call-chain authority — a plain field, not behind
    /// `inner`'s coarse mutex (see `Platform::switch_manager`'s doc
    /// comment for why: reaching one core's state must never contend
    /// with an unrelated core).
    switch_manager: SwitchManager,
}

impl CliPlatform {
    pub fn new(num_cores: usize) -> Self {
        CliPlatform {
            op_lock: Arc::new(RwLock::new(())),
            inner: Arc::new(Mutex::new(CliPlatformInner {
                current_core: None,
                registers: BTreeMap::new(),
            })),
            switch_manager: SwitchManager::new(num_cores),
        }
    }

    /// Set the "currently executing" core ID used by VP-aware calls.
    pub fn set_current_core(&self, core: Option<CoreId>) {
        self.inner.lock().current_core = core;
    }

    pub fn route_interrupt(
        &self,
        vector: u8,
        domain: &CapabilityRef<Domain>,
        core: u64,
    ) -> Result<(u64, Vec<u64>)> {
        self.switch_manager.route_interrupt(vector, domain, core)
    }

    pub fn get_core(&self, core_id: u64) -> Result<Arc<capability_engine::CoreContext>> {
        self.switch_manager.get_core(core_id).cloned()
    }
}

impl Platform for CliPlatform {
    fn acquire_shared_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(CliSharedLock {
            _guard: self.op_lock.read_arc(),
        }))
    }

    fn acquire_exclusive_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(CliExclusiveLock {
            _guard: self.op_lock.write_arc(),
        }))
    }

    fn send_ipi(&self, _core_id: CoreId) {
        // no-op in CLI
    }

    fn apply_update(&self, update: &Update) {
        if let Update::CreateDomain { domain_id, parent_id } = update {
            self.register_domain(*domain_id, *parent_id);
        }
    }

    fn on_domain_revoked(&self, domain_id: DomainId, fallback: Option<DomainId>) {
        // Redirecting a core off `domain_id` is now done purely via the
        // `CoreUpdate::Switch` mechanism: `execute()` already queued one
        // for every core `revoke_domain_subtree` found actually running
        // this domain (see `batch.core_switches()`), naming only the
        // *source* — the resume target is resolved by
        // `Capability::switch_after_callee_revoked` popping that core's own
        // `call_stack` down to the first non-revoked ancestor. On bare
        // metal that drain happens asynchronously via IPI
        // (`apply_core_updates`, called from the target core's own
        // interrupt handler). The CLI simulator has no separate execution
        // context to deliver that IPI to, so it must drain inline, here,
        // by momentarily impersonating the affected core — this matters
        // because `switch_after_callee_revoked` resolves its target via
        // `Platform::get_current_core()`.
        //
        // `fallback` (the first non-revoked *structural* CDT ancestor,
        // pre-computed by `revoke_child_domain`/`revoke_subtree`) is not
        // consulted here: by this engine's switch-locality invariant (see
        // `find_interrupt_handler`'s doc comment), the live call chain a
        // Running VP followed to reach `domain_id` always matches its CDT
        // ancestor chain, so `switch_after_callee_revoked`'s call-stack walk
        // already derives the identical (and, for multi-level chains, more
        // precise) target without it.
        for core_id in self.switch_manager.cores_running(domain_id) {
            let saved = self.inner.lock().current_core;
            self.set_current_core(Some(core_id));
            let _ = capability_engine::domain_api::apply_core_updates(self, core_id);
            self.set_current_core(saved);
        }
        let _ = fallback;
    }

    fn register_domain(&self, _domain_id: DomainId, _parent_id: Option<DomainId>) {
        // No local domain bookkeeping needed: revoked-ness and CDT structure
        // are already authoritative in the capability tree itself, and
        // `on_domain_revoked` above resolves resume targets purely via
        // `SwitchManager`'s per-core `call_stack`, not via any shadow map
        // kept here.
    }

    fn get_current_core(&self) -> Option<CoreId> {
        self.inner.lock().current_core
    }

    fn register_count(&self) -> u64 {
        64
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
