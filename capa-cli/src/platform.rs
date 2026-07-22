//! CliPlatform: Platform implementation for the CLI simulator.

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::{
    lock_api::{ArcRwLockReadGuard, ArcRwLockWriteGuard},
    Mutex, RawRwLock, RwLock,
};

use capability_engine::{
    CapaError, CoreId, CoreState, DomainId, OpLockGuard, Platform, Result, SwitchManager, Update,
};
use capability_engine::{CapabilityRef, Domain};

struct CliDomainEntry {
    revoked: bool,
    parent_id: Option<DomainId>,
}

struct CliPlatformInner {
    domains: BTreeMap<DomainId, CliDomainEntry>,
    num_cores: usize,
    /// The core ID "currently executing" (set by the CLI before VP-aware calls).
    current_core: Option<CoreId>,
    /// VP register storage: (domain_id, vp_id, reg_id) → value
    registers: BTreeMap<(DomainId, u64, u64), u64>,
}

impl CliPlatformInner {
    #[allow(dead_code)]
    fn is_revoked(&self, id: DomainId) -> bool {
        self.domains.get(&id).map(|e| e.revoked).unwrap_or(true)
    }
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
                domains: BTreeMap::new(),
                num_cores,
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

    /// CLI-only helper: set core domain by DomainId (no CapabilityRef needed).
    /// Used for non-VP interrupt fallback where only the DomainId is known.
    pub fn set_core_domain_by_id(&self, core_id: CoreId, domain_id: DomainId) {
        if let Ok(core_ref) = self.switch_manager.get_core(core_id) {
            *core_ref.state.write() = CoreState::Running(domain_id);
        }
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

    fn sync_barrier(&self, _id: u8, _participants: usize) {
        // no-op in CLI
    }

    fn apply_update(&self, update: &Update) {
        if let Update::CreateDomain { domain_id, parent_id } = update {
            self.register_domain(*domain_id, *parent_id);
        }
    }

    fn on_domain_revoked(&self, domain_id: DomainId, fallback: Option<DomainId>) {
        let mut inner = self.inner.lock();
        let num_cores = inner.num_cores;

        // Find which core (if any) is running this domain
        let mut affected_core: Option<(u64, Arc<capability_engine::CoreContext>)> = None;
        for i in 0..num_cores as u64 {
            if let Ok(core_ref) = self.switch_manager.get_core(i) {
                if core_ref.current_domain() == Some(domain_id) {
                    affected_core = Some((i, core_ref.clone()));
                    break;
                }
            }
        }

        let new_domain = fallback.or_else(|| {
            inner.domains.get(&domain_id).and_then(|e| e.parent_id)
        });

        if let Some((core_id, core_ref)) = affected_core {
            let new_state = new_domain
                .map(CoreState::Running)
                .unwrap_or(CoreState::Idle);
            *core_ref.state.write() = new_state;
            println!(
                "  → Core {} domain revoked, switching to {:?}",
                core_id,
                new_domain
            );
        }

        if let Some(entry) = inner.domains.get_mut(&domain_id) {
            entry.revoked = true;
        }
    }

    fn register_domain(&self, domain_id: DomainId, parent_id: Option<DomainId>) {
        self.inner.lock().domains.insert(domain_id, CliDomainEntry {
            revoked: false,
            parent_id,
        });
    }

    fn set_core_context(
        &self,
        core_id: CoreId,
        domain_cap: &CapabilityRef<Domain>,
        vp_id: u64,
    ) {
        let domain_id = domain_cap.read().data.id;
        if let Ok(core_ref) = self.switch_manager.get_core(core_id) {
            *core_ref.state.write() = CoreState::Running(domain_id);
            *core_ref.running_vp.write() = Some(vp_id);
        }
    }

    fn clear_core_domain(&self, core_id: CoreId) {
        if let Ok(core_ref) = self.switch_manager.get_core(core_id) {
            *core_ref.state.write() = CoreState::Idle;
        }
    }

    fn domain_cores(&self, _domain_id: DomainId) -> Vec<CoreId> {
        // Return empty vec so execute() uses the local path (no IPI/barriers needed in CLI)
        Vec::new()
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
