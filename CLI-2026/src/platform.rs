//! CliPlatform: Platform implementation for the CLI simulator.

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::{
    lock_api::{ArcRwLockReadGuard, ArcRwLockWriteGuard},
    Mutex, RawRwLock, RwLock,
};

use capability_engine::{
    CoreId, CoreState, DomainId, OpLockGuard, Platform, Result, SwitchManager, Update,
};
use capability_engine::{CapabilityRef, Domain, SwitchContext};

struct CliDomainEntry {
    revoked: bool,
    parent_id: Option<DomainId>,
}

struct CliPlatformInner {
    domains: BTreeMap<DomainId, CliDomainEntry>,
    switch_manager: SwitchManager,
    num_cores: usize,
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
}

impl CliPlatform {
    pub fn new(num_cores: usize) -> Self {
        CliPlatform {
            op_lock: Arc::new(RwLock::new(())),
            inner: Arc::new(Mutex::new(CliPlatformInner {
                domains: BTreeMap::new(),
                switch_manager: SwitchManager::new(num_cores),
                num_cores,
            })),
        }
    }

    pub fn switch(
        &self,
        core: u64,
        from: &CapabilityRef<Domain>,
        to: Option<&CapabilityRef<Domain>>,
    ) -> Result<SwitchContext> {
        self.inner.lock().switch_manager.switch(core, from, to)
    }

    pub fn route_interrupt(
        &self,
        vector: u8,
        domain: &CapabilityRef<Domain>,
        core: u64,
    ) -> Result<(u64, Vec<u64>)> {
        self.inner.lock().switch_manager.route_interrupt(vector, domain, core)
    }

    pub fn get_core(&self, core_id: u64) -> Result<Arc<capability_engine::CoreContext>> {
        self.inner.lock().switch_manager.get_core(core_id).cloned()
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

    fn apply_update(&self, _update: &Update) {
        // no-op; output happens in process_updates
    }

    fn on_domain_revoked(&self, domain_id: DomainId, fallback: Option<DomainId>) {
        let mut inner = self.inner.lock();
        let num_cores = inner.num_cores;

        // Find which core (if any) is running this domain
        let mut affected_core: Option<(u64, Arc<capability_engine::CoreContext>)> = None;
        for i in 0..num_cores as u64 {
            if let Ok(core_ref) = inner.switch_manager.get_core(i) {
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

    fn set_core_domain(&self, core_id: CoreId, domain_id: DomainId) {
        let inner = self.inner.lock();
        if let Ok(core_ref) = inner.switch_manager.get_core(core_id) {
            *core_ref.state.write() = CoreState::Running(domain_id);
        }
    }

    fn clear_core_domain(&self, core_id: CoreId) {
        let inner = self.inner.lock();
        if let Ok(core_ref) = inner.switch_manager.get_core(core_id) {
            *core_ref.state.write() = CoreState::Idle;
        }
    }

    fn domain_core(&self, _domain_id: DomainId) -> Option<CoreId> {
        // Always return None so execute() uses the local path (no IPI/barriers needed in CLI)
        None
    }
}
