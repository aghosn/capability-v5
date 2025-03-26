use capability::{CapaError, CapaRef};
use domain::{Domain, InterruptPolicy, LocalCapa, MonitorAPI, Policies};
use memory_region::Access;

use crate::domain::CapaWrapper;

pub mod capability;
pub mod display;
pub mod domain;
pub mod memory_region;

/// Engine implementation.
/// This is the entry point for all operations.
pub struct Engine {}

impl Engine {
    pub fn new() -> Self {
        Engine {}
    }

    pub fn create(
        &self,
        domain: CapaRef<Domain>,
        cores: u64,
        api: MonitorAPI,
        interrupts: InterruptPolicy,
    ) -> Result<LocalCapa, CapaError> {
        domain
            .borrow_mut()
            .create(Policies::new(cores, api, interrupts))
    }

    pub fn set(&self, _domain: CapaRef<Domain>, _child: LocalCapa) -> Result<(), CapaError> {
        todo!();
    }

    pub fn get(&self, _domain: CapaRef<Domain>, _child: LocalCapa) -> Result<(), CapaError> {
        todo!();
    }

    pub fn seal(&self, domain: CapaRef<Domain>, child: LocalCapa) -> Result<(), CapaError> {
        domain.borrow().seal(child)
    }

    pub fn attest(
        &self,
        domain: CapaRef<Domain>,
        other: Option<LocalCapa>,
    ) -> Result<(), CapaError> {
        if let Some(child) = other {
            return domain.borrow().attest(child);
        }
        todo!();
    }

    pub fn enumerate(&self, _domain: CapaRef<Domain>, _capa: LocalCapa) -> Result<(), CapaError> {
        todo!();
    }

    pub fn switch(&self, _domain: CapaRef<Domain>, _capa: LocalCapa) -> Result<(), CapaError> {
        todo!();
    }

    pub fn alias(
        &self,
        domain: CapaRef<Domain>,
        capa: LocalCapa,
        access: &Access,
    ) -> Result<LocalCapa, CapaError> {
        let dom = &mut domain.borrow_mut();
        if !dom.data.operation_allowed(MonitorAPI::ALIAS) {
            return Err(CapaError::CallNotAllowed);
        }
        let region = dom.data.capabilities.get(&capa)?.as_region()?;
        let aliased = region.borrow_mut().alias(access)?;
        let aliased_capa = dom.data.install(CapaWrapper::Region(aliased));
        Ok(aliased_capa)
    }

    pub fn carve(
        &self,
        domain: CapaRef<Domain>,
        capa: LocalCapa,
        access: &Access,
    ) -> Result<LocalCapa, CapaError> {
        let dom = &mut domain.borrow_mut();
        if !dom.data.operation_allowed(MonitorAPI::CARVE) {
            return Err(CapaError::CallNotAllowed);
        }
        let region = dom.data.capabilities.get(&capa)?.as_region()?;
        let carved = region.borrow_mut().carve(access)?;
        let carved_capa = dom.data.install(CapaWrapper::Region(carved));
        //TODO: Updates
        Ok(carved_capa)
    }

    pub fn revoke(
        &self,
        _domain: CapaRef<Domain>,
        _capa: LocalCapa,
        _child: usize,
    ) -> Result<LocalCapa, CapaError> {
        todo!();
    }

    pub fn send(
        &self,
        domain: CapaRef<Domain>,
        dest: LocalCapa,
        capa: LocalCapa,
    ) -> Result<(), CapaError> {
        let dom = &mut domain.borrow_mut();
        //TODO: do we have updates to process?
        dom.send(dest, capa)
    }
}
