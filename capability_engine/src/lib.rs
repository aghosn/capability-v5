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
        domain: CapaRef<Domain>,
        capa: LocalCapa,
        child: usize,
    ) -> Result<(), CapaError> {
        let dom = domain.borrow_mut();
        if !dom.data.operation_allowed(MonitorAPI::REVOKE) {
            return Err(CapaError::CallNotAllowed);
        }
        let is_domain = dom.data.is_domain(capa)?;
        // Match directly on the wrapper while we hold the borrow
        if is_domain {
            todo!()
        } else {
            let r = dom.data.capabilities.get(&capa)?.as_region()?;
            // Drop borrow of dom before borrowing r
            let child = {
                let r_borrow = r.borrow();
                r_borrow
                    .children
                    .get(child)
                    .cloned()
                    .ok_or(CapaError::InvalidChildCapa)?
            };
            // TODO: Bug is that it doesn't remove the capa from the child.
            r.borrow_mut().revoke_with(&child, |_| {})?;
        }

        Ok(())
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
