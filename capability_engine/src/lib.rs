use std::{cell::RefCell, rc::Rc};

use capability::{CapaError, CapaRef, Capability, Ownership};
use domain::{Domain, InterruptPolicy, LocalCapa, MonitorAPI, Policies, Status};
use memory_region::{Access, MemoryRegion};

use crate::domain::CapaWrapper;

pub mod capability;
pub mod display;
pub mod domain;
pub mod memory_region;

/// Engine implementation.
/// This is the entry point for all operations.
pub struct Engine {}

fn is_core_subset(reference: u64, other: u64) -> bool {
    (reference & other) == other
}

impl Engine {
    pub fn new() -> Self {
        Engine {}
    }

    pub fn add_root_region(
        &self,
        domain: &CapaRef<Domain>,
        region: &CapaRef<MemoryRegion>,
    ) -> Result<LocalCapa, CapaError> {
        let local_handle = {
            let dom = &mut domain.borrow_mut();
            dom.data.install(CapaWrapper::Region(region.clone()))
        };
        let reg = &mut region.borrow_mut();
        reg.owned = Ownership::new(Rc::downgrade(domain), local_handle);
        Ok(local_handle)
    }

    pub fn create(
        &self,
        domain: CapaRef<Domain>,
        cores: u64,
        api: MonitorAPI,
        interrupts: InterruptPolicy,
    ) -> Result<LocalCapa, CapaError> {
        let dom = &mut domain.borrow_mut();
        if !dom.data.operation_allowed(MonitorAPI::CREATE) {
            return Err(CapaError::CallNotAllowed);
        }
        if !is_core_subset(dom.data.policies.cores, cores) {
            return Err(CapaError::InsufficientRights);
        }
        let policies = Policies::new(cores, api, interrupts);
        let child_dom = Domain::new(policies);

        let capa = Capability::<Domain>::new(child_dom);
        let reference = Rc::new(RefCell::new(capa));
        dom.add_child(reference.clone(), Rc::downgrade(&domain));
        let local_capa = dom.data.install(CapaWrapper::Domain(reference));
        Ok(local_capa)
    }

    pub fn set(&self, _domain: CapaRef<Domain>, _child: LocalCapa) -> Result<(), CapaError> {
        todo!();
    }

    pub fn get(&self, _domain: CapaRef<Domain>, _child: LocalCapa) -> Result<(), CapaError> {
        todo!();
    }

    pub fn seal(&self, domain: CapaRef<Domain>, child: LocalCapa) -> Result<(), CapaError> {
        //TODO:  Check the policies here before the seal.
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
        let aliased_capa = dom.data.install(CapaWrapper::Region(aliased.clone()));

        // Tree & ownership logic.
        aliased.borrow_mut().parent = Rc::downgrade(&region);
        aliased.borrow_mut().owned = Ownership::new(Rc::downgrade(&domain), aliased_capa);
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
        let carved_capa = dom.data.install(CapaWrapper::Region(carved.clone()));

        // Tree & ownership logic.
        carved.borrow_mut().parent = Rc::downgrade(&region);
        carved.borrow_mut().owned = Ownership::new(Rc::downgrade(&domain), carved_capa);

        //TODO: Updates
        Ok(carved_capa)
    }

    fn revoke_region_handler(capa: &mut Capability<MemoryRegion>) -> Result<(), CapaError> {
        let owner = capa.owned.owner.upgrade().ok_or(CapaError::CapaNotOwned)?;
        owner
            .borrow_mut()
            .data
            .capabilities
            .remove(&capa.owned.handle)?;
        //TODO: probably will need an update.
        Ok(())
    }

    pub fn revoke(
        &self,
        domain: CapaRef<Domain>,
        capa: LocalCapa,
        child: usize,
    ) -> Result<(), CapaError> {
        let is_domain = {
            let dom = &mut domain.borrow_mut();
            if !dom.data.operation_allowed(MonitorAPI::REVOKE) {
                return Err(CapaError::CallNotAllowed);
            }
            dom.data.is_domain(capa)?
        };
        // Match directly on the wrapper while we hold the borrow
        if is_domain {
            let dom = &mut domain.borrow_mut();
            let d = dom.data.capabilities.get(&capa)?.as_domain()?;

            dom.revoke_child(&d, &mut |c: &mut Capability<Domain>| {
                c.data.status = Status::Revoked;
                c.data
                    .capabilities
                    .foreach_region_mut(|c: &CapaRef<MemoryRegion>| {
                        Capability::<MemoryRegion>::revoke_node(c.clone(), &mut |_c| Ok(()))
                    })?;
                c.data.capabilities.reset();
                Ok(())
            })?;
            // Remove the handle
            dom.data.capabilities.remove(&capa)?;
        } else {
            let r = domain
                .borrow_mut()
                .data
                .capabilities
                .get(&capa)?
                .as_region()?;
            // Drop borrow of dom before borrowing r
            let child = {
                let r_borrow = r.borrow();
                r_borrow
                    .children
                    .get(child)
                    .cloned()
                    .ok_or(CapaError::InvalidChildCapa)?
            };
            // The region might belong to the dom, so we need to drop the domain.
            r.borrow_mut()
                .revoke_child(&child, &mut Self::revoke_region_handler)?;
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
        if !dom.data.operation_allowed(MonitorAPI::SEND) {
            return Err(CapaError::CallNotAllowed);
        }
        let dest = dom.data.capabilities.get(&dest)?.as_domain()?;
        if dest.borrow().data.is_sealed()
            && !dest.borrow().data.operation_allowed(MonitorAPI::RECEIVE)
        {
            return Err(CapaError::CallNotAllowed);
        }
        let region = dom.data.capabilities.remove(&capa)?.as_region()?;
        let dest_capa = dest
            .borrow_mut()
            .data
            .install(CapaWrapper::Region(region.clone()));
        region.borrow_mut().owned = Ownership::new(Rc::downgrade(&dest), dest_capa);
        Ok(())
    }
}
