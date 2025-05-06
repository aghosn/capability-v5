use std::{cell::RefCell, rc::Rc};

use crate::core::capability::{CapaError, CapaRef, Capability, Ownership};
use crate::core::domain::CapaWrapper;
use crate::core::domain::{
    Domain, Field, FieldType, InterruptPolicy, LocalCapa, MonitorAPI, Policies, Status,
};
use crate::core::memory_region::{Access, MemoryRegion, Remapped, ViewRegion};
use crate::is_core_subset;

/// Engine implementation.
/// This is the entry point for all operations.
pub struct Engine {}

impl Engine {
    pub fn new() -> Self {
        Engine {}
    }

    fn is_sealed_and_allowed(
        &self,
        domain: &CapaRef<Domain>,
        call: MonitorAPI,
    ) -> Result<(), CapaError> {
        let dom = domain.borrow();
        if dom.data.status != Status::Sealed {
            return Err(CapaError::DomainUnsealed);
        }
        if !dom.data.operation_allowed(call) {
            return Err(CapaError::CallNotAllowed);
        }
        Ok(())
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
        self.is_sealed_and_allowed(&domain, MonitorAPI::CREATE)?;

        let dom = &mut domain.borrow_mut();
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

    pub fn set(
        &self,
        domain: CapaRef<Domain>,
        child: LocalCapa,
        core: usize,
        tpe: FieldType,
        field: Field,
        value: usize,
    ) -> Result<(), CapaError> {
        self.is_sealed_and_allowed(&domain, MonitorAPI::SET)?;
        // Check if the domain is sealed in which case policies cannot be set.
        if tpe != FieldType::Register
            && domain
                .borrow()
                .data
                .capabilities
                .get(&child)?
                .as_domain()?
                .borrow()
                .data
                .is_sealed()
        {
            return Err(CapaError::DomainSealed);
        }
        // The fact that it is a subset will be checked at seal time for policies.
        domain
            .borrow()
            .data
            .capabilities
            .get(&child)?
            .as_domain()?
            .borrow_mut()
            .set(core, tpe, field, value)
    }

    pub fn get(
        &self,
        domain: CapaRef<Domain>,
        child: LocalCapa,
        core: usize,
        tpe: FieldType,
        field: Field,
    ) -> Result<usize, CapaError> {
        self.is_sealed_and_allowed(&domain, MonitorAPI::GET)?;
        domain
            .borrow()
            .data
            .capabilities
            .get(&child)?
            .as_domain()?
            .borrow()
            .get(core, tpe, field)
    }

    pub fn seal(&self, domain: CapaRef<Domain>, child: LocalCapa) -> Result<(), CapaError> {
        self.is_sealed_and_allowed(&domain, MonitorAPI::SEAL)?;

        let current_policies = &domain.borrow().data.policies;
        // Check the child's policies are a subset of the parent.
        if !current_policies.contains(
            &domain
                .borrow()
                .data
                .capabilities
                .get(&child)?
                .as_domain()?
                .borrow()
                .data
                .policies,
        ) {
            return Err(CapaError::InsufficientRights);
        }
        domain.borrow().seal(child)
    }

    pub fn attest(
        &self,
        domain: CapaRef<Domain>,
        other: Option<LocalCapa>,
    ) -> Result<String, CapaError> {
        self.is_sealed_and_allowed(&domain, MonitorAPI::ATTEST)?;

        if let Some(child) = other {
            return domain.borrow().attest(child);
        }
        let display = format!("{}", domain.borrow());
        return Ok(display);
    }

    pub fn enumerate(&self, domain: CapaRef<Domain>, capa: LocalCapa) -> Result<String, CapaError> {
        self.is_sealed_and_allowed(&domain, MonitorAPI::ENUMERATE)?;
        let binding = domain.borrow();
        let capa = binding.data.capabilities.get(&capa)?;
        match capa {
            CapaWrapper::Region(r) => Ok(format!("{}", r.borrow())),
            CapaWrapper::Domain(d) => Ok(format!("{}", d.borrow())),
        }
    }

    pub fn switch(&self, domain: CapaRef<Domain>, _capa: LocalCapa) -> Result<(), CapaError> {
        self.is_sealed_and_allowed(&domain, MonitorAPI::SWITCH)?;
        todo!();
    }

    pub fn alias(
        &self,
        domain: CapaRef<Domain>,
        capa: LocalCapa,
        access: &Access,
    ) -> Result<LocalCapa, CapaError> {
        self.is_sealed_and_allowed(&domain, MonitorAPI::ALIAS)?;

        let dom = &mut domain.borrow_mut();
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
        self.is_sealed_and_allowed(&domain, MonitorAPI::CARVE)?;

        let dom = &mut domain.borrow_mut();
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
        self.is_sealed_and_allowed(&domain, MonitorAPI::REVOKE)?;

        let is_domain = {
            let dom = &mut domain.borrow_mut();
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
        remap: Remapped,
    ) -> Result<(), CapaError> {
        self.is_sealed_and_allowed(&domain, MonitorAPI::SEND)?;

        let dom = &mut domain.borrow_mut();
        let dest = dom.data.capabilities.get(&dest)?.as_domain()?;
        if dest.borrow().data.is_sealed()
            && !dest.borrow().data.operation_allowed(MonitorAPI::RECEIVE)
        {
            return Err(CapaError::CallNotAllowed);
        }

        // Check the conflicts in the dest.
        {
            let region = dom.data.capabilities.get(&capa)?.as_region()?;
            dest.borrow()
                .check_conflict(&ViewRegion::new(region.borrow().data.access, remap))?;
        }

        let region = dom.data.capabilities.remove(&capa)?.as_region()?;

        //TODO: do vital clean etc?

        // Apply the remapping.
        {
            let mut ref_reg = region.borrow_mut();
            ref_reg.data.remapped = remap;
        };

        let dest_capa = dest
            .borrow_mut()
            .data
            .install(CapaWrapper::Region(region.clone()));
        region.borrow_mut().owned = Ownership::new(Rc::downgrade(&dest), dest_capa);
        Ok(())
    }
}
