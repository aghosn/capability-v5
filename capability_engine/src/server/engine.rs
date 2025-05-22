use std::collections::VecDeque;
use std::{cell::RefCell, rc::Rc};

use crate::core::capability::{CapaError, CapaRef, Capability, Ownership, WeakRef};
use crate::core::domain::CapaWrapper;
use crate::core::domain::{
    Domain, Field, FieldType, InterruptPolicy, LocalCapa, MonitorAPI, Policies, Status,
};
use crate::core::memory_region::{Access, Attributes, MemoryRegion, Remapped, ViewRegion};
use crate::core::update::{CoreUpdate, OperationUpdate, Update};
use crate::{is_core_subset, EngineInterface};

/// Engine implementation.
/// This is the entry point for all operations.
pub struct Engine {
    // The root lives in the engine.
    pub root: CapaRef<Domain>,
    pub scheduled: Vec<WeakRef<Domain>>,
    pub updates: VecDeque<Vec<Update>>,
    pub core_update: Vec<Vec<CoreUpdate>>,
}

impl Engine {
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

    fn revoke_region_handler(capa: &mut Capability<MemoryRegion>) -> Result<(), CapaError> {
        let owner = capa.owned.owner.upgrade().ok_or(CapaError::CapaNotOwned)?;
        owner
            .borrow_mut()
            .data
            .capabilities
            .remove(&capa.owned.handle)?;
        Ok(())
    }
}

impl EngineInterface for Engine {
    type CapaReference = CapaRef<Domain>;
    type OwnedCapa = LocalCapa;
    type CapabilityError = CapaError;

    fn new(nb_cores: u64) -> Self {
        // Create the root capability for the domain.
        let mut root = Domain::new(Policies::new(
            (1 << nb_cores) - 1,
            MonitorAPI::all(),
            InterruptPolicy::default_all(),
        ));
        root.status = Status::Sealed;
        let dom = Capability::<Domain>::new(root);
        let ref_td = Rc::new(RefCell::new(dom));
        Engine {
            root: ref_td,
            scheduled: Vec::new(), /*vec![&ref_td; nb_cores]*/
            updates: VecDeque::<Vec<Update>>::new(),
            core_update: Vec::new(),
        }
    }

    fn create(
        &mut self,
        domain: &CapaRef<Domain>,
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

    fn set(
        &mut self,
        domain: CapaRef<Domain>,
        child: LocalCapa,
        core: u64,
        tpe: FieldType,
        field: Field,
        value: u64,
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

    fn get(
        &mut self,
        domain: CapaRef<Domain>,
        child: LocalCapa,
        core: u64,
        tpe: FieldType,
        field: Field,
    ) -> Result<u64, CapaError> {
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

    fn seal(&mut self, domain: CapaRef<Domain>, child: LocalCapa) -> Result<(), CapaError> {
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

    fn attest(
        &mut self,
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

    fn enumerate(&mut self, domain: CapaRef<Domain>, capa: LocalCapa) -> Result<String, CapaError> {
        self.is_sealed_and_allowed(&domain, MonitorAPI::ENUMERATE)?;
        let binding = domain.borrow();
        let capa = binding.data.capabilities.get(&capa)?;
        match capa {
            CapaWrapper::Region(r) => Ok(format!("{}", r.borrow())),
            CapaWrapper::Domain(d) => Ok(format!("{}", d.borrow())),
        }
    }

    fn switch(&mut self, domain: CapaRef<Domain>, _capa: LocalCapa) -> Result<(), CapaError> {
        self.is_sealed_and_allowed(&domain, MonitorAPI::SWITCH)?;
        todo!();
    }

    fn alias(
        &mut self,
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

    fn carve(
        &mut self,
        domain: CapaRef<Domain>,
        capa: LocalCapa,
        access: &Access,
    ) -> Result<LocalCapa, CapaError> {
        self.is_sealed_and_allowed(&domain, MonitorAPI::CARVE)?;

        let mut updates = OperationUpdate::new();

        let region = {
            let dom = &domain.borrow();
            dom.data.capabilities.get(&capa)?.as_region()?
        };

        // Carve can require updates if we reduce access rights.
        if region.borrow().data.access.rights != access.rights {
            updates.add(Update::ChangeMemory {
                dom: Rc::downgrade(&domain.clone()),
            });
        }
        updates.snapshot()?;
        //TODO: notify all cores

        let dom = &mut domain.borrow_mut();
        let carved = region.borrow_mut().carve(access)?;
        let carved_capa = dom.data.install(CapaWrapper::Region(carved.clone()));

        // Tree & ownership logic.
        carved.borrow_mut().parent = Rc::downgrade(&region);
        carved.borrow_mut().owned = Ownership::new(Rc::downgrade(&domain), carved_capa);

        updates.compute()?;
        Ok(carved_capa)
    }

    fn revoke(
        &mut self,
        domain: CapaRef<Domain>,
        capa: LocalCapa,
        child: u64,
    ) -> Result<(), CapaError> {
        self.is_sealed_and_allowed(&domain, MonitorAPI::REVOKE)?;

        let is_domain = {
            let dom = &mut domain.borrow_mut();
            dom.data.is_domain(capa)?
        };
        // Match directly on the wrapper while we hold the borrow
        if is_domain {
            // Prepare the update.
            let mut update = OperationUpdate::new();
            {
                let dom = domain.borrow();
                let d = dom.data.capabilities.get(&capa)?.as_domain()?;
                dom.on_revoke_child(&d, &mut update)?;
            }
            update.snapshot()?;
            //TODO: notify all then we process the revoke.

            let dom = &mut domain.borrow_mut();
            let d = dom.data.capabilities.get(&capa)?.as_domain()?;

            // Mark the domain as being revoked.
            d.borrow_mut().data.status = Status::Revoked;
            dom.revoke_child(&d, &mut |c: &mut Capability<Domain>| {
                c.data.status = Status::Revoked;
                c.data
                    .capabilities
                    .foreach_region_mut(|c: &CapaRef<MemoryRegion>| {
                        Capability::<MemoryRegion>::revoke_node(c.clone(), &mut |_c| Ok(()))
                    })?;
                c.data.capabilities.reset();
                update.compute()?;
                //TODO: notify
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
                    .get(child as usize)
                    .cloned()
                    .ok_or(CapaError::InvalidChildCapa)?
            };

            // Prepare the update, this finds affected domains.
            let mut updates = OperationUpdate::new();
            child.borrow().on_revoke(&mut updates)?;
            updates.snapshot()?;

            // Now we should know all the affected domains.
            // TODO: preempt and process them.

            // Now actually do the revocation.
            // The region might belong to the dom, so we need to drop the domain.
            r.borrow_mut()
                .revoke_child(&child, &mut |a| Self::revoke_region_handler(a))?;
            updates.compute()?
            // TODO Will need to notify
        }

        Ok(())
    }

    fn send(
        &mut self,
        domain: CapaRef<Domain>,
        dest: LocalCapa,
        capa: LocalCapa,
        remap: Remapped,
        attributes: Attributes,
    ) -> Result<(), CapaError> {
        self.is_sealed_and_allowed(&domain, MonitorAPI::SEND)?;

        // Perform all the checks to ensure the operation is allowed.
        let dest = { domain.borrow().data.capabilities.get(&dest)?.as_domain()? };

        if dest.borrow().data.is_sealed()
            && (!dest.borrow().data.operation_allowed(MonitorAPI::RECEIVE)
                || !attributes.is_empty())
        {
            return Err(CapaError::CallNotAllowed);
        }

        // Check the attributes for the owner and conflicts in the dest.
        {
            let region = domain.borrow().data.capabilities.get(&capa)?.as_region()?;
            // Check attributes.
            if region
                .borrow()
                .data
                .attributes
                .intersects(Attributes::VITAL | Attributes::CLEAN)
            {
                return Err(CapaError::InvalidAttributes);
            }
            // Check conflicts.
            dest.borrow()
                .check_conflict(&ViewRegion::new(region.borrow().data.access, remap))?;
        }

        // Compute the updates, only trigger one if the dest is sealed.
        let mut updates = OperationUpdate::new();
        updates.add(Update::ChangeMemory {
            dom: Rc::downgrade(&domain.clone()),
        });
        if dest.borrow().data.is_sealed() {
            updates.add(Update::ChangeMemory {
                dom: Rc::downgrade(&dest.clone()),
            });
        }
        updates.snapshot()?;

        // Now effect the send.
        let dom = &mut domain.borrow_mut();
        let region = dom.data.capabilities.remove(&capa)?.as_region()?;

        // Apply the remapping and attributes.
        {
            let mut ref_reg = region.borrow_mut();
            ref_reg.data.remapped = remap;
            ref_reg.data.attributes = attributes;
        };

        let dest_capa = dest
            .borrow_mut()
            .data
            .install(CapaWrapper::Region(region.clone()));
        region.borrow_mut().owned = Ownership::new(Rc::downgrade(&dest), dest_capa);

        // Apply the updates.
        updates.compute()?;
        Ok(())
    }
}
