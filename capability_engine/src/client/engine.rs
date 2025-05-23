use std::{cell::RefCell, rc::Rc};

use crate::core::domain::{Field, Status};
use crate::core::memory_region::Attributes;
use crate::{
    core::{
        capability::{CapaError, CapaRef, Capability, Ownership},
        domain::{
            CapaWrapper, Domain, FieldType, InterruptPolicy, LocalCapa, MonitorAPI, Policies,
        },
        memory_region::{Access, MemoryRegion, RegionKind, Remapped, Rights},
    },
    CallInterface, EngineInterface,
};

#[derive(Debug)]
pub enum ClientError {
    FailedSet,
    FailedGet,
    FailedSeal,
    FailedSend,
    FailedAlias,
    FailedCarve,
    FailedAttest,
    FailedRevoke,
    FailedCreate,
    CapaError(CapaError),
}

#[derive(Debug)]
pub enum ClientResult {
    SingleValue(u64),
    StringValue(String),
    EmptyValue,
}

impl ClientResult {
    pub fn wrap_empty(input: Result<(), CapaError>) -> Result<ClientResult, ClientError> {
        match input {
            Ok(()) => Ok(Self::EmptyValue),
            Err(e) => Err(ClientError::CapaError(e)),
        }
    }

    pub fn wrap_value(input: Result<u64, CapaError>) -> Result<ClientResult, ClientError> {
        match input {
            Ok(v) => Ok(Self::SingleValue(v)),
            Err(e) => Err(ClientError::CapaError(e)),
        }
    }

    pub fn wrap_string(input: Result<String, CapaError>) -> Result<ClientResult, ClientError> {
        match input {
            Ok(s) => Ok(Self::StringValue(s)),
            Err(e) => Err(ClientError::CapaError(e)),
        }
    }
}

// Communication interface.
pub trait CommunicationInterface {
    fn new(nb_cores: u64) -> Self;
    fn send(&mut self, call: CallInterface, args: &[u64; 6]) -> Result<ClientResult, ClientError>;
    fn receive(
        &mut self,
        engine: &mut crate::server::engine::Engine,
        call: CallInterface,
        args: &[u64; 6],
    ) -> Result<ClientResult, ClientError>;
}

// Client-side engine
pub struct Engine<T: CommunicationInterface> {
    pub platform: T,
    pub current: CapaRef<Domain>,
}

impl<T: CommunicationInterface> Engine<T> {
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
}

impl<T: CommunicationInterface> EngineInterface for Engine<T> {
    type CapabilityError = ClientError;
    type OwnedCapa = LocalCapa;
    type CapaReference = CapaRef<Domain>;

    fn new(nb_cores: u64) -> Self {
        let policies = Policies::new(
            (1 << nb_cores) - 1,
            MonitorAPI::all(),
            InterruptPolicy::default_all(),
        );
        let mut capa = Capability::<Domain>::new(Domain::new(policies));
        capa.data.status = Status::Sealed;
        let ref_td = Rc::new(RefCell::new(capa));
        Self {
            platform: T::new(nb_cores),
            current: ref_td,
        }
    }

    fn set(
        &mut self,
        _domain: Self::CapaReference,
        child: Self::OwnedCapa,
        core: u64,
        tpe: crate::core::domain::FieldType,
        field: crate::core::domain::Field,
        value: u64,
    ) -> Result<(), Self::CapabilityError> {
        let args: [u64; 6] = [child as u64, core, tpe as u64, field, value, 0];
        let res = self.platform.send(CallInterface::SET, &args)?;
        match res {
            ClientResult::EmptyValue => Ok(()),
            _ => Err(ClientError::FailedSet),
        }
    }

    fn get(
        &mut self,
        _domain: Self::CapaReference,
        child: Self::OwnedCapa,
        core: u64,
        tpe: crate::core::domain::FieldType,
        field: crate::core::domain::Field,
    ) -> Result<u64, Self::CapabilityError> {
        let args: [u64; 6] = [child as u64, core, tpe as u64, field, 0, 0];
        let res = self.platform.send(CallInterface::GET, &args)?;
        match res {
            ClientResult::SingleValue(v) => Ok(v),
            _ => Err(ClientError::FailedGet),
        }
    }

    fn seal(
        &mut self,
        _domain: Self::CapaReference,
        child: Self::OwnedCapa,
    ) -> Result<(), Self::CapabilityError> {
        let args: [u64; 6] = [child as u64, 0, 0, 0, 0, 0];
        let res = self.platform.send(CallInterface::SEAL, &args)?;
        match res {
            ClientResult::EmptyValue => Ok(()),
            _ => Err(ClientError::FailedSeal),
        }
    }

    fn send(
        &mut self,
        _domain: Self::CapaReference,
        dest: Self::OwnedCapa,
        capa: Self::OwnedCapa,
        remap: crate::core::memory_region::Remapped,
        attributes: crate::core::memory_region::Attributes,
    ) -> Result<(), Self::CapabilityError> {
        let args: [u64; 6] = match remap {
            Remapped::Identity => [dest as u64, capa as u64, 0, 0, attributes.bits() as u64, 0],
            Remapped::Remapped(x) => [
                dest as u64,
                capa as u64,
                1,
                x as u64,
                attributes.bits() as u64,
                0,
            ],
        };
        let res = self.platform.send(CallInterface::SEND, &args)?;
        match res {
            ClientResult::EmptyValue => Ok(()),
            _ => Err(ClientError::FailedSend),
        }
    }
    fn alias(
        &mut self,
        _domain: Self::CapaReference,
        capa: Self::OwnedCapa,
        access: &crate::core::memory_region::Access,
    ) -> Result<Self::OwnedCapa, Self::CapabilityError> {
        let args: [u64; 6] = [
            capa as u64,
            access.start as u64,
            access.size as u64,
            access.rights.bits() as u64,
            0,
            0,
        ];
        let res = self.platform.send(CallInterface::ALIAS, &args)?;
        match res {
            ClientResult::SingleValue(v) => Ok(v as LocalCapa),
            _ => Err(ClientError::FailedAlias),
        }
    }
    fn carve(
        &mut self,
        _domain: Self::CapaReference,
        capa: Self::OwnedCapa,
        access: &crate::core::memory_region::Access,
    ) -> Result<Self::OwnedCapa, Self::CapabilityError> {
        let args: [u64; 6] = [
            capa as u64,
            access.start as u64,
            access.size as u64,
            access.rights.bits() as u64,
            0,
            0,
        ];
        let res = self.platform.send(CallInterface::CARVE, &args)?;
        // TODO: Should probably update the local state.
        match res {
            ClientResult::SingleValue(v) => Ok(v as LocalCapa),
            _ => Err(ClientError::FailedCarve),
        }
    }
    fn create(
        &mut self,
        _domain: &Self::CapaReference,
        cores: u64,
        api: crate::core::domain::MonitorAPI,
        interrupts: InterruptPolicy,
    ) -> Result<Self::OwnedCapa, Self::CapabilityError> {
        let args = [cores as u64, api.bits() as u64, 0, 0, 0, 0];
        let res = self.platform.send(CallInterface::CREATE, &args)?;

        match res {
            ClientResult::SingleValue(child) => {
                // Now set the interrutps.
                for (i, v) in interrupts.vectors.iter().enumerate() {
                    let args = [
                        child,
                        0,
                        FieldType::InterruptVisibility as u64,
                        i as u64,
                        v.visibility.bits() as u64,
                        0,
                    ];
                    self.platform.send(CallInterface::SET, &args)?;
                    let args = [
                        child,
                        0,
                        FieldType::InterruptRead as u64,
                        i as u64,
                        v.read_set as u64,
                        0,
                    ];
                    self.platform.send(CallInterface::SET, &args)?;
                    let args = [
                        child,
                        0,
                        FieldType::InterruptWrite as u64,
                        i as u64,
                        v.write_set as u64,
                        0,
                    ];
                    self.platform.send(CallInterface::SET, &args)?;
                }
                return Ok(child as LocalCapa);
            }
            _ => return Err(ClientError::FailedCreate),
        }
    }

    fn attest(
        &mut self,
        _domain: Self::CapaReference,
        other: Option<Self::OwnedCapa>,
    ) -> Result<String, Self::CapabilityError> {
        let args: [u64; 6] = if let Some(v) = other {
            [v as u64; 6]
        } else {
            [0; 6]
        };
        let res = self.platform.send(CallInterface::ATTEST, &args)?;
        match res {
            ClientResult::StringValue(v) => Ok(v),
            _ => Err(ClientError::FailedAttest),
        }
    }

    fn switch(
        &mut self,
        _domain: Self::CapaReference,
        _capa: Self::OwnedCapa,
    ) -> Result<(), Self::CapabilityError> {
        todo!()
    }

    fn revoke(
        &mut self,
        _domain: Self::CapaReference,
        capa: Self::OwnedCapa,
        child: u64,
    ) -> Result<(), Self::CapabilityError> {
        let args: [u64; 6] = [capa as u64, child, 0, 0, 0, 0];
        let res = self.platform.send(CallInterface::REVOKE, &args)?;
        match res {
            ClientResult::EmptyValue => Ok(()),
            _ => Err(ClientError::FailedRevoke),
        }
    }

    fn enumerate(
        &mut self,
        _domain: Self::CapaReference,
        capa: Self::OwnedCapa,
    ) -> Result<String, Self::CapabilityError> {
        let args: [u64; 6] = [capa as u64, 0, 0, 0, 0, 0];
        let res = self.platform.send(CallInterface::ENUMERATE, &args)?;
        match res {
            ClientResult::StringValue(v) => Ok(v),
            _ => Err(ClientError::FailedAttest),
        }
    }
}

// Simplified client interface.
impl<T: CommunicationInterface> Engine<T> {
    // Internal functions to maintain some state.
    fn add_region(
        &mut self,
        idx: LocalCapa,
        parent: &CapaRef<MemoryRegion>,
        access: &Access,
        kind: RegionKind,
    ) -> CapaRef<MemoryRegion> {
        let child = match kind {
            RegionKind::Carve => parent.borrow_mut().carve(access).unwrap(),
            RegionKind::Alias => parent.borrow_mut().alias(access).unwrap(),
        };
        self.current
            .borrow_mut()
            .data
            .capabilities
            .install_capabilitiy_at(CapaWrapper::Region(child.clone()), idx);

        // Tree & ownership logic.
        child.borrow_mut().parent = Rc::downgrade(&parent);
        child.borrow_mut().owned = Ownership::new(Rc::downgrade(&self.current), idx);
        child.clone()
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

    pub fn r_set(
        &mut self,
        child: &CapaRef<Domain>,
        core: u64,
        tpe: FieldType,
        field: Field,
        value: u64,
    ) -> Result<(), ClientError> {
        let local = child.borrow().owned.handle;
        self.set(self.current.clone(), local, core, tpe, field, value)?;
        {
            // Everything went well, set it now.
            child
                .borrow_mut()
                .set(core, tpe, field, value)
                .map_err(|_| ClientError::FailedSet)?;
        }
        Ok(())
    }

    pub fn r_get(
        &mut self,
        child: &CapaRef<Domain>,
        core: u64,
        tpe: FieldType,
        field: Field,
    ) -> Result<u64, ClientError> {
        let local = child.borrow().owned.handle;
        //TODO: check if we wanna bypass.
        self.get(self.current.clone(), local, core, tpe, field)
    }

    pub fn r_alias(
        &mut self,
        region: &CapaRef<MemoryRegion>,
        start: u64,
        size: u64,
        rights: u8,
    ) -> Result<CapaRef<MemoryRegion>, ClientError> {
        let local = region.borrow().owned.handle;
        let access = Access::new(start, size, Rights::from_bits_truncate(rights));
        let alias = self.alias(self.current.clone(), local, &access)?;
        Ok(self.add_region(alias, region, &access, RegionKind::Alias))
    }

    pub fn r_carve(
        &mut self,
        region: &CapaRef<MemoryRegion>,
        start: u64,
        size: u64,
        rights: u8,
    ) -> Result<CapaRef<MemoryRegion>, ClientError> {
        let local = region.borrow().owned.handle;
        let access = Access::new(start, size, Rights::from_bits_truncate(rights));
        let carve = self.carve(self.current.clone(), local, &access)?;
        // Now make sure we update the state.
        Ok(self.add_region(carve, region, &access, RegionKind::Carve))
    }

    pub fn r_create(
        &mut self,
        cores: u64,
        api: MonitorAPI,
        interrupts: InterruptPolicy,
    ) -> Result<CapaRef<Domain>, ClientError> {
        let local = self.create(&self.current.clone(), cores, api, interrupts)?;
        let policies = Policies::new(cores, api, interrupts);
        let child_dom = Domain::new(policies);
        let capa = Capability::<Domain>::new(child_dom);
        let reference = Rc::new(RefCell::new(capa));
        {
            let dom = &mut self.current.borrow_mut();
            dom.add_child(reference.clone(), Rc::downgrade(&self.current.clone()));
            reference.borrow_mut().owned.handle = local;
            dom.data
                .capabilities
                .install_capabilitiy_at(CapaWrapper::Domain(reference.clone()), local);
        }
        Ok(reference)
    }

    pub fn r_attest(&mut self, child: Option<&CapaRef<Domain>>) -> Result<String, ClientError> {
        let idx = if let Some(c) = child {
            Some(c.borrow().owned.handle)
        } else {
            None
        };
        self.attest(self.current.clone(), idx)
    }

    pub fn r_revoke_region(&mut self, child: &CapaRef<MemoryRegion>) -> Result<(), ClientError> {
        let parent = child
            .borrow()
            .parent
            .upgrade()
            .ok_or(ClientError::FailedRevoke)?;
        // Check it belongs to us.
        if parent
            .borrow()
            .owned
            .owner
            .upgrade()
            .ok_or(ClientError::FailedRevoke)?
            != self.current
        {
            return Err(ClientError::FailedRevoke);
        }
        let mut idx = -1;
        for (i, c) in parent.borrow().children.iter().enumerate() {
            if c == child {
                idx = i as i32;
                break;
            }
        }
        if idx == -1 {
            return Err(ClientError::FailedRevoke);
        }
        let local = parent.borrow().owned.handle;
        //let local = region.borrow().owned.handle;
        self.revoke(self.current.clone(), local, idx as u64)?;

        let child = {
            let r_borrow = parent.borrow();
            r_borrow.children.get(idx as usize).cloned().unwrap()
        };
        // It got revoked, time to update.
        parent
            .borrow_mut()
            .revoke_child(&child, &mut Self::revoke_region_handler)
            .map_err(|e| ClientError::CapaError(e))?;
        Ok(())
    }

    pub fn r_revoke_child(&mut self, child: &CapaRef<Domain>) -> Result<(), ClientError> {
        let local = child.borrow().owned.handle;
        self.revoke(self.current.clone(), local, 0)?;
        let dom = &mut self.current.borrow_mut();
        let d = dom
            .data
            .capabilities
            .get(&local)
            .map_err(|e| ClientError::CapaError(e))?
            .as_domain()
            .map_err(|e| ClientError::CapaError(e))?;

        dom.revoke_child(&d, &mut |c: &mut Capability<Domain>| {
            c.data.status = crate::core::domain::Status::Revoked;
            c.data
                .capabilities
                .foreach_region_mut(|c: &CapaRef<MemoryRegion>| {
                    Capability::<MemoryRegion>::revoke_node(c.clone(), &mut |_c| Ok(()))
                })?;
            c.data.capabilities.reset();
            Ok(())
        })
        .map_err(|e| ClientError::CapaError(e))?;
        // Remove the handle
        dom.data
            .capabilities
            .remove(&local)
            .map_err(|e| ClientError::CapaError(e))?;
        Ok(())
    }

    pub fn r_seal(&mut self, child: &CapaRef<Domain>) -> Result<(), ClientError> {
        let local = child.borrow().owned.handle;
        self.seal(self.current.clone(), local)?;
        child.borrow_mut().data.status = crate::core::domain::Status::Sealed;
        Ok(())
    }

    pub fn r_send(
        &mut self,
        child: &CapaRef<Domain>,
        region: &CapaRef<MemoryRegion>,
        remap: Remapped,
        attributes: Attributes,
    ) -> Result<(), ClientError> {
        let local_c = child.borrow().owned.handle;
        let local_m = region.borrow().owned.handle;
        self.send(self.current.clone(), local_c, local_m, remap, attributes)?;
        // Update locally by abusing the server interface.
        {
            let current = &mut self.current.borrow_mut();
            let region = current
                .data
                .capabilities
                .remove(&local_m)
                .map_err(|_| ClientError::FailedSend)?
                .as_region()
                .map_err(|_| ClientError::FailedSend)?;
            {
                let reg = &mut region.borrow_mut();
                reg.data.remapped = remap;
                reg.data.attributes = attributes;
            }
            let dest_capa = child
                .borrow_mut()
                .data
                .install(CapaWrapper::Region(region.clone()));
            region.borrow_mut().owned = Ownership::new(Rc::downgrade(&child), dest_capa);
        }
        Ok(())
    }

    pub fn find_region<F>(&self, condition: F) -> Option<CapaRef<MemoryRegion>>
    where
        F: Fn(&CapaRef<MemoryRegion>) -> bool,
    {
        for (_, c) in self.current.borrow().data.capabilities.capabilities.iter() {
            match c {
                CapaWrapper::Region(r) => {
                    if condition(r) {
                        return Some(r.clone());
                    }
                }
                _ => {}
            }
        }
        return None;
    }

    pub fn find_child<F>(&self, condition: F) -> Option<CapaRef<Domain>>
    where
        F: Fn(&CapaRef<Domain>) -> bool,
    {
        for (_, c) in self.current.borrow().data.capabilities.capabilities.iter() {
            match c {
                CapaWrapper::Domain(d) => {
                    if condition(d) {
                        return Some(d.clone());
                    }
                }
                _ => {}
            }
        }
        return None;
    }
}
