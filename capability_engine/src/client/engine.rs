use std::{cell::RefCell, rc::Rc};

use crate::server::engine::Engine as SEngine;
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

// Platform interface.
pub trait ClientInterface {
    fn init() -> Self;
    fn send(&self, call: CallInterface, args: &[u64; 6]) -> Result<ClientResult, ClientError>;
    fn receive(
        &self,
        engine: &mut crate::server::engine::Engine,
        call: CallInterface,
        args: &[u64; 6],
    ) -> Result<ClientResult, ClientError>;
}

// Client-side engine
pub struct Engine<T: ClientInterface> {
    pub platform: T,
    pub current: CapaRef<Domain>,
}

impl<T: ClientInterface> EngineInterface for Engine<T> {
    type CapabilityError = ClientError;
    type OwnedCapa = LocalCapa;
    type CapaReference = CapaRef<Domain>;
    fn set(
        &self,
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
        &self,
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
        &self,
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
        &self,
        _domain: Self::CapaReference,
        dest: Self::OwnedCapa,
        capa: Self::OwnedCapa,
        remap: crate::core::memory_region::Remapped,
    ) -> Result<(), Self::CapabilityError> {
        let args: [u64; 6] = match remap {
            Remapped::Identity => [dest as u64, capa as u64, 0, 0, 0, 0],
            Remapped::Remapped(x) => [dest as u64, capa as u64, 1, x as u64, 0, 0],
        };
        let res = self.platform.send(CallInterface::SEND, &args)?;
        match res {
            ClientResult::EmptyValue => Ok(()),
            _ => Err(ClientError::FailedSend),
        }
    }
    fn alias(
        &self,
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
        &self,
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
        &self,
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
        &self,
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
        &self,
        _domain: Self::CapaReference,
        _capa: Self::OwnedCapa,
    ) -> Result<(), Self::CapabilityError> {
        todo!()
    }

    fn revoke(
        &self,
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
        &self,
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
impl<T: ClientInterface> Engine<T> {
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

    pub fn r_revoke_region(
        &mut self,
        region: &CapaRef<MemoryRegion>,
        child: u64,
    ) -> Result<(), ClientError> {
        let local = region.borrow().owned.handle;
        self.revoke(self.current.clone(), local, child)?;

        let child = {
            let r_borrow = region.borrow();
            r_borrow.children.get(child as usize).cloned().unwrap()
        };
        // It got revoked, time to update.
        region
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
    ) -> Result<(), ClientError> {
        let local_c = child.borrow().owned.handle;
        let local_m = region.borrow().owned.handle;
        self.send(self.current.clone(), local_c, local_m, remap)?;
        // Update locally by abusing the server interface.
        {
            let engine = SEngine {};
            engine
                .send(self.current.clone(), local_c, local_m, remap)
                .unwrap();
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
