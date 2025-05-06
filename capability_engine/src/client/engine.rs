use std::rc::Rc;

use crate::{
    core::{
        capability::{CapaError, CapaRef, Capability, Ownership},
        domain::{CapaWrapper, Domain, LocalCapa},
        memory_region::{Access, MemoryRegion, RegionKind, Remapped, Rights},
    },
    server, CallInterface, EngineInterface,
};

pub enum ClientError {
    FailedSet,
    FailedGet,
    FailedSeal,
    FailedSend,
    FailedAlias,
    FailedCarve,
    FailedAttest,
    FailedRevoke,
    CapaError(CapaError),
}

pub enum ClientResult {
    SingleValue(usize),
    StringValue(String),
    EmptyValue,
}

// Platform interface.
pub trait ClientInterface {
    fn send(&self, call: CallInterface, args: &[usize; 6]) -> Result<ClientResult, ClientError>;
    fn receive(
        &self,
        engine: &mut crate::server::engine::Engine,
        call: CallInterface,
        args: &[usize; 6],
    ) -> Result<ClientResult, ClientError>;
}

// Client-side engine
pub struct Engine<T: ClientInterface> {
    pub platform: T,
    pub current: CapaRef<Domain>,
    // Copy of the server-side state. This makes it easier to perform operations.
    pub state: server::engine::Engine,
}

impl<T: ClientInterface> EngineInterface for Engine<T> {
    type CapabilityError = ClientError;
    type OwnedCapa = LocalCapa;
    type CapaReference = CapaRef<Domain>;
    fn set(
        &self,
        _domain: Self::CapaReference,
        child: Self::OwnedCapa,
        core: usize,
        tpe: crate::core::domain::FieldType,
        field: crate::core::domain::Field,
        value: usize,
    ) -> Result<(), Self::CapabilityError> {
        let args: [usize; 6] = [child as usize, core, tpe as usize, field, value, 0];
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
        core: usize,
        tpe: crate::core::domain::FieldType,
        field: crate::core::domain::Field,
    ) -> Result<usize, Self::CapabilityError> {
        let args: [usize; 6] = [child as usize, core, tpe as usize, field, 0, 0];
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
        let args: [usize; 6] = [child as usize, 0, 0, 0, 0, 0];
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
        let args: [usize; 6] = match remap {
            Remapped::Identity => [dest as usize, capa as usize, 0, 0, 0, 0],
            Remapped::Remapped(x) => [dest as usize, capa as usize, 1, x as usize, 0, 0],
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
        let args: [usize; 6] = [
            capa as usize,
            access.start as usize,
            access.size as usize,
            access.rights.bits() as usize,
            0,
            0,
        ];
        let res = self.platform.send(CallInterface::ALIAS, &args)?;
        // TODO: Should probably update the local state.
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
        let args: [usize; 6] = [
            capa as usize,
            access.start as usize,
            access.size as usize,
            access.rights.bits() as usize,
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
        _cores: u64,
        _api: crate::core::domain::MonitorAPI,
        _interrupts: crate::core::domain::InterruptPolicy,
    ) -> Result<Self::OwnedCapa, Self::CapabilityError> {
        // This one is gonna be a bitch.
        todo!()
    }
    fn attest(
        &self,
        _domain: Self::CapaReference,
        other: Option<Self::OwnedCapa>,
    ) -> Result<String, Self::CapabilityError> {
        let args: [usize; 6] = if let Some(v) = other {
            [v as usize; 6]
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
        child: usize,
    ) -> Result<(), Self::CapabilityError> {
        let args: [usize; 6] = [capa as usize, child, 0, 0, 0, 0];
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
        let args: [usize; 6] = [capa as usize, 0, 0, 0, 0, 0];
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
    ) {
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
    ) -> Result<LocalCapa, ClientError> {
        let local = region.borrow().owned.handle;
        let access = Access::new(start, size, Rights::from_bits_truncate(rights));
        let alias = self.alias(self.current.clone(), local, &access)?;
        self.add_region(local, region, &access, RegionKind::Alias);
        Ok(alias)
    }
    pub fn r_carve(
        &mut self,
        region: &CapaRef<MemoryRegion>,
        start: u64,
        size: u64,
        rights: u8,
    ) -> Result<LocalCapa, ClientError> {
        let local = region.borrow().owned.handle;
        let access = Access::new(start, size, Rights::from_bits_truncate(rights));
        let alias = self.carve(self.current.clone(), local, &access)?;
        // Now make sure we update the state.
        self.add_region(local, region, &access, RegionKind::Carve);
        Ok(alias)
    }

    pub fn r_revoke_region(
        &mut self,
        region: &CapaRef<MemoryRegion>,
        child: usize,
    ) -> Result<(), ClientError> {
        let local = region.borrow().owned.handle;
        self.revoke(self.current.clone(), local, child)?;

        let child = {
            let r_borrow = region.borrow();
            r_borrow.children.get(child).cloned().unwrap()
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
}
