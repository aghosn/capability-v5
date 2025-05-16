use core::{
    domain::{Field, FieldType, InterruptPolicy, MonitorAPI},
    memory_region::{Access, Remapped},
};

pub mod client;
pub mod core;
pub mod server;

fn is_core_subset(reference: u64, other: u64) -> bool {
    (reference & other) == other
}

// Call identifiers for the engine trait.
#[derive(Debug)]
#[repr(u8)]
pub enum CallInterface {
    CREATE = 1,
    SET = 2,
    GET = 3,
    SEAL = 4,
    ATTEST = 5,
    ENUMERATE = 6,
    SWITCH = 7,
    ALIAS = 8,
    CARVE = 9,
    REVOKE = 10,
    SEND = 11,
}

// Common interface for a capability engine.
// This trait is implemented by both the server side, implementing the actual state machine,
// and the client side that communicates with it.
pub trait EngineInterface {
    type CapaReference;
    type OwnedCapa;
    type CapabilityError;

    fn create(
        &self,
        domain: &Self::CapaReference,
        cores: u64,
        api: MonitorAPI,
        interrupts: InterruptPolicy,
    ) -> Result<Self::OwnedCapa, Self::CapabilityError>;

    fn set(
        &self,
        domain: Self::CapaReference,
        child: Self::OwnedCapa,
        core: u64,
        tpe: FieldType,
        field: Field,
        value: u64,
    ) -> Result<(), Self::CapabilityError>;

    fn get(
        &self,
        domain: Self::CapaReference,
        child: Self::OwnedCapa,
        core: u64,
        tpe: FieldType,
        field: Field,
    ) -> Result<u64, Self::CapabilityError>;

    fn seal(
        &self,
        domain: Self::CapaReference,
        child: Self::OwnedCapa,
    ) -> Result<(), Self::CapabilityError>;

    fn attest(
        &self,
        domain: Self::CapaReference,
        other: Option<Self::OwnedCapa>,
    ) -> Result<String, Self::CapabilityError>;

    fn enumerate(
        &self,
        domain: Self::CapaReference,
        capa: Self::OwnedCapa,
    ) -> Result<String, Self::CapabilityError>;

    fn switch(
        &self,
        domain: Self::CapaReference,
        _capa: Self::OwnedCapa,
    ) -> Result<(), Self::CapabilityError>;

    fn alias(
        &self,
        domain: Self::CapaReference,
        capa: Self::OwnedCapa,
        access: &Access,
    ) -> Result<Self::OwnedCapa, Self::CapabilityError>;

    fn carve(
        &self,
        domain: Self::CapaReference,
        capa: Self::OwnedCapa,
        access: &Access,
    ) -> Result<Self::OwnedCapa, Self::CapabilityError>;

    fn revoke(
        &self,
        domain: Self::CapaReference,
        capa: Self::OwnedCapa,
        child: u64,
    ) -> Result<(), Self::CapabilityError>;

    fn send(
        &self,
        domain: Self::CapaReference,
        dest: Self::OwnedCapa,
        capa: Self::OwnedCapa,
        remap: Remapped,
    ) -> Result<(), Self::CapabilityError>;
}
