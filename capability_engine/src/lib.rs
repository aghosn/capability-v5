use core::{
    domain::{Field, FieldType, InterruptPolicy, MonitorAPI},
    memory_region::{Access, Remapped},
};

pub mod core;
pub mod server;

fn is_core_subset(reference: u64, other: u64) -> bool {
    (reference & other) == other
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
        core: usize,
        tpe: FieldType,
        field: Field,
        value: usize,
    ) -> Result<(), Self::CapabilityError>;

    fn get(
        &self,
        domain: Self::CapaReference,
        child: Self::OwnedCapa,
        core: usize,
        tpe: FieldType,
        field: Field,
    ) -> Result<usize, Self::CapabilityError>;

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
        child: usize,
    ) -> Result<(), Self::CapabilityError>;

    fn send(
        &self,
        domain: Self::CapaReference,
        dest: Self::OwnedCapa,
        capa: Self::OwnedCapa,
        remap: Remapped,
    ) -> Result<(), Self::CapabilityError>;
}
