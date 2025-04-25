use crate::{
    capability::CapaError,
    domain::{InterruptPolicy, LocalCapa, MonitorAPI},
};

/// The interface to communicate with the engine.
pub trait ClientInterface {}

/// This is the client side of the capability engine.
pub struct Client<T: ClientInterface> {
    interface: T,
}

impl<T: ClientInterface> Client<T> {
    pub fn new(interface: T) -> Self {
        Self { interface }
    }
    pub fn create(
        &self,
        cores: u64,
        api: MonitorAPI,
        interrupts: InterruptPolicy,
    ) -> Result<LocalCapa, CapaError> {
        todo!();
    }

    pub fn enumerate(&self, capa: LocalCapa) -> Result<(), CapaError> {
        todo!()
    }
}
