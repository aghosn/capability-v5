use super::{
    capability::{CapaError, WeakRef},
    domain::{Domain, Field},
};

/// This structure keeps track of interrupt information.
/// TODO: extend with the information we need.
pub struct InterruptInfo {
    pub vector: u64,
}

/// A trait for the implementation of a domain's global state.
pub trait PlatformState {
    fn new() -> Self;
    fn set_register_on_core(
        &mut self,
        dom: WeakRef<Domain>,
        core: u64,
        field: Field,
        value: u64,
    ) -> Result<(), CapaError>;
    fn get_register_on_core(
        &mut self,
        dom: WeakRef<Domain>,
        core: u64,
        field: Field,
    ) -> Result<u64, CapaError>;
    fn interrupted_on_core(&self, dom: WeakRef<Domain>, core: u64) -> bool;
    fn interrupt_info_on_core(&self, dom: WeakRef<Domain>, core: u64) -> Option<InterruptInfo>;
}
