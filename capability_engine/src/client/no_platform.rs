use crate::core::{
    capability::WeakRef,
    domain::{Domain, Field},
    platform_state::{InterruptInfo, PlatformState},
};

pub struct NoPlatform {
    //TODO: Implement
}

impl PlatformState for NoPlatform {
    fn new() -> Self {
        NoPlatform {}
    }
    fn interrupted_on_core(&self, _dom: WeakRef<Domain>, _core: u64) -> bool {
        todo!();
    }

    fn set_register_on_core(
        &mut self,
        _dom: WeakRef<Domain>,
        _core: u64,
        _field: Field,
        _value: u64,
    ) -> Result<(), crate::core::capability::CapaError> {
        todo!();
    }

    fn get_register_on_core(
        &mut self,
        _dom: WeakRef<Domain>,
        _core: u64,
        _field: Field,
    ) -> Result<u64, crate::core::capability::CapaError> {
        todo!()
    }

    fn interrupt_info_on_core(&self, _dom: WeakRef<Domain>, _core: u64) -> Option<InterruptInfo> {
        todo!()
    }

    fn current_core(&self) -> usize {
        //TODO implement.
        todo!();
    }
}
