use crate::capability::CapaError;

pub trait Platform {
    fn set_register(dom: u64, core: usize, field: usize, value: usize);
    fn get_register(dom: u64, core: usize, field: usize) -> Result<usize, CapaError>;
    fn get_interrupt(dom: u64, core: usize) -> Result<usize, CapaError>;
}
