use std::{
    cell::RefCell,
    hash::{Hash, Hasher},
    rc::{Rc, Weak},
};

use super::capability::{CapaRef, Capability, WeakRef};

// Identity wrapper
#[derive(Clone)]
pub struct CapaKey<T>(pub CapaRef<T>);

impl<T> PartialEq for CapaKey<T> {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl<T> Eq for CapaKey<T> {}

impl<T> Hash for CapaKey<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let ptr: *const RefCell<Capability<T>> = Rc::as_ptr(&self.0);
        ptr.hash(state);
    }
}

pub struct WeakKey<T>(pub WeakRef<T>);

impl<T> PartialEq for WeakKey<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.ptr_eq(&other.0)
    }
}
impl<T> Eq for WeakKey<T> {}

impl<T> Hash for WeakKey<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Weak::as_ptr(&self.0).hash(state)
    }
}
