//! Address newtypes used by the EPT walker and mapper.

use crate::walker::Address;

macro_rules! addr_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
        #[repr(transparent)]
        pub struct $name(pub u64);

        impl $name {
            #[inline]
            pub fn new(val: usize) -> Self {
                Self(val as u64)
            }
            #[inline]
            pub fn from_u64(val: u64) -> Self {
                Self(val)
            }
            #[inline]
            pub fn as_u64(self) -> u64 {
                self.0
            }
            #[inline]
            pub fn as_usize(self) -> usize {
                self.0 as usize
            }
        }

        impl Address for $name {
            #[inline]
            fn from_u64(addr: u64) -> Self {
                Self(addr)
            }
            #[inline]
            fn as_u64(self) -> u64 {
                self.0
            }
            #[inline]
            fn from_usize(addr: usize) -> Self {
                Self(addr as u64)
            }
            #[inline]
            fn as_usize(self) -> usize {
                self.0 as usize
            }
        }
    };
}

addr_type!(GuestPhysAddr);
addr_type!(HostPhysAddr);
addr_type!(HostVirtAddr);

impl core::ops::Add<usize> for GuestPhysAddr {
    type Output = Self;
    #[inline]
    fn add(self, rhs: usize) -> Self {
        Self(self.0 + rhs as u64)
    }
}
