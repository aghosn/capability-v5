//! Extended Page Table (EPT) mapper for Themis.
//!
//! Ported from `vmxvmm/crates/mmu/` (local, Apache-2.0).  All vmxvmm
//! external dependencies (`utils`, `vmx::bitmaps`) have been replaced with
//! local types so this crate has no external dependencies beyond `bitflags`.
//!
//! ## AMD NPT note
//!
//! AMD Nested Page Tables have the identical 4-level structure and permission
//! encoding as Intel EPT.  This crate will be reused for NPT — the only
//! difference is writing the root physical address to `VMCB.N_CR3` instead
//! of `VMCS.EPT_POINTER`.

#![no_std]

mod addr;
mod mapper;
mod walker;

pub use addr::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};
pub use mapper::{EptMapper, EptMemoryType, EPT_MEM_TYPE_MASK, EPT_PRESENT, EPT_ROOT_FLAGS};
pub use walker::{Level, WalkNext, Walker};

bitflags::bitflags! {
    /// EPT page-table permission bits (Intel SDM Vol 3C §29.3.2).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct EptEntryFlags: u64 {
        const READ               = 1 << 0;
        const WRITE              = 1 << 1;
        /// Execute permission for supervisor-mode linear addresses.
        const SUPERVISOR_EXECUTE = 1 << 2;
        /// Large/huge page flag (set in L3 or L2 entries that are leaves).
        const PAGE               = 1 << 7;
        /// Execute permission for user-mode linear addresses.
        const USER_EXECUTE       = 1 << 10;
    }
}

/// Trait for physical frame allocators used by the EPT mapper.
///
/// The allocator MUST return zeroed frames (intermediate EPT page-table pages
/// must be zeroed to indicate "not present").  [`MetaAllocator::alloc_frame`]
/// already satisfies this invariant.
pub trait FrameAllocator {
    /// Allocate one 4 KiB zeroed frame.  Returns the physical address, or
    /// `None` if the allocator is exhausted.
    fn allocate_frame(&mut self) -> Option<u64>;

    /// Return a frame to the allocator.  The default implementation is a
    /// no-op; implementations should override this.
    fn free_frame(&mut self, _phys: u64) {}
}
