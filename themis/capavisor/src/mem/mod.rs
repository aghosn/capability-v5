//! Physical memory inventory — tracks usable memory regions and partitions META
//! from the top of physical memory.
//!
//! Parses the Limine memory map into a sorted list of usable physical regions
//! and partitions them into dom0-owned memory and a META pool for dom0's
//! hardware VP structures (VMXON, VMCS, VAPIC, EPT).

mod inventory;
mod meta_alloc;
mod uncacheable;

pub use inventory::{MemoryPartition, PhysRegion, PhysicalInventory};
#[cfg(target_arch = "aarch64")]
pub use inventory::MetaBreakdown;
pub use meta_alloc::MetaAllocator;
#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::paging::map_phys_range;
#[cfg(target_arch = "aarch64")]
pub use crate::arch::aarch64::paging::map_phys_range;
pub use uncacheable::UncacheableRanges;
