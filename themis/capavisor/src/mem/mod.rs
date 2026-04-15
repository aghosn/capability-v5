//! Physical memory inventory — tracks usable memory regions and partitions META
//! from the top of physical memory.
//!
//! Parses the Limine memory map into a sorted list of usable physical regions
//! and partitions them into dom0-owned memory and a META pool for dom0's
//! hardware VP structures (VMXON, VMCS, VAPIC, EPT).

mod inventory;
mod meta_alloc;
#[cfg(target_arch = "x86_64")]
mod paging;
#[cfg(target_arch = "aarch64")]
#[path = "paging_aarch64.rs"]
mod paging;
mod uncacheable;

pub use inventory::{MemoryPartition, MetaBreakdown, PhysRegion, PhysicalInventory};
pub use meta_alloc::MetaAllocator;
pub use paging::map_phys_range;
pub use uncacheable::UncacheableRanges;
