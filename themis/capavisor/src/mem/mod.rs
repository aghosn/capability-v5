//! Physical memory inventory and heap initialization.
//!
//! Parses the Limine memory map into a sorted list of usable physical regions,
//! carves out a contiguous heap for the global allocator, and prints a summary
//! to serial.
//!
//! The remaining usable regions are partitioned into dom0-owned memory and a
//! META pool for dom0's hardware VP structures (VMXON, VMCS, VAPIC, EPT).

mod inventory;

pub use inventory::{MemoryPartition, MetaBreakdown, PhysRegion, PhysicalInventory};
