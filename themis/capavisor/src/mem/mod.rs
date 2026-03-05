//! Physical memory inventory and heap initialization.
//!
//! Parses the Limine memory map into a sorted list of usable physical regions,
//! carves out a contiguous heap for the global allocator, and prints a summary
//! to serial.
//!
//! The remaining usable regions are recorded in [`PhysicalInventory`] for
//! Phase 1b (physical memory partitioning into dom0-owned + META pools).

mod inventory;

pub use inventory::PhysicalInventory;
