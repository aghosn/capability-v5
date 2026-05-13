//! Eunomia kernel library — exported services for workload crates.
//!
//! Workload crates depend on this library to access kernel services
//! (serial I/O, timer, IDT info).  The kernel binary (`main.rs`)
//! initialises everything and then calls the workload's `app_main`.

#![no_std]

pub mod serial;
pub mod timer;
pub mod test_harness;

/// Kernel services handle passed to workload's `app_main`.
///
/// Provides access to initialised kernel subsystems.  Currently a
/// marker — individual subsystems are accessed through their module
/// APIs (e.g., `eunomia::serial`, `eunomia::timer`).  As the kernel
/// grows, this struct will hold references to trait-object subsystems
/// (scheduler, memory manager, hypervisor interface, etc.).
pub struct KernelServices {
    /// Physical address of the hvm_start_info struct from PVH boot.
    pub hvm_start_info: u64,
}
