//! Eunomia kernel library — runtime and services for workload crates.
//!
//! Provides the complete boot runtime (PVH entry, 32→64 transition,
//! GDT, IDT, heap), kernel services (serial, timer, memory), and test
//! harness.  Workload crates depend on this library and define an
//! `app_main` function that the runtime calls after initialisation.

#![no_std]

extern crate alloc;

pub mod serial;
pub mod timer;
pub mod mm;
pub mod test_harness;
pub mod gdt;
pub mod idt;
pub mod boot;
pub mod sched;
pub mod hv;
pub mod domcomm;

// Re-export libthemis (typed hypercall wrappers) and themis-abi (opcodes,
// error codes) so workloads can call e.g. `eunomia::themis::alias()`.
pub use libthemis as themis;
pub use themis_abi;

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
