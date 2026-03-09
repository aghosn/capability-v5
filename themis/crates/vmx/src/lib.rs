//! Generic VT-x (VMX) support crate.
//!
//! Hardware abstraction with no hypervisor-specific policy:
//! - CPU feature detection and VMXON enable
//! - ActiveVcpu / InactiveVcpu type-state VMCS lifecycle
//! - Guest entry/exit via naked functions (LTO-safe)
//!
//! The consumer (e.g., capavisor) provides the VMCS field setup policy
//! (control bits, guest state, host state) and the VMEXIT dispatch loop.

#![no_std]

pub mod features;
pub mod vcpu;
