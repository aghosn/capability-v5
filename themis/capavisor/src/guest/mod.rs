//! Guest / dom0 module discovery and loading helpers.
//!
//! Limine delivers loaded modules (kernel, initrd, …) as [`limine::file::File`]
//! entries via `ModuleResponse`.  This module provides a thin wrapper that
//! extracts the information Themis needs from each module and offers a
//! name-based lookup via the `module_cmdline` tag set in `limine.conf`.

pub mod linux;
mod modules;

pub use modules::{find_module, ModuleInfo};
