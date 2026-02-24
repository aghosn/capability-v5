//! # Capability Engine V2
//!
//! A thread-safe implementation of a capability-based security system for managing
//! trust domains with composable isolation.
//!
//! This implementation provides:
//! - Thread-safe capability management using Arc, RwLock, and Mutex
//! - Memory capabilities with exclusive/aliased status
//! - Domain capabilities with policies and virtual processor states
//! - Atomic updates for address space modifications
//! - Switch and interrupt routing mechanisms
//!
//! ## no_std Support
//!
//! This crate can be used in `no_std` environments with the `alloc` crate.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod attest;
pub mod capability;
pub mod domain;
pub mod error;
pub mod memory;
pub mod switch;
pub mod update;
pub mod view;

pub use attest::{attest_domain, attest_memory_region, enumerate_domain_tree, AttestationReport};
pub use capability::{Capability, CapabilityRef, CapabilityWeak, DomainCapabilityExt, LocalHandle, MemoryCapabilityExt, Ownership};
pub use domain::{
    Domain, DomainPolicy, DomainStatus, InterruptPolicy, InterruptVisibility, MonitorAPI,
    VProcessorState, VectorPolicy,
};
pub use error::{CapaError, Result};
pub use memory::{Access, Attributes, MemoryRegion, RegionKind, RegionStatus, Rights};
pub use switch::{CoreContext, CoreState, InterruptContext, SwitchContext, SwitchManager};
pub use update::{CoreId, CoreUpdate, DomainId, Update, UpdateBatch, UpdateProcessor, UpdateStatus};
pub use view::{AddressSpaceView, ViewRegion, compute_address_space, compute_view_from_capabilities};
