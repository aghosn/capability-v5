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

#![cfg_attr(not(any(test, feature = "loom")), no_std)]

extern crate alloc;

pub mod attest;
pub mod bootstrap;
pub mod capability;
pub mod domain_api;
pub mod domain;
pub mod error;
pub mod interposition;
pub mod memory;
pub mod platform;
pub mod switch;
pub(crate) mod sync;
pub mod update;
pub mod view;

#[cfg(feature = "address_translation")]
pub mod translation;

pub use attest::{
    attest_domain, attest_memory_region, build_structured_attestation, enumerate_domain_tree,
    AttestationReport, DomCapInfo, MemCapInfo, PaMapInfo, StructuredAttestation,
};
pub use capability::{
    compute_address_space, Capability, CapabilityRef, CapabilityWeak, LocalHandle, Ownership,
    SubHandle,
};
pub use domain::{
    Domain, DomainPolicy, DomainStatus, ExitAction, ExitPolicy,
    InterruptPolicy, InterruptVisibility, MonitorAPI, PendingDomainCapability, PolicyIdentifier,
    RegBitmap, ResourceKind, VProcessorRef, VProcessorState, VectorPolicy, VpCallContext,
    VpRunState, VECTOR_AVAILABLE,
};
pub use error::{CapaError, Result};
pub use interposition::{
    Cpuid, CpuidPolicy, CpuidResult, DefaultAction, InsertError, Msr, MsrPolicy,
    ProcFeature, ProcFeatureConfig, ProcFeaturePolicy,
};
pub use memory::{Access, Attributes, MemoryRegion, RegionKind, RegionStatus, Rights};
pub use platform::{Barrier, CoreSyncBarriers, OpLockGuard, Platform};

/// Test-only shim that exposes the crate-internal `execute()` wrapper for
/// integration tests to validate lock discipline and update dispatch
/// semantics directly. Production consumers must use the domain-mediated
/// [`Capability`] API, which calls `execute()` internally.
#[cfg(feature = "test-utils")]
pub fn execute<F, R>(
    platform: &dyn Platform,
    exclusive: bool,
    op: F,
) -> Result<(R, update::UpdateBatch)>
where
    F: FnOnce() -> Result<(R, update::UpdateBatch)>,
{
    platform::execute(platform, exclusive, op)
}
pub use switch::{
    CoreBinding, CoreContext, CoreUpdate, InterruptContext, SwitchContext, SwitchManager,
    VpInterruptContext,
};
pub use update::{
    CoreId, DomainId, PolicyChange, QueuedUpdateBatch, Update, UpdateBatch, UpdateProcessor,
    UpdateStatus,
};
pub use view::{
    compute_view_from_capabilities, view_diff, AddressSpaceView, ViewRegion,
};

#[cfg(feature = "address_translation")]
pub use translation::{AddressMap, MapEntry, MappingEntry};
#[cfg(feature = "cache_coloring")]
pub use translation::ColorBitmap;
