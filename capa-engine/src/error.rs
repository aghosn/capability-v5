//! Error types for the capability engine

use core::fmt;

/// Result type for capability operations
pub type Result<T> = core::result::Result<T, CapaError>;

/// Errors that can occur during capability operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapaError {
    /// Capability referenced a domain that has been revoked
    DomainRevoked,

    /// Invalid access rights or range
    InvalidAccess,

    /// Operation not permitted
    PermissionDenied,

    /// Capability not found
    NotFound,

    /// Invalid operation on sealed domain
    DomainSealed,

    /// Invalid operation on unsealed domain
    DomainNotSealed,

    /// Parent capability has been revoked
    ParentRevoked,

    /// Cannot alias from a carved region
    CannotAliasCarved,

    /// Memory region overlap conflict
    RegionOverlap,

    /// Invalid remapping
    InvalidRemapping,

    /// Resource already exists
    AlreadyExists,

    /// Monotonicity violation (child exceeds parent permissions)
    MonotonicityViolation,

    /// Operation not allowed by domain's MonitorAPI
    ApiNotAllowed,

    /// Capability tree is locked (concurrent access)
    TreeLocked,

    /// Invalid operation
    InvalidOperation(alloc::string::String),

    /// Operation not supported by this platform
    NotSupported,

    /// Register ID out of range for this platform
    RegisterOutOfRange,

    /// Register access denied by the effective-vector policy bitmap
    RegisterAccessDenied,

    /// Invalid value for a policy field
    InvalidValue,

    /// Out of memory or resource limit reached
    NoMemory,
}

impl fmt::Display for CapaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapaError::DomainRevoked => write!(f, "Domain has been revoked"),
            CapaError::InvalidAccess => write!(f, "Invalid access rights or range"),
            CapaError::PermissionDenied => write!(f, "Operation not permitted"),
            CapaError::NotFound => write!(f, "Capability not found"),
            CapaError::DomainSealed => write!(f, "Invalid operation on sealed domain"),
            CapaError::DomainNotSealed => write!(f, "Invalid operation on unsealed domain"),
            CapaError::ParentRevoked => write!(f, "Parent capability has been revoked"),
            CapaError::CannotAliasCarved => write!(f, "Cannot alias from a carved region"),
            CapaError::RegionOverlap => write!(f, "Memory region overlap conflict"),
            CapaError::InvalidRemapping => write!(f, "Invalid remapping"),
            CapaError::AlreadyExists => write!(f, "Resource already exists"),
            CapaError::MonotonicityViolation => {
                write!(
                    f,
                    "Monotonicity violation: child exceeds parent permissions"
                )
            }
            CapaError::ApiNotAllowed => {
                write!(f, "Operation not allowed by domain's MonitorAPI")
            }
            CapaError::TreeLocked => write!(f, "Capability tree is locked"),
            CapaError::InvalidOperation(msg) => write!(f, "Invalid operation: {}", msg),
            CapaError::NotSupported => write!(f, "Operation not supported by this platform"),
            CapaError::RegisterOutOfRange => write!(f, "Register ID out of range"),
            CapaError::RegisterAccessDenied => {
                write!(f, "Register access denied by effective-vector policy bitmap")
            }
            CapaError::InvalidValue => write!(f, "Invalid value for a policy field"),
            CapaError::NoMemory => write!(f, "Out of memory or resource limit reached"),
        }
    }
}
