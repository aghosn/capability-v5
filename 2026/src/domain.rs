//! Domain capabilities and policies

use crate::error::{CapaError, Result};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// Global domain ID counter
static NEXT_DOMAIN_ID: AtomicU64 = AtomicU64::new(1);

/// Generate a unique domain ID
pub fn generate_domain_id() -> u64 {
    NEXT_DOMAIN_ID.fetch_add(1, Ordering::SeqCst)
}

/// Domain status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainStatus {
    /// Domain is being configured
    Unsealed,
    /// Domain is sealed and executable
    Sealed,
    /// Domain has been revoked
    Revoked,
}

/// Monitor API operations that can be allowed for a domain
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorAPI {
    pub create: bool,
    pub set: bool,
    pub get: bool,
    pub send: bool,
    pub seal: bool,
    pub attest: bool,
    pub enumerate: bool,
    pub switch: bool,
    pub alias: bool,
    pub carve: bool,
    pub revoke: bool,
    pub getchan: bool,
}

impl MonitorAPI {
    /// All operations allowed
    pub const ALL: Self = MonitorAPI {
        create: true,
        set: true,
        get: true,
        send: true,
        seal: true,
        attest: true,
        enumerate: true,
        switch: true,
        alias: true,
        carve: true,
        revoke: true,
        getchan: true,
    };

    /// No operations allowed
    pub const NONE: Self = MonitorAPI {
        create: false,
        set: false,
        get: false,
        send: false,
        seal: false,
        attest: false,
        enumerate: false,
        switch: false,
        alias: false,
        carve: false,
        revoke: false,
        getchan: false,
    };

    /// Check if self is a subset of other (for monotonicity)
    pub fn is_subset_of(&self, other: &MonitorAPI) -> bool {
        (!self.create || other.create)
            && (!self.set || other.set)
            && (!self.get || other.get)
            && (!self.send || other.send)
            && (!self.seal || other.seal)
            && (!self.attest || other.attest)
            && (!self.enumerate || other.enumerate)
            && (!self.switch || other.switch)
            && (!self.alias || other.alias)
            && (!self.carve || other.carve)
            && (!self.revoke || other.revoke)
            && (!self.getchan || other.getchan)
    }
}

/// Interrupt vector policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptVisibility {
    /// Interrupt is delivered directly to the domain
    Deliver,
    /// Interrupt is reported to domain but handled by parent
    Report,
    /// Interrupt is not reported to domain
    NotReport,
}

/// Policy for a specific interrupt vector
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorPolicy {
    pub visibility: InterruptVisibility,
    /// Bitmask of registers that can be read during interrupt handling
    pub read_set: u64,
    /// Bitmask of registers that can be written during interrupt handling
    pub write_set: u64,
}

impl VectorPolicy {
    pub fn default_deliver() -> Self {
        VectorPolicy {
            visibility: InterruptVisibility::Deliver,
            read_set: 0,
            write_set: 0,
        }
    }

    pub fn default_report() -> Self {
        VectorPolicy {
            visibility: InterruptVisibility::Report,
            read_set: 0,
            write_set: 0,
        }
    }
}

/// Interrupt routing policy
#[derive(Debug, Clone)]
pub struct InterruptPolicy {
    /// Default policy for all vectors
    pub default: VectorPolicy,
    /// Per-vector overrides (vector number -> policy)
    pub overrides: BTreeMap<u8, VectorPolicy>,
}

impl InterruptPolicy {
    pub fn new_default(default: VectorPolicy) -> Self {
        InterruptPolicy {
            default,
            overrides: BTreeMap::new(),
        }
    }

    pub fn get_policy(&self, vector: u8) -> &VectorPolicy {
        self.overrides.get(&vector).unwrap_or(&self.default)
    }

    pub fn set_policy(&mut self, vector: u8, policy: VectorPolicy) {
        self.overrides.insert(vector, policy);
    }
}

/// Virtual processor state (platform-specific)
#[derive(Debug, Clone)]
pub struct VProcessorState {
    pub id: u64,
    /// General-purpose registers
    pub registers: BTreeMap<alloc::string::String, u64>,
    /// Platform-specific state
    pub platform_data: Vec<u8>,
}

impl VProcessorState {
    pub fn new(id: u64) -> Self {
        VProcessorState {
            id,
            registers: BTreeMap::new(),
            platform_data: Vec::new(),
        }
    }
}

/// Domain policies
#[derive(Debug, Clone)]
pub struct DomainPolicy {
    /// Bitmap of allowed physical cores (bit i = core i)
    pub cores: u64,

    /// Allowed monitor API calls
    pub api: MonitorAPI,

    /// Interrupt routing policy
    pub interrupts: InterruptPolicy,

    /// Whether domain can receive new capabilities after sealing
    pub receive_after_seal: bool,

    /// List of valid virtual processor states
    pub vprocessor_states: Vec<VProcessorState>,
}

impl DomainPolicy {
    /// Create a default policy with all permissions
    pub fn new_root() -> Self {
        DomainPolicy {
            cores: u64::MAX, // All cores
            api: MonitorAPI::ALL,
            interrupts: InterruptPolicy::new_default(VectorPolicy::default_deliver()),
            receive_after_seal: true,
            vprocessor_states: Vec::new(),
        }
    }

    /// Create a restricted policy
    pub fn new_restricted(cores: u64, api: MonitorAPI) -> Self {
        DomainPolicy {
            cores,
            api,
            interrupts: InterruptPolicy::new_default(VectorPolicy::default_report()),
            receive_after_seal: false,
            vprocessor_states: Vec::new(),
        }
    }

    /// Check if this policy is a subset of another (for monotonicity)
    pub fn is_subset_of(&self, parent: &DomainPolicy) -> Result<()> {
        // Cores must be subset
        if (self.cores & !parent.cores) != 0 {
            return Err(CapaError::MonotonicityViolation);
        }

        // API must be subset
        if !self.api.is_subset_of(&parent.api) {
            return Err(CapaError::MonotonicityViolation);
        }

        Ok(())
    }

    /// Add a virtual processor state
    pub fn add_vprocessor_state(&mut self, state: VProcessorState) {
        self.vprocessor_states.push(state);
    }
}

/// Domain capability data
#[derive(Debug)]
pub struct Domain {
    /// Unique domain identifier
    pub id: u64,

    /// Domain status
    pub status: DomainStatus,

    /// Domain policies
    pub policy: DomainPolicy,
}

impl Domain {
    /// Create a new unsealed domain
    pub fn new(policy: DomainPolicy) -> Self {
        Domain {
            id: generate_domain_id(),
            status: DomainStatus::Unsealed,
            policy,
        }
    }

    /// Create the root domain
    pub fn new_root() -> Self {
        Domain {
            id: 0,
            status: DomainStatus::Sealed,
            policy: DomainPolicy::new_root(),
        }
    }

    /// Seal the domain
    pub fn seal(&mut self) -> Result<()> {
        if self.status != DomainStatus::Unsealed {
            return Err(CapaError::DomainSealed);
        }
        self.status = DomainStatus::Sealed;
        Ok(())
    }

    /// Check if domain is sealed
    pub fn is_sealed(&self) -> bool {
        matches!(self.status, DomainStatus::Sealed)
    }

    /// Check if domain is revoked
    pub fn is_revoked(&self) -> bool {
        matches!(self.status, DomainStatus::Revoked)
    }

    /// Revoke the domain
    pub fn revoke(&mut self) {
        self.status = DomainStatus::Revoked;
    }
}

