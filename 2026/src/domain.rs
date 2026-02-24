//! Domain capabilities and policies

use crate::error::{CapaError, Result};
use crate::capability::{CapabilityWeak, LocalHandle};
use crate::memory::MemoryRegion;
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
/// Implemented as a bitmap for compact representation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorAPI {
    bits: u16,
}

impl MonitorAPI {
    pub const CREATE: u16 = 1 << 0;
    pub const SET: u16 = 1 << 1;
    pub const GET: u16 = 1 << 2;
    pub const SEND: u16 = 1 << 3;
    pub const SEAL: u16 = 1 << 4;
    pub const ATTEST: u16 = 1 << 5;
    pub const ENUMERATE: u16 = 1 << 6;
    pub const SWITCH: u16 = 1 << 7;
    pub const ALIAS: u16 = 1 << 8;
    pub const CARVE: u16 = 1 << 9;
    pub const REVOKE: u16 = 1 << 10;
    pub const GETCHAN: u16 = 1 << 11;

    /// All operations allowed
    pub const ALL: Self = MonitorAPI { bits: 0xFFF };

    /// No operations allowed
    pub const NONE: Self = MonitorAPI { bits: 0 };

    /// Create from raw bits
    pub const fn from_bits(bits: u16) -> Self {
        MonitorAPI { bits: bits & 0xFFF }
    }

    /// Get raw bits
    pub const fn bits(&self) -> u16 {
        self.bits
    }

    /// Check if an operation is allowed
    pub const fn has(&self, flag: u16) -> bool {
        (self.bits & flag) != 0
    }

    /// Add an operation permission
    pub fn set(&mut self, flag: u16) {
        self.bits |= flag & 0xFFF;
    }

    /// Remove an operation permission
    pub fn clear(&mut self, flag: u16) {
        self.bits &= !(flag & 0xFFF);
    }

    /// Check if self is a subset of other (for monotonicity)
    pub fn is_subset_of(&self, other: &MonitorAPI) -> bool {
        (self.bits & !other.bits) == 0
    }

    // Convenience getters for compatibility
    pub const fn create(&self) -> bool {
        self.has(Self::CREATE)
    }
    pub const fn set_perm(&self) -> bool {
        self.has(Self::SET)
    }
    pub const fn get(&self) -> bool {
        self.has(Self::GET)
    }
    pub const fn send(&self) -> bool {
        self.has(Self::SEND)
    }
    pub const fn seal(&self) -> bool {
        self.has(Self::SEAL)
    }
    pub const fn attest(&self) -> bool {
        self.has(Self::ATTEST)
    }
    pub const fn enumerate(&self) -> bool {
        self.has(Self::ENUMERATE)
    }
    pub const fn switch(&self) -> bool {
        self.has(Self::SWITCH)
    }
    pub const fn alias(&self) -> bool {
        self.has(Self::ALIAS)
    }
    pub const fn carve(&self) -> bool {
        self.has(Self::CARVE)
    }
    pub const fn revoke(&self) -> bool {
        self.has(Self::REVOKE)
    }
    pub const fn getchan(&self) -> bool {
        self.has(Self::GETCHAN)
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

    /// Memory capabilities owned by this domain (handle -> weak ref)
    pub memory_capabilities: BTreeMap<LocalHandle, CapabilityWeak<MemoryRegion>>,

    /// Domain capabilities owned by this domain (handle -> weak ref)
    pub domain_capabilities: BTreeMap<LocalHandle, CapabilityWeak<Domain>>,
}

impl Domain {
    /// Create a new unsealed domain
    pub fn new(policy: DomainPolicy) -> Self {
        Domain {
            id: generate_domain_id(),
            status: DomainStatus::Unsealed,
            policy,
            memory_capabilities: BTreeMap::new(),
            domain_capabilities: BTreeMap::new(),
        }
    }

    /// Create the root domain
    pub fn new_root() -> Self {
        Domain {
            id: 0,
            status: DomainStatus::Sealed,
            policy: DomainPolicy::new_root(),
            memory_capabilities: BTreeMap::new(),
            domain_capabilities: BTreeMap::new(),
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

    /// Register a memory capability owned by this domain
    pub fn add_memory_capability(&mut self, handle: LocalHandle, capa: CapabilityWeak<MemoryRegion>) {
        self.memory_capabilities.insert(handle, capa);
    }

    /// Register a domain capability owned by this domain
    pub fn add_domain_capability(&mut self, handle: LocalHandle, capa: CapabilityWeak<Domain>) {
        self.domain_capabilities.insert(handle, capa);
    }

    /// Remove a memory capability from tracking
    pub fn remove_memory_capability(&mut self, handle: LocalHandle) -> Option<CapabilityWeak<MemoryRegion>> {
        self.memory_capabilities.remove(&handle)
    }

    /// Remove a domain capability from tracking
    pub fn remove_domain_capability(&mut self, handle: LocalHandle) -> Option<CapabilityWeak<Domain>> {
        self.domain_capabilities.remove(&handle)
    }

    /// Get a memory capability by handle
    pub fn get_memory_capability(&self, handle: LocalHandle) -> Option<&CapabilityWeak<MemoryRegion>> {
        self.memory_capabilities.get(&handle)
    }

    /// Get a domain capability by handle
    pub fn get_domain_capability(&self, handle: LocalHandle) -> Option<&CapabilityWeak<Domain>> {
        self.domain_capabilities.get(&handle)
    }

    /// Get all memory capability handles
    pub fn memory_capability_handles(&self) -> alloc::vec::Vec<LocalHandle> {
        self.memory_capabilities.keys().copied().collect()
    }

    /// Get all domain capability handles
    pub fn domain_capability_handles(&self) -> alloc::vec::Vec<LocalHandle> {
        self.domain_capabilities.keys().copied().collect()
    }
}

