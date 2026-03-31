//! Backend trait — abstracts the capability engine for swappable implementations.
//!
//! The CLI holds only `name → DomainId` and `name → MemCapUid` mappings.
//! The backend owns all internal state and resolves handles internally.

use std::fmt;

// ─── Opaque identifiers (no Arc/RwLock) ───

pub type DomainId = u64;
pub type MemCapUid = u64;

// ─── Error type ───

#[derive(Debug, Clone)]
pub enum BackendError {
    DomainRevoked,
    InvalidAccess,
    PermissionDenied,
    NotFound,
    DomainSealed,
    DomainNotSealed,
    ParentRevoked,
    CannotAliasCarved,
    RegionOverlap,
    InvalidRemapping,
    AlreadyExists,
    MonotonicityViolation,
    ApiNotAllowed,
    TreeLocked,
    InvalidOperation(String),
    NotSupported,
    RegisterOutOfRange,
    RegisterAccessDenied,
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendError::DomainRevoked => write!(f, "Domain revoked"),
            BackendError::InvalidAccess => write!(f, "Invalid access"),
            BackendError::PermissionDenied => write!(f, "Permission denied"),
            BackendError::NotFound => write!(f, "Not found"),
            BackendError::DomainSealed => write!(f, "Domain is sealed"),
            BackendError::DomainNotSealed => write!(f, "Domain is not sealed"),
            BackendError::ParentRevoked => write!(f, "Parent revoked"),
            BackendError::CannotAliasCarved => write!(f, "Cannot alias carved region"),
            BackendError::RegionOverlap => write!(f, "Region overlap"),
            BackendError::InvalidRemapping => write!(f, "Invalid remapping"),
            BackendError::AlreadyExists => write!(f, "Already exists"),
            BackendError::MonotonicityViolation => write!(f, "Monotonicity violation"),
            BackendError::ApiNotAllowed => write!(f, "API not allowed"),
            BackendError::TreeLocked => write!(f, "Tree locked"),
            BackendError::InvalidOperation(s) => write!(f, "Invalid operation: {}", s),
            BackendError::NotSupported => write!(f, "Not supported"),
            BackendError::RegisterOutOfRange => write!(f, "Register out of range"),
            BackendError::RegisterAccessDenied => write!(f, "Register access denied"),
        }
    }
}

pub type Result<T> = std::result::Result<T, BackendError>;

// ─── DTO structs ───

#[derive(Debug, Clone)]
pub struct InitResult {
    pub domain_id: DomainId,
    pub mem_uid: MemCapUid,
}

#[derive(Debug, Clone)]
pub struct DomainInfoDto {
    pub id: DomainId,
    pub status: String,
    pub is_channel: bool,
    pub channel_target: Option<DomainId>,
    pub cores_bitmap: u64,
    pub api_flags: String,
    pub num_vps: usize,
    pub vp_states: Vec<VpStateDto>,
}

#[derive(Debug, Clone)]
pub struct VpStateDto {
    pub vp_id: u64,
    pub state: String,
}

#[derive(Debug, Clone)]
pub struct MemCapInfoDto {
    pub uid: MemCapUid,
    pub local_handle: u64,
    pub start: u64,
    pub end: u64,
    pub rights: String,
    pub kind: String,
    pub status: String,
    pub attributes: String,
    pub owner_id: DomainId,
    pub num_children: usize,
    pub children: Vec<MemCapInfoDto>,
}

#[derive(Debug, Clone)]
pub struct DomCapInfoDto {
    pub local_handle: u64,
    pub domain_id: DomainId,
    pub is_channel: bool,
}

#[derive(Debug, Clone)]
pub struct PendingCapDto {
    pub pending_id: u64,
    pub is_domain: bool,
    pub sender_id: DomainId,
    pub start: u64,
    pub end: u64,
    pub rights: String,
}

#[derive(Debug, Clone)]
pub struct CoreStateDto {
    pub core_id: u64,
    pub state: String,
    pub domain_id: Option<DomainId>,
    pub vp_id: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct SwitchContextDto {
    pub from_domain: DomainId,
    pub to_domain: DomainId,
    pub core_id: u64,
    pub from_vp: Option<u64>,
    pub to_vp: Option<u64>,
    pub is_return: bool,
    pub interrupt_return: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct AddressRegionDto {
    pub gpa: u64,
    pub size: u64,
    pub rights: String,
    pub hpa: u64,
    pub is_identity_mapped: bool,
}

#[derive(Debug, Clone)]
pub struct HwUpdate {
    pub kind: HwUpdateKind,
    pub domain_id: DomainId,
    pub gpa: u64,
    pub size: u64,
    pub hpa: u64,
    pub rights: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HwUpdateKind {
    MapMemory,
    UnmapMemory,
    ZeroMemory,
    CreateDomain,
    RevokeDomain,
    FlushTlb,
    CommRegion,
    UncommRegion,
    GiveMetaMem,
}

impl fmt::Display for HwUpdateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HwUpdateKind::MapMemory => write!(f, "MapMemory"),
            HwUpdateKind::UnmapMemory => write!(f, "UnmapMemory"),
            HwUpdateKind::ZeroMemory => write!(f, "ZeroMemory"),
            HwUpdateKind::CreateDomain => write!(f, "CreateDomain"),
            HwUpdateKind::RevokeDomain => write!(f, "RevokeDomain"),
            HwUpdateKind::FlushTlb => write!(f, "FlushTLB"),
            HwUpdateKind::CommRegion => write!(f, "CommRegion"),
            HwUpdateKind::UncommRegion => write!(f, "UncommRegion"),
            HwUpdateKind::GiveMetaMem => write!(f, "GiveMetaMem"),
        }
    }
}

// ─── Backend trait ───

pub trait Backend {
    // === Lifecycle ===

    /// Initialize root domain + root memory region of given size.
    /// Returns (root_domain_id, root_mem_uid).
    fn init(&mut self, size: u64) -> Result<InitResult>;

    /// Reset all state, reinitialize with given number of cores.
    fn reset(&mut self, num_cores: usize);

    // === Memory Operations ===

    /// Carve exclusive sub-region from parent memory.
    fn carve(
        &mut self,
        owner: DomainId,
        parent: MemCapUid,
        start: u64,
        size: u64,
        rights: u8,
    ) -> Result<(MemCapUid, Vec<HwUpdate>)>;

    /// Alias (shared) sub-region from parent memory.
    fn alias(
        &mut self,
        owner: DomainId,
        parent: MemCapUid,
        start: u64,
        size: u64,
        rights: u8,
    ) -> Result<(MemCapUid, Vec<HwUpdate>)>;

    /// Send memory capability to receiver domain.
    /// Backend resolves sender domain from mem ownership + receiver handle.
    fn send(
        &mut self,
        mem: MemCapUid,
        receiver: DomainId,
        attrs: u8,
        gpa: Option<u64>,
    ) -> Result<Vec<HwUpdate>>;

    /// Accept a pending memory capability.
    fn accept(
        &mut self,
        domain: DomainId,
        pending_id: u64,
        gpa: Option<u64>,
    ) -> Result<(MemCapUid, Vec<HwUpdate>)>;

    /// Reject a pending memory capability.
    fn reject(&mut self, domain: DomainId, pending_id: u64) -> Result<()>;

    /// Revoke a child memory capability (identified by parent + child UIDs).
    fn revoke_mem(
        &mut self,
        owner: DomainId,
        parent: MemCapUid,
        child: MemCapUid,
    ) -> Result<Vec<HwUpdate>>;

    // === Domain Operations ===

    /// Create child domain with given core mask and API flags.
    fn create_domain(
        &mut self,
        parent: DomainId,
        cores: u64,
        api: u64,
    ) -> Result<(DomainId, Vec<HwUpdate>)>;

    /// Seal a child domain (parent must own it).
    fn seal(&mut self, owner: DomainId, child: DomainId) -> Result<()>;

    /// Revoke a child domain.
    fn revoke_domain(
        &mut self,
        parent: DomainId,
        child: DomainId,
    ) -> Result<Vec<HwUpdate>>;

    // === Channel Operations ===

    /// Create a channel capability from caller to target.
    fn get_chan(&mut self, caller: DomainId, target: DomainId) -> Result<DomainId>;

    /// Send a channel capability to a receiver.
    fn send_channel(
        &mut self,
        caller: DomainId,
        chan: DomainId,
        receiver: DomainId,
    ) -> Result<()>;

    /// Accept a pending channel capability.
    fn accept_channel(
        &mut self,
        receiver: DomainId,
        pending_id: u64,
    ) -> Result<DomainId>;

    /// Reject a pending channel capability.
    fn reject_channel(&mut self, receiver: DomainId, pending_id: u64) -> Result<()>;

    // === VP & Switch ===

    /// Add a VP to child domain with COMM page.
    fn add_vp(
        &mut self,
        parent: DomainId,
        child: DomainId,
        comm: MemCapUid,
        vp_id: u32,
    ) -> Result<Vec<HwUpdate>>;

    /// Register COMM page binding.
    fn register_comm(
        &mut self,
        owner: DomainId,
        mem: MemCapUid,
        child: DomainId,
        vp_id: u32,
    ) -> Result<Vec<HwUpdate>>;

    /// Forward switch: enter domain on core with VP.
    fn switch_forward(
        &mut self,
        domain: DomainId,
        core: u64,
        vp_id: u64,
    ) -> Result<SwitchContextDto>;

    /// Return switch: unwind call chain on core.
    fn switch_return(&mut self, core: u64) -> Result<SwitchContextDto>;

    /// Deliver interrupt to domain on core.
    fn deliver_interrupt(
        &mut self,
        vector: u8,
        domain: DomainId,
        core: u64,
    ) -> Result<()>;

    // === Policy & Registers ===

    fn set_policy(
        &mut self,
        parent: DomainId,
        child: DomainId,
        field: &str,
        value: u64,
    ) -> Result<()>;

    fn get_policy(
        &self,
        parent: DomainId,
        child: DomainId,
        field: &str,
    ) -> Result<u64>;

    fn set_register(
        &mut self,
        parent: DomainId,
        child: DomainId,
        vp: u64,
        reg: u64,
        value: u64,
    ) -> Result<()>;

    fn get_register(
        &self,
        parent: DomainId,
        child: DomainId,
        vp: u64,
        reg: u64,
    ) -> Result<u64>;

    fn set_interrupt_policy(
        &mut self,
        owner: DomainId,
        child: DomainId,
        vector: u8,
        visibility: u64,
    ) -> Result<()>;

    // === Queries (for display) ===

    /// List all domains with summary info (for `list` command).
    fn list_domains(&self) -> Vec<DomainInfoDto>;

    /// Get memory capabilities owned by a domain (with tree structure).
    fn get_domain_mem_caps(&self, id: DomainId) -> Vec<MemCapInfoDto>;

    /// Get domain capabilities owned by a domain.
    fn get_domain_dom_caps(&self, id: DomainId) -> Vec<DomCapInfoDto>;

    /// Get pending capabilities waiting for acceptance.
    fn get_pending_caps(&self, id: DomainId) -> Vec<PendingCapDto>;

    /// Get the effective address space (GPA regions) for a domain.
    fn get_address_space(&self, id: DomainId) -> Vec<AddressRegionDto>;

    /// Get current state of all cores.
    fn get_core_states(&self) -> Vec<CoreStateDto>;

    /// Compute attestation report for a domain.
    fn attest(&self, id: DomainId) -> Result<String>;

    /// Get number of cores.
    fn num_cores(&self) -> usize;
}
