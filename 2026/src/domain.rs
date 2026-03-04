//! Domain capabilities and policies

use crate::capability::{CapabilityWeak, LocalHandle};
use crate::error::{CapaError, Result};
use crate::memory::MemoryRegion;
use crate::sync::RwLock;
use crate::update::CoreId;
use crate::view::AddressSpaceView;
// CapabilityRef and compute_view_from_cap_arcs are only used in refresh_view,
// which is compiled out under loom to avoid O(N) lock acquisitions.
#[cfg(not(feature = "loom"))]
use crate::capability::CapabilityRef;
#[cfg(not(feature = "loom"))]
use crate::view::compute_view_from_cap_arcs;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Global domain ID counter
static NEXT_DOMAIN_ID: AtomicUsize = AtomicUsize::new(1);

/// Generate a unique domain ID
pub fn generate_domain_id() -> u64 {
    NEXT_DOMAIN_ID.fetch_add(1, Ordering::SeqCst) as u64
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
    pub const RECEIVE_AFTER_SEAL: u16 = 1 << 12;

    /// All operations allowed (including receive_after_seal)
    pub const ALL: Self = MonitorAPI { bits: 0x1FFF };

    /// No operations allowed
    pub const NONE: Self = MonitorAPI { bits: 0 };

    /// Permissions granted to a channel capability: attest, getchan, send.
    pub const CHAN_ALLOWED: Self = MonitorAPI {
        bits: Self::ATTEST | Self::GETCHAN | Self::SEND,
    };

    /// Create from raw bits
    pub const fn from_bits(bits: u16) -> Self {
        MonitorAPI {
            bits: bits & 0x1FFF,
        }
    }

    /// Get raw bits
    pub const fn bits(&self) -> u16 {
        self.bits
    }

    /// Check if an operation is allowed
    pub const fn has(&self, flag: u16) -> bool {
        (self.bits & flag) != 0
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
    pub const fn receive_after_seal(&self) -> bool {
        self.has(Self::RECEIVE_AFTER_SEAL)
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

/// Call-chain context saved when a VP does a switch call.
#[derive(Debug, Clone)]
pub struct VpCallContext {
    /// Weak reference to the calling domain's capability (no ownership cycle)
    pub domain: CapabilityWeak<crate::domain::Domain>,
    /// Domain ID of the caller
    pub domain_id: u64,
    /// VP id of the caller
    pub vp_id: u64,
}

/// Scheduling state of a virtual processor.
#[derive(Debug, Clone)]
pub enum VpRunState {
    /// VP is available and not executing anywhere.
    Available,
    /// VP is currently executing on the given core.
    Running {
        core: CoreId,
        /// The VP context that switched to us (None = no call-chain predecessor).
        caller: Option<VpCallContext>,
    },
    /// VP is locked because it called switch; waiting for the callee to return.
    Locked {
        callee_domain_id: u64,
        callee_vp_id: u64,
        /// This VP's own caller context (restored when the callee returns).
        prev_caller: Option<VpCallContext>,
    },
    /// VP was preempted by an interrupt while Locked on a callee.
    ///
    /// The callee VP is now `Interrupted` (or also `Suspended` for deeper chains).
    /// This VP is claimable by a forward `switch` (same as `Available`).
    /// When claimed, its direct callee is freed to `Available` if it is `Interrupted`.
    Suspended {
        /// Weak reference to the callee domain's capability.
        callee_domain: CapabilityWeak<Domain>,
        /// Domain ID of the callee.
        callee_domain_id: u64,
        /// VP ID of the callee within its domain.
        callee_vp_id: u64,
        /// The interrupt vector that caused the callee chain to be suspended.
        vector: u8,
    },
    /// VP was Running when an interrupt fired and preempted it.
    ///
    /// Cannot be claimed by normal `switch` (forward or return).
    /// Freed to `Available` when its `Suspended` parent is claimed via `switch`.
    Interrupted {
        /// The interrupt vector that caused this VP to be preempted.
        vector: u8,
    },
}

/// Synthetic interrupt vector representing the "VP is available / not interrupted" state.
///
/// When a VP is `Available`, `Running`, or `Locked`, register access policies are
/// looked up under this sentinel vector in the domain's `InterruptPolicy.overrides`.
/// Using a uniform lookup means there is no special-casing: a parent configures
/// register visibility for the normal state the same way it does for a real vector.
pub const VECTOR_AVAILABLE: u8 = 0xFF;

/// Return the effective interrupt vector to use for register-access policy lookups.
///
/// - `Available / Running / Locked`  → [`VECTOR_AVAILABLE`] (0xFF)
/// - `Interrupted { vector }`        → `vector`
/// - `Suspended   { vector, .. }`    → `vector` (callee's interrupt vector)
pub fn effective_vector(run_state: &VpRunState) -> u8 {
    match run_state {
        VpRunState::Available | VpRunState::Running { .. } | VpRunState::Locked { .. } => {
            VECTOR_AVAILABLE
        }
        VpRunState::Interrupted { vector } | VpRunState::Suspended { vector, .. } => *vector,
    }
}

/// Identifier for a domain-wide policy field, used by `set_policy` / `get_policy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyIdentifier {
    /// Bitmask of allowed physical cores (bit i = core i).
    Cores,
    /// Allowed monitor API calls; value is the raw `MonitorAPI` bits (u16 in a u64).
    ApiMonitor,
    /// Default interrupt-visibility for all vectors not explicitly overridden.
    /// Value: 0 = Deliver, 1 = Report, 2 = NotReport.
    DefaultInterruptVisibility,
    /// Per-vector interrupt visibility override.
    /// Value: 0 = Deliver, 1 = Report, 2 = NotReport.
    /// Use vector = [`VECTOR_AVAILABLE`] (0xFF) for the "VP available" synthetic entry.
    VectorVisibility(u8),
    /// Per-vector register read-access bitmap.
    /// Bit `i` set means the parent may read register `i` when the VP is in this
    /// interrupt state.
    VectorRegReadSet(u8),
    /// Per-vector register write-access bitmap.
    VectorRegWriteSet(u8),
}

/// Virtual processor state (platform-specific)
pub struct VProcessorState {
    pub id: u64,
    /// Platform-specific state (e.g. saved register file; managed by the platform)
    pub platform_data: Vec<u8>,
    /// Scheduling / call-chain state
    pub run_state: RwLock<VpRunState>,
}

impl core::fmt::Debug for VProcessorState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VProcessorState")
            .field("id", &self.id)
            .field("platform_data_len", &self.platform_data.len())
            .finish()
    }
}

impl VProcessorState {
    pub fn new(id: u64) -> Self {
        VProcessorState {
            id,
            platform_data: Vec::new(),
            run_state: RwLock::new(VpRunState::Available),
        }
    }
}

/// Reference-counted virtual processor handle.
pub type VProcessorRef = Arc<VProcessorState>;

/// Domain policies
#[derive(Debug, Clone)]
pub struct DomainPolicy {
    /// Bitmap of allowed physical cores (bit i = core i)
    pub cores: u64,

    /// Allowed monitor API calls (includes receive_after_seal flag)
    pub api: MonitorAPI,

    /// Interrupt routing policy
    pub interrupts: InterruptPolicy,

    /// List of valid virtual processor states
    pub vprocessor_states: Vec<VProcessorRef>,

    /// Number of virtual processors allocated for this domain.
    /// VPs are created at domain construction time (not at seal time).
    pub num_vprocessors: usize,
}

impl DomainPolicy {
    /// Create a default policy with all permissions.
    ///
    /// `num_vprocessors` defaults to `num_cores`.
    pub fn new_root(num_cores: usize) -> Self {
        let cores = if num_cores >= 64 {
            u64::MAX
        } else {
            (1u64 << num_cores) - 1
        };

        DomainPolicy {
            cores,
            api: MonitorAPI::ALL,
            interrupts: InterruptPolicy::new_default(VectorPolicy::default_deliver()),
            vprocessor_states: Vec::new(),
            num_vprocessors: num_cores,
        }
    }

    /// Create a restricted policy.
    ///
    /// `num_vprocessors` defaults to the popcount of the `cores` bitmask.
    pub fn new_restricted(cores: u64, api: MonitorAPI) -> Self {
        DomainPolicy {
            cores,
            api,
            interrupts: InterruptPolicy::new_default(VectorPolicy::default_report()),
            vprocessor_states: Vec::new(),
            num_vprocessors: cores.count_ones() as usize,
        }
    }

    /// Override the number of virtual processors created at seal time.
    pub fn with_vp_count(mut self, n: usize) -> Self {
        self.num_vprocessors = n;
        self
    }

    /// Check if domain can receive capabilities after sealing
    pub fn receive_after_seal(&self) -> bool {
        self.api.receive_after_seal()
    }

    /// Check if this policy is a subset of another (for monotonicity)
    pub fn is_subset_of(&self, parent: &DomainPolicy) -> Result<()> {
        if (self.cores & !parent.cores) != 0 {
            return Err(CapaError::MonotonicityViolation);
        }

        if !self.api.is_subset_of(&parent.api) {
            return Err(CapaError::MonotonicityViolation);
        }

        Ok(())
    }

    /// Add a virtual processor reference (for manual setup in tests)
    pub fn add_vprocessor_state(&mut self, state: VProcessorRef) {
        self.vprocessor_states.push(state);
    }
}

/// A memory capability that has been sent but not yet accepted by the receiver.
/// Domain capabilities are not sendable.
#[derive(Debug)]
pub struct PendingCapability {
    pub cap: CapabilityWeak<MemoryRegion>,
    /// Sender's domain ID (for UpdateBatch generation at accept time)
    pub sender_domain_id: crate::update::DomainId,
    /// Sender's LocalHandle for this cap (to unfreeze on reject, or remove on accept)
    pub sender_handle: LocalHandle,
    /// Weak ref to sender's domain (to unfreeze on reject)
    pub sender_domain: CapabilityWeak<Domain>,
}

/// Pending channel capability in transit (sent but not yet accepted by the receiver).
#[derive(Debug)]
pub struct PendingDomainCapability {
    /// The channel cap being transferred (weak; the strong ref lives in the CDT tree).
    pub cap: CapabilityWeak<Domain>,
    /// Sender's domain ID.
    pub sender_domain_id: crate::update::DomainId,
    /// Handle in the sender's domain_capabilities table (frozen during transit).
    pub sender_handle: LocalHandle,
    /// Weak ref to sender's domain (to unfreeze on reject).
    pub sender_domain: CapabilityWeak<Domain>,
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

    /// Pending memory capabilities that have been sent but not yet accepted (sealed domains only)
    pub pending_capabilities: BTreeMap<u64, PendingCapability>,

    /// Pending channel capabilities in transit (sent but not yet accepted).
    pub pending_domain_capabilities: BTreeMap<u64, PendingDomainCapability>,

    /// Handles that have been frozen (sent but not yet accepted/rejected)
    pub frozen_handles: BTreeSet<LocalHandle>,

    /// Cached address-space view (kept up-to-date by all capability mutations)
    pub cached_view: AddressSpaceView,

    /// Per-domain HPA↔GPA translation bookkeeping.
    #[cfg(feature = "address_translation")]
    pub address_map: crate::translation::AddressMap,

    /// Next pending capability ID
    next_pending_id: u64,
}

impl Domain {
    /// Create a new unsealed domain. VPs are allocated immediately.
    pub fn new(policy: DomainPolicy) -> Self {
        let id = generate_domain_id();
        let mut d = Domain {
            id,
            status: DomainStatus::Unsealed,
            policy,
            memory_capabilities: BTreeMap::new(),
            domain_capabilities: BTreeMap::new(),
            pending_capabilities: BTreeMap::new(),
            pending_domain_capabilities: BTreeMap::new(),
            frozen_handles: BTreeSet::new(),
            cached_view: AddressSpaceView::new(id),
            #[cfg(feature = "address_translation")]
            address_map: crate::translation::AddressMap::new(),
            next_pending_id: 0,
        };
        d.create_vprocessors();
        d
    }

    /// Create the root domain (born Sealed with VPs already allocated)
    pub fn new_root(num_cores: usize) -> Self {
        let mut d = Domain {
            id: 0,
            status: DomainStatus::Sealed,
            policy: DomainPolicy::new_root(num_cores),
            memory_capabilities: BTreeMap::new(),
            domain_capabilities: BTreeMap::new(),
            pending_capabilities: BTreeMap::new(),
            pending_domain_capabilities: BTreeMap::new(),
            frozen_handles: BTreeSet::new(),
            cached_view: AddressSpaceView::new(0),
            #[cfg(feature = "address_translation")]
            address_map: crate::translation::AddressMap::new(),
            next_pending_id: 0,
        };
        d.create_vprocessors();
        d
    }

    /// Create a sentinel Domain used as a placeholder inside channel capabilities.
    ///
    /// A sentinel must **never** be operated on directly; all operations on a
    /// channel capability are forwarded to the `channel_target` instead.
    /// `id` is set to `u64::MAX` to make accidental use obvious.
    pub fn new_sentinel() -> Self {
        Domain {
            id: u64::MAX,
            status: DomainStatus::Unsealed,
            policy: DomainPolicy::new_restricted(0, MonitorAPI::NONE),
            memory_capabilities: BTreeMap::new(),
            domain_capabilities: BTreeMap::new(),
            pending_capabilities: BTreeMap::new(),
            pending_domain_capabilities: BTreeMap::new(),
            frozen_handles: BTreeSet::new(),
            cached_view: AddressSpaceView::new(u64::MAX),
            #[cfg(feature = "address_translation")]
            address_map: crate::translation::AddressMap::new(),
            next_pending_id: 0,
        }
    }

    /// Seal the domain. VPs are already allocated at creation time.
    pub fn seal(&mut self) -> Result<()> {
        if self.status != DomainStatus::Unsealed {
            return Err(CapaError::DomainSealed);
        }
        self.status = DomainStatus::Sealed;
        Ok(())
    }

    /// Allocate VP Arc objects according to `policy.num_vprocessors`.
    fn create_vprocessors(&mut self) {
        for id in 0..self.policy.num_vprocessors as u64 {
            self.policy
                .vprocessor_states
                .push(Arc::new(VProcessorState::new(id)));
        }
    }

    /// Find the VP currently executing on the given core, if any.
    pub fn find_vp_on_core(&self, core_id: CoreId) -> Option<VProcessorRef> {
        self.policy.vprocessor_states.iter()
            .find(|vp| matches!(*vp.run_state.read(), VpRunState::Running { core, .. } if core == core_id))
            .cloned()
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
    pub fn add_memory_capability(
        &mut self,
        handle: LocalHandle,
        capa: CapabilityWeak<MemoryRegion>,
    ) {
        self.memory_capabilities.insert(handle, capa);
        self.refresh_view();
    }

    /// Register a domain capability owned by this domain
    pub fn add_domain_capability(&mut self, handle: LocalHandle, capa: CapabilityWeak<Domain>) {
        self.domain_capabilities.insert(handle, capa);
    }

    /// Remove a memory capability from tracking
    pub fn remove_memory_capability(
        &mut self,
        handle: LocalHandle,
    ) -> Option<CapabilityWeak<MemoryRegion>> {
        let result = self.memory_capabilities.remove(&handle);
        self.refresh_view();
        result
    }

    /// Remove a domain capability from tracking
    pub fn remove_domain_capability(
        &mut self,
        handle: LocalHandle,
    ) -> Option<CapabilityWeak<Domain>> {
        self.domain_capabilities.remove(&handle)
    }

    /// Get a memory capability by handle
    pub fn get_memory_capability(
        &self,
        handle: LocalHandle,
    ) -> Option<&CapabilityWeak<MemoryRegion>> {
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

    /// Allocate the next available handle for a memory capability
    pub fn allocate_memory_handle(&self) -> LocalHandle {
        let mut handle: LocalHandle = 1;
        while self.memory_capabilities.contains_key(&handle)
            || self.frozen_handles.contains(&handle)
        {
            handle += 1;
        }
        handle
    }

    /// Allocate the next available handle for a domain capability
    pub fn allocate_domain_handle(&self) -> LocalHandle {
        let mut handle: LocalHandle = 1;
        while self.domain_capabilities.contains_key(&handle) {
            handle += 1;
        }
        handle
    }

    /// Freeze a memory handle (mark as sent but not yet accepted)
    pub fn freeze_memory_handle(&mut self, handle: LocalHandle) {
        self.frozen_handles.insert(handle);
    }

    /// Unfreeze a memory handle
    pub fn unfreeze_memory_handle(&mut self, handle: LocalHandle) -> bool {
        self.frozen_handles.remove(&handle)
    }

    /// Check if a memory handle is frozen
    pub fn is_memory_handle_frozen(&self, handle: LocalHandle) -> bool {
        self.frozen_handles.contains(&handle)
    }

    /// Recompute the cached address-space view from the current memory_capabilities table.
    fn refresh_view(&mut self) {
        // Under loom, skip the O(N) lock-acquisition walk — view correctness is
        // covered by integration tests; loom only checks concurrency invariants.
        #[cfg(not(feature = "loom"))]
        {
            let cap_arcs: alloc::vec::Vec<CapabilityRef<MemoryRegion>> = self
                .memory_capabilities
                .values()
                .filter_map(|w| w.upgrade())
                .collect();
            self.cached_view = compute_view_from_cap_arcs(self.id, &cap_arcs);
        }
    }

    /// Add a capability to the pending queue (for sealed domains with RECEIVE_AFTER_SEAL)
    /// Returns the pending ID
    pub fn add_pending_capability(&mut self, capability: PendingCapability) -> u64 {
        let pending_id = self.next_pending_id;
        self.next_pending_id += 1;
        self.pending_capabilities.insert(pending_id, capability);
        pending_id
    }

    /// Get all pending capability IDs
    pub fn get_pending_ids(&self) -> Vec<u64> {
        self.pending_capabilities.keys().copied().collect()
    }

    // ── Channel (domain) pending helpers ────────────────────────────────────

    /// Freeze a domain handle (channel in transit; analogous to freeze_memory_handle).
    pub fn freeze_domain_handle(&mut self, handle: LocalHandle) {
        self.frozen_handles.insert(handle);
    }

    /// Unfreeze a domain handle.
    pub fn unfreeze_domain_handle(&mut self, handle: LocalHandle) -> bool {
        self.frozen_handles.remove(&handle)
    }

    /// Check if a domain handle is frozen.
    pub fn is_domain_handle_frozen(&self, handle: LocalHandle) -> bool {
        self.frozen_handles.contains(&handle)
    }

    /// Enqueue a pending domain (channel) capability. Returns the pending ID.
    pub fn add_pending_domain_capability(&mut self, cap: PendingDomainCapability) -> u64 {
        let pending_id = self.next_pending_id;
        self.next_pending_id += 1;
        self.pending_domain_capabilities.insert(pending_id, cap);
        pending_id
    }

    /// Get all pending domain capability IDs.
    pub fn get_pending_domain_ids(&self) -> Vec<u64> {
        self.pending_domain_capabilities.keys().copied().collect()
    }
}
