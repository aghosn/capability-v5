//! Domain capabilities and policies

use crate::capability::{CapabilityWeak, LocalHandle};
use crate::error::{CapaError, Result};
use crate::memory::MemoryRegion;
use crate::sync::RwLock;
use crate::update::CoreId;
use crate::interposition::{CpuidPolicy, DefaultAction, MsrPolicy};
use crate::view::AddressSpaceView;
use crate::capability::CapabilityRef;
use crate::view::compute_view_from_cap_arcs;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::{Arc, Weak};
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
    #[cfg(feature = "address_translation")]
    pub const MAP_SELF: u16 = 1 << 13;

    /// All operations allowed (including receive_after_seal)
    #[cfg(not(feature = "address_translation"))]
    pub const ALL: Self = MonitorAPI { bits: 0x1FFF };
    #[cfg(feature = "address_translation")]
    pub const ALL: Self = MonitorAPI { bits: 0x3FFF };

    /// No operations allowed
    pub const NONE: Self = MonitorAPI { bits: 0 };

    /// Permissions granted to a channel capability: attest, getchan, send.
    pub const CHAN_ALLOWED: Self = MonitorAPI {
        bits: Self::ATTEST | Self::GETCHAN | Self::SEND,
    };

    /// Create from raw bits
    pub const fn from_bits(bits: u16) -> Self {
        #[cfg(not(feature = "address_translation"))]
        let mask = 0x1FFF;
        #[cfg(feature = "address_translation")]
        let mask = 0x3FFF;
        MonitorAPI {
            bits: bits & mask,
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
    #[cfg(feature = "address_translation")]
    pub const fn map_self(&self) -> bool {
        self.has(Self::MAP_SELF)
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

/// Register-access bitmap covering up to 192 register IDs (3 × 64 bits).
///
/// Each bit corresponds to a register ID: word `i` covers IDs `i*64 .. (i+1)*64`.
/// The width matches the COMM page `dirty_mask` layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegBitmap(pub [u64; 3]);

impl RegBitmap {
    /// All bits cleared — no registers accessible.
    pub const NONE: Self = RegBitmap([0; 3]);
    /// All bits set — all registers accessible.
    pub const ALL: Self = RegBitmap([u64::MAX; 3]);

    /// Test whether bit `reg_id` is set.
    #[inline]
    pub fn is_set(&self, reg_id: u64) -> bool {
        let word = (reg_id / 64) as usize;
        let bit = reg_id % 64;
        word < 3 && (self.0[word] >> bit) & 1 != 0
    }

    /// Return the raw word at `idx` (0..3).
    #[inline]
    pub fn word(&self, idx: usize) -> u64 {
        if idx < 3 { self.0[idx] } else { 0 }
    }

    /// Set the raw word at `idx` (0..3).
    #[inline]
    pub fn set_word(&mut self, idx: usize, val: u64) {
        if idx < 3 { self.0[idx] = val; }
    }
}

impl core::fmt::LowerHex for RegBitmap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Print as a single big-endian hex string: word[2]:word[1]:word[0]
        // Skip leading all-zero words for compactness.
        if self.0 == [0; 3] {
            return write!(f, "0x0");
        }
        if self.0 == [u64::MAX; 3] {
            return write!(f, "0x{:x}{:016x}{:016x}", u64::MAX, u64::MAX, u64::MAX);
        }
        let first_nonzero = (0..3).rev().find(|&i| self.0[i] != 0).unwrap_or(0);
        write!(f, "0x{:x}", self.0[first_nonzero])?;
        for i in (0..first_nonzero).rev() {
            write!(f, "{:016x}", self.0[i])?;
        }
        Ok(())
    }
}

/// Policy for a specific interrupt vector
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorPolicy {
    pub visibility: InterruptVisibility,
    /// Bitmask of registers that can be read during interrupt handling
    pub read_set: RegBitmap,
    /// Bitmask of registers that can be written during interrupt handling
    pub write_set: RegBitmap,
}

impl VectorPolicy {
    pub fn default_deliver() -> Self {
        VectorPolicy {
            visibility: InterruptVisibility::Deliver,
            read_set: RegBitmap::NONE,
            write_set: RegBitmap::NONE,
        }
    }

    pub fn default_report() -> Self {
        VectorPolicy {
            visibility: InterruptVisibility::Report,
            read_set: RegBitmap::ALL,
            write_set: RegBitmap::ALL,
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

// ── VMEXIT exit policy ──────────────────────────────────────────────────── //

/// Action for a specific VMEXIT reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitAction {
    /// true = forward to parent via COMM page, false = handle locally in capavisor
    pub trap: bool,
    /// Registers parent can read on COMM page (only meaningful when trap=true)
    pub read_set: RegBitmap,
    /// Registers parent can write back (only meaningful when trap=true)
    pub write_set: RegBitmap,
}

impl ExitAction {
    /// Default for child domains: trap to parent with full register access.
    pub fn default_trap() -> Self {
        ExitAction {
            trap: true,
            read_set: RegBitmap::ALL,
            write_set: RegBitmap::ALL,
        }
    }

    /// Default for root domain: handle locally (no parent).
    pub fn default_local() -> Self {
        ExitAction {
            trap: false,
            read_set: RegBitmap::NONE,
            write_set: RegBitmap::NONE,
        }
    }
}

/// VMEXIT routing policy: default action + per-exit-reason overrides.
#[derive(Debug, Clone)]
pub struct ExitPolicy {
    /// Default action for all exit reasons not explicitly overridden
    pub default: ExitAction,
    /// Per-exit-reason overrides (exit reason number -> action)
    pub overrides: BTreeMap<u32, ExitAction>,
}

impl ExitPolicy {
    pub fn new_default(default: ExitAction) -> Self {
        ExitPolicy {
            default,
            overrides: BTreeMap::new(),
        }
    }

    pub fn get_action(&self, exit_reason: u32) -> &ExitAction {
        self.overrides.get(&exit_reason).unwrap_or(&self.default)
    }

    pub fn set_action(&mut self, exit_reason: u32, action: ExitAction) {
        self.overrides.insert(exit_reason, action);
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
    ///
    /// `last_exit_reason`: if this VP was most recently forwarded to its parent
    /// via a non-interrupt exit, this holds the exit reason (u32) so that
    /// `register_access_check` can look up the correct `ExitPolicy` write_set.
    /// `None` for fresh VPs or interrupt-caused exits.
    Available {
        last_exit_reason: Option<u32>,
    },
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

/// Which interposition policy to operate on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    Cpuid = 0,
    Msr = 1,
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
    /// Per-vector register read-access bitmap (one word at a time).
    /// First `u8` is the vector, second is the word index (0..3).
    /// Bit `i` set means the parent may read register `word*64 + i`.
    VectorRegReadSet(u8, u8),
    /// Per-vector register write-access bitmap (one word at a time).
    /// First `u8` is the vector, second is the word index (0..3).
    VectorRegWriteSet(u8, u8),

    // ── VMEXIT exit policy identifiers ──

    /// Default exit trap policy. Value: 0 = handle locally, 1 = trap to parent.
    DefaultExitTrap,
    /// Per-exit-reason trap policy. Value: 0 = handle locally, 1 = trap to parent.
    ExitReasonTrap(u32),
    /// Per-exit-reason register read bitmap (one word at a time).
    /// `u32` is the exit reason, `u8` is the word index (0..2).
    ExitReasonRegReadSet(u32, u8),
    /// Per-exit-reason register write bitmap (one word at a time).
    /// `u32` is the exit reason, `u8` is the word index (0..2).
    ExitReasonRegWriteSet(u32, u8),

    // ── Processor feature interposition policy identifiers ──

    /// Set the default action for a resource class.
    /// Value: 0 = Trap, 1 = Native.
    ProcFeatureDefault(ResourceKind),
    /// Insert a Trap or Native range override.
    /// For CPUID: (start_leaf, start_subleaf, end_leaf, end_subleaf).
    /// For MSR:   (start_msr, 0, end_msr, 0) — subleaf ignored.
    /// Value: 0 = Trap, 1 = Native.
    ProcFeatureRange(ResourceKind, u32, u32, u32, u32),
    /// Insert/update an Emulate point entry.
    /// For CPUID: (leaf, subleaf, word_index).
    /// For MSR:   (msr, 0, word_index) — subleaf ignored.
    /// Value: packed emulated value (resource-specific encoding).
    ProcFeatureEmulate(ResourceKind, u32, u32, u8),
}
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
            run_state: RwLock::new(VpRunState::Available { last_exit_reason: None }),
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

    /// VMEXIT exit routing policy
    pub exits: ExitPolicy,

    /// CPUID interposition policy
    pub cpuid: CpuidPolicy,

    /// MSR interposition policy
    pub msrs: MsrPolicy,

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
            exits: ExitPolicy::new_default(ExitAction::default_local()),
            cpuid: CpuidPolicy::new(DefaultAction::Native),
            msrs: MsrPolicy::new(DefaultAction::Native),
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
            exits: ExitPolicy::new_default(ExitAction::default_trap()),
            cpuid: CpuidPolicy::new(DefaultAction::Trap),
            msrs: MsrPolicy::new(DefaultAction::Trap),
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
    /// Optional GPA hint for the receiver's AddressMap.
    #[cfg(feature = "address_translation")]
    pub gpa_hint: Option<u64>,
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

    /// Weak refs to parent-owned COMM capabilities bound to this domain's VPs.
    /// Populated by `register_comm` when a parent registers a COMM page targeting
    /// this child domain.  Used during child revocation to clear COMM bindings.
    pub comm_bindings: Vec<CapabilityWeak<MemoryRegion>>,

    /// Cached address-space view (recomputed lazily when `view_dirty` is set)
    pub cached_view: AddressSpaceView,

    /// Set by any mutation that affects the address-space view (add/remove
    /// memory capabilities, address-map changes).  Cleared by
    /// [`ensure_view_fresh`] which recomputes `cached_view` on demand.
    pub view_dirty: bool,

    /// Per-domain HPA↔GPA translation bookkeeping.
    #[cfg(feature = "address_translation")]
    pub address_map: crate::translation::AddressMap,

    /// Per-handle GPA base: tracks where each memory capability's
    /// footprint is currently placed in this domain's GPA space.
    /// Updated by accept_at / map_self.  Used by map_self to know
    /// where to remove_footprint from before re-adding at new GPA.
    #[cfg(feature = "address_translation")]
    pub mapped_gpas: BTreeMap<LocalHandle, u64>,

    /// Next pending capability ID
    next_pending_id: u64,
}

impl Domain {
    /// Create a new unsealed domain. VPs are allocated immediately.
    pub fn new(policy: DomainPolicy) -> Self {
        let id = generate_domain_id();
        Domain {
            id,
            status: DomainStatus::Unsealed,
            policy,
            memory_capabilities: BTreeMap::new(),
            domain_capabilities: BTreeMap::new(),
            pending_capabilities: BTreeMap::new(),
            pending_domain_capabilities: BTreeMap::new(),
            frozen_handles: BTreeSet::new(),
            comm_bindings: Vec::new(),
            cached_view: AddressSpaceView::new(id),
            view_dirty: false,
            #[cfg(feature = "address_translation")]
            address_map: crate::translation::AddressMap::new(),
            #[cfg(feature = "address_translation")]
            mapped_gpas: BTreeMap::new(),
            next_pending_id: 0,
        }
        // VPs are NOT auto-created.  They are added one at a time via
        // Capability::add_vp().  `num_vprocessors` is the max limit.
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
            comm_bindings: Vec::new(),
            cached_view: AddressSpaceView::new(0),
            view_dirty: false,
            #[cfg(feature = "address_translation")]
            address_map: crate::translation::AddressMap::new(),
            #[cfg(feature = "address_translation")]
            mapped_gpas: BTreeMap::new(),
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
            comm_bindings: Vec::new(),
            cached_view: AddressSpaceView::new(u64::MAX),
            view_dirty: false,
            #[cfg(feature = "address_translation")]
            address_map: crate::translation::AddressMap::new(),
            #[cfg(feature = "address_translation")]
            mapped_gpas: BTreeMap::new(),
            next_pending_id: 0,
        }
    }

    /// Seal the domain.  No more VPs can be added after sealing.
    pub fn seal(&mut self) -> Result<()> {
        if self.status != DomainStatus::Unsealed {
            return Err(CapaError::DomainSealed);
        }
        self.status = DomainStatus::Sealed;
        Ok(())
    }

    /// Add a virtual processor to this domain.
    ///
    /// The domain must be Unsealed and the VP count must not exceed
    /// `num_vprocessors` (the max limit set at creation time).
    /// The VP ID is auto-assigned sequentially (0, 1, 2, …).
    /// Returns the assigned VP ID.
    pub fn add_vprocessor(&mut self) -> Result<u64> {
        if self.status != DomainStatus::Unsealed {
            return Err(CapaError::DomainSealed);
        }
        if self.policy.vprocessor_states.len() >= self.policy.num_vprocessors {
            return Err(CapaError::InvalidOperation(
                "VP count exceeds num_vprocessors limit".into(),
            ));
        }
        let vp_id = self.policy.vprocessor_states.len() as u64;
        self.policy
            .vprocessor_states
            .push(Arc::new(VProcessorState::new(vp_id)));
        Ok(vp_id)
    }

    /// Allocate VP Arc objects according to `policy.num_vprocessors`.
    /// Only used for the root domain which is born with all VPs.
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

    /// Validate that this domain is sealed and has the required API permission.
    ///
    /// Use this when the **caller domain itself** needs a permission check
    /// (e.g., CREATE, SET, GET, REVOKE).  In contrast, [`OwnedCapability::validate_operation`]
    /// checks the *owner* of a child capability — appropriate for operations
    /// on resources owned by the caller.
    pub fn require_api(&self, required_api: u16) -> Result<()> {
        // A revoked caller cannot be sealed, so today this returns
        // DomainNotSealed accidentally.  Reject explicitly with the correct
        // error so callers that obtained a `CapabilityRef<Domain>` outside
        // an engine lock (e.g. capavisor's `get_core_cap` at hypercall entry)
        // and got beaten to the punch by a concurrent revocation see the
        // real reason instead of a misleading "not sealed" error.
        if self.is_revoked() {
            return Err(CapaError::DomainRevoked);
        }
        if !self.is_sealed() {
            return Err(CapaError::DomainNotSealed);
        }
        if !self.policy.api.has(required_api) {
            return Err(CapaError::ApiNotAllowed);
        }
        Ok(())
    }

    /// Check if domain is revoked
    pub fn is_revoked(&self) -> bool {
        matches!(self.status, DomainStatus::Revoked)
    }

    /// Revoke the domain
    pub fn revoke(&mut self) {
        self.status = DomainStatus::Revoked;
        #[cfg(feature = "address_translation")]
        self.address_map.clear();
        #[cfg(feature = "address_translation")]
        self.mapped_gpas.clear();
    }

    /// Register a memory capability owned by this domain
    pub fn add_memory_capability(
        &mut self,
        handle: LocalHandle,
        capa: CapabilityWeak<MemoryRegion>,
    ) {
        self.memory_capabilities.insert(handle, capa);
        self.view_dirty = true;
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
        self.view_dirty = true;
        result
    }

    /// Remove all entries from `memory_capabilities` whose `Weak` refs can no
    /// longer be upgraded (the backing `Arc` has been dropped).
    ///
    /// # Safety (logical, not `unsafe`)
    ///
    /// This is called from `Capability::<Domain>::revoke()` which runs under:
    ///   1. The **exclusive global lock** (`execute(exclusive=true)`), so no
    ///      concurrent capability operation can create or drop `Arc`s between
    ///      `revoke_child` (which drops the subtree) and this call.
    ///   2. The **per-domain write lock** (`caller.write()`), so no concurrent
    ///      reader can observe a partially-pruned table.
    ///
    /// Together these guarantee that every `Weak` that fails to upgrade here
    /// genuinely refers to a revoked capability, not to a live one that is
    /// transiently unreachable.
    pub fn prune_stale_memory_capabilities(&mut self) {
        self.memory_capabilities.retain(|_, weak| weak.upgrade().is_some());
        self.view_dirty = true;
    }

    /// Remove the memory capability whose backing `Arc` is the same allocation
    /// as `target`.  Used by `revoke_subtree` to eagerly clean up the child
    /// domain's tracking table while the capability `Arc` is still alive.
    pub fn remove_memory_capability_by_ref(&mut self, target: &CapabilityWeak<MemoryRegion>) {
        self.memory_capabilities
            .retain(|_, weak| !Weak::ptr_eq(weak, target));
        self.view_dirty = true;
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

    /// Recompute the cached address-space view if `view_dirty` is set.
    /// No-op if the view is already up-to-date.
    ///
    /// When `address_translation` is enabled, translates HPA regions to GPA
    /// using the address_map. Regions with no mapping keep GPA = HPA.
    pub fn ensure_view_fresh(&mut self) {
        if !self.view_dirty {
            return;
        }
        let cap_arcs: alloc::vec::Vec<CapabilityRef<MemoryRegion>> = self
            .memory_capabilities
            .values()
            .filter_map(|w| w.upgrade())
            .collect();
        self.cached_view = compute_view_from_cap_arcs(self.id, &cap_arcs);

        #[cfg(feature = "address_translation")]
        self.translate_view_to_gpa();

        self.view_dirty = false;
    }

    /// Translate the cached HPA view to GPA using address_map.
    ///
    /// For each view region (HPA-keyed), find overlapping address_map entries
    /// and remap to GPA. Regions (or sub-regions) with no address_map coverage
    /// keep GPA = HPA (identity).
    #[cfg(feature = "address_translation")]
    fn translate_view_to_gpa(&mut self) {
        use crate::translation::MapEntry;
        use crate::view::ViewRegion;
        use crate::memory::Access;

        if self.address_map.entries().is_empty() {
            return; // All identity — nothing to do.
        }

        let mut translated = alloc::vec::Vec::new();

        for region in &self.cached_view.regions {
            let hpa_start = region.start();
            let hpa_end = region.end();
            let rights = region.rights();

            // Collect mapped sub-ranges that overlap this HPA region.
            let mut covers: alloc::vec::Vec<(u64, u64, u64)> = alloc::vec::Vec::new(); // (hpa_overlap_start, hpa_overlap_end, gpa_start)
            for entry in self.address_map.entries().values() {
                if let MapEntry::Mapped(m) = entry {
                    let m_hpa_end = m.hpa_start + m.size;
                    let overlap_start = core::cmp::max(hpa_start, m.hpa_start);
                    let overlap_end = core::cmp::min(hpa_end, m_hpa_end);
                    if overlap_start < overlap_end {
                        let offset = overlap_start - m.hpa_start;
                        covers.push((overlap_start, overlap_end, m.gpa_start + offset));
                    }
                }
            }
            covers.sort_by_key(|&(s, _, _)| s);

            if covers.is_empty() {
                // No mapping — identity (GPA = HPA).
                translated.push(region.clone());
                continue;
            }

            // Emit: identity gaps + translated overlaps.
            let mut cursor = hpa_start;
            for (cov_hpa_start, cov_hpa_end, cov_gpa) in &covers {
                // Identity gap before this covered range.
                if cursor < *cov_hpa_start {
                    let vr = ViewRegion::new(Access::new(cursor, *cov_hpa_start - cursor, rights));
                    // physical_start already == cursor (identity)
                    translated.push(vr);
                }
                // Translated range.
                let size = *cov_hpa_end - *cov_hpa_start;
                let mut vr = ViewRegion::new(Access::new(*cov_gpa, size, rights));
                vr.physical_start = *cov_hpa_start;
                translated.push(vr);
                cursor = *cov_hpa_end;
            }
            // Identity tail after last covered range.
            if cursor < hpa_end {
                let vr = ViewRegion::new(Access::new(cursor, hpa_end - cursor, rights));
                translated.push(vr);
            }
        }

        self.cached_view.regions = translated;
        self.cached_view.regions.sort();
        self.cached_view.coalesce();
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
