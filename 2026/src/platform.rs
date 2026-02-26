//! Platform abstraction for the capability engine.
//!
//! The capability engine is platform-independent. It communicates with the
//! hardware through the [`Platform`] trait, which the backend must implement.
//!
//! # Cross-core atomicity (§5.2 of the paper)
//!
//! Capability operations that affect domains running on remote cores use a
//! **two-barrier protocol**:
//!
//! 1. The initiating core acquires the operation lock (serialises conflicting ops).
//! 2. It runs the pure tree mutation and collects the `UpdateBatch`.
//! 3. For each core running an affected domain, it sends an IPI.
//! 4. **Barrier 0**: all affected cores are preempted and waiting.
//! 5. The initiating core applies hardware updates (EPT changes, zero memory…).
//! 6. **Barrier 1**: affected cores resume and apply local state (TLB flush…).
//! 7. `on_domain_revoked` is called for any revoked domains.
//! 8. The operation lock is released.
//!
//! For operations whose affected domains are not currently running on any
//! other core ("local path"), steps 3-6 are skipped for efficiency.
//!
//! # Memory lifecycle safety
//!
//! Domain objects must not be freed until all cores that may reference them
//! have acknowledged their revocation. The two-barrier protocol guarantees
//! this at the hardware level. In Rust library implementations (test, CLI),
//! `Arc` reference counting provides the same guarantee automatically.
//!
//! The operation lock (`op_lock`) is kept alive via `Arc` inside the
//! [`OpLockGuard`], so a thread waiting on the lock for a to-be-revoked
//! domain will still hold a valid `Arc` to the lock entry when it eventually
//! acquires it. After acquiring the lock, the TOCTOU check detects the
//! revocation and returns [`CapaError::DomainRevoked`] before accessing any
//! freed state.
//!
//! # Conflict identification
//!
//! The following capability operation pairs require serialisation:
//!
//! | Scenario | Affected domain set |
//! |---|---|
//! | `send` while receiver runs on another core | sender + receiver domains |
//! | `send` rejected by receiver (rollback) | sender + receiver domains |
//! | `carve`/`alias` overlapping with a concurrent `revoke` | parent domain |
//! | `create_child_domain` while parent is being revoked | parent domain |
//! | Concurrent `revoke` of overlapping subtrees | root parent domain |
//! | Domain running on 2+ cores being revoked | all affected cores get IPI |

use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use crate::error::Result;
use crate::update::{CoreId, DomainId, Update, UpdateBatch};

/// A RAII guard that holds all operation locks for a set of domains.
///
/// Dropping this guard releases every lock that was acquired during
/// [`Platform::acquire_op_locks`]. The guard must remain alive for the
/// entire duration of the capability operation — including the IPI/barrier
/// phase and the update application — so that:
///
/// - Concurrent operations on the same domains are serialised.
/// - Domain objects referenced by the operation remain alive (the Arc kept
///   inside the guard prevents the lock entry from being freed, and callers
///   keep their own Arcs to the capability tree nodes).
pub trait OpLockGuard: Send {}

/// Platform-specific primitives required by the capability engine.
///
/// Implementations must be `Send + Sync` so the engine can share a platform
/// reference across cores. Each method documents when it is called relative
/// to the two-barrier protocol.
pub trait Platform: Send + Sync {
    // -----------------------------------------------------------------------
    // Serialisation
    // -----------------------------------------------------------------------

    /// Acquire operation locks for the given set of domain IDs.
    ///
    /// Locks must be acquired in a **canonical (domain-ID-sorted) order** to
    /// prevent deadlocks when multiple cores race with overlapping domain sets.
    ///
    /// After acquiring each domain's lock the implementation must perform a
    /// **TOCTOU check**: if the domain has been revoked since the caller
    /// determined its domain set, the implementation releases all acquired
    /// locks and returns [`CapaError::DomainRevoked`]. This ensures the caller
    /// never proceeds with a stale domain reference.
    ///
    /// The returned guard owns the locks; dropping it releases them all.
    fn acquire_op_locks(&self, domains: &BTreeSet<DomainId>) -> Result<Box<dyn OpLockGuard>>;

    // -----------------------------------------------------------------------
    // Cross-core synchronisation (two-barrier protocol)
    // -----------------------------------------------------------------------

    /// Send a platform-specific IPI to preempt core `core_id`.
    ///
    /// The preempted core should trap into the monitor and wait at
    /// `sync_barrier(0, …)`. Called once per affected core before barrier 0.
    /// No-op for single-core or simulation platforms.
    fn send_ipi(&self, core_id: CoreId);

    /// Wait at a two-phase synchronisation barrier.
    ///
    /// - `id == 0` — "pre-update" barrier: the initiating core waits until
    ///   every preempted core has stopped executing and reached this barrier.
    /// - `id == 1` — "post-update" barrier: cores are released to apply local
    ///   hardware state (e.g. TLB shootdown).
    ///
    /// `participants` is the total number of cores expected (including the
    /// initiating core). No-op for platforms without parallel core execution.
    fn sync_barrier(&self, id: u8, participants: usize);

    // -----------------------------------------------------------------------
    // Hardware state
    // -----------------------------------------------------------------------

    /// Apply a single hardware-level update (map/unmap/zero memory/TLB flush…).
    ///
    /// Called by the initiating core **between** the two barriers, while all
    /// affected cores are stopped. This is the window in which EPT changes,
    /// memory zeroing, and similar operations must be performed so they appear
    /// atomic from the perspective of the paused cores.
    fn apply_update(&self, update: &Update);

    // -----------------------------------------------------------------------
    // Domain lifecycle
    // -----------------------------------------------------------------------

    /// Called after updates are applied when domain `domain_id` is revoked.
    ///
    /// The platform must:
    /// 1. Redirect any core currently running `domain_id` to `fallback`
    ///    (or set it idle if `fallback` is `None` and the domain has no parent).
    /// 2. Unregister `domain_id` from its internal tracking structures.
    ///
    /// `fallback` is the first non-revoked ancestor domain ID, pre-computed by
    /// the capability engine during `revoke_child_domain`. When revocation
    /// originates from a **vital memory capability** (`Update::RevokeDomain`
    /// with `fallback: None`), the platform must look up the parent from its
    /// own domain-parent map (set via [`Platform::register_domain`]).
    fn on_domain_revoked(&self, domain_id: DomainId, fallback: Option<DomainId>);

    /// Register a newly-created domain with the platform.
    ///
    /// `parent_id` is stored so the platform can compute the fallback domain
    /// when a vital-memory revocation does not provide one. Must be called
    /// immediately after the domain capability is created, while the caller
    /// still holds a reference to the parent.
    fn register_domain(&self, domain_id: DomainId, parent_id: Option<DomainId>);

    // -----------------------------------------------------------------------
    // Core state tracking
    // -----------------------------------------------------------------------

    /// Record that `domain_id` is now executing on `core_id`.
    fn set_core_domain(&self, core_id: CoreId, domain_id: DomainId);

    /// Record that `core_id` is no longer executing any domain (idle).
    fn clear_core_domain(&self, core_id: CoreId);

    /// Return the core ID that `domain_id` is currently running on, if any.
    fn domain_core(&self, domain_id: DomainId) -> Option<CoreId>;
}

/// Execute a capability operation atomically using the given platform.
///
/// This is the central execution entry point that implements the full
/// cross-core synchronisation protocol described in §5.2 of the paper.
///
/// # Protocol
///
/// 1. **Lock**: acquire operation locks for `affected_domains` in sorted order.
///    Returns [`CapaError::DomainRevoked`] if any domain was revoked while
///    waiting (TOCTOU protection).
/// 2. **Operate**: call `op()`, which performs the pure capability tree
///    mutation and returns `(R, UpdateBatch)`.
/// 3. **Synchronise** (cross-core path — only if affected domains are running
///    on remote cores):
///    - Send IPIs to preempt every affected core.
///    - Wait at barrier 0 (all affected cores have stopped).
///    - Apply hardware updates (EPT, zero memory…).
///    - Wait at barrier 1 (cores apply local state: TLB flush…).
/// 4. **Local path**: if no remote cores are affected, apply updates directly
///    (avoids IPI/barrier overhead for the common case).
/// 5. **Revocations**: for each `RevokeDomain` update, call
///    [`Platform::on_domain_revoked`] so the platform can redirect cores and
///    clean up its internal state.
/// 6. **Unlock**: the `OpLockGuard` is dropped, releasing all operation locks.
///
/// Returns `(R, UpdateBatch)` so callers can inspect the updates (e.g. for
/// higher-level state cleanup such as removing entries from CLI name maps).
pub fn execute<F, R>(
    platform: &dyn Platform,
    affected_domains: &BTreeSet<DomainId>,
    op: F,
) -> Result<(R, UpdateBatch)>
where
    F: FnOnce() -> Result<(R, UpdateBatch)>,
{
    // Step 1 — acquire operation locks; fail fast if any domain is revoked
    let _guard = platform.acquire_op_locks(affected_domains)?;

    // Step 2 — run the pure capability tree mutation
    let (result, batch) = op()?;

    // Step 3/4 — determine affected cores and choose local vs cross-core path
    let affected_cores: BTreeSet<CoreId> = batch
        .affected_domains()
        .iter()
        .filter_map(|&d| platform.domain_core(d))
        .collect();

    if !affected_cores.is_empty() {
        // Cross-core path: preempt affected cores, apply updates, release them
        for &core_id in &affected_cores {
            platform.send_ipi(core_id);
        }
        // Barrier 0: initiating core waits until all affected cores are stopped
        platform.sync_barrier(0, affected_cores.len() + 1);

        // Apply hardware updates while other cores are paused
        for update in batch.updates() {
            platform.apply_update(update);
        }

        // Barrier 1: release cores to apply their local hardware state
        platform.sync_barrier(1, affected_cores.len() + 1);
    } else {
        // Local path: no other core is running an affected domain
        for update in batch.updates() {
            platform.apply_update(update);
        }
    }

    // Step 5 — notify platform about domain revocations (update core state)
    for update in batch.updates() {
        if let Update::RevokeDomain { domain, fallback } = update {
            platform.on_domain_revoked(*domain, *fallback);
        }
    }

    Ok((result, batch))
    // Step 6 — _guard dropped here: all operation locks released
}
