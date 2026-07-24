//! Platform abstraction for the capability engine.
//!
//! The capability engine is platform-independent. It communicates with the
//! hardware through the [`Platform`] trait, which the backend must implement.
//!
//! # Locking model
//!
//! Capability operations are serialised using a **global read-write lock**
//! exposed through the [`Platform`] trait:
//!
//! - **Shared lock** ([`Platform::acquire_shared_lock`]): held by non-destructive
//!   operations (carve, alias, send). Multiple holders can run concurrently.
//! - **Exclusive lock** ([`Platform::acquire_exclusive_lock`]): held by any revoke
//!   operation. Blocks until all shared-lock holders have released, then runs
//!   alone. This ensures revocation is fully isolated — no concurrent operation
//!   can observe a partially-revoked subtree, and no TOCTOU check is needed.
//!
//! On bare metal the two methods map directly to a hardware RW spinlock
//! (`rwlock_read_lock` / `rwlock_write_lock`).
//!
//! # Cross-core atomicity (§5.2 of the paper)
//!
//! After the lock is acquired and the tree mutation runs, hardware state
//! (EPT, TLB) is updated via a two-rendezvous IPI protocol, using a fresh
//! pair of [`Barrier`]s ([`CoreSyncBarriers`], constructed per transaction
//! by [`Platform::new_barrier`]) embedded directly into the per-core update
//! data each affected core drains — not a fixed set of global barrier slots:
//!
//! 1. Acquire shared or exclusive lock.
//! 2. Run the pure tree mutation → collect `UpdateBatch`.
//! 3. For each core running an affected domain, send an IPI.
//! 4. **First rendezvous**: all affected cores have drained their queue and
//!    switched off the doomed domain.
//! 5. Initiating core applies hardware updates (EPT changes, zero memory…).
//! 6. **Second rendezvous**: affected cores resume and apply local state
//!    (TLB flush…).
//! 7. `on_domain_revoked` is called for any revoked domains.
//! 8. Lock is released.
//!
//! For operations whose affected domains are not currently running on any
//! remote core ("local path"), steps 3-6 are skipped.
//!
//! # Memory lifecycle safety
//!
//! `Arc` reference counting keeps capability tree nodes alive for the full
//! duration of any operation that holds references to them. The exclusive lock
//! ensures that by the time a revoke operation completes and releases the lock,
//! no other thread is accessing the revoked domains.

use crate::error::{CapaError, Result};
use crate::switch::CoreUpdate;
use crate::update::{CoreId, DomainId, Update, UpdateBatch};
use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::sync::Arc;

/// A RAII guard that holds a platform operation lock (shared or exclusive).
///
/// Dropping this guard releases the lock, allowing other operations to proceed.
/// The guard must remain alive for the entire duration of the capability
/// operation — including the IPI/barrier phase and update application.
pub trait OpLockGuard: Send {}

/// A single rendezvous point: every participant calls `wait`, and all of
/// them block until every one of them has arrived.
///
/// The initiator calls `wait(participants)` with the total participant
/// count (including itself), exactly once. Every other participant calls
/// `wait(0)`, spinning until the initiator's count becomes visible.
pub trait Barrier: Send + Sync {
    fn wait(&self, participants: usize);
}

/// No-op [`Barrier`] for platforms where the cross-core path is never
/// exercised (single-core simulators, tests).
struct NoOpBarrier;
impl Barrier for NoOpBarrier {
    fn wait(&self, _participants: usize) {}
}

/// The two rendezvous points for one cross-core transaction: `switched`
/// (every affected core has switched off the doomed domain) and `applied`
/// (the initiator has finished applying updates, cores may resume).
///
/// Constructed fresh per transaction via [`Platform::new_barrier`], then
/// embedded directly into the per-core update data each affected core
/// already drains (see [`crate::platform::execute`]'s per-domain push loop)
/// — so the initiator and every affected core consult the exact same
/// objects, instead of independently-hardcoded barrier slots that only
/// agree by convention.
#[derive(Clone)]
pub struct CoreSyncBarriers {
    pub switched: Arc<dyn Barrier>,
    pub applied: Arc<dyn Barrier>,
}


/// Platform-specific primitives required by the capability engine.
///
/// Implementations must be `Send + Sync` so the engine can share a platform
/// reference across cores.
pub trait Platform: Send + Sync {
    // -----------------------------------------------------------------------
    // Serialisation — global read-write lock
    // -----------------------------------------------------------------------

    /// Acquire a **shared** operation lock for non-destructive operations
    /// (carve, alias, send).
    ///
    /// Multiple shared-lock holders can coexist. Blocks only while an
    /// exclusive lock is held. On bare metal, maps to `rwlock_read_lock`.
    fn acquire_shared_lock(&self) -> Result<Box<dyn OpLockGuard>>;

    /// Acquire an **exclusive** operation lock for revoke operations.
    ///
    /// Blocks until all shared and exclusive lock holders have released, then
    /// runs alone. Guarantees that no other capability operation is in-flight
    /// during the revocation, eliminating the need for TOCTOU checks or
    /// per-domain domain-set enumeration. On bare metal, maps to
    /// `rwlock_write_lock`.
    fn acquire_exclusive_lock(&self) -> Result<Box<dyn OpLockGuard>>;

    // -----------------------------------------------------------------------
    // Cross-core synchronisation (two-barrier protocol)
    // -----------------------------------------------------------------------

    /// Send a platform-specific IPI to preempt core `core_id`.
    ///
    /// The preempted core should trap into the monitor and drain its update
    /// queue, then rendezvous on the transaction's [`CoreSyncBarriers`] (found
    /// embedded in the queue entries it just drained — see
    /// [`crate::platform::execute`]'s per-domain push loop).
    /// Called once per affected core before the first rendezvous.
    /// No-op for single-core or simulation platforms.
    fn send_ipi(&self, core_id: CoreId);

    /// Construct one rendezvous point for a cross-core transaction.
    ///
    /// Called twice per cross-core transaction (once for `switched`, once
    /// for `applied` — see [`CoreSyncBarriers`]), before any per-core
    /// update is pushed, so the same `Arc`s can be cloned into every
    /// affected core's queue entries (see [`crate::platform::execute`]'s
    /// per-domain push loop) as well as kept by the initiator itself.
    ///
    /// **Default implementation** returns a no-op barrier, suitable for
    /// single-core/simulation platforms where the cross-core path is never
    /// taken (no core is ever a rendezvous participant).
    fn new_barrier(&self) -> Arc<dyn Barrier> {
        Arc::new(NoOpBarrier)
    }

    // -----------------------------------------------------------------------
    // Update-application serialisation
    // -----------------------------------------------------------------------

    /// Attempt to acquire the **update-application lock** without blocking.
    ///
    /// Only one initiating core at a time may run the IPI / barrier /
    /// `apply_update` sequence.  This serialises concurrent shared-operation
    /// initiators, preventing two problems:
    ///
    /// 1. **Deadlock** — if core A and core B both hold a shared capability
    ///    lock and send IPIs to each other, they would each block at their own
    ///    its own barrier wait, waiting for the other to acknowledge, with neither
    ///    able to proceed.  With the update lock, only one core enters the IPI
    ///    protocol at a time; the other spins and responds to incoming IPIs via
    ///    [`poll_and_respond_cross_core`].
    ///
    /// 2. **Non-atomic interleaving** — two concurrent `apply_update` streams
    ///    for different batches can produce an inconsistent hardware state if
    ///    they target overlapping domains.  The lock gives a total order on
    ///    all UpdateBatch applications.
    ///
    /// **Returns** `true` if the lock was acquired, `false` if another core
    /// holds it.  The caller **must** release it with [`release_update_lock`]
    /// after the full update-application phase (including `on_domain_revoked`
    /// calls) completes.
    ///
    /// **Default implementation** always returns `true` (no contention),
    /// suitable for single-core and simulation platforms.
    fn try_acquire_update_lock(&self) -> bool {
        true
    }

    /// Release the update-application lock acquired by
    /// [`try_acquire_update_lock`].
    ///
    /// **Default implementation** is a no-op.
    fn release_update_lock(&self) {}

    /// Poll for and respond to any pending cross-core synchronisation requests.
    ///
    /// Called in the spin loop while waiting for the update-application lock.
    /// On bare metal, this checks whether a cross-core IPI from another
    /// initiating core is pending and, if so, executes the IPI-handler path
    /// (i.e. rendezvous on that core's barrier so it can proceed with
    /// its own update application).
    ///
    /// A core running a capability operation in the monitor will have
    /// interrupts disabled and therefore cannot be preempted by an IPI in the
    /// usual way.  By calling this inside the spin loop the core still
    /// participates in the cross-core protocol without having to reload the
    /// domain context on every monitor entry/exit — the response is just a
    /// barrier signal, not a context switch.
    ///
    /// **Default implementation** is a no-op (single-core / test platforms).
    fn poll_and_respond_cross_core(&self) {}

    // -----------------------------------------------------------------------
    // Hardware state
    // -----------------------------------------------------------------------

    /// Validate an exit policy change before it is applied.
    ///
    /// Called by `set_policy` for exit-related [`PolicyIdentifier`] variants.
    /// The platform can reject:
    /// - Invalid exit reason numbers for this architecture
    /// - `trap=false` for exits the platform cannot emulate locally
    /// - `trap=true` for exits that are internal mechanisms (timer, interrupt window)
    ///
    /// **Default implementation** accepts everything.
    fn validate_exit_policy(
        &self,
        _exit_reason: u32,
        _action: &crate::domain::ExitAction,
    ) -> Result<()> {
        Ok(())
    }

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
    // Hardware core-state actions
    // -----------------------------------------------------------------------
    //
    // The engine owns "which domain/VP is running where", the per-core
    // update queue, and the "which cores may have cached entries for a
    // domain" tracking directly (see [`crate::switch::CoreContext`]) — these
    // two hooks are the only genuinely hardware-specific actions the
    // platform must still provide.

    /// Return the TLB/second-stage flush handle for `domain_id` (e.g. the
    /// EPTP/SLAT physical address) — a pure hardware fact, opaque to the
    /// engine.
    ///
    /// **Default implementation** returns `0`.
    fn tlb_flush_handle(&self, _domain_id: DomainId) -> u64 {
        0
    }

    /// Flush any second-stage entries `core_id` may have cached for
    /// `domain_id`, using the handle from
    /// [`tlb_flush_handle`](Self::tlb_flush_handle).
    ///
    /// **Default implementation** is a no-op.
    fn flush_tlb(&self, _domain_id: DomainId, _handle: u64, _core_id: CoreId) {}

    /// Perform the hardware swap (e.g. VMCLEAR/VMPTRLD) moving `core_id`
    /// from `src` to `dst`, each given as `(domain_id, vp_id)`.
    ///
    /// Called by [`crate::domain_api::apply_core_updates`] for a
    /// revoke-driven `CoreUpdate::Switch`, strictly after the engine has
    /// already resolved and committed the new binding.
    ///
    /// **Default implementation** is a no-op.
    fn apply_cross_core_switch(&self, _core_id: CoreId, _src: (DomainId, u64), _dst: (DomainId, u64)) {}

    // -----------------------------------------------------------------------
    // Virtual processor tracking
    // -----------------------------------------------------------------------

    /// Return the ID of the physical core currently executing this call.
    ///
    /// Returns `None` on platforms where the calling core cannot be determined
    /// (e.g. single-core simulators). VP-aware operations require a `Some` value.
    ///
    /// **Default implementation** returns `None`.
    fn get_current_core(&self) -> Option<CoreId> {
        None
    }

    // -----------------------------------------------------------------------
    // VP register access (platform-managed register file)
    // -----------------------------------------------------------------------

    /// Number of registers per VP supported by this platform.
    ///
    /// Register IDs are in `0..register_count()`. The engine uses this to
    /// validate `reg_id` bounds before checking the access bitmap.
    ///
    /// **Default implementation** returns 64.
    fn register_count(&self) -> u64 {
        64
    }

    /// Read the value of register `reg_id` for VP `vp_id` of domain `domain_id`.
    ///
    /// Called by the engine after validating that the caller has read permission
    /// for this register (via the effective-vector policy bitmap).
    ///
    /// **Default implementation** returns `CapaError::NotSupported`.
    fn get_vp_register(
        &self,
        _domain_id: DomainId,
        _vp_id: u64,
        _reg_id: u64,
    ) -> crate::error::Result<u64> {
        Err(crate::error::CapaError::NotSupported)
    }

    /// Write `value` to register `reg_id` for VP `vp_id` of domain `domain_id`.
    ///
    /// Called by the engine after validating that the caller has write permission
    /// for this register (via the effective-vector policy bitmap).
    ///
    /// **Default implementation** returns `CapaError::NotSupported`.
    fn set_vp_register(
        &self,
        _domain_id: DomainId,
        _vp_id: u64,
        _reg_id: u64,
        _value: u64,
    ) -> crate::error::Result<()> {
        Err(crate::error::CapaError::NotSupported)
    }

    // -----------------------------------------------------------------------
    // Memory measurement (attestation)
    // -----------------------------------------------------------------------

    /// Measure the physical memory region `[address, address + size)` and
    /// return a cryptographic hash of its contents.
    ///
    /// Called by [`Capability::compute_memory_hash`] to populate
    /// `MemoryRegion::content_hash` for capabilities that carry the
    /// [`Attributes::HASH`] flag.
    ///
    /// The hash algorithm is platform-defined. Returning a 32-byte value
    /// matches the SHA-256 / SHA3-256 conventions used by most attestation
    /// stacks, but the engine treats it as an opaque byte array.
    ///
    /// **Default implementation** returns `[0u8; 32]` (no-op / not supported).
    fn measure_region(&self, _address: u64, _size: u64) -> [u8; 32] {
        [0u8; 32]
    }

    // -----------------------------------------------------------------------
    // Per-core switch / call-chain authority
    // -----------------------------------------------------------------------

    /// Return this platform's [`crate::switch::SwitchManager`] — the single
    /// per-core authority for "which domain/VP is running where" and each
    /// core's live call chain.
    ///
    /// `SwitchManager`'s per-core table is fixed-size and built once at
    /// construction; each core's mutable state is lock-scoped to that one
    /// core only (see [`crate::switch::CoreContext`]). Implementers must
    /// store their `SwitchManager` as a plain field — like `op_lock` /
    /// `update_lock` — never behind a coarser platform-wide mutex, so that
    /// reaching one core's state can never contend with an unrelated core.
    fn switch_manager(&self) -> &crate::switch::SwitchManager;
}

/// Execute a capability operation atomically using the given platform.
///
/// This is the central execution entry point that implements the full
/// cross-core synchronisation protocol described in §5.2 of the paper.
///
/// # Lock kind
///
/// Pass `exclusive = false` for non-destructive operations (carve, alias,
/// send). Pass `exclusive = true` for any revoke operation. The exclusive
/// lock guarantees that no other capability operation is in-flight during
/// revocation — no caller needs to enumerate affected domain IDs in advance.
///
/// # Protocol
///
/// 1. **Lock**: acquire shared or exclusive lock via the platform.
/// 2. **Operate**: call `op()`, which performs the pure capability tree
///    mutation and returns `(R, UpdateBatch)`.
/// 3. **Update-application lock**: spin to acquire the update-application
///    serialisation lock, responding to cross-core sync requests while
///    waiting (see [`Platform::try_acquire_update_lock`]).
/// 4. **Synchronise** (cross-core path — only if affected domains are running
///    on remote cores):
///    - Send IPIs to preempt every affected core.
///    - Rendezvous once every affected core has switched off (see
///      [`CoreSyncBarriers::switched`]).
///    - Apply hardware updates (EPT, zero memory…).
///    - Rendezvous once more so cores may resume (see
///      [`CoreSyncBarriers::applied`]).
/// 5. **Local path**: if no remote cores are affected, apply updates directly.
/// 6. **Revocations**: for each `RevokeDomain` update, call
///    [`Platform::on_domain_revoked`] so the platform can redirect cores.
///    This is done inside the update-application lock so that
///    `SwitchManager::cores_running`/`cores_with_cached` queries from
///    concurrent initiators see a consistent core-binding snapshot.
/// 7. **Release update lock**, then drop the capability lock guard.
///
/// Returns `(R, UpdateBatch)` so callers can inspect the updates.
pub(crate) fn execute<F, R>(
    platform: &dyn Platform,
    exclusive: bool,
    op: F,
) -> Result<(R, UpdateBatch)>
where
    F: FnOnce() -> Result<(R, UpdateBatch)>,
{
    // Step 1 — acquire shared or exclusive capability lock
    let _guard = if exclusive {
        platform.acquire_exclusive_lock()?
    } else {
        platform.acquire_shared_lock()?
    };

    // Step 2 — run the pure capability tree mutation
    let (result, batch) = op()?;

    // Steps 3–6 — update-application phase (skipped entirely for empty batches)
    if !batch.updates().is_empty() {
        // Step 3 — acquire the update-application serialisation lock.
        //
        // Only one initiating core at a time runs the IPI/rendezvous/apply
        // sequence.  While spinning, we call poll_and_respond_cross_core()
        // so that if another core has already acquired this lock and sent us
        // an IPI (waiting on its own transaction's barriers for our
        // acknowledgement), we signal back before we proceed.  This breaks
        // the A↔B deadlock:
        //
        //   A holds update_lock → sends IPI to B → waits on its barrier
        //   B spins here → poll detects A's IPI → B rendezvous on A's barrier
        //   A applies updates → releases update_lock
        //   B acquires update_lock → runs its own IPI/rendezvous/apply
        while !platform.try_acquire_update_lock() {
            platform.poll_and_respond_cross_core();
        }

        // This transaction's two rendezvous points — constructed once,
        // before any per-core update is pushed, so the very same `Arc`s can
        // be embedded into every affected core's queue entries below (see
        // `domain_cores`/`push_core_switch`) as well as kept here by the
        // initiator. No global/fixed-size barrier state is involved: each
        // barrier lives exactly as long as this transaction.
        let sync = CoreSyncBarriers {
            switched: platform.new_barrier(),
            applied: platform.new_barrier(),
        };

        // Step 4/5 — determine affected cores and choose path.
        //
        // For each affected domain, the engine already knows both which
        // cores are genuine rendezvous participants (currently running it)
        // and which cores may have cached stale entries for it (bound to it
        // in the past, not yet flushed) — both are scans of engine-owned
        // per-core state (see `SwitchManager::cores_running`/
        // `cores_with_cached`). The union of the two gets a `TlbShootdown`
        // pushed, but only participants are rendezvous-counted and get
        // `sync`. Queried inside the update lock so concurrent
        // `on_domain_revoked` calls (also inside the lock) cannot race here.
        // The current core (handling the hypercall) is excluded: it already
        // stopped running guest code (VMEXIT) and will apply updates directly.
        let current_core = platform.get_current_core();
        let switch_mgr = platform.switch_manager();
        let mut affected_cores: BTreeSet<CoreId> = BTreeSet::new();
        for &domain_id in batch.affected_domains() {
            let participants: BTreeSet<CoreId> = switch_mgr
                .cores_running(domain_id)
                .into_iter()
                .filter(|&c| Some(c) != current_core)
                .collect();
            let handle = platform.tlb_flush_handle(domain_id);
            let mut targets: BTreeSet<CoreId> =
                switch_mgr.cores_with_cached(domain_id).into_iter().collect();
            targets.extend(participants.iter().copied());
            for c in targets {
                if Some(c) == current_core {
                    // Local flush is performed inline by `apply_update`.
                    continue;
                }
                let entry_sync = if participants.contains(&c) {
                    Some(sync.clone())
                } else {
                    None
                };
                if let Ok(core_ctx) = switch_mgr.get_core(c) {
                    core_ctx.push_update(CoreUpdate::TlbShootdown {
                        domain: domain_id,
                        handle,
                        sync: entry_sync,
                    });
                }
            }
            affected_cores.extend(participants);
        }
        affected_cores.extend(
            batch
                .core_switches()
                .map(|switch| switch.core)
                .filter(|&c| Some(c) != current_core),
        );

        // Step 5a — push per-core switch orders BEFORE sending IPIs.
        // Under the Tyche-aligned
        // barrier protocol, target cores drain their per-core update queue
        // BEFORE rendezvousing (that is what the first rendezvous attests
        // to: "targets have switched off the doomed domain").  So every
        // `CoreSwitch` that the initiator wants a target to observe must be
        // enqueued happens-before the target's `send_ipi` here — otherwise
        // the target drains an empty queue and rendezvouses with the target
        // still bound to the doomed domain, breaking `apply_update`'s
        // "no live reference" precondition.
        let mut switched_cores = BTreeSet::new();
        for switch in batch.core_switches() {
            if !switched_cores.insert(switch.core) {
                platform.release_update_lock();
                return Err(CapaError::InvalidOperation(
                    String::from("multiple revoke switch orders for one core"),
                ));
            }
            if let Ok(core_ctx) = switch_mgr.get_core(switch.core) {
                core_ctx.push_update(CoreUpdate::Switch {
                    source_cap: switch.source_domain.clone(),
                    source_vp: switch.source_vp,
                    sync: sync.clone(),
                });
            }
        }

        if !affected_cores.is_empty() {
            // Cross-core path: preempt affected cores, apply updates, release them
            for &core_id in &affected_cores {
                platform.send_ipi(core_id);
            }
            // Rendezvous once all affected cores have drained their per-core
            // update queue and switched off the doomed domain.
            sync.switched.wait(affected_cores.len() + 1);

            // Step 5b — apply the global updates (EPT/IOMMU frees, etc.).
            // Safe: every affected core is parked at the rendezvous above, no
            // live reference to the doomed domain remains.
            for update in batch.updates() {
                if let Update::RevokeDomain { domain, fallback } = update {
                    platform.on_domain_revoked(*domain, *fallback);
                }
            }
            for update in batch.updates() {
                platform.apply_update(update);
            }

            // Rendezvous once more to release cores to resume execution.
            sync.applied.wait(affected_cores.len() + 1);
        } else {
            // Local path: no remote core is running an affected domain.
            for update in batch.updates() {
                if let Update::RevokeDomain { domain, fallback } = update {
                    platform.on_domain_revoked(*domain, *fallback);
                }
            }
            for update in batch.updates() {
                platform.apply_update(update);
            }
        }

        // Step 7 — release update-application lock
        platform.release_update_lock();
    }

    Ok((result, batch))
    // Capability lock (_guard) dropped here
}
