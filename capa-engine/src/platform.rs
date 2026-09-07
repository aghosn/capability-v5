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
//! (EPT, TLB) is updated via a two-phase IPI protocol, using a fresh pair of
//! [`Semaphore`]s ([`CoreSyncPoints`], constructed per transaction by
//! [`Platform::new_semaphore`]) embedded directly into the per-core update
//! data each affected core drains — not a fixed set of global barrier slots:
//!
//! 1. Acquire shared or exclusive lock.
//! 2. Run the pure tree mutation → collect `UpdateBatch`.
//! 3. For each core running an affected domain, send an IPI.
//! 4. **`switched` phase**: the initiator blocks (`acquire`) until every
//!    affected core has drained its queue and switched off the doomed
//!    domain — each drained entry (`TlbShootdown` or `Switch`) is one
//!    `release`, so a core with both queued contributes two.
//! 5. Initiating core applies hardware updates (EPT changes, zero memory…).
//! 6. **`applied` phase**: the initiator releases the same `switched_events`
//!    count of permits (non-blocking — it does not itself wait for cores to
//!    resume), so each core's queued entry can `acquire(1)` — a core with
//!    both a `TlbShootdown` and a `Switch` queued acquires twice.
//! 7. `on_domain_revoked` is called for any revoked domains.
//! 8. Lock is released.
//!
//! For operations whose affected domains are not currently running on any
//! remote core ("local path"), steps 3-6 are skipped.
//!
//! Unlike a barrier, a [`Semaphore`] has no notion of participant count or
//! generation: `release(n)` unconditionally adds `n` permits and never
//! blocks; `acquire(n)` blocks until `n` cumulative permits are available,
//! then consumes them. This maps directly onto "count of events that must
//! occur before I may proceed" without the `participants == 0` vs `> 0`
//! overloaded convention the previous `Barrier::wait` used to distinguish
//! initiator from responder.
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

/// A counting semaphore used for per-transaction cross-core rendezvous.
///
/// `release(n)` adds `n` permits and never blocks. `acquire(n)` blocks the
/// calling core until `n` permits are cumulatively available (across
/// possibly many `release` calls, from possibly many callers), then
/// consumes them. There is no "generation"/reuse concept — each transaction
/// constructs a fresh instance via [`Platform::new_semaphore`], used exactly
/// once, so there is nothing to reset.
pub trait Semaphore: Send + Sync {
    /// Block until `n` permits are available, then consume them. `n == 0`
    /// returns immediately.
    fn acquire(&self, n: usize);
    /// Add `n` permits. Never blocks. `n == 0` is a no-op.
    fn release(&self, n: usize);
}

/// No-op [`Semaphore`] for platforms where the cross-core path is never
/// exercised (single-core simulators, tests).
struct NoOpSemaphore;
impl Semaphore for NoOpSemaphore {
    fn acquire(&self, _n: usize) {}
    fn release(&self, _n: usize) {}
}

/// The two rendezvous points for one cross-core transaction: `switched`
/// (every affected core has switched off the doomed domain) and `applied`
/// (the initiator has finished applying updates, cores may resume).
///
/// Constructed fresh per transaction via [`Platform::new_semaphore`], then
/// embedded directly into the per-core update data each affected core
/// already drains (see [`crate::platform::execute`]'s per-domain push loop)
/// — so the initiator and every affected core consult the exact same
/// objects, instead of independently-hardcoded barrier slots that only
/// agree by convention.
#[derive(Clone)]
pub struct CoreSyncPoints {
    pub switched: Arc<dyn Semaphore>,
    pub applied: Arc<dyn Semaphore>,
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
    // Cross-core synchronisation (two-phase semaphore protocol)
    // -----------------------------------------------------------------------

    /// Send a platform-specific IPI to preempt core `core_id`.
    ///
    /// The preempted core should trap into the monitor and drain its update
    /// queue, then release the transaction's [`CoreSyncPoints`] (found
    /// embedded in the queue entries it just drained — see
    /// [`crate::platform::execute`]'s per-domain push loop).
    /// Called once per affected core before the `switched` phase.
    /// No-op for single-core or simulation platforms.
    fn send_ipi(&self, core_id: CoreId);

    /// Construct one fresh semaphore for a cross-core transaction.
    ///
    /// Called twice per cross-core transaction (once for `switched`, once
    /// for `applied` — see [`CoreSyncPoints`]), before any per-core update
    /// is pushed, so the same `Arc`s can be cloned into every affected
    /// core's queue entries (see [`crate::platform::execute`]'s per-domain
    /// push loop) as well as kept by the initiator itself.
    ///
    /// **Default implementation** returns a no-op semaphore, suitable for
    /// single-core/simulation platforms where the cross-core path is never
    /// taken (no core is ever a rendezvous participant).
    fn new_semaphore(&self) -> Arc<dyn Semaphore> {
        Arc::new(NoOpSemaphore)
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

    /// Called for each revoked domain, after the `switched` phase (all
    /// affected cores have already drained their own `CoreUpdate::Switch`/
    /// `TlbShootdown` entries and switched off `domain_id`) but before
    /// [`Platform::apply_update`] tears down its hardware state.
    ///
    /// Core redirection is **not** this callback's job any more: any core
    /// that was running `domain_id` already popped its own `call_stack` to
    /// the first non-revoked ancestor via the `CoreUpdate::Switch` queued by
    /// `execute` (see [`crate::domain_api::apply_core_updates`] /
    /// `Capability::switch_after_callee_revoked`) — `fallback` is not
    /// consulted for that purpose (the live call-stack walk always agrees
    /// with it, per the engine's switch-locality invariant). Platforms with
    /// no local bookkeeping to update (e.g. bare-metal capavisor) may
    /// implement this as a no-op; platforms whose cross-core path cannot
    /// otherwise reach a remote core (e.g. capa-cli's single-process
    /// simulation, which must drain affected cores' queues inline here
    /// since it has no real IPI delivery) use it as their hook to do so.
    fn on_domain_revoked(&self, domain_id: DomainId, fallback: Option<DomainId>);

    /// Register a newly-created domain with the platform.
    ///
    /// `parent_id` is stored so the platform can compute the fallback domain
    /// when a vital-memory revocation does not provide one. Must be called
    /// immediately after the domain capability is created, while the caller
    /// still holds a reference to the parent.
    fn register_domain(&self, domain_id: DomainId, parent_id: Option<DomainId>);

    /// Called by `Capability::seal`, still under `execute()`'s op-lock,
    /// right after the domain transitions Unsealed → Sealed.
    ///
    /// `interrupts`/`msrs` are a snapshot of the domain's final policy at
    /// the moment of sealing, so the platform can (re-)project it onto
    /// whatever hardware state it derives from that policy (VMCS MSR
    /// bitmap, IRTEs) without a second, unsynchronized resolution of the
    /// domain's capability handle after `seal` has already returned and
    /// released the lock. This makes seal the authoritative
    /// synchronization point regardless of the order in which
    /// policy-setting and VP-creation calls arrived beforehand (both
    /// untrusted per axiom A2).
    ///
    /// **Default implementation** is a no-op (platforms with no derived
    /// hardware state to project, e.g. capa-cli's simulation).
    fn on_domain_sealed(
        &self,
        _domain_id: DomainId,
        _interrupts: &crate::domain::InterruptPolicy,
        _msrs: &crate::interposition::MsrPolicy,
    ) {
    }

    /// Called by `Capability::add_vp`, still under `execute()`'s op-lock,
    /// right after the VP is provisionally added to the domain's VP list.
    ///
    /// The platform must allocate and store whatever hardware-backed VP
    /// state it needs (e.g. VMCS/VAPIC on x86) for `(domain_id, vp_id)`,
    /// keyed however the platform likes — the engine never touches or
    /// interprets this state. `msrs` is the domain's current `MsrPolicy`,
    /// passed through so the platform can project it onto VP-local
    /// hardware state (e.g. an MSR bitmap) without a second,
    /// unsynchronized resolution of the domain's capability handle.
    ///
    /// Returning `Err` aborts the whole `add_vp` operation atomically: the
    /// provisional VP entry is rolled back and no capability-tree mutation
    /// is left in place, so capability creation and platform allocation
    /// share fate — no manual rollback is needed by the caller.
    ///
    /// **Default implementation** is a no-op success (platforms with no
    /// hardware VP state to allocate, e.g. capa-cli's simulation).
    fn allocate_vp(
        &self,
        _domain_id: DomainId,
        _vp_id: u32,
        _msrs: &crate::interposition::MsrPolicy,
    ) -> Result<()> {
        Ok(())
    }

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
    fn complete_revoke_switch(&self, _core_id: CoreId, _src: (DomainId, u64), _dst: (DomainId, u64)) {}

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
    /// Called internally when sending a memory capability that carries the
    /// [`Attributes::HASH`] flag, to populate `MemoryRegion::content_hash`
    /// (see `send_memory_sealed`/`send_memory_unsealed` in `domain_api.rs`).
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
///    - Block (`switched.acquire`) until every queued `TlbShootdown`/
///      `Switch` entry has been drained and released — see
///      [`CoreSyncPoints::switched`].
///    - Apply hardware updates (EPT, zero memory…).
///    - Release one `applied` permit per `switched`-phase event so each
///      affected core may resume (same event count on both phases, so a
///      core with two entries queued acquires two `applied` permits)
///      (non-blocking — see [`CoreSyncPoints::applied`]).
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
        // an IPI (waiting on its own transaction's semaphore for our
        // release), we signal back before we proceed.  This breaks
        // the A↔B deadlock:
        //
        //   A holds update_lock → sends IPI to B → waits on its semaphore
        //   B spins here → poll detects A's IPI → B releases A's semaphore
        //   A applies updates → releases update_lock
        //   B acquires update_lock → runs its own IPI/rendezvous/apply
        while !platform.try_acquire_update_lock() {
            platform.poll_and_respond_cross_core();
        }

        // This transaction's two semaphores — constructed once, before any
        // per-core update is pushed, so the very same `Arc`s can be
        // embedded into every affected core's queue entries below (see
        // `domain_cores`/`push_core_switch`) as well as kept here by the
        // initiator. No global/fixed-size barrier state is involved: each
        // semaphore lives exactly as long as this transaction.
        let sync = CoreSyncPoints {
            switched: platform.new_semaphore(),
            applied: platform.new_semaphore(),
        };

        // Step 4/5 — determine affected cores and choose path.
        //
        // For each affected domain, the engine already knows both which
        // cores are genuine rendezvous participants (currently running it)
        // and which cores may have cached stale entries for it (bound to it
        // in the past, not yet flushed) — both are scans of engine-owned
        // per-core state (see `SwitchManager::cores_running`/
        // `cores_with_cached`). The union of the two gets a `TlbShootdown`
        // pushed, but only participants are rendezvous-counted (contribute a
        // `switched.release(1)` when drained) and get `sync`. Queried inside
        // the update lock so concurrent `on_domain_revoked` calls (also
        // inside the lock) cannot race here. The current core (handling the
        // hypercall) is excluded: it already stopped running guest code
        // (VMEXIT) and will apply updates directly.
        let current_core = platform.get_current_core();
        let switch_mgr = platform.switch_manager();
        let mut affected_cores: BTreeSet<CoreId> = BTreeSet::new();
        // Total `switched`-phase releases the initiator must collect: one
        // per queued `TlbShootdown`/`Switch` entry actually pushed to a
        // rendezvous participant. A core with BOTH queued (it is currently
        // running the doomed domain, and also has a stale cache entry from
        // an unrelated earlier domain) contributes two releases, not one —
        // counted here per-entry rather than per-core.
        let mut switched_events: usize = 0;
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
                if let Ok(core_ctx) = switch_mgr.get_core(c) {
                    let entry_sync = if participants.contains(&c) {
                        switched_events += 1;
                        Some(sync.clone())
                    } else {
                        None
                    };
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
        // BEFORE releasing `switched` (that is what the `switched` phase
        // attests to: "targets have switched off the doomed domain").  So
        // every `CoreSwitch` that the initiator wants a target to observe
        // must be enqueued happens-before the target's `send_ipi` here —
        // otherwise the target drains an empty queue and releases with the
        // target still bound to the doomed domain, breaking `apply_update`'s
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
                switched_events += 1;
            }
        }

        if !affected_cores.is_empty() {
            // Cross-core path: preempt affected cores, apply updates, release them
            for &core_id in &affected_cores {
                platform.send_ipi(core_id);
            }
            // Block until every queued entry above has been drained and
            // released — one release per entry (see `switched_events`).
            sync.switched.acquire(switched_events);

            // Step 5b — apply the global updates (EPT/IOMMU frees, etc.).
            // Safe: every affected core has already drained/switched off
            // above, no live reference to the doomed domain remains.
            for update in batch.updates() {
                if let Update::RevokeDomain { domain, fallback } = update {
                    platform.on_domain_revoked(*domain, *fallback);
                }
            }
            for update in batch.updates() {
                platform.apply_update(update);
            }

            // Release one `applied` permit per `switched`-phase event above
            // — the same count, so each core's `apply_core_updates` can
            // consume exactly one `applied` permit per entry it drained,
            // with no need to track distinct transactions by identity (a
            // core with two entries for this transaction just calls
            // `acquire(1)` twice, consuming two of these permits — see
            // `apply_core_updates`). Non-blocking: unlike the old symmetric
            // barrier, the initiator does not itself wait for cores to
            // observe this before releasing the update lock below — a core
            // that hasn't yet consumed its permit simply finds it already
            // available whenever it next calls `acquire`, so there is
            // nothing to gain by blocking here and it only added a needless
            // rendezvous.
            sync.applied.release(switched_events);
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
