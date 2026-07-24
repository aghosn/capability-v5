//! Switch and interrupt routing mechanisms

use crate::capability::CapabilityRef;
use crate::domain::{Domain, InterruptVisibility, VpCallContext};
use crate::error::{CapaError, Result};
use crate::platform::CoreSyncPoints;
use crate::sync::RwLock;
use alloc::collections::{BTreeSet, VecDeque};
use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// One core's live scheduling binding: which domain + VP is running there.
///
/// The sole authoritative source for "what is core X running right now" —
/// shared by every backend (bare-metal capavisor, hosted capa-cli) so this
/// fact is never independently tracked in more than one place.
#[derive(Clone)]
pub struct CoreBinding {
    pub domain: CapabilityRef<Domain>,
    pub vp_id: u64,
}

/// A cross-core update queued for a specific core to drain and apply.
///
/// Pushed by the initiating core (under the update lock) before sending an
/// IPI; drained by the target core via [`crate::domain_api::apply_core_updates`].
#[derive(Clone)]
pub enum CoreUpdate {
    /// Flush any second-stage entries this core may have cached for
    /// `domain`. `sync` is `Some` only for cores that are genuine rendezvous
    /// participants (currently running `domain`); lazily-cached,
    /// non-participant cores get `None` and flush asynchronously without
    /// rendezvousing.
    TlbShootdown {
        domain: u64,
        handle: u64,
        sync: Option<CoreSyncPoints>,
    },
    /// Revoke-driven cross-core switch: the VP `source_vp` of `source_cap`
    /// running on this core is being torn down. The resume target is not
    /// carried here — it is resolved locally from this core's own
    /// `call_stack` (see `Capability::switch_after_callee_revoked`).
    Switch {
        source_cap: CapabilityRef<Domain>,
        source_vp: u64,
        sync: CoreSyncPoints,
    },
}

/// Per-core execution context
pub struct CoreContext {
    /// Core ID
    pub core_id: u64,
    /// Currently bound (domain, vp) on this core, if any. `None` when idle.
    binding: RwLock<Option<CoreBinding>>,
    /// Pending cross-core updates for this core, drained via
    /// [`crate::domain_api::apply_core_updates`].
    updates: RwLock<VecDeque<CoreUpdate>>,
    /// Domain ids this core may have cached second-stage entries for.
    ///
    /// Set automatically by [`Self::set_binding`] (binding to a domain is
    /// exactly the event that may leave cached entries behind); cleared by
    /// [`crate::domain_api::apply_core_updates`] once the corresponding
    /// `TlbShootdown` has actually been flushed. This is the authoritative
    /// per-domain flush-target set — a domain being revoked queries every
    /// core's set via [`SwitchManager::cores_with_cached`] rather than the
    /// platform maintaining its own shadow copy.
    cached_domains: RwLock<BTreeSet<u64>>,
    /// Live call chain for this core, bottom (root-most caller) to top
    /// (most recent switch target).
    ///
    /// Mirrors `VpRunState`'s `Running`/`Locked` `caller`/`prev_caller`
    /// links for the normal switch/interrupt paths (`switch_domain_forward`,
    /// `switch_domain_return`, `deliver_interrupt_vp` push/pop this stack
    /// alongside those fields, cross-checked via `debug_assert!`), and is
    /// the sole source of truth for resolving a revoke-driven return's
    /// resume target: `Capability::switch_after_callee_revoked` pops this
    /// stack directly, with no remote caller-chain walk.
    ///
    /// `Suspended`/`Interrupted` VPs keep their own `prev_caller`/`caller`
    /// fields regardless — those describe chain segments frozen off any
    /// specific core, which may later resume on a *different* physical core
    /// than the one that froze them, so they can't live in a per-core stack.
    ///
    /// Single-writer per core in steady state: only the physical core
    /// owning this `CoreContext` pushes/pops during its own synchronous
    /// switches and interrupt entry/exit. The one cross-core exception is
    /// revoke, where — per the engine's locking model — the initiator holds
    /// the exclusive op-lock for the entire operation, which blocks every
    /// other core from starting a new switch/interrupt in the meantime; the
    /// *affected* core itself (not the initiator) is the one that walks/pops
    /// its own stack once released, so there is still never a genuine
    /// concurrent writer.
    pub call_stack: RwLock<Vec<VpCallContext>>,
}

impl CoreContext {
    pub fn new(core_id: u64) -> Self {
        CoreContext {
            core_id,
            binding: RwLock::new(None),
            updates: RwLock::new(VecDeque::new()),
            cached_domains: RwLock::new(BTreeSet::new()),
            call_stack: RwLock::new(Vec::new()),
        }
    }

    /// Check if this core can run the given domain
    pub fn can_run_domain(&self, domain: &Domain) -> bool {
        let core_bit = 1u64 << self.core_id;
        (domain.policy.cores & core_bit) != 0
    }

    /// Get the currently running domain (if any)
    pub fn current_domain(&self) -> Option<u64> {
        self.binding.read().as_ref().map(|b| b.domain.read().data.id)
    }

    /// Get the currently running VP (if any)
    pub fn current_vp(&self) -> Option<u64> {
        self.binding.read().as_ref().map(|b| b.vp_id)
    }

    /// Get a clone of the full current binding (if any).
    pub fn current_binding(&self) -> Option<CoreBinding> {
        self.binding.read().clone()
    }

    /// Bind this core to `domain`/`vp_id`. Called on every switch/interrupt
    /// entry (forward, return, revoke-driven) so this is always the single
    /// authoritative record of what is running here. Also marks `domain` as
    /// possibly-cached on this core (see `cached_domains`).
    pub fn set_binding(&self, domain: CapabilityRef<Domain>, vp_id: u64) {
        let domain_id = domain.read().data.id;
        self.cached_domains.write().insert(domain_id);
        *self.binding.write() = Some(CoreBinding { domain, vp_id });
    }

    /// Mark this core idle (no domain/VP running).
    pub fn clear_binding(&self) {
        *self.binding.write() = None;
    }

    /// Forget that this core may have cached entries for `domain_id`.
    ///
    /// Called after the corresponding `TlbShootdown` has actually been
    /// flushed (see [`crate::domain_api::apply_core_updates`]).
    pub fn clear_cached(&self, domain_id: u64) {
        self.cached_domains.write().remove(&domain_id);
    }

    /// Push a `CoreUpdate` onto this core's queue.
    ///
    /// Called by the initiating core (under the update lock) before sending
    /// the IPI.
    pub fn push_update(&self, update: CoreUpdate) {
        self.updates.write().push_back(update);
    }

    /// Non-blocking drain of all currently-queued updates for this core, in
    /// FIFO order. Returns `None` if the queue is contended (drained
    /// concurrently by the other caller that can race here — see
    /// `apply_core_updates`), in which case the caller should simply do
    /// nothing: whichever caller wins the race handles every entry.
    pub fn try_drain_updates(&self) -> Option<Vec<CoreUpdate>> {
        let mut queue = self.updates.try_write()?;
        Some(queue.drain(..).collect())
    }

    /// Push a new frame (the caller we are switching away from) onto this
    /// core's call chain.
    pub fn push_frame(&self, frame: VpCallContext) {
        self.call_stack.write().push(frame);
    }

    /// Pop and return the most recent frame (the caller to resume), if any.
    pub fn pop_frame(&self) -> Option<VpCallContext> {
        self.call_stack.write().pop()
    }

    /// Peek at the most recent frame without removing it.
    pub fn top_frame(&self) -> Option<VpCallContext> {
        self.call_stack.read().last().cloned()
    }

    /// Peek at the frame `depth` entries below the top, without removing
    /// anything. `depth == 0` is equivalent to [`Self::top_frame`]; `depth
    /// == 1` is the frame that would become the new top after one
    /// `pop_frame()`, and so on. Returns `None` if the stack is shallower
    /// than `depth + 1` frames.
    ///
    /// Read-only cross-check against `VpRunState`'s own `caller`/
    /// `prev_caller` fields, without mutating the stack — prefer this over
    /// `pop_frame()` when the value is only needed for an assertion, so an
    /// unrelated error path elsewhere can't leave the stack popped without
    /// a matching `VpRunState` change.
    pub fn peek_at(&self, depth: usize) -> Option<VpCallContext> {
        let stack = self.call_stack.read();
        let len = stack.len();
        if depth >= len {
            return None;
        }
        stack.get(len - 1 - depth).cloned()
    }
}

/// Switch context for a domain transition
#[derive(Clone)]
pub struct SwitchContext {
    /// Source domain (caller). `None` only for the revoke-return path,
    /// where the source domain is being torn down concurrently by the
    /// initiator and has no meaningful identity to hand back — there is no
    /// bare id substitute for "no source": a `CapabilityRef` is either the
    /// real caller or absent, never a stale/recycled id.
    pub from_domain: Option<CapabilityRef<Domain>>,
    /// Target domain (callee). Always present: every switch/interrupt/
    /// revoke-return path resolves a concrete resume target before
    /// constructing this context.
    pub to_domain: CapabilityRef<Domain>,
    /// Core performing the switch
    pub core_id: u64,
    /// Whether this is a return (switch with no target)
    pub is_return: bool,
    /// VP ID of the source domain (None for non-VP switches)
    pub from_vp_id: Option<u64>,
    /// VP ID of the target domain (None for non-VP switches)
    pub to_vp_id: Option<u64>,
    /// If the target VP was Suspended due to an interrupt, this carries the
    /// interrupt vector.  `do_switch` uses this to set `RDI = vector` on the
    /// SWITCH return rather than `RDI = exit_reason` from a normal child exit.
    /// `None` for all normal SWITCH forward operations.
    pub interrupt_return: Option<u8>,
}

impl core::fmt::Debug for SwitchContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let from_id = self.from_domain.as_ref().map(|d| d.read().data.id);
        let to_id = self.to_domain.read().data.id;
        f.debug_struct("SwitchContext")
            .field("from_domain_id", &from_id)
            .field("to_domain_id", &to_id)
            .field("core_id", &self.core_id)
            .field("is_return", &self.is_return)
            .field("from_vp_id", &self.from_vp_id)
            .field("to_vp_id", &self.to_vp_id)
            .field("interrupt_return", &self.interrupt_return)
            .finish()
    }
}

/// Interrupt context
#[derive(Debug, Clone)]
pub struct InterruptContext {
    /// Interrupt vector number
    pub vector: u8,
    /// Domain that was interrupted
    pub interrupted_domain: u64,
    /// Core that received the interrupt
    pub core_id: u64,
}

/// VP state context returned by [`Capability::deliver_interrupt_vp`].
///
/// Describes the outcome of a VP-aware interrupt delivery using the
/// lazy-unwind model: the interrupted VP is frozen (`Interrupted`), all
/// intermediate VPs are frozen (`Suspended`), and the handler VP is woken
/// to `Running`.
#[derive(Clone)]
pub struct VpInterruptContext {
    /// Domain of the VP that was preempted (leaf of the call chain).
    pub interrupted_domain: CapabilityRef<Domain>,
    /// VP ID within the interrupted domain.
    pub interrupted_vp_id: u64,
    /// Domain of the interrupt handler (DELIVER policy ancestor).
    pub handler_domain: CapabilityRef<Domain>,
    /// VP ID within the handler domain that is now Running.
    pub handler_vp_id: u64,
    /// Core on which the interrupt was delivered.
    pub core_id: u64,
}

impl core::fmt::Debug for VpInterruptContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let interrupted_id = self.interrupted_domain.read().data.id;
        let handler_id = self.handler_domain.read().data.id;
        f.debug_struct("VpInterruptContext")
            .field("interrupted_domain_id", &interrupted_id)
            .field("interrupted_vp_id", &self.interrupted_vp_id)
            .field("handler_domain_id", &handler_id)
            .field("handler_vp_id", &self.handler_vp_id)
            .field("core_id", &self.core_id)
            .finish()
    }
}

/// Switch manager handles domain transitions and interrupt routing
pub struct SwitchManager {
    /// Per-core contexts
    cores: Vec<Arc<CoreContext>>,
}

impl SwitchManager {
    /// Create a new switch manager with the given number of cores
    pub fn new(num_cores: usize) -> Self {
        let mut cores = Vec::new();
        for i in 0..num_cores {
            cores.push(Arc::new(CoreContext::new(i as u64)));
        }
        SwitchManager { cores }
    }

    /// Get the context for a specific core
    pub fn get_core(&self, core_id: u64) -> Result<&Arc<CoreContext>> {
        self.cores
            .get(core_id as usize)
            .ok_or(CapaError::InvalidOperation(format!(
                "Invalid core ID: {}",
                core_id
            )))
    }

    /// Scan every core's binding and return the ones currently running
    /// `domain_id`. Replaces a platform-maintained routing map: this fact is
    /// derived directly from the authoritative per-core bindings, so there
    /// is exactly one place it can ever be tracked.
    pub fn cores_running(&self, domain_id: u64) -> Vec<u64> {
        self.cores
            .iter()
            .filter(|c| c.current_domain() == Some(domain_id))
            .map(|c| c.core_id)
            .collect()
    }

    /// Scan every core's `cached_domains` and return the ones that may have
    /// cached second-stage entries for `domain_id` — the flush target set
    /// for a revoke, replacing a platform-maintained bitmap (see
    /// [`CoreContext::set_binding`]/[`CoreContext::clear_cached`]).
    pub fn cores_with_cached(&self, domain_id: u64) -> Vec<u64> {
        self.cores
            .iter()
            .filter(|c| c.cached_domains.read().contains(&domain_id))
            .map(|c| c.core_id)
            .collect()
    }

    /// Perform a switch from one domain to another
    ///
    /// Returns the switch context for the transition
    pub fn switch(
        &self,
        core_id: u64,
        from: &CapabilityRef<Domain>,
        to: Option<&CapabilityRef<Domain>>,
    ) -> Result<SwitchContext> {
        let core = self.get_core(core_id)?;

        let from_domain = from.read();
        let from_id = from_domain.data.id;

        // Verify the from domain is actually running on this core
        if core.current_domain() != Some(from_id) {
            return Err(CapaError::InvalidOperation(
                "Domain is not running on this core".to_string(),
            ));
        }

        let (_to_id, to_domain_ref, is_return) = if let Some(to_ref) = to {
            let to_domain = to_ref.read();

            // Verify target domain is sealed
            if !to_domain.data.is_sealed() {
                return Err(CapaError::DomainNotSealed);
            }

            // Verify target can run on this core
            if !core.can_run_domain(&to_domain.data) {
                return Err(CapaError::PermissionDenied);
            }

            // Verify target is a direct child or parent of from domain (CDT hierarchy check)
            let is_direct_relationship = {
                // Check if to_domain is a child of from_domain
                let is_child = from_domain
                    .children
                    .iter()
                    .any(|child| Arc::ptr_eq(child, to_ref));

                // Check if to_domain is the parent of from_domain
                let is_parent = from_domain
                    .get_parent()
                    .map(|p| Arc::ptr_eq(&p, to_ref))
                    .unwrap_or(false);

                is_child || is_parent
            };

            if !is_direct_relationship {
                return Err(CapaError::InvalidOperation(
                    "Target domain must be a direct child or parent of the current domain"
                        .to_string(),
                ));
            }

            (to_domain.data.id, to_ref.clone(), false)
        } else {
            // Returning to parent
            let parent_ref = from_domain.get_parent().ok_or(CapaError::InvalidOperation(
                "No parent to return to".to_string(),
            ))?;
            let parent_id = parent_ref.read().data.id;
            (parent_id, parent_ref, true)
        };

        drop(from_domain);

        // Update core binding. This simple, non-VP-aware entry point has no
        // VP identity to track — `vp_id` is always 0 by convention here.
        core.set_binding(to_domain_ref.clone(), 0);

        Ok(SwitchContext {
            from_domain: Some(from.clone()),
            to_domain: to_domain_ref,
            core_id,
            is_return,
            from_vp_id: None,
            to_vp_id: None,
            interrupt_return: None,
        })
    }

    /// Route an interrupt through the domain hierarchy
    ///
    /// Returns the domain ID that should handle the interrupt
    pub fn route_interrupt(
        &self,
        vector: u8,
        interrupted: &CapabilityRef<Domain>,
        _core_id: u64,
    ) -> Result<(u64, Vec<u64>)> {
        find_interrupt_handler(vector, interrupted)
    }

}

/// Walk the domain CDT upward from `interrupted`, applying each ancestor's
/// per-vector [`InterruptVisibility`] policy, until reaching the first
/// `Deliver` domain (the handler).  `Report` ancestors along the way are
/// collected into the returned list; `NotReport` ancestors are skipped.
///
/// This is a pure capability-tree query — it does not touch any VP call
/// state — shared by [`SwitchManager::route_interrupt`] (the simple,
/// non-VP-aware entry point used directly by the CLI simulator and its
/// own unit/integration tests) and by
/// [`crate::domain_api::deliver_interrupt_vp`] (the VP-aware lazy-unwind
/// path), so the "which domain handles this vector" decision has exactly
/// one implementation.
///
/// Under this engine's model, switches only ever cross a domain's direct
/// CDT parent/child edge (see [`SwitchManager::switch`]'s direct-relationship
/// check), so the live VP call chain of any Running VP is always identical
/// in domain sequence to its CDT ancestor chain — `deliver_interrupt_vp`
/// relies on that invariant to cross-check the handler this function finds
/// against the domain it actually reaches by walking VP `caller`/`prev_caller`
/// links.
///
/// Returns [`CapaError::InvalidOperation`] if the root is reached without
/// finding a `Deliver` ancestor.
pub fn find_interrupt_handler(
    vector: u8,
    interrupted: &CapabilityRef<Domain>,
) -> Result<(u64, Vec<u64>)> {
    let mut current_ref = interrupted.clone();
    let mut reported_to = Vec::new();

    loop {
        let current = current_ref.read();
        let policy = current.data.policy.interrupts.get_policy(vector);

        match policy.visibility {
            InterruptVisibility::Deliver => {
                // This domain handles the interrupt
                return Ok((current.data.id, reported_to));
            }
            InterruptVisibility::Report => {
                // Report to this domain but continue walking up
                reported_to.push(current.data.id);
            }
            InterruptVisibility::NotReport => {
                // Skip this domain
            }
        }

        // Move to parent
        let parent = current.get_parent();
        drop(current);

        match parent {
            Some(parent_ref) => current_ref = parent_ref,
            None => {
                // Reached root without finding a handler
                return Err(CapaError::InvalidOperation(
                    "No interrupt handler found".to_string(),
                ));
            }
        }
    }
}
