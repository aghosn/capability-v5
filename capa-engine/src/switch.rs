//! Switch and interrupt routing mechanisms

use crate::capability::CapabilityRef;
use crate::domain::{Domain, InterruptVisibility};
use crate::error::{CapaError, Result};
use crate::sync::RwLock;
use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// Core state tracking which domain is running
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreState {
    /// Core is idle
    Idle,
    /// Core is running a domain
    Running(u64), // domain_id
}

/// Per-core execution context
pub struct CoreContext {
    /// Current state of the core
    pub state: RwLock<CoreState>,
    /// Core ID
    pub core_id: u64,
    /// Which VP (by ID) is currently executing on this core, if any.
    pub running_vp: RwLock<Option<u64>>,
}

impl CoreContext {
    pub fn new(core_id: u64) -> Self {
        CoreContext {
            state: RwLock::new(CoreState::Idle),
            core_id,
            running_vp: RwLock::new(None),
        }
    }

    /// Check if this core can run the given domain
    pub fn can_run_domain(&self, domain: &Domain) -> bool {
        let core_bit = 1u64 << self.core_id;
        (domain.policy.cores & core_bit) != 0
    }

    /// Get the currently running domain (if any)
    pub fn current_domain(&self) -> Option<u64> {
        match *self.state.read() {
            CoreState::Running(domain_id) => Some(domain_id),
            CoreState::Idle => None,
        }
    }
}

/// Switch context for a domain transition
#[derive(Debug, Clone)]
pub struct SwitchContext {
    /// Source domain ID (caller)
    pub from_domain: u64,
    /// Target domain ID (callee)
    pub to_domain: u64,
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
#[derive(Debug, Clone)]
pub struct VpInterruptContext {
    /// Domain ID of the VP that was preempted (leaf of the call chain).
    pub interrupted_domain_id: u64,
    /// VP ID within the interrupted domain.
    pub interrupted_vp_id: u64,
    /// Domain ID of the interrupt handler (DELIVER policy ancestor).
    pub handler_domain_id: u64,
    /// VP ID within the handler domain that is now Running.
    pub handler_vp_id: u64,
    /// Core on which the interrupt was delivered.
    pub core_id: u64,
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

        let (to_id, is_return) = if let Some(to_ref) = to {
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

            (to_domain.data.id, false)
        } else {
            // Returning to parent
            let parent_ref = from_domain.get_parent().ok_or(CapaError::InvalidOperation(
                "No parent to return to".to_string(),
            ))?;
            let parent_id = parent_ref.read().data.id;
            (parent_id, true)
        };

        drop(from_domain);

        // Update core state
        *core.state.write() = CoreState::Running(to_id);

        Ok(SwitchContext {
            from_domain: from_id,
            to_domain: to_id,
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
