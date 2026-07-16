//! Bootstrap-phase escape hatch for applying [`UpdateBatch`]es that are
//! constructed *outside* the domain-mediated API.
//!
//! # Purpose
//!
//! Every hardware-affecting operation must flow through
//! [`crate::platform::execute`] so the capability engine can validate the
//! transition, take the shared/exclusive cap lock, and coordinate cross-core
//! IPI/barrier synchronisation before touching hardware (axiom A1).
//!
//! During capavisor bring-up we need to *seed* dom0's initial EPT (identity
//! map of dom0-owned RAM + passthrough MMIO/ACPI regions) before any domain
//! is scheduled.  These initial updates are hand-crafted [`UpdateBatch`]es
//! that do not correspond to any `Capability::…` operation, so they cannot
//! be produced by the normal domain-mediated API.
//!
//! [`apply_initial_updates`] is the *only* sanctioned way to apply such a
//! raw batch.  It is a thin wrapper around [`crate::platform::execute`]
//! that emphasises the caller is in the pre-domain bring-up phase.
//!
//! # Invariants
//!
//! - Must be called before any child domain is created or scheduled.
//! - The batch is applied under the shared cap lock; boot code runs
//!   single-threaded so the shared lock is sufficient.
//! - This entry point is *grep-visible*: every use of it is a documented
//!   A1-exempt bring-up site and must be justified in the calling code.
//!
//! # Non-goals
//!
//! This is **not** a general-purpose "apply a batch" API.  Post-bring-up,
//! every hardware mutation must be initiated by a `Capability::…` method,
//! which internally handles [`execute`].

use crate::error::Result;
use crate::platform::{execute, Platform};
use crate::update::UpdateBatch;

/// Apply a hand-crafted [`UpdateBatch`] during capavisor bring-up.
///
/// See the [module docs](self) for the invariants callers must uphold.
///
/// # Errors
///
/// Propagates any error from [`crate::platform::execute`] (lock acquisition
/// or platform-side `apply_update` failures).
pub fn apply_initial_updates(platform: &dyn Platform, batch: UpdateBatch) -> Result<()> {
    execute(platform, false, || Ok(((), batch))).map(|_| ())
}
