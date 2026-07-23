//! Per-domain bookkeeping collections shared by the cross-core protocol:
//! the [`CoreUpdate`] command queue payload (Tier 1), the
//! [`DomainTable`] keyed map of `PlatformDomain`s (Tier 2), and the
//! [`RoutingMaps`] core↔domain reverse index (Tier 3).

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use spin::{Mutex, RwLock};

use capability_engine::{CapabilityRef, CoreId, Domain, DomainId};

use super::domain::PlatformDomain;

// ── Per-core update command ───────────────────────────────────────────────── //

/// Command pushed by the initiating core into a target core's update queue,
/// consumed by that core between barriers 0 and 1 in `poll_and_respond_cross_core`.
///
#[derive(Clone)]
pub enum CoreUpdate {
    /// Flush per-LP second-stage cache for `domain` using the provided
    /// `handle` (arch-specific: x86 EPTP, ARM VMID-derived; see
    /// [`crate::arch_traits::ArchDomain::slat`]).
    ///
    /// The handle is snapshotted at queue time so the receiver can flush
    /// without holding any reference to (a possibly-revoked) `domain`.
    /// `domain` is also carried so the receiver can clear its own bit in
    /// `PlatformDomain::cached_on` after flushing — a best-effort cleanup
    /// (silently skipped if the domain was already revoked).
    TlbShootdown { domain: DomainId, handle: u64 },
    /// Atomically switch this core off its doomed VP. The resume target is
    /// resolved locally by the receiving core itself (see
    /// `Capability::switch_after_callee_revoked`), not carried here — see
    /// module doc / `CoreSwitch` (capa-engine) for why.
    Switch {
        source_cap: CapabilityRef<Domain>,
        source_vp: u32,
    },
}

impl core::fmt::Debug for CoreUpdate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CoreUpdate::TlbShootdown { domain, handle } => write!(
                f,
                "TlbShootdown {{ domain: {:?}, handle: {:#x} }}",
                domain, handle
            ),
            CoreUpdate::Switch { source_vp, .. } => {
                write!(f, "Switch {{ source_vp: {} }}", source_vp)
            }
        }
    }
}
// ── Domain table (Tier 2) ─────────────────────────────────────────────────── //

pub(super) struct DomainTable {
    pub(super) map: RwLock<BTreeMap<DomainId, alloc::sync::Arc<Mutex<PlatformDomain>>>>,
}

impl DomainTable {
    pub(super) fn new() -> Self {
        DomainTable {
            map: RwLock::new(BTreeMap::new()),
        }
    }

    pub(super) fn get(&self, id: DomainId) -> Option<alloc::sync::Arc<Mutex<PlatformDomain>>> {
        self.map.read().get(&id).cloned()
    }

    pub(super) fn insert(&self, id: DomainId, domain: PlatformDomain) {
        self.map
            .write()
            .insert(id, alloc::sync::Arc::new(Mutex::new(domain)));
    }

    pub(super) fn remove(&self, id: DomainId) -> Option<PlatformDomain> {
        self.map
            .write()
            .remove(&id)
            .and_then(|arc| alloc::sync::Arc::try_unwrap(arc).ok())
            .map(|m| m.into_inner())
    }

    pub(super) fn contains(&self, id: DomainId) -> bool {
        self.map.read().contains_key(&id)
    }
}
// ── Routing maps (Tier 3) ─────────────────────────────────────────────────── //

pub(super) struct RoutingMaps {
    pub(super) core_to_domain: BTreeMap<CoreId, DomainId>,
    pub(super) domain_to_cores: BTreeMap<DomainId, BTreeSet<CoreId>>,
}

impl RoutingMaps {
    pub(super) fn new() -> Self {
        RoutingMaps {
            core_to_domain: BTreeMap::new(),
            domain_to_cores: BTreeMap::new(),
        }
    }
}
