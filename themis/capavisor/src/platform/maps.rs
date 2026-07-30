//! Per-domain bookkeeping collections shared by the cross-core protocol:
//! the [`DomainTable`] keyed map of `PlatformDomain`s (Tier 2).
//!
//! The per-core update queue and core↔domain routing index (formerly
//! Tier 1/3 here) are now owned entirely by the capability engine's
//! `SwitchManager`/`CoreContext` (see `capability_engine::switch`) — this
//! module only keeps the hardware-state map that has no engine-side
//! equivalent.

extern crate alloc;

use alloc::collections::BTreeMap;
use spin::{Mutex, RwLock};

use capability_engine::DomainId;

use super::domain::PlatformDomain;

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
