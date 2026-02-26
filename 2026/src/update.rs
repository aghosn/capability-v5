//! Update tracking for domain address space modifications

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::sync::RwLock;

/// A domain identifier
pub type DomainId = u64;

/// Core identifier
pub type CoreId = u64;

/// Types of updates that affect domain address spaces
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Update {
    /// Unmap a memory range in a domain
    Unmap {
        domain: DomainId,
        address: u64,
        size: u64,
    },

    /// Map a memory range in a domain
    Map {
        domain: DomainId,
        address: u64,
        size: u64,
        physical: u64,
        read: bool,
        write: bool,
        execute: bool,
    },

    /// Change access rights for a memory range
    ChangeRights {
        domain: DomainId,
        address: u64,
        size: u64,
        read: bool,
        write: bool,
        execute: bool,
    },

    /// Zero memory region (for clean attribute)
    ZeroMemory {
        address: u64,
        size: u64,
    },

    /// Revoke a domain entirely.
    /// `fallback` is the first non-revoked ancestor domain ID computed by the
    /// capability engine. If `None`, the platform must look up the parent from
    /// its own domain-parent map (used when revocation originates from a vital
    /// memory capability where the engine has no domain CDT context).
    RevokeDomain {
        domain: DomainId,
        fallback: Option<DomainId>,
    },

    /// Flush TLB for a domain
    FlushTLB {
        domain: DomainId,
    },
}

impl Update {
    /// Get the domain ID affected by this update (if applicable)
    pub fn affected_domain(&self) -> Option<DomainId> {
        match self {
            Update::Unmap { domain, .. }
            | Update::Map { domain, .. }
            | Update::ChangeRights { domain, .. }
            | Update::RevokeDomain { domain, .. }
            | Update::FlushTLB { domain } => Some(*domain),
            Update::ZeroMemory { .. } => None,
        }
    }
}

/// A batch of updates that should be applied atomically
#[derive(Debug, Default, Clone)]
pub struct UpdateBatch {
    /// List of updates to apply
    updates: Vec<Update>,

    /// Domains affected by these updates
    affected_domains: BTreeSet<DomainId>,

    /// Snapshot of domain states before updates (for rollback)
    snapshots: BTreeMap<DomainId, Vec<u8>>,
}

impl UpdateBatch {
    /// Create a new empty update batch
    pub fn new() -> Self {
        UpdateBatch::default()
    }

    /// Add an update to the batch
    pub fn add(&mut self, update: Update) {
        if let Some(domain) = update.affected_domain() {
            self.affected_domains.insert(domain);
        }
        self.updates.push(update);
    }

    /// Add multiple unmap operations
    pub fn add_unmap(&mut self, domain: DomainId, address: u64, size: u64) {
        self.add(Update::Unmap {
            domain,
            address,
            size,
        });
    }

    /// Add multiple map operations
    pub fn add_map(
        &mut self,
        domain: DomainId,
        address: u64,
        size: u64,
        physical: u64,
        read: bool,
        write: bool,
        execute: bool,
    ) {
        self.add(Update::Map {
            domain,
            address,
            size,
            physical,
            read,
            write,
            execute,
        });
    }

    /// Add domain revocation with no pre-computed fallback (platform looks up parent)
    pub fn add_revoke_domain(&mut self, domain: DomainId) {
        self.add_revoke_domain_with_fallback(domain, None);
    }

    /// Add domain revocation with an explicit fallback domain.
    /// `fallback` is the first non-revoked ancestor; passed to the platform's
    /// `on_domain_revoked` so it can redirect any core running `domain` without
    /// needing CDT access. Must be `None` for vital-memory-triggered revocations.
    pub fn add_revoke_domain_with_fallback(&mut self, domain: DomainId, fallback: Option<DomainId>) {
        self.add(Update::RevokeDomain { domain, fallback });
    }

    /// Add memory zeroing (for clean attribute)
    pub fn add_zero_memory(&mut self, address: u64, size: u64) {
        self.add(Update::ZeroMemory { address, size });
    }

    /// Get all updates in the batch
    pub fn updates(&self) -> &[Update] {
        &self.updates
    }

    /// Get all affected domains
    pub fn affected_domains(&self) -> &BTreeSet<DomainId> {
        &self.affected_domains
    }

    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.updates.is_empty()
    }

    /// Get the number of updates
    pub fn len(&self) -> usize {
        self.updates.len()
    }

    /// Clear all updates
    pub fn clear(&mut self) {
        self.updates.clear();
        self.affected_domains.clear();
        self.snapshots.clear();
    }

    /// Merge another batch into this one
    pub fn merge(&mut self, other: UpdateBatch) {
        self.updates.extend(other.updates);
        self.affected_domains.extend(other.affected_domains);
        self.snapshots.extend(other.snapshots);
    }
}

/// Status of an update on a specific core
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateStatus {
    /// Update is pending and needs to be processed
    Pending,
    /// Update is being processed
    InProgress,
    /// Update has been completed
    Completed,
}

/// Per-core update queue entry
#[derive(Debug, Clone)]
pub struct CoreUpdate {
    /// The update batch
    pub batch: UpdateBatch,
    /// Status of this update on this core
    pub status: UpdateStatus,
}

/// Update processor that manages distributing updates to cores
pub struct UpdateProcessor {
    /// Mapping from core ID to pending updates
    core_queues: Arc<RwLock<BTreeMap<CoreId, Vec<CoreUpdate>>>>,
    /// Mapping from domain ID to currently running core (if any)
    domain_to_core: Arc<RwLock<BTreeMap<DomainId, CoreId>>>,
}

impl UpdateProcessor {
    /// Create a new update processor
    pub fn new() -> Self {
        UpdateProcessor {
            core_queues: Arc::new(RwLock::new(BTreeMap::new())),
            domain_to_core: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    /// Register a domain as running on a specific core
    pub fn register_domain_on_core(&self, domain_id: DomainId, core_id: CoreId) {
        let mut mapping = self.domain_to_core.write();
        mapping.insert(domain_id, core_id);
    }

    /// Unregister a domain from its core (domain stopped running)
    pub fn unregister_domain(&self, domain_id: DomainId) {
        let mut mapping = self.domain_to_core.write();
        mapping.remove(&domain_id);
    }

    /// Get the core a domain is currently running on
    pub fn get_domain_core(&self, domain_id: DomainId) -> Option<CoreId> {
        let mapping = self.domain_to_core.read();
        mapping.get(&domain_id).copied()
    }

    /// Submit an update batch for processing
    /// Returns the set of cores that need to process this update
    pub fn submit_updates(&self, batch: UpdateBatch) -> BTreeSet<CoreId> {
        let mut cores_to_notify = BTreeSet::new();
        let mapping = self.domain_to_core.read();

        // Find which cores are running affected domains
        for domain_id in batch.affected_domains() {
            if let Some(core_id) = mapping.get(domain_id) {
                cores_to_notify.insert(*core_id);
            }
        }

        drop(mapping);

        // Add update to each affected core's queue
        let mut queues = self.core_queues.write();
        for core_id in &cores_to_notify {
            let queue = queues.entry(*core_id).or_insert_with(Vec::new);
            queue.push(CoreUpdate {
                batch: batch.clone(),
                status: UpdateStatus::Pending,
            });
        }

        cores_to_notify
    }

    /// Get pending updates for a specific core
    pub fn get_pending_updates(&self, core_id: CoreId) -> Vec<CoreUpdate> {
        let queues = self.core_queues.read();
        queues
            .get(&core_id)
            .map(|q| {
                q.iter()
                    .filter(|u| matches!(u.status, UpdateStatus::Pending))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Mark an update as in progress for a core
    pub fn mark_in_progress(&self, core_id: CoreId, batch_index: usize) -> bool {
        let mut queues = self.core_queues.write();
        if let Some(queue) = queues.get_mut(&core_id) {
            if let Some(update) = queue.get_mut(batch_index) {
                if matches!(update.status, UpdateStatus::Pending) {
                    update.status = UpdateStatus::InProgress;
                    return true;
                }
            }
        }
        false
    }

    /// Mark an update as completed for a core
    pub fn mark_completed(&self, core_id: CoreId, batch_index: usize) -> bool {
        let mut queues = self.core_queues.write();
        if let Some(queue) = queues.get_mut(&core_id) {
            if let Some(update) = queue.get_mut(batch_index) {
                update.status = UpdateStatus::Completed;
                return true;
            }
        }
        false
    }

    /// Clean completed updates from a core's queue
    pub fn clean_completed(&self, core_id: CoreId) {
        let mut queues = self.core_queues.write();
        if let Some(queue) = queues.get_mut(&core_id) {
            queue.retain(|u| !matches!(u.status, UpdateStatus::Completed));
        }
    }

    /// Check if a core has any pending updates
    pub fn has_pending_updates(&self, core_id: CoreId) -> bool {
        let queues = self.core_queues.read();
        queues
            .get(&core_id)
            .map(|q| q.iter().any(|u| matches!(u.status, UpdateStatus::Pending)))
            .unwrap_or(false)
    }

    /// Get all cores with pending updates
    pub fn get_cores_with_pending_updates(&self) -> Vec<CoreId> {
        let queues = self.core_queues.read();
        queues
            .iter()
            .filter(|(_, q)| q.iter().any(|u| matches!(u.status, UpdateStatus::Pending)))
            .map(|(core_id, _)| *core_id)
            .collect()
    }
}

impl Default for UpdateProcessor {
    fn default() -> Self {
        Self::new()
    }
}

