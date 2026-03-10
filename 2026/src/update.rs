//! Update tracking for domain address space modifications

use crate::memory::Rights;
use crate::sync::RwLock;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

/// A domain identifier
pub type DomainId = u64;

/// Core identifier
pub type CoreId = u64;

/// Types of updates that affect domain address spaces
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Update {
    /// Set access rights for a memory range in a domain.
    /// `rights == Rights::NONE` means no access (full unmap).
    /// `shootdown_required` must be `true` when rights are being reduced or the
    /// mapping is being fully removed — the platform must perform a TLB shootdown
    /// before allowing any receiver to proceed.
    /// `shootdown_required` must be `false` for additive changes (new mapping or
    /// rights upgrade) — no shootdown needed.
    /// `physical` is the backing physical address; ignored by the platform when
    /// `rights == Rights::NONE`.
    ///
    /// NOTE (#7): `physical` is currently always set equal to the virtual `address`
    /// (identity-map assumption). This is correct for the current identity-mapped
    /// deployment but must be revisited for non-identity-mapped platforms.
    ChangeRights {
        domain: DomainId,
        address: u64,
        size: u64,
        physical: u64,
        rights: Rights,
        shootdown_required: bool,
        /// Authorized cache colors for this range.
        #[cfg(feature = "cache_coloring")]
        colors: Option<crate::translation::ColorBitmap>,
    },

    /// Zero memory region (for clean attribute)
    ZeroMemory { address: u64, size: u64 },

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
    FlushTLB { domain: DomainId },

    /// A new domain was created.  The platform must initialise hardware state
    /// (domain registry entry, empty frame allocator) for this domain.
    CreateDomain {
        domain_id: DomainId,
        parent_id: Option<DomainId>,
    },

    /// A META-flagged memory region was transferred to `domain_id`.
    /// The platform must add `[start, start+size)` to the domain's frame
    /// allocator so it can be used for EPT page-table pages etc.
    GiveMetaMem {
        domain_id: DomainId,
        start: u64,
        size: u64,
    },

    /// A COMM region was registered by `domain_id` (the parent/owner).
    /// `target_domain_id` is the child domain it is bound to, `vp_id` is the VP index.
    /// The platform must map `[phys, phys+size)` into its own address space
    /// (e.g. via HHDM) so it can read/write the domain's communication buffer.
    CommRegion {
        domain_id: DomainId,
        target_domain_id: DomainId,
        vp_id: u32,
        phys: u64,
        size: u64,
    },

    /// A COMM region was unregistered or revoked for `domain_id` (the parent/owner).
    /// The platform must unmap its own access to `[phys, phys+size)`.
    UncommRegion {
        domain_id: DomainId,
        target_domain_id: DomainId,
        vp_id: u32,
        phys: u64,
        size: u64,
    },
}

impl Update {
    /// Get the domain ID affected by this update (if applicable)
    pub fn affected_domain(&self) -> Option<DomainId> {
        match self {
            Update::ChangeRights { domain, .. }
            | Update::RevokeDomain { domain, .. }
            | Update::FlushTLB { domain } => Some(*domain),
            Update::CreateDomain { domain_id, .. }
            | Update::GiveMetaMem { domain_id, .. } => Some(*domain_id),
            // CommRegion/UncommRegion affect only the platform's own mappings,
            // not the domain's EPT — no IPI needed.
            Update::CommRegion { .. } | Update::UncommRegion { .. } => None,
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

    /// Add domain revocation with no pre-computed fallback (platform looks up parent)
    pub fn add_revoke_domain(&mut self, domain: DomainId) {
        self.add_revoke_domain_with_fallback(domain, None);
    }

    /// Add domain revocation with an explicit fallback domain.
    /// `fallback` is the first non-revoked ancestor; passed to the platform's
    /// `on_domain_revoked` so it can redirect any core running `domain` without
    /// needing CDT access. Must be `None` for vital-memory-triggered revocations.
    pub fn add_revoke_domain_with_fallback(
        &mut self,
        domain: DomainId,
        fallback: Option<DomainId>,
    ) {
        self.add(Update::RevokeDomain { domain, fallback });
    }

    /// Add memory zeroing (for clean attribute)
    pub fn add_zero_memory(&mut self, address: u64, size: u64) {
        self.add(Update::ZeroMemory { address, size });
    }

    /// Add a change-rights update for a memory range
    pub fn add_change_rights(
        &mut self,
        domain: DomainId,
        address: u64,
        size: u64,
        physical: u64,
        rights: Rights,
        shootdown_required: bool,
    ) {
        self.add(Update::ChangeRights {
            domain,
            address,
            size,
            physical,
            rights,
            shootdown_required,
            #[cfg(feature = "cache_coloring")]
            colors: None,
        });
    }

    /// Add a create-domain update.
    pub fn add_create_domain(&mut self, domain_id: DomainId, parent_id: Option<DomainId>) {
        self.add(Update::CreateDomain { domain_id, parent_id });
    }

    /// Add a give-meta-mem update.
    pub fn add_give_meta_mem(&mut self, domain_id: DomainId, start: u64, size: u64) {
        self.add(Update::GiveMetaMem { domain_id, start, size });
    }

    /// Add a comm-region update (COMM page registered by a domain, bound to a child VP).
    pub fn add_comm_region(
        &mut self,
        domain_id: DomainId,
        target_domain_id: DomainId,
        vp_id: u32,
        phys: u64,
        size: u64,
    ) {
        self.add(Update::CommRegion { domain_id, target_domain_id, vp_id, phys, size });
    }

    /// Add an uncomm-region update (COMM page unregistered or revoked).
    pub fn add_uncomm_region(
        &mut self,
        domain_id: DomainId,
        target_domain_id: DomainId,
        vp_id: u32,
        phys: u64,
        size: u64,
    ) {
        self.add(Update::UncommRegion { domain_id, target_domain_id, vp_id, phys, size });
    }

    /// Get all updates in the batch
    pub fn updates(&self) -> &[Update] {
        &self.updates
    }

    /// Rewrite `ChangeRights.address` from HPA to GPA for one domain.
    ///
    /// Searches the domain's [`AddressMap`] (both `Mapped` and `Blocked`
    /// entries) for the matching HPA and replaces the `address` field
    /// with the corresponding GPA.  Updates whose HPA has no translation
    /// are left unchanged (identity mapping fallback).
    #[cfg(feature = "address_translation")]
    pub fn fixup_domain_addresses(
        &mut self,
        domain_id: DomainId,
        map: &crate::translation::AddressMap,
    ) {
        for update in &mut self.updates {
            if let Update::ChangeRights {
                domain,
                address,
                size,
                physical,
                ..
            } = update
            {
                if *domain == domain_id {
                    if let Some(gpa) = map.find_gpa_for_hpa(*physical, *size) {
                        *address = gpa;
                    }
                }
            }
        }
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
