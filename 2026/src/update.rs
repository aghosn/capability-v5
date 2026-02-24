//! Update tracking for domain address space modifications

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

/// A domain identifier
pub type DomainId = u64;

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

    /// Revoke a domain entirely
    RevokeDomain {
        domain: DomainId,
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
            | Update::RevokeDomain { domain }
            | Update::FlushTLB { domain } => Some(*domain),
            Update::ZeroMemory { .. } => None,
        }
    }
}

/// A batch of updates that should be applied atomically
#[derive(Debug, Default)]
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

    /// Add domain revocation
    pub fn add_revoke_domain(&mut self, domain: DomainId) {
        self.add(Update::RevokeDomain { domain });
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

