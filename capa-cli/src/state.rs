//! CLI state management

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use capability_engine::{Capability, Domain, LocalHandle, MemoryRegion};

use crate::backend::{Backend, DomainId, MemCapUid};
use crate::rust_backend::RustBackend;
use crate::session::Session;

// ─────────────────────────────────────────────────────────────────────────────
// Handle-lookup helpers (used internally by RustBackend)
// ─────────────────────────────────────────────────────────────────────────────

/// Find the LocalHandle that `domain` holds for `mem` in its memory-capability table.
pub fn find_memory_handle(
    domain: &Arc<RwLock<Capability<Domain>>>,
    mem: &Arc<RwLock<Capability<MemoryRegion>>>,
) -> Option<LocalHandle> {
    let mem_ptr = Arc::as_ptr(mem);
    domain
        .read()
        .data
        .memory_capabilities
        .iter()
        .find(|(_, weak)| {
            weak.upgrade()
                .map(|r| Arc::as_ptr(&r) == mem_ptr)
                .unwrap_or(false)
        })
        .map(|(h, _)| *h)
}

/// Find the LocalHandle that `owner` holds for `child` in its domain-capability table.
pub fn find_domain_handle(
    owner: &Arc<RwLock<Capability<Domain>>>,
    child: &Arc<RwLock<Capability<Domain>>>,
) -> Option<LocalHandle> {
    let child_ptr = Arc::as_ptr(child);
    owner
        .read()
        .data
        .domain_capabilities
        .iter()
        .find(|(_, weak)| {
            weak.upgrade()
                .map(|r| Arc::as_ptr(&r) == child_ptr)
                .unwrap_or(false)
        })
        .map(|(h, _)| *h)
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI State
// ─────────────────────────────────────────────────────────────────────────────

/// CLI state — holds only name→ID maps; the backend owns all engine state.
pub struct CliState {
    /// Map from user-assigned names to domain IDs
    pub domain_names: HashMap<String, DomainId>,
    /// Map from user-assigned names to memory capability UIDs
    pub mem_names: HashMap<String, MemCapUid>,
    /// Map from memory capability UID to its owning domain ID
    pub mem_owners: HashMap<MemCapUid, DomainId>,
    /// Map from child domain ID to parent domain ID
    pub domain_parents: HashMap<DomainId, DomainId>,
    /// Map from domain ID to user-assigned name (reverse lookup)
    pub domain_id_to_name: HashMap<DomainId, String>,
    /// Backend implementation (owns all engine state)
    pub backend: Box<dyn Backend + Send + Sync>,
    /// Session recorder
    pub session: Session,
    /// Number of cores
    pub num_cores: usize,
    /// Auto-list mode: automatically run 'list' after each successful command
    pub auto_list: bool,
}

impl CliState {
    /// Create a new CLI state with the specified number of cores
    pub fn new(num_cores: usize) -> Self {
        CliState {
            domain_names: HashMap::new(),
            mem_names: HashMap::new(),
            mem_owners: HashMap::new(),
            domain_parents: HashMap::new(),
            domain_id_to_name: HashMap::new(),
            backend: Box::new(RustBackend::new(num_cores)),
            session: Session::new(),
            num_cores,
            auto_list: false,
        }
    }

    /// Get the name of a domain by its ID
    pub fn get_domain_name(&self, domain_id: DomainId) -> Option<&str> {
        self.domain_id_to_name.get(&domain_id).map(|s| s.as_str())
    }

    /// Register a domain name mapping (both directions)
    pub fn register_domain_name(&mut self, domain_id: DomainId, name: String) {
        self.domain_id_to_name.insert(domain_id, name.clone());
        self.domain_names.insert(name, domain_id);
    }
}
