//! CLI state management

use capability_engine::*;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use crate::platform::CliPlatform;
use crate::session::Session;

// ─────────────────────────────────────────────────────────────────────────────
// Handle-lookup helpers (pointer-based search in domain capability tables)
// ─────────────────────────────────────────────────────────────────────────────

/// Find the LocalHandle that `domain` holds for `mem` in its memory-capability table.
pub fn find_memory_handle(
    domain: &Arc<RwLock<Capability<Domain>>>,
    mem: &Arc<RwLock<Capability<MemoryRegion>>>,
) -> Option<LocalHandle> {
    let mem_ptr = Arc::as_ptr(mem);
    domain.read().data.memory_capabilities.iter()
        .find(|(_, weak)| {
            weak.upgrade().map(|r| Arc::as_ptr(&r) == mem_ptr).unwrap_or(false)
        })
        .map(|(h, _)| *h)
}

/// Find the LocalHandle that `owner` holds for `child` in its domain-capability table.
pub fn find_domain_handle(
    owner: &Arc<RwLock<Capability<Domain>>>,
    child: &Arc<RwLock<Capability<Domain>>>,
) -> Option<LocalHandle> {
    let child_ptr = Arc::as_ptr(child);
    owner.read().data.domain_capabilities.iter()
        .find(|(_, weak)| {
            weak.upgrade().map(|r| Arc::as_ptr(&r) == child_ptr).unwrap_or(false)
        })
        .map(|(h, _)| *h)
}

/// Search all domains in state for the one that holds `cap` in its domain_capabilities table.
/// Returns `(owner_name, owner_arc, handle)` if found.
pub fn find_domain_owner<'a>(
    state: &'a super::state::CliState,
    cap: &Arc<RwLock<Capability<Domain>>>,
) -> Option<(String, Arc<RwLock<Capability<Domain>>>, LocalHandle)> {
    let cap_ptr = Arc::as_ptr(cap);
    for (name, owner) in &state.domains {
        if let Some(h) = owner.read().data.domain_capabilities.iter()
            .find(|(_, weak)| weak.upgrade().map(|r| Arc::as_ptr(&r) == cap_ptr).unwrap_or(false))
            .map(|(h, _)| *h)
        {
            return Some((name.clone(), owner.clone(), h));
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI State
// ─────────────────────────────────────────────────────────────────────────────

/// CLI state maintaining all capabilities and domains
pub struct CliState {
    /// Map from user-assigned names to domain capabilities
    pub domains: HashMap<String, Arc<RwLock<Capability<Domain>>>>,
    /// Map from user-assigned names to memory capabilities
    pub memories: HashMap<String, Arc<RwLock<Capability<MemoryRegion>>>>,
    /// Platform abstraction (owns SwitchManager)
    pub platform: Arc<CliPlatform>,
    /// Session recorder
    pub session: Session,
    /// Next available capability ID
    next_cap_id: u64,
    /// Map from domain ID to user-assigned name (for reverse lookup)
    pub domain_id_to_name: HashMap<u64, String>,
    /// Number of cores
    pub num_cores: usize,
    /// Auto-list mode: automatically run 'list' after each successful command
    pub auto_list: bool,
}

impl CliState {
    /// Create a new CLI state with the specified number of cores
    pub fn new(num_cores: usize) -> Self {
        CliState {
            domains: HashMap::new(),
            memories: HashMap::new(),
            platform: Arc::new(CliPlatform::new(num_cores)),
            session: Session::new(),
            next_cap_id: 0,
            domain_id_to_name: HashMap::new(),
            num_cores,
            auto_list: false,
        }
    }

    /// Allocate and return the next capability ID
    pub fn next_id(&mut self) -> u64 {
        let id = self.next_cap_id;
        self.next_cap_id += 1;
        id
    }

    /// Get the name of a domain by its ID
    pub fn get_domain_name(&self, domain_id: u64) -> Option<&str> {
        self.domain_id_to_name.get(&domain_id).map(|s| s.as_str())
    }

    /// Register a domain name mapping
    pub fn register_domain_name(&mut self, domain_id: u64, name: String) {
        self.domain_id_to_name.insert(domain_id, name);
    }

    /// Find the Arc for the domain with the given ID.
    pub fn get_domain_cap_by_id(&self, domain_id: u64) -> Option<Arc<RwLock<Capability<Domain>>>> {
        let name = self.domain_id_to_name.get(&domain_id)?;
        self.domains.get(name).cloned()
    }
}
