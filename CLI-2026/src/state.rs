//! CLI state management

use capability_engine::*;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use crate::session::Session;

/// CLI state maintaining all capabilities and domains
pub struct CliState {
    /// Map from user-assigned names to domain capabilities
    pub domains: HashMap<String, Arc<RwLock<Capability<Domain>>>>,
    /// Map from user-assigned names to memory capabilities
    pub memories: HashMap<String, Arc<RwLock<Capability<MemoryRegion>>>>,
    /// Switch manager for domain switching
    pub switch_manager: SwitchManager,
    /// Session recorder
    pub session: Session,
    /// Next available capability ID
    next_cap_id: u64,
    /// Map from domain ID to user-assigned name (for reverse lookup)
    pub domain_id_to_name: HashMap<u64, String>,
    /// Number of cores
    pub num_cores: usize,
}

impl CliState {
    /// Create a new CLI state with the specified number of cores
    pub fn new(num_cores: usize) -> Self {
        CliState {
            domains: HashMap::new(),
            memories: HashMap::new(),
            switch_manager: SwitchManager::new(num_cores),
            session: Session::new(),
            next_cap_id: 0,
            domain_id_to_name: HashMap::new(),
            num_cores,
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
}
