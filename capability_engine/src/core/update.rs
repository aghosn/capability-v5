use std::collections::BTreeMap;

use super::{
    capability::{Capability, WeakRef},
    domain::Domain,
    memory_region::{Access, Remapped},
};

// Encodes the updates of memory operations.
pub enum Update {
    // Zero-out a region.
    Clean {
        start: u64,
        size: u64,
    },
    // Add a region to a domain.
    Add {
        dom: WeakRef<Capability<Domain>>,
        access: Access,
        remapped: Remapped,
    },
    // Remove a region from a domain.
    Remove {
        dom: WeakRef<Capability<Domain>>,
        access: Access,
        remapped: Remapped,
    },
    // Revoke a domain.
    Revoke {
        dom: WeakRef<Capability<Domain>>,
    },
}

// This structure maintains updates during an operation and attempts to keep them compact.
pub struct OperationUpdate {
    pub to_clean: Vec<Update>,
    pub per_domain: BTreeMap<WeakRef<Domain>, Vec<Update>>,
}

// TODO: We'll have to see what we do about it.
impl OperationUpdate {}
