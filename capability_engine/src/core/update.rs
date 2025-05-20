use super::{
    capability::{Capability, WeakRef},
    domain::Domain,
    memory_region::{Remapped, Rights},
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
        start: u64,
        size: u64,
        rights: Rights,
        remapped: Remapped,
    },
    // Remove a region from a domain.
    Remove {
        dom: WeakRef<Capability<Domain>>,
        start: u64,
        size: u64,
        rights: Rights,
        remapped: Remapped,
    },
    // Revoke a domain.
    Revoke {
        dom: WeakRef<Capability<Domain>>,
    },
}
