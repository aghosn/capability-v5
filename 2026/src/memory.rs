//! Memory capabilities and related types

use crate::error::{CapaError, Result};
use alloc::vec::Vec;
use core::fmt;

/// Access rights for memory regions
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rights {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Rights {
    pub const NONE: Self = Rights {
        read: false,
        write: false,
        execute: false,
    };

    pub const R: Self = Rights {
        read: true,
        write: false,
        execute: false,
    };

    pub const RW: Self = Rights {
        read: true,
        write: true,
        execute: false,
    };

    pub const RX: Self = Rights {
        read: true,
        write: false,
        execute: true,
    };

    pub const RWX: Self = Rights {
        read: true,
        write: true,
        execute: true,
    };

    /// Check if self is a subset of other (for monotonicity)
    pub fn is_subset_of(&self, other: &Rights) -> bool {
        (!self.read || other.read)
            && (!self.write || other.write)
            && (!self.execute || other.execute)
    }

    /// Compute intersection of rights
    pub fn intersect(&self, other: &Rights) -> Rights {
        Rights {
            read: self.read && other.read,
            write: self.write && other.write,
            execute: self.execute && other.execute,
        }
    }
}

impl fmt::Display for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}",
            if self.read { "R" } else { "-" },
            if self.write { "W" } else { "-" },
            if self.execute { "X" } else { "-" }
        )
    }
}

/// Memory region attributes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Attributes {
    /// Region content is hashed and verified
    pub hash: bool,
    /// Region is zeroed on revocation
    pub clean: bool,
    /// Revocation of this region causes domain revocation
    pub vital: bool,
    /// Region is used for metadata storage
    pub meta: bool,
}

impl Attributes {
    pub const NONE: Self = Attributes {
        hash: false,
        clean: false,
        vital: false,
        meta: false,
    };
}

impl fmt::Display for Attributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut attrs = Vec::new();
        if self.hash {
            attrs.push("HASH");
        }
        if self.clean {
            attrs.push("CLEAN");
        }
        if self.vital {
            attrs.push("VITAL");
        }
        if self.meta {
            attrs.push("META");
        }
        write!(f, "{}", attrs.join("|"))
    }
}

/// Status of a memory region
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionStatus {
    /// Region has exclusive access (carved from exclusive parent)
    Exclusive,
    /// Region is aliased (shared with parent or siblings)
    Aliased,
}

/// Kind of memory region creation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// Created via alias operation
    Alias,
    /// Created via carve operation
    Carve,
}

/// Physical address remapping information
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Remapped {
    /// Identity mapping (virtual == physical)
    Identity,
    /// Remapped to specific physical address
    Remapped(u64),
}

/// Memory access descriptor
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Access {
    /// Virtual start address
    pub start: u64,
    /// Size in bytes
    pub size: u64,
    /// Access rights
    pub rights: Rights,
}

impl Access {
    /// Create a new access descriptor
    pub fn new(start: u64, size: u64, rights: Rights) -> Self {
        Access { start, size, rights }
    }

    /// Get end address (exclusive)
    pub fn end(&self) -> u64 {
        self.start + self.size
    }

    /// Check if this access range is fully contained within another
    pub fn contained_in(&self, other: &Access) -> bool {
        self.start >= other.start && self.end() <= other.end()
    }

    /// Check if two access ranges overlap
    pub fn overlaps(&self, other: &Access) -> bool {
        !(self.end() <= other.start || self.start >= other.end())
    }

    /// Check if rights are subset of other
    pub fn rights_subset_of(&self, other: &Access) -> bool {
        self.rights.is_subset_of(&other.rights)
    }
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:#x}..{:#x}) {}",
            self.start,
            self.end(),
            self.rights
        )
    }
}

/// Memory region capability data
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// How this region was created
    pub kind: RegionKind,
    /// Exclusive or aliased status
    pub status: RegionStatus,
    /// Access descriptor
    pub access: Access,
    /// Security attributes
    pub attributes: Attributes,
    /// Physical address remapping
    pub remapped: Remapped,
    /// Hash of region content (if hash attribute is set)
    pub content_hash: Option<[u8; 32]>,
}

impl MemoryRegion {
    /// Create a new exclusive root memory region
    pub fn new_root(start: u64, size: u64) -> Self {
        MemoryRegion {
            kind: RegionKind::Carve,
            status: RegionStatus::Exclusive,
            access: Access::new(start, size, Rights::RWX),
            attributes: Attributes::NONE,
            remapped: Remapped::Identity,
            content_hash: None,
        }
    }

    /// Create an aliased child region
    pub fn alias(&self, access: Access) -> Result<Self> {
        // Validate access is within parent
        if !access.contained_in(&self.access) {
            return Err(CapaError::InvalidAccess);
        }

        // Validate rights are subset
        if !access.rights_subset_of(&self.access) {
            return Err(CapaError::InvalidAccess);
        }

        // Compute remapping for child
        let child_remapped = match self.remapped {
            Remapped::Identity => Remapped::Identity,
            Remapped::Remapped(phys) => {
                let offset = access.start - self.access.start;
                Remapped::Remapped(phys + offset)
            }
        };

        Ok(MemoryRegion {
            kind: RegionKind::Alias,
            status: RegionStatus::Aliased,
            access,
            attributes: Attributes::NONE,
            remapped: child_remapped,
            content_hash: None,
        })
    }

    /// Create a carved child region
    pub fn carve(&self, access: Access) -> Result<Self> {
        // Validate access is within parent
        if !access.contained_in(&self.access) {
            return Err(CapaError::InvalidAccess);
        }

        // Validate rights are subset
        if !access.rights_subset_of(&self.access) {
            return Err(CapaError::InvalidAccess);
        }

        // Compute remapping for child
        let child_remapped = match self.remapped {
            Remapped::Identity => Remapped::Identity,
            Remapped::Remapped(phys) => {
                let offset = access.start - self.access.start;
                Remapped::Remapped(phys + offset)
            }
        };

        // Carved child inherits parent's status
        Ok(MemoryRegion {
            kind: RegionKind::Carve,
            status: self.status,
            access,
            attributes: Attributes::NONE,
            remapped: child_remapped,
            content_hash: None,
        })
    }

    /// Set attributes when sending to another domain
    pub fn with_attributes(mut self, attributes: Attributes) -> Self {
        self.attributes = attributes;
        self
    }

    /// Set content hash
    pub fn with_hash(mut self, hash: [u8; 32]) -> Self {
        self.content_hash = Some(hash);
        self
    }
}

impl fmt::Display for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MemoryRegion {{ {:?} {:?} {} attrs:{} }}",
            self.kind, self.status, self.access, self.attributes
        )
    }
}

