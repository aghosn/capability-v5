//! Memory capabilities and related types

use crate::error::{CapaError, Result};
use alloc::vec::Vec;
use core::fmt;

/// Access rights for memory regions (bitmap representation)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rights {
    bits: u8,
}

impl Rights {
    /// Read permission
    pub const READ: u8 = 1 << 0;
    /// Write permission
    pub const WRITE: u8 = 1 << 1;
    /// Execute permission
    pub const EXECUTE: u8 = 1 << 2;

    pub const NONE: Self = Rights { bits: 0 };
    pub const R: Self = Rights { bits: Self::READ };
    pub const RW: Self = Rights {
        bits: Self::READ | Self::WRITE,
    };
    pub const RX: Self = Rights {
        bits: Self::READ | Self::EXECUTE,
    };
    pub const RWX: Self = Rights {
        bits: Self::READ | Self::WRITE | Self::EXECUTE,
    };

    /// Create Rights from raw bits
    pub const fn from_bits(bits: u8) -> Self {
        Rights { bits: bits & 0x07 } // Mask to 3 bits
    }

    /// Get raw bits
    pub const fn bits(&self) -> u8 {
        self.bits
    }

    /// Check if a specific flag is set
    pub const fn has(&self, flag: u8) -> bool {
        (self.bits & flag) != 0
    }

    /// Check if self is a subset of other (for monotonicity)
    pub fn is_subset_of(&self, other: &Rights) -> bool {
        (self.bits & !other.bits) == 0
    }

    /// Compute intersection of rights
    pub fn intersect(&self, other: &Rights) -> Rights {
        Rights {
            bits: self.bits & other.bits,
        }
    }

    /// Compute union of rights
    pub fn union(&self, other: &Rights) -> Rights {
        Rights {
            bits: self.bits | other.bits,
        }
    }

    // Convenience methods for compatibility with existing code
    pub const fn read(&self) -> bool {
        self.has(Self::READ)
    }

    pub const fn write(&self) -> bool {
        self.has(Self::WRITE)
    }

    pub const fn execute(&self) -> bool {
        self.has(Self::EXECUTE)
    }
}

impl fmt::Display for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}",
            if self.read() { "R" } else { "-" },
            if self.write() { "W" } else { "-" },
            if self.execute() { "X" } else { "-" }
        )
    }
}

/// Memory region attributes (bitmap representation)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attributes {
    bits: u8,
}

impl Attributes {
    /// Region content is hashed and verified
    pub const HASH: u8 = 1 << 0;
    /// Region is zeroed on revocation
    pub const CLEAN: u8 = 1 << 1;
    /// Revocation of this region causes domain revocation
    pub const VITAL: u8 = 1 << 2;
    /// Region is used for metadata storage
    pub const META: u8 = 1 << 3;
    /// Region is a COMM page (parent↔monitor shared buffer bound to a child VP).
    /// Implies CLEAN (zeroed on revocation); does NOT imply VITAL.
    /// Cannot be carved, aliased, or sent while the binding is active.
    pub const COMM: u8 = 1 << 4;

    pub const NONE: Self = Attributes { bits: 0 };

    /// Create Attributes from raw bits
    pub const fn from_bits(bits: u8) -> Self {
        Attributes { bits: bits & 0x1F } // Mask to 5 bits
    }

    /// Get raw bits
    pub const fn bits(&self) -> u8 {
        self.bits
    }

    /// Check if a specific flag is set
    pub const fn has(&self, flag: u8) -> bool {
        (self.bits & flag) != 0
    }

    // Convenience methods for compatibility with existing code
    pub const fn hash(&self) -> bool {
        self.has(Self::HASH)
    }

    pub const fn clean(&self) -> bool {
        self.has(Self::CLEAN)
    }

    pub const fn vital(&self) -> bool {
        self.has(Self::VITAL)
    }

    pub const fn meta(&self) -> bool {
        self.has(Self::META)
    }

    pub const fn comm(&self) -> bool {
        self.has(Self::COMM)
    }

    /// Canonicalize: META implies CLEAN + VITAL; COMM implies CLEAN only.
    /// Call this once at registration/send time to avoid scattered checks in the revocation path.
    pub const fn canonicalize(self) -> Self {
        if self.meta() {
            Attributes { bits: self.bits | Self::CLEAN | Self::VITAL }
        } else if self.comm() {
            Attributes { bits: self.bits | Self::CLEAN }
        } else {
            self
        }
    }
}

impl Default for Attributes {
    fn default() -> Self {
        Self::NONE
    }
}

impl fmt::Display for Attributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut attrs = Vec::new();
        if self.hash() {
            attrs.push("HASH");
        }
        if self.clean() {
            attrs.push("CLEAN");
        }
        if self.vital() {
            attrs.push("VITAL");
        }
        if self.meta() {
            attrs.push("META");
        }
        if self.comm() {
            attrs.push("COMM");
        }
        write!(f, "{}", attrs.join("|"))
    }
}

/// Describes which child domain + VP a COMM capability is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommBinding {
    /// Domain ID of the child this COMM page targets.
    pub target_domain_id: u64,
    /// Virtual processor index within that child.
    pub vp_id: u32,
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
        Access {
            start,
            size,
            rights,
        }
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
        write!(f, "[{:#x}..{:#x}) {}", self.start, self.end(), self.rights)
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
    /// Hash of region content (if hash attribute is set)
    pub content_hash: Option<[u8; 32]>,
    /// If this region is a COMM page, which child domain + VP it is bound to.
    pub comm_binding: Option<CommBinding>,
    /// Authorized cache colors for this region.
    #[cfg(feature = "cache_coloring")]
    pub color_bitmap: Option<crate::translation::ColorBitmap>,
}

impl MemoryRegion {
    /// Create a new exclusive root memory region
    pub fn new_root(start: u64, size: u64) -> Self {
        MemoryRegion {
            kind: RegionKind::Carve,
            status: RegionStatus::Exclusive,
            access: Access::new(start, size, Rights::RWX),
            content_hash: None,
            comm_binding: None,
            #[cfg(feature = "cache_coloring")]
            color_bitmap: None,
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

        Ok(MemoryRegion {
            kind: RegionKind::Alias,
            status: RegionStatus::Aliased,
            access,
            content_hash: None,
            comm_binding: None,
            #[cfg(feature = "cache_coloring")]
            color_bitmap: None,
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

        // Carved child inherits parent's status
        Ok(MemoryRegion {
            kind: RegionKind::Carve,
            status: self.status,
            access,
            content_hash: None,
            comm_binding: None,
            #[cfg(feature = "cache_coloring")]
            color_bitmap: None,
        })
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
            "MemoryRegion {{ {:?} {:?} {} }}",
            self.kind, self.status, self.access
        )
    }
}
