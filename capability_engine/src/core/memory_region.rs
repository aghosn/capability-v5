use std::cmp::Ordering;

use bitflags::bitflags;

use crate::core::capability::CapaError;

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum RegionKind {
    Carve,
    Alias,
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum Status {
    Exclusive,
    Aliased,
}

bitflags! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct Rights: u8 {
        const READ    = 0b001;
        const WRITE   = 0b010;
        const EXECUTE = 0b100;
    }
}

bitflags! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct Attributes: u8 {
        const NONE =    0b000;
        const HASH    = 0b001;
        const CLEAN   = 0b010;
        const VITAL   = 0b100;
    }
}

#[derive(PartialEq, Debug, Clone, Copy, Eq)]
pub enum Remapped {
    Identity,
    Remapped(u64),
}

#[derive(PartialEq, Clone, Copy, Debug, Eq)]
pub struct Access {
    pub start: u64,
    pub size: u64,
    pub rights: Rights,
}

impl Access {
    pub fn new(start: u64, size: u64, rights: Rights) -> Self {
        Access {
            start,
            size,
            rights,
        }
    }
    pub fn contained(&self, other: &Self) -> bool {
        self.start >= other.start
            && self.start + self.size <= other.start + other.size
            && other.rights.contains(self.rights)
    }

    pub fn intersect(&self, other: &Self) -> bool {
        let case_1 = self.start <= other.start && other.start < self.start + self.size;
        let case_2 = other.start <= self.start && self.start < other.start + other.size;
        case_1 || case_2
    }
    pub fn end(&self) -> u64 {
        self.start + self.size
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct MemoryRegion {
    pub kind: RegionKind,
    pub status: Status,
    pub access: Access,
    pub attributes: Attributes,
    pub remapped: Remapped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViewRegion {
    pub access: Access,
    pub remap: Remapped,
}

impl ViewRegion {
    pub fn new(access: Access, remap: Remapped) -> Self {
        ViewRegion { access, remap }
    }

    pub fn active_start(&self) -> u64 {
        if let Remapped::Remapped(gva) = self.remap {
            gva
        } else {
            self.access.start
        }
    }
    pub fn active_end(&self) -> u64 {
        self.active_start() + self.access.size
    }

    pub fn contains_remap(&self, other: &ViewRegion) -> bool {
        self.active_start() <= other.active_start()
            && other.active_end() <= self.active_end()
            && self.access.rights.contains(other.access.rights)
    }

    pub fn contiguous(&self, other: &ViewRegion) -> bool {
        // They must be contiguous in remaps and non remaps
        // and have the same access rights
        self.active_end() == other.active_start()
            && self.access.end() == other.access.start
            && self.access.rights == other.access.rights
    }

    pub fn overlap_remap(&self, other: &ViewRegion) -> bool {
        self.active_start() <= other.active_start() && other.active_start() < self.active_end()
        //&& self.active_end() < other.active_end()
    }

    pub fn overlap(&self, other: &ViewRegion) -> bool {
        self.access.start <= other.access.start && other.access.start < self.access.end()
        //&& self.access.end() < other.access.end()
    }

    pub fn compatible(&self, other: &ViewRegion) -> bool {
        if self.active_start() <= other.active_start() && !self.overlap_remap(other) {
            return true;
        }
        if self.active_start() >= other.active_start() && !other.overlap_remap(self) {
            return true;
        }
        let (first, second) = if self.active_start() <= other.active_start() {
            (self, other)
        } else {
            (other, self)
        };

        match (first.remap, second.remap) {
            (Remapped::Identity, Remapped::Identity) => {
                return true;
            }
            // Needs to be remapped in exactly the same way.
            // We can have several capabilities with the same physical and remaped
            // range but we cannot have a gap with two different ranges, i.e.,
            // we need to avoid gva mapping to multiple hpa.
            (Remapped::Remapped(x), Remapped::Remapped(y)) => {
                // They are not ordered in the same way, that won't work.
                if first.access.start > second.access.start {
                    return false;
                }
                let diff_active = y - x;
                let diff_real = second.access.start - first.access.start;
                return diff_active == diff_real;
            }
            // For the moment, let's disallow all remapping overlaps.
            _ => return false,
        }
    }

    pub fn merge_at(curr: usize, regions: &mut Vec<Self>) -> Result<usize, CapaError> {
        if curr == regions.len() - 1 {
            return Ok(regions.len());
        }

        let mut current = regions[curr];
        let mut other = regions[curr + 1];

        // Case 1: contained.
        if current.contains_remap(&other) {
            // Safety check, this should only happen if they are the same in physical space.
            if !(current.access.start <= other.access.start
                && other.access.end() <= current.access.end())
            {
                return Err(CapaError::DoubleRemapping);
            }
            // Remove the next.
            regions.remove(curr + 1);
            return Ok(curr);
        }

        // Case 2: contiguous
        if current.contiguous(&other) {
            current = ViewRegion::new(
                Access::new(
                    current.access.start,
                    current.access.size + other.access.size,
                    current.access.rights,
                ),
                current.remap,
            );
            // Commit the change.
            regions[curr] = current;
            regions.remove(curr + 1);
            return Ok(curr);
        }

        if current.overlap_remap(&other) {
            // Check that they are in the same physical space.
            if !current.overlap(&other) {
                return Err(CapaError::DoubleRemapping);
            }
            // Split the overlap and let the next round merge contiguous.
            let middle_remap = match current.remap {
                Remapped::Identity => Remapped::Identity,
                Remapped::Remapped(x) => {
                    Remapped::Remapped(other.access.start - current.access.start + x)
                }
            };
            let middle = ViewRegion::new(
                Access::new(
                    other.access.start,
                    u64::min(current.access.end(), other.access.end()) - other.access.start,
                    current.access.rights.union(other.access.rights),
                ),
                middle_remap,
            );
            let remainder = u64::max(current.access.end(), other.access.end());
            let rights = if remainder == current.access.end() {
                current.access.rights
            } else {
                other.access.rights
            };
            // Update left.
            current.access.size = middle.access.start - current.access.start;
            // Update right
            other.access.start = middle.access.end();
            other.access.size = remainder - other.access.start;
            other.access.rights = rights;
            let other_remap = match other.remap {
                Remapped::Identity => Remapped::Identity,
                Remapped::Remapped(x) => Remapped::Remapped(x + middle.access.size),
            };

            other.remap = other_remap;
            // Commit the changes before inserting the new view.
            regions[curr] = current;
            regions[curr + 1] = other;
            // Now insert
            if current.access.size == 0 {
                regions[curr] = middle;
            } else {
                regions.insert(curr + 1, middle);
            }
            return Ok(curr);
        }
        Ok(curr + 1)
    }
}

impl PartialOrd for ViewRegion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ViewRegion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.active_start()
            .cmp(&other.active_start())
            .then(self.access.size.cmp(&other.access.size))
    }
}
