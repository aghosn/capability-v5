use bitflags::bitflags;

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

#[derive(PartialEq, Debug)]
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
