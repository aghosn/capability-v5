use bitflags::bitflags;
use std::cell::RefCell;
use std::rc::Rc;

type CapaRef<T> = Rc<RefCell<Capability<T>>>;

pub struct Capability<T> {
    pub data: T,
    pub children: Vec<CapaRef<T>>,
}

#[derive(PartialEq)]
pub enum RegionKind {
    Carve,
    Alias,
}

#[derive(PartialEq, Clone, Copy)]
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

#[derive(PartialEq)]
pub enum Remapped {
    Identity,
    Remapped(u64),
}

#[derive(PartialEq, Clone, Copy)]
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
}

#[derive(PartialEq)]
pub struct MemoryRegion {
    pub kind: RegionKind,
    pub status: Status,
    pub access: Access,
    pub attributes: Attributes,
    pub remapped: Remapped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapaError {
    InvalidAccess,
}

impl<T> Capability<T>
where
    T: PartialEq,
{
    pub fn add_child(&mut self, child: CapaRef<T>) {
        self.children.push(child)
    }

    pub fn remove_child(&mut self, child: &T) -> Option<CapaRef<T>> {
        if let Some(pos) = self.children.iter().position(|c| c.borrow().data == *child) {
            Some(self.children.remove(pos))
        } else {
            None
        }
    }
}

impl Capability<MemoryRegion> {
    pub fn new(region: MemoryRegion) -> Self {
        Capability::<MemoryRegion> {
            data: region,
            children: Vec::new(),
        }
    }

    pub fn alias(&mut self, access: &Access) -> Result<CapaRef<MemoryRegion>, CapaError> {
        self.alias_carve_logic(access, RegionKind::Alias)
    }

    pub fn carve(&mut self, access: &Access) -> Result<CapaRef<MemoryRegion>, CapaError> {
        self.alias_carve_logic(access, RegionKind::Carve)
    }

    pub fn alias_carve_logic(
        &mut self,
        access: &Access,
        kind_op: RegionKind,
    ) -> Result<CapaRef<MemoryRegion>, CapaError> {
        if !self.contained(access) {
            return Err(CapaError::InvalidAccess);
        }
        // Compute the remapping
        let remapping = match self.data.remapped {
            Remapped::Identity => Remapped::Identity,
            Remapped::Remapped(s) => {
                Remapped::Remapped(s + (access.start - self.data.access.start))
            }
        };
        // Compute the status: alias -> aliased, carve inherit
        let status_obtained = if kind_op == RegionKind::Alias {
            Status::Aliased
        } else {
            self.data.status
        };
        // Create the region
        let region = MemoryRegion {
            kind: kind_op,
            status: status_obtained,
            access: *access,
            attributes: Attributes::NONE,
            remapped: remapping,
        };
        let new_capa = Self::new(region);
        let reference = Rc::new(RefCell::new(new_capa));
        self.add_child_sorted(reference.clone());
        Ok(reference)
    }

    pub fn add_child_sorted(&mut self, child: CapaRef<MemoryRegion>) {
        self.add_child(child);
        self.children.sort_by(|a, b| {
            a.borrow()
                .data
                .access
                .start
                .cmp(&b.borrow().data.access.start)
        });
    }

    pub fn to_map() -> Vec<(Access, Status)> {
        todo!("Implement")
    }

    pub fn contained(&self, access: &Access) -> bool {
        // Easy case, it's not even contained without considering children.
        if !access.contained(&self.data.access) {
            return false;
        }
        // Now see if it's carved.
        let children = &self.children;
        for c in children {
            if c.borrow().data.kind == RegionKind::Alias {
                continue;
            }
            if c.borrow().data.kind == RegionKind::Carve && c.borrow().data.access.intersect(access)
            {
                return false;
            }
        }
        return true;
    }
}
