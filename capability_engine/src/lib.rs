use bitflags::bitflags;
use std::cell::RefCell;
use std::rc::Rc;

pub mod display;

type CapaRef<T> = Rc<RefCell<Capability<T>>>;

#[derive(Debug, PartialEq)]
pub struct Capability<T> {
    pub data: T,
    pub children: Vec<CapaRef<T>>,
}

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
pub enum CapaError {
    InvalidAccess,
    ChildNotFound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViewRegion {
    pub access: Access,
    pub remap: Remapped,
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

    pub fn revoke_with<F>(&mut self, child: &CapaRef<T>, mut on_revoke: F) -> Result<(), CapaError>
    where
        F: FnMut(&Capability<T>),
    {
        if let Some(pos) = self.children.iter().position(|c| Rc::ptr_eq(c, child)) {
            // Safely remove the child and pass it for revocation
            let child = self.children.remove(pos);
            Capability::recurse_revoke(child, &mut on_revoke);
            Ok(())
        } else {
            Err(CapaError::ChildNotFound)
        }
    }

    fn recurse_revoke<F>(node: CapaRef<T>, on_revoke: &mut F)
    where
        F: FnMut(&Capability<T>),
    {
        // First, take the children out to avoid borrowing conflicts
        let children = {
            let mut node_borrow = node.borrow_mut();
            std::mem::take(&mut node_borrow.children) // Extract the children
        };

        // Now we can safely recurse on the children
        for child in children {
            Capability::recurse_revoke(child, on_revoke);
        }

        // Finally, call the callback after all children are revoked
        on_revoke(&node.borrow());
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

    pub fn view(&self) -> Vec<ViewRegion> {
        let mut views = Vec::new();
        // This is the range we consider.
        let mut start = self.data.access.start;

        // Constants.
        let base = self.data.access.start;

        // Children are sorted.
        for c in &self.children {
            let c_borrow = c.borrow();
            // We do not care
            if c_borrow.data.kind == RegionKind::Alias {
                continue;
            }
            // It is a carve, the segment loses access.
            if start < c_borrow.data.access.start {
                let r = match self.data.remapped {
                    Remapped::Identity => Remapped::Identity,
                    Remapped::Remapped(x) => Remapped::Remapped(x + (start - base)),
                };
                views.push(ViewRegion {
                    access: Access {
                        start,
                        size: (c_borrow.data.access.start - start),
                        rights: self.data.access.rights,
                    },
                    remap: r,
                });
                start = c_borrow.data.access.end();
            }
        }
        if start < self.data.access.end() {
            let r = match self.data.remapped {
                Remapped::Identity => Remapped::Identity,
                Remapped::Remapped(x) => Remapped::Remapped(x + (start - base)),
            };
            views.push(ViewRegion {
                access: Access {
                    start,
                    size: self.data.access.end() - start,
                    rights: self.data.access.rights,
                },
                remap: r,
            });
        }

        views
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
