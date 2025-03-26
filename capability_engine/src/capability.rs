use crate::domain::{CapaWrapper, Domain, LocalCapa, MonitorAPI, Policies, Status as DStatus};
use crate::memory_region::{
    Access, Attributes, MemoryRegion, RegionKind, Remapped, Status, ViewRegion,
};
use std::cell::RefCell;
use std::rc::Rc;

pub type CapaRef<T> = Rc<RefCell<Capability<T>>>;

#[derive(Debug, PartialEq)]
pub struct Capability<T> {
    pub data: T,
    pub children: Vec<CapaRef<T>>,
}

/// Capability errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapaError {
    InvalidAccess,
    ChildNotFound,
    InvalidLocalCapa,
    WrongCapaType,
    CallNotAllowed,
    DomainSealed,
    InsufficientRights,
    InvalidChildCapa,
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

// ———————————————————— Region Capability implementation ———————————————————— //
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

// ———————————————————— Domain Capability implementation ———————————————————— //

fn is_core_subset(reference: u64, other: u64) -> bool {
    (reference & other) == other
}

impl Capability<Domain> {
    pub fn new(domain: Domain) -> Self {
        Capability::<Domain> {
            data: domain,
            children: Vec::new(),
        }
    }
    pub fn create(&mut self, policies: Policies) -> Result<LocalCapa, CapaError> {
        if !self.data.operation_allowed(MonitorAPI::CREATE) {
            return Err(CapaError::CallNotAllowed);
        }
        // Check cores.
        if !is_core_subset(self.data.policies.cores, policies.cores) {
            return Err(CapaError::InsufficientRights);
        }
        let domain = Domain::new(policies);

        let capa = Self::new(domain);
        let reference = Rc::new(RefCell::new(capa));
        self.add_child(reference.clone());
        let local_capa = self.data.install(CapaWrapper::Domain(reference));
        Ok(local_capa)
    }

    pub fn set(&self, _child: LocalCapa) -> Result<(), CapaError> {
        if !self.data.operation_allowed(MonitorAPI::SET) {
            return Err(CapaError::CallNotAllowed);
        }
        todo!()
    }

    pub fn get(&self, _child: LocalCapa) -> Result<(), CapaError> {
        if !self.data.operation_allowed(MonitorAPI::GET) {
            return Err(CapaError::CallNotAllowed);
        }
        todo!();
    }

    pub fn seal(&self, child: LocalCapa) -> Result<(), CapaError> {
        if !self.data.operation_allowed(MonitorAPI::SEAL) {
            return Err(CapaError::CallNotAllowed);
        }
        if !self.data.is_domain(child)? {
            return Err(CapaError::WrongCapaType);
        }
        let domain = self.data.capabilities.get(&child)?.as_domain()?;

        if domain.borrow().data.is_sealed() {
            return Err(CapaError::DomainSealed);
        }
        domain.borrow_mut().data.status = DStatus::Sealed;

        //TODO: should we generate anything now?

        Ok(())
    }

    pub fn attest(&self, child: LocalCapa) -> Result<(), CapaError> {
        if !self.data.operation_allowed(MonitorAPI::ATTEST) {
            return Err(CapaError::CallNotAllowed);
        }
        if !self.data.is_domain(child)? {
            return Err(CapaError::WrongCapaType);
        }
        todo!()
    }

    pub fn send(&mut self, dest: LocalCapa, capa: LocalCapa) -> Result<(), CapaError> {
        if !self.data.operation_allowed(MonitorAPI::SEND) {
            return Err(CapaError::CallNotAllowed);
        }
        let dest = self.data.capabilities.get(&dest)?.as_domain()?;

        // Is the dest allowed to receive capabilities.
        if dest.borrow().data.is_sealed()
            && !dest.borrow().data.operation_allowed(MonitorAPI::RECEIVE)
        {
            return Err(CapaError::CallNotAllowed);
        }
        let region = self.data.capabilities.remove(&capa)?.as_region()?;

        //TODO: UPDATE here because we're losing a region.
        // We do not care about the receiver's local capa.
        let _ = dest.borrow_mut().data.install(CapaWrapper::Region(region));

        //TODO: Update Receiver too.

        Ok(())
    }
}
