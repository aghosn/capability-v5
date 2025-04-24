use crate::domain::{CapaWrapper, Domain, LocalCapa, MonitorAPI, Status as DStatus};
use crate::memory_region::{
    Access, Attributes, MemoryRegion, RegionKind, Remapped, Status, ViewRegion,
};
use std::cell::RefCell;
use std::rc::{Rc, Weak};

pub type CapaRef<T> = Rc<RefCell<Capability<T>>>;

pub type WeakRef<T> = Weak<RefCell<T>>;

#[derive(Debug)]
pub struct Ownership {
    pub owner: WeakRef<Capability<Domain>>,
    pub handle: LocalCapa,
}

impl Ownership {
    pub fn new(owner: WeakRef<Capability<Domain>>, handle: LocalCapa) -> Self {
        Ownership { owner, handle }
    }
    pub fn empty() -> Self {
        Ownership {
            owner: WeakRef::new(),
            handle: 0,
        }
    }
}

#[derive(Debug)]
pub struct Capability<T> {
    pub owned: Ownership,
    pub data: T,
    pub parent: WeakRef<Capability<T>>,
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
    DomainUnsealed,
    DomainSealed,
    InsufficientRights,
    InvalidChildCapa,
    CapaNotOwned,
    RevokeOnRootCapa,
    DoubleRemapping,
    IncompatibleRemap,
}

/// Have to implement it by hand because Weak does not support PartialEq
impl<T: PartialEq> PartialEq for Capability<T> {
    fn eq(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.owned.owner, &other.owned.owner)
            && self.data == other.data
            && self.children == other.children
    }
}

impl<T> Capability<T>
where
    T: PartialEq,
{
    pub fn add_child(&mut self, child: CapaRef<T>, owner: WeakRef<Capability<Domain>>) {
        {
            child.borrow_mut().owned = Ownership::new(owner, 0);
        }
        self.children.push(child)
    }

    pub fn revoke_node<F>(node: CapaRef<T>, on_revoke: &mut F) -> Result<(), CapaError>
    where
        F: FnMut(&mut Capability<T>) -> Result<(), CapaError>,
    {
        let parent = {
            let borrowed = node.borrow();
            borrowed
                .parent
                .upgrade()
                .ok_or(CapaError::RevokeOnRootCapa)?
        };

        parent.borrow_mut().revoke_child(&node, on_revoke)?;
        Ok(())
    }

    pub fn revoke_child<F>(
        &mut self,
        child: &CapaRef<T>,
        on_revoke: &mut F,
    ) -> Result<(), CapaError>
    where
        F: FnMut(&mut Capability<T>) -> Result<(), CapaError>,
    {
        if let Some(pos) = self.children.iter().position(|c| Rc::ptr_eq(c, child)) {
            // Safely remove the child and pass it for revocation
            let child = self.children.remove(pos);
            // Remove the backward edge to the parent.
            child.borrow_mut().parent = WeakRef::new();
            child.borrow_mut().revoke_all(on_revoke)?;
            Ok(())
        } else {
            Err(CapaError::ChildNotFound)
        }
    }

    pub fn revoke_all<F>(&mut self, on_revoke: &mut F) -> Result<(), CapaError>
    where
        F: FnMut(&mut Capability<T>) -> Result<(), CapaError>,
    {
        for c in &self.children {
            let child = &mut c.borrow_mut();
            child.parent = WeakRef::new();
            child.revoke_all(on_revoke)?;
        }
        self.children = Vec::new();
        // Remove the node from its parent.
        on_revoke(self)
    }

    pub fn dfs<F>(&mut self, visit: &F) -> Result<(), CapaError>
    where
        F: Fn(&mut Capability<T>) -> Result<(), CapaError>,
    {
        for c in &self.children {
            c.borrow_mut().dfs(visit)?;
        }
        visit(self)
    }
}

// ———————————————————— Region Capability implementation ———————————————————— //
impl Capability<MemoryRegion> {
    pub fn new(region: MemoryRegion) -> Self {
        Capability::<MemoryRegion> {
            owned: Ownership::empty(),
            data: region,
            parent: WeakRef::new(),
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
        self.add_child(reference.clone(), Weak::new());
        Ok(reference)
    }

    pub fn view(&self) -> Vec<ViewRegion> {
        let mut views = Vec::new();
        // This is the range we consider.
        let mut start = self.data.access.start;

        // Constants.
        let base = self.data.access.start;

        // Children are sorted.
        let mut sorted = self.children.clone();
        sorted.sort_by(|a, b| {
            a.borrow()
                .data
                .access
                .start
                .cmp(&b.borrow().data.access.start)
        });
        for c in sorted {
            let c_borrow = c.borrow();
            // We do not care
            if c_borrow.data.kind == RegionKind::Alias {
                continue;
            }
            // It is a carve, the segment loses access.
            if start <= c_borrow.data.access.start {
                let r = match self.data.remapped {
                    Remapped::Identity => Remapped::Identity,
                    Remapped::Remapped(x) => Remapped::Remapped(x + (start - base)),
                };
                if c_borrow.data.access.start != start {
                    views.push(ViewRegion {
                        access: Access {
                            start,
                            size: (c_borrow.data.access.start - start),
                            rights: self.data.access.rights,
                        },
                        remap: r,
                    });
                }
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

impl Capability<Domain> {
    pub fn new(domain: Domain) -> Self {
        Capability::<Domain> {
            owned: Ownership::empty(),
            data: domain,
            parent: WeakRef::new(),
            children: Vec::new(),
        }
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

    pub fn coalesce_view_regions(regions: &mut Vec<ViewRegion>) -> Result<(), CapaError> {
        let mut curr: usize = 0;
        while curr < regions.len() {
            let next = ViewRegion::merge_at(curr, regions)?;
            curr = next;
        }
        Ok(())
    }

    pub fn view(&self) -> Result<Vec<ViewRegion>, CapaError> {
        let mut regions: Vec<ViewRegion> = self
            .data
            .capabilities
            .capabilities
            .iter()
            .filter_map(|(_, c)| match c {
                CapaWrapper::Region(r) => Some(r.borrow().view()),
                _ => None,
            })
            .flatten()
            .collect();

        // Now we need to sort and coalesce.
        regions.sort_by_key(|c| c.access.start);

        // Now go through it and merge.
        Self::coalesce_view_regions(&mut regions)?;

        Ok(regions)
    }

    pub fn gva_view(&self) -> Result<Vec<ViewRegion>, CapaError> {
        let mut view = self.view()?;
        view.sort_by(|a, b| a.active_start().cmp(&b.active_start()));
        Ok(view)
    }

    pub fn check_conflict(&self, capa: CapaRef<MemoryRegion>) -> Result<(), CapaError> {
        // Ensure there is no ambiguity when we map a gva.
        let view = capa.borrow().view();
        let effective = self.gva_view()?;
        for r in effective.iter() {
            for v in view.iter() {
                // Check that they are mapping to the same thing.
                if !r.compatible(v) {
                    return Err(CapaError::IncompatibleRemap);
                }
            }
        }
        Ok(())
    }
}
