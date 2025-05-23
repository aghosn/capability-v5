use crate::core::domain::{
    CapaWrapper, Domain, Field, FieldType, LocalCapa, MonitorAPI, Status as DStatus,
};
use crate::core::memory_region::{
    Access, Attributes, MemoryRegion, RegionKind, Remapped, Status, ViewRegion,
};
use std::cell::RefCell;
use std::rc::{Rc, Weak};

use super::update::{OperationUpdate, Update};

pub type CapaRef<T> = Rc<RefCell<Capability<T>>>;

pub type WeakRef<T> = Weak<RefCell<Capability<T>>>;

#[derive(Debug)]
pub struct Ownership {
    pub owner: WeakRef<Domain>,
    pub handle: LocalCapa,
}

impl Ownership {
    pub fn new(owner: WeakRef<Domain>, handle: LocalCapa) -> Self {
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
    pub parent: WeakRef<T>,
    pub children: Vec<CapaRef<T>>,
}

/// Capability errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapaError {
    InvalidAccess,
    InvalidAttributes,
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
    InvalidField,
    InvalidValue,
    // For parsing
    ParserDomain,
    ParserRegion,
    ParserStatus,
    ParserMonitor,
    ParserCapability,
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
    pub fn add_child(&mut self, child: CapaRef<T>, owner: WeakRef<Domain>) {
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

    pub fn dfs<F>(&self, visit: &mut F) -> Result<(), CapaError>
    where
        F: FnMut(&Capability<T>) -> Result<(), CapaError>,
    {
        visit(self)?;
        for c in &self.children {
            c.borrow().dfs(visit)?;
        }
        Ok(())
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
        //TODO: bug should not be able to carve an aliased region.
        if !self.contained(access, kind_op == RegionKind::Carve) {
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
            // A new region has no attributes.
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

    // Does not remove the carved.
    // This is used to check for compatible sends.
    pub fn view_raw(&self) -> Vec<ViewRegion> {
        vec![ViewRegion::new(self.data.access, self.data.remapped)]
    }

    pub fn contained(&self, access: &Access, strict: bool) -> bool {
        // Easy case, it's not even contained without considering children.
        if !access.contained(&self.data.access) {
            return false;
        }
        // Now see if it's carved.
        let children = &self.children;
        for c in children {
            if !strict && c.borrow().data.kind == RegionKind::Alias {
                continue;
            }
            if c.borrow().data.access.intersect(access) {
                return false;
            }
        }
        return true;
    }

    // We should implement two on_revoke.
    // One will do the dfs, the other will consider local changes
    pub fn on_revoke(&self, operation: &mut OperationUpdate) -> Result<(), CapaError> {
        // Simple per node visit to collect attributes.
        let mut visit = |capa: &Capability<MemoryRegion>| -> Result<(), CapaError> {
            // This algorithm is a bit complicated so here is the explanation.
            // we go top to bottom dfs style, so technically if the parent was visited,
            // we do not need to do a reenable in the case of a carve.
            // In the case of an alias, it will be merged within the updates for the domain
            // as they are subsets of each other.
            if capa.data.attributes.contains(Attributes::VITAL) {
                operation.add(Update::Revoke {
                    dom: capa.owned.owner.clone(),
                });
            }
            if capa.data.attributes.contains(Attributes::CLEAN) {
                operation.add(Update::Clean {
                    start: capa.data.access.start,
                    size: capa.data.access.size,
                });
            }
            // We lose this access.
            operation.add(Update::ChangeMemory {
                dom: capa.owned.owner.clone(),
            });

            // For a carve the parent is affected as well.
            if capa.data.kind == RegionKind::Carve {
                if let Some(parent) = capa.parent.upgrade() {
                    operation.add(Update::ChangeMemory {
                        dom: parent.borrow().owned.owner.clone(),
                    });
                } else {
                    return Err(CapaError::InvalidValue);
                }
            }
            Ok(())
        };

        // Now go through the nodes.
        self.dfs(&mut visit)
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

    // Set on self.
    pub fn set(
        &mut self,
        _core: u64,
        tpe: FieldType,
        field: Field,
        value: u64,
    ) -> Result<(), CapaError> {
        match tpe {
            FieldType::Register => {
                todo!()
            }
            _ => {
                if self.data.is_sealed() {
                    return Err(CapaError::DomainSealed);
                }

                self.data.set_policy(tpe, field, value)?;
            }
        }
        Ok(())
    }

    // Get on self.
    pub fn get(&self, _core: u64, tpe: FieldType, field: Field) -> Result<u64, CapaError> {
        match tpe {
            FieldType::Register => todo!(),
            _ => self.data.get_policy(tpe, field),
        }
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

    pub fn attest(&self, child: LocalCapa) -> Result<String, CapaError> {
        if !self.data.operation_allowed(MonitorAPI::ATTEST) {
            return Err(CapaError::CallNotAllowed);
        }
        if !self.data.is_domain(child)? {
            return Err(CapaError::WrongCapaType);
        }
        let child = self.data.capabilities.get(&child)?.as_domain()?;
        let attestation = format!("{}", child.borrow());
        return Ok(attestation);
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

    pub fn gva_view_raw(&self) -> Result<Vec<ViewRegion>, CapaError> {
        let mut regions: Vec<ViewRegion> = self
            .data
            .capabilities
            .capabilities
            .iter()
            .filter_map(|(_, c)| match c {
                CapaWrapper::Region(r) => Some(r.borrow().view_raw()),
                _ => None,
            })
            .flatten()
            .collect();
        regions.sort_by(|a, b| a.active_start().cmp(&b.active_start()));
        Ok(regions)
    }

    pub fn check_conflict(&self, view: &ViewRegion) -> Result<(), CapaError> {
        // Ensure there is no ambiguity when we map a gva.
        let effective = self.gva_view_raw()?;
        for r in effective.iter() {
            // Check that they are mapping to the same thing.
            if !r.compatible(view) {
                return Err(CapaError::IncompatibleRemap);
            }
        }
        Ok(())
    }

    pub fn on_revoke_child(
        &self,
        child: &CapaRef<Domain>,
        updates: &mut OperationUpdate,
    ) -> Result<(), CapaError> {
        // Add the child to the revoke.
        updates.add(Update::Revoke {
            dom: Rc::downgrade(child),
        });
        let mut visit = |capa: &Capability<Domain>| -> Result<(), CapaError> {
            // The capa should have been marked for removal already.
            for c in &capa.children {
                updates.add(Update::Revoke {
                    dom: Rc::downgrade(c),
                });
            }
            // Now go through the domain's regions.
            capa.data
                .capabilities
                .foreach_region(&mut |c: &CapaRef<MemoryRegion>| c.borrow().on_revoke(updates))
        };

        // We go through the child.
        child.borrow().dfs(&mut visit)
    }
}
