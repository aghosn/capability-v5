//! Core capability structures with thread-safe parent-child relationships

use crate::domain::{Domain, DomainPolicy};
use crate::error::{CapaError, Result};
use crate::memory::{Access, Attributes, MemoryRegion, RegionKind};
use crate::update::{DomainId, UpdateBatch};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::mem;
use parking_lot::RwLock;

/// Thread-safe reference to a capability (strong reference, owned)
pub type CapabilityRef<T> = Arc<RwLock<Capability<T>>>;

/// Thread-safe weak reference to a capability (non-owning)
pub type CapabilityWeak<T> = Weak<RwLock<Capability<T>>>;

/// Local capability handle (index within a domain's capability store)
pub type LocalHandle = u64;

/// Ownership information for a capability
#[derive(Debug, Clone)]
pub struct Ownership {
    /// Domain that owns this capability
    pub owner: DomainId,
    /// Local handle within the domain
    pub handle: LocalHandle,
}

impl Ownership {
    pub fn new(owner: DomainId, handle: LocalHandle) -> Self {
        Ownership { owner, handle }
    }
}

/// Generic capability structure
///
/// Capabilities form a tree structure where:
/// - Parent -> Children: Strong references (Arc) - children are owned
/// - Child -> Parent: Weak reference (Weak) - prevents cycles
pub struct Capability<T> {
    /// Ownership information
    pub owned: Ownership,

    /// Capability data (Domain or MemoryRegion)
    pub data: T,

    /// Weak reference to parent (prevents reference cycles)
    pub parent: CapabilityWeak<T>,

    /// Strong references to children (owned)
    pub children: Vec<CapabilityRef<T>>,
}

impl<T> Capability<T> {
    /// Create a new root capability (no parent)
    pub fn new_root(owner: DomainId, handle: LocalHandle, data: T) -> CapabilityRef<T> {
        Arc::new(RwLock::new(Capability {
            owned: Ownership::new(owner, handle),
            data,
            parent: Weak::new(),
            children: Vec::new(),
        }))
    }

    /// Create a new child capability
    pub fn new_child(
        owner: DomainId,
        handle: LocalHandle,
        data: T,
        parent: CapabilityWeak<T>,
    ) -> CapabilityRef<T> {
        Arc::new(RwLock::new(Capability {
            owned: Ownership::new(owner, handle),
            data,
            parent,
            children: Vec::new(),
        }))
    }

    /// Add a child capability
    pub fn add_child(&mut self, child: CapabilityRef<T>) {
        self.children.push(child);
    }

    /// Remove a specific child
    pub fn remove_child(&mut self, child_handle: LocalHandle) -> Option<CapabilityRef<T>> {
        if let Some(pos) = self
            .children
            .iter()
            .position(|c| c.read().owned.handle == child_handle)
        {
            Some(self.children.remove(pos))
        } else {
            None
        }
    }

    /// Get parent capability (if it still exists)
    pub fn get_parent(&self) -> Option<CapabilityRef<T>> {
        self.parent.upgrade()
    }

    /// Check if capability has a parent
    pub fn has_parent(&self) -> bool {
        self.parent.strong_count() > 0
    }
}

impl Capability<MemoryRegion> {
    /// Create an aliased child region
    pub fn alias_child(
        parent_ref: &CapabilityRef<MemoryRegion>,
        access: Access,
        owner: DomainId,
        handle: LocalHandle,
    ) -> Result<CapabilityRef<MemoryRegion>> {
        let parent = parent_ref.read();

        // Create aliased region from parent
        let child_region = parent.data.alias(access)?;

        // Create child capability
        let child = Capability::new_child(
            owner,
            handle,
            child_region,
            Arc::downgrade(parent_ref),
        );

        // Drop parent read lock before acquiring write lock
        drop(parent);

        // Add child to parent's children list
        parent_ref.write().add_child(child.clone());

        Ok(child)
    }

    /// Create a carved child region
    pub fn carve_child(
        parent_ref: &CapabilityRef<MemoryRegion>,
        access: Access,
        owner: DomainId,
        handle: LocalHandle,
    ) -> Result<(CapabilityRef<MemoryRegion>, UpdateBatch)> {
        let parent = parent_ref.read();

        // Create carved region from parent
        let child_region = parent.data.carve(access)?;

        let parent_owner = parent.owned.owner;

        // Drop parent read lock
        drop(parent);

        // Create update batch for the carve operation
        let mut updates = UpdateBatch::new();

        // Unmap the carved region from parent's address space
        updates.add_unmap(parent_owner, access.start, access.size);

        // Create child capability
        let child = Capability::new_child(
            owner,
            handle,
            child_region,
            Arc::downgrade(parent_ref),
        );

        // Add child to parent's children list
        parent_ref.write().add_child(child.clone());

        Ok((child, updates))
    }

    /// Send this capability to another domain
    pub fn send_to(
        capa_ref: &CapabilityRef<MemoryRegion>,
        new_owner: DomainId,
        new_handle: LocalHandle,
        attributes: Attributes,
    ) -> Result<UpdateBatch> {
        let mut capa = capa_ref.write();

        let old_owner = capa.owned.owner;

        // Update ownership
        capa.owned.owner = new_owner;
        capa.owned.handle = new_handle;

        // Set attributes
        capa.data = capa.data.clone().with_attributes(attributes);

        // Create updates
        let mut updates = UpdateBatch::new();

        // Unmap from old owner
        updates.add_unmap(old_owner, capa.data.access.start, capa.data.access.size);

        // Map to new owner
        let phys_addr = match capa.data.remapped {
            crate::memory::Remapped::Identity => capa.data.access.start,
            crate::memory::Remapped::Remapped(phys) => phys,
        };

        updates.add_map(
            new_owner,
            capa.data.access.start,
            capa.data.access.size,
            phys_addr,
            capa.data.access.rights.read,
            capa.data.access.rights.write,
            capa.data.access.rights.execute,
        );

        Ok(updates)
    }

    /// Revoke a child capability and all its descendants
    ///
    /// This performs a depth-first traversal and collects all updates
    pub fn revoke_child(
        parent_ref: &CapabilityRef<MemoryRegion>,
        child_handle: LocalHandle,
    ) -> Result<UpdateBatch> {
        let mut parent = parent_ref.write();

        // Remove child from parent's children list
        let child_ref = parent
            .remove_child(child_handle)
            .ok_or(CapaError::NotFound)?;

        // Drop parent lock before recursing
        drop(parent);

        // Collect updates from revoking the entire subtree
        let updates = Self::revoke_subtree(&child_ref)?;

        Ok(updates)
    }

    /// Recursively revoke a capability subtree
    fn revoke_subtree(capa_ref: &CapabilityRef<MemoryRegion>) -> Result<UpdateBatch> {
        let mut capa = capa_ref.write();

        let mut updates = UpdateBatch::new();

        // First, recursively revoke all children
        let children = mem::take(&mut capa.children);
        drop(capa); // Release lock before recursing

        for child_ref in children {
            let child_updates = Self::revoke_subtree(&child_ref)?;
            updates.merge(child_updates);
        }

        // Re-acquire lock to process this capability
        let capa = capa_ref.read();

        // Check if we need to clean memory
        if capa.data.attributes.clean {
            updates.add_zero_memory(capa.data.access.start, capa.data.access.size);
        }

        // If this is a carved region, we need to restore access to parent
        if capa.data.kind == RegionKind::Carve {
            if let Some(parent_ref) = capa.get_parent() {
                let parent = parent_ref.read();
                let parent_owner = parent.owned.owner;

                // Map the region back to the parent
                let phys_addr = match capa.data.remapped {
                    crate::memory::Remapped::Identity => capa.data.access.start,
                    crate::memory::Remapped::Remapped(phys) => phys,
                };

                updates.add_map(
                    parent_owner,
                    capa.data.access.start,
                    capa.data.access.size,
                    phys_addr,
                    parent.data.access.rights.read,
                    parent.data.access.rights.write,
                    parent.data.access.rights.execute,
                );
            }
        }

        // If vital, revoke the owning domain
        if capa.data.attributes.vital {
            updates.add_revoke_domain(capa.owned.owner);
        }

        Ok(updates)
    }

    /// Compute the current view of memory (considering carved children)
    pub fn compute_view(&self) -> Vec<Access> {
        let mut view = vec![self.data.access];

        // Subtract carved children from the view
        for child_ref in &self.children {
            let child = child_ref.read();
            if child.data.kind == RegionKind::Carve {
                // Remove the carved region from the view
                view = subtract_region(&view, &child.data.access);
            }
        }

        view
    }
}

/// Subtract one region from a list of regions
fn subtract_region(regions: &[Access], to_subtract: &Access) -> Vec<Access> {
    let mut result = Vec::new();

    for region in regions {
        if !region.overlaps(to_subtract) {
            // No overlap, keep the region
            result.push(*region);
        } else {
            // There's overlap, potentially split the region
            if region.start < to_subtract.start {
                // Keep the part before the subtracted region
                result.push(Access::new(
                    region.start,
                    to_subtract.start - region.start,
                    region.rights,
                ));
            }
            if region.end() > to_subtract.end() {
                // Keep the part after the subtracted region
                result.push(Access::new(
                    to_subtract.end(),
                    region.end() - to_subtract.end(),
                    region.rights,
                ));
            }
        }
    }

    result
}

impl Capability<Domain> {
    /// Create a child domain
    pub fn create_child_domain(
        parent_ref: &CapabilityRef<Domain>,
        policy: DomainPolicy,
        owner: DomainId,
        handle: LocalHandle,
    ) -> Result<CapabilityRef<Domain>> {
        let parent = parent_ref.read();

        // Validate child policy is subset of parent
        policy.is_subset_of(&parent.data.policy)?;

        // Create child domain
        let child_domain = Domain::new(policy);

        // Drop read lock
        drop(parent);

        // Create child capability
        let child = Capability::new_child(
            owner,
            handle,
            child_domain,
            Arc::downgrade(parent_ref),
        );

        // Add child to parent's children list
        parent_ref.write().add_child(child.clone());

        Ok(child)
    }

    /// Revoke a child domain and all its descendants
    pub fn revoke_child_domain(
        parent_ref: &CapabilityRef<Domain>,
        child_handle: LocalHandle,
    ) -> Result<UpdateBatch> {
        let mut parent = parent_ref.write();

        // Remove child from parent's children list
        let child_ref = parent
            .remove_child(child_handle)
            .ok_or(CapaError::NotFound)?;

        // Drop parent lock
        drop(parent);

        // Revoke the domain subtree
        let updates = Self::revoke_domain_subtree(&child_ref)?;

        Ok(updates)
    }

    /// Recursively revoke a domain capability subtree
    fn revoke_domain_subtree(domain_ref: &CapabilityRef<Domain>) -> Result<UpdateBatch> {
        let mut domain = domain_ref.write();

        let mut updates = UpdateBatch::new();

        // Revoke all children first
        let children = mem::take(&mut domain.children);
        drop(domain); // Release lock

        for child_ref in children {
            let child_updates = Self::revoke_domain_subtree(&child_ref)?;
            updates.merge(child_updates);
        }

        // Re-acquire lock and revoke this domain
        let mut domain = domain_ref.write();
        domain.data.revoke();
        updates.add_revoke_domain(domain.data.id);

        Ok(updates)
    }
}

