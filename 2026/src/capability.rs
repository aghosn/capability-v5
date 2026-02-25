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
    /// Security attributes for this ownership
    pub attributes: Attributes,
}

impl Ownership {
    pub fn new(owner: DomainId, handle: LocalHandle) -> Self {
        Ownership {
            owner,
            handle,
            attributes: Attributes::NONE,
        }
    }

    pub fn with_attributes(owner: DomainId, handle: LocalHandle, attributes: Attributes) -> Self {
        Ownership {
            owner,
            handle,
            attributes,
        }
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

/// Extension trait for CapabilityRef<MemoryRegion> to provide instance methods
pub trait MemoryCapabilityExt {
    /// Create an aliased child region (instance method, infers owner from parent)
    fn alias(&self, access: Access, handle: LocalHandle) -> Result<CapabilityRef<MemoryRegion>>;

    /// Create a carved child region (instance method, infers owner from parent)
    fn carve(&self, access: Access, handle: LocalHandle) -> Result<(CapabilityRef<MemoryRegion>, UpdateBatch)>;

    /// Send this capability to another domain (instance method)
    fn send(&self, new_owner: DomainId, new_handle: LocalHandle, attributes: Attributes) -> Result<UpdateBatch>;

    /// Revoke a child capability by handle (instance method)
    fn revoke(&self, child_handle: LocalHandle) -> Result<UpdateBatch>;

    /// Revoke a child capability by Arc reference (instance method)
    fn revoke_ref(&self, child: &CapabilityRef<MemoryRegion>) -> Result<UpdateBatch>;
}

impl MemoryCapabilityExt for CapabilityRef<MemoryRegion> {
    fn alias(&self, access: Access, handle: LocalHandle) -> Result<CapabilityRef<MemoryRegion>> {
        // Infer owner from parent
        let owner = self.read().owned.owner;
        Capability::alias_child(self, access, owner, handle)
    }

    fn carve(&self, access: Access, handle: LocalHandle) -> Result<(CapabilityRef<MemoryRegion>, UpdateBatch)> {
        // Infer owner from parent
        let owner = self.read().owned.owner;
        Capability::carve_child(self, access, owner, handle)
    }

    fn send(&self, new_owner: DomainId, new_handle: LocalHandle, attributes: Attributes) -> Result<UpdateBatch> {
        Capability::send_to(self, new_owner, new_handle, attributes)
    }

    fn revoke(&self, child_handle: LocalHandle) -> Result<UpdateBatch> {
        Capability::revoke_child(self, child_handle)
    }

    fn revoke_ref(&self, child: &CapabilityRef<MemoryRegion>) -> Result<UpdateBatch> {
        Capability::revoke_child_ref(self, child)
    }
}

impl Capability<MemoryRegion> {
    /// Create an aliased child region (static method, explicit owner)
    pub fn alias_child(
        parent_ref: &CapabilityRef<MemoryRegion>,
        access: Access,
        owner: DomainId,
        handle: LocalHandle,
    ) -> Result<CapabilityRef<MemoryRegion>> {
        let parent = parent_ref.read();

        // Check if the requested range overlaps with any existing carved children
        // Aliasing is not allowed to overlap with carved regions
        for child_ref in &parent.children {
            let child = child_ref.read();
            if child.data.kind == RegionKind::Carve && access.overlaps(&child.data.access) {
                return Err(CapaError::InvalidAccess);
            }
        }

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

        // Check if the requested range overlaps with any existing children.
        // Carving is not allowed to overlap with carved regions (exclusivity) or
        // aliased regions (an alias means shared access already exists in that range,
        // so a carve would falsely appear exclusive).
        for child_ref in &parent.children {
            let child = child_ref.read();
            if access.overlaps(&child.data.access) {
                return Err(CapaError::InvalidAccess);
            }
        }

        // Create carved region from parent
        let child_region = parent.data.carve(access)?;

        // Drop parent read lock
        drop(parent);

        // Create update batch for the carve operation
        let updates = UpdateBatch::new();

        // IMPORTANT: When carving, the owner of the child is the same as the owner
        // of the parent. According to the paper (Section 4.2), carving removes access
        // from the parent capability's view, but since ownership doesn't change,
        // the parent owner retains access to the memory region through the child capability.
        // Therefore, NO unmapping is needed here.
        //
        // Only when the child is sent to a different domain (changing ownership) or
        // when the child is revoked should address space updates occur.

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

        // Check if old owner retains access via parent capability
        let parent_owned_by_old_owner = if let Some(parent_ref) = capa.get_parent() {
            parent_ref.read().owned.owner == old_owner
        } else {
            false
        };

        // Update ownership and set attributes
        capa.owned.owner = new_owner;
        capa.owned.handle = new_handle;
        capa.owned.attributes = attributes;

        // Create updates
        let mut updates = UpdateBatch::new();

        // IMPORTANT: According to the paper (Section 4.2), when sending a capability,
        // we might or might not lose access to the region depending on whether we
        // retain ownership over a memory capability that covers the same region.
        //
        // Key insight: If the old owner still owns the parent capability, they retain
        // access to this memory region through the parent, so we should NOT unmap.
        // We only unmap if the old owner loses all ownership over capabilities covering
        // this region.
        //
        // NOTE: This is a simplification. A complete implementation would need to check
        // all ancestor capabilities and sibling capabilities for overlaps. For now, we
        // only check the direct parent.

        if !parent_owned_by_old_owner {
            // Old owner loses access - unmap from their address space
            updates.add_unmap(old_owner, capa.data.access.start, capa.data.access.size);
        }

        // Map to new owner's address space (identity mapping - no remapping)
        updates.add_map(
            new_owner,
            capa.data.access.start,
            capa.data.access.size,
            capa.data.access.start, // Physical address is same as virtual (identity mapping)
            capa.data.access.rights.read(),
            capa.data.access.rights.write(),
            capa.data.access.rights.execute(),
        );

        Ok(updates)
    }

    /// Revoke a child capability by Arc reference
    ///
    /// This is useful when you have a direct reference to the child capability
    pub fn revoke_child_ref(
        parent_ref: &CapabilityRef<MemoryRegion>,
        child_ref: &CapabilityRef<MemoryRegion>,
    ) -> Result<UpdateBatch> {
        let mut parent = parent_ref.write();

        // Find and remove child by Arc pointer equality
        let child_arc_ptr = Arc::as_ptr(child_ref);
        let pos = parent
            .children
            .iter()
            .position(|c| Arc::as_ptr(c) == child_arc_ptr)
            .ok_or(CapaError::NotFound)?;

        let child = parent.children.remove(pos);

        // Drop parent lock before recursing
        drop(parent);

        // Collect updates from revoking the entire subtree
        let updates = Self::revoke_subtree(&child)?;

        Ok(updates)
    }

    /// Revoke a child capability by handle
    ///
    /// NOTE: This searches for a child with the CURRENT handle matching child_handle.
    /// If a child was sent to another domain (changing its handle), this will NOT find it.
    /// Use revoke_child_ref() instead if you have a reference to the child.
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
        if capa.owned.attributes.clean() {
            updates.add_zero_memory(capa.data.access.start, capa.data.access.size);
        }

        // IMPORTANT: Handle re-enabling parent access for carved regions
        //
        // According to the paper (Section 4.2), when a carved region is revoked:
        // 1. If the child was never sent to another domain (owner == parent owner):
        //    - Parent never lost access, no remapping needed
        // 2. If the child was sent to another domain (owner != parent owner):
        //    - Parent lost access when the child was sent
        //    - Parent should regain access when the child is revoked
        //    - We need to add a map update to restore parent's access
        //
        // Check if this was a carved region that was sent to a different domain
        if capa.data.kind == RegionKind::Carve {
            if let Some(parent_ref) = capa.get_parent() {
                let parent = parent_ref.read();
                let parent_owner = parent.owned.owner;
                let child_owner = capa.owned.owner;

                // If the child was sent to a different domain, parent needs to regain access
                if parent_owner != child_owner {
                    // Unmap from child's address space (they're losing the capability)
                    updates.add_unmap(child_owner, capa.data.access.start, capa.data.access.size);

                    // Remap to parent's address space (they regain access)
                    updates.add_map(
                        parent_owner,
                        capa.data.access.start,
                        capa.data.access.size,
                        capa.data.access.start, // Identity mapping
                        parent.data.access.rights.read(),
                        parent.data.access.rights.write(),
                        parent.data.access.rights.execute(),
                    );
                }
            }
        }

        // If vital, revoke the owning domain
        if capa.owned.attributes.vital() {
            updates.add_revoke_domain(capa.owned.owner);
        }

        Ok(updates)
    }

    /// Compute the current view of memory (considering carved children)
    pub fn compute_view(&self) -> Vec<Access> {
        let mut view = vec![self.data.access];
        let parent_owner = self.owned.owner;

        // Subtract carved children that were sent to different domains
        // If a carved child is still owned by the same domain, it's still accessible
        for child_ref in &self.children {
            let child = child_ref.read();
            if child.data.kind == RegionKind::Carve && child.owned.owner != parent_owner {
                // Child was sent to another domain - remove from parent's view
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

/// Extension trait for CapabilityRef<Domain> to provide instance methods
pub trait DomainCapabilityExt {
    /// Create a child domain (instance method, infers owner from parent)
    fn create_child(&self, policy: DomainPolicy, handle: LocalHandle) -> Result<CapabilityRef<Domain>>;

    /// Revoke a child domain (instance method)
    fn revoke_child(&self, child_handle: LocalHandle) -> Result<UpdateBatch>;
}

impl DomainCapabilityExt for CapabilityRef<Domain> {
    fn create_child(&self, policy: DomainPolicy, handle: LocalHandle) -> Result<CapabilityRef<Domain>> {
        // Infer owner from parent
        let owner = self.read().owned.owner;
        Capability::create_child_domain(self, policy, owner, handle)
    }

    fn revoke_child(&self, child_handle: LocalHandle) -> Result<UpdateBatch> {
        Capability::revoke_child_domain(self, child_handle)
    }
}

impl Capability<Domain> {
    /// Create a child domain (static method, explicit owner)
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

