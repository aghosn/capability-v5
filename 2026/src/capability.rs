//! Core capability structures with thread-safe parent-child relationships

use crate::domain::{Domain, DomainPolicy, MonitorAPI, PendingCapability};
use crate::error::{CapaError, Result};
use crate::memory::{Access, Attributes, MemoryRegion, RegionKind};
use crate::update::{DomainId, UpdateBatch};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::mem;
use crate::sync::RwLock;

/// Thread-safe reference to a capability (strong reference, owned)
pub type CapabilityRef<T> = Arc<RwLock<Capability<T>>>;

/// Thread-safe weak reference to a capability (non-owning)
pub type CapabilityWeak<T> = Weak<RwLock<Capability<T>>>;

/// Local capability handle (index within a domain's capability store)
pub type LocalHandle = u64;

/// Stable tree identity set at creation time. Used by the parent to revoke a child
/// even after the child has been sent away. Equals the LocalHandle the parent's domain
/// allocated for the child at creation; never changes.
pub type SubHandle = u64;

/// Ownership information for a capability
#[derive(Debug, Clone)]
pub struct Ownership {
    /// Domain that owns this capability
    pub owner: DomainId,
    /// Security attributes for this ownership
    pub attributes: Attributes,
    /// Weak reference to the owning domain capability (for sealed/API validation)
    pub owner_domain: Option<CapabilityWeak<Domain>>,
}

impl Ownership {
    pub fn new(owner: DomainId) -> Self {
        Ownership {
            owner,
            attributes: Attributes::NONE,
            owner_domain: None,
        }
    }

    pub fn with_attributes(owner: DomainId, attributes: Attributes) -> Self {
        Ownership {
            owner,
            attributes,
            owner_domain: None,
        }
    }

    /// Set the owning domain reference
    pub fn set_owner_domain(&mut self, domain: CapabilityWeak<Domain>) {
        self.owner_domain = Some(domain);
    }

    /// Validate that the owning domain is sealed and allows the given API operation.
    /// If no owner domain is set (e.g., standalone test capabilities), the check is skipped.
    pub fn validate_operation(&self, required_api: u16) -> Result<()> {
        if let Some(ref weak_domain) = self.owner_domain {
            let domain_ref = weak_domain.upgrade()
                .ok_or(CapaError::PermissionDenied)?;
            let domain = domain_ref.read();
            if !domain.data.is_sealed() {
                return Err(CapaError::DomainNotSealed);
            }
            if !domain.data.policy.api.has(required_api) {
                return Err(CapaError::ApiNotAllowed);
            }
        }
        Ok(())
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

    /// Stable tree identity; set at creation time; never changes
    pub sub_handle: SubHandle,

    /// Capability data (Domain or MemoryRegion)
    pub data: T,

    /// Weak reference to parent (prevents reference cycles)
    pub parent: CapabilityWeak<T>,

    /// Strong references to children (owned)
    pub children: Vec<CapabilityRef<T>>,
}

impl<T> Capability<T> {
    /// Create a new root capability (no parent)
    pub fn new_root(owner: DomainId, sub_handle: SubHandle, data: T) -> CapabilityRef<T> {
        Arc::new(RwLock::new(Capability {
            owned: Ownership::new(owner),
            sub_handle,
            data,
            parent: Weak::new(),
            children: Vec::new(),
        }))
    }

    /// Create a new child capability
    pub fn new_child(
        owner: DomainId,
        sub_handle: SubHandle,
        data: T,
        parent: CapabilityWeak<T>,
    ) -> CapabilityRef<T> {
        Arc::new(RwLock::new(Capability {
            owned: Ownership::new(owner),
            sub_handle,
            data,
            parent,
            children: Vec::new(),
        }))
    }

    /// Add a child capability
    pub fn add_child(&mut self, child: CapabilityRef<T>) {
        self.children.push(child);
    }

    /// Remove a specific child by its stable SubHandle
    pub fn remove_child(&mut self, child_sub: SubHandle) -> Option<CapabilityRef<T>> {
        if let Some(pos) = self
            .children
            .iter()
            .position(|c| c.read().sub_handle == child_sub)
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
    /// Create an aliased child region (static method, explicit owner)
    pub fn alias_child(
        parent_ref: &CapabilityRef<MemoryRegion>,
        access: Access,
        owner: DomainId,
        sub_handle: SubHandle,
    ) -> Result<CapabilityRef<MemoryRegion>> {
        let mut parent = parent_ref.write();

        // Validate owner domain is sealed and has ALIAS permission
        parent.owned.validate_operation(MonitorAPI::ALIAS)?;

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
            sub_handle,
            child_region,
            Arc::downgrade(parent_ref),
        );

        // Add child to parent's children list (still under write lock)
        parent.add_child(child.clone());

        Ok(child)
    }

    /// Create a carved child region
    pub fn carve_child(
        parent_ref: &CapabilityRef<MemoryRegion>,
        access: Access,
        owner: DomainId,
        sub_handle: SubHandle,
    ) -> Result<(CapabilityRef<MemoryRegion>, UpdateBatch)> {
        let mut parent = parent_ref.write();

        // Validate owner domain is sealed and has CARVE permission
        parent.owned.validate_operation(MonitorAPI::CARVE)?;

        // Check if the requested range overlaps with any existing children.
        for child_ref in &parent.children {
            let child = child_ref.read();
            if access.overlaps(&child.data.access) {
                return Err(CapaError::InvalidAccess);
            }
        }

        // Create carved region from parent
        let child_region = parent.data.carve(access)?;

        // Create update batch for the carve operation
        let updates = UpdateBatch::new();

        // Create child capability
        let child = Capability::new_child(
            owner,
            sub_handle,
            child_region,
            Arc::downgrade(parent_ref),
        );

        // Add child to parent's children list
        parent.add_child(child.clone());

        Ok((child, updates))
    }

    /// Send this capability to another domain.
    ///
    /// `caller` is the domain ID of the entity initiating the send.
    pub fn send_to(
        capa_ref: &CapabilityRef<MemoryRegion>,
        caller: DomainId,
        new_owner: DomainId,
        attributes: Attributes,
    ) -> Result<UpdateBatch> {
        // Phase 1 — read child + parent under read locks to determine unmap behaviour.
        let parent_owned_by_caller = {
            let capa = capa_ref.read();

            // Verify the caller is the current owner.
            if capa.owned.owner != caller {
                return Err(CapaError::PermissionDenied);
            }

            capa.owned.validate_operation(MonitorAPI::SEND)?;

            if let Some(parent_ref) = capa.get_parent() {
                parent_ref.read().owned.owner == caller
            } else {
                false
            }
        };
        // All read locks released.

        // Phase 2 — write-lock only the child.
        let mut capa = capa_ref.write();

        // Linearisability check
        if capa.owned.owner != caller {
            return Err(CapaError::PermissionDenied);
        }

        let skip_unmap = parent_owned_by_caller;

        // Update ownership and set attributes
        capa.owned.owner = new_owner;
        capa.owned.attributes = attributes;
        // Clear owner_domain since the capability now belongs to a new domain
        capa.owned.owner_domain = None;

        // Create updates
        let mut updates = UpdateBatch::new();

        if !skip_unmap {
            updates.add_unmap(caller, capa.data.access.start, capa.data.access.size);
        }

        updates.add_map(
            new_owner,
            capa.data.access.start,
            capa.data.access.size,
            capa.data.access.start,
            capa.data.access.rights.read(),
            capa.data.access.rights.write(),
            capa.data.access.rights.execute(),
        );

        Ok(updates)
    }

    /// Revoke a child capability by Arc reference
    pub fn revoke_child_ref(
        parent_ref: &CapabilityRef<MemoryRegion>,
        child_ref: &CapabilityRef<MemoryRegion>,
    ) -> Result<UpdateBatch> {
        let mut parent = parent_ref.write();

        // Validate owner domain is sealed and has REVOKE permission
        parent.owned.validate_operation(MonitorAPI::REVOKE)?;

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

    /// Revoke a child capability by its stable SubHandle
    pub fn revoke_child(
        parent_ref: &CapabilityRef<MemoryRegion>,
        child_sub: SubHandle,
    ) -> Result<UpdateBatch> {
        let mut parent = parent_ref.write();

        // Validate owner domain is sealed and has REVOKE permission
        parent.owned.validate_operation(MonitorAPI::REVOKE)?;

        // Remove child from parent's children list by sub_handle
        let child_ref = parent
            .remove_child(child_sub)
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

        if capa.data.kind == RegionKind::Carve {
            if let Some(parent_ref) = capa.get_parent() {
                let parent = parent_ref.read();
                let parent_owner = parent.owned.owner;
                let child_owner = capa.owned.owner;

                if parent_owner != child_owner {
                    updates.add_unmap(child_owner, capa.data.access.start, capa.data.access.size);

                    updates.add_map(
                        parent_owner,
                        capa.data.access.start,
                        capa.data.access.size,
                        capa.data.access.start,
                        parent.data.access.rights.read(),
                        parent.data.access.rights.write(),
                        parent.data.access.rights.execute(),
                    );
                }
            }
        }

        if capa.owned.attributes.vital() {
            updates.add_revoke_domain_with_fallback(capa.owned.owner, None);
        }

        Ok(updates)
    }

    /// Compute the current view of memory (considering carved children)
    pub fn compute_view(&self) -> Vec<Access> {
        let mut view = vec![self.data.access];
        let parent_owner = self.owned.owner;

        for child_ref in &self.children {
            let child = child_ref.read();
            if child.data.kind == RegionKind::Carve && child.owned.owner != parent_owner {
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
            result.push(*region);
        } else {
            if region.start < to_subtract.start {
                result.push(Access::new(
                    region.start,
                    to_subtract.start - region.start,
                    region.rights,
                ));
            }
            if region.end() > to_subtract.end() {
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
    /// Create a child domain (static method, explicit owner)
    pub fn create_child_domain(
        parent_ref: &CapabilityRef<Domain>,
        policy: DomainPolicy,
        owner: DomainId,
        sub_handle: SubHandle,
    ) -> Result<CapabilityRef<Domain>> {
        let parent = parent_ref.read();

        if !parent.data.is_sealed() {
            return Err(CapaError::DomainNotSealed);
        }

        parent.owned.validate_operation(MonitorAPI::CREATE)?;

        policy.is_subset_of(&parent.data.policy)?;

        let child_domain = Domain::new(policy);

        drop(parent);

        let child = Capability::new_child(
            owner,
            sub_handle,
            child_domain,
            Arc::downgrade(parent_ref),
        );

        parent_ref.write().add_child(child.clone());

        Ok(child)
    }

    /// Revoke a child domain and all its descendants by SubHandle
    pub fn revoke_child_domain(
        parent_ref: &CapabilityRef<Domain>,
        child_sub: SubHandle,
    ) -> Result<UpdateBatch> {
        let mut parent = parent_ref.write();

        parent.owned.validate_operation(MonitorAPI::REVOKE)?;

        let child_ref = parent
            .remove_child(child_sub)
            .ok_or(CapaError::NotFound)?;

        let parent_id = parent.data.id;
        drop(parent);

        let updates = Self::revoke_domain_subtree(&child_ref, Some(parent_id))?;

        Ok(updates)
    }

    /// Recursively revoke a domain capability subtree.
    fn revoke_domain_subtree(
        domain_ref: &CapabilityRef<Domain>,
        fallback: Option<DomainId>,
    ) -> Result<UpdateBatch> {
        let mut domain = domain_ref.write();

        let mut updates = UpdateBatch::new();

        let children = mem::take(&mut domain.children);
        drop(domain);

        for child_ref in children {
            let child_updates = Self::revoke_domain_subtree(&child_ref, fallback)?;
            updates.merge(child_updates);
        }

        let mut domain = domain_ref.write();
        domain.data.revoke();
        updates.add_revoke_domain_with_fallback(domain.data.id, fallback);

        Ok(updates)
    }

    // =========================================================================
    // Domain-mediated high-level operations
    // =========================================================================

    /// Carve a memory sub-region. Resolves `parent` handle from caller's table,
    /// auto-allocates a new LocalHandle for the child, registers it in caller's table,
    /// and uses that handle value as the child's SubHandle.
    pub fn carve_memory(
        caller: &CapabilityRef<Domain>,
        parent: LocalHandle,
        access: Access,
    ) -> Result<(LocalHandle, UpdateBatch)> {
        // 1. Validate parent handle not frozen
        if caller.read().data.is_memory_handle_frozen(parent) {
            return Err(CapaError::PermissionDenied);
        }

        // 2. Resolve parent ref
        let parent_weak = caller.read().data
            .get_memory_capability(parent)
            .ok_or(CapaError::NotFound)?
            .clone();
        let parent_ref = parent_weak.upgrade().ok_or(CapaError::NotFound)?;

        // 3. Verify ownership
        let owner_id = caller.read().data.id;
        if parent_ref.read().owned.owner != owner_id {
            return Err(CapaError::PermissionDenied);
        }

        // 4. Auto-allocate new handle
        let new_handle = caller.read().data.allocate_memory_handle();

        // 5. Call carve_child (new_handle used as sub_handle)
        let (child_ref, updates) = Capability::carve_child(&parent_ref, access, owner_id, new_handle)?;

        // 6. Set owner_domain on child
        child_ref.write().owned.owner_domain = Some(Arc::downgrade(caller));

        // 7. Register child in caller's table
        caller.write().data.add_memory_capability(new_handle, Arc::downgrade(&child_ref));

        Ok((new_handle, updates))
    }

    /// Alias a memory sub-region. Same handle bookkeeping as carve_memory.
    pub fn alias_memory(
        caller: &CapabilityRef<Domain>,
        parent: LocalHandle,
        access: Access,
    ) -> Result<LocalHandle> {
        // 1. Validate parent handle not frozen
        if caller.read().data.is_memory_handle_frozen(parent) {
            return Err(CapaError::PermissionDenied);
        }

        // 2. Resolve parent ref
        let parent_weak = caller.read().data
            .get_memory_capability(parent)
            .ok_or(CapaError::NotFound)?
            .clone();
        let parent_ref = parent_weak.upgrade().ok_or(CapaError::NotFound)?;

        // 3. Verify ownership
        let owner_id = caller.read().data.id;
        if parent_ref.read().owned.owner != owner_id {
            return Err(CapaError::PermissionDenied);
        }

        // 4. Auto-allocate new handle
        let new_handle = caller.read().data.allocate_memory_handle();

        // 5. Call alias_child
        let child_ref = Capability::alias_child(&parent_ref, access, owner_id, new_handle)?;

        // 6. Set owner_domain on child
        child_ref.write().owned.owner_domain = Some(Arc::downgrade(caller));

        // 7. Register child in caller's table
        caller.write().data.add_memory_capability(new_handle, Arc::downgrade(&child_ref));

        Ok(new_handle)
    }

    /// Send a memory capability to another domain (freeze model).
    /// The caller's LocalHandle is frozen; the capability is placed in the receiver's
    /// pending queue. No MMU operation yet.
    pub fn send_memory(
        caller: &CapabilityRef<Domain>,
        cap: LocalHandle,
        receiver: &CapabilityRef<Domain>,
        attrs: Attributes,
    ) -> Result<()> {
        // 1. Check cap not already frozen
        if caller.read().data.is_memory_handle_frozen(cap) {
            return Err(CapaError::PermissionDenied);
        }

        // 2. Resolve cap ref
        let cap_weak = caller.read().data
            .get_memory_capability(cap)
            .ok_or(CapaError::NotFound)?
            .clone();
        let cap_ref = cap_weak.upgrade().ok_or(CapaError::NotFound)?;

        // 3. Verify ownership
        let caller_id = caller.read().data.id;
        if cap_ref.read().owned.owner != caller_id {
            return Err(CapaError::PermissionDenied);
        }

        // 4. Validate operation
        cap_ref.read().owned.validate_operation(MonitorAPI::SEND)?;

        // 5. Check receiver can accept
        {
            let recv = receiver.read();
            if !recv.data.policy.receive_after_seal() || !recv.data.is_sealed() {
                return Err(CapaError::PermissionDenied);
            }
        }

        // 6. Update cap attributes
        cap_ref.write().owned.attributes = attrs;

        // 7. Atomically freeze handle under write lock (TOCTOU prevention:
        //    re-check frozen status after acquiring the write lock so that two
        //    concurrent send_memory calls for the same handle cannot both slip
        //    through the read-lock check and both freeze/enqueue the cap).
        {
            let mut caller_w = caller.write();
            if caller_w.data.is_memory_handle_frozen(cap) {
                return Err(CapaError::PermissionDenied);
            }
            caller_w.data.freeze_memory_handle(cap);
        }

        // 8. Build PendingCapability and add to receiver
        let pending = PendingCapability {
            cap: Arc::downgrade(&cap_ref),
            sender_domain_id: caller_id,
            sender_handle: cap,
            sender_domain: Arc::downgrade(caller),
        };
        receiver.write().data.add_pending_capability(pending);

        Ok(())
    }

    /// Accept a pending memory capability. Auto-allocates a new LocalHandle in the
    /// receiver's table. Fires the actual MMU unmap (sender) + map (receiver).
    pub fn accept_memory(
        receiver: &CapabilityRef<Domain>,
        pending_id: u64,
    ) -> Result<(LocalHandle, UpdateBatch)> {
        // 1. Atomically take the pending entry under a write lock.
        //    This ensures that two concurrent accept calls (or an accept+reject race)
        //    cannot both find the entry — only one proceeds, the other gets NotFound.
        let (sender_domain_id, sender_handle, cap_weak, sender_domain_weak) = {
            let mut recv = receiver.write();
            let pending = recv.data.pending_capabilities.remove(&pending_id)
                .ok_or(CapaError::NotFound)?;
            (
                pending.sender_domain_id,
                pending.sender_handle,
                pending.cap,
                pending.sender_domain,
            )
        };

        // 2. Upgrade weak refs
        let cap_ref = cap_weak.upgrade().ok_or(CapaError::NotFound)?;
        let sender_ref = sender_domain_weak.upgrade().ok_or(CapaError::PermissionDenied)?;

        // Check sender domain not revoked — domain revocation cancels pending transfers.
        // If the sending domain was revoked after the transfer was initiated, the
        // receiver must not be able to accept the capability.
        if sender_ref.read().data.is_revoked() {
            return Err(CapaError::PermissionDenied);
        }

        // 3. Collect cap info before modification (skip_unmap logic)
        let (skip_unmap, cap_access) = {
            let cap = cap_ref.read();
            let skip_unmap = if let Some(parent_ref) = cap.get_parent() {
                parent_ref.read().owned.owner == sender_domain_id
            } else {
                false
            };
            (skip_unmap, cap.data.access)
        };

        let receiver_id = receiver.read().data.id;
        let new_handle = receiver.read().data.allocate_memory_handle();

        // 4. Remove cap from sender's tables
        {
            let mut s = sender_ref.write();
            s.data.remove_memory_capability(sender_handle);
            s.data.unfreeze_memory_handle(sender_handle);
        }

        // 6. Update cap ownership
        {
            let mut cap = cap_ref.write();
            cap.owned.owner = receiver_id;
            cap.owned.owner_domain = Some(Arc::downgrade(receiver));
        }

        // 7. Register in receiver's table
        receiver.write().data.add_memory_capability(new_handle, Arc::downgrade(&cap_ref));

        // 8. Build update batch
        let mut updates = UpdateBatch::new();
        if !skip_unmap {
            updates.add_unmap(sender_domain_id, cap_access.start, cap_access.size);
        }
        updates.add_map(
            receiver_id,
            cap_access.start,
            cap_access.size,
            cap_access.start,
            cap_access.rights.read(),
            cap_access.rights.write(),
            cap_access.rights.execute(),
        );

        Ok((new_handle, updates))
    }

    /// Reject a pending memory capability. Unfreezes the sender's LocalHandle.
    pub fn reject_memory(
        receiver: &CapabilityRef<Domain>,
        pending_id: u64,
    ) -> Result<()> {
        // 1. Remove pending from receiver
        let pending = {
            let mut recv = receiver.write();
            recv.data.pending_capabilities.remove(&pending_id)
                .ok_or(CapaError::NotFound)?
        };

        // 2. Unfreeze sender's handle
        if let Some(sender_ref) = pending.sender_domain.upgrade() {
            sender_ref.write().data.unfreeze_memory_handle(pending.sender_handle);
        }

        Ok(())
    }

    /// Revoke a child memory capability using its stable SubHandle.
    pub fn revoke_memory_child(
        caller: &CapabilityRef<Domain>,
        parent: LocalHandle,
        child_sub: SubHandle,
    ) -> Result<UpdateBatch> {
        // 1. Validate parent handle not frozen
        if caller.read().data.is_memory_handle_frozen(parent) {
            return Err(CapaError::PermissionDenied);
        }

        // 2. Resolve parent ref
        let parent_weak = caller.read().data
            .get_memory_capability(parent)
            .ok_or(CapaError::NotFound)?
            .clone();
        let parent_ref = parent_weak.upgrade().ok_or(CapaError::NotFound)?;

        // 3. Verify ownership
        let owner_id = caller.read().data.id;
        if parent_ref.read().owned.owner != owner_id {
            return Err(CapaError::PermissionDenied);
        }

        // 4. Call revoke_child
        Capability::revoke_child(&parent_ref, child_sub)
    }

    /// Voluntarily release a leaf memory capability.
    pub fn release_memory(
        caller: &CapabilityRef<Domain>,
        cap: LocalHandle,
    ) -> Result<()> {
        // 1. Validate handle not frozen
        if caller.read().data.is_memory_handle_frozen(cap) {
            return Err(CapaError::PermissionDenied);
        }

        // 2. Resolve cap ref
        let cap_weak = caller.read().data
            .get_memory_capability(cap)
            .ok_or(CapaError::NotFound)?
            .clone();
        let cap_ref = cap_weak.upgrade().ok_or(CapaError::NotFound)?;

        // 3. Verify ownership, verify no children
        let caller_id = caller.read().data.id;
        {
            let cap_read = cap_ref.read();
            if cap_read.owned.owner != caller_id {
                return Err(CapaError::PermissionDenied);
            }
            if !cap_read.children.is_empty() {
                return Err(CapaError::PermissionDenied);
            }
        }

        // 4. Remove from parent's children
        let child_sub = cap_ref.read().sub_handle;
        let parent_opt = cap_ref.read().get_parent();
        if let Some(parent_ref) = parent_opt {
            parent_ref.write().remove_child(child_sub);
        }

        // 5. Remove from caller's table
        caller.write().data.remove_memory_capability(cap);

        Ok(())
    }

    /// Create a child domain under the domain identified by parent handle.
    pub fn create_child_domain_op(
        caller: &CapabilityRef<Domain>,
        parent: LocalHandle,
        policy: DomainPolicy,
    ) -> Result<LocalHandle> {
        // 1. Validate parent handle not frozen
        if caller.read().data.is_domain_handle_frozen(parent) {
            return Err(CapaError::PermissionDenied);
        }

        // 2. Resolve parent domain ref
        let parent_weak = caller.read().data
            .get_domain_capability(parent)
            .ok_or(CapaError::NotFound)?
            .clone();
        let parent_ref = parent_weak.upgrade().ok_or(CapaError::NotFound)?;

        // 3. Auto-allocate new handle
        let new_handle = caller.read().data.allocate_domain_handle();

        // 4. Get owner id
        let owner_id = caller.read().data.id;

        // 5. Call create_child_domain
        let child_ref = Capability::create_child_domain(&parent_ref, policy, owner_id, new_handle)?;

        // 6. Set owner_domain on child
        child_ref.write().owned.owner_domain = Some(Arc::downgrade(caller));

        // 7. Register in caller's table
        caller.write().data.add_domain_capability(new_handle, Arc::downgrade(&child_ref));

        Ok(new_handle)
    }

    /// Seal the domain identified by cap handle.
    pub fn seal_domain_op(
        caller: &CapabilityRef<Domain>,
        cap: LocalHandle,
    ) -> Result<()> {
        let cap_weak = caller.read().data
            .get_domain_capability(cap)
            .ok_or(CapaError::NotFound)?
            .clone();
        let cap_ref = cap_weak.upgrade().ok_or(CapaError::NotFound)?;
        let result = cap_ref.write().data.seal();
        result
    }

    /// Revoke a child domain using its stable SubHandle.
    pub fn revoke_child_domain_op(
        caller: &CapabilityRef<Domain>,
        parent: LocalHandle,
        child_sub: SubHandle,
    ) -> Result<UpdateBatch> {
        let parent_weak = caller.read().data
            .get_domain_capability(parent)
            .ok_or(CapaError::NotFound)?
            .clone();
        let parent_ref = parent_weak.upgrade().ok_or(CapaError::NotFound)?;
        Capability::revoke_child_domain(&parent_ref, child_sub)
    }
}
