//! Core capability structures with thread-safe parent-child relationships

use crate::domain::{Domain, DomainPolicy, MonitorAPI, PendingCapability};
use crate::error::{CapaError, Result};
use crate::memory::{Access, Attributes, MemoryRegion, RegionKind};
use crate::sync::RwLock;
use crate::update::{DomainId, UpdateBatch};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::mem;

/// Thread-safe reference to a capability (strong reference, owned)
pub type CapabilityRef<T> = Arc<RwLock<Capability<T>>>;

/// Thread-safe weak reference to a capability (non-owning)
pub type CapabilityWeak<T> = Weak<RwLock<Capability<T>>>;

/// Local capability handle (index within a domain's capability store)
pub type LocalHandle = u64;

/// Stable tree identity set at creation time, auto-allocated from the parent
/// capability's internal counter.  Unique among siblings; used by the parent
/// to find and remove a specific child during revocation.  Completely independent
/// from `LocalHandle` (the domain's table key for the same capability).
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
            let domain_ref = weak_domain.upgrade().ok_or(CapaError::PermissionDenied)?;
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
    /// Per-capability counter for assigning unique SubHandles to children.
    /// Starts at 1 and increments monotonically; never decremented on revoke.
    pub next_child_sub: SubHandle,
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
            next_child_sub: 1,
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
            next_child_sub: 1,
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

        // Auto-allocate a unique SubHandle from the parent's counter
        let sub_handle = parent.next_child_sub;
        parent.next_child_sub += 1;

        // Create child capability
        let child =
            Capability::new_child(owner, sub_handle, child_region, Arc::downgrade(parent_ref));

        // Add child to parent's children list (still under write lock)
        parent.add_child(child.clone());

        Ok(child)
    }

    /// Create a carved child region
    pub fn carve_child(
        parent_ref: &CapabilityRef<MemoryRegion>,
        access: Access,
        owner: DomainId,
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

        // Auto-allocate a unique SubHandle from the parent's counter
        let sub_handle = parent.next_child_sub;
        parent.next_child_sub += 1;

        // Create child capability
        let child =
            Capability::new_child(owner, sub_handle, child_region, Arc::downgrade(parent_ref));

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
        let child_ref = parent.remove_child(child_sub).ok_or(CapaError::NotFound)?;

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
    ) -> Result<CapabilityRef<Domain>> {
        let parent = parent_ref.read();

        if !parent.data.is_sealed() {
            return Err(CapaError::DomainNotSealed);
        }

        parent.owned.validate_operation(MonitorAPI::CREATE)?;

        policy.is_subset_of(&parent.data.policy)?;

        let child_domain = Domain::new(policy);

        drop(parent);

        // Auto-allocate a unique SubHandle from the parent's counter
        let sub_handle = {
            let mut parent = parent_ref.write();
            let s = parent.next_child_sub;
            parent.next_child_sub += 1;
            s
        };

        let child =
            Capability::new_child(owner, sub_handle, child_domain, Arc::downgrade(parent_ref));

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

        let child_ref = parent.remove_child(child_sub).ok_or(CapaError::NotFound)?;

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

    /// Carve a memory sub-region.  Returns `(LocalHandle, SubHandle, UpdateBatch)`.
    ///
    /// - `LocalHandle`: the caller's domain-table key for the new child.
    /// - `SubHandle`: the child's stable tree identity (auto-allocated from the
    ///   parent capability's counter).  Pass this to [`revoke_memory_child`] to
    ///   revoke the child even after it has been sent to another domain.
    pub fn carve_memory(
        caller: &CapabilityRef<Domain>,
        parent: LocalHandle,
        access: Access,
    ) -> Result<(LocalHandle, SubHandle, UpdateBatch)> {
        // 1. Validate parent handle not frozen
        if caller.read().data.is_memory_handle_frozen(parent) {
            return Err(CapaError::PermissionDenied);
        }

        // 2. Resolve parent ref
        let parent_weak = caller
            .read()
            .data
            .get_memory_capability(parent)
            .ok_or(CapaError::NotFound)?
            .clone();
        let parent_ref = parent_weak.upgrade().ok_or(CapaError::NotFound)?;

        // 3. Verify ownership
        let owner_id = caller.read().data.id;
        if parent_ref.read().owned.owner != owner_id {
            return Err(CapaError::PermissionDenied);
        }

        // 4. Auto-allocate new LocalHandle in caller's table
        let new_handle = caller.read().data.allocate_memory_handle();

        // 5. Carve child — SubHandle auto-allocated from parent's counter
        let (child_ref, updates) =
            Capability::carve_child(&parent_ref, access, owner_id)?;

        // Capture the auto-assigned sub_handle for the caller
        let child_sub = child_ref.read().sub_handle;

        // 6. Set owner_domain on child
        child_ref.write().owned.owner_domain = Some(Arc::downgrade(caller));

        // 7. Register child in caller's table
        caller
            .write()
            .data
            .add_memory_capability(new_handle, Arc::downgrade(&child_ref));

        Ok((new_handle, child_sub, updates))
    }

    /// Alias a memory sub-region.  Returns `(LocalHandle, SubHandle)`.
    ///
    /// See [`carve_memory`] for the meaning of each return value.
    pub fn alias_memory(
        caller: &CapabilityRef<Domain>,
        parent: LocalHandle,
        access: Access,
    ) -> Result<(LocalHandle, SubHandle)> {
        // 1. Validate parent handle not frozen
        if caller.read().data.is_memory_handle_frozen(parent) {
            return Err(CapaError::PermissionDenied);
        }

        // 2. Resolve parent ref
        let parent_weak = caller
            .read()
            .data
            .get_memory_capability(parent)
            .ok_or(CapaError::NotFound)?
            .clone();
        let parent_ref = parent_weak.upgrade().ok_or(CapaError::NotFound)?;

        // 3. Verify ownership
        let owner_id = caller.read().data.id;
        if parent_ref.read().owned.owner != owner_id {
            return Err(CapaError::PermissionDenied);
        }

        // 4. Auto-allocate new LocalHandle in caller's table
        let new_handle = caller.read().data.allocate_memory_handle();

        // 5. Alias child — SubHandle auto-allocated from parent's counter
        let child_ref = Capability::alias_child(&parent_ref, access, owner_id)?;

        // Capture the auto-assigned sub_handle for the caller
        let child_sub = child_ref.read().sub_handle;

        // 6. Set owner_domain on child
        child_ref.write().owned.owner_domain = Some(Arc::downgrade(caller));

        // 7. Register child in caller's table
        caller
            .write()
            .data
            .add_memory_capability(new_handle, Arc::downgrade(&child_ref));

        Ok((new_handle, child_sub))
    }

    /// Send a memory capability to a receiver domain.
    ///
    /// `receiver` is a LocalHandle identifying the target domain in `caller`'s
    /// domain table.  By construction, a domain you send to is a child you
    /// created (or at least a domain reference you hold), so the handle must
    /// already exist in `caller`'s domain_capabilities table.
    ///
    /// - If the receiver is **unsealed**, ownership is transferred immediately and
    ///   MMU updates are returned.
    /// - If the receiver is **sealed** with `RECEIVE_AFTER_SEAL`, the caller's
    ///   LocalHandle is frozen and the capability is placed in the receiver's
    ///   pending queue (no MMU operation yet).
    /// - If the receiver is **sealed** without `RECEIVE_AFTER_SEAL`, the send is
    ///   rejected.
    pub fn send_memory(
        caller: &CapabilityRef<Domain>,
        cap: LocalHandle,
        receiver: LocalHandle,
        attrs: Attributes,
    ) -> Result<UpdateBatch> {
        // 1. Check cap not already frozen
        if caller.read().data.is_memory_handle_frozen(cap) {
            return Err(CapaError::PermissionDenied);
        }

        // 2. Resolve cap ref
        let cap_weak = caller
            .read()
            .data
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

        // 5. Resolve receiver from caller's domain table
        let recv_weak = caller
            .read()
            .data
            .get_domain_capability(receiver)
            .ok_or(CapaError::NotFound)?
            .clone();
        let receiver = recv_weak.upgrade().ok_or(CapaError::NotFound)?;

        // 6. Branch on receiver state
        let recv_sealed = receiver.read().data.is_sealed();

        if recv_sealed {
            // Sealed receiver — must have RECEIVE_AFTER_SEAL, use pending queue
            if !receiver.read().data.policy.receive_after_seal() {
                return Err(CapaError::PermissionDenied);
            }

            // Update cap attributes
            cap_ref.write().owned.attributes = attrs;

            // Atomically freeze handle under write lock (TOCTOU prevention)
            {
                let mut caller_w = caller.write();
                if caller_w.data.is_memory_handle_frozen(cap) {
                    return Err(CapaError::PermissionDenied);
                }
                caller_w.data.freeze_memory_handle(cap);
            }

            // Build PendingCapability and add to receiver
            let pending = PendingCapability {
                cap: Arc::downgrade(&cap_ref),
                sender_domain_id: caller_id,
                sender_handle: cap,
                sender_domain: Arc::downgrade(caller),
            };
            receiver.write().data.add_pending_capability(pending);

            Ok(UpdateBatch::new())
        } else {
            // Unsealed receiver — immediate transfer
            let (skip_unmap, cap_access) = {
                let cap = cap_ref.read();
                let skip_unmap = if let Some(parent_ref) = cap.get_parent() {
                    parent_ref.read().owned.owner == caller_id
                } else {
                    false
                };
                (skip_unmap, cap.data.access)
            };

            let receiver_id = receiver.read().data.id;
            let new_handle = receiver.read().data.allocate_memory_handle();

            // Remove cap from sender's table
            caller.write().data.remove_memory_capability(cap);

            // Update cap ownership
            {
                let mut cap = cap_ref.write();
                cap.owned.owner = receiver_id;
                cap.owned.attributes = attrs;
                cap.owned.owner_domain = Some(Arc::downgrade(&receiver));
            }

            // Register in receiver's table
            receiver
                .write()
                .data
                .add_memory_capability(new_handle, Arc::downgrade(&cap_ref));

            // Build update batch
            let mut updates = UpdateBatch::new();
            if !skip_unmap {
                updates.add_unmap(caller_id, cap_access.start, cap_access.size);
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

            Ok(updates)
        }
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
            let pending = recv
                .data
                .pending_capabilities
                .remove(&pending_id)
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
        let sender_ref = sender_domain_weak
            .upgrade()
            .ok_or(CapaError::PermissionDenied)?;

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
        receiver
            .write()
            .data
            .add_memory_capability(new_handle, Arc::downgrade(&cap_ref));

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
    pub fn reject_memory(receiver: &CapabilityRef<Domain>, pending_id: u64) -> Result<()> {
        // 1. Remove pending from receiver
        let pending = {
            let mut recv = receiver.write();
            recv.data
                .pending_capabilities
                .remove(&pending_id)
                .ok_or(CapaError::NotFound)?
        };

        // 2. Unfreeze sender's handle
        if let Some(sender_ref) = pending.sender_domain.upgrade() {
            sender_ref
                .write()
                .data
                .unfreeze_memory_handle(pending.sender_handle);
        }

        Ok(())
    }

    /// Revoke a direct child of the parent capability identified by `child_sub`.
    ///
    /// `parent` is the LocalHandle of the parent memory region in `caller`'s table.
    /// `child_sub` is the SubHandle returned by [`carve_memory`] or [`alias_memory`]
    /// when the child was created.  Because SubHandles are auto-allocated from the
    /// parent's internal counter they are unique among siblings and stable across
    /// ownership transfers — so this call succeeds even after the child has been
    /// sent to another domain.
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
        let parent_weak = caller
            .read()
            .data
            .get_memory_capability(parent)
            .ok_or(CapaError::NotFound)?
            .clone();
        let parent_ref = parent_weak.upgrade().ok_or(CapaError::NotFound)?;

        // 3. Verify ownership of parent
        let owner_id = caller.read().data.id;
        if parent_ref.read().owned.owner != owner_id {
            return Err(CapaError::PermissionDenied);
        }

        // 4. Revoke child by its SubHandle (unique, stable, tree-level identity)
        Capability::revoke_child(&parent_ref, child_sub)
    }

    /// Seal the domain identified by cap handle.
    pub fn seal_domain_op(caller: &CapabilityRef<Domain>, cap: LocalHandle) -> Result<()> {
        let cap_weak = caller
            .read()
            .data
            .get_domain_capability(cap)
            .ok_or(CapaError::NotFound)?
            .clone();
        let cap_ref = cap_weak.upgrade().ok_or(CapaError::NotFound)?;
        let result = cap_ref.write().data.seal();
        result
    }

    /// Create a child domain under `parent`, auto-allocating a LocalHandle in
    /// `parent`'s domain table.  Sets `owner_domain` on the child so subsequent
    /// domain-mediated operations on it are properly validated.
    pub fn create_domain(
        parent: &CapabilityRef<Domain>,
        policy: DomainPolicy,
    ) -> Result<LocalHandle> {
        let owner_id = parent.read().data.id;

        // 1. Auto-allocate handle (domain table key)
        let new_handle = parent.read().data.allocate_domain_handle();

        // 2. Create the child (validates sealed + CREATE permission + policy monotonicity)
        //    sub_handle is auto-allocated from parent's next_child_sub counter
        let child_ref = Capability::create_child_domain(parent, policy, owner_id)?;

        // 3. Set owner_domain so API checks work on the child
        child_ref.write().owned.owner_domain = Some(Arc::downgrade(parent));

        // 4. Register child in parent's table
        parent
            .write()
            .data
            .add_domain_capability(new_handle, Arc::downgrade(&child_ref));

        Ok(new_handle)
    }

    /// Revoke a child domain that `caller` holds at `child_handle` in its domain table.
    ///
    /// Looks up the child's Arc to get its actual SubHandle, then delegates to
    /// the low-level `revoke_child_domain`.
    pub fn revoke_domain(
        caller: &CapabilityRef<Domain>,
        child_handle: LocalHandle,
    ) -> Result<UpdateBatch> {
        // Look up child to get its actual sub_handle (independent of LocalHandle)
        let child_weak = caller
            .read()
            .data
            .get_domain_capability(child_handle)
            .ok_or(CapaError::NotFound)?
            .clone();
        let child_ref = child_weak.upgrade().ok_or(CapaError::NotFound)?;
        let child_sub = child_ref.read().sub_handle;
        caller.read().owned.validate_operation(MonitorAPI::REVOKE)?;
        Capability::revoke_child_domain(caller, child_sub)
    }
}
