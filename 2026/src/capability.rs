//! Core capability structures with thread-safe parent-child relationships

use crate::domain::{
    Domain, DomainPolicy, MonitorAPI, PendingCapability, VProcessorRef, VpCallContext, VpRunState,
};
use crate::error::{CapaError, Result};
use crate::memory::{Access, Attributes, MemoryRegion, RegionKind};
use crate::platform::Platform;
use crate::switch::{SwitchContext, VpInterruptContext};
use crate::sync::RwLock;
use crate::update::{CoreId, DomainId, UpdateBatch};
use crate::view::{compute_view_from_cap_arcs, view_diff, AddressSpaceView};
use alloc::string::ToString;
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

    /// Set the owning domain reference.
    ///
    /// Used by the domain-mediated layer and test setup only.
    #[doc(hidden)]
    pub fn set_owner_domain(&mut self, domain: CapabilityWeak<Domain>) {
        self.owner_domain = Some(domain);
    }

    /// Validate that the owning domain is sealed and allows the given API operation.
    /// If no owner domain is set (e.g., standalone test capabilities), the check is skipped.
    pub(crate) fn validate_operation(&self, required_api: u16) -> Result<()> {
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

    /// Distance from the root capability (0 for roots, parent.depth + 1 for children).
    /// Used to sort capabilities for view computation without dereferencing cross-domain pointers.
    pub depth: u64,

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
            depth: 0,
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
        depth: u64,
        data: T,
        parent: CapabilityWeak<T>,
    ) -> CapabilityRef<T> {
        Arc::new(RwLock::new(Capability {
            owned: Ownership::new(owner),
            sub_handle,
            depth,
            data,
            parent,
            children: Vec::new(),
            next_child_sub: 1,
        }))
    }

    /// Add a child capability.
    ///
    /// **Internal.** Used by the capability engine and tests only.
    #[doc(hidden)]
    pub fn add_child(&mut self, child: CapabilityRef<T>) {
        self.children.push(child);
    }

    /// Remove a specific child by its stable SubHandle
    ///
    /// **Internal.** Used by the capability engine only.
    pub(crate) fn remove_child(&mut self, child_sub: SubHandle) -> Option<CapabilityRef<T>> {
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
    ///
    /// **Internal primitive.** Prefer the domain-mediated [`alias_memory`] instead.
    #[doc(hidden)]
    pub fn alias_child(
        parent_ref: &CapabilityRef<MemoryRegion>,
        access: Access,
        owner: DomainId,
    ) -> Result<CapabilityRef<MemoryRegion>> {
        let mut parent = parent_ref.write();

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
        let child_depth = parent.depth + 1;

        // Auto-allocate a unique SubHandle from the parent's counter
        let sub_handle = parent.next_child_sub;
        parent.next_child_sub += 1;

        // Create child capability
        let child = Capability::new_child(
            owner,
            sub_handle,
            child_depth,
            child_region,
            Arc::downgrade(parent_ref),
        );

        // Add child to parent's children list (still under write lock)
        parent.add_child(child.clone());

        Ok(child)
    }

    /// Create a carved child region
    ///
    /// **Internal primitive.** Prefer the domain-mediated [`carve_memory`] instead.
    /// Returns only the child capability ref; update generation is handled by the
    /// domain-mediated layer via view-diff.
    #[doc(hidden)]
    pub fn carve_child(
        parent_ref: &CapabilityRef<MemoryRegion>,
        access: Access,
        owner: DomainId,
    ) -> Result<CapabilityRef<MemoryRegion>> {
        let mut parent = parent_ref.write();

        // Check if the requested range overlaps with any existing children.
        for child_ref in &parent.children {
            let child = child_ref.read();
            if access.overlaps(&child.data.access) {
                return Err(CapaError::InvalidAccess);
            }
        }

        // Create carved region from parent
        let child_region = parent.data.carve(access)?;
        let child_depth = parent.depth + 1;

        // Auto-allocate a unique SubHandle from the parent's counter
        let sub_handle = parent.next_child_sub;
        parent.next_child_sub += 1;

        // Create child capability
        let child = Capability::new_child(
            owner,
            sub_handle,
            child_depth,
            child_region,
            Arc::downgrade(parent_ref),
        );

        // Add child to parent's children list
        parent.add_child(child.clone());

        Ok(child)
    }

    /// Send this capability to another domain.
    ///
    /// **Internal primitive.** Prefer the domain-mediated [`send_memory`] instead.
    /// Transfers ownership only; callers are responsible for generating MMU updates
    /// via view-diff at the domain-mediated layer.
    #[doc(hidden)]
    pub fn send_to(
        capa_ref: &CapabilityRef<MemoryRegion>,
        caller: DomainId,
        new_owner: DomainId,
        attributes: Attributes,
    ) -> Result<()> {
        // Phase 1 — verify ownership under a read lock.
        {
            let capa = capa_ref.read();
            if capa.owned.owner != caller {
                return Err(CapaError::PermissionDenied);
            }
            capa.owned.validate_operation(MonitorAPI::SEND)?;
        }

        // Phase 2 — write-lock only the child.
        let mut capa = capa_ref.write();

        // Linearisability check
        if capa.owned.owner != caller {
            return Err(CapaError::PermissionDenied);
        }

        capa.owned.owner = new_owner;
        capa.owned.attributes = attributes;
        capa.owned.owner_domain = None;

        Ok(())
    }

    /// Revoke a child capability by Arc reference.
    ///
    /// Prefer this over [`revoke_child`] when the capability may have been `send`-ed
    /// (its `LocalHandle` changes on transfer but the `Arc` identity is stable).
    ///
    /// **Internal primitive.** Prefer the domain-mediated [`revoke_memory_child`] instead.
    #[doc(hidden)]
    pub fn revoke_child_ref(
        parent_ref: &CapabilityRef<MemoryRegion>,
        child_ref: &CapabilityRef<MemoryRegion>,
    ) -> Result<UpdateBatch> {
        // Read sub_handle before acquiring the parent write lock to avoid nested locking.
        let child_sub = child_ref.read().sub_handle;

        let mut parent = parent_ref.write();

        let child = parent.remove_child(child_sub).ok_or(CapaError::NotFound)?;

        // Drop parent lock before recursing
        drop(parent);

        // Collect updates from revoking the entire subtree
        let updates = Self::revoke_subtree(&child)?;

        Ok(updates)
    }

    /// Revoke a child capability by its stable SubHandle
    ///
    /// **Internal primitive.** Prefer the domain-mediated [`revoke_memory_child`] instead.
    #[doc(hidden)]
    pub fn revoke_child(
        parent_ref: &CapabilityRef<MemoryRegion>,
        child_sub: SubHandle,
    ) -> Result<UpdateBatch> {
        let mut parent = parent_ref.write();

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
                    updates.add_change_rights(child_owner, capa.data.access.start, capa.data.access.size, capa.data.access.start, crate::memory::Rights::NONE, true);

                    updates.add_change_rights(
                        parent_owner,
                        capa.data.access.start,
                        capa.data.access.size,
                        capa.data.access.start,
                        parent.data.access.rights,
                        false,
                    );
                }
            }
        }

        if capa.owned.attributes.vital() {
            updates.add_revoke_domain_with_fallback(capa.owned.owner, None);
        }

        Ok(updates)
    }

    ///TODO(aghosn): We need to stress test this. What happens if we have partially overlapping
    ///capabilities with distinct access rights? Is this handled correctly? For example one that
    ///has r1: [0x0..0x2000) RW and one r2: [0x1000...0x3000) RX, then we need to make sure the
    ///view is [0x0..0x1000) RW union [0x1000...0x2000) RWX union [0x2000...0x3000) RX.
    /// Compute the current view of memory (considering carved children)
    ///
    /// **Internal.** Use [`compute_address_space`] for the full domain view.
    #[doc(hidden)]
    pub fn compute_view(&self) -> Vec<Access> {
        let mut view = vec![self.data.access];

        for child_ref in &self.children {
            let child = child_ref.read();
            if child.data.kind == RegionKind::Carve {
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
    /// Create a child domain (static method, explicit owner).
    ///
    /// The `owner` parameter allows tests and low-level callers to assign an explicit
    /// owner domain ID. The high-level [`create_domain`] always uses the parent's own ID.
    ///
    /// **Internal primitive.** Prefer the domain-mediated [`create_domain`] instead.
    #[doc(hidden)]
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

        // Auto-allocate a unique SubHandle from the parent's counter; capture depth too.
        let (sub_handle, child_depth) = {
            let mut parent = parent_ref.write();
            let s = parent.next_child_sub;
            parent.next_child_sub += 1;
            (s, parent.depth + 1)
        };

        let child = Capability::new_child(
            owner,
            sub_handle,
            child_depth,
            child_domain,
            Arc::downgrade(parent_ref),
        );

        parent_ref.write().add_child(child.clone());

        Ok(child)
    }

    /// Revoke a child domain and all its descendants by SubHandle
    ///
    /// Internal implementation called by [`revoke_domain`].
    pub(crate) fn revoke_child_domain(
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
    /// TODO(aghosn): Does this correctly revoke the memory capabilities owned by the domains?
    /// Or is this done elsewhere?
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
}

/// Read the cached address-space view for a domain.  O(1).
///
/// Recompute and store the domain's cached address-space view.
/// Must be called while the caller holds the domain write lock
/// (passed as `&mut Capability<Domain>`).  Acquiring cap read locks inside
/// is safe because the domain write lock prevents concurrent table mutations.
fn refresh_domain_view(cap: &mut Capability<Domain>) {
    let domain_id = cap.data.id;
    let cap_arcs: alloc::vec::Vec<Arc<RwLock<Capability<MemoryRegion>>>> = cap
        .data
        .memory_capabilities
        .values()
        .filter_map(|w| w.upgrade())
        .collect();
    cap.data.cached_view = compute_view_from_cap_arcs(domain_id, &cap_arcs);
}


/// (carve, send, accept, revoke).  Callers get a consistent snapshot
/// by reading under a single domain read lock.
pub fn compute_address_space(domain: &CapabilityRef<Domain>) -> AddressSpaceView {
    domain.read().data.cached_view.clone()
}

impl Capability<Domain> {
    // =========================================================================
    // Domain-mediated high-level operations (continued)
    // =========================================================================

    /// Carve a memory sub-region.  Returns `(LocalHandle, SubHandle, UpdateBatch)`.
    ///
    /// - `LocalHandle`: the caller's domain-table key for the new child.
    /// - `SubHandle`: the child's stable tree identity (auto-allocated from the
    ///   parent capability's counter).  Pass this to [`revoke_memory_child`] to
    ///   revoke the child even after it has been sent to another domain.
    ///
    ///
    /// The domain-level checks (frozen handle, ownership) are performed here before
    /// delegating to the low-level primitive, keeping domain logic in the domain-mediated layer.
    pub fn carve_memory(
        caller: &CapabilityRef<Domain>,
        parent: LocalHandle,
        access: Access,
    ) -> Result<(LocalHandle, SubHandle, UpdateBatch)> {
        // Pre-flight: read-only validation before acquiring the write lock.
        // validate_operation reads owner_domain (= caller via a read lock), which would
        // deadlock if called while we hold caller.write().
        let owner_id;
        let parent_ref: CapabilityRef<MemoryRegion>;
        let same_rights;
        {
            let r = caller.read();
            if r.data.is_memory_handle_frozen(parent) {
                return Err(CapaError::PermissionDenied);
            }
            owner_id = r.data.id;
            let parent_weak = r
                .data
                .get_memory_capability(parent)
                .ok_or(CapaError::NotFound)?
                .clone();
            drop(r);
            parent_ref = parent_weak.upgrade().ok_or(CapaError::NotFound)?;
            let parent_owned = {
                let p = parent_ref.read();
                if p.owned.owner != owner_id {
                    return Err(CapaError::PermissionDenied);
                }
                let parent_rights = p.data.access.rights;
                same_rights = access.rights == parent_rights;
                p.owned.clone()
                // p (parent_ref.read()) dropped here
            };
            // Validate AFTER releasing parent_ref.read() to avoid ABBA:
            // mutation holds dom.write() → parent_ref.write() (via carve_child);
            // pre-flight holding parent_ref.read() while validate_operation
            // tries dom.read() would deadlock.
            parent_owned.validate_operation(MonitorAPI::CARVE)?;
        }

        // Mutation: hold write lock for the atomic before/mutate/after sequence.
        // carve_child and child_ref operate on CapabilityRef<MemoryRegion> — independent
        // arcs, safe to lock while holding the domain write lock.
        let mut w = caller.write();
        let view_before = w.data.cached_view.clone();

        let child_ref = Capability::carve_child(&parent_ref, access, owner_id)?;
        let child_sub = child_ref.read().sub_handle;

        let new_handle = w.data.allocate_memory_handle();
        child_ref.write().owned.owner_domain = Some(Arc::downgrade(caller));
        w.data.add_memory_capability(new_handle, Arc::downgrade(&child_ref));
        refresh_domain_view(&mut *w);

        let updates = if same_rights {
            UpdateBatch::new()
        } else {
            let view_after = w.data.cached_view.clone();
            view_diff(owner_id, &view_before, &view_after)
        };

        Ok((new_handle, child_sub, updates))
    }

    /// Alias a memory sub-region.  Returns `(LocalHandle, SubHandle)`.
    ///
    /// See [`carve_memory`] for the meaning of each return value.
    /// The domain-level checks (frozen handle, ownership) are performed here before
    /// delegating to the low-level primitive, keeping domain logic in the domain-mediated layer.
    pub fn alias_memory(
        caller: &CapabilityRef<Domain>,
        parent: LocalHandle,
        access: Access,
    ) -> Result<(LocalHandle, SubHandle)> {
        // Pre-flight: read-only validation (same rationale as carve_memory).
        let owner_id;
        let parent_ref: CapabilityRef<MemoryRegion>;
        {
            let r = caller.read();
            if r.data.is_memory_handle_frozen(parent) {
                return Err(CapaError::PermissionDenied);
            }
            owner_id = r.data.id;
            let parent_weak = r
                .data
                .get_memory_capability(parent)
                .ok_or(CapaError::NotFound)?
                .clone();
            drop(r);
            parent_ref = parent_weak.upgrade().ok_or(CapaError::NotFound)?;
            let parent_owned = {
                let p = parent_ref.read();
                if p.owned.owner != owner_id {
                    return Err(CapaError::PermissionDenied);
                }
                p.owned.clone()
                // p (parent_ref.read()) dropped here
            };
            // Validate after releasing parent_ref.read() — same ABBA fix as carve_memory.
            parent_owned.validate_operation(MonitorAPI::ALIAS)?;
        }

        // Mutation: hold write lock for the atomic mutation.
        let mut w = caller.write();
        let child_ref = Capability::alias_child(&parent_ref, access, owner_id)?;
        let child_sub = child_ref.read().sub_handle;

        let new_handle = w.data.allocate_memory_handle();
        child_ref.write().owned.owner_domain = Some(Arc::downgrade(caller));
        w.data.add_memory_capability(new_handle, Arc::downgrade(&child_ref));
        refresh_domain_view(&mut *w);

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
        // Pre-flight: one read block to resolve receiver and get caller_id.
        // The frozen check here is a fast-fail; the authoritative check happens
        // inside the write lock below.
        let caller_id;
        let receiver_ref: CapabilityRef<Domain>;
        let recv_sealed;
        {
            let r = caller.read();
            if r.data.is_memory_handle_frozen(cap) {
                return Err(CapaError::PermissionDenied);
            }
            caller_id = r.data.id;
            let recv_weak = r
                .data
                .get_domain_capability(receiver)
                .ok_or(CapaError::NotFound)?
                .clone();
            drop(r);
            receiver_ref = recv_weak.upgrade().ok_or(CapaError::NotFound)?;
            recv_sealed = receiver_ref.read().data.is_sealed();
        }

        if recv_sealed {
            // ── Sealed path ─────────────────────────────────────────────────
            // Pre-flight: resolve cap, check ownership, validate SEND — all under
            // read locks only so validate_operation can safely read owner_domain.
            let cap_ref = {
                let r = caller.read();
                let cap_weak = r
                    .data
                    .get_memory_capability(cap)
                    .ok_or(CapaError::NotFound)?
                    .clone();
                drop(r);
                let cap_ref = cap_weak.upgrade().ok_or(CapaError::NotFound)?;
                if cap_ref.read().owned.owner != caller_id {
                    return Err(CapaError::PermissionDenied);
                }
                if !receiver_ref.read().data.policy.receive_after_seal() {
                    return Err(CapaError::PermissionDenied);
                }
                let cap_owned = cap_ref.read().owned.clone();
                // cap_ref.read() released here; validate_operation acquires dom.read()
                // separately, so no cap.read() + dom.read() overlap.
                cap_owned.validate_operation(MonitorAPI::SEND)?;
                cap_ref.write().owned.attributes = attrs;
                cap_ref
            };

            // Mutation: freeze under caller.write() — the authoritative commit point.
            {
                let mut caller_w = caller.write();
                if caller_w.data.is_memory_handle_frozen(cap) {
                    return Err(CapaError::PermissionDenied);
                }
                caller_w.data.freeze_memory_handle(cap);
            }

            let pending = PendingCapability {
                cap: Arc::downgrade(&cap_ref),
                sender_domain_id: caller_id,
                sender_handle: cap,
                sender_domain: Arc::downgrade(caller),
            };
            receiver_ref.write().data.add_pending_capability(pending);

            Ok(UpdateBatch::new())
        } else {
            // ── Unsealed path ────────────────────────────────────────────────
            // Pre-flight: validate SEND permission before acquiring write locks.
            // validate_operation reads owner_domain (= caller) — safe here since
            // we only hold a read lock on cap_ref, not caller.write().
            let receiver_id = receiver_ref.read().data.id;
            {
                let r = caller.read();
                let cap_weak = r
                    .data
                    .get_memory_capability(cap)
                    .ok_or(CapaError::NotFound)?
                    .clone();
                drop(r);
                let cap_ref = cap_weak.upgrade().ok_or(CapaError::NotFound)?;
                // Capture ownership in a single read-lock scope so that the owner
                // check and owner_domain are read atomically.  A concurrent thread
                // that transfers this cap will change both owner and owner_domain
                // under its write lock; if we see the new owner here we return
                // PermissionDenied, and if we see the old owner (dom) our clone of
                // owner_domain still points to the sealed caller — in neither case
                // can we read a partially-updated ownership (owner=recv but
                // owner_domain still pointing to an unsealed domain, which would
                // incorrectly surface as DomainNotSealed).
                let cap_owned = {
                    let cr = cap_ref.read();
                    if cr.owned.owner != caller_id {
                        return Err(CapaError::PermissionDenied);
                    }
                    cr.owned.clone()
                };
                cap_owned.validate_operation(MonitorAPI::SEND)?;
            }

            // Acquire both domain write locks in domain-ID order to prevent
            // ABBA deadlock when concurrent sends touch the same pair of domains
            // in opposite directions.  Holding both locks throughout ensures the
            // view snapshots (before and after) are fully atomic with the mutation.
            let (mut caller_w, mut recv_w) = if caller_id < receiver_id {
                let c = caller.write();
                let r = receiver_ref.write();
                (c, r)
            } else {
                let r = receiver_ref.write();
                let c = caller.write();
                (c, r)
            };

            // Authoritative frozen check and atomic remove (commit point).
            if caller_w.data.is_memory_handle_frozen(cap) {
                return Err(CapaError::PermissionDenied);
            }

            // Snapshot views BEFORE mutation.
            let view_caller_before = caller_w.data.cached_view.clone();
            let view_receiver_before = recv_w.data.cached_view.clone();

            let cap_weak = caller_w
                .data
                .remove_memory_capability(cap)
                .ok_or(CapaError::NotFound)?;
            refresh_domain_view(&mut *caller_w);

            let cap_ref = cap_weak.upgrade().ok_or(CapaError::NotFound)?;

            let new_handle = recv_w.data.allocate_memory_handle();

            // Transfer ownership (cap_ref is a separate arc — safe).
            {
                let mut c = cap_ref.write();
                c.owned.owner = receiver_id;
                c.owned.attributes = attrs;
                c.owned.owner_domain = Some(Arc::downgrade(&receiver_ref));
            }

            recv_w
                .data
                .add_memory_capability(new_handle, Arc::downgrade(&cap_ref));
            refresh_domain_view(&mut *recv_w);

            // Snapshot views AFTER mutation.
            let view_caller_after = caller_w.data.cached_view.clone();
            let view_receiver_after = recv_w.data.cached_view.clone();

            drop(caller_w);
            drop(recv_w);

            let mut updates = view_diff(caller_id, &view_caller_before, &view_caller_after);
            updates.merge(view_diff(
                receiver_id,
                &view_receiver_before,
                &view_receiver_after,
            ));

            Ok(updates)
        }
    }

    /// Accept a pending memory capability. Auto-allocates a new LocalHandle in the
    /// receiver's table. Fires the actual MMU unmap (sender) + map (receiver).
    pub fn accept_memory(
        receiver: &CapabilityRef<Domain>,
        pending_id: u64,
    ) -> Result<(LocalHandle, UpdateBatch)> {
        // Peek at the pending entry to learn the sender's domain ID, which we need
        // to acquire both write locks in a consistent order.  The actual removal
        // happens atomically under the write lock below — the peek is not the commit.
        let (receiver_id, sender_id_peek, sender_domain_weak) = {
            let r = receiver.read();
            let pending = r
                .data
                .pending_capabilities
                .get(&pending_id)
                .ok_or(CapaError::NotFound)?;
            (r.data.id, pending.sender_domain_id, pending.sender_domain.clone())
        };

        let sender_ref = sender_domain_weak
            .upgrade()
            .ok_or(CapaError::PermissionDenied)?;

        // Acquire both write locks in domain-ID order (same rule as send_memory unsealed
        // path) so that concurrent send + accept on the same domain pair cannot deadlock.
        let (mut recv_w, mut sender_w) = if receiver_id < sender_id_peek {
            let r = receiver.write();
            let s = sender_ref.write();
            (r, s)
        } else {
            let s = sender_ref.write();
            let r = receiver.write();
            (r, s)
        };

        // Atomically remove the pending entry (commit point for accept vs. reject race).
        let pending = recv_w
            .data
            .pending_capabilities
            .remove(&pending_id)
            .ok_or(CapaError::NotFound)?;
        let (sender_domain_id, sender_handle, cap_weak) = (
            pending.sender_domain_id,
            pending.sender_handle,
            pending.cap,
        );

        let cap_ref = cap_weak.upgrade().ok_or(CapaError::NotFound)?;

        // Check sender domain not revoked — revocation cancels pending transfers.
        if sender_w.data.is_revoked() {
            return Err(CapaError::PermissionDenied);
        }

        // Snapshot views BEFORE mutation.
        let view_sender_before = sender_w.data.cached_view.clone();
        let view_receiver_before = recv_w.data.cached_view.clone();

        let new_handle = recv_w.data.allocate_memory_handle();

        // Remove cap from sender's tables and refresh.
        sender_w.data.remove_memory_capability(sender_handle);
        sender_w.data.unfreeze_memory_handle(sender_handle);
        refresh_domain_view(&mut *sender_w);

        // Update cap ownership (cap_ref is a separate arc — safe).
        {
            let mut cap = cap_ref.write();
            cap.owned.owner = receiver_id;
            cap.owned.owner_domain = Some(Arc::downgrade(receiver));
        }

        // Register in receiver's table and refresh.
        recv_w
            .data
            .add_memory_capability(new_handle, Arc::downgrade(&cap_ref));
        refresh_domain_view(&mut *recv_w);

        // Snapshot views AFTER mutation.
        let view_sender_after = sender_w.data.cached_view.clone();
        let view_receiver_after = recv_w.data.cached_view.clone();

        drop(recv_w);
        drop(sender_w);

        let mut updates = view_diff(sender_domain_id, &view_sender_before, &view_sender_after);
        updates.merge(view_diff(
            receiver_id,
            &view_receiver_before,
            &view_receiver_after,
        ));

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
        // Pre-flight: read-only validation before acquiring the write lock.
        let owner_id;
        let parent_ref: CapabilityRef<MemoryRegion>;
        {
            let r = caller.read();
            if r.data.is_memory_handle_frozen(parent) {
                return Err(CapaError::PermissionDenied);
            }
            owner_id = r.data.id;
            let parent_weak = r
                .data
                .get_memory_capability(parent)
                .ok_or(CapaError::NotFound)?
                .clone();
            drop(r);
            parent_ref = parent_weak.upgrade().ok_or(CapaError::NotFound)?;
            let parent_owned = {
                let p = parent_ref.read();
                if p.owned.owner != owner_id {
                    return Err(CapaError::PermissionDenied);
                }
                p.owned.clone()
                // p (parent_ref.read()) dropped here
            };
            // Validate after releasing parent_ref.read() — same ABBA fix as carve_memory.
            parent_owned.validate_operation(MonitorAPI::REVOKE)?;
        }

        // Mutation: hold write lock. revoke_child operates only on
        // CapabilityRef<MemoryRegion> arcs (independent) — no deadlock risk.
        let mut w = caller.write();
        let updates = Capability::revoke_child(&parent_ref, child_sub)?;
        refresh_domain_view(&mut *w);

        Ok(updates)
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
    /// the low-level `revoke_child_domain` (which validates the REVOKE permission).
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
        let updates = Capability::revoke_child_domain(caller, child_sub)?;
        // Remove the now-revoked child from caller's domain table so the
        // LocalHandle is reclaimed by allocate_domain_handle.
        caller.write().data.remove_domain_capability(child_handle);
        Ok(updates)
    }

    // =========================================================================
    // VP-aware domain switching
    // =========================================================================

    /// Unified VP-aware domain switch.
    ///
    /// **Forward switch** (`to_handle != 0`): claim VP `to_vp_id` of the domain
    /// identified by `to_handle` in `caller`'s domain table, atomically locking
    /// the caller VP in the process.
    ///
    /// **Return** (`to_handle == 0`): unwind the VP call chain — restore the VP
    /// that originally called into `caller` and mark `caller`'s VP as Available.
    /// `to_vp_id` is ignored for returns; the target VP is determined from the
    /// saved call context.
    ///
    /// # Forward switch protocol
    /// 1. `platform.get_current_core()` — fails if None.
    /// 2. Validate `caller` sealed + SWITCH permission.
    /// 3. Find caller VP running on that core.
    /// 4. Resolve `to_handle` → target domain; validate sealed + core bit.
    /// 5. Atomically claim target VP (`Available → Running`).
    /// 6. Transition caller VP (`Running → Locked`).
    /// 7. Update platform core tracking.
    ///
    /// # Return protocol (to_handle == 0)
    /// 1. `platform.get_current_core()`.
    /// 2. Find caller VP running on that core.
    /// 3. Read `Running.caller` → previous VP context (err if None).
    /// 4. Verify previous VP is `Locked { callee == caller }`.
    /// 5. Restore previous VP (`Locked → Running`); mark caller VP `Available`.
    /// 6. Update platform core tracking.
    pub fn switch_domain(
        caller: &CapabilityRef<Domain>,
        to_handle: LocalHandle,
        to_vp_id: u64,
        platform: &dyn Platform,
    ) -> Result<SwitchContext> {
        // Step 1: determine current core (common to both paths).
        let core_id = platform
            .get_current_core()
            .ok_or_else(|| CapaError::InvalidOperation("current core unknown".to_string()))?;

        if to_handle == 0 {
            // ── RETURN: unwind VP call chain ─────────────────────────────────

            // Caller must be sealed (it is running, so it should always be).
            if !caller.read().data.is_sealed() {
                return Err(CapaError::DomainNotSealed);
            }

            let caller_id = caller.read().data.id;

            // Find caller VP running on this core.
            let caller_vp_arc = {
                let c = caller.read();
                c.data.find_vp_on_core(core_id).ok_or_else(|| {
                    CapaError::InvalidOperation("no VP running on this core".to_string())
                })?
            };
            let caller_vp_id = caller_vp_arc.id;

            // Read caller VP's saved caller context.
            let prev_ctx = {
                match &*caller_vp_arc.run_state.read() {
                    VpRunState::Running {
                        caller: Some(ctx), ..
                    } => ctx.clone(),
                    VpRunState::Running { caller: None, .. } => {
                        return Err(CapaError::InvalidOperation(
                            "no caller to return to".to_string(),
                        ));
                    }
                    _ => {
                        return Err(CapaError::InvalidOperation(
                            "caller VP not in Running state".to_string(),
                        ))
                    }
                }
            };

            let prev_domain_id = prev_ctx.domain_id;
            let prev_vp_id = prev_ctx.vp_id;
            let prev_domain_ref = prev_ctx
                .domain
                .upgrade()
                .ok_or(CapaError::PermissionDenied)?;

            // Clone previous VP Arc (brief read lock on domain).
            let prev_vp_arc = {
                let pd = prev_domain_ref.read();
                pd.data
                    .policy
                    .vprocessor_states
                    .get(prev_vp_id as usize)
                    .ok_or(CapaError::NotFound)?
                    .clone()
            };

            // Verify previous VP is Locked waiting for this callee, extract its caller.
            let prev_prev_caller = {
                match &*prev_vp_arc.run_state.read() {
                    VpRunState::Locked {
                        callee_domain_id,
                        callee_vp_id,
                        prev_caller,
                    } if *callee_domain_id == caller_id && *callee_vp_id == caller_vp_id => {
                        prev_caller.clone()
                    }
                    _ => {
                        return Err(CapaError::InvalidOperation(
                            "previous VP is not locked waiting for this callee".to_string(),
                        ))
                    }
                }
            };

            // Restore previous VP: Locked → Running.
            *prev_vp_arc.run_state.write() = VpRunState::Running {
                core: core_id,
                caller: prev_prev_caller,
            };
            // Mark caller VP: Running → Available.
            *caller_vp_arc.run_state.write() = VpRunState::Available;

            // Update platform.
            platform.set_core_domain(core_id, prev_domain_id);
            platform.set_core_vp(core_id, Some(prev_vp_id));

            Ok(SwitchContext {
                from_domain: caller_id,
                to_domain: prev_domain_id,
                core_id,
                is_return: true,
                from_vp_id: Some(caller_vp_id),
                to_vp_id: Some(prev_vp_id),
            })
        } else {
            // ── FORWARD SWITCH: claim target VP ──────────────────────────────

            // Validate caller: sealed + SWITCH permission.
            {
                let c = caller.read();
                if !c.data.is_sealed() {
                    return Err(CapaError::DomainNotSealed);
                }
                if !c.data.policy.api.has(MonitorAPI::SWITCH) {
                    return Err(CapaError::ApiNotAllowed);
                }
            }

            // Find caller VP running on this core.
            let caller_vp_arc = {
                let c = caller.read();
                c.data.find_vp_on_core(core_id).ok_or_else(|| {
                    CapaError::InvalidOperation("no VP running on this core".to_string())
                })?
            };
            let caller_vp_id = caller_vp_arc.id;
            let caller_id = caller.read().data.id;

            // Resolve target domain.
            let to_domain_weak = caller
                .read()
                .data
                .get_domain_capability(to_handle)
                .ok_or(CapaError::NotFound)?
                .clone();
            let to_domain_ref = to_domain_weak.upgrade().ok_or(CapaError::NotFound)?;

            let (to_domain_id, core_allowed) = {
                let td = to_domain_ref.read();
                if !td.data.is_sealed() {
                    return Err(CapaError::DomainNotSealed);
                }
                let core_bit = 1u64 << core_id;
                (td.data.id, (td.data.policy.cores & core_bit) != 0)
            };
            if !core_allowed {
                return Err(CapaError::PermissionDenied);
            }

            // Clone target VP Arc (brief read lock on target domain).
            let to_vp_arc = {
                let td = to_domain_ref.read();
                td.data
                    .policy
                    .vprocessor_states
                    .get(to_vp_id as usize)
                    .ok_or(CapaError::NotFound)?
                    .clone()
            };

            // Capture caller's saved caller before mutating anything.
            let caller_prev_caller = {
                match &*caller_vp_arc.run_state.read() {
                    VpRunState::Running { caller: prev, .. } => prev.clone(),
                    _ => {
                        return Err(CapaError::InvalidOperation(
                            "caller VP not in Running state".to_string(),
                        ))
                    }
                }
            };

            // Claim target VP: Available → Running, or Suspended → Running
            // (interrupt-resume path).  If Suspended, record callee info so the
            // Interrupted callee can be freed after the lock is released.
            let suspended_callee: Option<(CapabilityWeak<Domain>, u64)> = {
                let mut state = to_vp_arc.run_state.write();

                // Extract callee info before overwriting state (borrow ends here).
                let callee_info = if let VpRunState::Suspended {
                    callee_domain,
                    callee_vp_id,
                    ..
                } = &*state
                {
                    Some((callee_domain.clone(), *callee_vp_id))
                } else {
                    None
                };

                // Verify the VP is claimable.
                match &*state {
                    VpRunState::Available | VpRunState::Suspended { .. } => {}
                    _ => {
                        return Err(CapaError::InvalidOperation(
                            "target VP is not available".to_string(),
                        ))
                    }
                }

                *state = VpRunState::Running {
                    core: core_id,
                    caller: Some(VpCallContext {
                        domain: Arc::downgrade(caller),
                        domain_id: caller_id,
                        vp_id: caller_vp_id,
                    }),
                };
                callee_info
            };

            // If the target VP was Suspended, free its Interrupted callee.
            if let Some((callee_weak, callee_vp_id)) = suspended_callee {
                if let Some(callee_cap) = callee_weak.upgrade() {
                    let vp_opt = callee_cap
                        .read()
                        .data
                        .policy
                        .vprocessor_states
                        .get(callee_vp_id as usize)
                        .cloned();
                    if let Some(vp) = vp_opt {
                        let mut s = vp.run_state.write();
                        if matches!(*s, VpRunState::Interrupted) {
                            *s = VpRunState::Available;
                        }
                    }
                }
            }

            // Transition caller VP: Running → Locked.
            *caller_vp_arc.run_state.write() = VpRunState::Locked {
                callee_domain_id: to_domain_id,
                callee_vp_id: to_vp_id,
                prev_caller: caller_prev_caller,
            };

            // Update platform.
            platform.set_core_domain(core_id, to_domain_id);
            platform.set_core_vp(core_id, Some(to_vp_id));

            Ok(SwitchContext {
                from_domain: caller_id,
                to_domain: to_domain_id,
                core_id,
                is_return: false,
                from_vp_id: Some(caller_vp_id),
                to_vp_id: Some(to_vp_id),
            })
        }
    }

    /// Deliver an interrupt via the VP call-chain **lazy-unwind** model.
    ///
    /// Walks from the currently-running VP on `core_id` (which must belong to
    /// `interrupted_cap`) up the VP call chain to the DELIVER handler domain
    /// (`handler_domain_id`), applying the following state changes:
    ///
    /// ```text
    /// handler.vp  (Locked)  → Running { core, caller: handler's prev_caller }
    /// ...report.vp(Locked)  → Suspended { callee = next VP down the chain }
    /// interrupted.vp(Running)→ Interrupted
    /// ```
    ///
    /// This preserves the synchronous call chain: intermediate VPs stay frozen
    /// (`Suspended`) so no other VP can claim the interrupted leaf prematurely.
    /// The leaf is only freed (`Available`) when its direct `Suspended` parent
    /// is later claimed via a forward `switch_domain`.
    ///
    /// # Special case
    ///
    /// If `handler_domain_id == interrupted_cap.id` (the interrupted domain IS
    /// the handler), no VP state changes are made — the VP stays `Running`.
    ///
    /// # Errors
    ///
    /// Returns an error if no VP is `Running` on `core_id` in `interrupted_cap`
    /// (e.g. when using the non-VP `SwitchManager::switch` path), or if the
    /// handler domain is not reachable via the VP call chain.
    pub fn deliver_interrupt_vp(
        interrupted_cap: &CapabilityRef<Domain>,
        handler_domain_id: u64,
        core_id: CoreId,
        platform: &dyn Platform,
    ) -> Result<VpInterruptContext> {
        let interrupted_domain_id = interrupted_cap.read().data.id;

        // Find the VP currently running on core_id in the interrupted domain.
        let leaf_vp_arc: VProcessorRef = {
            let d = interrupted_cap.read();
            d.data.find_vp_on_core(core_id).ok_or_else(|| {
                CapaError::InvalidOperation(
                    "no VP running on core for interrupt delivery".to_string(),
                )
            })?
        };
        let leaf_vp_id = leaf_vp_arc.id;

        // Short-circuit: handler is the interrupted domain itself.
        if interrupted_domain_id == handler_domain_id {
            return Ok(VpInterruptContext {
                interrupted_domain_id,
                interrupted_vp_id: leaf_vp_id,
                handler_domain_id,
                handler_vp_id: leaf_vp_id,
                core_id,
            });
        }

        // Build call chain: chain[0] = leaf (Running), chain[n-1] = handler (Locked).
        // Each element: (domain_cap, domain_id, vp_arc).
        let mut chain: Vec<(CapabilityRef<Domain>, u64, VProcessorRef)> = vec![(
            interrupted_cap.clone(),
            interrupted_domain_id,
            leaf_vp_arc.clone(),
        )];

        // Seed: read caller context from leaf VP.
        let mut next_ctx: Option<VpCallContext> = {
            match &*leaf_vp_arc.run_state.read() {
                VpRunState::Running { caller, .. } => caller.clone(),
                _ => {
                    return Err(CapaError::InvalidOperation(
                        "leaf VP not Running during interrupt delivery".to_string(),
                    ))
                }
            }
        };

        loop {
            let ctx = next_ctx.ok_or_else(|| {
                CapaError::InvalidOperation(
                    "VP chain exhausted before reaching handler domain".to_string(),
                )
            })?;

            let domain_cap = ctx.domain.upgrade().ok_or_else(|| {
                CapaError::InvalidOperation(
                    "domain capability dropped during interrupt chain walk".to_string(),
                )
            })?;
            let domain_id = ctx.domain_id;

            let vp_arc: VProcessorRef = {
                let d = domain_cap.read();
                d.data
                    .policy
                    .vprocessor_states
                    .get(ctx.vp_id as usize)
                    .ok_or(CapaError::NotFound)?
                    .clone()
            };

            chain.push((domain_cap, domain_id, vp_arc.clone()));

            if domain_id == handler_domain_id {
                break;
            }

            // Walk further up via the Locked VP's prev_caller.
            next_ctx = {
                match &*vp_arc.run_state.read() {
                    VpRunState::Locked { prev_caller, .. } => prev_caller.clone(),
                    _ => {
                        return Err(CapaError::InvalidOperation(
                            "expected Locked VP in interrupt call chain".to_string(),
                        ))
                    }
                }
            };
        }

        // Verify handler was reached.
        let last_domain_id = chain.last().unwrap().1;
        if last_domain_id != handler_domain_id {
            return Err(CapaError::InvalidOperation(
                "interrupt handler domain not found in VP call chain".to_string(),
            ));
        }

        let n = chain.len();
        let handler_vp_id = chain[n - 1].2.id;

        // Apply state changes (all VP locks are independent — no deadlock risk).
        //
        // chain[0]:     Running  → Interrupted
        // chain[1..n-2]: Locked  → Suspended { callee = chain[i-1] }
        // chain[n-1]:   Locked   → Running { core, caller: handler's prev_caller }

        // Leaf: Running → Interrupted.
        *chain[0].2.run_state.write() = VpRunState::Interrupted;

        // Intermediate VPs: Locked → Suspended.
        for i in 1..n - 1 {
            let callee_domain = Arc::downgrade(&chain[i - 1].0);
            let callee_domain_id = chain[i - 1].1;
            let callee_vp_id = chain[i - 1].2.id;
            *chain[i].2.run_state.write() = VpRunState::Suspended {
                callee_domain,
                callee_domain_id,
                callee_vp_id,
            };
        }

        // Handler: Locked → Running (restoring its own prev_caller).
        let handler_prev_caller = {
            match &*chain[n - 1].2.run_state.read() {
                VpRunState::Locked { prev_caller, .. } => prev_caller.clone(),
                _ => {
                    return Err(CapaError::InvalidOperation(
                        "handler VP not in Locked state".to_string(),
                    ))
                }
            }
        };
        *chain[n - 1].2.run_state.write() = VpRunState::Running {
            core: core_id,
            caller: handler_prev_caller,
        };

        // Update platform core tracking.
        platform.set_core_domain(core_id, handler_domain_id);
        platform.set_core_vp(core_id, Some(handler_vp_id));

        Ok(VpInterruptContext {
            interrupted_domain_id,
            interrupted_vp_id: leaf_vp_id,
            handler_domain_id,
            handler_vp_id,
            core_id,
        })
    }
}
