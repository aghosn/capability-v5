//! Core capability structures with thread-safe parent-child relationships

use crate::attest::{self, AttestationReport};
use crate::domain::{
    effective_vector, Domain, DomainPolicy, InterruptVisibility, MonitorAPI, PendingCapability,
    PendingDomainCapability, PolicyIdentifier, RegBitmap, VProcessorRef, VectorPolicy, VpCallContext,
    VpRunState, VECTOR_AVAILABLE,
};
use crate::error::{CapaError, Result};
use crate::memory::{Access, Attributes, CommBinding, MemoryRegion, RegionKind, RegionStatus};
use crate::platform::Platform;
use crate::switch::{SwitchContext, VpInterruptContext};
use crate::sync::RwLock;
#[cfg(feature = "address_translation")]
use crate::update::{CoreId, DomainId, Update, UpdateBatch};
#[cfg(not(feature = "address_translation"))]
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
    /// Set when a channel capability is frozen in-transit (send_channel).
    /// Points to the receiver domain so revocation can cancel the pending entry.
    /// Always `None` for non-channel capabilities.
    pub pending_receiver: Option<CapabilityWeak<Domain>>,
}

impl Ownership {
    pub fn new(owner: DomainId) -> Self {
        Ownership {
            owner,
            attributes: Attributes::NONE,
            owner_domain: None,
            pending_receiver: None,
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

    /// If `Some`, this is a channel capability: all operations are forwarded to
    /// the target domain.  Always `None` for `Capability<MemoryRegion>`.
    pub channel_target: Option<CapabilityWeak<Domain>>,

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
            channel_target: None,
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
            channel_target: None,
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
    /// **Internal primitive.** Prefer the domain-mediated [`alias`] instead.
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
    /// **Internal primitive.** Prefer the domain-mediated [`carve`] instead.
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
    /// **Internal primitive.** Prefer the domain-mediated [`send`] instead.
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
    /// **Internal primitive.** Prefer the domain-mediated [`revoke`] instead.
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
    /// **Internal primitive.** Prefer the domain-mediated [`revoke`] instead.
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
    pub(crate) fn revoke_subtree(capa_ref: &CapabilityRef<MemoryRegion>) -> Result<UpdateBatch> {
        let mut capa = capa_ref.write();

        let mut updates = UpdateBatch::new();

        // First, recursively revoke all children
        let children = mem::take(&mut capa.children);
        drop(capa); // Release lock before recursing

        for child_ref in children {
            let child_updates = Self::revoke_subtree(&child_ref)?;
            updates.merge(child_updates);
        }

        // Re-acquire lock to extract all needed info.
        let capa = capa_ref.read();

        let hpa_start = capa.data.access.start;
        let hpa_size = capa.data.access.size;
        let child_owner = capa.owned.owner;
        let kind = capa.data.kind;
        let clean = capa.owned.attributes.clean();
        let vital = capa.owned.attributes.vital();
        let meta = capa.owned.attributes.meta();
        let comm = capa.owned.attributes.comm();
        let comm_binding = capa.data.comm_binding;

        // Check if child owner's domain is already revoked.
        // If so, skip ChangeRights and RevokeDomain — the domain's EPT
        // will be freed by the RevokeDomain already in the batch.
        // Use try_read to avoid deadlock: Capability::revoke holds the caller's
        // domain write lock when it calls revoke_subtree.  revoke_domain_subtree
        // always drops the write lock before calling revoke_subtree, so if
        // try_read fails the domain is active (not being revoked) → false.
        let child_revoked = capa
            .owned
            .owner_domain
            .as_ref()
            .and_then(|w| w.upgrade())
            .map_or(false, |dom_ref| {
                dom_ref
                    .try_read()
                    .map_or(false, |r| r.data.is_revoked())
            });

        #[cfg(feature = "address_translation")]
        let child_domain_weak = capa.owned.owner_domain.clone();

        // Extract cross-domain info while we hold the lock.
        let parent_info = if kind == RegionKind::Carve {
            capa.get_parent().and_then(|parent_ref| {
                let parent = parent_ref.read();
                let parent_owner = parent.owned.owner;
                if parent_owner != child_owner {
                    // Also check if parent owner's domain is revoked — no point
                    // remapping into a domain whose EPT is about to be freed.
                    // Use try_read: if the parent's domain write lock is already
                    // held (e.g. by Capability::revoke on the parent domain),
                    // the domain is active (not being revoked) → false.
                    let parent_revoked = parent
                        .owned
                        .owner_domain
                        .as_ref()
                        .and_then(|w| w.upgrade())
                        .map_or(false, |dom_ref| {
                            dom_ref
                                .try_read()
                                .map_or(false, |r| r.data.is_revoked())
                        });
                    Some((parent_owner, parent.data.access.rights, parent_revoked))
                } else {
                    None
                }
            })
        } else if kind == RegionKind::Alias {
            capa.get_parent().and_then(|parent_ref| {
                let parent_owner = parent_ref.read().owned.owner;
                if parent_owner != child_owner {
                    Some((parent_owner, crate::memory::Rights::NONE, false))
                } else {
                    None
                }
            })
        } else {
            None
        };

        drop(capa);

        // === Address translation: look up child's GPA ===
        // Only needed when parent_info.is_some() (cross-domain transfer).
        // Use try_read to avoid deadlock when child_owner is the top-level
        // caller (whose domain write-lock is already held by revoke()).
        #[cfg(feature = "address_translation")]
        let child_gpa = if parent_info.is_some() {
            child_domain_weak
                .as_ref()
                .and_then(|w| w.upgrade())
                .and_then(|dom_ref| {
                    dom_ref
                        .try_read()
                        .and_then(|dom| dom.data.address_map.find_gpa_for_hpa(hpa_start, hpa_size))
                })
                .unwrap_or(hpa_start)
        } else {
            hpa_start
        };
        #[cfg(not(feature = "address_translation"))]
        let child_gpa = hpa_start;

        // Check if we need to clean memory
        if clean {
            updates.add_zero_memory(hpa_start, hpa_size);
        }

        if kind == RegionKind::Carve {
            if let Some((parent_owner, parent_rights, parent_revoked)) = parent_info {
                // Skip ChangeRights for revoked child domains — RevokeDomain
                // (emitted first) frees the EPT; a subsequent unmap would
                // touch an already-torn-down domain.
                if !meta && !child_revoked {
                    updates.add_change_rights(
                        child_owner,
                        child_gpa,
                        hpa_size,
                        hpa_start,
                        crate::memory::Rights::NONE,
                        true,
                    );
                }
                if !parent_revoked {
                    updates.add_change_rights(
                        parent_owner,
                        hpa_start,
                        hpa_size,
                        hpa_start,
                        parent_rights,
                        false,
                    );
                }
            }
        }

        // Aliased children share access with the parent but may have been sent to
        // another domain. Unmap from the receiver; do NOT remap the parent because
        // alias never removes parent access.
        if kind == RegionKind::Alias {
            if let Some((_, _, _)) = parent_info {
                if !meta && !child_revoked {
                    updates.add_change_rights(
                        child_owner,
                        child_gpa,
                        hpa_size,
                        hpa_start,
                        crate::memory::Rights::NONE,
                        true,
                    );
                }
            }
        }

        // === Address translation: clean up child domain's AddressMap ===
        // Skip if child is revoked — address_map was already cleared by revoke().
        #[cfg(feature = "address_translation")]
        if parent_info.is_some() && !child_revoked {
            if let Some(ref w) = child_domain_weak {
                if let Some(dom_ref) = w.upgrade() {
                    if let Some(mut dom) = dom_ref.try_write() {
                        dom.data
                            .address_map
                            .remove_by_hpa_range(hpa_start, hpa_size);
                    }
                }
            }
        }

        // Notify the platform that its access to the COMM region is gone.
        // Emitted before RevokeDomain so the platform can unmap before tearing down.
        if comm {
            let (target_id, vp) = match comm_binding {
                Some(b) => (b.target_domain_id, b.vp_id),
                None => (child_owner, 0),
            };
            updates.add_uncomm_region(child_owner, target_id, vp, hpa_start, hpa_size);
        }

        // Only emit RevokeDomain if the domain wasn't already marked revoked
        // (which means revoke_domain_subtree already emitted it).
        if vital && !child_revoked {
            updates.add_revoke_domain_with_fallback(child_owner, None);
        }

        Ok(updates)
    }

    /// Compute the current view of memory (considering carved children).
    ///
    /// Carved and aliased children cannot overlap each other — enforced at creation time
    /// in `carve_child` / `alias_child`. Each carved child's region is subtracted from the
    /// parent view; aliased children share the parent's region and are never subtracted.
    /// Because two children with the same address range and distinct rights cannot coexist,
    /// this subtraction-based computation is correct.
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
    /// Returns `true` if this is a channel capability (created by [`get_chan`]).
    #[inline]
    pub fn is_channel(&self) -> bool {
        self.channel_target.is_some()
    }

    /// Create a child domain (static method, explicit owner).
    ///
    /// The `owner` parameter allows tests and low-level callers to assign an explicit
    /// owner domain ID. The high-level [`create`] always uses the parent's own ID.
    ///
    /// **Internal primitive.** Prefer the domain-mediated [`create`] instead.
    #[doc(hidden)]
    pub fn create_child_domain(
        parent_ref: &CapabilityRef<Domain>,
        policy: DomainPolicy,
        owner: DomainId,
    ) -> Result<CapabilityRef<Domain>> {
        let parent = parent_ref.read();

        parent.data.require_api(MonitorAPI::CREATE)?;

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

        parent.data.require_api(MonitorAPI::REVOKE)?;

        let child_ref = parent.remove_child(child_sub).ok_or(CapaError::NotFound)?;

        let parent_id = parent.data.id;
        drop(parent);

        let updates = Self::revoke_domain_subtree(&child_ref, Some(parent_id))?;

        Ok(updates)
    }

    /// Recursively revoke a domain capability subtree.
    ///
    /// Revokes all child domains first (depth-first), then revokes any "root"
    /// memory capabilities owned by this domain, i.e. memory capabilities whose
    /// parent in the capability tree belongs to a different domain.  This generates
    /// the `ChangeRights` restore updates so that ancestor domains regain access to
    /// regions they had carved and sent into the revoked domain.
    ///
    /// Lock discipline: the domain write lock is dropped before touching memory
    /// capabilities (only memory locks are acquired), then re-acquired for final
    /// domain processing.
    fn revoke_domain_subtree(
        domain_ref: &CapabilityRef<Domain>,
        fallback: Option<DomainId>,
    ) -> Result<UpdateBatch> {
        let mut domain = domain_ref.write();

        let mut updates = UpdateBatch::new();

        let children = mem::take(&mut domain.children);

        // Snapshot memory capability weak refs and domain id while we hold the lock.
        let mem_weak_refs: Vec<CapabilityWeak<MemoryRegion>> =
            domain.data.memory_capabilities.values().cloned().collect();
        let domain_id = domain.data.id;

        // Mark revoked early so that revoke_subtree (called below for memory
        // caps) sees this domain as revoked and skips redundant ChangeRights
        // and VITAL-triggered RevokeDomain updates.
        domain.data.revoke();
        updates.add_revoke_domain_with_fallback(domain_id, fallback);

        drop(domain);

        for child_ref in children {
            let child_updates = Self::revoke_domain_subtree(&child_ref, fallback)?;
            updates.merge(child_updates);
        }

        // Revoke root memory capabilities: those whose parent in the capability
        // tree is owned by a different domain.  Child domains were already
        // processed above, so any memory they held has already been detached
        // from the tree.
        for mem_weak in &mem_weak_refs {
            if let Some(mem_ref) = mem_weak.upgrade() {
                let info = {
                    let m = mem_ref.read();
                    let sub = m.sub_handle;
                    match m.get_parent() {
                        Some(parent_ref) => {
                            let is_root = parent_ref.read().owned.owner != domain_id;
                            Some((sub, parent_ref, is_root))
                        }
                        None => None,
                    }
                };
                match info {
                    Some((sub, parent_ref, true)) => {
                        // NotFound means the capability was already revoked
                        // from the tree (e.g. by an explicit revoke before the
                        // domain revocation).  Safe to skip.
                        match Capability::<MemoryRegion>::revoke_child(&parent_ref, sub) {
                            Ok(mem_updates) => updates.merge(mem_updates),
                            Err(CapaError::NotFound) => {}
                            Err(e) => return Err(e),
                        }
                    }
                    None => {
                        // Parentless root: should only occur for the initial
                        // memory capability owned by the root domain.
                        let mem_updates = Capability::<MemoryRegion>::revoke_subtree(&mem_ref)?;
                        updates.merge(mem_updates);
                    }
                    _ => {} // Same-domain parent: handled transitively via a root ancestor.
                }
            }
        }

        let mut domain = domain_ref.write();

        // If this is a channel capability currently frozen (in transit), cancel
        // the pending entry in the receiver domain and unfreeze the sender's handle.
        if domain.is_channel() {
            if let Some(recv_ref) = domain
                .owned
                .pending_receiver
                .as_ref()
                .and_then(|w| w.upgrade())
            {
                let mut rw = recv_ref.write();
                // Find and remove the pending entry for this channel
                let pending_id = rw
                    .data
                    .pending_domain_capabilities
                    .iter()
                    .find(|(_, p)| {
                        p.cap
                            .upgrade()
                            .map_or(false, |c| Arc::ptr_eq(&c, domain_ref))
                    })
                    .map(|(id, _)| *id);
                if let Some(id) = pending_id {
                    if let Some(pending) = rw.data.pending_domain_capabilities.remove(&id) {
                        if let Some(sender_ref) = pending.sender_domain.upgrade() {
                            if !Arc::ptr_eq(&sender_ref, domain_ref) {
                                sender_ref
                                    .write()
                                    .data
                                    .unfreeze_domain_handle(pending.sender_handle);
                            }
                        }
                    }
                }
            }
            domain.owned.pending_receiver = None;
        }

        // Clean up COMM bindings: this domain is about to be revoked.
        // Any parent-owned COMM capabilities bound to this child must have
        // their COMM attribute and binding cleared.
        let comm_bindings = mem::take(&mut domain.data.comm_bindings);
        let revoked_domain_id = domain.data.id;
        drop(domain);

        for weak in &comm_bindings {
            if let Some(cap_ref) = weak.upgrade() {
                let mut c = cap_ref.write();
                if c.owned.attributes.comm() {
                    let phys = c.data.access.start;
                    let size = c.data.access.size;
                    let (target_id, vp) = match c.data.comm_binding {
                        Some(b) => (b.target_domain_id, b.vp_id),
                        None => (revoked_domain_id, 0),
                    };
                    // Strip COMM (and the implied CLEAN) from attributes.
                    c.owned.attributes = Attributes::NONE;
                    c.data.comm_binding = None;
                    updates.add_uncomm_region(c.owned.owner, target_id, vp, phys, size);
                }
            }
        }

        // domain.data.revoke() and RevokeDomain already emitted at the top.

        Ok(updates)
    }
}

/// Recompute and store the domain's cached address-space view.
/// Must be called while holding the domain write lock
/// (`&mut Capability<Domain>`). Acquiring cap read locks inside is safe
/// because the domain write lock prevents concurrent table mutations.
/// Insert a capability's view into the receiver's AddressMap.
///
/// Visible ranges (from `compute_view`) are inserted as `Mapped`.
/// Carved-away gaps (ranges in `[hpa_start, hpa_start+size)` not covered
/// by the view) are inserted as `Blocked`.
#[cfg(feature = "address_translation")]
fn insert_view_aware(
    map: &mut crate::translation::AddressMap,
    hpa_start: u64,
    size: u64,
    gpa_base: u64,
    view: &[Access],
) {
    let hpa_end = hpa_start + size;
    let mut cursor = hpa_start;

    // View ranges are sorted by start address (from compute_view).
    // Walk through and insert Mapped for visible, Blocked for gaps.
    for v in view {
        let v_start = v.start;
        let v_end = v.start + v.size;

        // Gap before this visible range → Blocked.
        if cursor < v_start {
            let gap_size = v_start - cursor;
            let gap_gpa = gpa_base + (cursor - hpa_start);
            map.entries_mut().insert(
                gap_gpa,
                crate::translation::MapEntry::Blocked {
                    hpa_start: cursor,
                    size: gap_size,
                },
            );
            cursor = v_start;
        }

        // Visible range → Mapped.
        if cursor < v_end {
            let mapped_size = v_end - cursor;
            let mapped_gpa = gpa_base + (cursor - hpa_start);
            let _ = map.insert(
                cursor,
                mapped_size,
                v.rights,
                #[cfg(feature = "cache_coloring")]
                None,
                Some(mapped_gpa),
            );
            cursor = v_end;
        }
    }

    // Trailing gap after last visible range → Blocked.
    if cursor < hpa_end {
        let gap_size = hpa_end - cursor;
        let gap_gpa = gpa_base + (cursor - hpa_start);
        map.entries_mut().insert(
            gap_gpa,
            crate::translation::MapEntry::Blocked {
                hpa_start: cursor,
                size: gap_size,
            },
        );
    }
}

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

/// Read the cached address-space view for a domain.  O(1).
/// Updated automatically after every mutating operation
/// (carve, send, accept, revoke).  Callers get a consistent snapshot
/// by reading under a single domain read lock.
pub fn compute_address_space(domain: &CapabilityRef<Domain>) -> AddressSpaceView {
    domain.read().data.cached_view.clone()
}

// =============================================================================
// Domain-mediated high-level operations
// =============================================================================

impl Capability<Domain> {
    /// Carve a memory sub-region.  Returns `(LocalHandle, SubHandle, UpdateBatch)`.
    ///
    /// - `LocalHandle`: the caller's domain-table key for the new child.
    /// - `SubHandle`: the child's stable tree identity (auto-allocated from the
    ///   parent capability's counter).  Pass this to [`revoke`] to
    ///   revoke the child even after it has been sent to another domain.
    ///
    /// # Errors
    /// - [`CapaError::PermissionDenied`] — handle is frozen, parent has `META` attribute, or `CARVE` API not allowed.
    /// - [`CapaError::NotFound`] — `parent` handle not found in caller's table.
    /// - [`CapaError::InvalidAccess`] — requested range or rights exceed parent.
    pub fn carve(
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
                // META and COMM regions may not be carved.
                if p.owned.attributes.meta() || p.owned.attributes.comm() {
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
        w.data
            .add_memory_capability(new_handle, Arc::downgrade(&child_ref));
        refresh_domain_view(&mut *w);

        let updates = if same_rights {
            UpdateBatch::new()
        } else {
            // Split the parent's AddressMap entry at the carved range.
            #[cfg(feature = "address_translation")]
            {
                if let Ok((gpa, _, _)) = w.data.address_map.translate(access.start, access.size) {
                    let _ = w.data.address_map.split(gpa, access.size, access.rights);
                }
            }

            let view_after = w.data.cached_view.clone();
            #[allow(unused_mut)]
            let mut updates = view_diff(owner_id, &view_before, &view_after);

            #[cfg(feature = "address_translation")]
            updates.fixup_domain_addresses(owner_id, &w.data.address_map);

            updates
        };

        Ok((new_handle, child_sub, updates))
    }

    /// Alias a memory sub-region.  Returns `(LocalHandle, SubHandle)`.
    ///
    /// See [`carve`] for the meaning of each return value.
    /// The domain-level checks (frozen handle, ownership) are performed here before
    /// delegating to the low-level primitive, keeping domain logic in the domain-mediated layer.
    /// Alias a memory region.  Returns `(LocalHandle, SubHandle)`.
    ///
    /// Creates a read-only alias of `parent` restricted to `access` in the caller's table.
    ///
    /// # Errors
    /// - [`CapaError::PermissionDenied`] — handle is frozen, parent has `META` attribute, or `ALIAS` API not allowed.
    /// - [`CapaError::NotFound`] — `parent` handle not found in caller's table.
    /// - [`CapaError::InvalidAccess`] — requested range or rights exceed parent.
    pub fn alias(
        caller: &CapabilityRef<Domain>,
        parent: LocalHandle,
        access: Access,
    ) -> Result<(LocalHandle, SubHandle)> {
        // Pre-flight: read-only validation (same rationale as carve).
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
                // META and COMM regions may not be aliased.
                if p.owned.attributes.meta() || p.owned.attributes.comm() {
                    return Err(CapaError::PermissionDenied);
                }
                p.owned.clone()
                // p (parent_ref.read()) dropped here
            };
            // Validate after releasing parent_ref.read() — same ABBA fix as carve.
            parent_owned.validate_operation(MonitorAPI::ALIAS)?;
        }

        // Mutation: hold write lock for the atomic mutation.
        let mut w = caller.write();
        let child_ref = Capability::alias_child(&parent_ref, access, owner_id)?;
        let child_sub = child_ref.read().sub_handle;

        let new_handle = w.data.allocate_memory_handle();
        child_ref.write().owned.owner_domain = Some(Arc::downgrade(caller));
        w.data
            .add_memory_capability(new_handle, Arc::downgrade(&child_ref));
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
    ///
    /// # Errors
    /// - [`CapaError::PermissionDenied`] — `cap` handle is frozen, caller does not own the
    ///   capability, `META` region may not be sent via non-META path, or `SEND` API not allowed.
    /// - [`CapaError::NotFound`] — `cap` or `receiver` handle not found.
    /// - [`CapaError::ApiNotAllowed`] — receiver is sealed without `RECEIVE_AFTER_SEAL`.
    pub fn send(
        caller: &CapabilityRef<Domain>,
        cap: LocalHandle,
        receiver: LocalHandle,
        attrs: Attributes,
    ) -> Result<UpdateBatch> {
        Self::send_at(caller, cap, receiver, attrs, None)
    }

    /// Send a memory capability to a receiver domain, with an optional GPA
    /// hint that controls where the region appears in the receiver's guest
    /// address space.
    ///
    /// When `gpa_hint` is `None` (or `address_translation` is disabled), the
    /// receiver gets an identity mapping (GPA = HPA).  When `Some(gpa)`, the
    /// receiver's `AddressMap` places the region at the requested GPA.
    ///
    /// See [`send`] for the full description of the send semantics.
    pub fn send_at(
        caller: &CapabilityRef<Domain>,
        cap: LocalHandle,
        receiver: LocalHandle,
        attrs: Attributes,
        _gpa_hint: Option<u64>,
    ) -> Result<UpdateBatch> {
        // Pre-flight: fast-fail frozen check, resolve caller_id, receiver Arc, and META
        // constraints — all under a single caller.read() to minimise lock round-trips.
        // These checks are non-authoritative; the write-lock commit below is authoritative.
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
            let cap_weak = r
                .data
                .get_memory_capability(cap)
                .ok_or(CapaError::NotFound)?
                .clone();
            drop(r);

            let resolved = recv_weak.upgrade().ok_or(CapaError::NotFound)?;
            // One resolved.read(): channel follow + sealed check.
            let (resolved_ref, recv_sealed_val) = {
                let r = resolved.read();
                if r.is_channel() {
                    let target = r.channel_target.as_ref().and_then(|w| w.upgrade());
                    drop(r);
                    let t = target.unwrap_or(resolved);
                    let sealed = t.read().data.is_sealed();
                    (t, sealed)
                } else {
                    let sealed = r.data.is_sealed();
                    drop(r);
                    (resolved, sealed)
                }
            };
            receiver_ref = resolved_ref;
            recv_sealed = recv_sealed_val;

            // META constraints: check capability attributes under cap_ref.read() only
            // (caller.read() already dropped above, so no overlapping lock).
            let cap_ref = cap_weak.upgrade().ok_or(CapaError::NotFound)?;
            let c = cap_ref.read();
            // A region already marked META or COMM cannot be sent.
            if c.owned.attributes.meta() || c.owned.attributes.comm() {
                return Err(CapaError::PermissionDenied);
            }
            // Only exclusive (unbroken chain of carves) regions may be sent as META.
            if attrs.meta() && c.data.status != RegionStatus::Exclusive {
                return Err(CapaError::PermissionDenied);
            }
        }

        // Materialize META → META|CLEAN|VITAL so that revoke_subtree's existing
        // CLEAN and VITAL checks handle zeroing and domain revocation without
        // any META-specific branches there.
        let attrs = attrs.canonicalize();

        if recv_sealed {
            Self::send_memory_sealed(caller, cap, &receiver_ref, caller_id, attrs, _gpa_hint)
        } else {
            Self::send_memory_unsealed(caller, cap, &receiver_ref, caller_id, attrs, _gpa_hint)
        }
    }

    /// Sealed send: freeze the caller's handle and enqueue in the receiver's pending table.
    /// No MMU updates are emitted — those are deferred to `accept`.
    fn send_memory_sealed(
        caller: &CapabilityRef<Domain>,
        cap: LocalHandle,
        receiver_ref: &CapabilityRef<Domain>,
        caller_id: DomainId,
        attrs: Attributes,
        _gpa_hint: Option<u64>,
    ) -> Result<UpdateBatch> {
        // Pre-flight: resolve cap, check ownership, validate SEND — all under read
        // locks so validate_operation can safely upgrade owner_domain.
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
            // cap_ref.read() released here; validate_operation acquires dom.read()
            // separately, so no cap.read() + dom.read() overlap.
            let cap_owned = cap_ref.read().owned.clone();
            cap_owned.validate_operation(MonitorAPI::SEND)?;
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

        // Attributes are applied only after the freeze is committed, so a failed
        // freeze (concurrent send) never leaves attributes in an inconsistent state.
        cap_ref.write().owned.attributes = attrs;

        let pending = PendingCapability {
            cap: Arc::downgrade(&cap_ref),
            sender_domain_id: caller_id,
            sender_handle: cap,
            sender_domain: Arc::downgrade(caller),
            #[cfg(feature = "address_translation")]
            gpa_hint: _gpa_hint,
        };
        receiver_ref.write().data.add_pending_capability(pending);

        Ok(UpdateBatch::new())
    }

    /// Unsealed send: immediately transfer ownership and emit MMU updates.
    ///
    /// Acquires both domain write locks in domain-ID order (ABBA-safe). The
    /// ownership change and view refresh happen atomically under both locks.
    ///
    /// Owner check and `owner_domain` clone are captured in a single read-lock
    /// scope to prevent a TOCTOU where a concurrent transfer changes `owner_domain`
    /// between an ownership check and a later read (which would erroneously surface
    /// as `DomainNotSealed` from `validate_operation`).
    fn send_memory_unsealed(
        caller: &CapabilityRef<Domain>,
        cap: LocalHandle,
        receiver_ref: &CapabilityRef<Domain>,
        caller_id: DomainId,
        attrs: Attributes,
        _gpa_hint: Option<u64>,
    ) -> Result<UpdateBatch> {
        let receiver_id = receiver_ref.read().data.id;

        // Pre-flight: validate SEND permission before acquiring write locks.
        {
            let r = caller.read();
            let cap_weak = r
                .data
                .get_memory_capability(cap)
                .ok_or(CapaError::NotFound)?
                .clone();
            drop(r);
            let cap_ref = cap_weak.upgrade().ok_or(CapaError::NotFound)?;
            let cap_owned = {
                let cr = cap_ref.read();
                if cr.owned.owner != caller_id {
                    return Err(CapaError::PermissionDenied);
                }
                cr.owned.clone()
            };
            cap_owned.validate_operation(MonitorAPI::SEND)?;
        }

        // Acquire both write locks in domain-ID order.
        let (mut caller_w, mut recv_w) = if caller_id < receiver_id {
            let c = caller.write();
            let r = receiver_ref.write();
            (c, r)
        } else {
            let r = receiver_ref.write();
            let c = caller.write();
            (c, r)
        };

        // Authoritative frozen check (commit point).
        if caller_w.data.is_memory_handle_frozen(cap) {
            return Err(CapaError::PermissionDenied);
        }

        let view_caller_before = caller_w.data.cached_view.clone();
        let view_receiver_before = recv_w.data.cached_view.clone();

        let cap_weak = caller_w
            .data
            .remove_memory_capability(cap)
            .ok_or(CapaError::NotFound)?;
        refresh_domain_view(&mut *caller_w);

        let cap_ref = cap_weak.upgrade().ok_or(CapaError::NotFound)?;

        // Read cap info for AddressMap operations. Also capture `meta_start/size`
        // and `is_meta` here so the ownership write below needs no extra field reads.
        #[cfg(feature = "address_translation")]
        let (cap_hpa, cap_size, _cap_rights, cap_is_carve, cap_view) = {
            let c = cap_ref.read();
            (
                c.data.access.start,
                c.data.access.size,
                c.data.access.rights,
                c.data.kind == RegionKind::Carve,
                c.compute_view(),
            )
        };

        // Validate GPA hint: the full range must not overlap any existing
        // entry in the receiver's AddressMap.
        #[cfg(feature = "address_translation")]
        {
            let gpa_base = _gpa_hint.unwrap_or(cap_hpa);
            if recv_w.data.address_map.overlaps(gpa_base, cap_size) {
                // Roll back: re-insert the cap into the caller's table.
                caller_w
                    .data
                    .add_memory_capability(cap, Arc::downgrade(&cap_ref));
                refresh_domain_view(&mut *caller_w);
                return Err(CapaError::RegionOverlap);
            }
        }

        // Block sender's AddressMap entry (Carve only; aliases don't
        // remove sender access).
        #[cfg(feature = "address_translation")]
        if cap_is_carve {
            if let Ok((gpa, _, _)) = caller_w.data.address_map.translate(cap_hpa, cap_size) {
                let _ = caller_w.data.address_map.block(gpa);
            }
        }

        let new_handle = recv_w.data.allocate_memory_handle();

        // Transfer ownership (cap_ref is a separate arc — safe to write while
        // holding domain write locks). Capture the immutable access region here
        // so we never need to re-acquire cap_ref after the domain locks drop.
        let (meta_start, meta_size) = {
            let mut c = cap_ref.write();
            let start = c.data.access.start;
            let size = c.data.access.size;
            c.owned.owner = receiver_id;
            c.owned.attributes = attrs;
            c.owned.owner_domain = Some(Arc::downgrade(receiver_ref));
            (start, size)
        };

        recv_w
            .data
            .add_memory_capability(new_handle, Arc::downgrade(&cap_ref));
        refresh_domain_view(&mut *recv_w);

        // Insert into receiver's AddressMap: visible ranges as Mapped,
        // carved-away gaps as Blocked.
        #[cfg(feature = "address_translation")]
        {
            let gpa_base = _gpa_hint.unwrap_or(cap_hpa);
            insert_view_aware(
                &mut recv_w.data.address_map,
                cap_hpa,
                cap_size,
                gpa_base,
                &cap_view,
            );
        }

        let view_caller_after = caller_w.data.cached_view.clone();
        let view_receiver_after = recv_w.data.cached_view.clone();

        let mut updates = view_diff(caller_id, &view_caller_before, &view_caller_after);
        updates.merge(view_diff(
            receiver_id,
            &view_receiver_before,
            &view_receiver_after,
        ));

        #[cfg(feature = "address_translation")]
        {
            updates.fixup_domain_addresses(caller_id, &caller_w.data.address_map);
            updates.fixup_domain_addresses(receiver_id, &recv_w.data.address_map);
        }

        drop(caller_w);
        drop(recv_w);

        // `attrs` is the value just written to cap; `meta_start/size` captured above.
        if attrs.meta() {
            updates.add_give_meta_mem(receiver_id, meta_start, meta_size);
        }

        Ok(updates)
    }

    /// Accept a pending memory capability. Auto-allocates a new LocalHandle in the
    /// receiver's table. Fires the actual MMU unmap (sender) + map (receiver).
    ///
    /// Uses the GPA hint specified by the sender at `send_at` time (if any).
    /// To override the sender's hint, use [`accept_at`] instead.
    ///
    /// # Errors
    /// - [`CapaError::NotFound`] — `pending_id` not found in receiver's pending queue.
    pub fn accept(
        receiver: &CapabilityRef<Domain>,
        pending_id: u64,
    ) -> Result<(LocalHandle, UpdateBatch)> {
        Self::accept_at(receiver, pending_id, None)
    }

    /// Accept a pending memory capability with an optional GPA override.
    ///
    /// If `gpa_hint` is `Some(gpa)`, the receiver's `AddressMap` places the
    /// region at the requested GPA, ignoring the sender's hint.
    /// If `gpa_hint` is `None`, the sender's original hint is used (which
    /// itself defaults to identity GPA = HPA if the sender didn't specify one).
    ///
    /// # Errors
    /// - [`CapaError::NotFound`] — `pending_id` not found in receiver's pending queue.
    pub fn accept_at(
        receiver: &CapabilityRef<Domain>,
        pending_id: u64,
        _gpa_override: Option<u64>,
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
            (
                r.data.id,
                pending.sender_domain_id,
                pending.sender_domain.clone(),
            )
        };

        let sender_ref = sender_domain_weak
            .upgrade()
            .ok_or(CapaError::PermissionDenied)?;

        // Acquire both write locks in domain-ID order (same rule as send unsealed
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
        #[cfg(feature = "address_translation")]
        let orig_gpa_hint = pending.gpa_hint;
        #[cfg(feature = "address_translation")]
        let pending_gpa_hint = _gpa_override.or(orig_gpa_hint);
        let (sender_domain_id, sender_handle, cap_weak) =
            (pending.sender_domain_id, pending.sender_handle, pending.cap);

        let cap_ref = cap_weak.upgrade().ok_or(CapaError::NotFound)?;

        // Read cap info for AddressMap operations.
        #[cfg(feature = "address_translation")]
        let (cap_hpa, cap_size, cap_is_carve, cap_view) = {
            let c = cap_ref.read();
            (
                c.data.access.start,
                c.data.access.size,
                c.data.kind == RegionKind::Carve,
                c.compute_view(),
            )
        };

        // Validate GPA hint before mutations.
        #[cfg(feature = "address_translation")]
        {
            let gpa_base = pending_gpa_hint.unwrap_or(cap_hpa);
            if recv_w.data.address_map.overlaps(gpa_base, cap_size) {
                // Roll back: re-insert the pending entry.
                recv_w.data.pending_capabilities.insert(pending_id, PendingCapability {
                    cap: Arc::downgrade(&cap_ref),
                    sender_domain_id,
                    sender_handle,
                    sender_domain: Arc::downgrade(&sender_ref),
                    #[cfg(feature = "address_translation")]
                    gpa_hint: orig_gpa_hint,
                });
                return Err(CapaError::RegionOverlap);
            }
        }

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

        // Block sender's AddressMap entry (Carve only).
        #[cfg(feature = "address_translation")]
        if cap_is_carve {
            if let Ok((gpa, _, _)) = sender_w.data.address_map.translate(cap_hpa, cap_size) {
                let _ = sender_w.data.address_map.block(gpa);
            }
        }

        // Update cap ownership (cap_ref is a separate arc — safe). Capture
        // meta info here to avoid a re-acquire after the domain locks are dropped.
        let (is_meta, meta_start, meta_size) = {
            let mut cap = cap_ref.write();
            let is_meta = cap.owned.attributes.meta();
            let start = cap.data.access.start;
            let size = cap.data.access.size;
            cap.owned.owner = receiver_id;
            cap.owned.owner_domain = Some(Arc::downgrade(receiver));
            (is_meta, start, size)
        };

        // Register in receiver's table and refresh.
        recv_w
            .data
            .add_memory_capability(new_handle, Arc::downgrade(&cap_ref));
        refresh_domain_view(&mut *recv_w);

        // Insert into receiver's AddressMap: visible ranges as Mapped,
        // carved-away gaps as Blocked.
        #[cfg(feature = "address_translation")]
        {
            let gpa_base = pending_gpa_hint.unwrap_or(cap_hpa);
            insert_view_aware(
                &mut recv_w.data.address_map,
                cap_hpa,
                cap_size,
                gpa_base,
                &cap_view,
            );
        }

        // Snapshot views AFTER mutation.
        let view_sender_after = sender_w.data.cached_view.clone();
        let view_receiver_after = recv_w.data.cached_view.clone();

        let mut updates = view_diff(sender_domain_id, &view_sender_before, &view_sender_after);
        updates.merge(view_diff(
            receiver_id,
            &view_receiver_before,
            &view_receiver_after,
        ));

        #[cfg(feature = "address_translation")]
        {
            updates.fixup_domain_addresses(sender_domain_id, &sender_w.data.address_map);
            updates.fixup_domain_addresses(receiver_id, &recv_w.data.address_map);
        }

        drop(recv_w);
        drop(sender_w);

        if is_meta {
            updates.add_give_meta_mem(receiver_id, meta_start, meta_size);
        }

        Ok((new_handle, updates))
    }

    /// Reject a pending memory capability. Unfreezes the sender's LocalHandle.
    ///
    /// # Errors
    /// - [`CapaError::NotFound`] — `pending_id` not found in receiver's pending queue.
    pub fn reject(receiver: &CapabilityRef<Domain>, pending_id: u64) -> Result<()> {
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

    // ── Channel transfer (send_channel / accept_channel / reject_channel) ────

    /// Transfer a channel capability (move semantics) to another domain.
    ///
    /// Only channel capabilities (created by [`get_chan`]) may be transferred.
    /// Regular domain capabilities are not transferable.
    ///
    /// For **sealed receivers** (`RECEIVE_AFTER_SEAL` required): the source handle
    /// is frozen and a [`PendingDomainCapability`] is enqueued in the receiver.
    /// The receiver must call [`accept_channel`] to complete the transfer.
    ///
    /// For **unsealed receivers**: ownership transfers immediately.
    ///
    /// # Errors
    /// - [`CapaError::NotFound`] — handle not found.
    /// - [`CapaError::PermissionDenied`] — capability is not a channel, handle is
    ///   frozen, caller does not own the channel, or sealed receiver lacks
    ///   `RECEIVE_AFTER_SEAL`.
    pub fn send_channel(
        caller: &CapabilityRef<Domain>,
        chan_handle: LocalHandle,
        receiver_handle: LocalHandle,
        attrs: Attributes,
    ) -> Result<()> {
        // Pre-flight reads.
        let caller_id;
        let chan_ref: CapabilityRef<Domain>;
        let receiver_ref: CapabilityRef<Domain>;
        let recv_sealed;
        {
            let r = caller.read();
            if r.data.is_domain_handle_frozen(chan_handle) {
                return Err(CapaError::PermissionDenied);
            }
            caller_id = r.data.id;
            let chan_weak = r
                .data
                .get_domain_capability(chan_handle)
                .ok_or(CapaError::NotFound)?
                .clone();
            let recv_weak = r
                .data
                .get_domain_capability(receiver_handle)
                .ok_or(CapaError::NotFound)?
                .clone();
            drop(r);
            chan_ref = chan_weak.upgrade().ok_or(CapaError::NotFound)?;
            receiver_ref = recv_weak.upgrade().ok_or(CapaError::NotFound)?;
            recv_sealed = receiver_ref.read().data.is_sealed();
        }

        // Only channels may be transferred.
        if !chan_ref.read().is_channel() {
            return Err(CapaError::PermissionDenied);
        }

        // Caller must own the channel.
        if chan_ref.read().owned.owner != caller_id {
            return Err(CapaError::PermissionDenied);
        }

        // Validate SEND permission on channel cap.
        chan_ref.read().owned.validate_operation(MonitorAPI::SEND)?;

        if recv_sealed {
            // Sealed path: check receiver accepts after seal.
            if !receiver_ref.read().data.policy.receive_after_seal() {
                return Err(CapaError::PermissionDenied);
            }

            // Freeze source handle (authoritative commit).
            {
                let mut cw = caller.write();
                if cw.data.is_domain_handle_frozen(chan_handle) {
                    return Err(CapaError::PermissionDenied);
                }
                cw.data.freeze_domain_handle(chan_handle);
            }

            // Apply attrs (after freeze commit) and record the receiver for revocation cleanup.
            {
                let mut cw = chan_ref.write();
                cw.owned.attributes = attrs;
                cw.owned.pending_receiver = Some(Arc::downgrade(&receiver_ref));
            }

            let pending = PendingDomainCapability {
                cap: Arc::downgrade(&chan_ref),
                sender_domain_id: caller_id,
                sender_handle: chan_handle,
                sender_domain: Arc::downgrade(caller),
            };
            receiver_ref
                .write()
                .data
                .add_pending_domain_capability(pending);
        } else {
            // Unsealed path: immediate ownership transfer.
            let receiver_id = receiver_ref.read().data.id;
            {
                let mut cw = caller.write();
                cw.data.remove_domain_capability(chan_handle);
            }
            {
                let mut cw = chan_ref.write();
                cw.owned.owner = receiver_id;
                cw.owned.owner_domain = Some(Arc::downgrade(&receiver_ref));
                cw.owned.attributes = attrs;
            }
            let new_handle = {
                let mut rw = receiver_ref.write();
                let h = rw.data.allocate_domain_handle();
                rw.data.add_domain_capability(h, Arc::downgrade(&chan_ref));
                h
            };
            let _ = new_handle;
        }

        Ok(())
    }

    /// Accept a pending channel capability.
    ///
    /// Transfers ownership from the sender to the receiver, allocates a fresh
    /// [`LocalHandle`] in the receiver's domain capability table, and clears the
    /// sender's frozen handle.
    ///
    /// Returns the new [`LocalHandle`] assigned to the channel in the receiver.
    ///
    /// # Errors
    /// - [`CapaError::NotFound`] — `pending_id` not found in receiver's pending channel queue.
    pub fn accept_channel(
        receiver: &CapabilityRef<Domain>,
        pending_id: u64,
    ) -> Result<LocalHandle> {
        let receiver_id = receiver.read().data.id;

        // Atomically remove the pending entry.
        let pending = {
            let mut rw = receiver.write();
            rw.data
                .pending_domain_capabilities
                .remove(&pending_id)
                .ok_or(CapaError::NotFound)?
        };

        // Check sender is still alive.
        let sender_ref = pending.sender_domain.upgrade().ok_or(CapaError::NotFound)?;
        let chan_ref = pending.cap.upgrade().ok_or(CapaError::NotFound)?;

        // Transfer ownership and clear the in-transit marker.
        {
            let mut cw = chan_ref.write();
            cw.owned.owner = receiver_id;
            cw.owned.owner_domain = Some(Arc::downgrade(receiver));
            cw.owned.pending_receiver = None;
        }

        // Unfreeze sender's handle and remove it from sender's table.
        {
            let mut sw = sender_ref.write();
            sw.data.unfreeze_domain_handle(pending.sender_handle);
            sw.data.remove_domain_capability(pending.sender_handle);
        }

        // Allocate handle in receiver's table.
        let new_handle = {
            let mut rw = receiver.write();
            let h = rw.data.allocate_domain_handle();
            rw.data.add_domain_capability(h, Arc::downgrade(&chan_ref));
            h
        };

        Ok(new_handle)
    }

    /// Reject a pending channel capability. Unfreezes the sender's handle.
    ///
    /// # Errors
    /// - [`CapaError::NotFound`] — `pending_id` not found in receiver's pending channel queue.
    pub fn reject_channel(receiver: &CapabilityRef<Domain>, pending_id: u64) -> Result<()> {
        let pending = {
            let mut rw = receiver.write();
            rw.data
                .pending_domain_capabilities
                .remove(&pending_id)
                .ok_or(CapaError::NotFound)?
        };

        if let Some(sender_ref) = pending.sender_domain.upgrade() {
            sender_ref
                .write()
                .data
                .unfreeze_domain_handle(pending.sender_handle);
        }
        // Clear in-transit marker on the channel cap.
        if let Some(chan_ref) = pending.cap.upgrade() {
            chan_ref.write().owned.pending_receiver = None;
        }

        Ok(())
    }

    /// Revoke a direct child of the parent capability identified by `child_sub`.
    ///
    /// `parent` is the LocalHandle of the parent memory region in `caller`'s table.
    /// `child_sub` is the SubHandle returned by [`carve`] or [`alias`]
    /// when the child was created.  Because SubHandles are auto-allocated from the
    /// parent's internal counter they are unique among siblings and stable across
    /// ownership transfers — so this call succeeds even after the child has been
    /// sent to another domain.
    ///
    /// # Errors
    /// - [`CapaError::PermissionDenied`] — `parent` handle is frozen, caller does not own the parent,
    ///   parent has `META` attribute, or `REVOKE` API not allowed.
    /// - [`CapaError::NotFound`] — `parent` handle or `child_sub` not found.
    pub fn revoke(
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
            // Validate after releasing parent_ref.read() — same ABBA fix as carve.
            parent_owned.validate_operation(MonitorAPI::REVOKE)?;
        }

        // Mutation: hold write lock. revoke_child operates only on
        // CapabilityRef<MemoryRegion> arcs (independent) — no deadlock risk.
        let mut w = caller.write();
        #[allow(unused_mut)]
        let mut updates = Capability::revoke_child(&parent_ref, child_sub)?;
        refresh_domain_view(&mut *w);

        // Unblock parent's AddressMap entries that were blocked during send.
        // The updates contain ChangeRights(parent, ..., rights, false) for
        // each restored region.  We do NOT remove entries for unmap updates
        // (shootdown_required && rights==NONE) because those come from alias
        // revocations that never had their own AddressMap entry in the caller.
        #[cfg(feature = "address_translation")]
        {
            for update in updates.updates() {
                if let Update::ChangeRights {
                    domain,
                    physical,
                    size,
                    rights,
                    shootdown_required,
                    ..
                } = update
                {
                    if *domain == owner_id
                        && !*shootdown_required
                        && *rights != crate::memory::Rights::NONE
                    {
                        if let Some(gpa) = w.data.address_map.find_gpa_for_hpa(*physical, *size) {
                            let _ = w.data.address_map.unblock(gpa, *rights);
                        }
                    }
                }
            }
            updates.fixup_domain_addresses(owner_id, &w.data.address_map);
        }

        Ok(updates)
    }

    /// Seal the domain identified by cap handle.
    ///
    /// # Errors
    /// - [`CapaError::NotFound`] — `cap` not found in caller's domain table.
    /// - [`CapaError::ApiNotAllowed`] — `cap` is a channel capability, or `SEAL` API not allowed.
    /// - [`CapaError::DomainAlreadySealed`] — domain is already sealed.
    pub fn seal(caller: &CapabilityRef<Domain>, cap: LocalHandle) -> Result<()> {
        let cap_weak = caller
            .read()
            .data
            .get_domain_capability(cap)
            .ok_or(CapaError::NotFound)?
            .clone();
        let cap_ref = cap_weak.upgrade().ok_or(CapaError::NotFound)?;
        if cap_ref.read().is_channel() {
            return Err(CapaError::ApiNotAllowed);
        }
        // Caller must have SEAL permission before sealing a child domain.
        cap_ref.read().owned.validate_operation(MonitorAPI::SEAL)?;
        let result = cap_ref.write().data.seal();
        result
    }

    /// Create a child domain under `parent`, auto-allocating a LocalHandle in
    /// `parent`'s domain table.  Sets `owner_domain` on the child so subsequent
    /// domain-mediated operations on it are properly validated.
    ///
    /// # Errors
    /// - [`CapaError::DomainNotSealed`] — `parent` is not yet sealed.
    /// - [`CapaError::ApiNotAllowed`] — `CREATE` API not allowed on `parent`.
    /// - [`CapaError::InvalidPolicy`] — `policy` violates monotonicity relative to parent.
    pub fn create(parent: &CapabilityRef<Domain>, policy: DomainPolicy) -> Result<(LocalHandle, UpdateBatch)> {
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

        let new_domain_id = child_ref.read().data.id;
        let parent_id = Some(parent.read().data.id);
        let mut batch = UpdateBatch::new();
        batch.add_create_domain(new_domain_id, parent_id);
        Ok((new_handle, batch))
    }

    /// Revoke a child domain that `caller` holds at `child_handle` in its domain table.
    ///
    /// Looks up the child's Arc to get its actual SubHandle, then delegates to
    /// the low-level `revoke_child_domain` (which validates the REVOKE permission).
    ///
    /// # Errors
    /// - [`CapaError::NotFound`] — `child_handle` not found in caller's domain table.
    /// - [`CapaError::ApiNotAllowed`] — `child_handle` is a channel capability.
    /// - [`CapaError::PermissionDenied`] — `REVOKE` API not allowed on caller.
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
        if child_ref.read().is_channel() {
            return Err(CapaError::ApiNotAllowed);
        }
        let child_sub = child_ref.read().sub_handle;
        let updates = Capability::revoke_child_domain(caller, child_sub)?;
        // Remove the now-revoked child from caller's domain table so the
        // LocalHandle is reclaimed by allocate_domain_handle.
        caller.write().data.remove_domain_capability(child_handle);
        Ok(updates)
    }

    /// Register a COMM page owned by `caller`, bound to a child domain's VP.
    ///
    /// The capability at `handle` becomes a shared communication buffer that the
    /// monitor can read/write on behalf of the child's VP.  It must be a **carve**
    /// with **exclusive** status and must not already carry the `COMM` attribute.
    /// The engine sets `COMM|CLEAN` on the capability (no VITAL — revoking a COMM
    /// page does not kill the owning domain) and records a [`CommBinding`] linking
    /// it to `(child_domain, vp_id)`.
    ///
    /// Multiple COMM pages may be registered for the same child domain (e.g. one
    /// per VP, or separate pages for messages vs event flags).  A weak reference
    /// is pushed into the child domain's `comm_bindings` so that the binding can
    /// be automatically cleaned up when the child is revoked.
    ///
    /// # Errors
    /// - [`CapaError::NotFound`]         — `handle` or `child_domain_handle` not found.
    /// - [`CapaError::PermissionDenied`] — handle is frozen, not owned by caller,
    ///                                     not a carve, or not exclusive.
    /// - [`CapaError::InvalidOperation`] — capability already carries `COMM`.
    pub fn register_comm(
        caller: &CapabilityRef<Domain>,
        handle: LocalHandle,
        child_domain_handle: LocalHandle,
        vp_id: u32,
    ) -> Result<UpdateBatch> {
        let owner_id: DomainId;
        let cap_ref: CapabilityRef<MemoryRegion>;
        let child_ref: CapabilityRef<Domain>;

        // Pre-flight: resolve memory handle and child domain handle.
        {
            let r = caller.read();
            if r.data.is_memory_handle_frozen(handle) {
                return Err(CapaError::PermissionDenied);
            }
            owner_id = r.data.id;

            let cap_weak = r
                .data
                .get_memory_capability(handle)
                .ok_or(CapaError::NotFound)?
                .clone();

            let child_weak = r
                .data
                .get_domain_capability(child_domain_handle)
                .ok_or(CapaError::NotFound)?
                .clone();

            drop(r);
            cap_ref = cap_weak.upgrade().ok_or(CapaError::NotFound)?;
            child_ref = child_weak.upgrade().ok_or(CapaError::NotFound)?;
        }

        let child_domain_id: DomainId;

        // Validate cap: must be Carve, Exclusive, leaf, owned by caller,
        // not META, not already COMM.
        let cap_owned = {
            let c = cap_ref.read();
            if c.owned.owner != owner_id {
                return Err(CapaError::PermissionDenied);
            }
            if c.data.kind != RegionKind::Carve {
                return Err(CapaError::PermissionDenied);
            }
            if c.data.status != RegionStatus::Exclusive {
                return Err(CapaError::PermissionDenied);
            }
            if !c.children.is_empty() {
                return Err(CapaError::PermissionDenied);
            }
            if c.owned.attributes.meta() || c.owned.attributes.comm() {
                return Err(CapaError::InvalidOperation(
                    "capability already carries the COMM or META attribute".into(),
                ));
            }
            c.owned.clone()
            // c (cap_ref.read()) released here
        };
        // Validate AFTER releasing cap_ref.read() to avoid ABBA deadlock
        // (same pattern as carve/alias/send).
        cap_owned.validate_operation(MonitorAPI::SET)?;

        // Read child domain ID, validate VP index, and check no existing
        // COMM binding for this VP.
        {
            let child_r = child_ref.read();
            child_domain_id = child_r.data.id;
            if vp_id as usize >= child_r.data.policy.num_vprocessors {
                return Err(CapaError::InvalidOperation(
                    "vp_id exceeds child domain VP count".into(),
                ));
            }
            // Each VP may have at most one COMM binding.
            let already_bound = child_r.data.comm_bindings.iter().any(|weak| {
                weak.upgrade()
                    .map(|cap| {
                        cap.read()
                            .data
                            .comm_binding
                            .map_or(false, |b| b.vp_id == vp_id)
                    })
                    .unwrap_or(false)
            });
            if already_bound {
                return Err(CapaError::InvalidOperation(
                    "VP already has a COMM binding".into(),
                ));
            }
        }

        // Mutation: set COMM attribute + binding on the memory cap,
        // push weak ref into child domain's comm_bindings.
        let (new_phys, new_size) = {
            let mut c = cap_ref.write();
            let phys = c.data.access.start;
            let size = c.data.access.size;
            c.owned.attributes = Attributes::from_bits(Attributes::COMM).canonicalize();
            c.data.comm_binding = Some(CommBinding {
                target_domain_id: child_domain_id,
                vp_id,
            });
            (phys, size)
        };

        // Record weak ref on the child domain for cleanup on revocation.
        {
            let mut child_w = child_ref.write();
            child_w.data.comm_bindings.push(Arc::downgrade(&cap_ref));
        }

        let mut batch = UpdateBatch::new();
        batch.add_comm_region(owner_id, child_domain_id, vp_id, new_phys, new_size);
        Ok(batch)
    }

    /// Add a virtual processor to a child domain.
    ///
    /// Creates a [`VProcessorState`] in the child domain and binds the
    /// supplied COMM capability to it.  The domain must be **Unsealed**
    /// and the VP count must not exceed the policy limit.
    ///
    /// Returns `(vp_id, UpdateBatch)` — the `UpdateBatch` contains a
    /// `CommRegion` update for the COMM binding.  The platform must
    /// additionally allocate hardware VP state (VMCS, VAPIC, etc.)
    /// outside the capability engine.
    ///
    /// # Arguments
    /// * `caller`             — parent domain reference
    /// * `child_domain_handle` — local handle to child domain capability
    /// * `comm_mem_handle`    — local handle to CARVEd memory cap for COMM page
    pub fn add_vp(
        caller: &CapabilityRef<Domain>,
        child_domain_handle: LocalHandle,
        comm_mem_handle: LocalHandle,
    ) -> Result<(u32, UpdateBatch)> {
        let owner_id: DomainId;
        let cap_ref: CapabilityRef<MemoryRegion>;
        let child_ref: CapabilityRef<Domain>;

        // Pre-flight: resolve handles.
        {
            let r = caller.read();
            if r.data.is_memory_handle_frozen(comm_mem_handle) {
                return Err(CapaError::PermissionDenied);
            }
            owner_id = r.data.id;

            let cap_weak = r
                .data
                .get_memory_capability(comm_mem_handle)
                .ok_or(CapaError::NotFound)?
                .clone();
            let child_weak = r
                .data
                .get_domain_capability(child_domain_handle)
                .ok_or(CapaError::NotFound)?
                .clone();

            drop(r);
            cap_ref = cap_weak.upgrade().ok_or(CapaError::NotFound)?;
            child_ref = child_weak.upgrade().ok_or(CapaError::NotFound)?;
        }

        let child_domain_id: DomainId;

        // Validate COMM cap: Carve, Exclusive, owned by caller, not already COMM.
        {
            let c = cap_ref.read();
            if c.owned.owner != owner_id {
                return Err(CapaError::PermissionDenied);
            }
            if c.data.kind != RegionKind::Carve {
                return Err(CapaError::PermissionDenied);
            }
            if c.data.status != RegionStatus::Exclusive {
                return Err(CapaError::PermissionDenied);
            }
            if c.owned.attributes.comm() {
                return Err(CapaError::InvalidOperation(
                    "capability already carries the COMM attribute".into(),
                ));
            }
        }

        // Add VP to child domain (validates unsealed + limit); returns assigned vp_id.
        let vp_id: u32;
        {
            let mut child_w = child_ref.write();
            child_domain_id = child_w.data.id;
            vp_id = child_w.data.add_vprocessor()? as u32;
        }

        // Mutation: set COMM attribute + binding on the memory cap.
        let (comm_phys, comm_size) = {
            let mut c = cap_ref.write();
            let phys = c.data.access.start;
            let size = c.data.access.size;
            c.owned.attributes = Attributes::from_bits(Attributes::COMM).canonicalize();
            c.data.comm_binding = Some(CommBinding {
                target_domain_id: child_domain_id,
                vp_id,
            });
            (phys, size)
        };

        // Record weak ref for cleanup on revocation.
        {
            let mut child_w = child_ref.write();
            child_w.data.comm_bindings.push(Arc::downgrade(&cap_ref));
        }

        let mut batch = UpdateBatch::new();
        batch.add_comm_region(owner_id, child_domain_id, vp_id, comm_phys, comm_size);
        Ok((vp_id, batch))
    }

    /// Attest the caller domain itself.
    ///
    /// Requires the caller domain to be sealed and have `MonitorAPI::ATTEST` enabled.
    ///
    /// # Errors
    /// - [`CapaError::DomainNotSealed`] — caller is not sealed.
    /// - [`CapaError::ApiNotAllowed`] — caller lacks `MonitorAPI::ATTEST`.
    pub fn attest_self(caller: &CapabilityRef<Domain>) -> Result<AttestationReport> {
        {
            let c = caller.read();
            if !c.data.is_sealed() {
                return Err(CapaError::DomainNotSealed);
            }
            if !c.data.policy.api.attest() {
                return Err(CapaError::ApiNotAllowed);
            }
        }
        Ok(attest::attest_domain(caller))
    }

    /// Attest a domain (or its channel target) identified by `handle` in the caller's table.
    ///
    /// Requires the **caller** domain to be sealed and have `MonitorAPI::ATTEST` enabled.
    /// The domain at `handle` must also be sealed.
    /// If `handle` resolves to a channel capability, the channel's target domain is attested
    /// (channel targets are always sealed by construction).
    ///
    /// # Errors
    /// - [`CapaError::DomainNotSealed`] — caller or target is not sealed.
    /// - [`CapaError::ApiNotAllowed`] — caller lacks `MonitorAPI::ATTEST`.
    /// - [`CapaError::NotFound`] — `handle` not found in caller's domain table.
    pub fn attest(
        caller: &CapabilityRef<Domain>,
        handle: LocalHandle,
    ) -> Result<AttestationReport> {
        {
            let c = caller.read();
            if !c.data.is_sealed() {
                return Err(CapaError::DomainNotSealed);
            }
            if !c.data.policy.api.attest() {
                return Err(CapaError::ApiNotAllowed);
            }
        }
        let cap_weak = caller
            .read()
            .data
            .get_domain_capability(handle)
            .ok_or(CapaError::NotFound)?
            .clone();
        let cap_ref = cap_weak.upgrade().ok_or(CapaError::NotFound)?;
        // For non-channel caps, verify the target is sealed.
        // Channel caps always reference a sealed target (enforced at get_chan time).
        if !cap_ref.read().is_channel() && !cap_ref.read().data.is_sealed() {
            return Err(CapaError::DomainNotSealed);
        }
        // Pass cap_ref directly — attest::attest_domain handles channel resolution
        // internally and preserves the "Channel: true" header.
        Ok(attest::attest_domain(&cap_ref))
    }

    /// Create a channel capability for `target_handle`.
    ///
    /// A channel is a restricted child capability of the target domain.
    /// It can be used to:
    ///   - Attest the target domain (`attest`).
    ///   - Send memory capabilities to the target domain (`send`).
    ///   - Be transferred to another domain (`send_channel` / `accept_channel`).
    ///
    /// A channel cannot switch to, revoke, or administer the target domain.
    ///
    /// The channel is inserted as a child of `target`'s CDT node and registered
    /// in `caller`'s domain capability table at a freshly allocated handle.
    ///
    /// # Errors
    /// - [`CapaError::ApiNotAllowed`] — caller lacks `MonitorAPI::GETCHAN`.
    /// - [`CapaError::NotFound`] — `target_handle` not found in caller.
    /// - [`CapaError::DomainNotSealed`] — target domain is not yet sealed.
    pub fn get_chan(
        caller: &CapabilityRef<Domain>,
        target_handle: LocalHandle,
    ) -> Result<LocalHandle> {
        let caller_id = caller.read().data.id;

        // 1. Resolve target domain capability.
        let target_weak = caller
            .read()
            .data
            .get_domain_capability(target_handle)
            .ok_or(CapaError::NotFound)?
            .clone();
        let target_ref = target_weak.upgrade().ok_or(CapaError::NotFound)?;

        // 2. Check GETCHAN permission: validate that the caller domain (owner of
        //    target_ref) has GETCHAN in its policy.  We use the standard pattern of
        //    calling validate_operation on the owned struct of the capability being
        //    operated on — its owner_domain IS the caller.
        {
            let target_r = target_ref.read();
            target_r.owned.validate_operation(MonitorAPI::GETCHAN)?;
        }

        // 3. Target must be sealed (channels are only meaningful for live domains).
        if !target_ref.read().data.is_sealed() {
            return Err(CapaError::DomainNotSealed);
        }

        // 4. Allocate a SubHandle and depth from the target's CDT node.
        let (sub_handle, chan_depth) = {
            let mut t = target_ref.write();
            let s = t.next_child_sub;
            t.next_child_sub += 1;
            (s, t.depth + 1)
        };

        // 5. Build the channel capability.
        //    - data: sentinel (never used directly)
        //    - channel_target: weak ref to target
        //    - MonitorAPI: ATTEST | GETCHAN | SEND only
        let chan_policy = DomainPolicy::new_restricted(0, MonitorAPI::CHAN_ALLOWED);
        let chan_domain = Domain::new_sentinel();
        let chan_ref: CapabilityRef<Domain> = Arc::new(crate::sync::RwLock::new(Capability {
            owned: {
                let mut o = Ownership::new(caller_id);
                o.owner_domain = Some(Arc::downgrade(caller));
                o
            },
            sub_handle,
            depth: chan_depth,
            data: chan_domain,
            channel_target: Some(Arc::downgrade(&target_ref)),
            parent: Arc::downgrade(&target_ref),
            children: Vec::new(),
            next_child_sub: 1,
        }));

        // 6. Register channel as a child of target in the CDT.
        target_ref.write().add_child(chan_ref.clone());

        // 7. Register in caller's domain capability table and return handle.
        let chan_handle = {
            let mut cw = caller.write();
            let h = cw.data.allocate_domain_handle();
            cw.data.add_domain_capability(h, Arc::downgrade(&chan_ref));
            h
        };

        // Keep a strong reference alive inside the CDT (the target's children vec
        // already holds one, so the Arc won't be dropped prematurely).
        let _ = chan_policy; // chan_policy embedded in sentinel; not separately stored
        Ok(chan_handle)
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
    ///
    /// # Errors
    /// - [`CapaError::InvalidOperation`] — current core unknown, no VP running on that core,
    ///   or (return path) no saved caller context.
    /// - [`CapaError::DomainNotSealed`] — caller or target domain not sealed.
    /// - [`CapaError::ApiNotAllowed`] — caller lacks `MonitorAPI::SWITCH`, or target VP
    ///   is not `Available`.
    /// - [`CapaError::NotFound`] — `to_handle` not found in caller's domain table.
    pub fn switch(
        caller: &CapabilityRef<Domain>,
        to_handle: LocalHandle,
        to_vp_id: u64,
        platform: &dyn Platform,
    ) -> Result<SwitchContext> {
        let core_id = platform
            .get_current_core()
            .ok_or_else(|| CapaError::InvalidOperation("current core unknown".to_string()))?;

        if to_handle == 0 {
            Self::switch_domain_return(caller, core_id, platform)
        } else {
            Self::switch_domain_forward(caller, to_handle, to_vp_id, core_id, platform)
        }
    }

    /// Return path: unwind the VP call chain one step.
    ///
    /// Transitions:
    /// - Caller VP: `Running → Available`
    /// - Previous (Locked) VP: `Locked → Running { core, caller: prev_prev_caller }`
    fn switch_domain_return(
        caller: &CapabilityRef<Domain>,
        core_id: CoreId,
        platform: &dyn Platform,
    ) -> Result<SwitchContext> {
        let (caller_id, caller_vp_arc) = {
            let c = caller.read();
            if !c.data.is_sealed() {
                return Err(CapaError::DomainNotSealed);
            }
            let id = c.data.id;
            let vp = c.data.find_vp_on_core(core_id).ok_or_else(|| {
                CapaError::InvalidOperation("no VP running on this core".to_string())
            })?;
            (id, vp)
        };
        let caller_vp_id = caller_vp_arc.id;

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

        let prev_vp_arc = {
            let pd = prev_domain_ref.read();
            pd.data
                .policy
                .vprocessor_states
                .get(prev_vp_id as usize)
                .ok_or(CapaError::NotFound)?
                .clone()
        };

        // Verify previous VP is Locked waiting for this callee and extract its saved caller.
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

        *prev_vp_arc.run_state.write() = VpRunState::Running {
            core: core_id,
            caller: prev_prev_caller,
        };
        *caller_vp_arc.run_state.write() = VpRunState::Available;

        platform.set_core_context(core_id, &prev_domain_ref, prev_vp_id);

        Ok(SwitchContext {
            from_domain: caller_id,
            to_domain: prev_domain_id,
            core_id,
            is_return: true,
            from_vp_id: Some(caller_vp_id),
            to_vp_id: Some(prev_vp_id),
            interrupt_return: None,
        })
    }

    /// Forward switch: claim the target VP and lock the caller VP.
    ///
    /// Transitions:
    /// - Target VP: `Available → Running` or `Suspended → Running` (interrupt-resume)
    /// - Caller VP: `Running → Locked { callee: target }`
    ///
    /// If the target VP was `Suspended`, its `Interrupted` callee is freed (`→ Available`)
    /// after the target VP's lock is released.
    fn switch_domain_forward(
        caller: &CapabilityRef<Domain>,
        to_handle: LocalHandle,
        to_vp_id: u64,
        core_id: CoreId,
        platform: &dyn Platform,
    ) -> Result<SwitchContext> {
        // One caller.read(): sealed + SWITCH check, caller_id, to_domain_weak.
        let (caller_id, to_domain_ref) = {
            let c = caller.read();
            if !c.data.is_sealed() {
                return Err(CapaError::DomainNotSealed);
            }
            if !c.data.policy.api.has(MonitorAPI::SWITCH) {
                return Err(CapaError::ApiNotAllowed);
            }
            let id = c.data.id;
            let to_weak = c
                .data
                .get_domain_capability(to_handle)
                .ok_or(CapaError::NotFound)?
                .clone();
            drop(c);
            let to_ref = to_weak.upgrade().ok_or(CapaError::NotFound)?;
            (id, to_ref)
        };

        // One to_domain_ref.read(): channel guard, sealed, core mask, target VP arc.
        // Channel check runs before VP lookup to preserve early-reject ordering.
        let (to_domain_id, core_allowed, to_vp_arc) = {
            let td = to_domain_ref.read();
            if td.is_channel() {
                return Err(CapaError::ApiNotAllowed);
            }
            if !td.data.is_sealed() {
                return Err(CapaError::DomainNotSealed);
            }
            let core_bit = 1u64 << core_id;
            let allowed = (td.data.policy.cores & core_bit) != 0;
            let vp = td
                .data
                .policy
                .vprocessor_states
                .get(to_vp_id as usize)
                .ok_or(CapaError::NotFound)?
                .clone();
            (td.data.id, allowed, vp)
        };
        if !core_allowed {
            return Err(CapaError::PermissionDenied);
        }

        // Second caller.read(): VP lookup (after channel/target checks to preserve error ordering).
        let caller_vp_arc = {
            let c = caller.read();
            c.data.find_vp_on_core(core_id).ok_or_else(|| {
                CapaError::InvalidOperation("no VP running on this core".to_string())
            })?
        };
        let caller_vp_id = caller_vp_arc.id;

        // Capture caller's saved-caller context before mutating anything.
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

        // Claim target VP: Available → Running, or Suspended → Running.
        // If Suspended, record callee info so the Interrupted callee can be freed,
        // and capture the interrupt vector for SwitchContext.interrupt_return.
        let suspended_info: Option<(CapabilityWeak<Domain>, u64, u8)> = {
            let mut state = to_vp_arc.run_state.write();

            let callee_info = if let VpRunState::Suspended {
                callee_domain,
                callee_vp_id,
                vector,
                ..
            } = &*state
            {
                Some((callee_domain.clone(), *callee_vp_id, *vector))
            } else {
                None
            };

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

        // interrupt_return: Some(vector) if the target VP was Suspended (interrupt return path).
        // This is used by do_switch to set RDI=vector on the synthetic SWITCH return.
        let interrupt_return: Option<u8> = suspended_info.as_ref().map(|(_, _, v)| *v);

        // If the target VP was Suspended, free its Interrupted callee.
        if let Some((callee_weak, callee_vp_id, _)) = suspended_info {
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
                    if matches!(*s, VpRunState::Interrupted { .. }) {
                        *s = VpRunState::Available;
                    }
                }
            }
        }

        *caller_vp_arc.run_state.write() = VpRunState::Locked {
            callee_domain_id: to_domain_id,
            callee_vp_id: to_vp_id,
            prev_caller: caller_prev_caller,
        };

        platform.set_core_context(core_id, &to_domain_ref, to_vp_id);

        Ok(SwitchContext {
            from_domain: caller_id,
            to_domain: to_domain_id,
            core_id,
            is_return: false,
            from_vp_id: Some(caller_vp_id),
            to_vp_id: Some(to_vp_id),
            interrupt_return,
        })
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
    /// is later claimed via a forward `switch`.
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
        vector: u8,
        platform: &dyn Platform,
    ) -> Result<VpInterruptContext> {
        let (interrupted_domain_id, leaf_vp_arc) = {
            let d = interrupted_cap.read();
            let id = d.data.id;
            let vp = d.data.find_vp_on_core(core_id).ok_or_else(|| {
                CapaError::InvalidOperation(
                    "no VP running on core for interrupt delivery".to_string(),
                )
            })?;
            (id, vp)
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
        // chain[0]:      Running → Interrupted (or Available when n==2)
        // chain[1..n-2]: Locked  → Suspended { callee = chain[i-1] }
        // chain[n-1]:    Locked  → Running { core, caller: handler's prev_caller }
        //
        // When the handler VP becomes Running it "unlocks" its immediate callee.
        // For n>2 the callee is Suspended (already claimable).  For n==2 the
        // callee is the leaf itself, so we set it to Available directly.

        // Leaf: Running → Interrupted, unless the handler is the direct caller
        // (n==2) in which case the handler becoming Running unlocks it immediately.
        if n > 2 {
            *chain[0].2.run_state.write() = VpRunState::Interrupted { vector };
        } else {
            *chain[0].2.run_state.write() = VpRunState::Available;
        }

        // Intermediate VPs: Locked → Suspended.
        for i in 1..n - 1 {
            let callee_domain = Arc::downgrade(&chain[i - 1].0);
            let callee_domain_id = chain[i - 1].1;
            let callee_vp_id = chain[i - 1].2.id;
            *chain[i].2.run_state.write() = VpRunState::Suspended {
                callee_domain,
                callee_domain_id,
                callee_vp_id,
                vector,
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
        platform.set_core_context(core_id, &chain[n - 1].0, handler_vp_id);

        Ok(VpInterruptContext {
            interrupted_domain_id,
            interrupted_vp_id: leaf_vp_id,
            handler_domain_id,
            handler_vp_id,
            core_id,
        })
    }

    // =========================================================================
    // Policy and register set / get
    // =========================================================================

    /// Modify a domain-wide policy field on a child domain.
    ///
    /// # Rules
    /// - Caller must have [`MonitorAPI::SET`] permission.
    /// - The child domain must be **Unsealed** (hard error if already sealed).
    /// - For `Cores` and `ApiMonitor`, the new value must be a *subset* of the
    ///   corresponding parent field (monotonicity).
    /// - Register-access bitmaps (`VectorRegReadSet` / `VectorRegWriteSet`) are
    ///   **not** subject to monotonicity; the parent may freely configure them.
    ///
    /// # Errors
    /// - [`CapaError::ApiNotAllowed`] — caller lacks `MonitorAPI::SET`.
    /// - [`CapaError::NotFound`] — `child_handle` not found in caller's domain table.
    /// - [`CapaError::DomainAlreadySealed`] — child is already sealed.
    /// - [`CapaError::InvalidPolicy`] — new value exceeds parent (monotonicity violation).
    pub fn set_policy(
        caller: &CapabilityRef<Domain>,
        child_handle: LocalHandle,
        id: PolicyIdentifier,
        value: u64,
    ) -> Result<()> {
        // Validate caller has SET permission.
        caller.read().data.require_api(MonitorAPI::SET)?;

        // Retrieve child.
        let child_weak = caller
            .read()
            .data
            .get_domain_capability(child_handle)
            .ok_or(CapaError::NotFound)?
            .clone();
        let child_ref = child_weak.upgrade().ok_or(CapaError::NotFound)?;

        let parent_policy = caller.read().data.policy.clone();
        let mut child_w = child_ref.write();

        // Sealed check must be done while holding the write lock to prevent a
        // concurrent seal from racing between the check and the mutation.
        if child_w.data.status != crate::domain::DomainStatus::Unsealed {
            return Err(CapaError::DomainSealed);
        }

        match id {
            PolicyIdentifier::Cores => {
                // Monotonicity: new cores must be a subset of parent cores.
                if (value & !parent_policy.cores) != 0 {
                    return Err(CapaError::MonotonicityViolation);
                }
                child_w.data.policy.cores = value;
                // Maintain invariant: num_vprocessors ≤ popcount(cores).
                let max_vps = value.count_ones() as usize;
                if child_w.data.policy.num_vprocessors > max_vps {
                    child_w.data.policy.num_vprocessors = max_vps;
                }
            }
            PolicyIdentifier::ApiMonitor => {
                let bits = value as u16;
                if (bits & !parent_policy.api.bits()) != 0 {
                    return Err(CapaError::MonotonicityViolation);
                }
                child_w.data.policy.api = MonitorAPI::from_bits(bits);
            }
            PolicyIdentifier::DefaultInterruptVisibility => {
                let vis = visibility_from_u64(value)?;
                // Monotonicity: child cannot be more permissive than parent default.
                // Ordering: Deliver (0) > Report (1) > NotReport (2); higher u64 = more restrictive.
                if visibility_to_u64(vis)
                    < visibility_to_u64(parent_policy.interrupts.default.visibility)
                {
                    return Err(CapaError::MonotonicityViolation);
                }
                child_w.data.policy.interrupts.default.visibility = vis;
            }
            PolicyIdentifier::VectorVisibility(vec) => {
                let vis = visibility_from_u64(value)?;
                // Monotonicity: child cannot be more permissive than the parent's
                // effective policy for this vector (override if present, else default).
                let parent_effective = parent_policy.interrupts.get_policy(vec).visibility;
                if visibility_to_u64(vis) < visibility_to_u64(parent_effective) {
                    return Err(CapaError::MonotonicityViolation);
                }
                let default_vis = child_w.data.policy.interrupts.default.visibility;
                let default_read = child_w.data.policy.interrupts.default.read_set;
                let default_write = child_w.data.policy.interrupts.default.write_set;
                let entry = child_w
                    .data
                    .policy
                    .interrupts
                    .overrides
                    .entry(vec)
                    .or_insert_with(|| VectorPolicy {
                        visibility: default_vis,
                        read_set: default_read,
                        write_set: default_write,
                    });
                entry.visibility = vis;
            }
            PolicyIdentifier::VectorRegReadSet(vec, word) => {
                let entry = child_w
                    .data
                    .policy
                    .interrupts
                    .overrides
                    .entry(vec)
                    .or_insert_with(VectorPolicy::default_report);
                entry.read_set.set_word(word as usize, value);
            }
            PolicyIdentifier::VectorRegWriteSet(vec, word) => {
                let entry = child_w
                    .data
                    .policy
                    .interrupts
                    .overrides
                    .entry(vec)
                    .or_insert_with(VectorPolicy::default_report);
                entry.write_set.set_word(word as usize, value);
            }
        }

        Ok(())
    }

    /// Read a domain-wide policy field from a child domain.
    ///
    /// Caller must have [`MonitorAPI::GET`] permission.
    /// Succeeds regardless of the child's seal status.
    ///
    /// # Errors
    /// - [`CapaError::ApiNotAllowed`] — caller lacks `MonitorAPI::GET`.
    /// - [`CapaError::NotFound`] — `child_handle` not found in caller's domain table.
    pub fn get_policy(
        caller: &CapabilityRef<Domain>,
        child_handle: LocalHandle,
        id: PolicyIdentifier,
    ) -> Result<u64> {
        caller.read().data.require_api(MonitorAPI::GET)?;

        let child_weak = caller
            .read()
            .data
            .get_domain_capability(child_handle)
            .ok_or(CapaError::NotFound)?
            .clone();
        let child_ref = child_weak.upgrade().ok_or(CapaError::NotFound)?;
        let child_r = child_ref.read();

        let value = match id {
            PolicyIdentifier::Cores => child_r.data.policy.cores,
            PolicyIdentifier::ApiMonitor => child_r.data.policy.api.bits() as u64,
            PolicyIdentifier::DefaultInterruptVisibility => {
                visibility_to_u64(child_r.data.policy.interrupts.default.visibility)
            }
            PolicyIdentifier::VectorVisibility(vec) => {
                visibility_to_u64(child_r.data.policy.interrupts.get_policy(vec).visibility)
            }
            PolicyIdentifier::VectorRegReadSet(vec, word) => {
                child_r.data.policy.interrupts.get_policy(vec).read_set.word(word as usize)
            }
            PolicyIdentifier::VectorRegWriteSet(vec, word) => {
                child_r.data.policy.interrupts.get_policy(vec).write_set.word(word as usize)
            }
        };

        Ok(value)
    }

    /// Write a VP register on a child domain.
    ///
    /// The engine validates:
    /// 1. Caller has [`MonitorAPI::SET`] permission.
    /// 2. `reg_id` is within `platform.register_count()`.
    /// 3. Bit `reg_id` is set in the **write** bitmap of the effective-vector
    ///    policy for the target VP's current run state.
    ///
    /// The actual write is delegated to [`Platform::set_vp_register`].
    ///
    /// # Errors
    /// - [`CapaError::ApiNotAllowed`] — caller lacks `MonitorAPI::SET`.
    /// - [`CapaError::NotFound`] — `child_handle` or `vp_id` not found.
    /// - [`CapaError::RegisterAccessDenied`] — `reg_id` not set in write bitmap.
    /// - [`CapaError::InvalidOperation`] — `reg_id` out of range.
    pub fn set_register(
        caller: &CapabilityRef<Domain>,
        child_handle: LocalHandle,
        vp_id: u64,
        reg_id: u64,
        value: u64,
        platform: &dyn Platform,
    ) -> Result<()> {
        caller.read().data.require_api(MonitorAPI::SET)?;

        let (child_domain_id, write_set) =
            register_access_check(caller, child_handle, vp_id, reg_id, platform, false)?;

        if !write_set.is_set(reg_id) {
            return Err(CapaError::RegisterAccessDenied);
        }

        platform.set_vp_register(child_domain_id, vp_id, reg_id, value)
    }

    /// Validate that `caller` may write `reg_id` on the child VP, without
    /// performing the actual write or touching the COMM page.
    ///
    /// Used by `do_switch` when draining dirty COMM-page bits: the capability
    /// engine validates access, but the write is applied directly to the VMCS
    /// via `apply_vmcs_reg` — not via `set_vp_register` (which would re-mark
    /// the dirty bit and cause an infinite replay loop).
    pub fn check_register_write(
        caller: &CapabilityRef<Domain>,
        child_handle: LocalHandle,
        vp_id: u64,
        reg_id: u64,
        platform: &dyn Platform,
    ) -> Result<()> {
        caller.read().data.require_api(MonitorAPI::SET)?;

        let (_child_domain_id, write_set) =
            register_access_check(caller, child_handle, vp_id, reg_id, platform, false)?;

        if !write_set.is_set(reg_id) {
            return Err(CapaError::RegisterAccessDenied);
        }

        Ok(())
    }

    /// Read a VP register from a child domain.
    ///
    /// The engine validates:
    /// 1. Caller has [`MonitorAPI::GET`] permission.
    /// 2. `reg_id` is within `platform.register_count()`.
    /// 3. Bit `reg_id` is set in the **read** bitmap of the effective-vector
    ///    policy for the target VP's current run state.
    ///
    /// The actual read is delegated to [`Platform::get_vp_register`].
    ///
    /// # Errors
    /// - [`CapaError::ApiNotAllowed`] — caller lacks `MonitorAPI::GET`.
    /// - [`CapaError::NotFound`] — `child_handle` or `vp_id` not found.
    /// - [`CapaError::RegisterAccessDenied`] — `reg_id` not set in read bitmap.
    /// - [`CapaError::InvalidOperation`] — `reg_id` out of range.
    pub fn get_register(
        caller: &CapabilityRef<Domain>,
        child_handle: LocalHandle,
        vp_id: u64,
        reg_id: u64,
        platform: &dyn Platform,
    ) -> Result<u64> {
        caller.read().data.require_api(MonitorAPI::GET)?;

        let (child_domain_id, read_set) =
            register_access_check(caller, child_handle, vp_id, reg_id, platform, true)?;

        if !read_set.is_set(reg_id) {
            return Err(CapaError::RegisterAccessDenied);
        }

        platform.get_vp_register(child_domain_id, vp_id, reg_id)
    }

    /// Compute a cryptographic hash of the physical memory backing a memory
    /// capability and store it in the capability's `content_hash` field.
    ///
    /// Intended for capabilities carrying [`crate::memory::Attributes::HASH`].
    /// The hash is computed by delegating to [`Platform::measure_region`], which
    /// is free to use any algorithm (SHA-256, SHA3-256, …). The result is stored
    /// as a 32-byte opaque array in [`MemoryRegion::content_hash`].
    ///
    /// # Errors
    /// - [`CapaError::NotFound`] if the handle does not resolve to a memory capability.
    /// - [`CapaError::PermissionDenied`] if the caller does not own the capability.
    pub fn compute_memory_hash(
        caller: &CapabilityRef<Domain>,
        handle: LocalHandle,
        platform: &dyn Platform,
    ) -> Result<[u8; 32]> {
        let caller_id = caller.read().data.id;

        let cap_weak = caller
            .read()
            .data
            .get_memory_capability(handle)
            .ok_or(CapaError::NotFound)?
            .clone();
        let cap_ref = cap_weak.upgrade().ok_or(CapaError::NotFound)?;

        let (address, size) = {
            let cap_r = cap_ref.read();
            if cap_r.owned.owner != caller_id {
                return Err(CapaError::PermissionDenied);
            }
            (cap_r.data.access.start, cap_r.data.access.size)
        };

        let hash = platform.measure_region(address, size);
        cap_ref.write().data.content_hash = Some(hash);
        Ok(hash)
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Encode [`InterruptVisibility`] as a `u64` (0=Deliver, 1=Report, 2=NotReport).
fn visibility_to_u64(v: InterruptVisibility) -> u64 {
    match v {
        InterruptVisibility::Deliver => 0,
        InterruptVisibility::Report => 1,
        InterruptVisibility::NotReport => 2,
    }
}

/// Decode a `u64` to [`InterruptVisibility`].
fn visibility_from_u64(v: u64) -> Result<InterruptVisibility> {
    match v {
        0 => Ok(InterruptVisibility::Deliver),
        1 => Ok(InterruptVisibility::Report),
        2 => Ok(InterruptVisibility::NotReport),
        _ => Err(CapaError::InvalidOperation(alloc::format!(
            "invalid visibility value: {}",
            v
        ))),
    }
}

/// Shared validation for `set_register` and `get_register`.
///
/// Returns `(child_domain_id, bitmap)` where `bitmap` is the read bitmap when
/// `want_read = true` and the write bitmap otherwise.
fn register_access_check(
    caller: &CapabilityRef<Domain>,
    child_handle: LocalHandle,
    vp_id: u64,
    reg_id: u64,
    platform: &dyn Platform,
    want_read: bool,
) -> Result<(DomainId, RegBitmap)> {
    // Bounds check.
    if reg_id >= platform.register_count() {
        return Err(CapaError::RegisterOutOfRange);
    }

    let child_weak = caller
        .read()
        .data
        .get_domain_capability(child_handle)
        .ok_or(CapaError::NotFound)?
        .clone();
    let child_ref = child_weak.upgrade().ok_or(CapaError::NotFound)?;
    let child_r = child_ref.read();

    let child_domain_id = child_r.data.id;

    // Look up the target VP.
    let vp = child_r
        .data
        .policy
        .vprocessor_states
        .get(vp_id as usize)
        .ok_or(CapaError::NotFound)?
        .clone();

    // A VP that is actively executing cannot have its registers safely accessed.
    if matches!(*vp.run_state.read(), VpRunState::Running { .. }) {
        return Err(CapaError::RegisterAccessDenied);
    }

    // Determine effective interrupt vector from VP run state.
    let vec = effective_vector(&vp.run_state.read());

    // Retrieve the effective VectorPolicy (override or domain default).
    let policy = child_r.data.policy.interrupts.get_policy(vec);
    let bitmap = if want_read {
        policy.read_set
    } else {
        policy.write_set
    };

    Ok((child_domain_id, bitmap))
}

// Suppress the unused-import warning for VECTOR_AVAILABLE when it's only
// referenced indirectly through effective_vector.
const _: u8 = VECTOR_AVAILABLE;
