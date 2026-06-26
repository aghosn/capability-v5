//! Core capability structures with thread-safe parent-child relationships

use crate::attest::{self, AttestationReport};
use crate::domain::{
    Domain, DomainPolicy, ExitAction, InterruptVisibility, MonitorAPI,
    PendingCapability, PendingDomainCapability, PolicyIdentifier, RegBitmap, ResourceKind,
    VProcessorRef, VectorPolicy, VpCallContext, VpRunState, VECTOR_AVAILABLE,
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
use crate::view::{view_diff, AddressSpaceView};
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

        // META and COMM regions may not be aliased.  Checked under parent.write()
        // so the domain-mediated layer doesn't need a separate parent.read() pre-flight.
        if parent.owned.attributes.meta() || parent.owned.attributes.comm() {
            return Err(CapaError::PermissionDenied);
        }

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

        // META and COMM regions may not be carved.  Checked under parent.write()
        // so the domain-mediated layer doesn't need a separate parent.read() pre-flight.
        if parent.owned.attributes.meta() || parent.owned.attributes.comm() {
            return Err(CapaError::PermissionDenied);
        }

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
                dom_ref.try_read().map_or(false, |r| r.data.is_revoked())
            });

        // Capture the domain ref for VITAL cascade (before dropping the lock).
        // If this cap has vital=true and the owning domain isn't already revoked,
        // we'll need the CapabilityRef<Domain> to call revoke_domain_subtree.
        let vital_domain_ref = if vital && !child_revoked {
            capa.owned.owner_domain.as_ref().and_then(|w| w.upgrade())
        } else {
            None
        };

        let child_domain_weak = capa.owned.owner_domain.clone();

        // Weak ref to the capability being revoked — used to remove it from the
        // child domain's memory_capabilities table (the Arc is still live at
        // this point, so prune_stale won't catch it).
        let cap_weak_ref = Arc::downgrade(capa_ref);

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
                            dom_ref.try_read().map_or(false, |r| r.data.is_revoked())
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

        // === Clean up child domain after cross-domain revoke ===
        // Remove the revoked capability from the child domain's tracking table
        // and refresh cached_view.  We use remove_memory_capability_by_ref
        // because the Arc is still alive (held by revoke_child), so
        // prune_stale_memory_capabilities would not catch it.
        // With address_translation, also remove from the child's AddressMap.
        // Skip if child is revoked — it's already being torn down.
        if parent_info.is_some() && !child_revoked {
            if let Some(ref w) = child_domain_weak {
                if let Some(dom_ref) = w.upgrade() {
                    if let Some(mut dom) = dom_ref.try_write() {
                        #[cfg(feature = "address_translation")]
                        dom.data
                            .address_map
                            .remove_by_hpa_range(hpa_start, hpa_size);
                        dom.data.remove_memory_capability_by_ref(&cap_weak_ref);
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
        //
        // VITAL cascade: call revoke_domain_subtree to fully clean up the dead
        // domain — revoke its root memory caps (restoring parent ranges),
        // recursively revoke child domains, and clean up channels/COMM bindings.
        //
        // Safety: revoke_child (our caller) already removed this cap from
        // the parent's children list before calling revoke_subtree.  So the
        // cascade's attempt to re-revoke this cap via revoke_child will get
        // NotFound and skip it — no duplicate updates.
        if vital && !child_revoked {
            if let Some(ref domain_ref) = vital_domain_ref {
                let cascade = Capability::<Domain>::revoke_domain_subtree(domain_ref, None)?;
                updates.merge(cascade);
            } else {
                // Fallback: domain ref unavailable (e.g. root cap without
                // owner_domain set).  Emit the update without cascade.
                updates.add_revoke_domain_with_fallback(child_owner, None);
            }
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
    pub(crate) fn revoke_domain_subtree(
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

/// Add a capability's full footprint to the address map using the refcounted
/// contribution model.  Walks `view` (visible ranges) and inserts:
/// - **Mapped** segments for each visible range (with the cap's `rights`)
/// - **Blocked** segments for gaps (carved-away holes)
///
/// `hpa_start` / `size` define the capability's HPA extent.
/// `gpa_base` is where the footprint is placed in GPA space.
/// `view` comes from `compute_view()`.
/// `rights` are the capability's own access rights.
#[cfg(feature = "address_translation")]
fn add_footprint(
    map: &mut crate::translation::AddressMap,
    hpa_start: u64,
    size: u64,
    gpa_base: u64,
    view: &[Access],
    rights: crate::memory::Rights,
) -> core::result::Result<(), &'static str> {
    let hpa_end = hpa_start + size;
    let mut cursor = hpa_start;

    for v in view {
        let v_start = v.start;
        let v_end = v.start + v.size;

        // Gap before this visible range → Blocked contribution.
        if cursor < v_start {
            let gap_size = v_start - cursor;
            let gap_gpa = gpa_base + (cursor - hpa_start);
            let gap_hpa = cursor;
            map.add_contribution(gap_gpa, gap_hpa, gap_size, crate::memory::Rights::NONE, true)?;
            cursor = v_start;
        }

        // Visible range → Mapped contribution.
        if cursor < v_end {
            let mapped_size = v_end - cursor;
            let mapped_gpa = gpa_base + (cursor - hpa_start);
            let mapped_hpa = cursor;
            map.add_contribution(mapped_gpa, mapped_hpa, mapped_size, rights, false)?;
            cursor = v_end;
        }
    }

    // Trailing gap → Blocked.
    if cursor < hpa_end {
        let gap_size = hpa_end - cursor;
        let gap_gpa = gpa_base + (cursor - hpa_start);
        let gap_hpa = cursor;
        map.add_contribution(gap_gpa, gap_hpa, gap_size, crate::memory::Rights::NONE, true)?;
    }

    Ok(())
}

/// Remove a capability's full footprint from the address map (inverse of
/// [`add_footprint`]).
#[cfg(feature = "address_translation")]
fn remove_footprint(
    map: &mut crate::translation::AddressMap,
    hpa_start: u64,
    size: u64,
    gpa_base: u64,
    view: &[Access],
    rights: crate::memory::Rights,
) -> core::result::Result<(), &'static str> {
    let hpa_end = hpa_start + size;
    let mut cursor = hpa_start;

    for v in view {
        let v_start = v.start;
        let v_end = v.start + v.size;

        // Gap → remove blocked contribution.
        if cursor < v_start {
            let gap_size = v_start - cursor;
            let gap_gpa = gpa_base + (cursor - hpa_start);
            let gap_hpa = cursor;
            map.remove_contribution(gap_gpa, gap_hpa, gap_size, crate::memory::Rights::NONE, true)?;
            cursor = v_start;
        }

        // Visible range → remove mapped contribution.
        if cursor < v_end {
            let mapped_size = v_end - cursor;
            let mapped_gpa = gpa_base + (cursor - hpa_start);
            let mapped_hpa = cursor;
            map.remove_contribution(mapped_gpa, mapped_hpa, mapped_size, rights, false)?;
            cursor = v_end;
        }
    }

    // Trailing gap → remove blocked.
    if cursor < hpa_end {
        let gap_size = hpa_end - cursor;
        let gap_gpa = gpa_base + (cursor - hpa_start);
        let gap_hpa = cursor;
        map.remove_contribution(gap_gpa, gap_hpa, gap_size, crate::memory::Rights::NONE, true)?;
    }

    Ok(())
}

/// Read the cached address-space view for a domain.  Lazily recomputes
/// if the view is dirty.
pub fn compute_address_space(domain: &CapabilityRef<Domain>) -> AddressSpaceView {
    let mut w = domain.write();
    w.data.ensure_view_fresh();
    w.data.cached_view.clone()
}

// =============================================================================
// Domain-mediated high-level operations
// =============================================================================

/// Acquire two domain write locks in ascending `DomainId` order, then bind the
/// guards back to the caller's chosen names so the body reads naturally
/// regardless of which physical order was used.
///
/// Domain IDs are immutable post-creation, so reading `data.id` under
/// short-lived read locks before taking the write locks is safe.
///
/// Caller MUST pass two *distinct* domains (different `Arc` identity *and*
/// different `DomainId`).  Passing the same domain twice would deadlock
/// (`RwLock` is not reentrant).
///
/// This is the codebase-wide rule for any cross-domain mutation: see
/// `send_memory_unsealed`, `accept_capability`, `send_channel`, `accept_channel`.
macro_rules! lock_two_domains_ordered {
    (
        let ($a_guard:ident, $b_guard:ident) =
            ($a_ref:expr, $a_id:expr, $b_ref:expr, $b_id:expr);
    ) => {
        debug_assert!(
            $a_id != $b_id,
            "lock_two_domains_ordered: same DomainId — would deadlock"
        );
        let (mut $a_guard, mut $b_guard) = if $a_id < $b_id {
            let a_w = $a_ref.write();
            let b_w = $b_ref.write();
            (a_w, b_w)
        } else {
            let b_w = $b_ref.write();
            let a_w = $a_ref.write();
            (a_w, b_w)
        };
    };
}

impl Capability<Domain> {
    /// Carve a memory sub-region.  Returns `(LocalHandle, SubHandle, UpdateBatch)`.
    ///
    /// - `LocalHandle`: the caller's domain-table key for the new child.
    /// - `SubHandle`: the child's stable tree identity (auto-allocated from the
    ///   source region's counter).  Pass this to [`revoke`] to revoke the child
    ///   even after it has been sent to another domain.
    ///
    /// # Errors
    /// - [`CapaError::PermissionDenied`] — handle is frozen, source region has `META`/`COMM` attribute, or `CARVE` API not allowed.
    /// - [`CapaError::NotFound`] — `region` handle not found in caller's table.
    /// - [`CapaError::InvalidAccess`] — requested range or rights exceed source region.
    pub fn carve(
        caller: &CapabilityRef<Domain>,
        region: LocalHandle,
        access: Access,
    ) -> Result<(LocalHandle, SubHandle, UpdateBatch)> {
        // Single-lock discipline: validate + mutate atomically under caller.write().
        //
        // Why this is safe:
        //   - Every memory cap reachable via `caller.data.memory_capabilities[h]`
        //     has `cap.owned.owner == caller.id` by construction (invariant
        //     maintained at every transfer point).  So we don't need to fetch
        //     `owner_domain` and re-validate — the caller IS the owner.
        //   - `require_api` checks sealed + API on the caller's own policy,
        //     which we already hold under `w`.
        //   - Lock order: `caller.write()` → `region_ref.write()` (taken inside
        //     `carve_child`).  Per-region attribute checks (META/COMM) are also
        //     enforced inside carve_child as defence in depth; we do an early
        //     check here under region.read so that META/COMM rejection takes
        //     precedence over a stale-caller `DomainNotSealed` error.
        let mut w = caller.write();
        if w.data.is_memory_handle_frozen(region) {
            return Err(CapaError::PermissionDenied);
        }
        let owner_id = w.data.id;
        let region_ref = w
            .data
            .get_memory_capability(region)
            .ok_or(CapaError::NotFound)?
            .upgrade()
            .ok_or(CapaError::NotFound)?;

        // Early per-region rejection (error-precedence preservation).
        {
            let p = region_ref.read();
            if p.owned.attributes.meta() || p.owned.attributes.comm() {
                return Err(CapaError::PermissionDenied);
            }
        }

        w.data.require_api(MonitorAPI::CARVE)?;

        w.data.ensure_view_fresh();
        let view_before = w.data.cached_view.clone();

        // carve_child takes region_ref.write() and rejects META/COMM regions
        // under that same lock — see fold-in below.
        let child_ref = Capability::carve_child(&region_ref, access, owner_id)?;

        let same_rights;
        // Single write lock on child_ref: extract sub_handle, set owner, grab
        // footprint data.  Avoids 2 extra read-lock sync points that blow up
        // loom's interleaving space.
        let child_sub;
        #[cfg(feature = "address_translation")]
        let footprint: (u64, u64, Vec<Access>, crate::memory::Rights);
        {
            let mut cw = child_ref.write();
            child_sub = cw.sub_handle;
            cw.owned.owner_domain = Some(Arc::downgrade(caller));
            // Same-rights check, captured here while we already hold the child write.
            // Parent's rights == child's rights iff the carve preserved them — read
            // the parent rights briefly under read (lock order: child write held
            // is OK because parent is a *different* Arc — read while holding child
            // write is the same direction we already use in carve_child).
            let parent_rights = region_ref.read().data.access.rights;
            same_rights = access.rights == parent_rights;
            #[cfg(feature = "address_translation")]
            {
                footprint = (
                    cw.data.access.start,
                    cw.data.access.size,
                    cw.compute_view(),
                    cw.data.access.rights,
                );
            }
        }

        let new_handle = w.data.allocate_memory_handle();
        w.data
            .add_memory_capability(new_handle, Arc::downgrade(&child_ref));

        // Record the carved child's GPA and add its footprint (bumps refcounts
        // in the overlapping region with the parent).
        #[cfg(feature = "address_translation")]
        {
            let (child_hpa, child_size, child_view, child_rights) = footprint;
            let child_gpa = w.data.address_map.translate(child_hpa, child_size)
                .map(|(gpa, _, _)| gpa)
                .unwrap_or(child_hpa);
            let _ = add_footprint(
                &mut w.data.address_map,
                child_hpa,
                child_size,
                child_gpa,
                &child_view,
                child_rights,
            );
            w.data.mapped_gpas.insert(new_handle, child_gpa);
        }

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

            w.data.ensure_view_fresh();
            let view_after = w.data.cached_view.clone();
            let updates = view_diff(owner_id, &view_before, &view_after);
            updates
        };

        Ok((new_handle, child_sub, updates))
    }

    /// Alias a memory sub-region.  Returns `(LocalHandle, SubHandle)`.
    ///
    /// See [`carve`] for the meaning of each return value.
    /// Creates a read-only alias of `region` restricted to `access` in the caller's table.
    ///
    /// # Errors
    /// - [`CapaError::PermissionDenied`] — handle is frozen, source region has `META`/`COMM` attribute, or `ALIAS` API not allowed.
    /// - [`CapaError::NotFound`] — `region` handle not found in caller's table.
    /// - [`CapaError::InvalidAccess`] — requested range or rights exceed source region.
    pub fn alias(
        caller: &CapabilityRef<Domain>,
        region: LocalHandle,
        access: Access,
    ) -> Result<(LocalHandle, SubHandle)> {
        // Single-lock discipline (see carve for the full rationale): validate +
        // mutate atomically under caller.write(); per-region attribute checks
        // live in alias_child under region_ref.write(), with an early check
        // here to preserve error precedence.
        let mut w = caller.write();
        if w.data.is_memory_handle_frozen(region) {
            return Err(CapaError::PermissionDenied);
        }
        let owner_id = w.data.id;
        let region_ref = w
            .data
            .get_memory_capability(region)
            .ok_or(CapaError::NotFound)?
            .upgrade()
            .ok_or(CapaError::NotFound)?;
        {
            let p = region_ref.read();
            if p.owned.attributes.meta() || p.owned.attributes.comm() {
                return Err(CapaError::PermissionDenied);
            }
        }
        w.data.require_api(MonitorAPI::ALIAS)?;
        #[cfg(feature = "address_translation")]
        let parent_hpa_start: u64 = region_ref.read().data.access.start;

        let child_ref = Capability::alias_child(&region_ref, access, owner_id)?;

        // Single write lock on child_ref: extract sub_handle, set owner, grab
        // footprint data.  Same loom optimisation as carve().
        let child_sub;
        #[cfg(feature = "address_translation")]
        let footprint: (u64, u64, Vec<Access>, crate::memory::Rights);
        {
            let mut cw = child_ref.write();
            child_sub = cw.sub_handle;
            cw.owned.owner_domain = Some(Arc::downgrade(caller));
            #[cfg(feature = "address_translation")]
            {
                footprint = (
                    cw.data.access.start,
                    cw.data.access.size,
                    cw.compute_view(),
                    cw.data.access.rights,
                );
            }
        }

        let new_handle = w.data.allocate_memory_handle();
        w.data
            .add_memory_capability(new_handle, Arc::downgrade(&child_ref));

        // Add the alias's footprint to the address map (bumps refcounts in
        // the overlapping region) and record its GPA for future MAP_SELF.
        #[cfg(feature = "address_translation")]
        {
            let (alias_hpa, alias_size, alias_view, alias_rights) = footprint;
            // Alias's initial GPA = parent's GPA + offset within parent.
            let parent_gpa = w.data.mapped_gpas.get(&region).copied()
                .unwrap_or(parent_hpa_start);
            let alias_gpa = parent_gpa + (alias_hpa - parent_hpa_start);
            let _ = add_footprint(
                &mut w.data.address_map,
                alias_hpa,
                alias_size,
                alias_gpa,
                &alias_view,
                alias_rights,
            );
            w.data.mapped_gpas.insert(new_handle, alias_gpa);
        }

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
            // Note: checking Exclusive implicitly covers the Carve requirement —
            // only carved regions can be Exclusive (aliases are always Aliased).
            // Additionally, the region must be a leaf (no children): if a parent
            // with children were marked META (excluded from EPT), the children
            // would remain in the tree with inconsistent address-space semantics.
            if attrs.meta() && c.data.status != RegionStatus::Exclusive {
                return Err(CapaError::PermissionDenied);
            }
            if attrs.meta() && !c.children.is_empty() {
                return Err(CapaError::PermissionDenied);
            }
        }

        // Materialize META → META|CLEAN|VITAL so that revoke_subtree's existing
        // CLEAN and VITAL checks handle zeroing and domain revocation without
        // any META-specific branches there.
        let attrs = attrs.canonicalize();

        // COMM sends are only valid to unsealed receivers — they need
        // immediate EPT mapping (the unsealed path handles this).
        if recv_sealed && attrs.comm() {
            return Err(CapaError::PermissionDenied);
        }

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
        // Single-lock discipline: validate caller.require_api(SEND) + freeze
        // under caller.write().  By the dom↔cap invariant, every cap in
        // caller's table is owned by caller, so no owner_domain re-validation
        // is needed.  The receiver-side mutations (pending insertion) are
        // sequential — sealed sends do not need atomic two-domain mutation
        // because the receiver only observes the pending entry as an opaque
        // queue item.
        let cap_ref = {
            let mut caller_w = caller.write();
            caller_w.data.require_api(MonitorAPI::SEND)?;
            if caller_w.data.is_memory_handle_frozen(cap) {
                return Err(CapaError::PermissionDenied);
            }
            let cap_ref = caller_w
                .data
                .get_memory_capability(cap)
                .ok_or(CapaError::NotFound)?
                .upgrade()
                .ok_or(CapaError::NotFound)?;
            // RECEIVE_AFTER_SEAL check is a property of the receiver's policy;
            // takes a brief receiver read while we hold caller.write().  Lock
            // order: there is no rule requiring caller.write before receiver.read,
            // but no concurrent mutation can reorder the chain (parking_lot
            // read locks are non-recursive but compatible with writes on
            // unrelated locks).
            if !receiver_ref.read().data.policy.receive_after_seal() {
                return Err(CapaError::PermissionDenied);
            }
            caller_w.data.freeze_memory_handle(cap);
            cap_ref
        };

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
    /// Acquires both domain write locks in domain-ID order (ABBA-safe).  The
    /// ownership change and view refresh happen atomically under both locks.
    fn send_memory_unsealed(
        caller: &CapabilityRef<Domain>,
        cap: LocalHandle,
        receiver_ref: &CapabilityRef<Domain>,
        caller_id: DomainId,
        attrs: Attributes,
        _gpa_hint: Option<u64>,
    ) -> Result<UpdateBatch> {
        let receiver_id = receiver_ref.read().data.id;

        // Atomic acquisition of both domain write locks, ordered by DomainId.
        lock_two_domains_ordered! {
            let (caller_w, recv_w) = (caller, caller_id, receiver_ref, receiver_id);
        }

        // Validate caller-side permission + frozen state under the authoritative
        // write lock (no separate read-lock pre-flight — the dom↔cap invariant
        // makes the indirect validate_operation check redundant).
        caller_w.data.require_api(MonitorAPI::SEND)?;
        if caller_w.data.is_memory_handle_frozen(cap) {
            return Err(CapaError::PermissionDenied);
        }

        caller_w.data.ensure_view_fresh();
        let view_caller_before = caller_w.data.cached_view.clone();
        recv_w.data.ensure_view_fresh();
        let view_receiver_before = recv_w.data.cached_view.clone();

        let cap_weak = caller_w
            .data
            .remove_memory_capability(cap)
            .ok_or(CapaError::NotFound)?;

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
            recv_w.data.mapped_gpas.insert(new_handle, gpa_base);
        }

        // Snapshot views AFTER all mutations.
        caller_w.data.ensure_view_fresh();
        let view_caller_after = caller_w.data.cached_view.clone();
        recv_w.data.ensure_view_fresh();
        let view_receiver_after = recv_w.data.cached_view.clone();

        let mut updates = view_diff(caller_id, &view_caller_before, &view_caller_after);
        updates.merge(view_diff(
            receiver_id,
            &view_receiver_before,
            &view_receiver_after,
        ));

        drop(caller_w);
        drop(recv_w);

        // `attrs` is the value just written to cap; `meta_start/size` captured above.
        if attrs.meta() {
            updates.add_give_meta_mem(receiver_id, meta_start, meta_size);
        }

        // COMM send: tell the platform about the new COMM region so it can
        // accumulate HPAs for DomainComm initialisation at seal time.
        // domain_id = caller (parent), target_domain_id = receiver (child).
        // vp_id = u32::MAX signals domain-level COMM (not per-VP).
        if attrs.comm() {
            updates.add_comm_region(caller_id, receiver_id, u32::MAX, meta_start, meta_size);
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
        lock_two_domains_ordered! {
            let (recv_w, sender_w) =
                (receiver, receiver_id, &sender_ref, sender_id_peek);
        }

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
                recv_w.data.pending_capabilities.insert(
                    pending_id,
                    PendingCapability {
                        cap: Arc::downgrade(&cap_ref),
                        sender_domain_id,
                        sender_handle,
                        sender_domain: Arc::downgrade(&sender_ref),
                        #[cfg(feature = "address_translation")]
                        gpa_hint: orig_gpa_hint,
                    },
                );
                return Err(CapaError::RegionOverlap);
            }
        }

        // Check sender domain not revoked — revocation cancels pending transfers.
        if sender_w.data.is_revoked() {
            return Err(CapaError::PermissionDenied);
        }

        // Snapshot views BEFORE mutation.
        sender_w.data.ensure_view_fresh();
        let view_sender_before = sender_w.data.cached_view.clone();
        recv_w.data.ensure_view_fresh();
        let view_receiver_before = recv_w.data.cached_view.clone();

        let new_handle = recv_w.data.allocate_memory_handle();

        // Remove cap from sender's tables.
        sender_w.data.remove_memory_capability(sender_handle);
        sender_w.data.unfreeze_memory_handle(sender_handle);

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

        // Register in receiver's table.
        recv_w
            .data
            .add_memory_capability(new_handle, Arc::downgrade(&cap_ref));

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
            recv_w.data.mapped_gpas.insert(new_handle, gpa_base);
        }

        // Snapshot views AFTER all mutations.
        sender_w.data.ensure_view_fresh();
        let view_sender_after = sender_w.data.cached_view.clone();
        recv_w.data.ensure_view_fresh();
        let view_receiver_after = recv_w.data.cached_view.clone();

        let mut updates = view_diff(sender_domain_id, &view_sender_before, &view_sender_after);
        updates.merge(view_diff(
            receiver_id,
            &view_receiver_before,
            &view_receiver_after,
        ));

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

    // ── MAP_SELF (address_translation only) ─────────────────────────────────

    /// Remap a memory capability at a chosen GPA in the caller's own AddressMap.
    ///
    /// If the capability already has a dedicated AddressMap entry (e.g. a carved
    /// region with its own split entry, or a cap received via `accept`), that
    /// entry is removed and re-inserted at `new_gpa`.  If the capability has no
    /// dedicated entry (e.g. an alias whose HPA range is covered by the parent's
    /// mapping), a *new* entry is added without removing anything.
    ///
    /// The resulting [`UpdateBatch`] is computed by diffing the AddressMap
    /// before and after the remap.
    ///
    /// # Rules
    /// - Caller must be sealed and have [`MonitorAPI::MAP_SELF`] permission.
    /// - Handle must not be frozen.
    /// - META and COMM capabilities are rejected.
    /// Remap a sealed domain's own memory capability at a new GPA.
    ///
    /// Uses the refcounted contribution model:
    /// 1. `remove_footprint` at old GPA (decrements refcounts, preserving
    ///    parent/sibling contributions)
    /// 2. Overlap check at new GPA (after removal)
    /// 3. `add_footprint` at new GPA
    /// 4. Snapshot diff → UpdateBatch
    ///
    /// # Requirements
    /// - Caller must be sealed with `MAP_SELF` permission.
    /// - Handle must not be frozen, META, or COMM.
    /// - `new_gpa` must not overlap existing mapped/blocked segments (after
    ///   removing the cap's old footprint).
    ///
    /// # Errors
    /// - [`CapaError::DomainNotSealed`] — caller is not sealed.
    /// - [`CapaError::ApiNotAllowed`] — caller lacks `MAP_SELF` permission.
    /// - [`CapaError::PermissionDenied`] — handle is frozen, META/COMM cap,
    ///   or caller doesn't own the capability.
    /// - [`CapaError::NotFound`] — `cap_handle` not found or no recorded GPA.
    /// - [`CapaError::RegionOverlap`] — `new_gpa` overlaps remaining segments.
    #[cfg(feature = "address_translation")]
    pub fn map_self(
        caller: &CapabilityRef<Domain>,
        cap_handle: LocalHandle,
        new_gpa: u64,
    ) -> Result<UpdateBatch> {
        use crate::translation::address_map_diff;

        // Single-lock discipline: validate + mutate under caller.write().
        // Per-cap META/COMM check happens under cap_ref.read() inside the
        // write-locked region (cap_ref is a separate Arc — taking its read
        // while holding caller.write() does not introduce any new lock
        // edge: the established mutation order is caller.write → cap.write).
        let mut w = caller.write();
        w.data.require_api(MonitorAPI::MAP_SELF)?;
        if w.data.is_memory_handle_frozen(cap_handle) {
            return Err(CapaError::PermissionDenied);
        }
        let owner_id = w.data.id;
        let cap_ref = w
            .data
            .get_memory_capability(cap_handle)
            .ok_or(CapaError::NotFound)?
            .upgrade()
            .ok_or(CapaError::NotFound)?;

        // Read cap address info + rights + reject META/COMM.
        let (cap_hpa, cap_size, cap_view, cap_rights) = {
            let c = cap_ref.read();
            if c.owned.attributes.meta() || c.owned.attributes.comm() {
                return Err(CapaError::PermissionDenied);
            }
            (
                c.data.access.start,
                c.data.access.size,
                c.compute_view(),
                c.data.access.rights,
            )
        };

        // Look up where this cap's footprint currently lives.
        let old_gpa = *w
            .data
            .mapped_gpas
            .get(&cap_handle)
            .ok_or(CapaError::NotFound)?;

        // Snapshot AddressMap before.
        let snapshot_before = w.data.address_map.mapped_snapshot();

        // 1. Remove the cap's footprint at old GPA (refcounted — won't nuke
        //    parent/sibling contributions).
        remove_footprint(
            &mut w.data.address_map,
            cap_hpa,
            cap_size,
            old_gpa,
            &cap_view,
            cap_rights,
        )
        .map_err(|e| CapaError::InvalidOperation(alloc::string::String::from(e)))?;

        // 2. Check new_gpa doesn't overlap remaining segments.
        if w.data.address_map.overlaps(new_gpa, cap_size) {
            // Rollback: re-add at old position.
            let _ = add_footprint(
                &mut w.data.address_map,
                cap_hpa,
                cap_size,
                old_gpa,
                &cap_view,
                cap_rights,
            );
            return Err(CapaError::RegionOverlap);
        }

        // 3. Add the cap's footprint at new GPA.
        add_footprint(
            &mut w.data.address_map,
            cap_hpa,
            cap_size,
            new_gpa,
            &cap_view,
            cap_rights,
        )
        .map_err(|e| CapaError::InvalidOperation(alloc::string::String::from(e)))?;

        // 4. Update tracked GPA for this handle.
        w.data.mapped_gpas.insert(cap_handle, new_gpa);

        // 5. Snapshot after → diff → UpdateBatch.
        let snapshot_after = w.data.address_map.mapped_snapshot();
        let updates = address_map_diff(owner_id, &snapshot_before, &snapshot_after);

        Ok(updates)
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
        // Resolve chan/receiver Arcs and the receiver-sealed predicate under a
        // single short caller.read() — these reads are non-authoritative; the
        // authoritative checks happen under caller.write() below.
        let caller_id;
        let chan_ref: CapabilityRef<Domain>;
        let receiver_ref: CapabilityRef<Domain>;
        let receiver_id;
        let recv_sealed;
        {
            let r = caller.read();
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
            let rr = receiver_ref.read();
            receiver_id = rr.data.id;
            recv_sealed = rr.data.is_sealed();
        }

        // Only channels may be transferred — checked under chan.read().
        if !chan_ref.read().is_channel() {
            return Err(CapaError::PermissionDenied);
        }

        if recv_sealed {
            // ── Sealed receiver: freeze + enqueue pending ─────────────────
            //
            // Lock-order rule for channels: `chan.write` is never held while
            // any of `caller/recv/sender.write` is held.  This rule is required
            // by `revoke_domain_subtree`'s channel branch which holds `chan.write`
            // and then takes `(recv, sender)` ordered via the macro — if any
            // path took `chan.write` *while holding* `recv` or `sender`, we'd
            // have a classic ABBA.
            //
            // Consequence: chan mutations happen in a separate phase from the
            // two-domain table mutation.  A brief mid-state where the chan
            // attributes haven't been updated yet is acceptable — the only
            // observers are other send/accept_channel calls, which read the
            // chan independently.
            lock_two_domains_ordered! {
                let (caller_w, recv_w) =
                    (caller, caller_id, &receiver_ref, receiver_id);
            }

            // Authoritative checks under caller.write().
            caller_w.data.require_api(MonitorAPI::SEND)?;
            if caller_w.data.is_domain_handle_frozen(chan_handle) {
                return Err(CapaError::PermissionDenied);
            }
            if !recv_w.data.policy.receive_after_seal() {
                return Err(CapaError::PermissionDenied);
            }
            caller_w.data.freeze_domain_handle(chan_handle);

            // Pending insertion stays inside the atomic block so the freeze +
            // pending-insert pair is observed together (matters for accept/reject
            // races, which take recv.write to find pending entries).
            let pending = PendingDomainCapability {
                cap: Arc::downgrade(&chan_ref),
                sender_domain_id: caller_id,
                sender_handle: chan_handle,
                sender_domain: Arc::downgrade(caller),
            };
            recv_w.data.add_pending_domain_capability(pending);
            drop(caller_w);
            drop(recv_w);

            // Chan mutation in isolation (lock-order rule above).
            {
                let mut cw = chan_ref.write();
                cw.owned.attributes = attrs;
                cw.owned.pending_receiver = Some(Arc::downgrade(&receiver_ref));
            }
        } else {
            // ── Unsealed receiver: immediate ownership transfer ────────────
            //
            // Two-domain atomic block covers the table mutation only.  The chan
            // owner-update happens in a separate phase to honour the lock-order
            // rule (see sealed branch above).
            lock_two_domains_ordered! {
                let (caller_w, recv_w) =
                    (caller, caller_id, &receiver_ref, receiver_id);
            }

            caller_w.data.require_api(MonitorAPI::SEND)?;
            if caller_w.data.is_domain_handle_frozen(chan_handle) {
                return Err(CapaError::PermissionDenied);
            }

            caller_w.data.remove_domain_capability(chan_handle);
            let new_handle = recv_w.data.allocate_domain_handle();
            recv_w
                .data
                .add_domain_capability(new_handle, Arc::downgrade(&chan_ref));
            let _ = new_handle;
            drop(caller_w);
            drop(recv_w);

            // Chan owner mutation in isolation.
            {
                let mut cw = chan_ref.write();
                cw.owned.owner = receiver_id;
                cw.owned.owner_domain = Some(Arc::downgrade(&receiver_ref));
                cw.owned.attributes = attrs;
            }
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

        // Peek at the pending entry to learn sender's DomainId for ordered locking.
        // The actual commit (remove_from_pending) happens under both write locks below.
        let (sender_id_peek, sender_domain_weak) = {
            let r = receiver.read();
            let pending = r
                .data
                .pending_domain_capabilities
                .get(&pending_id)
                .ok_or(CapaError::NotFound)?;
            (pending.sender_domain_id, pending.sender_domain.clone())
        };
        let sender_ref = sender_domain_weak.upgrade().ok_or(CapaError::NotFound)?;

        // Acquire both domain write locks atomically (ABBA-safe by DomainId order)
        // so the remove-from-sender + add-to-receiver pair is observed atomically.
        // chan.write is taken AFTER releasing both — the lock-order rule for
        // channels is "chan.write never held with recv/sender.write"; see
        // send_channel for the rationale (deadlock avoidance with revoke).
        let (chan_ref, sender_handle);
        {
            lock_two_domains_ordered! {
                let (recv_w, sender_w) =
                    (receiver, receiver_id, &sender_ref, sender_id_peek);
            }

            // Atomically remove the pending entry (commit point).
            let pending = recv_w
                .data
                .pending_domain_capabilities
                .remove(&pending_id)
                .ok_or(CapaError::NotFound)?;
            chan_ref = pending.cap.upgrade().ok_or(CapaError::NotFound)?;
            sender_handle = pending.sender_handle;

            // Unfreeze sender's handle and remove it from sender's table.
            sender_w.data.unfreeze_domain_handle(sender_handle);
            sender_w.data.remove_domain_capability(sender_handle);

            // Allocate handle in receiver's table (atomic with pending removal
            // so concurrent readers never see the chan in neither table).
            let new_handle = recv_w.data.allocate_domain_handle();
            recv_w
                .data
                .add_domain_capability(new_handle, Arc::downgrade(&chan_ref));

            // Capture new_handle for the function return value before guards drop.
            let result_handle = new_handle;

            // Drop both domain writes BEFORE taking chan.write (lock-order rule).
            drop(recv_w);
            drop(sender_w);

            // Now safe to take chan.write standalone.
            {
                let mut cw = chan_ref.write();
                cw.owned.owner = receiver_id;
                cw.owned.owner_domain = Some(Arc::downgrade(receiver));
                cw.owned.pending_receiver = None;
            }

            return Ok(result_handle);
        }
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

    /// Revoke a direct child of the memory region capability identified by `child_sub`.
    ///
    /// `region` is the LocalHandle of the parent memory region in `caller`'s table.
    /// `child_sub` is the SubHandle returned by [`carve`] or [`alias`] when the
    /// child was created.  Because SubHandles are auto-allocated from the region's
    /// internal counter they are unique among siblings and stable across ownership
    /// transfers — so this call succeeds even after the child has been sent to
    /// another domain.
    ///
    /// # Errors
    /// - [`CapaError::PermissionDenied`] — `region` handle is frozen, or `REVOKE` API not allowed.
    /// - [`CapaError::NotFound`] — `region` handle or `child_sub` not found.
    pub fn revoke(
        caller: &CapabilityRef<Domain>,
        region: LocalHandle,
        child_sub: SubHandle,
    ) -> Result<UpdateBatch> {
        // Single-lock discipline: validate + mutate under caller.write().
        // Per the dom↔cap invariant, region looked up in caller's table is
        // owned by caller; the owner_domain indirection is redundant.
        let mut w = caller.write();
        w.data.require_api(MonitorAPI::REVOKE)?;
        if w.data.is_memory_handle_frozen(region) {
            return Err(CapaError::PermissionDenied);
        }
        let owner_id = w.data.id;
        #[cfg(not(feature = "address_translation"))]
        let _ = owner_id;
        let region_ref = w
            .data
            .get_memory_capability(region)
            .ok_or(CapaError::NotFound)?
            .upgrade()
            .ok_or(CapaError::NotFound)?;

        // revoke_child operates only on CapabilityRef<MemoryRegion> arcs
        // (independent of the domain lock) — no deadlock risk.
        #[allow(unused_mut)]
        let mut updates = Capability::revoke_child(&region_ref, child_sub)?;
        w.data.prune_stale_memory_capabilities();

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
        // Single-lock discipline: validate SEAL on the caller (the owner of
        // the child domain cap, by the dom↔cap invariant) and seal the child
        // under its own write lock.
        let cap_ref = {
            let r = caller.read();
            r.data.require_api(MonitorAPI::SEAL)?;
            r.data
                .get_domain_capability(cap)
                .ok_or(CapaError::NotFound)?
                .upgrade()
                .ok_or(CapaError::NotFound)?
        };
        if cap_ref.read().is_channel() {
            return Err(CapaError::ApiNotAllowed);
        }
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
    pub fn create(
        parent: &CapabilityRef<Domain>,
        policy: DomainPolicy,
    ) -> Result<(LocalHandle, UpdateBatch)> {
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

        // Pre-flight: validate SET on caller + resolve memory and child domain handles.
        {
            let r = caller.read();
            r.data.require_api(MonitorAPI::SET)?;
            if r.data.is_memory_handle_frozen(handle) {
                return Err(CapaError::PermissionDenied);
            }
            owner_id = r.data.id;

            cap_ref = r
                .data
                .get_memory_capability(handle)
                .ok_or(CapaError::NotFound)?
                .upgrade()
                .ok_or(CapaError::NotFound)?;
            child_ref = r
                .data
                .get_domain_capability(child_domain_handle)
                .ok_or(CapaError::NotFound)?
                .upgrade()
                .ok_or(CapaError::NotFound)?;
        }

        let child_domain_id: DomainId;

        // Validate cap shape: must be Carve, Exclusive, leaf, not META/COMM already.
        // (Ownership-by-caller is implied by reaching cap_ref through caller's table.)
        {
            let c = cap_ref.read();
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
        }

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
    /// Create a channel pointing back to the caller itself.
    ///
    /// This is used when a domain wants to receive capabilities from its
    /// children.  The caller gets a channel that, when sent to a child,
    /// lets the child send capabilities back to the caller via the channel.
    ///
    /// Same semantics as [`get_chan`] but the caller IS the target.
    pub fn get_chan_self(caller: &CapabilityRef<Domain>) -> Result<LocalHandle> {
        let caller_id = caller.read().data.id;

        // 1. Caller must be sealed.
        if !caller.read().data.is_sealed() {
            return Err(CapaError::DomainNotSealed);
        }

        // 2. Check GETCHAN permission on the caller's policy directly.
        if !caller.read().data.policy.api.has(MonitorAPI::GETCHAN) {
            return Err(CapaError::ApiNotAllowed);
        }

        // 3. Allocate a SubHandle and depth from the caller's CDT node.
        let (sub_handle, chan_depth) = {
            let mut c = caller.write();
            let s = c.next_child_sub;
            c.next_child_sub += 1;
            (s, c.depth + 1)
        };

        // 4. Build the channel capability (target = caller).
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
            channel_target: Some(Arc::downgrade(caller)),
            parent: Arc::downgrade(caller),
            children: Vec::new(),
            next_child_sub: 1,
        }));

        // 5. Register channel as a child of caller in the CDT.
        caller.write().add_child(chan_ref.clone());

        // 6. Register in caller's domain capability table and return handle.
        let chan_handle = {
            let mut cw = caller.write();
            let h = cw.data.allocate_domain_handle();
            cw.data.add_domain_capability(h, Arc::downgrade(&chan_ref));
            h
        };

        Ok(chan_handle)
    }

    pub fn get_chan(
        caller: &CapabilityRef<Domain>,
        target_handle: LocalHandle,
    ) -> Result<LocalHandle> {
        // Validate GETCHAN on caller + resolve target Arc under one caller.read().
        // By the dom↔cap invariant, target_ref looked up in caller's table is
        // owned by caller, so the indirect validate_operation is equivalent
        // to require_api on the caller itself.
        let caller_id;
        let target_ref: CapabilityRef<Domain>;
        {
            let r = caller.read();
            r.data.require_api(MonitorAPI::GETCHAN)?;
            caller_id = r.data.id;
            target_ref = r
                .data
                .get_domain_capability(target_handle)
                .ok_or(CapaError::NotFound)?
                .upgrade()
                .ok_or(CapaError::NotFound)?;
        }

        // Target must be sealed (channels are only meaningful for live domains).
        if !target_ref.read().data.is_sealed() {
            return Err(CapaError::DomainNotSealed);
        }

        // Allocate a SubHandle and depth from the target's CDT node.
        let (sub_handle, chan_depth) = {
            let mut t = target_ref.write();
            let s = t.next_child_sub;
            t.next_child_sub += 1;
            (s, t.depth + 1)
        };

        // Build the channel capability.
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

        // Register channel as a child of target in the CDT.
        target_ref.write().add_child(chan_ref.clone());

        // Register in caller's domain capability table and return handle.
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

        // Switch participates in the engine's shared capability lock so it
        // serializes against destructive operations (ChangeRights /
        // RevokeDomain) which take the exclusive lock via `execute`. Without
        // this, a switch INTO a domain D can race with a concurrent
        // ChangeRights ON D: D's EPT is mutated while this core's VMENTER
        // walks the EPT into a fresh TLB, with no INVEPT directed at this
        // core (the initiator's `domain_cores(D)` snapshot taken before our
        // `set_core_context` finishes does not include us). The empty
        // UpdateBatch skips the cross-core IPI/barrier path and only takes
        // the shared cap lock — exactly the synchronisation we need.
        let (ctx, _batch) = crate::platform::execute(platform, false, || {
            let ctx = if to_handle == 0 {
                Self::switch_domain_return(caller, core_id, platform, None)?
            } else {
                Self::switch_domain_forward(caller, to_handle, to_vp_id, core_id, platform)?
            };
            Ok((ctx, UpdateBatch::new()))
        })?;
        Ok(ctx)
    }

    /// Return switch that records a non-interrupt exit reason on the caller VP.
    ///
    /// Used by the capavisor's `forward_child_exit` path: the child VP transitions
    /// to `Available { last_exit_reason }` so that the subsequent `register_access_check`
    /// on the resume path can look up the correct `ExitPolicy` write_set.
    pub fn switch_return_with_exit(
        caller: &CapabilityRef<Domain>,
        exit_reason: u32,
        platform: &dyn Platform,
    ) -> Result<SwitchContext> {
        let core_id = platform
            .get_current_core()
            .ok_or_else(|| CapaError::InvalidOperation("current core unknown".to_string()))?;
        // See comment on `switch`: the empty-batch `execute` here serialises
        // the return-path `set_core_context` against destructive engine ops.
        let (ctx, _batch) = crate::platform::execute(platform, false, || {
            let ctx = Self::switch_domain_return(caller, core_id, platform, Some(exit_reason))?;
            Ok((ctx, UpdateBatch::new()))
        })?;
        Ok(ctx)
    }

    /// Return path: unwind the VP call chain one step.
    ///
    /// Transitions:
    /// - Caller VP: `Running → Available { last_exit_reason }`
    /// - Previous (Locked) VP: `Locked → Running { core, caller: prev_prev_caller }`
    fn switch_domain_return(
        caller: &CapabilityRef<Domain>,
        core_id: CoreId,
        platform: &dyn Platform,
        exit_reason: Option<u32>,
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
        *caller_vp_arc.run_state.write() = VpRunState::Available {
            last_exit_reason: exit_reason,
        };

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
                VpRunState::Available { .. } | VpRunState::Suspended { .. } => {}
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
                        *s = VpRunState::Available {
                            last_exit_reason: None,
                        };
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
            *chain[0].2.run_state.write() = VpRunState::Available {
                last_exit_reason: None,
            };
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
    ) -> Result<UpdateBatch> {
        use crate::update::PolicyChange;

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

        let child_id = child_w.data.id;
        let mut batch = UpdateBatch::new();

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
                batch.add_policy_changed(child_id, PolicyChange::Cores(value));
            }
            PolicyIdentifier::ApiMonitor => {
                let bits = value as u16;
                if (bits & !parent_policy.api.bits()) != 0 {
                    return Err(CapaError::MonotonicityViolation);
                }
                child_w.data.policy.api = MonitorAPI::from_bits(bits);
                batch.add_policy_changed(child_id, PolicyChange::ApiMonitor(bits));
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
                batch.add_policy_changed(
                    child_id,
                    PolicyChange::InterruptDefaultVisibility(vis),
                );
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
                let snapshot = entry.clone();
                batch.add_policy_changed(
                    child_id,
                    PolicyChange::VectorVisibility { vector: vec, policy: snapshot },
                );
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
                batch.add_policy_changed(
                    child_id,
                    PolicyChange::VectorRegReadSet { vector: vec, word, bits: value },
                );
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
                batch.add_policy_changed(
                    child_id,
                    PolicyChange::VectorRegWriteSet { vector: vec, word, bits: value },
                );
            }
            PolicyIdentifier::DefaultExitTrap => {
                let trap = value != 0;
                // Monotonicity: child cannot un-trap if parent traps by default.
                if !trap && parent_policy.exits.default.trap {
                    return Err(CapaError::MonotonicityViolation);
                }
                child_w.data.policy.exits.default.trap = trap;
                batch.add_policy_changed(child_id, PolicyChange::DefaultExitTrap(trap));
            }
            PolicyIdentifier::ExitReasonTrap(reason) => {
                let trap = value != 0;
                // Monotonicity: child cannot un-trap an exit that the parent traps.
                let parent_effective = parent_policy.exits.get_action(reason);
                if !trap && parent_effective.trap {
                    return Err(CapaError::MonotonicityViolation);
                }
                let default_trap = child_w.data.policy.exits.default.trap;
                let entry = child_w
                    .data
                    .policy
                    .exits
                    .overrides
                    .entry(reason)
                    .or_insert_with(|| ExitAction {
                        trap: default_trap,
                        read_set: RegBitmap::ALL,
                        write_set: RegBitmap::ALL,
                    });
                entry.trap = trap;
                let snapshot = entry.clone();
                batch.add_policy_changed(
                    child_id,
                    PolicyChange::ExitReason { reason, action: snapshot },
                );
            }
            PolicyIdentifier::ExitReasonRegReadSet(reason, word) => {
                let default_trap = child_w.data.policy.exits.default.trap;
                let entry = child_w
                    .data
                    .policy
                    .exits
                    .overrides
                    .entry(reason)
                    .or_insert_with(|| ExitAction {
                        trap: default_trap,
                        read_set: RegBitmap::ALL,
                        write_set: RegBitmap::ALL,
                    });
                entry.read_set.set_word(word as usize, value);
                batch.add_policy_changed(
                    child_id,
                    PolicyChange::ExitReasonRegReadSet { reason, word, bits: value },
                );
            }
            PolicyIdentifier::ExitReasonRegWriteSet(reason, word) => {
                let default_trap = child_w.data.policy.exits.default.trap;
                let entry = child_w
                    .data
                    .policy
                    .exits
                    .overrides
                    .entry(reason)
                    .or_insert_with(|| ExitAction {
                        trap: default_trap,
                        read_set: RegBitmap::ALL,
                        write_set: RegBitmap::ALL,
                    });
                entry.write_set.set_word(word as usize, value);
                batch.add_policy_changed(
                    child_id,
                    PolicyChange::ExitReasonRegWriteSet { reason, word, bits: value },
                );
            }

            // ── Processor feature interposition policy ──

            PolicyIdentifier::ProcFeatureDefault(rk) => {
                let default = crate::interposition::DefaultAction::from_u8(value as u8)
                    .ok_or(CapaError::InvalidValue)?;
                match rk {
                    ResourceKind::Cpuid => {
                        child_w.data.policy.cpuid.default = default;
                        batch.add_policy_changed(
                            child_id,
                            PolicyChange::CpuidDefault(default),
                        );
                    }
                    ResourceKind::Msr => {
                        child_w.data.policy.msrs.default = default;
                        batch.add_policy_changed(
                            child_id,
                            PolicyChange::MsrDefault(default),
                        );
                        // The MsrDefault delta sets the bitmap background
                        // but clobbers existing override bits on the
                        // platform side (the platform applies updates
                        // incrementally from the live engine state — see
                        // PolicyChange docs). Re-emit each existing
                        // override so the bitmap converges to the full
                        // current policy without requiring the platform
                        // to re-read the engine.
                        for rule in &child_w.data.policy.msrs.overrides {
                            let (start, end) = match rule {
                                crate::interposition::ProcFeaturePolicy::Trap(r)
                                | crate::interposition::ProcFeaturePolicy::Native(r)
                                | crate::interposition::ProcFeaturePolicy::Emulate(r, _) => *r,
                            };
                            let action = match rule {
                                crate::interposition::ProcFeaturePolicy::Trap(_) => {
                                    crate::interposition::DefaultAction::Trap
                                }
                                crate::interposition::ProcFeaturePolicy::Native(_) => {
                                    crate::interposition::DefaultAction::Native
                                }
                                crate::interposition::ProcFeaturePolicy::Emulate(_, _) => {
                                    // Emulate ⇒ trap (engine consumes the
                                    // exit and returns/discards the stored
                                    // value); from a bitmap perspective
                                    // Emulate is equivalent to Trap.
                                    crate::interposition::DefaultAction::Trap
                                }
                            };
                            batch.add_policy_changed(
                                child_id,
                                PolicyChange::MsrRange { start, end, action },
                            );
                        }
                    }
                }
            }
            PolicyIdentifier::ProcFeatureRange(rk, start, start_sub, end, end_sub) => {
                let action = crate::interposition::DefaultAction::from_u8(value as u8)
                    .ok_or(CapaError::InvalidValue)?;
                let result = match rk {
                    ResourceKind::Cpuid => {
                        child_w.data.policy.cpuid.insert_range(
                            ((start, start_sub), (end, end_sub)), action,
                        )
                    }
                    ResourceKind::Msr => {
                        child_w.data.policy.msrs.insert_range((start, end), action)
                    }
                };
                result.map_err(|e| match e {
                    crate::interposition::InsertError::Overlap => CapaError::RegionOverlap,
                    crate::interposition::InsertError::InvalidRange => CapaError::InvalidValue,
                    crate::interposition::InsertError::NotFound => CapaError::NotFound,
                })?;
                match rk {
                    ResourceKind::Cpuid => batch.add_policy_changed(
                        child_id,
                        PolicyChange::CpuidRange {
                            start_leaf: start, start_sub, end_leaf: end, end_sub, action,
                        },
                    ),
                    ResourceKind::Msr => batch.add_policy_changed(
                        child_id,
                        PolicyChange::MsrRange { start, end, action },
                    ),
                }
            }
            PolicyIdentifier::ProcFeatureEmulate(rk, key32, sub_key32, word) => {
                match rk {
                    ResourceKind::Cpuid => {
                        cpuid_set_emulate_word(
                            &mut child_w.data.policy.cpuid,
                            key32,
                            sub_key32,
                            word,
                            value,
                        )?;
                        batch.add_policy_changed(
                            child_id,
                            PolicyChange::CpuidEmulate {
                                leaf: key32,
                                subleaf: sub_key32,
                                word_index: word,
                                value: value as u32,
                            },
                        );
                    }
                    ResourceKind::Msr => {
                        msr_set_emulate_word(
                            &mut child_w.data.policy.msrs,
                            key32,
                            word,
                            value,
                        )?;
                        batch.add_policy_changed(
                            child_id,
                            PolicyChange::MsrEmulate {
                                msr: key32,
                                word_index: word,
                                value: value as u32,
                            },
                        );
                    }
                }
            }
        }

        Ok(batch)
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
            PolicyIdentifier::VectorRegReadSet(vec, word) => child_r
                .data
                .policy
                .interrupts
                .get_policy(vec)
                .read_set
                .word(word as usize),
            PolicyIdentifier::VectorRegWriteSet(vec, word) => child_r
                .data
                .policy
                .interrupts
                .get_policy(vec)
                .write_set
                .word(word as usize),
            PolicyIdentifier::DefaultExitTrap => {
                if child_r.data.policy.exits.default.trap { 1 } else { 0 }
            }
            PolicyIdentifier::ExitReasonTrap(reason) => {
                if child_r.data.policy.exits.get_action(reason).trap { 1 } else { 0 }
            }
            PolicyIdentifier::ExitReasonRegReadSet(reason, word) => child_r
                .data
                .policy
                .exits
                .get_action(reason)
                .read_set
                .word(word as usize),
            PolicyIdentifier::ExitReasonRegWriteSet(reason, word) => child_r
                .data
                .policy
                .exits
                .get_action(reason)
                .write_set
                .word(word as usize),
            // ProcFeature policies are set-only for now; get returns the default.
            PolicyIdentifier::ProcFeatureDefault(rk) => {
                let default = match rk {
                    ResourceKind::Cpuid => child_r.data.policy.cpuid.default,
                    ResourceKind::Msr => child_r.data.policy.msrs.default,
                };
                default as u64
            }
            PolicyIdentifier::ProcFeatureRange(..)
            | PolicyIdentifier::ProcFeatureEmulate(..) => {
                return Err(CapaError::NotSupported);
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
    let run_state = vp.run_state.read();
    if matches!(*run_state, VpRunState::Running { .. }) {
        return Err(CapaError::RegisterAccessDenied);
    }

    // Select the correct policy source based on why the VP stopped.
    //
    // - Interrupted / Suspended: interrupt-caused exit → use InterruptPolicy
    //   for the vector that caused the preemption.
    // - Available with last_exit_reason: non-interrupt exit forwarded to parent
    //   → use ExitPolicy for that exit reason.
    // - Available without exit reason (fresh VP) or Locked: use InterruptPolicy
    //   default (VECTOR_AVAILABLE).
    let bitmap = match &*run_state {
        VpRunState::Interrupted { vector } | VpRunState::Suspended { vector, .. } => {
            let policy = child_r.data.policy.interrupts.get_policy(*vector);
            if want_read { policy.read_set } else { policy.write_set }
        }
        VpRunState::Available { last_exit_reason: Some(reason) } => {
            let action = child_r.data.policy.exits.get_action(*reason);
            if want_read { action.read_set } else { action.write_set }
        }
        _ => {
            // Fresh VP (no exit yet), or Locked VP — use VECTOR_AVAILABLE default.
            let policy = child_r.data.policy.interrupts.get_policy(VECTOR_AVAILABLE);
            if want_read { policy.read_set } else { policy.write_set }
        }
    };

    Ok((child_domain_id, bitmap))
}

// ── CPUID/MSR emulate word helpers ───────────────────────────────────────── //

use crate::interposition::{CpuidResult, CpuidPolicy, MsrPolicy, ProcFeaturePolicy};

/// Set one word of a CPUID emulate entry.
///
/// - word 0: `value = (eax << 32) | ebx`
/// - word 1: `value = (ecx << 32) | edx`
///
/// If no emulate entry exists for `(leaf, subleaf)`, word 0 creates it.
/// Word 1 then updates the existing entry.
fn cpuid_set_emulate_word(
    policy: &mut CpuidPolicy,
    leaf: u32,
    subleaf: u32,
    word: u8,
    value: u64,
) -> Result<()> {
    let key = (leaf, subleaf);
    match word {
        0 => {
            let hi = (value >> 32) as u32;
            let lo = value as u32;
            let result = CpuidResult { v0: hi, v1: lo, v2: 0, v3: 0 };
            // Try update first; if not found, insert new.
            if policy.update_emulate_value(&key, result.clone()).is_err() {
                policy.insert_emulate((key, key), result)
                    .map_err(|e| match e {
                        crate::interposition::InsertError::Overlap => CapaError::RegionOverlap,
                        crate::interposition::InsertError::InvalidRange => CapaError::InvalidValue,
                        crate::interposition::InsertError::NotFound => CapaError::NotFound,
                    })?;
            }
            Ok(())
        }
        1 => {
            let hi = (value >> 32) as u32;
            let lo = value as u32;
            // Must find existing entry (word 0 should have been set first).
            let idx = policy.overrides.iter().position(|rule| {
                if let ProcFeaturePolicy::Emulate(range, _) = rule {
                    key >= range.0 && key <= range.1
                } else {
                    false
                }
            }).ok_or(CapaError::NotFound)?;
            if let ProcFeaturePolicy::Emulate(_range, ref mut result) = policy.overrides[idx] {
                result.v2 = hi;
                result.v3 = lo;
            }
            Ok(())
        }
        _ => Err(CapaError::InvalidValue),
    }
}

/// Set one word of an MSR emulate entry.
///
/// - word 0: `value` = lower 32 bits of emulated MSR value
/// - word 1: `value` = upper 32 bits of emulated MSR value
///
/// Word 0 creates the entry; word 1 updates it.
fn msr_set_emulate_word(
    policy: &mut MsrPolicy,
    msr: u32,
    word: u8,
    value: u64,
) -> Result<()> {
    match word {
        0 => {
            let lo = value as u64;
            if policy.update_emulate_value(&msr, lo).is_err() {
                policy.insert_emulate((msr, msr), lo)
                    .map_err(|e| match e {
                        crate::interposition::InsertError::Overlap => CapaError::RegionOverlap,
                        crate::interposition::InsertError::InvalidRange => CapaError::InvalidValue,
                        crate::interposition::InsertError::NotFound => CapaError::NotFound,
                    })?;
            }
            Ok(())
        }
        1 => {
            let hi = value & 0xFFFF_FFFF;
            let idx = policy.overrides.iter().position(|rule| {
                if let ProcFeaturePolicy::Emulate(range, _) = rule {
                    range.0 <= msr && msr <= range.1
                } else {
                    false
                }
            }).ok_or(CapaError::NotFound)?;
            if let ProcFeaturePolicy::Emulate(_, ref mut val) = policy.overrides[idx] {
                // Keep lower 32 bits, set upper 32 bits.
                *val = (*val & 0xFFFF_FFFF) | (hi << 32);
            }
            Ok(())
        }
        _ => Err(CapaError::InvalidValue),
    }
}
