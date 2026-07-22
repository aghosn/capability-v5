//! Core capability structures with thread-safe parent-child relationships

use crate::domain::{Domain, DomainPolicy, MonitorAPI, VpCallContext, VpRunState};
use crate::error::{CapaError, Result};
use crate::memory::{Access, Attributes, MemoryRegion, RegionKind};
use crate::sync::{no_arcs_past_here, RwLock};
use crate::update::{CoreSwitch, DomainId, UpdateBatch};
use crate::view::AddressSpaceView;
use alloc::string::String;
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
    /// Create a child domain capability under the parent.
    ///
    /// **Locking contract (explicit):** the caller must hold `parent`'s write
    /// lock; `parent_cap` is the inner value reborrowed from that guard
    /// (e.g. `&mut *parent.write()`). This function acquires no lock itself
    /// so the caller can keep the parent write held across surrounding work
    /// (e.g. `LocalHandle` allocate + insert in [`Capability::create`]).
    ///
    /// `parent` is also passed to obtain a `Weak` reference for the child's
    /// CDT back-pointer — there is no way to recover the surrounding `Arc`
    /// from `parent_cap` alone.
    pub fn create_child_domain(
        parent_cap: &mut Capability<Domain>,
        parent: &CapabilityRef<Domain>,
        policy: DomainPolicy,
        owner: DomainId,
    ) -> Result<CapabilityRef<Domain>> {
        parent_cap.data.require_api(MonitorAPI::CREATE)?;
        policy.is_subset_of(&parent_cap.data.policy)?;

        let child_domain = Domain::new(policy);

        // Auto-allocate a unique SubHandle from the parent's counter; capture depth too.
        let sub_handle = parent_cap.next_child_sub;
        parent_cap.next_child_sub += 1;
        let child_depth = parent_cap.depth + 1;

        let child = Capability::new_child(
            owner,
            sub_handle,
            child_depth,
            child_domain,
            Arc::downgrade(parent),
        );

        parent_cap.add_child(child.clone());

        Ok(child)
    }

    /// Walk the caller chain from the direct caller of a revoked Running VP
    /// up to the first non-revoked ancestor.  Returns the resume target
    /// `(target_domain_cap, target_vp_id)` — the ancestor VP that will
    /// receive control on the affected core when the initiator finishes
    /// applying updates.
    ///
    /// Preconditions:
    /// - `first_caller` is the `VpCallContext` taken from the revoked
    ///   `Running{ caller: Some(_) }` VP.
    /// - Each ancestor whose domain is revoked must have its VP in
    ///   `Locked{ prev_caller }` state (invariant maintained by
    ///   `Capability::switch` when the callee is entered).
    ///
    /// Returns [`CapaError::NotFound`] if the chain terminates without
    /// reaching a non-revoked ancestor (D1 violation — should not happen
    /// under the "root is unrevokable" invariant).
    fn walk_revoke_caller_chain(
        first_caller: VpCallContext,
    ) -> Result<(CapabilityRef<Domain>, u64)> {
        let mut ctx = Some(first_caller);
        while let Some(c) = ctx {
            let cap = c.domain.upgrade().ok_or(CapaError::NotFound)?;

            // If this ancestor is not revoked, it is our resume target.
            no_arcs_past_here!({
                let guard = cap.read();
                if !guard.data.is_revoked() {
                    return Ok((cap.clone(), c.vp_id));
                }
            });

            // Ancestor is revoked — step to its own caller via the Locked VP.
            let ancestor_vp = no_arcs_past_here!({
                let guard = cap.read();
                guard
                    .data
                    .policy
                    .vprocessor_states
                    .iter()
                    .find(|v| v.id == c.vp_id)
                    .cloned()
                    .ok_or(CapaError::NotFound)?
            });
            let rs = ancestor_vp.run_state.read();
            ctx = match &*rs {
                VpRunState::Locked { prev_caller, .. } => prev_caller.clone(),
                VpRunState::Suspended { .. } => {
                    // Suspended = interrupt preempted a switch; treat prev
                    // context as chain-root (there's no further caller to
                    // walk to for revocation return).  Fail so the caller
                    // sees an engine invariant violation rather than
                    // silently attaching to the wrong VP.
                    return Err(CapaError::InvalidValue);
                }
                _ => return Err(CapaError::InvalidValue),
            };
        }
        Err(CapaError::NotFound)
    }

    fn validate_revoke_domain_subtree(domain_ref: &CapabilityRef<Domain>) -> Result<()> {
        let children = no_arcs_past_here!({
            let domain = domain_ref.read();
            for vp in &domain.data.policy.vprocessor_states {
                if matches!(
                    *vp.run_state.read(),
                    VpRunState::Running { caller: None, .. }
                ) {
                    return Err(CapaError::InvalidOperation(
                        String::from("revoked running VP has no caller"),
                    ));
                }
            }
            domain.children.clone()
        });

        for child in children {
            Self::validate_revoke_domain_subtree(&child)?;
        }
        Ok(())
    }

    /// Revoke a child domain and all its descendants by SubHandle
    ///
    /// Internal implementation called by [`revoke_domain`].
    pub(crate) fn revoke_child_domain(
        parent_ref: &CapabilityRef<Domain>,
        child_sub: SubHandle,
    ) -> Result<UpdateBatch> {
        let (parent_id, child_ref) = no_arcs_past_here!({
            let parent = parent_ref.read();
            parent.data.require_api(MonitorAPI::REVOKE)?;
            let child = parent
                .children
                .iter()
                .find(|child| child.read().sub_handle == child_sub)
                .cloned()
                .ok_or(CapaError::NotFound)?;
            (parent.data.id, child)
        });

        Self::validate_revoke_domain_subtree(&child_ref)?;

        parent_ref
            .write()
            .remove_child(child_sub)
            .ok_or(CapaError::NotFound)?;

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
        let mut updates = UpdateBatch::new();

        let (children, mem_weak_refs, domain_id, running_vps) = no_arcs_past_here!({
            let mut domain = domain_ref.write();

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

            // Snapshot Running VPs so we can walk their caller chains after
            // releasing the domain lock (the walk touches ancestor domains).
            //
            // Each `Running { core, caller: Some(ctx) }` VP produces one
            // `CoreSwitch` naming the resume target — the first non-revoked
            // ancestor of the doomed VP in its caller chain.  Descendant
            // revocations (children of this domain) contribute additional
            // switches at their own recursion levels via `updates.merge`
            // below.  Because this level marks `domain.data.revoke()` before
            // recursing, ancestor-of-a-child walks correctly see this domain
            // as revoked and skip past it.
            let running_vps: Vec<(crate::update::CoreId, u64, VpCallContext)> = domain
                .data
                .policy
                .vprocessor_states
                .iter()
                .filter_map(|vp| {
                    let rs = vp.run_state.read();
                    if let VpRunState::Running { core, caller: Some(ctx) } = &*rs {
                        Some((*core, vp.id, ctx.clone()))
                    } else {
                        None
                    }
                })
                .collect();

            (children, mem_weak_refs, domain_id, running_vps)
        });

        for (core, source_vp, first_caller) in running_vps {
            let (target_domain, target_vp) = Self::walk_revoke_caller_chain(first_caller)?;
            updates.add_core_switch(CoreSwitch {
                core,
                source_domain: domain_ref.clone(),
                source_vp,
                target_domain,
                target_vp,
            });
        }

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

        let (comm_bindings, revoked_domain_id) = no_arcs_past_here!({
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

            (comm_bindings, revoked_domain_id)
        });

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
pub(crate) fn insert_view_aware(
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
pub(crate) fn add_footprint(
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
pub(crate) fn remove_footprint(
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
