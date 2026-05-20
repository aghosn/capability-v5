//! Address space view computation and diff generation.

use crate::capability::CapabilityRef;
use crate::memory::{Access, MemoryRegion, RegionKind, Rights};
use crate::update::{DomainId, UpdateBatch};
use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

/// A view region representing accessible memory for a domain.
///
/// `access.start` is the GPA (what the domain sees).
/// `physical_start` is the HPA (backing physical address).
/// When no remap, `physical_start == access.start`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ViewRegion {
    /// Memory access descriptor (GPA address, size, rights)
    pub access: Access,
    /// Backing physical address (HPA). Equal to access.start when no remap.
    pub physical_start: u64,
}

impl ViewRegion {
    pub fn new(access: Access) -> Self {
        let physical_start = access.start;
        ViewRegion { access, physical_start }
    }

    pub fn start(&self) -> u64 {
        self.access.start
    }
    pub fn end(&self) -> u64 {
        self.access.end()
    }
    pub fn rights(&self) -> Rights {
        self.access.rights
    }
    pub fn size(&self) -> u64 {
        self.access.size
    }
    pub fn physical_end(&self) -> u64 {
        self.physical_start + self.access.size
    }
}

impl fmt::Display for ViewRegion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.access)
    }
}

/// Address space view for a domain
#[derive(Debug, Clone)]
pub struct AddressSpaceView {
    pub domain_id: u64,
    pub regions: Vec<ViewRegion>,
}

impl AddressSpaceView {
    pub fn new(domain_id: u64) -> Self {
        AddressSpaceView {
            domain_id,
            regions: Vec::new(),
        }
    }

    pub fn add_region(&mut self, region: ViewRegion) {
        self.regions.push(region);
        self.regions.sort();
    }

    /// Coalesce regions.
    ///
    /// Handles both adjacent regions (same rights) and *overlapping* regions
    /// (which arise when a domain owns two aliases with overlapping ranges).
    /// Overlapping segments are merged by taking the **union of rights**.
    pub fn coalesce(&mut self) {
        if self.regions.len() <= 1 {
            return;
        }
        coalesce_regions(&mut self.regions);
    }

    pub fn total_size(&self) -> u64 {
        self.regions.iter().map(|r| r.size()).sum()
    }

    pub fn is_accessible(&self, addr: u64) -> bool {
        self.regions
            .iter()
            .any(|r| addr >= r.start() && addr < r.end())
    }

    pub fn get_region_at(&self, addr: u64) -> Option<&ViewRegion> {
        self.regions
            .iter()
            .find(|r| addr >= r.start() && addr < r.end())
    }
}

impl fmt::Display for AddressSpaceView {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Address Space for Domain {}:", self.domain_id)?;
        writeln!(f, "Total accessible: {} bytes", self.total_size())?;
        writeln!(f, "Regions ({}):", self.regions.len())?;
        for (i, region) in self.regions.iter().enumerate() {
            writeln!(f, "  {}: {}", i, region)?;
        }
        Ok(())
    }
}

// ── Coalesce implementation ────────────────────────────────────────────────

/// Coalesce a sorted list of ViewRegions in-place.
///
/// Uses a sweep-line over all boundary points:
/// for each sub-interval between adjacent boundaries, compute the union of
/// rights from all regions that cover it.  Then merge adjacent same-rights
/// sub-intervals in a final pass.
fn coalesce_regions(regions: &mut Vec<ViewRegion>) {
    // Collect all boundary points (GPA-based).
    let mut points: Vec<u64> = Vec::new();
    for r in regions.iter() {
        points.push(r.start());
        points.push(r.end());
    }
    points.sort_unstable();
    points.dedup();

    let mut result: Vec<ViewRegion> = Vec::new();
    for w in points.windows(2) {
        let seg_start = w[0];
        let seg_end = w[1];
        let seg_size = seg_end - seg_start;

        // Union of rights from every region that fully covers [seg_start, seg_end).
        // Also recover the physical_start from the first covering region.
        let mut combined: Option<Rights> = None;
        let mut phys = seg_start; // default: identity
        for r in regions.iter() {
            if r.start() <= seg_start && r.end() >= seg_end {
                if combined.is_none() {
                    // Physical offset within the covering region.
                    phys = r.physical_start + (seg_start - r.start());
                }
                combined = Some(match combined {
                    None => r.rights(),
                    Some(e) => e.union(&r.rights()),
                });
            }
        }
        if let Some(rights) = combined {
            let mut vr = ViewRegion::new(Access::new(seg_start, seg_size, rights));
            vr.physical_start = phys;
            result.push(vr);
        }
    }

    // Merge adjacent sub-intervals with identical rights AND contiguous physical backing.
    if result.is_empty() {
        *regions = result;
        return;
    }
    let mut merged: Vec<ViewRegion> = Vec::new();
    let mut cur = result[0].clone();
    for next in result.into_iter().skip(1) {
        if cur.end() == next.start()
            && cur.rights() == next.rights()
            && cur.physical_end() == next.physical_start
        {
            cur.access.size += next.size();
        } else {
            merged.push(cur);
            cur = next;
        }
    }
    merged.push(cur);
    *regions = merged;
}

// ── compute_view_from_cap_arcs ─────────────────────────────────────────────

/// Core view computation from a list of capability Arcs.
/// Acquires read locks on each cap and its children.
/// Does NOT require a domain lock — caller is responsible for providing
/// a stable cap list (e.g. while holding the domain write lock).
pub fn compute_view_from_cap_arcs(
    domain_id: DomainId,
    cap_arcs: &[CapabilityRef<MemoryRegion>],
) -> AddressSpaceView {
    let mut view = AddressSpaceView::new(domain_id);
    if cap_arcs.is_empty() {
        return view;
    }

    // Sort by depth (ascending) so parents are processed before children.
    let mut sorted: Vec<CapabilityRef<MemoryRegion>> = cap_arcs.to_vec();
    sorted.sort_by_key(|c| c.read().depth);

    // Iterate, skipping dominated alias children.
    // The skip set holds Arc pointer addresses (usize) for caps to skip.
    let mut skip: BTreeSet<usize> = BTreeSet::new();

    for cap_arc in &sorted {
        let ptr = Arc::as_ptr(cap_arc) as usize;
        if skip.contains(&ptr) {
            continue;
        }

        let cap = cap_arc.read();

        // META regions are excluded from the address space.
        if cap.owned.attributes.meta() {
            continue;
        }

        // Mark alias children owned by this domain for skipping.
        for child_arc in &cap.children {
            let child = child_arc.read();
            if child.data.kind == RegionKind::Alias && child.owned.owner == domain_id {
                skip.insert(Arc::as_ptr(child_arc) as usize);
            }
        }

        // Contribution: cap's access minus all directly carved children.
        let mut contribution = alloc::vec![cap.data.access];
        for child_arc in &cap.children {
            let child = child_arc.read();
            if child.data.kind == RegionKind::Carve {
                contribution = subtract_access_list(contribution, child.data.access);
            }
        }

        for access in contribution {
            view.add_region(ViewRegion::new(access));
        }
    }

    view.coalesce();
    view
}

// ── view_diff ──────────────────────────────────────────────────────────────

/// Compute the `UpdateBatch` that reflects the diff from `before` to `after`
/// for `domain_id`.
///
/// Both views must be in canonical (coalesced, non-overlapping, sorted) form.
/// Uses a sweep-line over all boundary points from both views.
pub fn view_diff(
    domain_id: DomainId,
    before: &AddressSpaceView,
    after: &AddressSpaceView,
) -> UpdateBatch {
    let mut updates = UpdateBatch::new();

    let mut points: Vec<u64> = Vec::new();
    for r in &before.regions {
        points.push(r.start());
        points.push(r.end());
    }
    for r in &after.regions {
        points.push(r.start());
        points.push(r.end());
    }
    points.sort_unstable();
    points.dedup();

    for w in points.windows(2) {
        let seg_start = w[0];
        let seg_end = w[1];
        let seg_size = seg_end - seg_start;

        let before_region = before
            .regions
            .iter()
            .find(|r| r.start() <= seg_start && r.end() >= seg_end);
        let after_region = after
            .regions
            .iter()
            .find(|r| r.start() <= seg_start && r.end() >= seg_end);

        // Recover the physical address for this segment from the covering region.
        let phys_from = |r: &ViewRegion| r.physical_start + (seg_start - r.start());

        match (before_region, after_region) {
            (None, None) => {}
            (Some(_), None) => {
                updates.add_change_rights(domain_id, seg_start, seg_size, seg_start, Rights::NONE, true);
            }
            (None, Some(a)) => {
                updates.add_change_rights(domain_id, seg_start, seg_size, phys_from(a), a.rights(), false);
            }
            (Some(b), Some(a)) if b.rights() == a.rights() => {}
            (Some(_b), Some(a)) => {
                let shootdown = a.rights().is_subset_of(&_b.rights());
                updates.add_change_rights(domain_id, seg_start, seg_size, phys_from(a), a.rights(), shootdown);
            }
        }
    }

    updates
}

// ── helpers ────────────────────────────────────────────────────────────────

/// Compute the address-space view for a domain from a given list of capabilities.
///
/// This is a compatibility helper for tests that construct a capability list directly
/// rather than using a domain table.  Uses the same correct algorithm as
/// `compute_address_space`: depth-sort, subtract carved children, coalesce.
pub fn compute_view_from_capabilities(
    domain_id: DomainId,
    caps: &[CapabilityRef<MemoryRegion>],
) -> AddressSpaceView {
    let mut view = AddressSpaceView::new(domain_id);
    if caps.is_empty() {
        return view;
    }

    // Sort by depth ascending (parents before children).
    let mut sorted: Vec<&CapabilityRef<MemoryRegion>> = caps.iter().collect();
    sorted.sort_by_key(|c| c.read().depth);

    for cap_arc in &sorted {
        let cap = cap_arc.read();

        // META regions are excluded from the address space.
        if cap.owned.attributes.meta() {
            continue;
        }

        // Contribution: cap's access minus all directly carved children.
        let mut contribution = alloc::vec![cap.data.access];
        for child_arc in &cap.children {
            let child = child_arc.read();
            if child.data.kind == RegionKind::Carve {
                contribution = subtract_access_list(contribution, child.data.access);
            }
        }

        for access in contribution {
            view.add_region(ViewRegion::new(access));
        }
    }

    view.coalesce();
    view
}
pub(crate) fn subtract_access_list(regions: Vec<Access>, to_sub: Access) -> Vec<Access> {
    let mut result = Vec::new();
    for r in regions {
        if !r.overlaps(&to_sub) {
            result.push(r);
        } else {
            if r.start < to_sub.start {
                result.push(Access::new(r.start, to_sub.start - r.start, r.rights));
            }
            if r.end() > to_sub.end() {
                result.push(Access::new(to_sub.end(), r.end() - to_sub.end(), r.rights));
            }
        }
    }
    result
}
