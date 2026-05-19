//! Address space view computation and diff generation.

use crate::capability::CapabilityRef;
use crate::memory::{Access, MemoryRegion, RegionKind, Rights};
use crate::update::{DomainId, UpdateBatch};
#[cfg(feature = "address_translation")]
use crate::translation::{AddressMap, MapEntry};
use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

/// A view region representing accessible memory for a domain.
///
/// When `address_translation` is enabled, `access.start` is the GPA and
/// `physical_start` is the backing HPA.  Without translation both are equal.
#[derive(Debug, Clone)]
pub struct ViewRegion {
    /// Memory access descriptor (address, size, rights).
    /// `start` is GPA when translated, HPA otherwise.
    pub access: Access,
    /// Backing physical address (HPA).  Equals `access.start` when no
    /// address translation is in use.
    pub physical_start: u64,
}

/// Sort by address (GPA/HPA) only; physical_start is secondary.
impl PartialEq for ViewRegion {
    fn eq(&self, other: &Self) -> bool {
        self.access == other.access && self.physical_start == other.physical_start
    }
}
impl Eq for ViewRegion {}

impl PartialOrd for ViewRegion {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ViewRegion {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.access
            .cmp(&other.access)
            .then(self.physical_start.cmp(&other.physical_start))
    }
}

impl ViewRegion {
    /// Create a view region where physical == virtual (identity / HPA mode).
    pub fn new(access: Access) -> Self {
        ViewRegion {
            physical_start: access.start,
            access,
        }
    }

    /// Create a view region with explicit physical backing (GPA mode).
    pub fn new_translated(access: Access, physical_start: u64) -> Self {
        ViewRegion {
            access,
            physical_start,
        }
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
    /// End of the physical backing range.
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
/// sub-intervals in a final pass (only if physically contiguous).
fn coalesce_regions(regions: &mut Vec<ViewRegion>) {
    // Collect all boundary points.
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

        // Union of rights from every region that fully covers [seg_start, seg_end).
        // Take physical_start from the first covering region.
        let mut combined: Option<Rights> = None;
        let mut phys: Option<u64> = None;
        for r in regions.iter() {
            if r.start() <= seg_start && r.end() >= seg_end {
                combined = Some(match combined {
                    None => r.rights(),
                    Some(e) => e.union(&r.rights()),
                });
                if phys.is_none() {
                    phys = Some(r.physical_start + (seg_start - r.start()));
                }
            }
        }
        if let Some(rights) = combined {
            let physical = phys.unwrap_or(seg_start);
            result.push(ViewRegion::new_translated(
                Access::new(seg_start, seg_end - seg_start, rights),
                physical,
            ));
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
///
/// When views are GPA-based (address_translation), the emitted `ChangeRights`
/// updates carry the correct `address` (GPA) and `physical` (HPA) fields
/// directly — no post-hoc fixup is needed.
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

        let before_rights = before_region.map(|r| r.rights());
        let after_rights = after_region.map(|r| r.rights());

        match (before_rights, after_rights) {
            (None, None) => {}
            (Some(_), None) => {
                let phys = before_region
                    .map(|r| r.physical_start + (seg_start - r.start()))
                    .unwrap_or(seg_start);
                updates.add_change_rights(domain_id, seg_start, seg_size, phys, Rights::NONE, true);
            }
            (None, Some(r)) => {
                let phys = after_region
                    .map(|r| r.physical_start + (seg_start - r.start()))
                    .unwrap_or(seg_start);
                updates.add_change_rights(domain_id, seg_start, seg_size, phys, r, false);
            }
            (Some(b), Some(a)) if b == a => {}
            (Some(b), Some(a)) => {
                let phys = after_region
                    .map(|r| r.physical_start + (seg_start - r.start()))
                    .unwrap_or(seg_start);
                if a.is_subset_of(&b) {
                    // Rights reduced.
                    updates.add_change_rights(domain_id, seg_start, seg_size, phys, a, true);
                } else {
                    // Rights expanded or changed — remap with new rights.
                    updates.add_change_rights(domain_id, seg_start, seg_size, phys, a, false);
                }
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

// ── GPA translation ───────────────────────────────────────────────────────

/// Translate an HPA-based view into a GPA-based view using the domain's
/// [`AddressMap`].
///
/// For each HPA view region, finds ALL matching `Mapped` entries in the
/// address map (handles double-maps: same HPA mapped at multiple GPAs).
/// The resulting view has `access.start` = GPA and `physical_start` = HPA.
///
/// HPA regions with no corresponding AddressMap entry are omitted (they
/// have no GPA translation → no EPT mapping).
#[cfg(feature = "address_translation")]
pub fn translate_view_to_gpa(
    hpa_view: &AddressSpaceView,
    map: &AddressMap,
) -> AddressSpaceView {
    let mut gpa_view = AddressSpaceView::new(hpa_view.domain_id);

    for region in &hpa_view.regions {
        let hpa_start = region.start();
        let hpa_end = region.end();
        let rights = region.rights();

        for entry in map.entries().values() {
            if let MapEntry::Mapped(m) = entry {
                let m_hpa_end = m.hpa_start + m.size;
                // Compute overlap of [hpa_start, hpa_end) and [m.hpa_start, m_hpa_end)
                let overlap_start = core::cmp::max(hpa_start, m.hpa_start);
                let overlap_end = core::cmp::min(hpa_end, m_hpa_end);
                if overlap_start < overlap_end {
                    let offset_in_entry = overlap_start - m.hpa_start;
                    let gpa_start = m.gpa_start + offset_in_entry;
                    let overlap_size = overlap_end - overlap_start;
                    gpa_view.add_region(ViewRegion::new_translated(
                        Access::new(gpa_start, overlap_size, rights),
                        overlap_start,
                    ));
                }
            }
        }
    }

    gpa_view.coalesce();
    gpa_view
}
