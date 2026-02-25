//! Address space visualization and memory view computation

use crate::capability::CapabilityRef;
use crate::domain::Domain;
use crate::memory::{Access, MemoryRegion, Rights};
use alloc::vec::Vec;
use core::fmt;

/// A view region representing accessible memory for a domain
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ViewRegion {
    /// Memory access descriptor (address, size, rights)
    pub access: Access,
}

impl ViewRegion {
    pub fn new(access: Access) -> Self {
        ViewRegion { access }
    }

    /// Get the start address
    pub fn start(&self) -> u64 {
        self.access.start
    }

    /// Get the end address (exclusive)
    pub fn end(&self) -> u64 {
        self.access.end()
    }

    /// Get access rights
    pub fn rights(&self) -> Rights {
        self.access.rights
    }

    /// Get size
    pub fn size(&self) -> u64 {
        self.access.size
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
    /// Domain ID
    pub domain_id: u64,
    /// Sorted list of accessible regions
    pub regions: Vec<ViewRegion>,
}

impl AddressSpaceView {
    pub fn new(domain_id: u64) -> Self {
        AddressSpaceView {
            domain_id,
            regions: Vec::new(),
        }
    }

    /// Add a region to the view
    pub fn add_region(&mut self, region: ViewRegion) {
        self.regions.push(region);
        self.regions.sort();
    }

    /// Coalesce adjacent regions with same rights
    pub fn coalesce(&mut self) {
        if self.regions.len() <= 1 {
            return;
        }

        let mut coalesced = Vec::new();
        let mut current = self.regions[0].clone();

        for next in self.regions.iter().skip(1) {
            // Check if regions can be coalesced
            if current.end() == next.start() && current.rights() == next.rights() {
                // Extend current region
                let new_size = current.access.size + next.access.size;
                current.access.size = new_size;
            } else {
                // Cannot coalesce, save current and move to next
                coalesced.push(current);
                current = next.clone();
            }
        }
        coalesced.push(current);
        self.regions = coalesced;
    }

    /// Get total accessible memory size
    pub fn total_size(&self) -> u64 {
        self.regions.iter().map(|r| r.access.size).sum()
    }

    /// Check if an address is accessible
    pub fn is_accessible(&self, addr: u64) -> bool {
        self.regions
            .iter()
            .any(|r| addr >= r.start() && addr < r.end())
    }

    /// Get the region containing an address (if any)
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

/// Compute the address space view for a domain
/// This walks all memory capabilities owned by the domain
pub fn compute_address_space(domain_ref: &CapabilityRef<Domain>) -> AddressSpaceView {
    let domain = domain_ref.read();
    let mut view = AddressSpaceView::new(domain.data.id);

    // Collect all memory capabilities owned by this domain
    for (_handle, weak_ref) in &domain.data.memory_capabilities {
        if let Some(mem_ref) = weak_ref.upgrade() {
            add_capability_to_view(&mut view, &mem_ref);
        }
    }

    view.coalesce();
    view
}

/// Compute view from explicitly provided memory capabilities
/// This function trusts that the caller has provided the correct set of capabilities
/// for the domain, so it doesn't filter by ownership
pub fn compute_view_from_capabilities(
    domain_id: u64,
    memory_caps: &[CapabilityRef<MemoryRegion>],
) -> AddressSpaceView {
    let mut view = AddressSpaceView::new(domain_id);

    for mem_ref in memory_caps {
        add_capability_to_view_no_filter(&mut view, mem_ref);
    }

    view.coalesce();
    view
}

/// Add capability to view without ownership filtering
/// Used when the caller explicitly provides the capabilities to include
fn add_capability_to_view_no_filter(view: &mut AddressSpaceView, mem_ref: &CapabilityRef<MemoryRegion>) {
    let mem = mem_ref.read();

    // Use compute_view() to get the actual accessible regions
    // This subtracts carved children that were sent to other domains
    let accessible_regions = mem.compute_view();
    for access in accessible_regions {
        let region = ViewRegion::new(access);
        view.add_region(region);
    }

    // Process children
    for child_ref in &mem.children {
        add_capability_to_view_no_filter(view, child_ref);
    }
}

/// Recursively add a memory capability and its accessible children to the view
fn add_capability_to_view(view: &mut AddressSpaceView, mem_ref: &CapabilityRef<MemoryRegion>) {
    let mem = mem_ref.read();

    // IMPORTANT: Only add regions that are actually accessible by this domain
    // For carved children sent to other domains, they should NOT appear in the parent's view

    // Check if this capability is owned by the domain we're viewing
    if mem.owned.owner == view.domain_id {
        // Use compute_view() to get the actual accessible regions
        // This subtracts carved children that were sent to other domains
        let accessible_regions = mem.compute_view();
        for access in accessible_regions {
            let region = ViewRegion::new(access);
            view.add_region(region);
        }
    }

    // Process children - they may be owned by this domain even if parent isn't
    for child_ref in &mem.children {
        add_capability_to_view(view, child_ref);
    }
}