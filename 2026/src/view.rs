//! Address space visualization and memory view computation

use crate::capability::{CapabilityRef, CapabilityWeak};
use crate::domain::Domain;
use crate::memory::{Access, MemoryRegion, Remapped, Rights};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// A view region representing accessible memory for a domain
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ViewRegion {
    /// Virtual address and access rights
    pub access: Access,
    /// Physical mapping (identity or remapped)
    pub remap: Remapped,
}

impl ViewRegion {
    pub fn new(access: Access, remap: Remapped) -> Self {
        ViewRegion { access, remap }
    }

    /// Get the virtual start address
    pub fn virt_start(&self) -> u64 {
        self.access.start
    }

    /// Get the virtual end address
    pub fn virt_end(&self) -> u64 {
        self.access.end()
    }

    /// Get the physical start address
    pub fn phys_start(&self) -> u64 {
        match self.remap {
            Remapped::Identity => self.access.start,
            Remapped::Remapped(addr) => addr,
        }
    }

    /// Get the physical end address
    pub fn phys_end(&self) -> u64 {
        match self.remap {
            Remapped::Identity => self.access.end(),
            Remapped::Remapped(addr) => addr + self.access.size,
        }
    }

    /// Get access rights
    pub fn rights(&self) -> Rights {
        self.access.rights
    }
}

impl fmt::Display for ViewRegion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[{:#x}..{:#x}] -> [{:#x}..{:#x}] {}",
            self.virt_start(),
            self.virt_end(),
            self.phys_start(),
            self.phys_end(),
            self.access.rights
        )
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

    /// Coalesce adjacent regions with same rights and contiguous mappings
    pub fn coalesce(&mut self) {
        if self.regions.len() <= 1 {
            return;
        }

        let mut coalesced = Vec::new();
        let mut current = self.regions[0].clone();

        for next in self.regions.iter().skip(1) {
            // Check if regions can be coalesced
            if current.virt_end() == next.virt_start()
                && current.phys_end() == next.phys_start()
                && current.rights() == next.rights()
            {
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
            .any(|r| addr >= r.virt_start() && addr < r.virt_end())
    }

    /// Get the region containing an address (if any)
    pub fn get_region_at(&self, addr: u64) -> Option<&ViewRegion> {
        self.regions
            .iter()
            .find(|r| addr >= r.virt_start() && addr < r.virt_end())
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

    // Collect all memory capabilities
    let memory_caps = collect_memory_capabilities(domain_ref);

    // Build regions from each memory capability
    for mem_ref in memory_caps {
        let mem = mem_ref.read();
        let region = ViewRegion::new(mem.data.access, mem.data.remapped);
        view.add_region(region);
    }

    // Coalesce adjacent regions
    view.coalesce();

    view
}

/// Helper to collect all memory capabilities accessible from a domain
fn collect_memory_capabilities(
    _domain_ref: &CapabilityRef<Domain>,
) -> Vec<CapabilityRef<MemoryRegion>> {
    // In the 2026 implementation, domains don't directly store memory capabilities
    // in a retrievable way. This is a simplified implementation that would need
    // to be extended based on how capabilities are tracked.
    // For now, return an empty vec - this will be populated by the caller
    // who has access to the actual memory capability references.
    Vec::new()
}

/// Compute view from explicitly provided memory capabilities
pub fn compute_view_from_capabilities(
    domain_id: u64,
    memory_caps: &[CapabilityRef<MemoryRegion>],
) -> AddressSpaceView {
    let mut view = AddressSpaceView::new(domain_id);

    for mem_ref in memory_caps {
        add_capability_to_view(&mut view, mem_ref, Remapped::Identity);
    }

    view.coalesce();
    view
}

/// Recursively add a memory capability and its accessible children to the view
fn add_capability_to_view(
    view: &mut AddressSpaceView,
    mem_ref: &CapabilityRef<MemoryRegion>,
    parent_remap: Remapped,
) {
    let mem = mem_ref.read();

    // Compute effective remapping
    let effective_remap = match (parent_remap, mem.data.remapped) {
        (Remapped::Identity, remap) => remap,
        (Remapped::Remapped(base), Remapped::Identity) => {
            Remapped::Remapped(base + mem.data.access.start)
        }
        (Remapped::Remapped(_), Remapped::Remapped(addr)) => Remapped::Remapped(addr),
    };

    // Add this region - for simplicity, include all regions
    // A more sophisticated implementation would subtract carved children
    let region = ViewRegion::new(mem.data.access, effective_remap);
    view.add_region(region);

    // Process children
    for child_ref in &mem.children {
        add_capability_to_view(view, child_ref, effective_remap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_view_region_creation() {
        let access = Access::new(0x1000, 0x2000, Rights::RWX);
        let region = ViewRegion::new(access, Remapped::Identity);

        assert_eq!(region.virt_start(), 0x1000);
        assert_eq!(region.virt_end(), 0x3000);
        assert_eq!(region.phys_start(), 0x1000);
        assert_eq!(region.phys_end(), 0x3000);
    }

    #[test]
    fn test_view_region_remapped() {
        let access = Access::new(0x1000, 0x2000, Rights::RW);
        let region = ViewRegion::new(access, Remapped::Remapped(0x10000));

        assert_eq!(region.virt_start(), 0x1000);
        assert_eq!(region.virt_end(), 0x3000);
        assert_eq!(region.phys_start(), 0x10000);
        assert_eq!(region.phys_end(), 0x12000);
    }

    #[test]
    fn test_address_space_coalesce() {
        let mut view = AddressSpaceView::new(1);

        // Add three contiguous regions with same rights
        view.add_region(ViewRegion::new(
            Access::new(0x0, 0x1000, Rights::RW),
            Remapped::Identity,
        ));
        view.add_region(ViewRegion::new(
            Access::new(0x1000, 0x1000, Rights::RW),
            Remapped::Identity,
        ));
        view.add_region(ViewRegion::new(
            Access::new(0x2000, 0x1000, Rights::RW),
            Remapped::Identity,
        ));

        assert_eq!(view.regions.len(), 3);

        view.coalesce();

        assert_eq!(view.regions.len(), 1);
        assert_eq!(view.regions[0].virt_start(), 0x0);
        assert_eq!(view.regions[0].virt_end(), 0x3000);
    }

    #[test]
    fn test_address_space_no_coalesce_different_rights() {
        let mut view = AddressSpaceView::new(1);

        view.add_region(ViewRegion::new(
            Access::new(0x0, 0x1000, Rights::RW),
            Remapped::Identity,
        ));
        view.add_region(ViewRegion::new(
            Access::new(0x1000, 0x1000, Rights::RWX),
            Remapped::Identity,
        ));

        assert_eq!(view.regions.len(), 2);

        view.coalesce();

        // Should not coalesce because rights differ
        assert_eq!(view.regions.len(), 2);
    }

    #[test]
    fn test_is_accessible() {
        let mut view = AddressSpaceView::new(1);
        view.add_region(ViewRegion::new(
            Access::new(0x1000, 0x1000, Rights::RW),
            Remapped::Identity,
        ));
        view.add_region(ViewRegion::new(
            Access::new(0x3000, 0x1000, Rights::RW),
            Remapped::Identity,
        ));

        assert!(view.is_accessible(0x1000));
        assert!(view.is_accessible(0x1500));
        assert!(!view.is_accessible(0x2000));
        assert!(view.is_accessible(0x3000));
        assert!(!view.is_accessible(0x4500));
    }

    #[test]
    fn test_total_size() {
        let mut view = AddressSpaceView::new(1);
        view.add_region(ViewRegion::new(
            Access::new(0x1000, 0x1000, Rights::RW),
            Remapped::Identity,
        ));
        view.add_region(ViewRegion::new(
            Access::new(0x3000, 0x2000, Rights::RW),
            Remapped::Identity,
        ));

        assert_eq!(view.total_size(), 0x3000);
    }
}
