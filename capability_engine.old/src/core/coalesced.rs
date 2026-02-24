use super::{
    capability::CapaError,
    memory_region::{Access, ViewRegion},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoalescedView {
    pub regions: Vec<ViewRegion>,
}

impl CoalescedView {
    pub fn new() -> Self {
        CoalescedView { regions: vec![] }
    }

    pub fn from_regions(mut regions: Vec<ViewRegion>) -> Result<Self, CapaError> {
        Self::coalesce(&mut regions)?;
        Ok(CoalescedView { regions })
    }

    pub fn coalesce(regions: &mut Vec<ViewRegion>) -> Result<(), CapaError> {
        regions.sort_by_key(|c| c.access.start);
        let mut curr: usize = 0;
        while curr < regions.len() {
            let next = ViewRegion::merge_at(curr, regions)?;
            curr = next;
        }
        Ok(())
    }

    // Add a single ViewRegion

    pub fn add(&mut self, region: ViewRegion) -> Result<(), CapaError> {
        self.regions.push(region);
        Self::coalesce(&mut self.regions)
    }

    pub fn sub(&mut self, region: &ViewRegion) -> Result<(), CapaError> {
        let mut idx: usize = 0;
        while idx < self.regions.len() {
            if !self.regions[idx].intersect_remap(&region) {
                continue;
            }

            // We have an overlap.
            let current = &mut self.regions[idx];

            // Check compatibility now.
            if !current.compatible(region) {
                return Err(CapaError::IncompatibleRemap);
            }

            if region.contains_remap(current) {
                // Easy case, fully contained including access rights.
                self.regions.remove(idx);
                continue;
            }
            // Less easy, fully contained but not access rights.
            if region.active_start() <= current.active_start()
                && current.active_end() <= region.active_end()
            {
                current.access.rights.remove(region.access.rights);
                idx += 1;
                continue;
            }
            // Worst scenario is if we have split.
            let mut replace: Vec<ViewRegion> = Vec::new();
            let mut rights = current.access.rights;
            rights.remove(region.access.rights);

            // left.
            if region.active_start() > current.active_start() {
                let left = ViewRegion::new(
                    Access::new(
                        current.access.start,
                        region.access.start - current.access.start,
                        current.access.rights,
                    ),
                    current.remap,
                );
                replace.push(left);
            };

            // Middle
            if !rights.is_empty() {
                let start = u64::max(current.access.start, region.access.start);
                let end = u64::min(current.access.end(), region.access.end());
                let m = ViewRegion::new(
                    Access::new(start, end - start, rights),
                    current.remap.shift(start - current.access.start),
                );
                replace.push(m);
            }

            // Right
            if region.active_end() < current.active_end() {
                let r = ViewRegion::new(
                    Access::new(
                        region.access.end(),
                        current.access.end() - region.access.end(),
                        current.access.rights,
                    ),
                    current
                        .remap
                        .shift(region.access.end() - current.access.start),
                );
                replace.push(r);
            }
            // Add the regions now.
            self.regions.remove(idx);
            for c in replace.iter() {
                self.regions.insert(idx, *c);
                idx += 1;
            }
        }
        Ok(())
    }
}
