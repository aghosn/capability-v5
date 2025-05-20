use std::ops::{Add, Sub};

use super::memory_region::{Access, ViewRegion};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoalescedView {
    regions: Vec<ViewRegion>,
}

impl CoalescedView {
    pub fn new() -> Self {
        CoalescedView { regions: vec![] }
    }

    pub fn from_regions(mut regions: Vec<ViewRegion>) -> Self {
        regions.sort_by_key(|r| r.access.start);
        let mut coalesced = Vec::new();

        for region in regions {
            if let Some(last) = coalesced.last_mut() {
                if Self::can_merge(last, &region) {
                    last.access.size =
                        (region.access.start + region.access.size) - last.access.start;
                } else {
                    coalesced.push(region);
                }
            } else {
                coalesced.push(region);
            }
        }

        CoalescedView { regions: coalesced }
    }

    fn can_merge(a: &ViewRegion, b: &ViewRegion) -> bool {
        let a_end = a.access.start + a.access.size;
        let b_end = b.access.start + b.access.size;

        a_end >= b.access.start
            && a.remap == b.remap
            && a.access.rights == b.access.rights
            && (a_end == b.access.start || b.access.start <= a_end)
    }

    pub fn regions(&self) -> &[ViewRegion] {
        &self.regions
    }
}

// Add a single ViewRegion
impl Add<ViewRegion> for CoalescedView {
    type Output = CoalescedView;

    fn add(mut self, region: ViewRegion) -> Self::Output {
        self.regions.push(region);
        CoalescedView::from_regions(self.regions)
    }
}

// Subtract a single ViewRegion
impl Sub<ViewRegion> for CoalescedView {
    type Output = CoalescedView;

    fn sub(self, region: ViewRegion) -> Self::Output {
        let mut result = Vec::new();
        let start = region.access.start;
        let end = start + region.access.size;

        for r in self.regions {
            let r_start = r.access.start;
            let r_end = r_start + r.access.size;

            if end <= r_start || start >= r_end {
                result.push(r); // no overlap
            } else if start <= r_start && end >= r_end {
                continue; // fully covered: drop
            } else if start > r_start && end < r_end {
                // split into two
                let left = ViewRegion {
                    access: Access {
                        start: r_start,
                        size: start - r_start,
                        rights: r.access.rights,
                    },
                    remap: r.remap,
                };
                let right = ViewRegion {
                    access: Access {
                        start: end,
                        size: r_end - end,
                        rights: r.access.rights,
                    },
                    remap: r.remap,
                };
                result.push(left);
                result.push(right);
            } else if start <= r_start {
                // truncate left
                let truncated = ViewRegion {
                    access: Access {
                        start: end,
                        size: r_end.saturating_sub(end),
                        rights: r.access.rights,
                    },
                    remap: r.remap,
                };
                if truncated.access.size > 0 {
                    result.push(truncated);
                }
            } else if end >= r_end {
                // truncate right
                let truncated = ViewRegion {
                    access: Access {
                        start: r_start,
                        size: start - r_start,
                        rights: r.access.rights,
                    },
                    remap: r.remap,
                };
                if truncated.access.size > 0 {
                    result.push(truncated);
                }
            }
        }

        CoalescedView::from_regions(result)
    }
}
