//! Uncacheable physical address range registry.
//!
//! Device MMIO regions must be mapped with the UC (uncacheable) memory type in
//! the EPT.  Tracking this in capability attributes would require plumbing memory
//! type through the entire capability engine; instead Themis maintains a small
//! sorted table of UC physical ranges built once at boot from the Limine memory
//! map (RESERVED + FRAMEBUFFER entries).
//!
//! The primary API is [`UncacheableRanges::first_overlap`]: given a HPA range,
//! return the first intersection with a UC range.  The EPT mapping path calls
//! this to split a `ChangeRights` range at UC boundaries without checking every
//! page individually.
//!
//! After boot the table is frozen and only read.  Internal state is held behind a
//! `spin::RwLock` so concurrent readers on multiple cores never contend.

use spin::RwLock;
use super::PhysRegion;

/// Maximum number of UC ranges tracked (sufficient for any real hardware).
const MAX_UC_RANGES: usize = 64;

/// Mutable inner state — only written during boot initialisation.
struct Inner {
    ranges: [PhysRegion; MAX_UC_RANGES],
    count:  usize,
}

impl Inner {
    const fn new() -> Self {
        Self {
            ranges: [PhysRegion { base: 0, length: 0 }; MAX_UC_RANGES],
            count:  0,
        }
    }
}

/// Sorted, non-overlapping table of physical address ranges that must be mapped
/// uncacheable (UC) in any EPT that covers them.
///
/// Built once during `boot::platform()` from the Limine memory map and stored in
/// [`PlatformInfo`](crate::boot::PlatformInfo) and [`ThemisPlatform`](crate::platform::ThemisPlatform).
/// After construction only read access is used; the internal `RwLock` allows
/// multiple cores to query concurrently without contention.
pub struct UncacheableRanges {
    inner: RwLock<Inner>,
}

impl UncacheableRanges {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self { inner: RwLock::new(Inner::new()) }
    }

    /// Register `[base, base+length)` as uncacheable.
    ///
    /// Ranges are inserted in sorted order; overlapping or adjacent ranges are
    /// merged.  Panics if more than `MAX_UC_RANGES` disjoint ranges are added.
    /// Must only be called during single-threaded boot initialisation.
    pub fn add(&self, base: u64, length: u64) {
        if length == 0 {
            return;
        }
        let mut g = self.inner.write();
        let end = base + length;

        // Find insertion point (first existing range whose base >= new base).
        let mut pos = g.count;
        for i in 0..g.count {
            if g.ranges[i].base >= base {
                pos = i;
                break;
            }
        }

        // Extend the merge window backward if the preceding range overlaps/touches.
        let mut merged_base = base;
        let mut merged_end  = end;
        let mut start = pos;
        if start > 0 {
            let prev = g.ranges[start - 1];
            if prev.base + prev.length >= base {
                merged_base = prev.base;
                merged_end  = merged_end.max(prev.base + prev.length);
                start -= 1;
            }
        }

        // Absorb any following ranges that fall within the merged span.
        let mut absorb_end = start;
        while absorb_end < g.count {
            let r = g.ranges[absorb_end];
            if r.base <= merged_end {
                merged_end = merged_end.max(r.base + r.length);
                absorb_end += 1;
            } else {
                break;
            }
        }

        // Compact: replace the absorbed slot(s) with the merged range.
        let absorbed  = absorb_end - start;
        let new_count = g.count - absorbed + 1;
        assert!(new_count <= MAX_UC_RANGES, "UncacheableRanges: too many disjoint UC regions");

        for i in (start + 1)..new_count {
            g.ranges[i] = g.ranges[i + absorbed - 1];
        }
        g.ranges[start] = PhysRegion { base: merged_base, length: merged_end - merged_base };
        g.count = new_count;
    }

    /// Return the intersection `[overlap_start, overlap_end)` of the **first**
    /// UC range that overlaps with `[start, start + size)`, or `None`.
    ///
    /// The returned bounds are clipped to the query window:
    /// ```text
    /// overlap_start = max(start, uc_range.base)
    /// overlap_end   = min(start + size, uc_range.base + uc_range.length)
    /// ```
    ///
    /// Callers iterate this to split a mapping into WB and UC segments without
    /// inspecting individual pages.  Multiple cores may call this concurrently.
    pub fn first_overlap(&self, start: u64, size: u64) -> Option<(u64, u64)> {
        let end = start + size;
        let g = self.inner.read();

        // Binary search: find the first range whose end > start.
        let mut lo = 0usize;
        let mut hi = g.count;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let r = g.ranges[mid];
            if r.base + r.length <= start {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        if lo < g.count {
            let r = g.ranges[lo];
            if r.base < end {
                return Some((start.max(r.base), end.min(r.base + r.length)));
            }
        }
        None
    }

    /// Returns `true` if any part of `[start, start+size)` is uncacheable.
    #[allow(dead_code)]
    #[inline]
    pub fn any_overlap(&self, start: u64, size: u64) -> bool {
        self.first_overlap(start, size).is_some()
    }

    /// Number of registered UC ranges (acquires a read lock).
    pub fn len(&self) -> usize {
        self.inner.read().count
    }
}

