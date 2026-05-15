//! Address translation layer for HPA→GPA mapping.
//!
//! This module provides per-domain address translation bookkeeping,
//! mapping host physical addresses (HPA) to guest physical addresses
//! (GPA).  Each domain holds an [`AddressMap`] that tracks all active
//! and blocked GPA ranges.
//!
//! Enabled by `feature = "address_translation"`.  Cache-color-aware
//! compaction is available with `feature = "cache_coloring"` (which
//! implies `address_translation`).
//!
//! See `docs/design/address_translation.md` for the full design.

use crate::memory::Rights;
use alloc::collections::BTreeMap;
#[cfg(feature = "cache_coloring")]
use alloc::vec::Vec;

// ── ColorBitmap ─────────────────────────────────────────────────────

/// Bitmap selecting which cache colors are authorized for a capability.
///
/// Bit `i` set means pages with color `i` are included.  Dynamically
/// sized to support platforms with arbitrary color counts.
#[cfg(feature = "cache_coloring")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColorBitmap {
    bits: Vec<u64>,
}

#[cfg(feature = "cache_coloring")]
impl ColorBitmap {
    /// Create a bitmap with `num_colors` capacity, all colors enabled.
    pub fn all(num_colors: u32) -> Self {
        let words = ((num_colors as usize) + 63) / 64;
        let mut bits = alloc::vec![u64::MAX; words];
        // Mask off unused high bits in the last word.
        let rem = (num_colors as usize) % 64;
        if rem != 0 && !bits.is_empty() {
            let last = bits.len() - 1;
            bits[last] = (1u64 << rem) - 1;
        }
        Self { bits }
    }

    /// Create a bitmap from a raw slice of words.
    pub fn from_raw(bits: Vec<u64>) -> Self {
        Self { bits }
    }

    /// True if color `i` is authorized.
    pub fn contains(&self, color: u32) -> bool {
        let word = (color / 64) as usize;
        let bit = color % 64;
        word < self.bits.len() && (self.bits[word] & (1u64 << bit)) != 0
    }

    /// True if `self` is a subset of `other` (monotonicity check).
    pub fn is_subset_of(&self, other: &ColorBitmap) -> bool {
        for (i, &w) in self.bits.iter().enumerate() {
            let o = other.bits.get(i).copied().unwrap_or(0);
            if w & !o != 0 {
                return false;
            }
        }
        true
    }

    /// Number of set bits (authorized colors).
    pub fn popcount(&self) -> u32 {
        self.bits.iter().map(|w| w.count_ones()).sum()
    }
}

// ── MappingEntry ────────────────────────────────────────────────────

/// An active GPA→HPA mapping with access rights.
#[derive(Clone, Debug)]
pub struct MappingEntry {
    /// Host physical address start.
    pub hpa_start: u64,
    /// Guest physical address start.
    pub gpa_start: u64,
    /// Mapped size in bytes.
    pub size: u64,
    /// Access rights for this mapping.
    pub rights: Rights,
    /// Color bitmap (only with `cache_coloring`).
    #[cfg(feature = "cache_coloring")]
    pub color_bitmap: Option<ColorBitmap>,
}

/// An entry in the per-domain address map.
#[derive(Clone, Debug)]
pub enum MapEntry {
    /// Active mapping: this GPA range is mapped to an HPA range.
    Mapped(MappingEntry),
    /// Blocked: this GPA range is reserved (carved region was sent).
    /// Stores the original HPA start and size so it can be restored
    /// on revocation.
    Blocked {
        hpa_start: u64,
        size: u64,
    },
}

impl MapEntry {
    /// Return the size of this entry.
    pub fn size(&self) -> u64 {
        match self {
            MapEntry::Mapped(m) => m.size,
            MapEntry::Blocked { size, .. } => *size,
        }
    }
}

// ── AddressMap ──────────────────────────────────────────────────────

/// Per-segment refcount metadata, stored alongside MapEntry.
///
/// This tracks the true per-right reference counts that the MapEntry
/// representation (which only stores effective rights) cannot capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentMeta {
    pub refcounts: RightsRefCount,
    pub blocked: bool,
}

/// Per-domain address translation bookkeeping.
///
/// Tracks all GPA ranges (mapped and blocked) for a single domain.
/// Free GPA ranges are derived as gaps between entries — no explicit
/// free-list is maintained.
///
/// The `segment_meta` map tracks per-right reference counts for the
/// contribution API (add_contribution / remove_contribution).  It is
/// keyed by the same GPA-start as `entries`.
#[derive(Clone, Debug)]
pub struct AddressMap {
    /// GPA-start → entry, sorted for efficient lookup.
    entries: BTreeMap<u64, MapEntry>,
    /// Per-segment refcount metadata (used by contribution API).
    segment_meta: BTreeMap<u64, SegmentMeta>,
}

impl AddressMap {
    /// Create an empty address map.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            segment_meta: BTreeMap::new(),
        }
    }

    /// All entries (for inspection / attestation).
    pub fn entries(&self) -> &BTreeMap<u64, MapEntry> {
        &self.entries
    }

    /// Mutable access to the entries map.
    pub fn entries_mut(&mut self) -> &mut BTreeMap<u64, MapEntry> {
        &mut self.entries
    }

    /// Register a new GPA→HPA mapping.
    ///
    /// If `gpa_hint` is `Some`, uses that GPA (rejects if it overlaps
    /// an existing entry).  If `None`, defaults to identity mapping
    /// (GPA == HPA).
    ///
    /// Returns the assigned GPA start, or an error message.
    pub fn insert(
        &mut self,
        hpa_start: u64,
        size: u64,
        rights: Rights,
        #[cfg(feature = "cache_coloring")]
        color_bitmap: Option<ColorBitmap>,
        gpa_hint: Option<u64>,
    ) -> core::result::Result<u64, &'static str> {
        let gpa = gpa_hint.unwrap_or(hpa_start);

        // Check for overlap with any existing entry.
        if self.overlaps(gpa, size) {
            return Err("GPA range overlaps existing entry");
        }

        self.entries.insert(gpa, MapEntry::Mapped(MappingEntry {
            hpa_start,
            gpa_start: gpa,
            size,
            rights,
            #[cfg(feature = "cache_coloring")]
            color_bitmap,
        }));
        self.segment_meta.insert(gpa, SegmentMeta {
            refcounts: RightsRefCount::from_rights(rights),
            blocked: false,
        });

        Ok(gpa)
    }

    /// Split an existing mapped entry at a sub-range with different
    /// rights.
    ///
    /// Used at carve time: the parent's entry is split into up to 3
    /// entries (left, sub-range with `new_rights`, right).
    ///
    /// `sub_gpa` and `sub_size` must fall entirely within an existing
    /// `Mapped` entry.
    pub fn split(
        &mut self,
        sub_gpa: u64,
        sub_size: u64,
        new_rights: Rights,
    ) -> core::result::Result<(), &'static str> {
        // Find the entry that contains [sub_gpa, sub_gpa + sub_size).
        let (&parent_gpa, _) = self.entries
            .range(..=sub_gpa)
            .next_back()
            .ok_or("no entry contains the sub-range")?;

        let parent = match self.entries.get(&parent_gpa) {
            Some(MapEntry::Mapped(m)) => m.clone(),
            _ => return Err("entry at GPA is not Mapped"),
        };

        let parent_end = parent.gpa_start + parent.size;
        let sub_end = sub_gpa + sub_size;

        if sub_gpa < parent.gpa_start || sub_end > parent_end {
            return Err("sub-range exceeds parent entry");
        }

        // If rights are the same, nothing to do.
        if parent.rights == new_rights {
            return Ok(());
        }

        // Read parent's metadata (preserves true refcounts).
        let parent_meta = self.get_or_init_meta(parent_gpa);

        // Remove the parent entry.
        self.entries.remove(&parent_gpa);
        self.segment_meta.remove(&parent_gpa);

        // HPA offset from parent start to sub-range start.
        let hpa_offset = sub_gpa - parent.gpa_start;

        // Left fragment: [parent_gpa, sub_gpa)
        if sub_gpa > parent.gpa_start {
            let left_size = sub_gpa - parent.gpa_start;
            self.entries.insert(parent.gpa_start, MapEntry::Mapped(MappingEntry {
                hpa_start: parent.hpa_start,
                gpa_start: parent.gpa_start,
                size: left_size,
                rights: parent.rights,
                #[cfg(feature = "cache_coloring")]
                color_bitmap: parent.color_bitmap.clone(),
            }));
            self.segment_meta.insert(parent.gpa_start, parent_meta.clone());
        }

        // Middle: [sub_gpa, sub_end) with new_rights
        self.entries.insert(sub_gpa, MapEntry::Mapped(MappingEntry {
            hpa_start: parent.hpa_start + hpa_offset,
            gpa_start: sub_gpa,
            size: sub_size,
            rights: new_rights,
            #[cfg(feature = "cache_coloring")]
            color_bitmap: parent.color_bitmap.clone(),
        }));
        self.segment_meta.insert(sub_gpa, SegmentMeta {
            refcounts: RightsRefCount::from_rights(new_rights),
            blocked: false,
        });

        // Right fragment: [sub_end, parent_end)
        if sub_end < parent_end {
            let right_size = parent_end - sub_end;
            let right_hpa = parent.hpa_start + (sub_end - parent.gpa_start);
            self.entries.insert(sub_end, MapEntry::Mapped(MappingEntry {
                hpa_start: right_hpa,
                gpa_start: sub_end,
                size: right_size,
                rights: parent.rights,
                #[cfg(feature = "cache_coloring")]
                color_bitmap: parent.color_bitmap,
            }));
            self.segment_meta.insert(sub_end, parent_meta);
        }

        Ok(())
    }

    /// Transition a `Mapped` entry to `Blocked`.
    ///
    /// Used at send time: the sender loses access to the carved range.
    /// The entry must already be its own entry (from a prior `split`).
    pub fn block(
        &mut self,
        gpa: u64,
    ) -> core::result::Result<MappingEntry, &'static str> {
        match self.entries.remove(&gpa) {
            Some(MapEntry::Mapped(m)) => {
                // Preserve refcounts underneath the blocked flag.
                let mut meta = self.get_or_init_meta(gpa);
                meta.blocked = true;
                self.segment_meta.insert(gpa, meta);

                self.entries.insert(gpa, MapEntry::Blocked {
                    hpa_start: m.hpa_start,
                    size: m.size,
                });
                Ok(m)
            }
            Some(other) => {
                // Put it back.
                self.entries.insert(gpa, other);
                Err("entry at GPA is not Mapped")
            }
            None => Err("no entry at GPA"),
        }
    }

    /// Transition a `Blocked` entry back to `Mapped`.
    ///
    /// Used at revoke time: the parent regains access.  May coalesce
    /// with adjacent entries that have the same rights and contiguous
    /// HPA ranges.
    pub fn unblock(
        &mut self,
        gpa: u64,
        rights: Rights,
    ) -> core::result::Result<(), &'static str> {
        let (hpa_start, size) = match self.entries.get(&gpa) {
            Some(MapEntry::Blocked { hpa_start, size }) => (*hpa_start, *size),
            Some(_) => return Err("entry at GPA is not Blocked"),
            None => return Err("no entry at GPA"),
        };

        self.entries.insert(gpa, MapEntry::Mapped(MappingEntry {
            hpa_start,
            gpa_start: gpa,
            size,
            rights,
            #[cfg(feature = "cache_coloring")]
            color_bitmap: None,
        }));
        self.segment_meta.insert(gpa, SegmentMeta {
            refcounts: RightsRefCount::from_rights(rights),
            blocked: false,
        });

        self.try_coalesce(gpa);
        Ok(())
    }

    /// Unblock a sub-range within a Blocked entry, converting it to Mapped.
    ///
    /// Used when a domain receives a capability (alias or carve) back for a
    /// sub-region of a previously carved-away range.  The capability's HPA
    /// must match the corresponding HPA within the Blocked range (same
    /// physical memory that was originally carved out).
    ///
    /// Splits the Blocked entry into up to 3 parts:
    ///   `Blocked(before) | Mapped(sub-range) | Blocked(after)`
    pub fn unblock_subrange(
        &mut self,
        gpa: u64,
        size: u64,
        hpa: u64,
        rights: Rights,
    ) -> core::result::Result<(), &'static str> {
        // Find the Blocked entry containing [gpa, gpa+size).
        let (&b_gpa, entry) = self
            .entries
            .range(..=gpa)
            .next_back()
            .ok_or("no entry contains GPA")?;
        let (b_hpa, b_size) = match entry {
            MapEntry::Blocked { hpa_start, size } => (*hpa_start, *size),
            _ => return Err("entry is not Blocked"),
        };
        if gpa + size > b_gpa + b_size {
            return Err("sub-range exceeds Blocked entry");
        }

        // Validate HPA: must map to the same physical memory.
        let expected_hpa = b_hpa + (gpa - b_gpa);
        if hpa != expected_hpa {
            return Err("HPA mismatch: capability does not match blocked physical memory");
        }

        // Remove the original Blocked entry.
        self.entries.remove(&b_gpa);
        self.segment_meta.remove(&b_gpa);

        // Insert Blocked(before) if non-empty.
        let before_size = gpa - b_gpa;
        if before_size > 0 {
            self.entries.insert(b_gpa, MapEntry::Blocked {
                hpa_start: b_hpa,
                size: before_size,
            });
            self.segment_meta.insert(b_gpa, SegmentMeta {
                refcounts: RightsRefCount::ZERO,
                blocked: true,
            });
        }

        // Insert Mapped(sub-range).
        self.entries.insert(gpa, MapEntry::Mapped(MappingEntry {
            hpa_start: hpa,
            gpa_start: gpa,
            size,
            rights,
            #[cfg(feature = "cache_coloring")]
            color_bitmap: None,
        }));
        self.segment_meta.insert(gpa, SegmentMeta {
            refcounts: RightsRefCount::from_rights(rights),
            blocked: false,
        });

        // Insert Blocked(after) if non-empty.
        let after_gpa = gpa + size;
        let after_size = (b_gpa + b_size) - after_gpa;
        if after_size > 0 {
            self.entries.insert(after_gpa, MapEntry::Blocked {
                hpa_start: b_hpa + (after_gpa - b_gpa),
                size: after_size,
            });
            self.segment_meta.insert(after_gpa, SegmentMeta {
                refcounts: RightsRefCount::ZERO,
                blocked: true,
            });
        }

        Ok(())
    }

    /// Remove a mapping entirely.
    ///
    /// Used when a domain is revoked — its entries are dropped.
    pub fn remove(
        &mut self,
        gpa: u64,
    ) -> core::result::Result<MapEntry, &'static str> {
        self.segment_meta.remove(&gpa);
        self.entries.remove(&gpa).ok_or("no entry at GPA")
    }

    /// Remove all entries whose HPA range falls within `[hpa, hpa+size)`.
    ///
    /// Used during revocation to clean up a domain's AddressMap for
    /// a revoked HPA range that may have been split into multiple
    /// GPA entries.
    pub fn remove_by_hpa_range(&mut self, hpa: u64, size: u64) {
        let hpa_end = hpa + size;
        let to_remove: alloc::vec::Vec<u64> = self
            .entries
            .iter()
            .filter_map(|(&gpa, entry)| {
                let (e_hpa, e_size) = match entry {
                    MapEntry::Mapped(m) => (m.hpa_start, m.size),
                    MapEntry::Blocked { hpa_start, size } => (*hpa_start, *size),
                };
                if e_hpa >= hpa && e_hpa + e_size <= hpa_end {
                    Some(gpa)
                } else {
                    None
                }
            })
            .collect();
        for gpa in to_remove {
            self.entries.remove(&gpa);
            self.segment_meta.remove(&gpa);
        }
    }

    /// Find the GPA corresponding to an HPA range, searching both
    /// `Mapped` and `Blocked` entries.
    ///
    /// Returns the GPA start (with offset applied) if found.
    pub fn find_gpa_for_hpa(&self, hpa: u64, size: u64) -> Option<u64> {
        for (&gpa, entry) in &self.entries {
            let (e_hpa, e_size) = match entry {
                MapEntry::Mapped(m) => (m.hpa_start, m.size),
                MapEntry::Blocked { hpa_start, size } => (*hpa_start, *size),
            };
            if hpa >= e_hpa && hpa + size <= e_hpa + e_size {
                return Some(gpa + (hpa - e_hpa));
            }
        }
        None
    }

    /// Drop all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.segment_meta.clear();
    }

    /// Translate an HPA range to GPA.
    ///
    /// Finds the entry whose HPA range contains the given address.
    /// Returns `(gpa, size, rights)`.
    pub fn translate(
        &self,
        hpa: u64,
        size: u64,
    ) -> core::result::Result<(u64, u64, Rights), &'static str> {
        for entry in self.entries.values() {
            if let MapEntry::Mapped(m) = entry {
                let hpa_end = m.hpa_start + m.size;
                if hpa >= m.hpa_start && hpa + size <= hpa_end {
                    let offset = hpa - m.hpa_start;
                    return Ok((m.gpa_start + offset, size, m.rights));
                }
            }
        }
        Err("no mapping found for HPA range")
    }

    // ── internal helpers ────────────────────────────────────────────

    /// Check if [gpa, gpa+size) overlaps any existing entry.
    pub fn overlaps(&self, gpa: u64, size: u64) -> bool {
        let end = gpa + size;
        // Check entry just before or at `gpa`.
        if let Some((&e_gpa, entry)) = self.entries.range(..end).next_back() {
            if e_gpa + entry.size() > gpa {
                return true;
            }
        }
        // Check entry just after `gpa`.
        if let Some((&e_gpa, _)) = self.entries.range(gpa..).next() {
            if e_gpa < end {
                return true;
            }
        }
        false
    }

    /// Try to coalesce the entry at `gpa` with its left and right
    /// neighbours if they are both `Mapped` with the same rights and
    /// contiguous HPA ranges.
    fn try_coalesce(&mut self, gpa: u64) {
        // Coalesce with right neighbour first.
        let entry = match self.entries.get(&gpa) {
            Some(MapEntry::Mapped(m)) => m.clone(),
            _ => return,
        };
        let entry_meta = self.get_or_init_meta(gpa);
        let entry_end = gpa + entry.size;
        if let Some(MapEntry::Mapped(right)) = self.entries.get(&entry_end) {
            let right_meta = self.get_or_init_meta(entry_end);
            let right_hpa_expected = entry.hpa_start + entry.size;
            if right.hpa_start == right_hpa_expected
                && entry_meta == right_meta
            {
                let right_size = right.size;
                self.entries.remove(&entry_end);
                self.segment_meta.remove(&entry_end);
                if let Some(MapEntry::Mapped(m)) = self.entries.get_mut(&gpa) {
                    m.size += right_size;
                }
            }
        }

        // Coalesce with left neighbour.
        let entry = match self.entries.get(&gpa) {
            Some(MapEntry::Mapped(m)) => m.clone(),
            _ => return,
        };
        let entry_meta = self.get_or_init_meta(gpa);
        if let Some((&left_gpa, _)) = self.entries.range(..gpa).next_back() {
            let left = match self.entries.get(&left_gpa) {
                Some(MapEntry::Mapped(m)) => m.clone(),
                _ => return,
            };
            let left_meta = self.get_or_init_meta(left_gpa);
            let left_end = left_gpa + left.size;
            let left_hpa_end = left.hpa_start + left.size;
            if left_end == gpa
                && left_hpa_end == entry.hpa_start
                && left_meta == entry_meta
            {
                self.entries.remove(&gpa);
                self.segment_meta.remove(&gpa);
                if let Some(MapEntry::Mapped(m)) =
                    self.entries.get_mut(&left_gpa)
                {
                    m.size += entry.size;
                }
            }
        }
    }
}

// ── Refcounted projection model ─────────────────────────────────────
//
// See docs/design/address_translation.md §13 for full design.
//
// The AddressMap is a projection of all capabilities' contributions
// onto GPA space.  Each GPA segment stores per-right reference counts
// so that overlapping contributions (e.g. parent + alias) are tracked
// independently and can be added/removed without affecting each other.

/// Per-right reference counts for a GPA segment.
///
/// Tracks how many capabilities contribute each access right (R, W, X)
/// to this segment.  Effective rights = union of all non-zero counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RightsRefCount {
    pub read: u32,
    pub write: u32,
    pub execute: u32,
}

impl RightsRefCount {
    /// All-zero refcounts.
    pub const ZERO: Self = Self {
        read: 0,
        write: 0,
        execute: 0,
    };

    /// Create from a Rights value (each set bit → count of 1).
    pub fn from_rights(rights: Rights) -> Self {
        Self {
            read: if rights.has(Rights::READ) { 1 } else { 0 },
            write: if rights.has(Rights::WRITE) { 1 } else { 0 },
            execute: if rights.has(Rights::EXECUTE) { 1 } else { 0 },
        }
    }

    /// Compute effective rights: any count > 0 → right is active.
    pub fn effective_rights(&self) -> Rights {
        let mut bits: u8 = 0;
        if self.read > 0 {
            bits |= Rights::READ;
        }
        if self.write > 0 {
            bits |= Rights::WRITE;
        }
        if self.execute > 0 {
            bits |= Rights::EXECUTE;
        }
        Rights::from_bits(bits)
    }

    /// True if all counts are zero (no contributors).
    pub fn is_empty(&self) -> bool {
        self.read == 0 && self.write == 0 && self.execute == 0
    }

    /// Increment counts for each right present in `rights`.
    pub fn add(&mut self, rights: Rights) {
        if rights.has(Rights::READ) {
            self.read += 1;
        }
        if rights.has(Rights::WRITE) {
            self.write += 1;
        }
        if rights.has(Rights::EXECUTE) {
            self.execute += 1;
        }
    }

    /// Decrement counts for each right present in `rights`.
    ///
    /// Saturates at zero (never underflows).
    pub fn sub(&mut self, rights: Rights) {
        if rights.has(Rights::READ) {
            self.read = self.read.saturating_sub(1);
        }
        if rights.has(Rights::WRITE) {
            self.write = self.write.saturating_sub(1);
        }
        if rights.has(Rights::EXECUTE) {
            self.execute = self.execute.saturating_sub(1);
        }
    }
}

/// A segment in the refcounted projected address map.
///
/// Represents a contiguous GPA range with uniform HPA mapping,
/// reference counts, and blocked status.
#[derive(Clone, Debug)]
pub struct Segment {
    /// HPA corresponding to the start of this GPA segment.
    pub hpa_start: u64,
    /// Segment size in bytes.
    pub size: u64,
    /// Per-right contributor counts.
    pub refcounts: RightsRefCount,
    /// If true, this range is reserved for a carved-away child.
    /// Refcounts should be zero (or at least not contribute visible rights).
    pub blocked: bool,
}

impl Segment {
    /// Effective rights for this segment.
    pub fn effective_rights(&self) -> Rights {
        if self.blocked {
            Rights::NONE
        } else {
            self.refcounts.effective_rights()
        }
    }
}

impl AddressMap {
    // ── Refcounted contribution API ────────────────────────────────

    /// Add a capability's contribution to GPA range `[gpa, gpa+size)`.
    ///
    /// If `blocked` is true, marks the range as blocked (carved hole).
    /// If `blocked` is false, increments per-right refcounts for `rights`.
    ///
    /// **HPA consistency**: if an existing segment at a given GPA has a
    /// different HPA, returns an error.
    ///
    /// Splits existing segments at the boundaries and coalesces afterward.
    pub fn add_contribution(
        &mut self,
        gpa: u64,
        hpa: u64,
        size: u64,
        rights: Rights,
        blocked: bool,
    ) -> core::result::Result<(), &'static str> {
        if size == 0 {
            return Ok(());
        }
        let end = gpa + size;

        // 1. Split any segment that straddles the boundaries.
        self.split_segment_at(gpa);
        self.split_segment_at(end);

        // 2. Collect existing segments in [gpa, end).
        let existing: alloc::vec::Vec<(u64, u64, u64)> = self
            .entries
            .range(gpa..end)
            .map(|(&g, e)| {
                let (e_hpa, e_size) = match e {
                    MapEntry::Mapped(m) => (m.hpa_start, m.size),
                    MapEntry::Blocked { hpa_start, size } => (*hpa_start, *size),
                };
                (g, e_hpa, e_size)
            })
            .collect();

        // 3. Walk the range, filling gaps and incrementing existing segments.
        let mut cursor = gpa;
        let mut existing_iter = existing.iter().peekable();

        while cursor < end {
            if let Some(&&(seg_gpa, seg_hpa, seg_size)) = existing_iter.peek() {
                if cursor < seg_gpa {
                    // Gap: [cursor, seg_gpa) — create new segment.
                    let gap_size = seg_gpa - cursor;
                    let gap_hpa = hpa + (cursor - gpa);
                    let meta = if blocked {
                        SegmentMeta {
                            refcounts: RightsRefCount::ZERO,
                            blocked: true,
                        }
                    } else {
                        SegmentMeta {
                            refcounts: RightsRefCount::from_rights(rights),
                            blocked: false,
                        }
                    };
                    self.insert_from_meta(cursor, gap_hpa, gap_size, &meta);
                    cursor = seg_gpa;
                } else {
                    // Existing segment at cursor — verify HPA and increment.
                    let expected_hpa = hpa + (cursor - gpa);
                    if seg_hpa != expected_hpa {
                        return Err("HPA conflict: existing segment has different HPA");
                    }

                    // Read true refcounts from segment_meta.
                    let mut meta = self.get_or_init_meta(cursor);
                    if blocked {
                        meta.blocked = true;
                    } else {
                        meta.refcounts.add(rights);
                    }
                    self.insert_from_meta(cursor, seg_hpa, seg_size, &meta);

                    cursor += seg_size;
                    existing_iter.next();
                }
            } else {
                // No more existing segments — fill remaining gap.
                let gap_size = end - cursor;
                let gap_hpa = hpa + (cursor - gpa);
                let meta = if blocked {
                    SegmentMeta {
                        refcounts: RightsRefCount::ZERO,
                        blocked: true,
                    }
                } else {
                    SegmentMeta {
                        refcounts: RightsRefCount::from_rights(rights),
                        blocked: false,
                    }
                };
                self.insert_from_meta(cursor, gap_hpa, gap_size, &meta);
                cursor = end;
            }
        }

        // 4. Coalesce neighbors in [gpa, end) and at boundaries.
        self.coalesce_range(gpa, end);

        Ok(())
    }

    /// Remove a capability's contribution from GPA range `[gpa, gpa+size)`.
    ///
    /// If `blocked` is true, clears the blocked flag.
    /// If `blocked` is false, decrements per-right refcounts for `rights`.
    ///
    /// Segments whose refcounts reach zero and are not blocked are removed.
    /// Splits at boundaries and coalesces afterward.
    pub fn remove_contribution(
        &mut self,
        gpa: u64,
        hpa: u64,
        size: u64,
        rights: Rights,
        blocked: bool,
    ) -> core::result::Result<(), &'static str> {
        if size == 0 {
            return Ok(());
        }
        let end = gpa + size;

        // 1. Split at boundaries.
        self.split_segment_at(gpa);
        self.split_segment_at(end);

        // 2. Collect segments in range.
        let in_range: alloc::vec::Vec<(u64, u64, u64)> = self
            .entries
            .range(gpa..end)
            .map(|(&g, e)| {
                let (e_hpa, e_size) = match e {
                    MapEntry::Mapped(m) => (m.hpa_start, m.size),
                    MapEntry::Blocked { hpa_start, size } => (*hpa_start, *size),
                };
                (g, e_hpa, e_size)
            })
            .collect();

        // 3. Decrement/clear and remove empty segments.
        for (seg_gpa, seg_hpa, seg_size) in in_range {
            // Verify HPA consistency.
            let expected_hpa = hpa + (seg_gpa - gpa);
            if seg_hpa != expected_hpa {
                return Err("HPA mismatch during remove_contribution");
            }

            let mut meta = self.get_or_init_meta(seg_gpa);

            if blocked {
                meta.blocked = false;
            } else {
                meta.refcounts.sub(rights);
            }

            if meta.refcounts.is_empty() && !meta.blocked {
                // No contributors left — remove segment entirely.
                self.entries.remove(&seg_gpa);
                self.segment_meta.remove(&seg_gpa);
            } else {
                self.insert_from_meta(seg_gpa, seg_hpa, seg_size, &meta);
            }
        }

        // 4. Coalesce neighbors.
        self.coalesce_range(gpa, end);

        Ok(())
    }

    // ── Internal helpers for contribution API ──────────────────────

    /// Get the SegmentMeta for a GPA, or initialize it from the
    /// existing MapEntry if not yet tracked.
    fn get_or_init_meta(&self, gpa: u64) -> SegmentMeta {
        if let Some(meta) = self.segment_meta.get(&gpa) {
            return meta.clone();
        }
        // Derive from MapEntry.
        match self.entries.get(&gpa) {
            Some(MapEntry::Mapped(m)) => SegmentMeta {
                refcounts: RightsRefCount::from_rights(m.rights),
                blocked: false,
            },
            Some(MapEntry::Blocked { .. }) => SegmentMeta {
                refcounts: RightsRefCount::ZERO,
                blocked: true,
            },
            None => SegmentMeta {
                refcounts: RightsRefCount::ZERO,
                blocked: false,
            },
        }
    }

    /// Write both entries and segment_meta from a SegmentMeta.
    fn insert_from_meta(&mut self, gpa: u64, hpa: u64, size: u64, meta: &SegmentMeta) {
        let entry = if meta.blocked {
            MapEntry::Blocked {
                hpa_start: hpa,
                size,
            }
        } else {
            MapEntry::Mapped(MappingEntry {
                hpa_start: hpa,
                gpa_start: gpa,
                size,
                rights: meta.refcounts.effective_rights(),
                #[cfg(feature = "cache_coloring")]
                color_bitmap: None,
            })
        };
        self.entries.insert(gpa, entry);
        self.segment_meta.insert(gpa, meta.clone());
    }

    // ── Segment splitting and coalescing ───────────────────────────

    /// Split the segment that contains `at` into two segments, one
    /// ending at `at` and one starting at `at`.
    ///
    /// If `at` falls exactly on a segment boundary (or in a gap),
    /// this is a no-op.
    fn split_segment_at(&mut self, at: u64) {
        // Find the segment whose range contains `at` (if any).
        let (&seg_gpa, _) = match self.entries.range(..at).next_back() {
            Some(pair) => pair,
            None => return,
        };

        let (seg_hpa, seg_size) = match self.entries.get(&seg_gpa) {
            Some(MapEntry::Mapped(m)) => (m.hpa_start, m.size),
            Some(MapEntry::Blocked { hpa_start, size }) => (*hpa_start, *size),
            None => return,
        };

        let seg_end = seg_gpa + seg_size;
        if at <= seg_gpa || at >= seg_end {
            return;
        }

        // Read true metadata.
        let meta = self.get_or_init_meta(seg_gpa);

        let left_size = at - seg_gpa;
        let right_size = seg_end - at;
        let right_hpa = seg_hpa + left_size;

        // Left half.
        self.insert_from_meta(seg_gpa, seg_hpa, left_size, &meta);
        // Right half.
        self.insert_from_meta(at, right_hpa, right_size, &meta);
    }

    /// Coalesce adjacent segments in and around the range [start, end).
    ///
    /// Two adjacent segments can merge if they have the same refcounts,
    /// contiguous HPA, and same blocked status.
    fn coalesce_range(&mut self, start: u64, end: u64) {
        let mut candidates: alloc::vec::Vec<u64> = alloc::vec::Vec::new();

        if let Some((&g, _)) = self.entries.range(..start).next_back() {
            candidates.push(g);
        }
        for (&g, _) in self.entries.range(start..end) {
            candidates.push(g);
        }
        if let Some((&g, _)) = self.entries.range(end..).next() {
            candidates.push(g);
        }

        let mut i = 0;
        while i + 1 < candidates.len() {
            let left_gpa = candidates[i];
            let right_gpa = candidates[i + 1];

            if self.try_coalesce_pair(left_gpa, right_gpa) {
                candidates.remove(i + 1);
            } else {
                i += 1;
            }
        }
    }

    /// Try to merge two adjacent segments.  Returns true if merged.
    fn try_coalesce_pair(&mut self, left_gpa: u64, right_gpa: u64) -> bool {
        let (left_hpa, left_size) = match self.entries.get(&left_gpa) {
            Some(MapEntry::Mapped(m)) => (m.hpa_start, m.size),
            Some(MapEntry::Blocked { hpa_start, size }) => (*hpa_start, *size),
            None => return false,
        };
        let (right_hpa, right_size) = match self.entries.get(&right_gpa) {
            Some(MapEntry::Mapped(m)) => (m.hpa_start, m.size),
            Some(MapEntry::Blocked { hpa_start, size }) => (*hpa_start, *size),
            None => return false,
        };

        // Must be adjacent in GPA.
        if left_gpa + left_size != right_gpa {
            return false;
        }
        // Must have contiguous HPA.
        if left_hpa + left_size != right_hpa {
            return false;
        }

        // Compare metadata (refcounts + blocked).
        let left_meta = self.get_or_init_meta(left_gpa);
        let right_meta = self.get_or_init_meta(right_gpa);

        if left_meta != right_meta {
            return false;
        }

        // Merge: extend left, remove right.
        let new_size = left_size + right_size;
        self.insert_from_meta(left_gpa, left_hpa, new_size, &left_meta);
        self.entries.remove(&right_gpa);
        self.segment_meta.remove(&right_gpa);
        true
    }
}

// ── AddressMap diff ─────────────────────────────────────────────────

/// A snapshot of an AddressMap's Mapped entries for diffing.
///
/// Each element is `(gpa_start, hpa_start, size, rights)`.
pub type MappedSnapshot = alloc::vec::Vec<(u64, u64, u64, Rights)>;

impl AddressMap {
    /// Snapshot all `Mapped` entries for later diffing.
    pub fn mapped_snapshot(&self) -> MappedSnapshot {
        self.entries
            .iter()
            .filter_map(|(&gpa, entry)| match entry {
                MapEntry::Mapped(m) => Some((gpa, m.hpa_start, m.size, m.rights)),
                _ => None,
            })
            .collect()
    }
}

/// Diff two AddressMap snapshots and produce an [`UpdateBatch`].
///
/// Entries present in `before` but not `after` become `ChangeRights(NONE, shootdown=true)`.
/// Entries present in `after` but not `before` become `ChangeRights(rights, shootdown=false)`.
/// Entries present in both with different rights get the appropriate shootdown flag.
///
/// Comparison is by `gpa_start` — if an entry moves GPA, it appears as
/// a removal at the old GPA and an addition at the new GPA.
pub fn address_map_diff(
    domain_id: crate::update::DomainId,
    before: &MappedSnapshot,
    after: &MappedSnapshot,
) -> crate::update::UpdateBatch {
    use crate::update::UpdateBatch;
    use alloc::collections::BTreeMap;

    // Index both snapshots by gpa_start.
    let before_map: BTreeMap<u64, (u64, u64, Rights)> = before
        .iter()
        .map(|&(gpa, hpa, size, rights)| (gpa, (hpa, size, rights)))
        .collect();
    let after_map: BTreeMap<u64, (u64, u64, Rights)> = after
        .iter()
        .map(|&(gpa, hpa, size, rights)| (gpa, (hpa, size, rights)))
        .collect();

    let mut updates = UpdateBatch::new();

    // Removed or changed entries.
    for (&gpa, &(hpa, size, before_rights)) in &before_map {
        match after_map.get(&gpa) {
            None => {
                // Entry removed: unmap.
                updates.add_change_rights(domain_id, gpa, size, hpa, Rights::NONE, true);
            }
            Some(&(_, _, after_rights)) if after_rights != before_rights => {
                let shootdown = after_rights.is_subset_of(&before_rights);
                updates.add_change_rights(domain_id, gpa, size, hpa, after_rights, shootdown);
            }
            _ => {} // unchanged
        }
    }

    // New entries.
    for (&gpa, &(hpa, size, rights)) in &after_map {
        if !before_map.contains_key(&gpa) {
            updates.add_change_rights(domain_id, gpa, size, hpa, rights, false);
        }
    }

    updates
}
