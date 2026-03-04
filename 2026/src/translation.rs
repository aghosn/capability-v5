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

/// Per-domain address translation bookkeeping.
///
/// Tracks all GPA ranges (mapped and blocked) for a single domain.
/// Free GPA ranges are derived as gaps between entries — no explicit
/// free-list is maintained.
#[derive(Clone, Debug)]
pub struct AddressMap {
    /// GPA-start → entry, sorted for efficient lookup.
    entries: BTreeMap<u64, MapEntry>,
}

impl AddressMap {
    /// Create an empty address map.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
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

        // Remove the parent entry.
        self.entries.remove(&parent_gpa);

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

        self.try_coalesce(gpa);
        Ok(())
    }

    /// Remove a mapping entirely.
    ///
    /// Used when a domain is revoked — its entries are dropped.
    pub fn remove(
        &mut self,
        gpa: u64,
    ) -> core::result::Result<MapEntry, &'static str> {
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
        let entry_end = gpa + entry.size;
        if let Some(MapEntry::Mapped(right)) = self.entries.get(&entry_end) {
            let right_hpa_expected = entry.hpa_start + entry.size;
            if right.rights == entry.rights
                && right.hpa_start == right_hpa_expected
            {
                let right_size = right.size;
                self.entries.remove(&entry_end);
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
        if let Some((&left_gpa, _)) = self.entries.range(..gpa).next_back() {
            let left = match self.entries.get(&left_gpa) {
                Some(MapEntry::Mapped(m)) => m.clone(),
                _ => return,
            };
            let left_end = left_gpa + left.size;
            let left_hpa_end = left.hpa_start + left.size;
            if left_end == gpa
                && left.rights == entry.rights
                && left_hpa_end == entry.hpa_start
            {
                self.entries.remove(&gpa);
                if let Some(MapEntry::Mapped(m)) =
                    self.entries.get_mut(&left_gpa)
                {
                    m.size += entry.size;
                }
            }
        }
    }
}
