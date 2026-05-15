//! Generic interposition policy for processor features (CPUID, MSR, etc.)
//!
//! Provides a trait-based framework where each resource class (CPUID, MSR)
//! implements `ProcFeature` to define its key, range, and value types.
//! The policy (`ProcFeatureConfig<T>`) stores a default action plus sorted
//! override entries, each of which is a `ProcFeaturePolicy<T>` variant.

use alloc::vec::Vec;

/// Maximum number of override entries per policy to prevent memory exhaustion.
pub const MAX_OVERRIDES: usize = 64;

/// Trait defining the associated types for a processor feature resource class.
pub trait ProcFeature: Clone {
    /// A single resource identifier (e.g., CPUID leaf number, MSR number).
    type Input: Ord + Copy;
    /// A range of resources, typically (start, end) inclusive.
    type Range: Clone + core::fmt::Debug;
    /// The emulated value type (e.g., CpuidResult or u64).
    type Value: Clone + core::fmt::Debug;

    /// Check whether `input` falls within `range`.
    fn in_range(input: &Self::Input, range: &Self::Range) -> bool;

    /// Return the start of a range (for sorting).
    fn range_start(range: &Self::Range) -> Self::Input;

    /// Return the end of a range (for sorting/validation).
    fn range_end(range: &Self::Range) -> Self::Input;
}

/// A policy entry: what action to take for a range of resources.
#[derive(Clone, Debug)]
pub enum ProcFeaturePolicy<T: ProcFeature> {
    /// Forward exits in this range to the parent domain.
    Trap(T::Range),
    /// Return a fixed value for resources in this range.
    Emulate(T::Range, T::Value),
    /// Execute natively on the physical CPU.
    Native(T::Range),
}

impl<T: ProcFeature> ProcFeaturePolicy<T> {
    /// Extract the range from any variant.
    pub fn range(&self) -> &T::Range {
        match self {
            ProcFeaturePolicy::Trap(r) => r,
            ProcFeaturePolicy::Emulate(r, _) => r,
            ProcFeaturePolicy::Native(r) => r,
        }
    }
}

/// Default action for resources not matched by any override.
/// Emulate doesn't make sense as a default (no value to return).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DefaultAction {
    Trap = 0,
    Native = 1,
}

impl DefaultAction {
    /// Convert from wire-format u8.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(DefaultAction::Trap),
            1 => Some(DefaultAction::Native),
            _ => None,
        }
    }
}

/// Per-domain configuration for a resource class.
#[derive(Clone, Debug)]
pub struct ProcFeatureConfig<T: ProcFeature> {
    /// Action for resources not matched by any override.
    pub default: DefaultAction,
    /// Sorted by range start, non-overlapping.
    pub overrides: Vec<ProcFeaturePolicy<T>>,
}

impl<T: ProcFeature> ProcFeatureConfig<T> {
    /// Create a new config with the given default and no overrides.
    pub fn new(default: DefaultAction) -> Self {
        ProcFeatureConfig {
            default,
            overrides: Vec::new(),
        }
    }

    /// Look up the action for a given resource.
    /// Returns the matching override, or None if the default applies.
    pub fn lookup(&self, input: &T::Input) -> Option<&ProcFeaturePolicy<T>> {
        // Binary search on sorted overrides.
        let idx = self.overrides.partition_point(|rule| {
            T::range_end(rule.range()) < *input
        });
        if idx < self.overrides.len() && T::in_range(input, self.overrides[idx].range()) {
            Some(&self.overrides[idx])
        } else {
            None
        }
    }

    /// Insert a Trap or Native range override.
    /// Returns an error if the range overlaps an existing override or exceeds
    /// the maximum number of entries.
    pub fn insert_range(
        &mut self,
        range: T::Range,
        action: DefaultAction,
    ) -> core::result::Result<(), InsertError> {
        if self.overrides.len() >= MAX_OVERRIDES {
            return Err(InsertError::TooManyEntries);
        }
        let start = T::range_start(&range);
        let end = T::range_end(&range);
        if end < start {
            return Err(InsertError::InvalidRange);
        }
        // Check for overlaps.
        if self.overlaps(start, end) {
            return Err(InsertError::Overlap);
        }
        let policy = match action {
            DefaultAction::Trap => ProcFeaturePolicy::Trap(range),
            DefaultAction::Native => ProcFeaturePolicy::Native(range),
        };
        // Insert in sorted order.
        let pos = self.overrides.partition_point(|rule| {
            T::range_start(rule.range()) < start
        });
        self.overrides.insert(pos, policy);
        Ok(())
    }

    /// Insert an Emulate point or range override.
    pub fn insert_emulate(
        &mut self,
        range: T::Range,
        value: T::Value,
    ) -> core::result::Result<(), InsertError> {
        if self.overrides.len() >= MAX_OVERRIDES {
            return Err(InsertError::TooManyEntries);
        }
        let start = T::range_start(&range);
        let end = T::range_end(&range);
        if end < start {
            return Err(InsertError::InvalidRange);
        }
        if self.overlaps(start, end) {
            return Err(InsertError::Overlap);
        }
        let pos = self.overrides.partition_point(|rule| {
            T::range_start(rule.range()) < start
        });
        self.overrides.insert(pos, ProcFeaturePolicy::Emulate(range, value));
        Ok(())
    }

    /// Update the emulated value for an existing Emulate entry at `key`.
    /// If no Emulate entry exists at that key, returns NotFound.
    pub fn update_emulate_value(
        &mut self,
        key: &T::Input,
        value: T::Value,
    ) -> core::result::Result<(), InsertError> {
        let idx = self.overrides.partition_point(|rule| {
            T::range_end(rule.range()) < *key
        });
        if idx < self.overrides.len() {
            if let ProcFeaturePolicy::Emulate(ref range, _) = self.overrides[idx] {
                if T::in_range(key, range) {
                    let r = range.clone();
                    self.overrides[idx] = ProcFeaturePolicy::Emulate(r, value);
                    return Ok(());
                }
            }
        }
        Err(InsertError::NotFound)
    }

    /// Check whether [start, end] overlaps any existing override.
    fn overlaps(&self, start: T::Input, end: T::Input) -> bool {
        // Find the first rule whose range_end >= start.
        let idx = self.overrides.partition_point(|rule| {
            T::range_end(rule.range()) < start
        });
        if idx < self.overrides.len() {
            // If that rule's start <= our end, they overlap.
            T::range_start(self.overrides[idx].range()) <= end
        } else {
            false
        }
    }

    /// Remove any override covering `key`. Returns true if one was removed.
    pub fn remove(&mut self, key: &T::Input) -> bool {
        let idx = self.overrides.partition_point(|rule| {
            T::range_end(rule.range()) < *key
        });
        if idx < self.overrides.len() && T::in_range(key, self.overrides[idx].range()) {
            self.overrides.remove(idx);
            true
        } else {
            false
        }
    }
}

/// Errors from insert operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertError {
    /// The new range overlaps an existing override.
    Overlap,
    /// Maximum number of overrides reached.
    TooManyEntries,
    /// Range end < start.
    InvalidRange,
    /// No matching entry found for update.
    NotFound,
}

// ── Concrete resource types ─────────────────────────────────────────────── //

/// CPUID emulated value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuidResult {
    pub v0: u32,
    pub v1: u32,
    pub v2: u32,
    pub v3: u32,
}

/// Marker type for the CPUID resource class.
#[derive(Clone, Debug)]
pub struct Cpuid;

impl ProcFeature for Cpuid {
    /// (leaf, subleaf) — uses lexicographic Ord on tuples.
    type Input = (u32, u32);
    /// ((start_leaf, start_subleaf), (end_leaf, end_subleaf)) inclusive.
    type Range = ((u32, u32), (u32, u32));
    type Value = CpuidResult;

    fn in_range(input: &(u32, u32), range: &((u32, u32), (u32, u32))) -> bool {
        *input >= range.0 && *input <= range.1
    }

    fn range_start(range: &((u32, u32), (u32, u32))) -> (u32, u32) {
        range.0
    }

    fn range_end(range: &((u32, u32), (u32, u32))) -> (u32, u32) {
        range.1
    }
}

/// Marker type for the MSR resource class.
#[derive(Clone, Debug)]
pub struct Msr;

impl ProcFeature for Msr {
    type Input = u32;
    type Range = (u32, u32); // (start, end) inclusive
    type Value = u64;

    fn in_range(msr: &u32, range: &(u32, u32)) -> bool {
        *msr >= range.0 && *msr <= range.1
    }

    fn range_start(range: &(u32, u32)) -> u32 {
        range.0
    }

    fn range_end(range: &(u32, u32)) -> u32 {
        range.1
    }
}

/// Type alias for CPUID policy.
pub type CpuidPolicy = ProcFeatureConfig<Cpuid>;

/// Type alias for MSR policy.
pub type MsrPolicy = ProcFeatureConfig<Msr>;
