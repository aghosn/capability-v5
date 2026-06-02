/-
  ThemisCapa.Translation — Address-translation algebra.

  Mirrors `capa-engine/src/translation.rs`, scope-restricted: drops cache
  coloring (orthogonal layered refinement) and the `Reserved` MapEntry
  variant (deferred). Keeps access rights, which are essential for any
  runtime-memory isolation theorem.

  This is a **pure data-structure layer (L0)**: no dependency on
  `SpecState`, `Action`, or the `step` relation. Lemmas here are
  algebraic facts about `AddressMap` operations and can be reused
  by any higher layer (engine integration, runtime-memory theorems).

  Axiom A4 (IOVA = GPA) becomes a Lean theorem statement at L1+:
  for every child domain the per-domain `AddressMap` agrees with the
  IOMMU view. That theorem lives outside this file.
-/
import ThemisCapa.Basic

namespace ThemisCapa
namespace Translation

-- ── ColorBitmap (stub — coloring deferred) ──────────────────────────

/-- Cache-coloring bitmap. We retain the type as a stub because
    `MemoryRegion.colorBitmap` carries one; we do not model its
    semantics in v2. Refining it is orthogonal to AddressMap algebra. -/
structure ColorBitmap where
  words : List Nat
deriving Repr

namespace ColorBitmap
def empty : ColorBitmap := ⟨[]⟩
end ColorBitmap

-- ── MapEntry / AddressMap ───────────────────────────────────────────

/-- One mapping in an `AddressMap`: the contiguous GPA range
    `[gpa, gpa + size)` translates to the contiguous HPA range
    `[hpa, hpa + size)` with effective rights `rights`. -/
structure MapEntry where
  gpa    : Nat
  hpa    : Nat
  size   : Nat
  rights : Rights
deriving DecidableEq, Repr

namespace MapEntry

/-- The half-open GPA range covered by this entry. -/
def gpaEnd (e : MapEntry) : Nat := e.gpa + e.size

/-- The half-open HPA range covered by this entry. -/
def hpaEnd (e : MapEntry) : Nat := e.hpa + e.size

/-- A point `g` is inside this entry's GPA range iff `gpa ≤ g < gpaEnd`. -/
def containsGpa (e : MapEntry) (g : Nat) : Prop :=
  e.gpa ≤ g ∧ g < e.gpaEnd

instance (e : MapEntry) (g : Nat) : Decidable (e.containsGpa g) :=
  inferInstanceAs (Decidable (_ ∧ _))

/-- Two GPA ranges `[a, a+sa)` and `[b, b+sb)` overlap. -/
def rangesOverlap (a sa b sb : Nat) : Prop :=
  a < b + sb ∧ b < a + sa

instance (a sa b sb : Nat) : Decidable (rangesOverlap a sa b sb) :=
  inferInstanceAs (Decidable (_ ∧ _))

/-- This entry's GPA range overlaps `[g, g+sz)`. -/
def overlapsRange (e : MapEntry) (g sz : Nat) : Prop :=
  rangesOverlap e.gpa e.size g sz

instance (e : MapEntry) (g sz : Nat) : Decidable (e.overlapsRange g sz) :=
  inferInstanceAs (Decidable (rangesOverlap _ _ _ _))

end MapEntry

/-- Per-domain HPA↔GPA translation table. The list is conceptually a
    sorted set of pairwise GPA-disjoint entries; we keep the shape
    flexible (just a `List`) and impose disjointness as a separate
    invariant `Wf` proved on each construction. -/
structure AddressMap where
  entries : List MapEntry
deriving Repr

namespace AddressMap

/-- Empty (identity) map. -/
def empty : AddressMap := ⟨[]⟩

/-- The entry whose GPA range contains `g`, if any.

    The list is conceptually disjoint, so `find?` returns at most one
    matching entry; `findGpa` exposes that as a function. -/
def lookup (m : AddressMap) (g : Nat) : Option MapEntry :=
  m.entries.find? (·.containsGpa g)

/-- Translate a GPA to an HPA, returning the offset within the entry. -/
def translate (m : AddressMap) (g : Nat) : Option Nat :=
  match m.lookup g with
  | none   => none
  | some e => some (e.hpa + (g - e.gpa))

/-- Some existing entry's GPA range overlaps `[g, g+sz)`. -/
def overlaps (m : AddressMap) (g sz : Nat) : Prop :=
  ∃ e ∈ m.entries, e.overlapsRange g sz

instance (m : AddressMap) (g sz : Nat) : Decidable (m.overlaps g sz) :=
  inferInstanceAs (Decidable (∃ _ ∈ _, _))

/-- Insert an entry. No automatic disjointness check — the caller is
    responsible for verifying `¬ m.overlaps e.gpa e.size` first.
    The engine's `add_footprint` performs that check before calling. -/
def insert (m : AddressMap) (e : MapEntry) : AddressMap :=
  ⟨e :: m.entries⟩

/-- Remove every entry whose GPA range falls *entirely* inside
    `[g, g+sz)`. (Partial-overlap removal is `split` semantics in
    Rust; we do not model that here.) -/
def removeWithin (m : AddressMap) (g sz : Nat) : AddressMap :=
  ⟨m.entries.filter (fun e =>
    decide ¬ (g ≤ e.gpa ∧ e.gpaEnd ≤ g + sz))⟩

/-- Disjointness invariant: no two entries' GPA ranges overlap. -/
def Wf (m : AddressMap) : Prop :=
  ∀ e₁ ∈ m.entries, ∀ e₂ ∈ m.entries,
    e₁ ≠ e₂ → ¬ MapEntry.rangesOverlap e₁.gpa e₁.size e₂.gpa e₂.size

-- ── Algebraic lemmas ─────────────────────────────────────────────────

@[simp] theorem lookup_empty (g : Nat) : empty.lookup g = none := by
  simp [empty, lookup]

@[simp] theorem translate_empty (g : Nat) : empty.translate g = none := by
  simp [empty, translate, lookup]

@[simp] theorem overlaps_empty (g sz : Nat) : ¬ empty.overlaps g sz := by
  simp [empty, overlaps]

/-- If `g` is not in `e`'s range, `lookup` skips `e`. -/
theorem lookup_cons_not_contains
    (e : MapEntry) (es : List MapEntry) (g : Nat)
    (h : ¬ e.containsGpa g) :
    AddressMap.lookup ⟨e :: es⟩ g = AddressMap.lookup ⟨es⟩ g := by
  simp [lookup, List.find?, h]

/-- If `g` is in `e`'s range, `lookup` returns `e`. -/
theorem lookup_cons_contains
    (e : MapEntry) (es : List MapEntry) (g : Nat)
    (h : e.containsGpa g) :
    AddressMap.lookup ⟨e :: es⟩ g = some e := by
  simp [lookup, List.find?, h]

/-- After `insert e`, looking up a GPA inside `e`'s range returns `e`. -/
theorem lookup_insert_self
    (m : AddressMap) (e : MapEntry) (g : Nat)
    (hin : e.containsGpa g) :
    (m.insert e).lookup g = some e := by
  simp [insert, lookup, hin]

/-- After `insert e`, GPAs outside `e`'s range still resolve to whatever
    they did before the insert. -/
theorem lookup_insert_outside
    (m : AddressMap) (e : MapEntry) (g : Nat)
    (hout : ¬ e.containsGpa g) :
    (m.insert e).lookup g = m.lookup g := by
  simp [insert, lookup, hout]

/-- `translate` after `insert` returns the new HPA when `g` lies inside
    the inserted entry. -/
theorem translate_insert_self
    (m : AddressMap) (e : MapEntry) (g : Nat)
    (hin : e.containsGpa g) :
    (m.insert e).translate g = some (e.hpa + (g - e.gpa)) := by
  simp [translate, lookup_insert_self _ _ _ hin]

/-- `translate` is preserved at GPAs outside the inserted entry. -/
theorem translate_insert_outside
    (m : AddressMap) (e : MapEntry) (g : Nat)
    (hout : ¬ e.containsGpa g) :
    (m.insert e).translate g = m.translate g := by
  simp [translate, lookup_insert_outside _ _ _ hout]

/-- Overlap is monotone under `insert`: anything that overlapped before
    still overlaps. -/
theorem overlaps_insert_of_overlaps
    (m : AddressMap) (e : MapEntry) (g sz : Nat)
    (h : m.overlaps g sz) :
    (m.insert e).overlaps g sz := by
  obtain ⟨f, hf, hfo⟩ := h
  exact ⟨f, by simp [insert]; exact Or.inr hf, hfo⟩

/-- After `insert e`, the inserted entry overlaps any range that
    intersects its GPA span. -/
theorem overlaps_insert_self
    (m : AddressMap) (e : MapEntry) (g sz : Nat)
    (h : e.overlapsRange g sz) :
    (m.insert e).overlaps g sz :=
  ⟨e, by simp [insert], h⟩

/-- Conversely, if `(m.insert e).overlaps g sz`, then either `e` itself
    overlaps `[g, g+sz)`, or some pre-existing entry did. -/
theorem overlaps_insert_iff
    (m : AddressMap) (e : MapEntry) (g sz : Nat) :
    (m.insert e).overlaps g sz ↔ e.overlapsRange g sz ∨ m.overlaps g sz := by
  constructor
  · intro ⟨f, hf, hfo⟩
    simp [insert] at hf
    rcases hf with hfeq | hfin
    · exact Or.inl (hfeq ▸ hfo)
    · exact Or.inr ⟨f, hfin, hfo⟩
  · intro h
    cases h with
    | inl h => exact overlaps_insert_self m e g sz h
    | inr h => exact overlaps_insert_of_overlaps m e g sz h

/-- The disjointness invariant is preserved by `insert e` provided `e`
    is itself disjoint from every existing entry. -/
theorem Wf_insert
    (m : AddressMap) (e : MapEntry)
    (hwf : m.Wf)
    (hdisj : ∀ f ∈ m.entries,
             ¬ MapEntry.rangesOverlap e.gpa e.size f.gpa f.size) :
    (m.insert e).Wf := by
  intro e₁ h₁ e₂ h₂ hne
  simp [insert] at h₁ h₂
  rcases h₁ with rfl | h₁
  · rcases h₂ with rfl | h₂
    · exact (hne rfl).elim
    · -- e₁ = e, e₂ ∈ m
      exact hdisj e₂ h₂
  · rcases h₂ with rfl | h₂
    · -- e₂ = e, e₁ ∈ m: symmetric
      intro hov
      exact hdisj e₁ h₁ ⟨hov.2, hov.1⟩
    · -- both in m: from hwf
      exact hwf e₁ h₁ e₂ h₂ hne

end AddressMap

end Translation
end ThemisCapa
