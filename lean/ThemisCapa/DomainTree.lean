/-
  ThemisCapa.DomainTree — Foundation for O2 (hierarchical encapsulation).

  Defines the domain CDT (Configuration-Definition-Tree at the *domain*
  level, distinct from the cap-tree handled by Invariants.CdtBidirectional /
  ParentChildAgreement).

  This module introduces:
  - The parent / child relations on domains (`IsParentOf`, `IsAncestorOf`).
  - Bidirectional consistency invariants
    (`DomainTreeBidirectional`, `DomainTreeParentChild`).
  - Reference-resolution invariants
    (`DomainParentResolves`, `DomainChildResolves`).
  - The combined invariant `DomainTreeWf`.
  - Subtree membership predicates (`InSubtree`, `IsStrictDescendant`).
  - Basic structural lemmas: ancestors and subtrees are well-defined,
    the parent relation is functional, etc.

  These pieces are **not yet** added to `WellFormed`. That happens in a
  subsequent batch once we've audited which step rules need them.
  Keeping the foundation self-contained makes the preservation argument
  easier to factor.

  Used by:
  - Future O2 (hierarchical encapsulation) theorems.
  - Future O3 (nested confidentiality composition) theorems.
-/
import ThemisCapa.State

namespace ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § Parent / Ancestor relations
-- ════════════════════════════════════════════════════════════════════

/-- `p` is the immediate parent of `c` in the domain CDT, witnessed by
    the child's `Domain.parent` field. We use the parent-pointer side as
    the canonical relation; consistency with `childrenDoms` is a
    separate well-formedness predicate. -/
def IsParentOf (s : SpecState) (p c : DomId) : Prop :=
  ∃ d, s.getDom c = some d ∧ d.parent = some p

/-- `a` is an ancestor of `d` (transitive closure of `IsParentOf`). -/
inductive IsAncestorOf (s : SpecState) : DomId → DomId → Prop
  | direct {p c : DomId} (h : IsParentOf s p c) : IsAncestorOf s p c
  | step   {a m c : DomId} (hpa : IsParentOf s a m)
           (hac : IsAncestorOf s m c) : IsAncestorOf s a c

/-- Reflexive ancestor relation: `a = d` or `IsAncestorOf s a d`. -/
def IsAncestorOrSelf (s : SpecState) (a d : DomId) : Prop :=
  a = d ∨ IsAncestorOf s a d

/-- `d` is a strict descendant of `a` (symmetric to `IsAncestorOf`). -/
def IsStrictDescendant (s : SpecState) (d a : DomId) : Prop :=
  IsAncestorOf s a d

/-- `d` is in `a`'s subtree (rooted at `a`). -/
def InSubtree (s : SpecState) (root d : DomId) : Prop :=
  IsAncestorOrSelf s root d

-- ── Basic relational lemmas ──────────────────────────────────────────

/-- The parent relation is functional: a domain has at most one parent. -/
theorem IsParentOf.functional
    {s : SpecState} {p p' c : DomId}
    (h₁ : IsParentOf s p c) (h₂ : IsParentOf s p' c) : p = p' := by
  obtain ⟨d, hd, hp⟩ := h₁
  obtain ⟨d', hd', hp'⟩ := h₂
  rw [hd] at hd'; injection hd' with he
  rw [← he] at hp'
  rw [hp] at hp'; injection hp'

/-- `IsAncestorOf` is transitive. -/
theorem IsAncestorOf.trans
    {s : SpecState} {a m d : DomId}
    (h₁ : IsAncestorOf s a m) (h₂ : IsAncestorOf s m d) :
    IsAncestorOf s a d := by
  induction h₁ with
  | direct hpa     => exact .step hpa h₂
  | step hpa _ ih  => exact .step hpa (ih h₂)

/-- An immediate parent is also an ancestor. -/
@[simp] theorem IsAncestorOf.of_parent
    {s : SpecState} {p c : DomId} (h : IsParentOf s p c) :
    IsAncestorOf s p c := .direct h

/-- `InSubtree` is reflexive. -/
@[simp] theorem InSubtree.refl
    {s : SpecState} (d : DomId) : InSubtree s d d := Or.inl rfl

/-- `InSubtree` from `IsAncestorOf`. -/
theorem InSubtree.of_ancestor
    {s : SpecState} {a d : DomId}
    (h : IsAncestorOf s a d) : InSubtree s a d := Or.inr h

/-- `InSubtree` is transitive. -/
theorem InSubtree.trans
    {s : SpecState} {a m d : DomId}
    (h₁ : InSubtree s a m) (h₂ : InSubtree s m d) : InSubtree s a d := by
  rcases h₁ with rfl | h₁
  · exact h₂
  · rcases h₂ with rfl | h₂
    · exact .of_ancestor h₁
    · exact .of_ancestor (h₁.trans h₂)

-- ════════════════════════════════════════════════════════════════════
-- § Reference-resolution invariants
-- ════════════════════════════════════════════════════════════════════

/-- Every `Domain.parent` pointer resolves to an existing domain. -/
def DomainParentResolves (s : SpecState) : Prop :=
  ∀ did d, s.getDom did = some d →
    ∀ pid, d.parent = some pid → (s.getDom pid).isSome

/-- Every entry of `Domain.childrenDoms` resolves to an existing
    domain. -/
def DomainChildResolves (s : SpecState) : Prop :=
  ∀ did d, s.getDom did = some d →
    ∀ cid ∈ d.childrenDoms, (s.getDom cid).isSome

-- ════════════════════════════════════════════════════════════════════
-- § Bidirectional consistency invariants
-- ════════════════════════════════════════════════════════════════════

/-- `cid ∈ p.childrenDoms ⇒ child.parent = some p`. Mirrors
    `Invariants.CdtBidirectional` for the domain tree. -/
def DomainTreeBidirectional (s : SpecState) : Prop :=
  ∀ pid p, s.getDom pid = some p →
    ∀ cid ∈ p.childrenDoms,
      ∀ c, s.getDom cid = some c → c.parent = some pid

/-- `child.parent = some p ⇒ child ∈ p.childrenDoms`. Dual of
    `DomainTreeBidirectional`; together they pin down a bijection. -/
def DomainTreeParentChild (s : SpecState) : Prop :=
  ∀ cid c, s.getDom cid = some c →
    ∀ pid, c.parent = some pid →
      ∀ p, s.getDom pid = some p → cid ∈ p.childrenDoms

-- ════════════════════════════════════════════════════════════════════
-- § Combined domain-tree well-formedness
-- ════════════════════════════════════════════════════════════════════

/-- Aggregate predicate: the domain tree is structurally consistent. -/
structure DomainTreeWf (s : SpecState) : Prop where
  parentResolves : DomainParentResolves s
  childResolves  : DomainChildResolves s
  bidirectional  : DomainTreeBidirectional s
  parentChild    : DomainTreeParentChild s

-- ════════════════════════════════════════════════════════════════════
-- § Helpers using the invariants
-- ════════════════════════════════════════════════════════════════════

/-- Under `DomainParentResolves`, an `IsParentOf` witness implies the
    parent domain exists in the arena. -/
theorem IsParentOf.parent_exists
    {s : SpecState} (h : DomainParentResolves s)
    {p c : DomId} (hpc : IsParentOf s p c) :
    (s.getDom p).isSome := by
  obtain ⟨d, hd, hp⟩ := hpc
  exact h c d hd p hp

/-- Under `DomainParentResolves`, an `IsParentOf` witness implies the
    child domain exists in the arena. -/
theorem IsParentOf.child_exists
    {s : SpecState} {p c : DomId} (hpc : IsParentOf s p c) :
    (s.getDom c).isSome := by
  obtain ⟨d, hd, _⟩ := hpc
  rw [hd]; rfl

/-- Conversely, `cid ∈ d.childrenDoms` implies an `IsParentOf` edge,
    *given the bidirectional invariant and existence of the child*. -/
theorem IsParentOf.of_child_in
    {s : SpecState} (hbi : DomainTreeBidirectional s)
    (hch : DomainChildResolves s)
    {pid : DomId} {p : Domain} (hp : s.getDom pid = some p)
    {cid : DomId} (hcin : cid ∈ p.childrenDoms) :
    IsParentOf s pid cid := by
  obtain ⟨c, hc⟩ := Option.isSome_iff_exists.mp (hch pid p hp cid hcin)
  exact ⟨c, hc, hbi pid p hp cid hcin c hc⟩

end ThemisCapa
