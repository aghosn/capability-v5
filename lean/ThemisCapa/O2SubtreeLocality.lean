/-
  ThemisCapa.O2SubtreeLocality — Domain-side component of O2
  (hierarchical encapsulation).

  This is the **first Tier-4 / Themis-novel** theorem:
  a step whose domain-write footprint is disjoint from the subtree
  rooted at `root` leaves every domain record inside that subtree
  unchanged, and consequently every parent edge with a child inside
  the subtree, and every ancestor chain rooted at `root`, are
  preserved.

  ## Scope
  This module covers the **domain-record** side AND the
  **owned-memcap** side of O2:
  - Domain-side: `step_subtree_dom_preserved`,
    `step_subtree_isParent_preserved`, `step_subtree_isAncestor_fwd`,
    `step_subtree_membership_fwd`.
  - Memory-side: `step_subtree_mem_preserved` — memcaps whose
    `owner` is in `subtree(s, root)` are preserved when the action's
    `affectsMem` footprint contains no such memcap.

  It does NOT cover:
  - Reverse direction `InSubtree s' root did → InSubtree s root did`.
    Proving this requires reasoning about how `create` introduces
    fresh `IsParentOf` edges; deferred to a follow-up batch.
  - Memcaps that are *aliased into* the subtree but owned outside
    (the canonical "outsider with a borrowed mem-handle" case).
    That belongs to a separate provenance-level theorem.

  ## What "footprint-disjoint" means
  The hypothesis `(∀ d, a.affectsDom s d → ¬ InSubtree s root d)` is a
  *frame condition* on the action's effect, not a property of the
  caller alone. Specifically:
    - It excludes any action whose over-approximated `affectsDom`
      footprint overlaps the subtree (e.g., a `revoke` whose target
      memcap is owned by a domain inside the subtree, or a `send`
      whose receiver is inside).
    - It admits any action whose footprint is entirely outside, even
      if the actor (caller) is a parent or sibling of the subtree.

  Used by:
  - Future O2 wrapper combining dom + mem sides.
  - Future O3 (nested confidentiality composition) theorems.
-/
import ThemisCapa.Locality
import ThemisCapa.DomainTree

namespace ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § Domain-record preservation across footprint-disjoint steps
-- ════════════════════════════════════════════════════════════════════

/-- **O2 dom-locality (atomic).**
    A step whose domain footprint is disjoint from the subtree rooted
    at `root` leaves every domain record inside that subtree
    unchanged. -/
theorem step_subtree_dom_preserved
    {s s' : SpecState} {a : Action} (hstep : step s a s')
    {root : DomId}
    (hout : ∀ d, a.affectsDom s d → ¬ InSubtree s root d)
    {did : DomId} (hin : InSubtree s root did) :
    s'.getDom did = s.getDom did := by
  apply step_locality_dom hstep
  intro haf
  exact hout did haf hin

-- ════════════════════════════════════════════════════════════════════
-- § Parent-edge preservation
-- ════════════════════════════════════════════════════════════════════

/-- Parent relation for any pre-state subtree child is preserved.

    Note: only the *child* needs to be in the subtree; `IsParentOf`
    only inspects the child's `Domain.parent` field. -/
theorem step_subtree_isParent_preserved
    {s s' : SpecState} {a : Action} (hstep : step s a s')
    {root : DomId}
    (hout : ∀ d, a.affectsDom s d → ¬ InSubtree s root d)
    {p c : DomId} (hc : InSubtree s root c) :
    IsParentOf s' p c ↔ IsParentOf s p c := by
  unfold IsParentOf
  rw [step_subtree_dom_preserved hstep hout hc]

-- ════════════════════════════════════════════════════════════════════
-- § Ancestor chain preservation (forward direction)
-- ════════════════════════════════════════════════════════════════════

/-- Auxiliary: induction-friendly form. `hout` is parameterized over
    the same index `r` as the ancestor relation `h`, so induction
    generalizes both consistently. -/
private theorem isAncestor_fwd_aux
    {s s' : SpecState} {a : Action} (hstep : step s a s')
    {r d : DomId} (h : IsAncestorOf s r d)
    (hout : ∀ x, a.affectsDom s x → ¬ InSubtree s r x) :
    IsAncestorOf s' r d := by
  induction h with
  | @direct p c hp =>
    -- p plays the role of root here. c is a direct child, so c ∈ subtree(p).
    have hcSub : InSubtree s p c := InSubtree.of_ancestor (.direct hp)
    have hp' : IsParentOf s' p c :=
      (step_subtree_isParent_preserved hstep hout hcSub).mpr hp
    exact .direct hp'
  | @step a' m c hpa hac ih =>
    -- a' → m → ... → c. m is a direct child of a', hence in subtree(a').
    have hmSub : InSubtree s a' m := InSubtree.of_ancestor (.direct hpa)
    have hpa' : IsParentOf s' a' m :=
      (step_subtree_isParent_preserved hstep hout hmSub).mpr hpa
    -- For the IH on `IsAncestorOf s m c`, we need hout-for-m: this
    -- follows from hout-for-a' since subtree(m) ⊆ subtree(a').
    have hout_m : ∀ x, a.affectsDom s x → ¬ InSubtree s m x := by
      intro x hx hxSub
      exact hout x hx (InSubtree.trans hmSub hxSub)
    exact .step hpa' (ih hout_m)

/-- Ancestor chains from `root` lift forward across footprint-disjoint
    steps. -/
theorem step_subtree_isAncestor_fwd
    {s s' : SpecState} {a : Action} (hstep : step s a s')
    {root : DomId}
    (hout : ∀ d, a.affectsDom s d → ¬ InSubtree s root d)
    {did : DomId} (h : IsAncestorOf s root did) :
    IsAncestorOf s' root did :=
  isAncestor_fwd_aux hstep h hout

-- ════════════════════════════════════════════════════════════════════
-- § Subtree-membership preservation (forward direction)
-- ════════════════════════════════════════════════════════════════════

/-- Subtree membership lifts forward across footprint-disjoint steps. -/
theorem step_subtree_membership_fwd
    {s s' : SpecState} {a : Action} (hstep : step s a s')
    {root : DomId}
    (hout : ∀ d, a.affectsDom s d → ¬ InSubtree s root d)
    {did : DomId} (h : InSubtree s root did) :
    InSubtree s' root did := by
  rcases h with heq | hanc
  · exact Or.inl heq
  · exact Or.inr (step_subtree_isAncestor_fwd hstep hout hanc)

-- ════════════════════════════════════════════════════════════════════
-- § Memory-side: memcaps owned by domains inside the subtree
-- ════════════════════════════════════════════════════════════════════

/-- A memcap "belongs to" the subtree rooted at `root` if it currently
    exists and its `owner` is in `subtree(s, root)`. -/
def MemCapInSubtree (s : SpecState) (root : DomId) (id : MemCapId) : Prop :=
  ∃ m, s.getMem id = some m ∧ InSubtree s root m.owner

/-- **O2 mem-locality (atomic).**
    A step whose memcap-write footprint avoids every memcap owned by
    a domain inside the subtree leaves those memcaps unchanged.

    Note the hypothesis is stated pointwise on `Action.affectsMem`:
    an action may freely modify memcaps owned outside the subtree,
    but no `affectsMem` id may have an owner inside subtree(root). -/
theorem step_subtree_mem_preserved
    {s s' : SpecState} {a : Action} (hstep : step s a s')
    {root : DomId}
    (hout : ∀ id, a.affectsMem s id →
            ∀ m, s.getMem id = some m → ¬ InSubtree s root m.owner)
    {id : MemCapId} (hin : MemCapInSubtree s root id) :
    s'.getMem id = s.getMem id := by
  apply step_locality_mem hstep
  intro haf
  obtain ⟨m, hm, hown⟩ := hin
  exact hout id haf m hm hown

/-- Convenience corollary: same conclusion phrased over a witness
    `(id, m)` rather than the packed `MemCapInSubtree`. -/
theorem step_subtree_mem_preserved'
    {s s' : SpecState} {a : Action} (hstep : step s a s')
    {root : DomId}
    (hout : ∀ id, a.affectsMem s id →
            ∀ m, s.getMem id = some m → ¬ InSubtree s root m.owner)
    {id : MemCapId} {m : MemCap}
    (hm : s.getMem id = some m) (hown : InSubtree s root m.owner) :
    s'.getMem id = s.getMem id :=
  step_subtree_mem_preserved hstep hout ⟨m, hm, hown⟩

end ThemisCapa
