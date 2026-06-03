/-
  ThemisCapa.O2SubtreeLocalityRev — Reverse direction of O2 subtree
  locality.

  Together with `O2SubtreeLocality`'s forward direction, this gives
  *subtree-set equality* across footprint-disjoint steps:

      InSubtree s' root d ↔ InSubtree s root d
        (for any pre-existing d, modulo create's fresh nextDomId).

  ## Why a separate file?

  The reverse direction requires a structural fact not needed by the
  forward direction: a single step never reroutes the `parent` field
  of an existing domain.  The only way to obtain a `parent = some x`
  edge in the post-state is for the same edge to already exist in the
  pre-state, OR for the action to be `create` and the child to be the
  freshly-allocated `nextDomId`.

  We capture this as `step_dom_parent_stable`.

  ## Outline

  - § 1: structural plumbing — `updDomain` is parent-preserving when
    its update function is, and `updMem`/`updDomCap`/`freshMem`/
    `freshDomCap` are transparent to `getDom`.
  - § 2: `step_dom_parent_stable` — case analysis over 21 actions.
  - § 3: `step_isParent_rev_root` — promotion at the root, killing
    the create-corner via `hout`.
  - § 4: `step_subtree_isAncestor_rev`, `step_subtree_membership_rev`,
    `step_subtree_membership_iff` — final results.
-/
import ThemisCapa.O2SubtreeLocality
import ThemisCapa.ParentStability

namespace ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § 1.  Plumbing — getDom transparency / parent preservation
-- ════════════════════════════════════════════════════════════════════

private theorem updMem_getDom (s : SpecState) (id : MemCapId)
    (g : MemCap → MemCap) (d : DomId) :
    (s.updMem id g).getDom d = s.getDom d := rfl

private theorem updDomCap_getDom (s : SpecState) (id : DomCapId)
    (g : DomCap → DomCap) (d : DomId) :
    (s.updDomCap id g).getDom d = s.getDom d := rfl

private theorem freshMem_getDom (s : SpecState) (c : MemCap) (d : DomId) :
    (s.freshMem c).snd.getDom d = s.getDom d := rfl

private theorem freshDomCap_getDom (s : SpecState) (dc : DomCap) (d : DomId) :
    (s.freshDomCap dc).snd.getDom d = s.getDom d := rfl

/-- `freshDom`: post-state has the fresh domain inserted at `nextDomId`. -/
private theorem freshDom_getDom (s : SpecState) (dm : Domain) (d : DomId) :
    (s.freshDom dm).snd.getDom d =
    if d = s.nextDomId then some dm else s.getDom d := by
  show ((s.freshDom dm).snd.domains).find? d = _
  simp only [SpecState.freshDom]
  by_cases h : d = s.nextDomId
  · rw [h, Arena.find?_insert_same, if_pos rfl]
  · rw [Arena.find?_insert_other _ _ _ _ h, if_neg h]; rfl

/-- `updDomain` is parent-preserving when the update function is. -/
private theorem updDomain_parent_stable
    (s : SpecState) (x : DomId) (f : Domain → Domain)
    (hfp : ∀ d, (f d).parent = d.parent)
    {d : DomId} {d_pre d_post : Domain}
    (hpre : s.getDom d = some d_pre)
    (hpost : (s.updDomain x f).getDom d = some d_post) :
    d_pre.parent = d_post.parent := by
  by_cases hd : d = x
  · subst hd
    have heq : (s.updDomain d f).getDom d = (s.getDom d).map f := by
      change (s.domains.update d f).find? d = _
      rw [Arena.find?_update_eq_map]; rfl
    rw [heq, hpre] at hpost
    simp only [Option.map_some, Option.some.injEq] at hpost
    rw [← hpost, hfp]
  · have hne : d ≠ x := hd
    have heq : (s.updDomain x f).getDom d = s.getDom d := by
      change (s.domains.update x f).find? d = _
      exact Arena.find?_update_other _ _ _ _ hne
    rw [heq, hpre] at hpost; injection hpost with he
    rw [he]

-- ════════════════════════════════════════════════════════════════════
-- § 2.  step_dom_parent_stable
-- ════════════════════════════════════════════════════════════════════

/-- For any single step from a well-formed state, the `parent` field
    of any pre-existing domain record is stable.

    Thin wrapper around `step_parent_immutable` from
    `ParentStability.lean`, with the equation oriented for use in the
    reverse-direction subtree-locality proofs. -/
theorem step_dom_parent_stable
    {s s' : SpecState} {a : Action}
    (hwf : WellFormed s) (hstep : step s a s')
    {d : DomId} {d_pre d_post : Domain}
    (hpre : s.getDom d = some d_pre) (hpost : s'.getDom d = some d_post) :
    d_pre.parent = d_post.parent :=
  (step_parent_immutable hwf hstep hpre hpost).symm

-- ════════════════════════════════════════════════════════════════════
-- § 3.  Reverse direction: ancestor / subtree membership
-- ════════════════════════════════════════════════════════════════════

/-- Auxiliary: `IsAncestorOf s' a d` lifts to `IsAncestorOf s a d` for
    any pre-existing `d`, and additionally `a` itself pre-exists in
    `s`. The induction simultaneously walks up the chain in `s'` and
    propagates pre-existence using `DomainParentResolves` on `s`.

    This works for any step (no `hout` required) because parent edges
    of pre-existing domains are stable across single steps. -/
private theorem isAncestor_rev_aux
    {s s' : SpecState} {a : Action}
    (hwf : WellFormed s) (hstep : step s a s')
    {root d : DomId} (h : IsAncestorOf s' root d) {d_pre : Domain}
    (hpre : s.getDom d = some d_pre) :
    IsAncestorOf s root d ∧ (s.getDom root).isSome := by
  induction h with
  | @direct p c hp =>
    obtain ⟨d', hd', hpa⟩ := hp
    have heq : d_pre.parent = some p := by
      have hep := step_dom_parent_stable hwf hstep hpre hd'
      rw [hep]; exact hpa
    have hres : (s.getDom p).isSome :=
      hwf.domainTreeWf.parentResolves c d_pre hpre p heq
    exact ⟨.direct ⟨d_pre, hpre, heq⟩, hres⟩
  | @step a' m c hpa hac ih =>
    obtain ⟨hanc_s, hm_some⟩ := ih hpre
    obtain ⟨m_pre, hm_pre⟩ := Option.isSome_iff_exists.mp hm_some
    obtain ⟨m', hm', hpa_eq⟩ := hpa
    have heq : m_pre.parent = some a' := by
      have hep := step_dom_parent_stable hwf hstep hm_pre hm'
      rw [hep]; exact hpa_eq
    have hres : (s.getDom a').isSome :=
      hwf.domainTreeWf.parentResolves m m_pre hm_pre a' heq
    exact ⟨.step ⟨m_pre, hm_pre, heq⟩ hanc_s, hres⟩

/-- `IsAncestorOf` lifts back from `s'` to `s` for pre-existing
    domains. -/
theorem step_subtree_isAncestor_rev
    {s s' : SpecState} {a : Action}
    (hwf : WellFormed s) (hstep : step s a s')
    {root d : DomId} (h : IsAncestorOf s' root d) {d_pre : Domain}
    (hpre : s.getDom d = some d_pre) :
    IsAncestorOf s root d :=
  (isAncestor_rev_aux hwf hstep h hpre).1

/-- Subtree membership lifts back from `s'` to `s` for pre-existing
    domains. -/
theorem step_subtree_membership_rev
    {s s' : SpecState} {a : Action}
    (hwf : WellFormed s) (hstep : step s a s')
    {root d : DomId} (h : InSubtree s' root d) {d_pre : Domain}
    (hpre : s.getDom d = some d_pre) :
    InSubtree s root d := by
  rcases h with heq | hanc
  · exact Or.inl heq
  · exact Or.inr (step_subtree_isAncestor_rev hwf hstep hanc hpre)

-- ════════════════════════════════════════════════════════════════════
-- § 4.  Set equality on the carrier of pre-existing domains
-- ════════════════════════════════════════════════════════════════════

/-- **Subtree-membership equality (pre-existing carrier).**

    For any pre-existing domain `d` (i.e. `s.getDom d = some _`),
    membership in `subtree(root)` agrees between `s` and `s'` across
    a footprint-disjoint step. This is the full O2 set-equality
    statement; together with the forward direction it gives the
    natural symmetric formulation. -/
theorem step_subtree_membership_iff
    {s s' : SpecState} {a : Action}
    (hwf : WellFormed s) (hstep : step s a s')
    {root : DomId}
    (hout : ∀ d, a.affectsDom s d → ¬ InSubtree s root d)
    {d : DomId} {d_pre : Domain}
    (hpre : s.getDom d = some d_pre) :
    InSubtree s' root d ↔ InSubtree s root d := by
  refine ⟨?_, ?_⟩
  · intro h; exact step_subtree_membership_rev hwf hstep h hpre
  · intro h; exact step_subtree_membership_fwd hstep hout h

end ThemisCapa
