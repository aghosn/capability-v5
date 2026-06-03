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
-- § 2.  step_dom_parent_stable (TODO: per-action proof)
-- ════════════════════════════════════════════════════════════════════

/-
  The key structural lemma:

      step s a s' →
      s.getDom d = some d_pre → s'.getDom d = some d_post →
      d_pre.parent = d_post.parent

  Plan: `cases hstep` produces 21 action constructors. For each,
  the apply function is structurally a chain of
  `updMem` / `updDomCap` / `freshMem` / `freshDomCap` (transparent
  to `getDom` — see § 1) and `updDomain` / `freshDom`.

  - updDomain x f  — discharge with `updDomain_parent_stable` provided
    that `f` does not rewrite the `parent` field. Inspection of every
    spec apply in `Step.lean` confirms this for every action: the
    closures only touch `memHandles`, `domHandles`, `childrenDoms`,
    `pendingMemCaps`, `pendingDomCaps`, `commBindings`, `addressMap`,
    `mappedGpas`, `nextHandle`, `nextPendingId`, `status`, `policy`,
    `vps`, `frozenHandles` — never `parent`.

  - freshDom dm  — only fires in `create_apply`. The fresh `nextDomId`
    has `s.getDom nextDomId = none` pre, so the lemma's `hpre`
    hypothesis cannot match for this id — the case is vacuously
    discharged when d = nextDomId. For d ≠ nextDomId, the insert
    is transparent (`Arena.find?_insert_other`).

  - domains.remove target  — only fires in `revokeDomain_apply`.
    Symmetric: for d = target, post-state's `getDom` returns `none`,
    so `hpost` cannot match. For d ≠ target, transparent.

  Per-action proof sketches: ~10–15 LOC each, ~250 LOC total.
  Deferred to a follow-up session.
-/

end ThemisCapa
