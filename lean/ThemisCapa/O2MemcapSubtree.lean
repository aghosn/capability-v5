/-
  ThemisCapa.O2MemcapSubtree — Memcap-side reverse direction of O2.

  ## Goal

  Mirror of `step_subtree_membership_iff` (domain side) at the memcap
  level: across a footprint-disjoint step, a pre-existing memcap's
  membership in `MemCapInSubtree s root` is invariant.

  ## What "footprint-disjoint" means here

  Two-sided pointwise frame condition:
  - `houtDom : ∀ d, a.affectsDom s d → ¬ InSubtree s root d`
  - `houtMem : ∀ id, a.affectsMem s id → ∀ m, s.getMem id = some m →
                                          ¬ InSubtree s root m.owner`

  These are exactly the conditions used by the forward direction
  (`step_subtree_mem_preserved` + `step_subtree_membership_fwd`).

  ## Owner pre-existence

  The reverse direction relies on `step_subtree_membership_rev` for
  the owner, which requires the owner be a pre-existing domain. There
  is no global invariant pinning "every memcap's owner is in
  `s.domains`" (memcap owners are just `DomId`s, not validated by
  `WellFormed`). We therefore require an explicit hypothesis
  `hOwnerPre : ∀ m, s.getMem id = some m → (s.getDom m.owner).isSome`.

  In practice, when callers chain this with `provenance_transfer`-style
  reasoning, the owner pre-existence is supplied directly by the
  action's guard (e.g., `send`'s `receiverExists`).

  ## What's covered

  * `step_memcap_subtree_iff` — set-equality on the carrier of
    pre-existing memcaps.
  * `step_memcap_subtree_preserved_rev` — the new ←-direction lemma.
-/
import ThemisCapa.O2SubtreeLocalityRev
import ThemisCapa.Provenance

namespace ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § 1.  Reverse direction
-- ════════════════════════════════════════════════════════════════════

/-- **O2 memcap reverse direction.**

    A pre-existing memcap that *appears* to belong to `subtree(root)`
    in the post-state already belonged to it in the pre-state, given
    both footprint-disjointness conditions. Together with the forward
    direction this gives the iff stated below. -/
theorem step_memcap_subtree_preserved_rev
    {s s' : SpecState} {a : Action}
    (hwf : WellFormed s) (hstep : step s a s')
    {root : DomId}
    (houtDom : ∀ d, a.affectsDom s d → ¬ InSubtree s root d)
    (houtMem : ∀ id, a.affectsMem s id →
            ∀ m, s.getMem id = some m → ¬ InSubtree s root m.owner)
    {id : MemCapId} {m_pre : MemCap} (hpre : s.getMem id = some m_pre)
    (hOwnerExists : ∀ m_post, s'.getMem id = some m_post →
                              (s.getDom m_post.owner).isSome)
    (hpost : MemCapInSubtree s' root id) :
    MemCapInSubtree s root id := by
  obtain ⟨m_post, hm_post, hown_post⟩ := hpost
  -- Two cases: either id is in affectsMem footprint or not.
  by_cases hAff : a.affectsMem s id
  · -- id is modified. Use provenance_transfer if owner changed.
    by_cases hOwn : m_pre.owner = m_post.owner
    · -- Owner unchanged: m_pre.owner ∈ subtree s'; pre-existing; rev.
      refine ⟨m_pre, hpre, ?_⟩
      have hOwnerInS : (s.getDom m_pre.owner).isSome := by
        rw [hOwn]; exact hOwnerExists m_post hm_post
      obtain ⟨d_pre, hd_pre⟩ := Option.isSome_iff_exists.mp hOwnerInS
      rw [hOwn] at hd_pre ⊢
      exact step_subtree_membership_rev hwf hstep hown_post hd_pre
    · -- Owner changed: action is .send or .accept. By provenance_transfer,
      -- m_post.owner = action's receiver, which lies in affectsDom.
      -- Then houtDom forces ¬ InSubtree s root m_post.owner; but rev
      -- on pre-existing m_post.owner contradicts InSubtree s' root.
      have hOwnerInS : (s.getDom m_post.owner).isSome := hOwnerExists m_post hm_post
      obtain ⟨d_post, hd_post⟩ := Option.isSome_iff_exists.mp hOwnerInS
      have hOwnInPre : InSubtree s root m_post.owner :=
        step_subtree_membership_rev hwf hstep hown_post hd_post
      -- Derive a.affectsDom s m_post.owner from provenance_transfer.
      rcases provenance_transfer hwf hstep hpre hm_post hOwn with
        ⟨caller, ha⟩ | ⟨pid, ha⟩ | ⟨caller, gpa, ha⟩ | ⟨pid, gpa, ha⟩
      · subst ha
        exfalso
        exact houtDom m_post.owner (Or.inr rfl) hOwnInPre
      · subst ha
        exfalso
        -- accept's affectsDom is `did = receiver ∨ ...`. m_post.owner
        -- equals the receiver (the first arg of `.accept m_post.owner pid`).
        exact houtDom m_post.owner (Or.inl rfl) hOwnInPre
      · subst ha
        exfalso
        exact houtDom m_post.owner (Or.inr rfl) hOwnInPre
      · subst ha
        exfalso
        exact houtDom m_post.owner (Or.inl rfl) hOwnInPre
  · -- id outside affectsMem footprint: getMem is preserved, owner same.
    have hframe : s'.getMem id = s.getMem id := step_locality_mem hstep hAff
    have hOwnerInS : (s.getDom m_post.owner).isSome := hOwnerExists m_post hm_post
    have hm_eq : some m_post = some m_pre := by rw [← hpre, ← hframe, hm_post]
    injection hm_eq with heq
    refine ⟨m_pre, hpre, ?_⟩
    rw [heq] at hown_post
    rw [heq] at hOwnerInS
    obtain ⟨d_pre, hd_pre⟩ := Option.isSome_iff_exists.mp hOwnerInS
    exact step_subtree_membership_rev hwf hstep hown_post hd_pre

-- ════════════════════════════════════════════════════════════════════
-- § 2.  Iff (forward + reverse)
-- ════════════════════════════════════════════════════════════════════

/-- **Memcap-side O2 set-equality (pre-existing carrier).**

    For any pre-existing memcap `id` (i.e. `s.getMem id = some _`)
    whose owner is a pre-existing domain, membership in
    `subtree(root)` agrees between `s` and `s'` across a step whose
    footprint avoids the subtree (both dom and mem sides). -/
theorem step_memcap_subtree_iff
    {s s' : SpecState} {a : Action}
    (hwf : WellFormed s) (hstep : step s a s')
    {root : DomId}
    (houtDom : ∀ d, a.affectsDom s d → ¬ InSubtree s root d)
    (houtMem : ∀ id, a.affectsMem s id →
            ∀ m, s.getMem id = some m → ¬ InSubtree s root m.owner)
    {id : MemCapId} {m_pre : MemCap} (hpre : s.getMem id = some m_pre)
    (hOwnerExists : ∀ m_post, s'.getMem id = some m_post →
                              (s.getDom m_post.owner).isSome) :
    MemCapInSubtree s' root id ↔ MemCapInSubtree s root id := by
  refine ⟨?_, ?_⟩
  · intro h
    exact step_memcap_subtree_preserved_rev hwf hstep houtDom houtMem hpre
      hOwnerExists h
  · intro h
    obtain ⟨m, hm, hown⟩ := h
    refine ⟨m, ?_, ?_⟩
    · rw [step_subtree_mem_preserved hstep houtMem ⟨m, hm, hown⟩]; exact hm
    · exact step_subtree_membership_fwd hstep houtDom hown

end ThemisCapa
