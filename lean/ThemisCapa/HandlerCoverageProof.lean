/-
  ThemisCapa.HandlerCoverageProof — preservation of `HandlerCoverage`.

  ## Statement
  For every live domain `d` and vector `v`, there is a live ancestor-or-self
  `a` with `a.visibilityFor v = .deliver`. See `HandlerCoverage.lean`.

  ## Top theorem
  `step_preservesHandlerCoverage :
      WellFormed s → step s a s' → HandlerCoverage s'`.

  Almost every action is trivial: 19 of 21 do not mutate any domain's
  `parent`, `policy`, or `status`. The two non-trivial cases:
  * `create` — introduces a new live edge `(newDom → caller)`. The new
    child inherits its handler from the caller's ancestor chain.
  * `revokeDomain` — removes the target. By `RevokeDomainGuard.targetIsLeaf`
    + `DomainTreeWf`, no surviving live domain has the target in its
    ancestor chain, so existing chains remain intact.
-/
import ThemisCapa.Step
import ThemisCapa.Invariants
import ThemisCapa.HandlerCoverage

namespace ThemisCapa
open Arena

-- ════════════════════════════════════════════════════════════════════
-- § 0.  Ancestor-relation transport lemmas
-- ════════════════════════════════════════════════════════════════════

/-! These small lemmas express that `IsParentOf` (and hence
    `IsAncestorOf` / `IsAncestorOrSelf`) only depends on the `domains`
    arena and on each domain's `parent` field.  Updates that leave
    `getDom` unchanged, or that preserve `parent` pointwise, leave the
    ancestor relation invariant. -/

/-- `IsParentOf` only inspects `getDom`. -/
theorem IsParentOf_congr {s₁ s₂ : SpecState} {p c : DomId}
    (h : s₁.getDom c = s₂.getDom c) :
    IsParentOf s₁ p c ↔ IsParentOf s₂ p c := by
  unfold IsParentOf
  refine ⟨?_, ?_⟩
  · rintro ⟨d, hd, hpar⟩; exact ⟨d, h ▸ hd, hpar⟩
  · rintro ⟨d, hd, hpar⟩; exact ⟨d, h.symm ▸ hd, hpar⟩

/-- `IsAncestorOf` only inspects `getDom`. -/
theorem IsAncestorOf_congr {s₁ s₂ : SpecState}
    (h : ∀ did, s₁.getDom did = s₂.getDom did) :
    ∀ {a d : DomId}, IsAncestorOf s₁ a d ↔ IsAncestorOf s₂ a d := by
  have mp : ∀ {a d : DomId}, IsAncestorOf s₁ a d → IsAncestorOf s₂ a d := by
    intro a d hh
    induction hh with
    | direct hpa => exact .direct ((IsParentOf_congr (h _)).mp hpa)
    | step hpa _ ih => exact .step ((IsParentOf_congr (h _)).mp hpa) ih
  have mpr : ∀ {a d : DomId}, IsAncestorOf s₂ a d → IsAncestorOf s₁ a d := by
    intro a d hh
    induction hh with
    | direct hpa => exact .direct ((IsParentOf_congr (h _)).mpr hpa)
    | step hpa _ ih => exact .step ((IsParentOf_congr (h _)).mpr hpa) ih
  intro a d; exact ⟨mp, mpr⟩

theorem IsAncestorOrSelf_congr {s₁ s₂ : SpecState}
    (h : ∀ did, s₁.getDom did = s₂.getDom did) {a d : DomId} :
    IsAncestorOrSelf s₁ a d ↔ IsAncestorOrSelf s₂ a d := by
  unfold IsAncestorOrSelf
  refine ⟨?_, ?_⟩
  · rintro (rfl | h')
    · exact Or.inl rfl
    · exact Or.inr ((IsAncestorOf_congr h).mp h')
  · rintro (rfl | h')
    · exact Or.inl rfl
    · exact Or.inr ((IsAncestorOf_congr h).mpr h')

/-- HC is preserved when the `domains` arena is fully unchanged. -/
theorem hc_of_getDom_eq {s₁ s₂ : SpecState}
    (h : ∀ did, s₁.getDom did = s₂.getDom did) :
    HandlerCoverage s₁ → HandlerCoverage s₂ := by
  intro hHC did d hd hlive vec
  have hd1 : s₁.getDom did = some d := (h did).symm ▸ hd
  obtain ⟨aid, a, hanc, ha, halive, hvis⟩ := hHC did d hd1 hlive vec
  exact ⟨aid, a, (IsAncestorOrSelf_congr h).mp hanc, (h aid).symm ▸ ha, halive, hvis⟩

/-- `IsParentOf` is preserved by `updDomain x f` when `f` preserves the
    `parent` field on every domain. -/
theorem IsParentOf_updDomain_id
    {s : SpecState} {p c : DomId} (x : DomId) (f : Domain → Domain)
    (hf : ∀ d, (f d).parent = d.parent) :
    IsParentOf (s.updDomain x f) p c ↔ IsParentOf s p c := by
  have hget : ∀ did, (s.updDomain x f).getDom did = (s.getDom did).map f ∨
                     (s.updDomain x f).getDom did = s.getDom did := by
    intro did
    unfold SpecState.updDomain SpecState.getDom
    by_cases hxd : did = x
    · subst hxd; left; rw [Arena.find?_update_eq_map]
    · right; rw [Arena.find?_update_other _ _ _ _ hxd]
  refine ⟨?_, ?_⟩
  · rintro ⟨d, hd, hpar⟩
    rcases hget c with hh | hh
    · rw [hh] at hd
      rcases hpre : s.getDom c with _ | d_pre
      · rw [hpre] at hd; cases hd
      · rw [hpre] at hd
        simp only [Option.map_some, Option.some.injEq] at hd
        refine ⟨d_pre, hpre, ?_⟩
        rw [← hf d_pre, hd]; exact hpar
    · refine ⟨d, ?_, hpar⟩; rw [← hh]; exact hd
  · rintro ⟨d, hd, hpar⟩
    rcases hget c with hh | hh
    · refine ⟨f d, ?_, ?_⟩
      · rw [hh, hd]; simp
      · rw [hf d]; exact hpar
    · exact ⟨d, by rw [hh]; exact hd, hpar⟩

theorem IsAncestorOf_updDomain_id
    {s : SpecState} (x : DomId) (f : Domain → Domain)
    (hf : ∀ d, (f d).parent = d.parent) :
    ∀ {a d : DomId}, IsAncestorOf (s.updDomain x f) a d ↔ IsAncestorOf s a d := by
  have mp : ∀ {a d : DomId}, IsAncestorOf (s.updDomain x f) a d → IsAncestorOf s a d := by
    intro a d hh
    induction hh with
    | direct hpa => exact .direct ((IsParentOf_updDomain_id x f hf).mp hpa)
    | step hpa _ ih => exact .step ((IsParentOf_updDomain_id x f hf).mp hpa) ih
  have mpr : ∀ {a d : DomId}, IsAncestorOf s a d → IsAncestorOf (s.updDomain x f) a d := by
    intro a d hh
    induction hh with
    | direct hpa => exact .direct ((IsParentOf_updDomain_id x f hf).mpr hpa)
    | step hpa _ ih => exact .step ((IsParentOf_updDomain_id x f hf).mpr hpa) ih
  intro a d; exact ⟨mp, mpr⟩

theorem IsAncestorOrSelf_updDomain_id
    {s : SpecState} (x : DomId) (f : Domain → Domain)
    (hf : ∀ d, (f d).parent = d.parent) {a d : DomId} :
    IsAncestorOrSelf (s.updDomain x f) a d ↔ IsAncestorOrSelf s a d := by
  unfold IsAncestorOrSelf
  refine ⟨?_, ?_⟩
  · rintro (rfl | h')
    · exact Or.inl rfl
    · exact Or.inr ((IsAncestorOf_updDomain_id x f hf).mp h')
  · rintro (rfl | h')
    · exact Or.inl rfl
    · exact Or.inr ((IsAncestorOf_updDomain_id x f hf).mpr h')

-- ════════════════════════════════════════════════════════════════════
-- § 1.  Primitive preservation helpers
-- ════════════════════════════════════════════════════════════════════

theorem hc_updMem
    {s : SpecState} (h : HandlerCoverage s) (id : MemCapId) (g : MemCap → MemCap) :
    HandlerCoverage (s.updMem id g) :=
  hc_of_getDom_eq (s₁ := s) (s₂ := s.updMem id g) (fun _ => rfl) h

theorem hc_updDomCap
    {s : SpecState} (h : HandlerCoverage s) (id : DomCapId) (g : DomCap → DomCap) :
    HandlerCoverage (s.updDomCap id g) :=
  hc_of_getDom_eq (s₁ := s) (s₂ := s.updDomCap id g) (fun _ => rfl) h

theorem hc_updCore
    {s : SpecState} (h : HandlerCoverage s) (id : CoreId) (g : CoreState → CoreState) :
    HandlerCoverage (s.updCore id g) :=
  hc_of_getDom_eq (s₁ := s) (s₂ := s.updCore id g) (fun _ => rfl) h

theorem hc_freshMem
    {s : SpecState} (h : HandlerCoverage s) (c : MemCap) :
    HandlerCoverage (s.freshMem c).snd :=
  hc_of_getDom_eq (s₁ := s) (s₂ := (s.freshMem c).snd) (fun _ => rfl) h

theorem hc_freshDomCap
    {s : SpecState} (h : HandlerCoverage s) (dc : DomCap) :
    HandlerCoverage (s.freshDomCap dc).snd :=
  hc_of_getDom_eq (s₁ := s) (s₂ := (s.freshDomCap dc).snd) (fun _ => rfl) h

/-- Generic `updDomain` lift: any `f` that preserves `parent`, `policy`,
    and `status` for every existing domain preserves `HandlerCoverage`. -/
theorem hc_updDomain_id
    {s : SpecState} (h : HandlerCoverage s)
    (x : DomId) (f : Domain → Domain)
    (h_par : ∀ d, (f d).parent = d.parent)
    (h_pol : ∀ d, (f d).policy = d.policy)
    (h_sta : ∀ d, (f d).status = d.status) :
    HandlerCoverage (s.updDomain x f) := by
  intro did d' hd' hlive vec
  -- Recover a pre-state domain for `did` and a live witness for the source.
  have hd_pre : ∃ d_pre, s.getDom did = some d_pre ∧
      d'.parent = d_pre.parent ∧ d'.policy = d_pre.policy ∧
      d'.status = d_pre.status := by
    unfold SpecState.updDomain SpecState.getDom at hd'
    by_cases hxd : did = x
    · subst hxd
      rw [Arena.find?_update_eq_map] at hd'
      rcases hpre : s.domains.find? did with _ | d_pre
      · rw [hpre] at hd'; cases hd'
      · rw [hpre] at hd'
        simp only [Option.map_some, Option.some.injEq] at hd'
        refine ⟨d_pre, ?_, ?_, ?_, ?_⟩
        · unfold SpecState.getDom; exact hpre
        · rw [← hd']; exact h_par d_pre
        · rw [← hd']; exact h_pol d_pre
        · rw [← hd']; exact h_sta d_pre
    · rw [Arena.find?_update_other _ _ _ _ hxd] at hd'
      refine ⟨d', ?_, rfl, rfl, rfl⟩
      unfold SpecState.getDom; exact hd'
  obtain ⟨d_pre, hd_pre, hpar_eq, hpol_eq, hsta_eq⟩ := hd_pre
  have hlive_pre : d_pre.isLive := by
    unfold Domain.isLive at hlive ⊢; rw [hsta_eq] at hlive; exact hlive
  -- Pull a witness out of HC in the pre-state.
  obtain ⟨aid, a_pre, hanc_pre, ha_pre, ha_live_pre, ha_vis_pre⟩ :=
    h did d_pre hd_pre hlive_pre vec
  -- Transport the witness to the post-state.
  refine ⟨aid, if aid = x then f a_pre else a_pre, ?_, ?_, ?_, ?_⟩
  · -- IsAncestorOrSelf preserved
    exact (IsAncestorOrSelf_updDomain_id x f h_par).mpr hanc_pre
  · -- getDom resolves
    unfold SpecState.updDomain SpecState.getDom
    by_cases hax : aid = x
    · subst hax
      rw [Arena.find?_update_eq_map]
      unfold SpecState.getDom at ha_pre
      rw [ha_pre]; simp
    · rw [Arena.find?_update_other _ _ _ _ hax]
      unfold SpecState.getDom at ha_pre
      simp [hax, ha_pre]
  · -- isLive preserved
    by_cases hax : aid = x
    · simp only [hax, if_true]
      unfold Domain.isLive at ha_live_pre ⊢
      rw [h_sta a_pre]; exact ha_live_pre
    · simp [hax]; exact ha_live_pre
  · -- visibilityFor preserved
    by_cases hax : aid = x
    · simp only [hax, if_true]
      unfold Domain.visibilityFor at ha_vis_pre ⊢
      rw [h_pol a_pre]; exact ha_vis_pre
    · simp [hax]; exact ha_vis_pre

end ThemisCapa
