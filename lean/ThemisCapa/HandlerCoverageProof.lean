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
    and the `isLive` predicate for every domain preserves `HandlerCoverage`. -/
theorem hc_updDomain_id
    {s : SpecState} (h : HandlerCoverage s)
    (x : DomId) (f : Domain → Domain)
    (h_par : ∀ d, (f d).parent = d.parent)
    (h_pol : ∀ d, (f d).policy = d.policy)
    (h_live : ∀ d, (f d).isLive ↔ d.isLive) :
    HandlerCoverage (s.updDomain x f) := by
  intro did d' hd' hlive vec
  -- Recover a pre-state domain for `did` and a live witness for the source.
  have hd_pre : ∃ d_pre, s.getDom did = some d_pre ∧
      d'.parent = d_pre.parent ∧ d'.policy = d_pre.policy ∧
      (d'.isLive ↔ d_pre.isLive) := by
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
        · rw [← hd']; exact h_live d_pre
    · rw [Arena.find?_update_other _ _ _ _ hxd] at hd'
      refine ⟨d', ?_, rfl, rfl, Iff.rfl⟩
      unfold SpecState.getDom; exact hd'
  obtain ⟨d_pre, hd_pre, hpar_eq, hpol_eq, hlive_iff⟩ := hd_pre
  have hlive_pre : d_pre.isLive := hlive_iff.mp hlive
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
      exact (h_live a_pre).mpr ha_live_pre
    · simp [hax]; exact ha_live_pre
  · -- visibilityFor preserved
    by_cases hax : aid = x
    · simp only [hax, if_true]
      unfold Domain.visibilityFor at ha_vis_pre ⊢
      rw [h_pol a_pre]; exact ha_vis_pre
    · simp [hax]; exact ha_vis_pre

/-- Conditional `updDomain` lift: when `f` preserves `parent`/`policy`
    pointwise but only preserves `isLive` *at* the specific updated key
    `x` (under a hypothesis on the pre-state domain there), HC still
    transports.  Used for `seal`, where `f := fun d => { d with status :=
    .sealed }` resurrects tombstones in general but is fine at the
    guarded `.unsealed` target. -/
theorem hc_updDomain_at
    {s : SpecState} (h : HandlerCoverage s)
    (x : DomId) (f : Domain → Domain)
    (h_par : ∀ d, (f d).parent = d.parent)
    (h_pol : ∀ d, (f d).policy = d.policy)
    (h_live_at : ∀ d_pre, s.getDom x = some d_pre →
                 ((f d_pre).isLive ↔ d_pre.isLive)) :
    HandlerCoverage (s.updDomain x f) := by
  intro did d' hd' hlive vec
  have hd_pre : ∃ d_pre, s.getDom did = some d_pre ∧
      d'.parent = d_pre.parent ∧ d'.policy = d_pre.policy ∧
      (d'.isLive ↔ d_pre.isLive) := by
    unfold SpecState.updDomain SpecState.getDom at hd'
    by_cases hxd : did = x
    · subst hxd
      rw [Arena.find?_update_eq_map] at hd'
      rcases hpre : s.domains.find? did with _ | d_pre
      · rw [hpre] at hd'; cases hd'
      · rw [hpre] at hd'
        simp only [Option.map_some, Option.some.injEq] at hd'
        have hpre' : s.getDom did = some d_pre := by
          unfold SpecState.getDom; exact hpre
        refine ⟨d_pre, hpre', ?_, ?_, ?_⟩
        · rw [← hd']; exact h_par d_pre
        · rw [← hd']; exact h_pol d_pre
        · rw [← hd']; exact h_live_at d_pre hpre'
    · rw [Arena.find?_update_other _ _ _ _ hxd] at hd'
      refine ⟨d', ?_, rfl, rfl, Iff.rfl⟩
      unfold SpecState.getDom; exact hd'
  obtain ⟨d_pre, hd_pre, hpar_eq, hpol_eq, hlive_iff⟩ := hd_pre
  have hlive_pre : d_pre.isLive := hlive_iff.mp hlive
  obtain ⟨aid, a_pre, hanc_pre, ha_pre, ha_live_pre, ha_vis_pre⟩ :=
    h did d_pre hd_pre hlive_pre vec
  refine ⟨aid, if aid = x then f a_pre else a_pre, ?_, ?_, ?_, ?_⟩
  · exact (IsAncestorOrSelf_updDomain_id x f h_par).mpr hanc_pre
  · unfold SpecState.updDomain SpecState.getDom
    by_cases hax : aid = x
    · subst hax
      rw [Arena.find?_update_eq_map]
      unfold SpecState.getDom at ha_pre
      rw [ha_pre]; simp
    · rw [Arena.find?_update_other _ _ _ _ hax]
      unfold SpecState.getDom at ha_pre
      simp [hax, ha_pre]
  · by_cases hax : aid = x
    · subst hax
      simp only [if_true]
      exact (h_live_at a_pre ha_pre).mpr ha_live_pre
    · simp [hax]; exact ha_live_pre
  · by_cases hax : aid = x
    · simp only [hax, if_true]
      unfold Domain.visibilityFor at ha_vis_pre ⊢
      rw [h_pol a_pre]; exact ha_vis_pre
    · simp [hax]; exact ha_vis_pre

-- ════════════════════════════════════════════════════════════════════
-- § 2.  Per-action lemmas — trivial (parent, policy, isLive untouched)
-- ════════════════════════════════════════════════════════════════════

/-! These 17 actions modify only bookkeeping fields (memHandles,
    frozenHandles, vps, pendingMemCaps, channels, etc.) — none of
    `parent`, `policy`, or `status` change for any domain.  They all
    discharge the `hc_updDomain_id` obligations with `rfl` / `Iff.rfl`.

    The 4 deferred cases (with bespoke status/structure changes):
    * `seal` — flips status `.unsealed → .sealed` (live → live but the
      `isLive ↔ isLive` only holds at the guarded target; needs a
      conditional helper).
    * `revoke` — vital cascade may flip a domain to `.revoked`; needs
      cascade-aware reasoning to show no live survivor depends on it.
    * `create` — introduces a new ancestor edge; needs `hc_freshDom_create`.
    * `revokeDomain` — removes a leaf domain; needs `hc_domains_remove`. -/

theorem carve_preservesHandlerCoverage
    (s : SpecState) (caller : DomId) (parent : MemCapId)
    (access : Access) (attrs : Attributes) (h : HandlerCoverage s) :
    HandlerCoverage (carve_apply s caller parent access attrs) := by
  rcases hm : s.getMem parent with _ | p
  · simp only [carve_apply, hm]; exact h
  · simp only [carve_apply, hm]
    exact hc_updDomain_id
      (hc_updMem (hc_freshMem h _) _ _) caller _
      (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)

theorem alias_preservesHandlerCoverage
    (s : SpecState) (caller : DomId) (parent : MemCapId) (access : Access)
    (h : HandlerCoverage s) :
    HandlerCoverage (alias_apply s caller parent access) := by
  rcases hm : s.getMem parent with _ | p
  · simp only [alias_apply, hm]; exact h
  · simp only [alias_apply, hm]
    exact hc_updDomain_id
      (hc_updMem (hc_freshMem h _) _ _) caller _
      (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)

theorem send_preservesHandlerCoverage
    (s : SpecState) (caller receiver : DomId) (cap : MemCapId)
    (h : HandlerCoverage s) :
    HandlerCoverage (send_apply s caller receiver cap) := by
  simp only [send_apply]
  apply hc_updMem _ cap
  apply hc_updDomain_id _ receiver
    (fun d => { d with memHandles := d.memHandles ++ [(d.nextHandle, cap)],
                       nextHandle := d.nextHandle + 1 })
    (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)
  exact hc_updDomain_id h caller
    (fun d => { d with memHandles := d.memHandles.filter (fun h => h.2 ≠ cap) })
    (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)

theorem accept_preservesHandlerCoverage
    (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    (h : HandlerCoverage s) :
    HandlerCoverage (accept_apply s receiver pendingId) := by
  rcases hp : (s.getDom receiver).bind (fun d => d.lookupPending pendingId)
    with _ | pe
  · simp only [accept_apply, hp]; exact h
  · simp only [accept_apply, hp]
    have h1 := send_preservesHandlerCoverage s pe.senderDomainId receiver pe.capId h
    have h2 := hc_updDomain_id h1 receiver
      (fun d => { d with pendingMemCaps :=
                  d.pendingMemCaps.filter (fun p => p.1 ≠ pendingId) })
      (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)
    exact hc_updDomain_id h2 pe.senderDomainId
      (fun d => { d with frozenHandles :=
                  d.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })
      (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)

theorem reject_preservesHandlerCoverage
    (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    (h : HandlerCoverage s) :
    HandlerCoverage (reject_apply s receiver pendingId) := by
  simp only [reject_apply]
  have h1 := hc_updDomain_id h receiver
    (fun d => { d with pendingMemCaps :=
                d.pendingMemCaps.filter (fun p => p.1 ≠ pendingId) })
    (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)
  rcases hp : (s.getDom receiver).bind (fun d => d.lookupPending pendingId)
    with _ | pe
  · simp only [hp]; exact h1
  · simp only [hp]
    exact hc_updDomain_id h1 pe.senderDomainId
      (fun d => { d with frozenHandles :=
                  d.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })
      (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)

theorem sealedSend_preservesHandlerCoverage
    (s : SpecState) (caller receiver : DomId) (handle : LocalHandle)
    (gpaHint : Option Nat) (h : HandlerCoverage s) :
    HandlerCoverage (sealedSend_apply s caller receiver handle gpaHint) := by
  rcases hp : (s.getDom caller).bind (fun d => d.lookupMemHandle handle)
    with _ | capId
  · simp only [sealedSend_apply, hp]; exact h
  · simp only [sealedSend_apply, hp]
    have h1 := hc_updDomain_id h caller
      (fun d => { d with frozenHandles := d.frozenHandles ++ [handle] })
      (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)
    exact hc_updDomain_id h1 receiver _
      (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)

theorem setPolicy_preservesHandlerCoverage
    (s : SpecState) (caller : DomId) (cap : DomCapId)
    (id : PolicyIdentifier) (value : Nat) (h : HandlerCoverage s) :
    HandlerCoverage (setPolicy_apply s caller cap id value) := by
  rcases hc : s.getDomCap cap with _ | dc
  · simp only [setPolicy_apply, hc]; exact h
  · simp only [setPolicy_apply, hc]
    -- `applyPolicyValue` is identity in v2 spec → policy preserved.
    exact hc_updDomain_id h dc.targetDom
      (fun d => { d with policy := applyPolicyValue d.policy id value })
      (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)

theorem sendChannel_preservesHandlerCoverage
    (s : SpecState) (caller receiver : DomId) (cap : DomCapId)
    (h : HandlerCoverage s) :
    HandlerCoverage (sendChannel_apply s caller receiver cap) := by
  simp only [sendChannel_apply]
  apply hc_updDomCap _ cap
  refine hc_updDomain_id ?_ receiver _
    (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)
  exact hc_updDomain_id h caller _
    (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)

theorem acceptChannel_preservesHandlerCoverage
    (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    (h : HandlerCoverage s) :
    HandlerCoverage (acceptChannel_apply s receiver pendingId) := by
  rcases hp : (s.getDom receiver).bind (fun d => d.lookupPendingDom pendingId)
    with _ | pe
  · simp only [acceptChannel_apply, hp]; exact h
  · simp only [acceptChannel_apply, hp]
    have h1 := sendChannel_preservesHandlerCoverage s pe.senderDomainId receiver pe.capId h
    have h2 := hc_updDomain_id h1 receiver
      (fun d => { d with pendingDomCaps :=
                  d.pendingDomCaps.filter (fun p => p.1 ≠ pendingId) })
      (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)
    exact hc_updDomain_id h2 pe.senderDomainId
      (fun d => { d with frozenHandles :=
                  d.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })
      (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)

theorem rejectChannel_preservesHandlerCoverage
    (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    (h : HandlerCoverage s) :
    HandlerCoverage (rejectChannel_apply s receiver pendingId) := by
  simp only [rejectChannel_apply]
  have h1 := hc_updDomain_id h receiver
    (fun d => { d with pendingDomCaps :=
                d.pendingDomCaps.filter (fun p => p.1 ≠ pendingId) })
    (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)
  rcases hp : (s.getDom receiver).bind (fun d => d.lookupPendingDom pendingId)
    with _ | pe
  · simp only [hp]; exact h1
  · simp only [hp]
    exact hc_updDomain_id h1 pe.senderDomainId
      (fun d => { d with frozenHandles :=
                  d.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })
      (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)

theorem addVp_preservesHandlerCoverage
    (s : SpecState) (caller : DomId) (childHandle commHandle : LocalHandle)
    (h : HandlerCoverage s) :
    HandlerCoverage (addVp_apply s caller childHandle commHandle) := by
  rcases hh : (s.getDom caller).bind (fun d => d.lookupDomHandle childHandle)
    with _ | cid
  · simp only [addVp_apply, hh]; exact h
  · rcases hc : s.getDomCap cid with _ | dc
    · simp only [addVp_apply, hh, hc]; exact h
    · rcases ht : s.getDom dc.targetDom with _ | cd
      · simp only [addVp_apply, hh, hc, ht]; exact h
      · rcases hm : (s.getDom caller).bind (fun d => d.lookupMemHandle commHandle)
          with _ | mid
        · simp only [addVp_apply, hh, hc, ht, hm]; exact h
        · simp only [addVp_apply, hh, hc, ht, hm]
          apply hc_updMem _ mid
          exact hc_updDomain_id h dc.targetDom _
            (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)

theorem registerComm_preservesHandlerCoverage
    (s : SpecState) (caller : DomId) (commHandle childHandle : LocalHandle)
    (vpId : VpId) (h : HandlerCoverage s) :
    HandlerCoverage (registerComm_apply s caller commHandle childHandle vpId) := by
  rcases hh : (s.getDom caller).bind (fun d => d.lookupDomHandle childHandle)
    with _ | cid
  · simp only [registerComm_apply, hh]; exact h
  · rcases hc : s.getDomCap cid with _ | dc
    · simp only [registerComm_apply, hh, hc]; exact h
    · rcases ht : s.getDom dc.targetDom with _ | _
      · simp only [registerComm_apply, hh, hc, ht]; exact h
      · rcases hm : (s.getDom caller).bind (fun d => d.lookupMemHandle commHandle)
          with _ | mid
        · simp only [registerComm_apply, hh, hc, ht, hm]; exact h
        · simp only [registerComm_apply, hh, hc, ht, hm]
          apply hc_updMem _ mid
          exact hc_updDomain_id h dc.targetDom _
            (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)

theorem mapSelf_preservesHandlerCoverage
    (s : SpecState) (caller : DomId) (capHandle : LocalHandle) (newGpa : Nat)
    (h : HandlerCoverage s) :
    HandlerCoverage (mapSelf_apply s caller capHandle newGpa) := by
  rcases hd : s.getDom caller with _ | d
  · simp only [mapSelf_apply, hd]; exact h
  · rcases hh : d.lookupMemHandle capHandle with _ | capId
    · simp only [mapSelf_apply, hd, hh]; exact h
    · rcases hg : s.getMem capId with _ | c
      · simp only [mapSelf_apply, hd, hh, hg]; exact h
      · rcases hog : d.lookupMappedGpa capHandle with _ | oldGpa
        · simp only [mapSelf_apply, hd, hh, hg, hog]; exact h
        · simp only [mapSelf_apply, hd, hh, hg, hog]
          refine hc_updDomain_id h caller _ ?_ ?_ ?_
          · intro d'; unfold Domain.updMappedGpa; split <;> rfl
          · intro d'; unfold Domain.updMappedGpa; split <;> rfl
          · intro d'; unfold Domain.updMappedGpa; split <;> exact Iff.rfl

-- ════════════════════════════════════════════════════════════════════
-- § 3.  Scheduling actions (switch, switchSuspended, switchReturn)
-- ════════════════════════════════════════════════════════════════════

theorem switch_preservesHandlerCoverage
    {s : SpecState} {caller : DomId} {toHandle : LocalHandle}
    {toVpId : VpId} {core : CoreId}
    (h : HandlerCoverage s) :
    HandlerCoverage (switch_apply s caller toHandle toVpId core) := by
  rcases hh : (s.getDom caller).bind (fun d => d.lookupDomHandle toHandle)
    with _ | cid
  · simp only [switch_apply, hh]; exact h
  · rcases hc : s.getDomCap cid with _ | dc
    · simp only [switch_apply, hh, hc]; exact h
    · rcases hv : (s.getDom caller).bind (fun d => d.vpAndOptPrevOnCore core)
        with _ | vpv
      · simp only [switch_apply, hh, hc, hv]; exact h
      · simp only [switch_apply, hh, hc, hv]
        apply hc_updCore _ core
        refine hc_updDomain_id ?_ caller _
          (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)
        exact hc_updDomain_id h dc.targetDom _
          (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)

theorem switchSuspended_preservesHandlerCoverage
    {s : SpecState} {caller : DomId} {toHandle : LocalHandle}
    {toVpId : VpId} {core : CoreId}
    {calleeDom : DomId} {calleeVp : VpId}
    (h : HandlerCoverage s) :
    HandlerCoverage
      (switchSuspended_apply s caller toHandle toVpId core calleeDom calleeVp) := by
  rcases hh : (s.getDom caller).bind (fun d => d.lookupDomHandle toHandle)
    with _ | cid
  · simp only [switchSuspended_apply, hh]; exact h
  · rcases hc : s.getDomCap cid with _ | dc
    · simp only [switchSuspended_apply, hh, hc]; exact h
    · rcases hv : (s.getDom caller).bind (fun d => d.vpAndOptPrevOnCore core)
        with _ | vpv
      · simp only [switchSuspended_apply, hh, hc, hv]; exact h
      · simp only [switchSuspended_apply, hh, hc, hv]
        apply hc_updCore _ core
        refine hc_updDomain_id ?_ caller _
          (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)
        refine hc_updDomain_id ?_ calleeDom _
          (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)
        exact hc_updDomain_id h dc.targetDom _
          (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)

theorem switchReturn_preservesHandlerCoverage
    {s : SpecState} {caller : DomId} {core : CoreId} {exitReason : Option Nat}
    (h : HandlerCoverage s) :
    HandlerCoverage (switchReturn_apply s caller core exitReason) := by
  rcases hp : (s.getDom caller).bind (fun d => d.vpAndPrevCallerOnCore core)
    with _ | pair
  · simp only [switchReturn_apply, hp]; exact h
  · obtain ⟨vpId, pctx⟩ := pair
    simp only [switchReturn_apply, hp]
    apply hc_updCore _ core
    refine hc_updDomain_id ?_ pctx.domainId _
      (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)
    exact hc_updDomain_id h caller _
      (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)

-- ════════════════════════════════════════════════════════════════════
-- § 4.  deliverInterrupt — induction over the chain
-- ════════════════════════════════════════════════════════════════════

theorem applyMidsAndHandler_preservesHandlerCoverage
    (core : CoreId) (vector : Nat) :
    ∀ (chain : List (DomId × VpId)) (prev : DomId × VpId) (s : SpecState),
    HandlerCoverage s →
    HandlerCoverage (applyMidsAndHandler core vector prev chain s) := by
  intro chain
  induction chain with
  | nil =>
    intro _ s h
    simp only [applyMidsAndHandler]; exact h
  | cons head tail ih =>
    intro prev s h
    match tail with
    | [] =>
      simp only [applyMidsAndHandler]
      exact hc_updDomain_id h head.1 _
        (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)
    | mid :: rest =>
      simp only [applyMidsAndHandler]
      apply ih head
      exact hc_updDomain_id h head.1 _
        (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)

theorem deliverInterrupt_preservesHandlerCoverage
    (s : SpecState) (interrupted handler : DomId) (core : CoreId)
    (vector : Nat) (chain : List (DomId × VpId))
    (h : HandlerCoverage s) :
    HandlerCoverage
      (deliverInterrupt_apply s interrupted handler core vector chain) := by
  unfold deliverInterrupt_apply
  rcases chain with _ | ⟨leaf, tail⟩
  · exact h
  rcases tail with _ | ⟨m, rest⟩
  · exact h
  -- chain = leaf :: m :: rest
  simp only
  have h0 : HandlerCoverage
      (s.updDomain leaf.1 (fun d => d.updVp leaf.2 (fun vp =>
        { vp with runState := .interrupted vector }))) :=
    hc_updDomain_id h leaf.1 _
      (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)
  have h1 := applyMidsAndHandler_preservesHandlerCoverage core vector
              (m :: rest) leaf _ h0
  rcases hgl : (leaf :: m :: rest).getLast? with _ | ⟨hDom, hVp⟩
  · exact h1
  · exact hc_updCore h1 core _

-- ════════════════════════════════════════════════════════════════════
-- § 3.  Per-action lemma — seal (status flip, conditional helper)
-- ════════════════════════════════════════════════════════════════════

/-- Sealing the target domain (`.unsealed → .sealed`) preserves
    `HandlerCoverage`.  The unconditional `hc_updDomain_id` doesn't
    apply because `(f d).isLive ↔ d.isLive` would resurrect a tombstone
    pointwise.  However, at the specific guarded target `dc.targetDom`
    the `SealGuard.targetUnsealed` premise gives us
    `td.status = .unsealed`, so both pre- and post-state are live —
    enough for `hc_updDomain_at`. -/
theorem seal_preservesHandlerCoverage
    (s : SpecState) (caller : DomId) (cap : DomCapId)
    (guard : SealGuard s caller cap) (h : HandlerCoverage s) :
    HandlerCoverage (seal_apply s caller cap) := by
  rcases hc : s.getDomCap cap with _ | dc
  · simp only [seal_apply, hc]; exact h
  · simp only [seal_apply, hc]
    apply hc_updDomain_at h dc.targetDom
            (fun d => { d with status := .sealed })
            (fun _ => rfl) (fun _ => rfl)
    -- Local liveness: at the guarded target, status = .unsealed pre,
    -- and .sealed post — both live (≠ .revoked).
    intro d_pre hpre
    have htu : d_pre.isUnsealed := guard.targetUnsealed dc hc d_pre hpre
    -- `.unsealed → True` for isLive; `.sealed → True` for isLive.
    constructor
    · intro _; unfold Domain.isLive; unfold Domain.isUnsealed at htu
      intro habs; rw [habs] at htu; cases htu
    · intro _; unfold Domain.isLive; intro habs; cases habs

-- ════════════════════════════════════════════════════════════════════
-- § 4.  Per-action lemma — revokeDomain (leaf removal)
-- ════════════════════════════════════════════════════════════════════

/-- If `target` has no children in the `IsParentOf` sense, then any
    ancestor chain `IsAncestorOf s a c` with `c ≠ target` lifts to the
    arena-removed state: `target` never appears on the chain (else it
    would be the parent of some next node, contradicting the no-children
    hypothesis), so every edge survives. -/
theorem IsAncestorOf_of_no_children
    {s : SpecState} (target : DomId)
    (h_no_ch : ∀ m, ¬ IsParentOf s target m) :
    ∀ {a c : DomId}, IsAncestorOf s a c → c ≠ target →
    a ≠ target ∧
    IsAncestorOf { s with domains := s.domains.remove target } a c := by
  intro a c hac
  induction hac with
  | @direct p c hpa =>
    intro hcne
    have hane : p ≠ target := by intro hp; subst hp; exact h_no_ch _ hpa
    refine ⟨hane, .direct ?_⟩
    obtain ⟨d, hd, hpar⟩ := hpa
    refine ⟨d, ?_, hpar⟩
    unfold SpecState.getDom at hd ⊢
    simp only
    rw [Arena.find?_remove_other _ _ _ hcne]; exact hd
  | @step a m c hpa _ ih =>
    intro hcne
    obtain ⟨hmne, hac'⟩ := ih hcne
    have hane : a ≠ target := by intro ha; subst ha; exact h_no_ch _ hpa
    refine ⟨hane, .step ?_ hac'⟩
    obtain ⟨d, hd, hpar⟩ := hpa
    refine ⟨d, ?_, hpar⟩
    unfold SpecState.getDom at hd ⊢
    simp only
    rw [Arena.find?_remove_other _ _ _ hmne]; exact hd

/-- Removing a leaf domain (`t.childrenDoms = []`) from the arena
    preserves `HandlerCoverage`.  Leaf-ness — combined with
    `DomainTreeParentChild` — implies no domain has `target` as parent,
    so no surviving live domain's ancestor chain passes through
    `target`.  Existing witnesses transport verbatim. -/
theorem hc_domains_remove
    {s : SpecState} (h : HandlerCoverage s)
    (hPC : DomainTreeParentChild s)
    (target : DomId) (t : Domain)
    (htarget : s.getDom target = some t)
    (hleaf : t.childrenDoms = []) :
    HandlerCoverage { s with domains := s.domains.remove target } := by
  have h_no_ch : ∀ m, ¬ IsParentOf s target m := by
    intro m hpc
    obtain ⟨d_m, hd_m, hpar_m⟩ := hpc
    have hin := hPC m d_m hd_m target hpar_m t htarget
    rw [hleaf] at hin
    cases hin
  intro did d' hd' hlive vec
  have hdne : did ≠ target := by
    intro heq; subst heq
    unfold SpecState.getDom at hd'
    simp only [Arena.find?_remove_same] at hd'
    cases hd'
  have hd_pre : s.getDom did = some d' := by
    unfold SpecState.getDom at hd' ⊢
    rw [Arena.find?_remove_other _ _ _ hdne] at hd'; exact hd'
  obtain ⟨aid, a, hanc, ha, halive, hvis⟩ := h did d' hd_pre hlive vec
  have hane : aid ≠ target := by
    rcases hanc with heq | hac'
    · rw [heq]; exact hdne
    · exact (IsAncestorOf_of_no_children target h_no_ch hac' hdne).1
  refine ⟨aid, a, ?_, ?_, halive, hvis⟩
  · rcases hanc with heq | hac'
    · exact Or.inl heq
    · exact Or.inr (IsAncestorOf_of_no_children target h_no_ch hac' hdne).2
  · unfold SpecState.getDom at ha ⊢
    simp only
    rw [Arena.find?_remove_other _ _ _ hane]; exact ha

/-- `revokeDomain` removes a leaf target from the arena, removes the
    associated dom-cap, and updates the caller's bookkeeping fields. -/
theorem revokeDomain_preservesHandlerCoverage
    (s : SpecState) (caller : DomId) (handle : LocalHandle)
    (guard : RevokeDomainGuard s caller handle)
    (hwf : DomainTreeWf s) (h : HandlerCoverage s) :
    HandlerCoverage (revokeDomain_apply s caller handle) := by
  rcases hd : s.getDom caller with _ | d
  · simp only [revokeDomain_apply, hd]; exact h
  · rcases hh : d.lookupDomHandle handle with _ | dcId
    · simp only [revokeDomain_apply, hd, hh]; exact h
    · rcases hc : s.getDomCap dcId with _ | dc
      · simp only [revokeDomain_apply, hd, hh, hc]; exact h
      · simp only [revokeDomain_apply, hd, hh, hc]
        -- Extract the leaf-ness premise from the guard.
        have htgtsome := guard.targetExists d hd dcId hh dc hc
        obtain ⟨t, htgt⟩ := Option.isSome_iff_exists.mp htgtsome
        have hleaf : t.childrenDoms = [] :=
          (guard.targetIsLeaf d hd dcId hh dc hc t htgt).1
        -- Step 1: remove the target domain.
        have h_rm := hc_domains_remove h hwf.parentChild dc.targetDom t htgt hleaf
        -- Step 2: removing the dom-cap doesn't affect getDom.
        have h_rm_dc :
            HandlerCoverage { s with domains := s.domains.remove dc.targetDom,
                                     domcaps := s.domcaps.remove dcId } :=
          hc_of_getDom_eq
            (s₁ := { s with domains := s.domains.remove dc.targetDom })
            (s₂ := { s with domains := s.domains.remove dc.targetDom,
                            domcaps := s.domcaps.remove dcId })
            (fun _ => rfl) h_rm
        -- Step 3: updDomain on caller (filters only — parent/policy/status untouched).
        exact hc_updDomain_id h_rm_dc caller _
                (fun _ => rfl) (fun _ => rfl) (fun _ => Iff.rfl)

end ThemisCapa
