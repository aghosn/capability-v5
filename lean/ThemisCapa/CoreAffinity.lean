/-
  ThemisCapa.CoreAffinity — preservation of the core-affinity invariant.

  ## Statement
  Every VP that is currently in `VpRunState.running c _` belongs to a
  domain whose policy permits `c`. See `Invariants.lean`.

  ## Top theorem
  `step_preservesCoreAffinity : CoreAffinity s → step s a s' → CoreAffinity s'`.
  Most actions don't touch `d.vps` or `d.policy`; the four scheduling
  actions (`switch`, `switchSuspended`, `switchReturn`,
  `deliverInterrupt`) introduce new `.running` states whose
  core-allowance is supplied by their respective guards
  (`SwitchGuard.coreAllowed`, `SwitchSuspendedGuard.coreAllowed`,
  `SwitchReturnGuard.prevCoreAllowed`,
  `DeliverInterruptGuard.handlerCoreAllowed`).
-/
import ThemisCapa.Step
import ThemisCapa.Invariants

namespace ThemisCapa
open Arena

-- ════════════════════════════════════════════════════════════════════
-- § 1.  Primitive preservation helpers
-- ════════════════════════════════════════════════════════════════════

theorem coreAffinity_updMem
    {s : SpecState} (h : CoreAffinity s) (id : MemCapId) (g : MemCap → MemCap) :
    CoreAffinity (s.updMem id g) := h

theorem coreAffinity_updDomCap
    {s : SpecState} (h : CoreAffinity s) (id : DomCapId) (g : DomCap → DomCap) :
    CoreAffinity (s.updDomCap id g) := h

theorem coreAffinity_updCore
    {s : SpecState} (h : CoreAffinity s) (id : CoreId) (g : CoreState → CoreState) :
    CoreAffinity (s.updCore id g) := h

theorem coreAffinity_freshMem
    {s : SpecState} (h : CoreAffinity s) (c : MemCap) :
    CoreAffinity (s.freshMem c).snd := h

theorem coreAffinity_freshDomCap
    {s : SpecState} (h : CoreAffinity s) (dc : DomCap) :
    CoreAffinity (s.freshDomCap dc).snd := h

/-- Generic `updDomain` lift: the updated domain record must
    (a) preserve `policy.cores`, and
    (b) for every `.running` VP in the post-record, that VP's core
        must be in the (preserved) policy. -/
theorem coreAffinity_updDomain
    {s : SpecState} (h : CoreAffinity s) (x : DomId) (f : Domain → Domain)
    (hf : ∀ d_pre, s.getDom x = some d_pre →
            (f d_pre).policy.cores = d_pre.policy.cores ∧
            ∀ vp ∈ (f d_pre).vps,
              ∀ c caller, vp.runState = VpRunState.running c caller →
              c ∈ (f d_pre).policy.cores) :
    CoreAffinity (s.updDomain x f) := by
  intro did d hd
  unfold SpecState.updDomain SpecState.getDom at hd
  by_cases heq : did = x
  · subst heq
    rw [Arena.find?_update_eq_map] at hd
    rcases hpre : s.domains.find? did with _ | d_pre
    · rw [hpre] at hd; cases hd
    · rw [hpre] at hd
      simp only [Option.map_some, Option.some.injEq] at hd
      rw [← hd]
      exact (hf d_pre hpre).2
  · rw [Arena.find?_update_other _ _ _ _ heq] at hd
    exact h did d hd

/-- Specialization: `f` leaves both `vps` and `policy` untouched. -/
theorem coreAffinity_updDomain_id
    {s : SpecState} (h : CoreAffinity s) (x : DomId) (f : Domain → Domain)
    (h1 : ∀ d, (f d).vps = d.vps)
    (h2 : ∀ d, (f d).policy = d.policy) :
    CoreAffinity (s.updDomain x f) := by
  apply coreAffinity_updDomain h
  intro d_pre hpre
  refine ⟨by rw [h2], ?_⟩
  rw [h1, h2]
  exact h x d_pre hpre

/-- Allocating a fresh domain with `vps = []` preserves `CoreAffinity`. -/
theorem coreAffinity_freshDom_emptyVps
    {s : SpecState} (h : CoreAffinity s) (dm : Domain) (hv : dm.vps = []) :
    CoreAffinity (s.freshDom dm).snd := by
  intro did d hd
  unfold SpecState.freshDom SpecState.getDom at hd
  by_cases heq : did = s.nextDomId
  · subst heq
    rw [Arena.find?_insert_same] at hd
    cases hd
    intro vp hvp
    rw [hv] at hvp; cases hvp
  · rw [Arena.find?_insert_other _ _ _ _ heq] at hd
    exact h did d hd

theorem coreAffinity_domains_remove
    {s : SpecState} (h : CoreAffinity s) (target : DomId) :
    CoreAffinity { s with domains := s.domains.remove target } := by
  intro did d hd
  unfold SpecState.getDom at hd
  by_cases heq : did = target
  · subst heq
    rw [Arena.find?_remove_same] at hd; cases hd
  · rw [Arena.find?_remove_other _ _ _ heq] at hd
    exact h did d hd

theorem coreAffinity_domcaps_remove
    {s : SpecState} (h : CoreAffinity s) (target : DomCapId) :
    CoreAffinity { s with domcaps := s.domcaps.remove target } := h

/-- Generic `updDomain (updVp vpId g)` lift: the only obligation is to
    show that the post-state of the touched VP — when in `.running c _` —
    has `c ∈ d_pre.policy.cores`. Other VPs are preserved by `h`. -/
theorem coreAffinity_updDomain_updVp
    {s : SpecState} (h : CoreAffinity s) (x : DomId) (vpId : VpId)
    (g : VProcessor → VProcessor)
    (hg : ∀ d_pre, s.getDom x = some d_pre →
            ∀ vp_pre ∈ d_pre.vps, vp_pre.id = vpId →
            ∀ c caller, (g vp_pre).runState = .running c caller →
            c ∈ d_pre.policy.cores) :
    CoreAffinity (s.updDomain x (fun d => d.updVp vpId g)) := by
  apply coreAffinity_updDomain h x (fun d => d.updVp vpId g)
  intro d_pre hpre
  refine ⟨rfl, ?_⟩
  intro vp hvp c caller hrun
  simp only [Domain.updVp, List.mem_map] at hvp
  obtain ⟨vp_pre, hvp_pre, hvp_eq⟩ := hvp
  by_cases heq : vp_pre.id = vpId
  · rw [if_pos heq] at hvp_eq
    rw [← hvp_eq] at hrun
    exact hg d_pre hpre vp_pre hvp_pre heq c caller hrun
  · rw [if_neg heq] at hvp_eq
    rw [← hvp_eq] at hrun
    exact h x d_pre hpre vp_pre hvp_pre c caller hrun

/-- Variant of `coreAffinity_updDomain_updVp` where `g` is allowed to
    preserve the runState. The hypothesis is split into two:
    - if `(g vp_pre).runState = .running c _`, either the pre-VP was
      already in `.running c _` (use outer `h`), or supply `hg`. -/
theorem coreAffinity_updDomain_updVp_preserveOrAllowed
    {s : SpecState} (h : CoreAffinity s) (x : DomId) (vpId : VpId)
    (g : VProcessor → VProcessor)
    (hg : ∀ d_pre, s.getDom x = some d_pre →
            ∀ vp_pre ∈ d_pre.vps, vp_pre.id = vpId →
            ∀ c caller, (g vp_pre).runState = .running c caller →
            vp_pre.runState = .running c caller ∨ c ∈ d_pre.policy.cores) :
    CoreAffinity (s.updDomain x (fun d => d.updVp vpId g)) := by
  apply coreAffinity_updDomain_updVp h x vpId g
  intro d_pre hpre vp_pre hvp_pre heq c caller hrun
  rcases hg d_pre hpre vp_pre hvp_pre heq c caller hrun with hpre_run | hok
  · exact h x d_pre hpre vp_pre hvp_pre c caller hpre_run
  · exact hok

-- ════════════════════════════════════════════════════════════════════
-- § 2.  Per-action lemmas — trivial (no vps/policy touched)
-- ════════════════════════════════════════════════════════════════════

theorem carve_preservesCoreAffinity
    (s : SpecState) (caller : DomId) (parent : MemCapId)
    (access : Access) (attrs : Attributes) (h : CoreAffinity s) :
    CoreAffinity (carve_apply s caller parent access attrs) := by
  rcases hm : s.getMem parent with _ | p
  · simp only [carve_apply, hm]; exact h
  · simp only [carve_apply, hm]
    exact coreAffinity_updDomain_id
      (coreAffinity_updMem (coreAffinity_freshMem h _) _ _) caller _
      (fun _ => rfl) (fun _ => rfl)

theorem alias_preservesCoreAffinity
    (s : SpecState) (caller : DomId) (parent : MemCapId) (access : Access)
    (h : CoreAffinity s) :
    CoreAffinity (alias_apply s caller parent access) := by
  rcases hm : s.getMem parent with _ | p
  · simp only [alias_apply, hm]; exact h
  · simp only [alias_apply, hm]
    exact coreAffinity_updDomain_id
      (coreAffinity_updMem (coreAffinity_freshMem h _) _ _) caller _
      (fun _ => rfl) (fun _ => rfl)

theorem revoke_preservesCoreAffinity
    (s : SpecState) (caller : DomId) (target : MemCapId) (h : CoreAffinity s) :
    CoreAffinity (revoke_apply s caller target) := by
  rcases hm : s.getMem target with _ | t
  · simp only [revoke_apply, hm]; exact h
  · rcases hp : t.parent with _ | pid
    · simp only [revoke_apply, hm, hp]; exact h
    · simp only [revoke_apply, hm, hp]
      have h1 : CoreAffinity { s with memcaps := s.memcaps.remove target } := h
      have h2 := coreAffinity_updMem h1 pid (fun p =>
        { p with childrenIds := p.childrenIds.filter (· ≠ target) })
      have h3 := coreAffinity_updDomain_id h2 t.owner
        (fun d => { d with memHandles := d.memHandles.filter (fun h => h.2 ≠ target) })
        (fun _ => rfl) (fun _ => rfl)
      by_cases hv : t.region.attributes.vital
      · rw [if_pos hv]
        exact coreAffinity_updDomain_id h3 t.owner
          (fun d => { d with status := .revoked })
          (fun _ => rfl) (fun _ => rfl)
      · rw [if_neg hv]; exact h3

theorem send_preservesCoreAffinity
    (s : SpecState) (caller receiver : DomId) (cap : MemCapId)
    (h : CoreAffinity s) :
    CoreAffinity (send_apply s caller receiver cap) := by
  simp only [send_apply]
  apply coreAffinity_updMem _ cap _
  apply coreAffinity_updDomain_id _ receiver
    (fun d => { d with memHandles := d.memHandles ++ [(d.nextHandle, cap)],
                       nextHandle := d.nextHandle + 1 })
    (fun _ => rfl) (fun _ => rfl)
  exact coreAffinity_updDomain_id h caller
    (fun d => { d with memHandles := d.memHandles.filter (fun h => h.2 ≠ cap) })
    (fun _ => rfl) (fun _ => rfl)

theorem seal_preservesCoreAffinity
    (s : SpecState) (caller : DomId) (cap : DomCapId) (h : CoreAffinity s) :
    CoreAffinity (seal_apply s caller cap) := by
  rcases hc : s.getDomCap cap with _ | dc
  · simp only [seal_apply, hc]; exact h
  · simp only [seal_apply, hc]
    exact coreAffinity_updDomain_id h dc.targetDom
      (fun d => { d with status := .sealed })
      (fun _ => rfl) (fun _ => rfl)

theorem accept_preservesCoreAffinity
    (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    (h : CoreAffinity s) :
    CoreAffinity (accept_apply s receiver pendingId) := by
  rcases hp : (s.getDom receiver).bind (fun d => d.lookupPending pendingId)
    with _ | pe
  · simp only [accept_apply, hp]; exact h
  · simp only [accept_apply, hp]
    have h1 := send_preservesCoreAffinity s pe.senderDomainId receiver pe.capId h
    have h2 := coreAffinity_updDomain_id h1 receiver
      (fun d => { d with pendingMemCaps :=
                  d.pendingMemCaps.filter (fun p => p.1 ≠ pendingId) })
      (fun _ => rfl) (fun _ => rfl)
    exact coreAffinity_updDomain_id h2 pe.senderDomainId
      (fun d => { d with frozenHandles :=
                  d.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })
      (fun _ => rfl) (fun _ => rfl)

theorem reject_preservesCoreAffinity
    (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    (h : CoreAffinity s) :
    CoreAffinity (reject_apply s receiver pendingId) := by
  simp only [reject_apply]
  have h1 := coreAffinity_updDomain_id h receiver
    (fun d => { d with pendingMemCaps :=
                d.pendingMemCaps.filter (fun p => p.1 ≠ pendingId) })
    (fun _ => rfl) (fun _ => rfl)
  rcases hp : (s.getDom receiver).bind (fun d => d.lookupPending pendingId)
    with _ | pe
  · simp only [hp]; exact h1
  · simp only [hp]
    exact coreAffinity_updDomain_id h1 pe.senderDomainId
      (fun d => { d with frozenHandles :=
                  d.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })
      (fun _ => rfl) (fun _ => rfl)

theorem sealedSend_preservesCoreAffinity
    (s : SpecState) (caller receiver : DomId) (handle : LocalHandle)
    (gpaHint : Option Nat) (h : CoreAffinity s) :
    CoreAffinity (sealedSend_apply s caller receiver handle gpaHint) := by
  rcases hp : (s.getDom caller).bind (fun d => d.lookupMemHandle handle)
    with _ | capId
  · simp only [sealedSend_apply, hp]; exact h
  · simp only [sealedSend_apply, hp]
    have h1 := coreAffinity_updDomain_id h caller
      (fun d => { d with frozenHandles := d.frozenHandles ++ [handle] })
      (fun _ => rfl) (fun _ => rfl)
    exact coreAffinity_updDomain_id h1 receiver
      (fun d =>
        let pid := d.nextPendingId
        let pe  : PendingMemCap :=
          { capId := capId, senderDomainId := caller,
            senderHandle := handle, gpaHint := gpaHint }
        { d with pendingMemCaps := d.pendingMemCaps ++ [(pid, pe)],
                 nextPendingId  := pid + 1 })
      (fun _ => rfl) (fun _ => rfl)

theorem create_preservesCoreAffinity
    (s : SpecState) (caller : DomId) (policy : DomainPolicy) (h : CoreAffinity s) :
    CoreAffinity (create_apply s caller policy) := by
  simp only [create_apply]
  exact coreAffinity_updDomain_id
    (coreAffinity_freshDomCap
      (coreAffinity_freshDom_emptyVps h _ rfl) _) caller
    (fun d => { d with domHandles := d.domHandles ++ [(d.nextHandle, s.nextDomCapId)],
                       childrenDoms := d.childrenDoms ++ [s.nextDomId],
                       nextHandle := d.nextHandle + 1 })
    (fun _ => rfl) (fun _ => rfl)

theorem revokeDomain_preservesCoreAffinity
    (s : SpecState) (caller : DomId) (handle : LocalHandle) (h : CoreAffinity s) :
    CoreAffinity (revokeDomain_apply s caller handle) := by
  rcases hd : s.getDom caller with _ | d
  · simp only [revokeDomain_apply, hd]; exact h
  · rcases hh : d.lookupDomHandle handle with _ | dcId
    · simp only [revokeDomain_apply, hd, hh]; exact h
    · rcases hc : s.getDomCap dcId with _ | dc
      · simp only [revokeDomain_apply, hd, hh, hc]; exact h
      · simp only [revokeDomain_apply, hd, hh, hc]
        exact coreAffinity_updDomain_id
          (coreAffinity_domains_remove
            (coreAffinity_domcaps_remove h _) dc.targetDom) caller
          (fun d =>
            { d with domHandles := d.domHandles.filter (fun h => h.2 ≠ dcId),
                     childrenDoms := d.childrenDoms.filter (· ≠ dc.targetDom) })
          (fun _ => rfl) (fun _ => rfl)

theorem setPolicy_preservesCoreAffinity
    (s : SpecState) (caller : DomId) (cap : DomCapId)
    (id : PolicyIdentifier) (value : Nat) (h : CoreAffinity s) :
    CoreAffinity (setPolicy_apply s caller cap id value) := by
  rcases hc : s.getDomCap cap with _ | dc
  · simp only [setPolicy_apply, hc]; exact h
  · simp only [setPolicy_apply, hc]
    -- `applyPolicyValue` is identity in v2 spec → policy.cores unchanged.
    exact coreAffinity_updDomain_id h dc.targetDom
      (fun d => { d with policy := applyPolicyValue d.policy id value })
      (fun _ => rfl) (fun _ => rfl)

theorem sendChannel_preservesCoreAffinity
    (s : SpecState) (caller receiver : DomId) (cap : DomCapId)
    (h : CoreAffinity s) :
    CoreAffinity (sendChannel_apply s caller receiver cap) := by
  simp only [sendChannel_apply]
  apply coreAffinity_updDomCap _ cap
  apply coreAffinity_updDomain_id _ receiver
    (fun d => { d with domHandles := d.domHandles ++ [(d.nextHandle, cap)],
                       nextHandle := d.nextHandle + 1 })
    (fun _ => rfl) (fun _ => rfl)
  exact coreAffinity_updDomain_id h caller
    (fun d => { d with domHandles := d.domHandles.filter (fun h => h.2 ≠ cap) })
    (fun _ => rfl) (fun _ => rfl)

theorem acceptChannel_preservesCoreAffinity
    (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    (h : CoreAffinity s) :
    CoreAffinity (acceptChannel_apply s receiver pendingId) := by
  rcases hp : (s.getDom receiver).bind (fun d => d.lookupPendingDom pendingId)
    with _ | pe
  · simp only [acceptChannel_apply, hp]; exact h
  · simp only [acceptChannel_apply, hp]
    have h1 := sendChannel_preservesCoreAffinity s pe.senderDomainId receiver pe.capId h
    have h2 := coreAffinity_updDomain_id h1 receiver
      (fun d => { d with pendingDomCaps :=
                  d.pendingDomCaps.filter (fun p => p.1 ≠ pendingId) })
      (fun _ => rfl) (fun _ => rfl)
    exact coreAffinity_updDomain_id h2 pe.senderDomainId
      (fun d => { d with frozenHandles :=
                  d.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })
      (fun _ => rfl) (fun _ => rfl)

theorem rejectChannel_preservesCoreAffinity
    (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    (h : CoreAffinity s) :
    CoreAffinity (rejectChannel_apply s receiver pendingId) := by
  simp only [rejectChannel_apply]
  have h1 := coreAffinity_updDomain_id h receiver
    (fun d => { d with pendingDomCaps :=
                d.pendingDomCaps.filter (fun p => p.1 ≠ pendingId) })
    (fun _ => rfl) (fun _ => rfl)
  rcases hp : (s.getDom receiver).bind (fun d => d.lookupPendingDom pendingId)
    with _ | pe
  · simp only [hp]; exact h1
  · simp only [hp]
    exact coreAffinity_updDomain_id h1 pe.senderDomainId
      (fun d => { d with frozenHandles :=
                  d.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })
      (fun _ => rfl) (fun _ => rfl)

theorem mapSelf_preservesCoreAffinity
    (s : SpecState) (caller : DomId) (capHandle : LocalHandle) (newGpa : Nat)
    (h : CoreAffinity s) :
    CoreAffinity (mapSelf_apply s caller capHandle newGpa) := by
  rcases hd : s.getDom caller with _ | d
  · simp only [mapSelf_apply, hd]; exact h
  · rcases hh : d.lookupMemHandle capHandle with _ | capId
    · simp only [mapSelf_apply, hd, hh]; exact h
    · rcases hm : s.getMem capId with _ | c
      · simp only [mapSelf_apply, hd, hh, hm]; exact h
      · rcases hg : d.lookupMappedGpa capHandle with _ | oldGpa
        · simp only [mapSelf_apply, hd, hh, hm, hg]; exact h
        · simp only [mapSelf_apply, hd, hh, hm, hg]
          refine coreAffinity_updDomain_id h caller _ ?_ ?_
          · intro d'; unfold Domain.updMappedGpa
            split <;> rfl
          · intro d'; unfold Domain.updMappedGpa
            split <;> rfl

theorem registerComm_preservesCoreAffinity
    (s : SpecState) (caller : DomId) (commHandle childHandle : LocalHandle)
    (vpId : VpId) (h : CoreAffinity s) :
    CoreAffinity (registerComm_apply s caller commHandle childHandle vpId) := by
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
          apply coreAffinity_updMem _ mid _
          exact coreAffinity_updDomain_id h dc.targetDom
            (fun d => { d with commBindings := d.commBindings ++ [mid] })
            (fun _ => rfl) (fun _ => rfl)

-- ════════════════════════════════════════════════════════════════════
-- § 3.  addVp — appended VP is `.available none`, vacuous case
-- ════════════════════════════════════════════════════════════════════

theorem addVp_preservesCoreAffinity
    (s : SpecState) (caller : DomId) (childHandle commHandle : LocalHandle)
    (h : CoreAffinity s) :
    CoreAffinity (addVp_apply s caller childHandle commHandle) := by
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
          apply coreAffinity_updMem _ mid _
          apply coreAffinity_updDomain h dc.targetDom
          intro d_pre hpre
          refine ⟨rfl, ?_⟩
          intro vp hvp c caller' hrun
          simp only at hvp
          rcases List.mem_append.mp hvp with hvp_pre | hvp_new
          · exact h dc.targetDom d_pre hpre vp hvp_pre c caller' hrun
          · -- The single appended VP has runState = .available none.
            rcases List.mem_singleton.mp hvp_new with rfl
            -- vp.runState = .available none, but hrun says .running ⇒ contradiction.
            cases hrun

-- ════════════════════════════════════════════════════════════════════
-- § 4.  Scheduling actions
-- ════════════════════════════════════════════════════════════════════

theorem switch_preservesCoreAffinity
    {s : SpecState} {caller : DomId} {toHandle : LocalHandle}
    {toVpId : VpId} {core : CoreId}
    (guard : SwitchGuard s caller toHandle toVpId core)
    (h : CoreAffinity s) :
    CoreAffinity (switch_apply s caller toHandle toVpId core) := by
  rcases hh : (s.getDom caller).bind (fun d => d.lookupDomHandle toHandle)
    with _ | cid
  · simp only [switch_apply, hh]; exact h
  · rcases hc : s.getDomCap cid with _ | dc
    · simp only [switch_apply, hh, hc]; exact h
    · rcases hv : (s.getDom caller).bind (fun d => d.vpAndOptPrevOnCore core)
        with _ | vpv
      · simp only [switch_apply, hh, hc, hv]; exact h
      · simp only [switch_apply, hh, hc, hv]
        rcases hd_pre : s.getDom caller with _ | d_pre
        · rw [hd_pre] at hh; cases hh
        have hH_pre : d_pre.lookupDomHandle toHandle = some cid := by
          rw [hd_pre] at hh; exact hh
        apply coreAffinity_updCore _ core
        apply coreAffinity_updDomain_updVp _ caller vpv.1
          (fun vp => { vp with runState := .locked dc.targetDom toVpId vpv.2 })
        · intro _ _ _ _ _ _ _ hrun
          simp only at hrun
          cases hrun
        apply coreAffinity_updDomain_updVp h dc.targetDom toVpId
          (fun vp => { vp with runState := VpRunState.running core (some { domainId := caller, vpId := vpv.1 }) })
        intro td hTd _ _ _ c _ hrun
        simp only at hrun
        cases hrun
        exact guard.coreAllowed d_pre hd_pre cid hH_pre dc hc td hTd

theorem switchSuspended_preservesCoreAffinity
    {s : SpecState} {caller : DomId} {toHandle : LocalHandle}
    {toVpId : VpId} {core : CoreId}
    {calleeDom : DomId} {calleeVp : VpId}
    (guard : SwitchSuspendedGuard s caller toHandle toVpId core calleeDom calleeVp)
    (h : CoreAffinity s) :
    CoreAffinity (switchSuspended_apply s caller toHandle toVpId core
                                         calleeDom calleeVp) := by
  rcases hh : (s.getDom caller).bind (fun d => d.lookupDomHandle toHandle)
    with _ | cid
  · simp only [switchSuspended_apply, hh]; exact h
  · rcases hc : s.getDomCap cid with _ | dc
    · simp only [switchSuspended_apply, hh, hc]; exact h
    · rcases hv : (s.getDom caller).bind (fun d => d.vpAndOptPrevOnCore core)
        with _ | vpv
      · simp only [switchSuspended_apply, hh, hc, hv]; exact h
      · simp only [switchSuspended_apply, hh, hc, hv]
        rcases hd_pre : s.getDom caller with _ | d_pre
        · rw [hd_pre] at hh; cases hh
        have hH_pre : d_pre.lookupDomHandle toHandle = some cid := by
          rw [hd_pre] at hh; exact hh
        apply coreAffinity_updCore _ core
        apply coreAffinity_updDomain_updVp _ caller vpv.1
          (fun vp => { vp with runState := .locked dc.targetDom toVpId vpv.2 })
        · intro _ _ _ _ _ _ _ hrun
          simp only at hrun
          cases hrun
        apply coreAffinity_updDomain_updVp_preserveOrAllowed _ calleeDom calleeVp
          (fun vp => match vp.runState with
                     | .interrupted _ => { vp with runState := .available none }
                     | _              => vp)
        · intro _ _ vp_pre _ _ c _ hrun
          -- Case-split via `match` to substitute vp_pre.runState in hrun.
          generalize hrs : vp_pre.runState = rs at *
          match rs, hrs with
          | .available _, _      => simp_all
          | .running _ _, _      =>
            left; simp_all
          | .locked _ _ _, _     => simp_all
          | .suspended _ _ _, _  => simp_all
          | .interrupted _, _    => simp_all
        apply coreAffinity_updDomain_updVp h dc.targetDom toVpId
          (fun vp => { vp with runState := VpRunState.running core (some { domainId := caller, vpId := vpv.1 }) })
        intro td hTd _ _ _ c _ hrun
        simp only at hrun
        cases hrun
        exact guard.coreAllowed d_pre hd_pre cid hH_pre dc hc td hTd

theorem switchReturn_preservesCoreAffinity
    {s : SpecState} {caller : DomId} {core : CoreId} {exitReason : Option Nat}
    (guard : SwitchReturnGuard s caller core)
    (h : CoreAffinity s) :
    CoreAffinity (switchReturn_apply s caller core exitReason) := by
  rcases hp : (s.getDom caller).bind (fun d => d.vpAndPrevCallerOnCore core)
    with _ | pair
  · simp only [switchReturn_apply, hp]; exact h
  · obtain ⟨vpId, pctx⟩ := pair
    simp only [switchReturn_apply, hp]
    rcases hd_pre : s.getDom caller with _ | d_pre
    · rw [hd_pre] at hp; cases hp
    have hp_pre : d_pre.vpAndPrevCallerOnCore core = some (vpId, pctx) := by
      rw [hd_pre] at hp; exact hp
    have hNotSelf : pctx.domainId ≠ caller :=
      guard.notSelf d_pre hd_pre (vpId, pctx) hp_pre
    apply coreAffinity_updCore _ core
    apply coreAffinity_updDomain_updVp_preserveOrAllowed _ pctx.domainId pctx.vpId
      (fun vp => match vp.runState with
                 | .locked _ _ prevPrev => { vp with runState := .running core prevPrev }
                 | other                => { vp with runState := other })
    · intro pd_post hpd_post vp_pre _ _ c _ hrun
      generalize hrs : vp_pre.runState = rs at *
      match rs, hrs with
      | .locked _ _ prevPrev, _ =>
        right
        simp only at hrun
        cases hrun
        have hpd_pre : s.getDom pctx.domainId = some pd_post := by
          unfold SpecState.updDomain SpecState.getDom at hpd_post
          rw [Arena.find?_update_other _ _ _ _ hNotSelf] at hpd_post
          exact hpd_post
        exact guard.prevCoreAllowed d_pre hd_pre (vpId, pctx) hp_pre pd_post hpd_pre
      | .available _, _      => simp_all
      | .running _ _, _      => left; simp_all
      | .suspended _ _ _, _  => simp_all
      | .interrupted _, _    => simp_all
    apply coreAffinity_updDomain_updVp h caller vpId
      (fun vp => { vp with runState := .available exitReason })
    intro _ _ _ _ _ _ _ hrun
    simp only at hrun
    cases hrun

-- ════════════════════════════════════════════════════════════════════
-- § 5.  deliverInterrupt — induction over chain
-- ════════════════════════════════════════════════════════════════════

/-- Auxiliary: `Domain.updVp` only modifies `vps`, so `updDomain x (updVp ...)`
    preserves the `policy` of every domain. -/
theorem getDom_policy_eq_after_updDomain_updVp
    (s : SpecState) (x : DomId) (vpId : VpId) (g : VProcessor → VProcessor)
    (y : DomId) (d : Domain)
    (hd : (s.updDomain x (fun d' => d'.updVp vpId g)).getDom y = some d) :
    ∃ d', s.getDom y = some d' ∧ d.policy = d'.policy := by
  unfold SpecState.updDomain SpecState.getDom at hd
  by_cases heq : y = x
  · subst heq
    rw [Arena.find?_update_eq_map] at hd
    rcases hpre : s.domains.find? y with _ | d_pre
    · rw [hpre] at hd; cases hd
    · rw [hpre] at hd
      simp only [Option.map_some, Option.some.injEq] at hd
      refine ⟨d_pre, ?_, ?_⟩
      · unfold SpecState.getDom; exact hpre
      · rw [← hd]; rfl
  · rw [Arena.find?_update_other _ _ _ _ heq] at hd
    refine ⟨d, ?_, rfl⟩
    unfold SpecState.getDom; exact hd

/-- Inductive preservation of `CoreAffinity` across the interrupt chain
    walk. The hypothesis `hHandler` is stated relative to the *current*
    state — through induction it weakens automatically across `updVp`
    steps because `Domain.updVp` preserves `policy`. -/
theorem applyMidsAndHandler_preservesCoreAffinity
    (core : CoreId) (vector : Nat) :
    ∀ (chain : List (DomId × VpId)) (prev : DomId × VpId) (s : SpecState),
    CoreAffinity s →
    (∀ handler vp, chain.getLast? = some (handler, vp) →
      ∀ hd, s.getDom handler = some hd → core ∈ hd.policy.cores) →
    CoreAffinity (applyMidsAndHandler core vector prev chain s) := by
  intro chain
  induction chain with
  | nil =>
    intro _ s hCA _
    simp only [applyMidsAndHandler]; exact hCA
  | cons head tail ih =>
    intro prev s hCA hHandler
    match tail with
    | [] =>
      simp only [applyMidsAndHandler]
      apply coreAffinity_updDomain_updVp_preserveOrAllowed hCA head.1 head.2
      intro d_pre hd_pre vp_pre _ _ c caller hrun
      generalize hrs : vp_pre.runState = rs at hrun
      match rs, hrs with
      | .locked _ _ p, _ =>
        right
        simp only at hrun
        injection hrun with hc _
        subst hc
        have hLast : (head :: ([] : List (DomId × VpId))).getLast? = some (head.1, head.2) := by
          rfl
        exact hHandler head.1 head.2 hLast d_pre hd_pre
      | .available _, _      => left; simp_all
      | .running _ _, _      => left; simp_all
      | .suspended _ _ _, _  => left; simp_all
      | .interrupted _, _    => left; simp_all
    | mid :: rest =>
      simp only [applyMidsAndHandler]
      have hCA' : CoreAffinity
          (s.updDomain head.1 (fun d => d.updVp head.2 (fun vp =>
            { vp with runState := .suspended prev.1 prev.2 vector }))) := by
        apply coreAffinity_updDomain_updVp hCA
        intro _ _ vp_pre _ _ c caller hrun
        cases hrun
      apply ih head _ hCA'
      intro hd hv hLastTail d hd_eq
      have hLastChain : (head :: mid :: rest).getLast? = some (hd, hv) := by
        show (mid :: rest).getLast? = some (hd, hv)
        exact hLastTail
      obtain ⟨d', hd'_pre, hpol⟩ :=
        getDom_policy_eq_after_updDomain_updVp s head.1 head.2 _ hd d hd_eq
      rw [hpol]
      exact hHandler hd hv hLastChain d' hd'_pre

theorem deliverInterrupt_preservesCoreAffinity
    {s : SpecState} {interrupted handler : DomId} {core : CoreId}
    {vector : Nat} {chain : List (DomId × VpId)}
    (guard : DeliverInterruptGuard s interrupted handler core vector chain)
    (h : CoreAffinity s) :
    CoreAffinity (deliverInterrupt_apply s interrupted handler core vector chain) := by
  obtain ⟨hVp, hLast⟩ := guard.chainLastHandler
  have hLen : chain.length ≥ 2 := guard.chainLenGe2
  rcases chain with _ | ⟨leaf, tail⟩
  · simp at hLen
  rcases tail with _ | ⟨m, rest⟩
  · simp at hLen
  -- chain = leaf :: m :: rest
  simp only [deliverInterrupt_apply]
  -- Step 1: leaf VP → .interrupted (vacuous).
  have h0 : CoreAffinity
      (s.updDomain leaf.1 (fun d => d.updVp leaf.2 (fun vp =>
        { vp with runState := .interrupted vector }))) := by
    apply coreAffinity_updDomain_updVp h
    intro _ _ _ _ _ _ _ hrun
    cases hrun
  -- Step 2: derive (m :: rest).getLast? = some (handler, hVp).
  have hLastTail : (m :: rest).getLast? = some (handler, hVp) := by
    show (m :: rest).getLast? = some (handler, hVp)
    exact hLast
  have hHandler : ∀ hd' vp', (m :: rest).getLast? = some (hd', vp') →
      ∀ d, (s.updDomain leaf.1 (fun d => d.updVp leaf.2 (fun vp =>
            { vp with runState := .interrupted vector }))).getDom hd' = some d →
      core ∈ d.policy.cores := by
    intro hd' vp' hLastTail' d hd_eq
    rw [hLastTail'] at hLastTail
    have hpair : (hd', vp') = (handler, hVp) := Option.some.inj hLastTail
    have hhd : hd' = handler := congrArg Prod.fst hpair
    rw [hhd] at hd_eq
    obtain ⟨d', hd'_pre, hpol⟩ :=
      getDom_policy_eq_after_updDomain_updVp s leaf.1 leaf.2 _ handler d hd_eq
    rw [hpol]
    exact guard.handlerCoreAllowed d' hd'_pre
  have h1 := applyMidsAndHandler_preservesCoreAffinity core vector (m :: rest) leaf _ h0 hHandler
  -- Step 3: rebind core (no effect).
  rw [hLast]
  exact coreAffinity_updCore h1 core _

-- ════════════════════════════════════════════════════════════════════
-- § 6.  Top theorem
-- ════════════════════════════════════════════════════════════════════

theorem step_preservesCoreAffinity
    {s s' : SpecState} {a : Action} (h : CoreAffinity s) (hstep : step s a s') :
    CoreAffinity s' := by
  cases hstep with
  | carve _             => exact carve_preservesCoreAffinity           _ _ _ _ _ h
  | alias _             => exact alias_preservesCoreAffinity           _ _ _ _ h
  | revoke _            => exact revoke_preservesCoreAffinity          _ _ _ h
  | send _              => exact send_preservesCoreAffinity            _ _ _ _ h
  | «seal» _            => exact seal_preservesCoreAffinity            _ _ _ h
  | accept _            => exact accept_preservesCoreAffinity          _ _ _ h
  | reject _            => exact reject_preservesCoreAffinity          _ _ _ h
  | sealedSend _        => exact sealedSend_preservesCoreAffinity      _ _ _ _ _ h
  | create _            => exact create_preservesCoreAffinity          _ _ _ h
  | revokeDomain _      => exact revokeDomain_preservesCoreAffinity    _ _ _ h
  | setPolicy _         => exact setPolicy_preservesCoreAffinity       _ _ _ _ _ h
  | sendChannel _       => exact sendChannel_preservesCoreAffinity     _ _ _ _ h
  | acceptChannel _     => exact acceptChannel_preservesCoreAffinity   _ _ _ h
  | rejectChannel _     => exact rejectChannel_preservesCoreAffinity   _ _ _ h
  | switchReturn g      => exact switchReturn_preservesCoreAffinity    g h
  | switch g            => exact switch_preservesCoreAffinity          g h
  | switchSuspended g   => exact switchSuspended_preservesCoreAffinity g h
  | deliverInterrupt g  => exact deliverInterrupt_preservesCoreAffinity g h
  | addVp _             => exact addVp_preservesCoreAffinity           _ _ _ _ h
  | registerComm _      => exact registerComm_preservesCoreAffinity    _ _ _ _ _ h
  | mapSelf _           => exact mapSelf_preservesCoreAffinity         _ _ _ _ h
  | attestSelf _        => exact h
  | attest _            => exact h
  | getPolicy _         => exact h
  | getChan _           => exact h
  | getChanSelf _       => exact h

end ThemisCapa
