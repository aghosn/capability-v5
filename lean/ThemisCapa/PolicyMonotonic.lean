/-
  ThemisCapa.PolicyMonotonic — preservation of the policy-monotonic-
  ancestry invariant.

  ## Statement
  For every (child, parent) edge in the static domain tree
  (`d_c.parent = some parent`), the child's policy refines the
  parent's (`d_c.policy ≤ d_p.policy`). See `Invariants.lean`.

  ## Top theorem
  `step_preservesPolicyMonotonicAncestry :
      WellFormed s → step s a s' → PolicyMonotonicAncestry s'`.

  Almost every action is trivial: 19 of 21 do not touch any domain's
  `parent` or `policy`. The two non-trivial cases:
  * `create` — introduces a new edge `(newDom → caller)`. The
    refinement obligation `newDom.policy ≤ caller.policy` is exactly
    `CreateGuard.policySubset`. We need
    `DomainParentResolves` + `FreshDomCounter` to rule out
    pre-existing dangling pointers to the fresh `DomId`.
  * `revokeDomain` — removes the target. By `DomainTreeWf` +
    `RevokeDomainGuard.targetIsLeaf`, target has no children, so
    no surviving child references it as parent (vacuous in post).
-/
import ThemisCapa.Step
import ThemisCapa.Invariants
import ThemisCapa.Policy
import ThemisCapa.RevokeHelpers

namespace ThemisCapa
open Arena

-- ════════════════════════════════════════════════════════════════════
-- § 1.  Primitive preservation helpers
-- ════════════════════════════════════════════════════════════════════

theorem policyMA_updMem
    {s : SpecState} (h : PolicyMonotonicAncestry s)
    (id : MemCapId) (g : MemCap → MemCap) :
    PolicyMonotonicAncestry (s.updMem id g) := h

theorem policyMA_updDomCap
    {s : SpecState} (h : PolicyMonotonicAncestry s)
    (id : DomCapId) (g : DomCap → DomCap) :
    PolicyMonotonicAncestry (s.updDomCap id g) := h

theorem policyMA_updCore
    {s : SpecState} (h : PolicyMonotonicAncestry s)
    (id : CoreId) (g : CoreState → CoreState) :
    PolicyMonotonicAncestry (s.updCore id g) := h

theorem policyMA_freshMem
    {s : SpecState} (h : PolicyMonotonicAncestry s) (c : MemCap) :
    PolicyMonotonicAncestry (s.freshMem c).snd := h

theorem policyMA_freshDomCap
    {s : SpecState} (h : PolicyMonotonicAncestry s) (dc : DomCap) :
    PolicyMonotonicAncestry (s.freshDomCap dc).snd := h

/-- Generic `updDomain` lift: any `f` that preserves both `parent`
    and `policy` for every existing domain preserves the invariant. -/
theorem policyMA_updDomain_id
    {s : SpecState} (h : PolicyMonotonicAncestry s)
    (x : DomId) (f : Domain → Domain)
    (h1 : ∀ d, (f d).parent = d.parent)
    (h2 : ∀ d, (f d).policy = d.policy) :
    PolicyMonotonicAncestry (s.updDomain x f) := by
  intro child parent d_c d_p hc hp hpd
  have hc_pre :
      ∃ d_c_pre, s.getDom child = some d_c_pre ∧
        d_c.parent = d_c_pre.parent ∧ d_c.policy = d_c_pre.policy := by
    unfold SpecState.updDomain SpecState.getDom at hc
    by_cases hxc : child = x
    · subst hxc
      rw [Arena.find?_update_eq_map] at hc
      rcases hpre : s.domains.find? child with _ | d_pre
      · rw [hpre] at hc; cases hc
      · rw [hpre] at hc
        simp only [Option.map_some, Option.some.injEq] at hc
        refine ⟨d_pre, ?_, ?_, ?_⟩
        · unfold SpecState.getDom; exact hpre
        · rw [← hc]; exact h1 d_pre
        · rw [← hc]; exact h2 d_pre
    · rw [Arena.find?_update_other _ _ _ _ hxc] at hc
      refine ⟨d_c, ?_, rfl, rfl⟩
      unfold SpecState.getDom; exact hc
  have hp_pre :
      ∃ d_p_pre, s.getDom parent = some d_p_pre ∧ d_p.policy = d_p_pre.policy := by
    unfold SpecState.updDomain SpecState.getDom at hpd
    by_cases hxp : parent = x
    · subst hxp
      rw [Arena.find?_update_eq_map] at hpd
      rcases hpre : s.domains.find? parent with _ | d_pre
      · rw [hpre] at hpd; cases hpd
      · rw [hpre] at hpd
        simp only [Option.map_some, Option.some.injEq] at hpd
        refine ⟨d_pre, ?_, ?_⟩
        · unfold SpecState.getDom; exact hpre
        · rw [← hpd]; exact h2 d_pre
    · rw [Arena.find?_update_other _ _ _ _ hxp] at hpd
      refine ⟨d_p, ?_, rfl⟩
      unfold SpecState.getDom; exact hpd
  obtain ⟨d_c_pre, hc_eq, hpar_eq, hpol_c⟩ := hc_pre
  obtain ⟨d_p_pre, hp_eq, hpol_p⟩ := hp_pre
  have hp' : d_c_pre.parent = some parent := by rw [← hpar_eq]; exact hp
  rw [hpol_c, hpol_p]
  exact h child parent d_c_pre d_p_pre hc_eq hp' hp_eq

/-- Removing a domain from the arena preserves the invariant. -/
theorem policyMA_domains_remove
    {s : SpecState} (h : PolicyMonotonicAncestry s) (target : DomId) :
    PolicyMonotonicAncestry { s with domains := s.domains.remove target } := by
  intro child parent d_c d_p hc hp hpd
  unfold SpecState.getDom at hc hpd
  by_cases hxc : child = target
  · subst hxc; rw [Arena.find?_remove_same] at hc; cases hc
  by_cases hxp : parent = target
  · subst hxp; rw [Arena.find?_remove_same] at hpd; cases hpd
  rw [Arena.find?_remove_other _ _ _ hxc] at hc
  rw [Arena.find?_remove_other _ _ _ hxp] at hpd
  have hc' : s.getDom child = some d_c := by unfold SpecState.getDom; exact hc
  have hpd' : s.getDom parent = some d_p := by unfold SpecState.getDom; exact hpd
  exact h child parent d_c d_p hc' hp hpd'

theorem policyMA_domcaps_remove
    {s : SpecState} (h : PolicyMonotonicAncestry s) (target : DomCapId) :
    PolicyMonotonicAncestry { s with domcaps := s.domcaps.remove target } := h

/-- Specialized `freshDom` lift for the `create` shape. -/
theorem policyMA_freshDom_create
    {s : SpecState} (h : PolicyMonotonicAncestry s)
    (hPR : DomainParentResolves s) (hFC : FreshDomCounter s)
    (dm : Domain) (caller : DomId)
    (hpar : dm.parent = some caller)
    (d_caller : Domain) (hcaller : s.getDom caller = some d_caller)
    (hpol : dm.policy ≤ d_caller.policy) :
    PolicyMonotonicAncestry (s.freshDom dm).snd := by
  intro child parent d_c d_p hc hp hpd
  -- We need to unpack getDom on the freshDom-result state.
  have hnext : s.domains.find? s.nextDomId = none := by
    rcases hf : s.domains.find? s.nextDomId with _ | d
    · rfl
    · exact absurd (hFC _ (Arena.mem_keys_of_find?_some _ _ _ hf)) (Nat.lt_irrefl _)
  unfold SpecState.freshDom at hc hpd
  simp only at hc hpd
  -- After freshDom, the arena is s.domains.insert s.nextDomId dm.
  -- s.getDom child = (...).domains.find? child
  unfold SpecState.getDom at hc hpd
  by_cases hxc : child = s.nextDomId
  · -- Child is the new domain.
    subst hxc
    rw [Arena.find?_insert_same] at hc
    cases hc  -- d_c = dm
    rw [hpar] at hp
    have hpeq : parent = caller := (Option.some.inj hp).symm
    -- After hpeq, replace parent with caller in remaining hypotheses.
    rw [hpeq] at hpd
    have hxp : caller ≠ s.nextDomId := by
      intro h_eq
      have hcaller' : s.domains.find? caller = some d_caller := by
        unfold SpecState.getDom at hcaller; exact hcaller
      have hkeys : caller ∈ s.domains.keys :=
        Arena.mem_keys_of_find?_some _ _ _ hcaller'
      exact Nat.lt_irrefl _ (h_eq ▸ hFC _ hkeys)
    rw [Arena.find?_insert_other _ _ _ _ hxp] at hpd
    have hd_eq : d_p = d_caller := by
      have hcaller' : s.domains.find? caller = some d_caller := by
        unfold SpecState.getDom at hcaller; exact hcaller
      have hpd' : s.domains.find? caller = some d_p := hpd
      rw [hcaller'] at hpd'; exact (Option.some.inj hpd').symm
    rw [hd_eq]; exact hpol
  · -- Child is pre-existing.
    rw [Arena.find?_insert_other _ _ _ _ hxc] at hc
    by_cases hxp : parent = s.nextDomId
    · -- Pre-existing child claims fresh-domain as parent ⇒ dangling, ruled out.
      exfalso
      have hc_pre : s.getDom child = some d_c := by unfold SpecState.getDom; exact hc
      have hp_dangling : d_c.parent = some s.nextDomId := hxp ▸ hp
      have := hPR child d_c hc_pre s.nextDomId hp_dangling
      unfold SpecState.getDom at this
      rw [hnext] at this
      cases this
    · rw [Arena.find?_insert_other _ _ _ _ hxp] at hpd
      have hc' : s.getDom child = some d_c := by unfold SpecState.getDom; exact hc
      have hpd' : s.getDom parent = some d_p := by unfold SpecState.getDom; exact hpd
      exact h child parent d_c d_p hc' hp hpd'

-- ════════════════════════════════════════════════════════════════════
-- § 2.  Per-action lemmas — trivial (no parent/policy touched)
-- ════════════════════════════════════════════════════════════════════

theorem carve_preservesPolicyMonotonicAncestry
    (s : SpecState) (caller : DomId) (parent : MemCapId)
    (access : Access) (attrs : Attributes) (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (carve_apply s caller parent access attrs) := by
  rcases hm : s.getMem parent with _ | p
  · simp only [carve_apply, hm]; exact h
  · simp only [carve_apply, hm]
    exact policyMA_updDomain_id
      (policyMA_updMem (policyMA_freshMem h _) _ _) caller _
      (fun _ => rfl) (fun _ => rfl)

theorem alias_preservesPolicyMonotonicAncestry
    (s : SpecState) (caller : DomId) (parent : MemCapId) (access : Access)
    (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (alias_apply s caller parent access) := by
  rcases hm : s.getMem parent with _ | p
  · simp only [alias_apply, hm]; exact h
  · simp only [alias_apply, hm]
    exact policyMA_updDomain_id
      (policyMA_updMem (policyMA_freshMem h _) _ _) caller _
      (fun _ => rfl) (fun _ => rfl)

theorem revoke_preservesPolicyMonotonicAncestry
    (s : SpecState) (caller : DomId) (target : MemCapId)
    (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (revoke_apply s caller target) := by
  rcases hm : s.getMem target with _ | t
  · simp only [revoke_apply, hm]; exact h
  · rcases hp : t.parent with _ | pid
    · simp only [revoke_apply, hm, hp]; exact h
    · simp only [revoke_apply, hm, hp]
      have h1 : PolicyMonotonicAncestry { s with memcaps := s.memcaps.remove target } := h
      have h2 := policyMA_updMem h1 pid (fun p =>
        { p with childrenIds := p.childrenIds.filter (· ≠ target) })
      have h3 := policyMA_updDomain_id h2 t.owner
        (fun d => { d with memHandles := d.memHandles.filter (fun h => h.2 ≠ target) })
        (fun _ => rfl) (fun _ => rfl)
      by_cases hv : t.region.attributes.vital
      · rw [if_pos hv]
        exact policyMA_updDomain_id h3 t.owner
          (fun d => { d with status := .revoked }) (fun _ => rfl) (fun _ => rfl)
      · rw [if_neg hv]; exact h3

theorem send_preservesPolicyMonotonicAncestry
    (s : SpecState) (caller receiver : DomId) (cap : MemCapId)
    (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (send_apply s caller receiver cap) := by
  simp only [send_apply]
  apply policyMA_updMem _ cap
  apply policyMA_updDomain_id _ receiver
    (fun d => { d with memHandles := d.memHandles ++ [(d.nextHandle, cap)],
                       nextHandle := d.nextHandle + 1 })
    (fun _ => rfl) (fun _ => rfl)
  exact policyMA_updDomain_id h caller
    (fun d => { d with memHandles := d.memHandles.filter (fun h => h.2 ≠ cap) })
    (fun _ => rfl) (fun _ => rfl)

theorem seal_preservesPolicyMonotonicAncestry
    (s : SpecState) (caller : DomId) (cap : DomCapId) (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (seal_apply s caller cap) := by
  rcases hc : s.getDomCap cap with _ | dc
  · simp only [seal_apply, hc]; exact h
  · simp only [seal_apply, hc]
    exact policyMA_updDomain_id h dc.targetDom
      (fun d => { d with status := .sealed }) (fun _ => rfl) (fun _ => rfl)

theorem accept_preservesPolicyMonotonicAncestry
    (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (accept_apply s receiver pendingId) := by
  rcases hp : (s.getDom receiver).bind (fun d => d.lookupPending pendingId)
    with _ | pe
  · simp only [accept_apply, hp]; exact h
  · simp only [accept_apply, hp]
    have h1 := send_preservesPolicyMonotonicAncestry s pe.senderDomainId receiver pe.capId h
    have h2 := policyMA_updDomain_id h1 receiver
      (fun d => { d with pendingMemCaps :=
                  d.pendingMemCaps.filter (fun p => p.1 ≠ pendingId) })
      (fun _ => rfl) (fun _ => rfl)
    exact policyMA_updDomain_id h2 pe.senderDomainId
      (fun d => { d with frozenHandles :=
                  d.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })
      (fun _ => rfl) (fun _ => rfl)

theorem reject_preservesPolicyMonotonicAncestry
    (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (reject_apply s receiver pendingId) := by
  simp only [reject_apply]
  have h1 := policyMA_updDomain_id h receiver
    (fun d => { d with pendingMemCaps :=
                d.pendingMemCaps.filter (fun p => p.1 ≠ pendingId) })
    (fun _ => rfl) (fun _ => rfl)
  rcases hp : (s.getDom receiver).bind (fun d => d.lookupPending pendingId)
    with _ | pe
  · simp only [hp]; exact h1
  · simp only [hp]
    exact policyMA_updDomain_id h1 pe.senderDomainId
      (fun d => { d with frozenHandles :=
                  d.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })
      (fun _ => rfl) (fun _ => rfl)

theorem sealedSend_preservesPolicyMonotonicAncestry
    (s : SpecState) (caller receiver : DomId) (handle : LocalHandle)
    (gpaHint : Option Nat) (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (sealedSend_apply s caller receiver handle gpaHint) := by
  rcases hp : (s.getDom caller).bind (fun d => d.lookupMemHandle handle)
    with _ | capId
  · simp only [sealedSend_apply, hp]; exact h
  · simp only [sealedSend_apply, hp]
    have h1 := policyMA_updDomain_id h caller
      (fun d => { d with frozenHandles := d.frozenHandles ++ [handle] })
      (fun _ => rfl) (fun _ => rfl)
    exact policyMA_updDomain_id h1 receiver _ (fun _ => rfl) (fun _ => rfl)

theorem sealedSendChannel_preservesPolicyMonotonicAncestry
    (s : SpecState) (caller receiver : DomId) (handle : LocalHandle)
    (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (sealedSendChannel_apply s caller receiver handle) := by
  rcases hp : (s.getDom caller).bind (fun d => d.lookupDomHandle handle)
    with _ | capId
  · simp only [sealedSendChannel_apply, hp]; exact h
  · simp only [sealedSendChannel_apply, hp]
    have h1 := policyMA_updDomain_id h caller
      (fun d => { d with frozenHandles := d.frozenHandles ++ [handle] })
      (fun _ => rfl) (fun _ => rfl)
    exact policyMA_updDomain_id h1 receiver _ (fun _ => rfl) (fun _ => rfl)

theorem send_at_preservesPolicyMonotonicAncestry
    (s : SpecState) (caller receiver : DomId) (cap : MemCapId)
    (gpaHint : Option Nat) (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (send_at_apply s caller receiver cap gpaHint) := by
  simp only [send_at_apply]
  exact send_preservesPolicyMonotonicAncestry s caller receiver cap h

theorem accept_at_preservesPolicyMonotonicAncestry
    (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    (gpaOverride : Option Nat) (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (accept_at_apply s receiver pendingId gpaOverride) := by
  simp only [accept_at_apply]
  exact accept_preservesPolicyMonotonicAncestry s receiver pendingId h

theorem setPolicy_preservesPolicyMonotonicAncestry
    (s : SpecState) (caller : DomId) (cap : DomCapId)
    (id : PolicyIdentifier) (value : Nat)
    (guard : SetPolicyGuard s caller cap id value)
    (hdtwf : DomainTreeParentChild s)
    (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (setPolicy_apply s caller cap id value) := by
  rcases hc : s.getDomCap cap with _ | dc
  · simp only [setPolicy_apply, hc]; exact h
  · simp only [setPolicy_apply, hc]
    -- Let `target := dc.targetDom` (inline; `set` tactic unavailable).
    -- Establish: caller ≠ target (caller is sealed, target is unsealed).
    have hcaller_get : (s.getDom caller).isSome := guard.callerExists
    obtain ⟨cd, hcd⟩ := Option.isSome_iff_exists.mp hcaller_get
    have htarget_get : (s.getDom dc.targetDom).isSome := guard.targetExists dc hc
    obtain ⟨td, htd⟩ := Option.isSome_iff_exists.mp htarget_get
    have hcaller_sealed : cd.isSealed := guard.callerSealed cd hcd
    have htarget_unsealed : td.isUnsealed := guard.targetUnsealed dc hc td htd
    have hne : caller ≠ dc.targetDom := by
      intro heq
      rw [heq] at hcd
      rw [hcd] at htd
      injection htd with hcdtd
      have hsealed : td.status = DomainStatus.sealed := by
        unfold Domain.isSealed at hcaller_sealed
        rw [← hcdtd]; exact hcaller_sealed
      have hunsealed : td.status = DomainStatus.unsealed := htarget_unsealed
      rw [hsealed] at hunsealed; cases hunsealed
    intro child parent d_c d_p hgc hpar hgp
    by_cases hct : child = dc.targetDom
    · subst hct
      have hd_c_pre :
          d_c.parent = td.parent ∧
          d_c.policy = applyPolicyValue td.policy id value := by
        unfold SpecState.updDomain SpecState.getDom at hgc
        rw [Arena.find?_update_eq_map] at hgc
        have htd' : s.domains.find? dc.targetDom = some td := htd
        rw [htd'] at hgc
        simp only [Option.map_some, Option.some.injEq] at hgc
        refine ⟨?_, ?_⟩
        · rw [← hgc]
        · rw [← hgc]
      have hpar_pre : td.parent = some parent := by
        rw [← hd_c_pre.1]; exact hpar
      have hpar_caller : parent = caller := by
        have hcip := guard.callerIsParent dc hc td htd
        rw [hpar_pre] at hcip; exact Option.some.inj hcip
      subst hpar_caller
      -- After subst, `caller` is replaced with `parent` (or vice versa).
      -- Now use whichever is in scope.
      have hd_p_eq : d_p = cd := by
        unfold SpecState.updDomain SpecState.getDom at hgp
        rw [Arena.find?_update_other _ _ _ _ hne] at hgp
        have hh' := hcd
        unfold SpecState.getDom at hh'
        rw [hh'] at hgp
        exact (Option.some.inj hgp).symm
      rw [hd_c_pre.2, hd_p_eq]
      exact guard.newPolicyMonotonic dc hc td htd cd hcd
    · have hd_c_pre : s.getDom child = some d_c := by
        unfold SpecState.updDomain SpecState.getDom at hgc
        rw [Arena.find?_update_other _ _ _ _ hct] at hgc
        unfold SpecState.getDom; exact hgc
      by_cases hpt : parent = dc.targetDom
      · subst hpt
        have hch : child ∈ td.childrenDoms :=
          hdtwf child d_c hd_c_pre dc.targetDom hpar td htd
        rw [guard.targetHasNoChildren dc hc td htd] at hch
        cases hch
      · have hd_p_pre : s.getDom parent = some d_p := by
          unfold SpecState.updDomain SpecState.getDom at hgp
          rw [Arena.find?_update_other _ _ _ _ hpt] at hgp
          unfold SpecState.getDom; exact hgp
        exact h child parent d_c d_p hd_c_pre hpar hd_p_pre

theorem sendChannel_preservesPolicyMonotonicAncestry
    (s : SpecState) (caller receiver : DomId) (cap : DomCapId)
    (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (sendChannel_apply s caller receiver cap) := by
  simp only [sendChannel_apply]
  apply policyMA_updDomCap _ cap
  refine policyMA_updDomain_id ?_ receiver _ (fun _ => rfl) (fun _ => rfl)
  exact policyMA_updDomain_id h caller _ (fun _ => rfl) (fun _ => rfl)

theorem acceptChannel_preservesPolicyMonotonicAncestry
    (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (acceptChannel_apply s receiver pendingId) := by
  rcases hp : (s.getDom receiver).bind (fun d => d.lookupPendingDom pendingId)
    with _ | pe
  · simp only [acceptChannel_apply, hp]; exact h
  · simp only [acceptChannel_apply, hp]
    have h1 := sendChannel_preservesPolicyMonotonicAncestry s pe.senderDomainId receiver pe.capId h
    have h2 := policyMA_updDomain_id h1 receiver
      (fun d => { d with pendingDomCaps :=
                  d.pendingDomCaps.filter (fun p => p.1 ≠ pendingId) })
      (fun _ => rfl) (fun _ => rfl)
    exact policyMA_updDomain_id h2 pe.senderDomainId
      (fun d => { d with frozenHandles :=
                  d.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })
      (fun _ => rfl) (fun _ => rfl)

theorem rejectChannel_preservesPolicyMonotonicAncestry
    (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (rejectChannel_apply s receiver pendingId) := by
  simp only [rejectChannel_apply]
  have h1 := policyMA_updDomain_id h receiver
    (fun d => { d with pendingDomCaps :=
                d.pendingDomCaps.filter (fun p => p.1 ≠ pendingId) })
    (fun _ => rfl) (fun _ => rfl)
  rcases hp : (s.getDom receiver).bind (fun d => d.lookupPendingDom pendingId)
    with _ | pe
  · simp only [hp]; exact h1
  · simp only [hp]
    exact policyMA_updDomain_id h1 pe.senderDomainId
      (fun d => { d with frozenHandles :=
                  d.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })
      (fun _ => rfl) (fun _ => rfl)

theorem addVp_preservesPolicyMonotonicAncestry
    (s : SpecState) (caller : DomId) (childHandle commHandle : LocalHandle)
    (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (addVp_apply s caller childHandle commHandle) := by
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
          apply policyMA_updMem _ mid
          exact policyMA_updDomain_id h dc.targetDom _ (fun _ => rfl) (fun _ => rfl)

theorem registerComm_preservesPolicyMonotonicAncestry
    (s : SpecState) (caller : DomId) (commHandle childHandle : LocalHandle)
    (vpId : VpId) (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (registerComm_apply s caller commHandle childHandle vpId) := by
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
          apply policyMA_updMem _ mid
          exact policyMA_updDomain_id h dc.targetDom _ (fun _ => rfl) (fun _ => rfl)

theorem mapSelf_preservesPolicyMonotonicAncestry
    (s : SpecState) (caller : DomId) (capHandle : LocalHandle) (newGpa : Nat)
    (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (mapSelf_apply s caller capHandle newGpa) := by
  rcases hd : s.getDom caller with _ | d
  · simp only [mapSelf_apply, hd]; exact h
  · rcases hh : d.lookupMemHandle capHandle with _ | capId
    · simp only [mapSelf_apply, hd, hh]; exact h
    · rcases hg : s.getMem capId with _ | c
      · simp only [mapSelf_apply, hd, hh, hg]; exact h
      · rcases hog : d.lookupMappedGpa capHandle with _ | oldGpa
        · simp only [mapSelf_apply, hd, hh, hg, hog]; exact h
        · simp only [mapSelf_apply, hd, hh, hg, hog]
          refine policyMA_updDomain_id h caller _ ?_ ?_
          · intro d'; unfold Domain.updMappedGpa; split <;> rfl
          · intro d'; unfold Domain.updMappedGpa; split <;> rfl

-- ════════════════════════════════════════════════════════════════════
-- § 3.  Scheduling actions (switch, switchSuspended, switchReturn)
-- ════════════════════════════════════════════════════════════════════

theorem switch_preservesPolicyMonotonicAncestry
    {s : SpecState} {caller : DomId} {toHandle : LocalHandle}
    {toVpId : VpId} {core : CoreId}
    (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (switch_apply s caller toHandle toVpId core) := by
  rcases hh : (s.getDom caller).bind (fun d => d.lookupDomHandle toHandle)
    with _ | cid
  · simp only [switch_apply, hh]; exact h
  · rcases hc : s.getDomCap cid with _ | dc
    · simp only [switch_apply, hh, hc]; exact h
    · rcases hv : (s.getDom caller).bind (fun d => d.vpAndOptPrevOnCore core)
        with _ | vpv
      · simp only [switch_apply, hh, hc, hv]; exact h
      · simp only [switch_apply, hh, hc, hv]
        apply policyMA_updCore _ core
        refine policyMA_updDomain_id ?_ caller _ (fun _ => rfl) (fun _ => rfl)
        exact policyMA_updDomain_id h dc.targetDom _ (fun _ => rfl) (fun _ => rfl)

theorem switchSuspended_preservesPolicyMonotonicAncestry
    {s : SpecState} {caller : DomId} {toHandle : LocalHandle}
    {toVpId : VpId} {core : CoreId}
    {calleeDom : DomId} {calleeVp : VpId}
    (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry
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
        apply policyMA_updCore _ core
        refine policyMA_updDomain_id ?_ caller _ (fun _ => rfl) (fun _ => rfl)
        refine policyMA_updDomain_id ?_ calleeDom _ (fun _ => rfl) (fun _ => rfl)
        exact policyMA_updDomain_id h dc.targetDom _ (fun _ => rfl) (fun _ => rfl)

theorem switchReturn_preservesPolicyMonotonicAncestry
    {s : SpecState} {caller : DomId} {core : CoreId} {exitReason : Option Nat}
    (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (switchReturn_apply s caller core exitReason) := by
  rcases hp : (s.getDom caller).bind (fun d => d.vpAndPrevCallerOnCore core)
    with _ | pair
  · simp only [switchReturn_apply, hp]; exact h
  · obtain ⟨vpId, pctx⟩ := pair
    simp only [switchReturn_apply, hp]
    apply policyMA_updCore _ core
    refine policyMA_updDomain_id ?_ pctx.domainId _ (fun _ => rfl) (fun _ => rfl)
    exact policyMA_updDomain_id h caller _ (fun _ => rfl) (fun _ => rfl)

-- ════════════════════════════════════════════════════════════════════
-- § 4.  deliverInterrupt — induction over the chain
-- ════════════════════════════════════════════════════════════════════

theorem applyMidsAndHandler_preservesPolicyMonotonicAncestry
    (core : CoreId) (vector : Nat) :
    ∀ (chain : List (DomId × VpId)) (prev : DomId × VpId) (s : SpecState),
    PolicyMonotonicAncestry s →
    PolicyMonotonicAncestry (applyMidsAndHandler core vector prev chain s) := by
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
      exact policyMA_updDomain_id h head.1 _ (fun _ => rfl) (fun _ => rfl)
    | mid :: rest =>
      simp only [applyMidsAndHandler]
      apply ih head
      exact policyMA_updDomain_id h head.1 _ (fun _ => rfl) (fun _ => rfl)

theorem deliverInterrupt_preservesPolicyMonotonicAncestry
    (s : SpecState) (interrupted handler : DomId) (core : CoreId)
    (vector : Nat) (chain : List (DomId × VpId))
    (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry
      (deliverInterrupt_apply s interrupted handler core vector chain) := by
  unfold deliverInterrupt_apply
  rcases chain with _ | ⟨leaf, tail⟩
  · exact h
  rcases tail with _ | ⟨m, rest⟩
  · exact h
  -- chain = leaf :: m :: rest
  simp only
  have h0 : PolicyMonotonicAncestry
      (s.updDomain leaf.1 (fun d => d.updVp leaf.2 (fun vp =>
        { vp with runState := .interrupted vector }))) :=
    policyMA_updDomain_id h leaf.1 _ (fun _ => rfl) (fun _ => rfl)
  have h1 := applyMidsAndHandler_preservesPolicyMonotonicAncestry core vector
              (m :: rest) leaf _ h0
  rcases hgl : (leaf :: m :: rest).getLast? with _ | ⟨hDom, hVp⟩
  · exact h1
  · exact policyMA_updCore h1 core _

-- ════════════════════════════════════════════════════════════════════
-- § 5.  create — the only ancestry-introducing action
-- ════════════════════════════════════════════════════════════════════

theorem create_preservesPolicyMonotonicAncestry
    {s : SpecState} {caller : DomId} {policy : DomainPolicy}
    (guard : CreateGuard s caller policy)
    (hPR : DomainParentResolves s) (hFC : FreshDomCounter s)
    (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (create_apply s caller policy) := by
  rcases hcaller : s.getDom caller with _ | d_caller
  · have hex := guard.callerExists
    rw [hcaller] at hex; cases hex
  have hpol : policy ≤ d_caller.policy := guard.policySubset d_caller hcaller
  simp only [create_apply]
  have h1 : PolicyMonotonicAncestry (s.freshDom (freshChildDomain caller policy)).snd :=
    policyMA_freshDom_create h hPR hFC (freshChildDomain caller policy) caller
      (by unfold freshChildDomain; rfl) d_caller hcaller hpol
  have h2 := policyMA_freshDomCap h1
    ({ parent := none, owner := caller,
       targetDom := (s.freshDom (freshChildDomain caller policy)).fst } : DomCap)
  exact policyMA_updDomain_id h2 caller _ (fun _ => rfl) (fun _ => rfl)

-- ════════════════════════════════════════════════════════════════════
-- § 6.  revokeDomain — removes the target domain
-- ════════════════════════════════════════════════════════════════════

theorem revokeDomain_preservesPolicyMonotonicAncestry
    (s : SpecState) (caller : DomId) (handle : LocalHandle)
    (h : PolicyMonotonicAncestry s) :
    PolicyMonotonicAncestry (revokeDomain_apply s caller handle) := by
  intro child parent d_c d_p hc hpar hp
  -- Survivors keep their `policy` and `parent`. Pull back both edges
  -- to the pre-state and apply the hypothesis.
  obtain ⟨d_c_pre, hc_pre, hpc, hparc, _, _⟩ :=
    revokeDomain_apply_dom_axes s caller handle child d_c hc
  obtain ⟨d_p_pre, hp_pre, hpp, _, _, _⟩ :=
    revokeDomain_apply_dom_axes s caller handle parent d_p hp
  -- d_c_pre.parent = d_c.parent = some parent
  have hparc' : d_c_pre.parent = some parent := hparc.trans hpar
  have hbase := h child parent d_c_pre d_p_pre hc_pre hparc' hp_pre
  -- d_c.policy = d_c_pre.policy, d_p.policy = d_p_pre.policy
  rw [← hpc, ← hpp]; exact hbase

-- ════════════════════════════════════════════════════════════════════
-- § 7.  Top theorem
-- ════════════════════════════════════════════════════════════════════

theorem step_preservesPolicyMonotonicAncestry
    {s s' : SpecState} {a : Action}
    (hwf : WellFormed s) (hstep : step s a s') :
    PolicyMonotonicAncestry s' := by
  have h := hwf.policyAncestry
  cases hstep with
  | carve _             => exact carve_preservesPolicyMonotonicAncestry           _ _ _ _ _ h
  | alias _             => exact alias_preservesPolicyMonotonicAncestry           _ _ _ _ h
  | revoke _            => exact revoke_preservesPolicyMonotonicAncestry          _ _ _ h
  | send _              => exact send_preservesPolicyMonotonicAncestry            _ _ _ _ h
  | «seal» _            => exact seal_preservesPolicyMonotonicAncestry            _ _ _ h
  | accept _            => exact accept_preservesPolicyMonotonicAncestry          _ _ _ h
  | reject _            => exact reject_preservesPolicyMonotonicAncestry          _ _ _ h
  | sealedSend _        => exact sealedSend_preservesPolicyMonotonicAncestry      _ _ _ _ _ h
  | create guard        =>
      exact create_preservesPolicyMonotonicAncestry guard
              hwf.domainTreeWf.parentResolves hwf.freshDomCounter h
  | revokeDomain _      => exact revokeDomain_preservesPolicyMonotonicAncestry    _ _ _ h
  | setPolicy guard     => exact setPolicy_preservesPolicyMonotonicAncestry _ _ _ _ _ guard hwf.domainTreeWf.parentChild h
  | sendChannel _       => exact sendChannel_preservesPolicyMonotonicAncestry     _ _ _ _ h
  | acceptChannel _     => exact acceptChannel_preservesPolicyMonotonicAncestry   _ _ _ h
  | rejectChannel _     => exact rejectChannel_preservesPolicyMonotonicAncestry   _ _ _ h
  | switchReturn _      => exact switchReturn_preservesPolicyMonotonicAncestry    h
  | switch _            => exact switch_preservesPolicyMonotonicAncestry          h
  | switchSuspended _   => exact switchSuspended_preservesPolicyMonotonicAncestry h
  | deliverInterrupt _  => exact deliverInterrupt_preservesPolicyMonotonicAncestry _ _ _ _ _ _ h
  | addVp _             => exact addVp_preservesPolicyMonotonicAncestry           _ _ _ _ h
  | registerComm _      => exact registerComm_preservesPolicyMonotonicAncestry    _ _ _ _ _ h
  | mapSelf _           => exact mapSelf_preservesPolicyMonotonicAncestry         _ _ _ _ h
  | attestSelf _        => exact h
  | attest _            => exact h
  | getPolicy _         => exact h
  | getChan _           => exact h
  | getChanSelf _       => exact h
  | sealedSendChannel _ => exact sealedSendChannel_preservesPolicyMonotonicAncestry _ _ _ _ h
  | send_at _           => exact send_at_preservesPolicyMonotonicAncestry         _ _ _ _ _ h
  | accept_at _         => exact accept_at_preservesPolicyMonotonicAncestry       _ _ _ _ h

end ThemisCapa
