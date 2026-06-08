/-
  ThemisCapa.FreshPending — a `nextPendingId`-freshness invariant.

  ## Statement

  For every domain `d`, every key in `d.pendingMemCaps` and
  `d.pendingDomCaps` is strictly less than `d.nextPendingId`.

  This is the analog of `FreshMemCounter` and `FreshDomCounter` for
  pending IPC entries. It guarantees that the freshly-allocated
  `nextPendingId` does not collide with any existing entry, which is
  exactly what the O3 round-trip integrity theorem needs to derive
  `lookupPending` of the new entry's id.

  ## Why standalone (not in `WellFormed`)?

  Adding a 12th field to `WellFormed` would force changes to all 8
  existing `WellFormed.mk` call sites in `Properties.lean`. Instead
  we prove `FreshPending` is preserved by `step` as a separate
  theorem and consume it directly. A future cleanup may promote it
  into `WellFormed`.
-/
import ThemisCapa.Step
import ThemisCapa.Locality
import ThemisCapa.Invariants

namespace ThemisCapa
open Arena

-- ════════════════════════════════════════════════════════════════════
-- Primitive preservation helpers
-- ════════════════════════════════════════════════════════════════════

/-- Generic `updDomain` lift: if `f` preserves `FreshPending`'s bound
    pointwise on the targeted domain record, the global invariant is
    preserved. -/
theorem freshPending_updDomain
    {s : SpecState} (h : FreshPending s) (x : DomId) (f : Domain → Domain)
    (hf : ∀ d_pre, s.getDom x = some d_pre →
            (∀ p ∈ (f d_pre).pendingMemCaps, p.1 < (f d_pre).nextPendingId) ∧
            (∀ p ∈ (f d_pre).pendingDomCaps, p.1 < (f d_pre).nextPendingId)) :
    FreshPending (s.updDomain x f) := by
  intro did d hd
  unfold SpecState.updDomain SpecState.getDom at hd
  by_cases heq : did = x
  · subst heq
    rw [Arena.find?_update_eq_map] at hd
    rcases hpre : s.domains.find? did with _ | d_pre
    · rw [hpre] at hd; cases hd
    · rw [hpre] at hd
      simp only [Option.map_some, Option.some.injEq] at hd
      rw [← hd]; exact hf d_pre hpre
  · rw [Arena.find?_update_other _ _ _ _ heq] at hd
    exact h did d hd

/-- Specialization: `f` preserves the three pending fields field-by-field. -/
theorem freshPending_updDomain_id
    {s : SpecState} (h : FreshPending s) (x : DomId) (f : Domain → Domain)
    (h1 : ∀ d, (f d).pendingMemCaps = d.pendingMemCaps)
    (h2 : ∀ d, (f d).pendingDomCaps = d.pendingDomCaps)
    (h3 : ∀ d, (f d).nextPendingId = d.nextPendingId) :
    FreshPending (s.updDomain x f) := by
  apply freshPending_updDomain h
  intro d_pre hpre
  rw [h1, h2, h3]
  exact h x d_pre hpre

/-- Filter on `pendingMemCaps` preserves the bound (no other field changes). -/
theorem freshPending_updDomain_filter_pendingMem
    {s : SpecState} (h : FreshPending s) (x : DomId)
    (pred : PendingId × PendingMemCap → Bool) :
    FreshPending (s.updDomain x (fun d =>
      { d with pendingMemCaps := d.pendingMemCaps.filter pred })) := by
  apply freshPending_updDomain h
  intro d_pre hpre
  refine ⟨?_, ?_⟩
  · intro p hp; exact (h x d_pre hpre).1 p (List.mem_filter.mp hp).1
  · intro p hp; exact (h x d_pre hpre).2 p hp

/-- Filter on `pendingDomCaps` preserves the bound. -/
theorem freshPending_updDomain_filter_pendingDom
    {s : SpecState} (h : FreshPending s) (x : DomId)
    (pred : PendingId × PendingDomCap → Bool) :
    FreshPending (s.updDomain x (fun d =>
      { d with pendingDomCaps := d.pendingDomCaps.filter pred })) := by
  apply freshPending_updDomain h
  intro d_pre hpre
  refine ⟨?_, ?_⟩
  · intro p hp; exact (h x d_pre hpre).1 p hp
  · intro p hp; exact (h x d_pre hpre).2 p (List.mem_filter.mp hp).1

/-- The headline append-and-bump case (sealedSend's receiver branch). -/
theorem freshPending_updDomain_sealedSendReceiver
    {s : SpecState} (h : FreshPending s) (x : DomId)
    (mk : Domain → PendingMemCap) :
    FreshPending (s.updDomain x (fun d =>
      { d with pendingMemCaps := d.pendingMemCaps ++ [(d.nextPendingId, mk d)],
               nextPendingId  := d.nextPendingId + 1 })) := by
  apply freshPending_updDomain h
  intro d_pre hpre
  refine ⟨?_, ?_⟩
  · intro p hp
    rcases List.mem_append.mp hp with hin | hin
    · exact Nat.lt_succ_of_lt ((h x d_pre hpre).1 p hin)
    · simp only [List.mem_singleton] at hin; rw [hin]; exact Nat.lt_succ_self _
  · intro p hp
    exact Nat.lt_succ_of_lt ((h x d_pre hpre).2 p hp)

/-- The headline append-and-bump case for the channel variant
    (sealedSendChannel's receiver branch). -/
theorem freshPending_updDomain_sealedSendChannelReceiver
    {s : SpecState} (h : FreshPending s) (x : DomId)
    (mk : Domain → PendingDomCap) :
    FreshPending (s.updDomain x (fun d =>
      { d with pendingDomCaps := d.pendingDomCaps ++ [(d.nextPendingId, mk d)],
               nextPendingId  := d.nextPendingId + 1 })) := by
  apply freshPending_updDomain h
  intro d_pre hpre
  refine ⟨?_, ?_⟩
  · intro p hp
    exact Nat.lt_succ_of_lt ((h x d_pre hpre).1 p hp)
  · intro p hp
    rcases List.mem_append.mp hp with hin | hin
    · exact Nat.lt_succ_of_lt ((h x d_pre hpre).2 p hin)
    · simp only [List.mem_singleton] at hin; rw [hin]; exact Nat.lt_succ_self _

/-- Non-domain primitives leave `FreshPending` definitionally untouched. -/
theorem freshPending_updMem
    {s : SpecState} (h : FreshPending s) (id : MemCapId) (g : MemCap → MemCap) :
    FreshPending (s.updMem id g) := h

theorem freshPending_updDomCap
    {s : SpecState} (h : FreshPending s) (id : DomCapId) (g : DomCap → DomCap) :
    FreshPending (s.updDomCap id g) := h

theorem freshPending_updCore
    {s : SpecState} (h : FreshPending s) (id : CoreId) (g : CoreState → CoreState) :
    FreshPending (s.updCore id g) := h

theorem freshPending_freshMem
    {s : SpecState} (h : FreshPending s) (c : MemCap) :
    FreshPending (s.freshMem c).snd := h

theorem freshPending_freshDomCap
    {s : SpecState} (h : FreshPending s) (dc : DomCap) :
    FreshPending (s.freshDomCap dc).snd := h

/-- `freshDom` allocating a domain whose pending lists are empty
    (and `nextPendingId = 0`) preserves `FreshPending`. -/
theorem freshPending_freshDom_empty
    {s : SpecState} (h : FreshPending s) (dm : Domain)
    (h1 : dm.pendingMemCaps = []) (h2 : dm.pendingDomCaps = []) :
    FreshPending (s.freshDom dm).snd := by
  intro did d hd
  unfold SpecState.freshDom SpecState.getDom at hd
  by_cases heq : did = s.nextDomId
  · subst heq
    rw [Arena.find?_insert_same] at hd
    cases hd
    refine ⟨?_, ?_⟩
    · rw [h1]; intro p hp; cases hp
    · rw [h2]; intro p hp; cases hp
  · rw [Arena.find?_insert_other _ _ _ _ heq] at hd
    exact h did d hd

/-- Removing a domain preserves `FreshPending` vacuously. -/
theorem freshPending_domains_remove
    {s : SpecState} (h : FreshPending s) (target : DomId) :
    FreshPending { s with domains := s.domains.remove target } := by
  intro did d hd
  unfold SpecState.getDom at hd
  by_cases heq : did = target
  · subst heq
    rw [Arena.find?_remove_same] at hd; cases hd
  · rw [Arena.find?_remove_other _ _ _ heq] at hd
    exact h did d hd

theorem freshPending_domcaps_set
    {s : SpecState} (h : FreshPending s) (dcs : Arena DomCapId DomCap) :
    FreshPending { s with domcaps := dcs } := h

-- ════════════════════════════════════════════════════════════════════
-- Per-action preservation lemmas (using simp-unfold pattern from Locality.lean)
-- ════════════════════════════════════════════════════════════════════

theorem carve_preservesFreshPending
    (s : SpecState) (caller : DomId) (parent : MemCapId)
    (access : Access) (attrs : Attributes) (h : FreshPending s) :
    FreshPending (carve_apply s caller parent access attrs) := by
  rcases hm : s.getMem parent with _ | p
  · simp only [carve_apply, hm]; exact h
  · simp only [carve_apply, hm]
    exact freshPending_updDomain_id
      (freshPending_updMem (freshPending_freshMem h _) _ _) caller _
      (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)

theorem alias_preservesFreshPending
    (s : SpecState) (caller : DomId) (parent : MemCapId) (access : Access)
    (h : FreshPending s) :
    FreshPending (alias_apply s caller parent access) := by
  rcases hm : s.getMem parent with _ | p
  · simp only [alias_apply, hm]; exact h
  · simp only [alias_apply, hm]
    exact freshPending_updDomain_id
      (freshPending_updMem (freshPending_freshMem h _) _ _) caller _
      (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)

theorem revoke_preservesFreshPending
    (s : SpecState) (caller : DomId) (target : MemCapId) (h : FreshPending s) :
    FreshPending (revoke_apply s caller target) := by
  rcases hm : s.getMem target with _ | t
  · simp only [revoke_apply, hm]; exact h
  · rcases hp : t.parent with _ | pid
    · simp only [revoke_apply, hm, hp]; exact h
    · simp only [revoke_apply, hm, hp]
      have h1 : FreshPending { s with memcaps := s.memcaps.remove target } := h
      have h2 := freshPending_updMem h1 pid (fun p =>
        { p with childrenIds := p.childrenIds.filter (· ≠ target) })
      have h3 := freshPending_updDomain_id h2 t.owner
        (fun d => { d with memHandles := d.memHandles.filter (fun h => h.2 ≠ target) })
        (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)
      by_cases hv : t.region.attributes.vital
      · rw [if_pos hv]
        exact freshPending_updDomain_id h3 t.owner
          (fun d => { d with status := .revoked })
          (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)
      · rw [if_neg hv]; exact h3

theorem send_preservesFreshPending
    (s : SpecState) (caller receiver : DomId) (cap : MemCapId)
    (h : FreshPending s) :
    FreshPending (send_apply s caller receiver cap) := by
  simp only [send_apply]
  apply freshPending_updMem _ cap _
  apply freshPending_updDomain_id _ receiver
    (fun d => { d with memHandles := d.memHandles ++ [(d.nextHandle, cap)],
                       nextHandle := d.nextHandle + 1 })
    (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)
  exact freshPending_updDomain_id h caller
    (fun d => { d with memHandles := d.memHandles.filter (fun h => h.2 ≠ cap) })
    (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)

theorem seal_preservesFreshPending
    (s : SpecState) (caller : DomId) (cap : DomCapId) (h : FreshPending s) :
    FreshPending (seal_apply s caller cap) := by
  rcases hc : s.getDomCap cap with _ | dc
  · simp only [seal_apply, hc]; exact h
  · simp only [seal_apply, hc]
    exact freshPending_updDomain_id h dc.targetDom
      (fun d => { d with status := .sealed })
      (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)

theorem accept_preservesFreshPending
    (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    (h : FreshPending s) :
    FreshPending (accept_apply s receiver pendingId) := by
  rcases hp : (s.getDom receiver).bind (fun d => d.lookupPending pendingId)
    with _ | pe
  · simp only [accept_apply, hp]; exact h
  · simp only [accept_apply, hp]
    have h1 := send_preservesFreshPending s pe.senderDomainId receiver pe.capId h
    have h2 := freshPending_updDomain_filter_pendingMem h1 receiver
      (fun p => p.1 ≠ pendingId)
    exact freshPending_updDomain_id h2 pe.senderDomainId
      (fun d => { d with frozenHandles :=
                  d.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })
      (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)

theorem reject_preservesFreshPending
    (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    (h : FreshPending s) :
    FreshPending (reject_apply s receiver pendingId) := by
  simp only [reject_apply]
  have h1 := freshPending_updDomain_filter_pendingMem h receiver
    (fun p => p.1 ≠ pendingId)
  rcases hp : (s.getDom receiver).bind (fun d => d.lookupPending pendingId)
    with _ | pe
  · simp only [hp]; exact h1
  · simp only [hp]
    exact freshPending_updDomain_id h1 pe.senderDomainId
      (fun d => { d with frozenHandles :=
                  d.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })
      (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)

theorem sealedSend_preservesFreshPending
    (s : SpecState) (caller receiver : DomId) (handle : LocalHandle)
    (gpaHint : Option Nat) (h : FreshPending s) :
    FreshPending (sealedSend_apply s caller receiver handle gpaHint) := by
  rcases hp : (s.getDom caller).bind (fun d => d.lookupMemHandle handle)
    with _ | capId
  · simp only [sealedSend_apply, hp]; exact h
  · simp only [sealedSend_apply, hp]
    have h1 := freshPending_updDomain_id h caller
      (fun d => { d with frozenHandles := d.frozenHandles ++ [handle] })
      (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)
    exact freshPending_updDomain_sealedSendReceiver h1 receiver
      (fun _ => { capId := capId, senderDomainId := caller,
                  senderHandle := handle, gpaHint := gpaHint })

theorem sealedSendChannel_preservesFreshPending
    (s : SpecState) (caller receiver : DomId) (handle : LocalHandle)
    (h : FreshPending s) :
    FreshPending (sealedSendChannel_apply s caller receiver handle) := by
  rcases hp : (s.getDom caller).bind (fun d => d.lookupDomHandle handle)
    with _ | capId
  · simp only [sealedSendChannel_apply, hp]; exact h
  · simp only [sealedSendChannel_apply, hp]
    have h1 := freshPending_updDomain_id h caller
      (fun d => { d with frozenHandles := d.frozenHandles ++ [handle] })
      (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)
    exact freshPending_updDomain_sealedSendChannelReceiver h1 receiver
      (fun _ => { capId := capId, senderDomainId := caller,
                  senderHandle := handle })

theorem send_at_preservesFreshPending
    (s : SpecState) (caller receiver : DomId) (cap : MemCapId)
    (gpaHint : Option Nat) (h : FreshPending s) :
    FreshPending (send_at_apply s caller receiver cap gpaHint) := by
  simp only [send_at_apply]; exact send_preservesFreshPending s caller receiver cap h

theorem accept_at_preservesFreshPending
    (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    (gpaOverride : Option Nat) (h : FreshPending s) :
    FreshPending (accept_at_apply s receiver pendingId gpaOverride) := by
  simp only [accept_at_apply]; exact accept_preservesFreshPending s receiver pendingId h

theorem setPolicy_preservesFreshPending
    (s : SpecState) (caller : DomId) (cap : DomCapId)
    (id : PolicyIdentifier) (value : Nat) (h : FreshPending s) :
    FreshPending (setPolicy_apply s caller cap id value) := by
  rcases hc : s.getDomCap cap with _ | dc
  · simp only [setPolicy_apply, hc]; exact h
  · simp only [setPolicy_apply, hc]
    exact freshPending_updDomain_id h dc.targetDom
      (fun d => { d with policy := applyPolicyValue d.policy id value })
      (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)

theorem sendChannel_preservesFreshPending
    (s : SpecState) (caller receiver : DomId) (cap : DomCapId)
    (h : FreshPending s) :
    FreshPending (sendChannel_apply s caller receiver cap) := by
  simp only [sendChannel_apply]
  apply freshPending_updDomCap _ cap
  apply freshPending_updDomain_id _ receiver
    (fun d => { d with domHandles := d.domHandles ++ [(d.nextHandle, cap)],
                       nextHandle := d.nextHandle + 1 })
    (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)
  exact freshPending_updDomain_id h caller
    (fun d => { d with domHandles := d.domHandles.filter (fun h => h.2 ≠ cap) })
    (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)

theorem acceptChannel_preservesFreshPending
    (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    (h : FreshPending s) :
    FreshPending (acceptChannel_apply s receiver pendingId) := by
  rcases hp : (s.getDom receiver).bind (fun d => d.lookupPendingDom pendingId)
    with _ | pe
  · simp only [acceptChannel_apply, hp]; exact h
  · simp only [acceptChannel_apply, hp]
    have h1 := sendChannel_preservesFreshPending s pe.senderDomainId receiver pe.capId h
    have h2 := freshPending_updDomain_filter_pendingDom h1 receiver
      (fun p => p.1 ≠ pendingId)
    exact freshPending_updDomain_id h2 pe.senderDomainId
      (fun d => { d with frozenHandles :=
                  d.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })
      (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)

theorem rejectChannel_preservesFreshPending
    (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    (h : FreshPending s) :
    FreshPending (rejectChannel_apply s receiver pendingId) := by
  simp only [rejectChannel_apply]
  have h1 := freshPending_updDomain_filter_pendingDom h receiver
    (fun p => p.1 ≠ pendingId)
  rcases hp : (s.getDom receiver).bind (fun d => d.lookupPendingDom pendingId)
    with _ | pe
  · simp only [hp]; exact h1
  · simp only [hp]
    exact freshPending_updDomain_id h1 pe.senderDomainId
      (fun d => { d with frozenHandles :=
                  d.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })
      (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)

theorem switchReturn_preservesFreshPending
    (s : SpecState) (caller : DomId) (core : CoreId)
    (exitReason : Option Nat) (h : FreshPending s) :
    FreshPending (switchReturn_apply s caller core exitReason) := by
  rcases hp : (s.getDom caller).bind (fun d => d.vpAndPrevCallerOnCore core)
    with _ | vp
  · simp only [switchReturn_apply, hp]; exact h
  · simp only [switchReturn_apply, hp]
    apply freshPending_updCore _ core
    apply freshPending_updDomain_id _ vp.2.domainId
      (fun d => d.updVp vp.2.vpId (fun vp =>
        match vp.runState with
        | .locked _ _ prevPrev => { vp with runState := .running core prevPrev }
        | other                => { vp with runState := other }))
      (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)
    exact freshPending_updDomain_id h caller
      (fun d => d.updVp vp.1 (fun vp =>
        { vp with runState := .available exitReason }))
      (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)

theorem switch_preservesFreshPending
    (s : SpecState) (caller : DomId) (toHandle : LocalHandle)
    (toVpId : VpId) (core : CoreId) (h : FreshPending s) :
    FreshPending (switch_apply s caller toHandle toVpId core) := by
  rcases hh : (s.getDom caller).bind (fun d => d.lookupDomHandle toHandle)
    with _ | cid
  · simp only [switch_apply, hh]; exact h
  · rcases hc : s.getDomCap cid with _ | dc
    · simp only [switch_apply, hh, hc]; exact h
    · rcases hv : (s.getDom caller).bind (fun d => d.vpAndOptPrevOnCore core)
        with _ | vpv
      · simp only [switch_apply, hh, hc, hv]; exact h
      · simp only [switch_apply, hh, hc, hv]
        apply freshPending_updCore _ core
        apply freshPending_updDomain_id _ caller
          (fun d => d.updVp vpv.1 (fun vp =>
            { vp with runState := .locked dc.targetDom toVpId vpv.2 }))
          (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)
        exact freshPending_updDomain_id h dc.targetDom
          (fun d => d.updVp toVpId (fun vp =>
            { vp with runState :=
                VpRunState.running core (some { domainId := caller, vpId := vpv.1 }) }))
          (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)

theorem switchSuspended_preservesFreshPending
    (s : SpecState) (caller : DomId) (toHandle : LocalHandle)
    (toVpId : VpId) (core : CoreId)
    (calleeDom : DomId) (calleeVp : VpId) (h : FreshPending s) :
    FreshPending (switchSuspended_apply s caller toHandle toVpId core calleeDom calleeVp) := by
  rcases hh : (s.getDom caller).bind (fun d => d.lookupDomHandle toHandle)
    with _ | cid
  · simp only [switchSuspended_apply, hh]; exact h
  · rcases hc : s.getDomCap cid with _ | dc
    · simp only [switchSuspended_apply, hh, hc]; exact h
    · rcases hv : (s.getDom caller).bind (fun d => d.vpAndOptPrevOnCore core)
        with _ | vpv
      · simp only [switchSuspended_apply, hh, hc, hv]; exact h
      · simp only [switchSuspended_apply, hh, hc, hv]
        have h1 := freshPending_updDomain_id h dc.targetDom
          (fun d => d.updVp toVpId (fun vp =>
            { vp with runState :=
                VpRunState.running core (some { domainId := caller, vpId := vpv.1 }) }))
          (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)
        have h2 := freshPending_updDomain_id h1 calleeDom
          (fun d => d.updVp calleeVp (fun vp =>
            match vp.runState with
            | .interrupted _ => { vp with runState := .available none }
            | _              => vp))
          (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)
        have h3 := freshPending_updDomain_id h2 caller
          (fun d => d.updVp vpv.1 (fun vp =>
            { vp with runState := .locked dc.targetDom toVpId vpv.2 }))
          (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)
        exact freshPending_updCore h3 core _

theorem addVp_preservesFreshPending
    (s : SpecState) (caller : DomId) (childHandle commHandle : LocalHandle)
    (h : FreshPending s) :
    FreshPending (addVp_apply s caller childHandle commHandle) := by
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
          apply freshPending_updMem _ mid
          exact freshPending_updDomain_id h dc.targetDom
            (fun d =>
              { d with vps := d.vps ++
                         [{ id := cd.vps.length, runState := .available none }],
                       commBindings := d.commBindings ++ [mid] })
            (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)

theorem registerComm_preservesFreshPending
    (s : SpecState) (caller : DomId) (commHandle childHandle : LocalHandle)
    (vpId : VpId) (h : FreshPending s) :
    FreshPending (registerComm_apply s caller commHandle childHandle vpId) := by
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
          apply freshPending_updMem _ mid
          exact freshPending_updDomain_id h dc.targetDom
            (fun d => { d with commBindings := d.commBindings ++ [mid] })
            (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)

theorem mapSelf_preservesFreshPending
    (s : SpecState) (caller : DomId) (capHandle : LocalHandle) (newGpa : Nat)
    (h : FreshPending s) :
    FreshPending (mapSelf_apply s caller capHandle newGpa) := by
  rcases hd : s.getDom caller with _ | d
  · simp only [mapSelf_apply, hd]; exact h
  · rcases hh : d.lookupMemHandle capHandle with _ | mid
    · simp only [mapSelf_apply, hd, hh]; exact h
    · rcases hcm : s.getMem mid with _ | c
      · simp only [mapSelf_apply, hd, hh, hcm]; exact h
      · rcases hg : d.lookupMappedGpa capHandle with _ | _
        · simp only [mapSelf_apply, hd, hh, hcm, hg]; exact h
        · simp only [mapSelf_apply, hd, hh, hcm, hg]
          apply freshPending_updDomain_id h caller _
          all_goals
            intro d'
            unfold Domain.updMappedGpa
            split <;> rfl

theorem create_preservesFreshPending
    (s : SpecState) (caller : DomId) (policy : DomainPolicy)
    (h : FreshPending s) :
    FreshPending (create_apply s caller policy) := by
  simp only [create_apply]
  exact freshPending_updDomain_id
    (freshPending_freshDomCap
      (freshPending_freshDom_empty h _ rfl rfl) _) caller _
    (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)

theorem revokeDomain_preservesFreshPending
    (s : SpecState) (caller : DomId) (handle : LocalHandle)
    (h : FreshPending s) :
    FreshPending (revokeDomain_apply s caller handle) := by
  -- Phase A (S4 plan, checkpoint 005): pending recursive subtree proof.
  -- Channel cancellation removes pending entries (decreases); per-domain
  -- nextPendingId stays monotone. Phase B will reduce this to a fold.
  sorry

-- ════════════════════════════════════════════════════════════════════
-- deliverInterrupt: chain induction
-- ════════════════════════════════════════════════════════════════════

theorem applyMidsAndHandler_preservesFreshPending
    (core : CoreId) (vector : Nat) :
    ∀ (prev : DomId × VpId) (chain : List (DomId × VpId)) (s : SpecState),
      FreshPending s → FreshPending (applyMidsAndHandler core vector prev chain s)
  | _,        [],            _, h => h
  | _,        [handler],     _, h => by
    simp only [applyMidsAndHandler]
    exact freshPending_updDomain_id h handler.1
      (fun d => d.updVp handler.2 (fun vp =>
        match vp.runState with
        | .locked _ _ p => { vp with runState := .running core p }
        | other         => { vp with runState := other }))
      (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)
  | prev,     mid :: a :: rest, _, h => by
    simp only [applyMidsAndHandler]
    exact applyMidsAndHandler_preservesFreshPending core vector mid (a :: rest) _
      (freshPending_updDomain_id h mid.1
        (fun d => d.updVp mid.2 (fun vp =>
          { vp with runState := .suspended prev.1 prev.2 vector }))
        (fun _ => rfl) (fun _ => rfl) (fun _ => rfl))

theorem deliverInterrupt_preservesFreshPending
    (s : SpecState) (interrupted handler : DomId) (core : CoreId)
    (vector : Nat) (chain : List (DomId × VpId)) (h : FreshPending s) :
    FreshPending (deliverInterrupt_apply s interrupted handler core vector chain) := by
  match chain with
  | []           => simp only [deliverInterrupt_apply]; exact h
  | [_]          => simp only [deliverInterrupt_apply]; exact h
  | leaf :: a :: rest =>
    simp only [deliverInterrupt_apply]
    have h1 := freshPending_updDomain_id h leaf.1
      (fun d => d.updVp leaf.2 (fun vp =>
        { vp with runState := VpRunState.interrupted vector }))
      (fun _ => rfl) (fun _ => rfl) (fun _ => rfl)
    have h2 := applyMidsAndHandler_preservesFreshPending core vector leaf
      (a :: rest) _ h1
    rcases hl : (leaf :: a :: rest).getLast? with _ | lh
    · simp only [hl]; exact h2
    · simp only [hl]
      exact freshPending_updCore h2 core (fun _ => .runningDomain lh.1 lh.2)

-- ════════════════════════════════════════════════════════════════════
-- Top theorem
-- ════════════════════════════════════════════════════════════════════

/-- `step` preserves `FreshPending`. -/
theorem step_preservesFreshPending
    {s s' : SpecState} {a : Action} (h : FreshPending s) (hstep : step s a s') :
    FreshPending s' := by
  cases hstep with
  | carve _             => exact carve_preservesFreshPending           _ _ _ _ _ h
  | alias _             => exact alias_preservesFreshPending           _ _ _ _ h
  | revoke _            => exact revoke_preservesFreshPending          _ _ _ h
  | send _              => exact send_preservesFreshPending            _ _ _ _ h
  | «seal» _            => exact seal_preservesFreshPending            _ _ _ h
  | accept _            => exact accept_preservesFreshPending          _ _ _ h
  | reject _            => exact reject_preservesFreshPending          _ _ _ h
  | sealedSend _        => exact sealedSend_preservesFreshPending      _ _ _ _ _ h
  | create _            => exact create_preservesFreshPending          _ _ _ h
  | revokeDomain _      => exact revokeDomain_preservesFreshPending    _ _ _ h
  | setPolicy _         => exact setPolicy_preservesFreshPending       _ _ _ _ _ h
  | sendChannel _       => exact sendChannel_preservesFreshPending     _ _ _ _ h
  | acceptChannel _     => exact acceptChannel_preservesFreshPending   _ _ _ h
  | rejectChannel _     => exact rejectChannel_preservesFreshPending   _ _ _ h
  | switchReturn _      => exact switchReturn_preservesFreshPending    _ _ _ _ h
  | switch _            => exact switch_preservesFreshPending          _ _ _ _ _ h
  | switchSuspended _   => exact switchSuspended_preservesFreshPending _ _ _ _ _ _ _ h
  | deliverInterrupt _  => exact deliverInterrupt_preservesFreshPending _ _ _ _ _ _ h
  | addVp _             => exact addVp_preservesFreshPending           _ _ _ _ h
  | registerComm _      => exact registerComm_preservesFreshPending    _ _ _ _ _ h
  | mapSelf _           => exact mapSelf_preservesFreshPending         _ _ _ _ h
  | attestSelf _        => exact h
  | attest _            => exact h
  | getPolicy _         => exact h
  | getChan _           => exact h
  | getChanSelf _       => exact h
  | sealedSendChannel _ => exact sealedSendChannel_preservesFreshPending _ _ _ _ h
  | send_at _           => exact send_at_preservesFreshPending         _ _ _ _ _ h
  | accept_at _         => exact accept_at_preservesFreshPending       _ _ _ _ h

end ThemisCapa
