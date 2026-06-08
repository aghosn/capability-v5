/-
  ThemisCapa.NonInterference — The capability-system payoff theorem.

  Combining `Locality` (per-action frame lemmas) and `Properties` /
  `Invariants` (existence + ownership accounting), we get:

  **If a domain B is outside an action's "view footprint", then B's
  observable state is unchanged by the step.** B's "view" comprises
  its own `Domain` record plus every memcap owned by B.

  Two flavors are exposed:

  * `step_non_interference` — atomic version: explicit `¬affectsDom B`
    and `¬affectsMem c` hypotheses. Trivial corollary of the locality
    theorems; convenient API.

  * `step_view_preservation` — the deep version: only requires
    `¬ a.affectsView s B`, where `affectsView` is the `affectsDom`
    footprint plus `{caller}` for `revoke` (whose `parent` cap is
    modified and owned by the caller, but whose caller's domain
    entry is itself unchanged). View preservation derives ¬affectsMem
    for every B-owned cap automatically using the action guards and
    the `HandleOwner` WF invariant.

  Slogan: "what you don't participate in can't change your world".
-/
import ThemisCapa.Locality
import ThemisCapa.Properties

namespace ThemisCapa
open Arena

/-! ## Atomic non-interference

A direct conjunction of the two locality theorems. -/

theorem step_non_interference
    {s s' : SpecState} {a : Action} (hstep : step s a s')
    {B : DomId} (hBdom : ¬ a.affectsDom s B)
    {c : MemCapId} (hcmem : ¬ a.affectsMem s c) :
    s'.getDom B = s.getDom B ∧ s'.getMem c = s.getMem c :=
  ⟨step_locality_dom hstep hBdom, step_locality_mem hstep hcmem⟩

/-! ## View footprint

`affectsView` extends `affectsDom` with caller-for-revoke (the one
case where the modified cap's owner — the caller — is not in
`affectsDom`). -/

def Action.affectsView (s : SpecState) (a : Action) (did : DomId) : Prop :=
  a.affectsDom s did ∨
    (∃ caller target, a = .revoke caller target ∧ did = caller) ∨
    (∃ caller ch cm, a = .addVp caller ch cm ∧ did = caller) ∨
    (∃ caller cm ch vp, a = .registerComm caller cm ch vp ∧ did = caller)

private theorem not_affectsDom_of_not_affectsView
    {s : SpecState} {a : Action} {did : DomId}
    (h : ¬ a.affectsView s did) : ¬ a.affectsDom s did :=
  fun hd => h (Or.inl hd)

/-! ## Lookup helpers -/

private theorem lookupMemHandle_mem
    (d : Domain) (h : LocalHandle) (parent : MemCapId)
    (hh : d.lookupMemHandle h = some parent) :
    ∃ p ∈ d.memHandles, p.2 = parent := by
  simp only [Domain.lookupMemHandle, Option.map_eq_some_iff] at hh
  obtain ⟨p, hp, hsnd⟩ := hh
  exact ⟨p, List.mem_of_find?_eq_some hp, hsnd⟩

/-- If domain `d` has a handle to `parent`, and WF holds, then `d` owns
    `parent`'s underlying memcap (provided it exists). -/
private theorem handle_implies_owner
    {s : SpecState} (hwf : WellFormed s) {did : DomId} {d : Domain}
    (hd : s.getDom did = some d) {h : LocalHandle} {parent : MemCapId}
    (hh : d.lookupMemHandle h = some parent)
    {p : MemCap} (hp : s.getMem parent = some p) :
    p.owner = did := by
  obtain ⟨pair, hpair, hsnd⟩ := lookupMemHandle_mem d h parent hh
  obtain ⟨c, hc, hco⟩ := hwf.handleOwner did d hd pair hpair
  rw [hsnd, hp] at hc; injection hc with hce
  rw [← hco, hce]

/-! ## View preservation

The headline theorem: a domain outside the view footprint sees no
change to either its own record or to any memcap it owns. -/

theorem step_view_preservation
    {s s' : SpecState} {a : Action} (hwf : WellFormed s)
    (hstep : step s a s')
    {B : DomId} (hB : ¬ a.affectsView s B) :
    s'.getDom B = s.getDom B ∧
    ∀ c capPre, s.getMem c = some capPre → capPre.owner = B →
      s'.getMem c = s.getMem c := by
  refine ⟨step_locality_dom hstep (not_affectsDom_of_not_affectsView hB), ?_⟩
  intro c capPre hPre hown
  apply step_locality_mem hstep
  -- Show ¬ a.affectsMem s c. Case-split on the action.
  cases hstep with
  | carve guard =>
    rename_i caller parent access attrs
    have hBcaller : B ≠ caller := fun he => hB (Or.inl he)
    have hcne : c ≠ s.nextMemCapId :=
      Nat.ne_of_lt (existing_lt_fresh s hwf.freshMemCounter hPre)
    have hcnep : c ≠ parent := by
      intro hep
      obtain ⟨dc, hdc⟩ := Option.isSome_iff_exists.mp guard.callerExists
      obtain ⟨h, hh⟩ := guard.parentOwned dc hdc
      have hp_caller : capPre.owner = caller := by
        rw [hep] at hPre
        exact handle_implies_owner hwf hdc hh hPre
      exact hBcaller (hown.symm.trans hp_caller)
    intro hmem
    rcases hmem with hnew | hpar
    · exact hcne hnew
    · exact hcnep hpar
  | alias guard =>
    rename_i caller parent access
    have hBcaller : B ≠ caller := fun he => hB (Or.inl he)
    have hcne : c ≠ s.nextMemCapId :=
      Nat.ne_of_lt (existing_lt_fresh s hwf.freshMemCounter hPre)
    have hcnep : c ≠ parent := by
      intro hep
      obtain ⟨dc, hdc⟩ := Option.isSome_iff_exists.mp guard.callerExists
      obtain ⟨h, hh⟩ := guard.parentOwned dc hdc
      have hp_caller : capPre.owner = caller := by
        rw [hep] at hPre
        exact handle_implies_owner hwf hdc hh hPre
      exact hBcaller (hown.symm.trans hp_caller)
    intro hmem
    rcases hmem with hnew | hpar
    · exact hcne hnew
    · exact hcnep hpar
  | revoke guard =>
    rename_i caller target
    have hBcaller : B ≠ caller :=
      fun he => hB (Or.inr (Or.inl ⟨caller, target, rfl, he⟩))
    obtain ⟨t, ht⟩ := Option.isSome_iff_exists.mp guard.targetExists
    obtain ⟨pid, htp⟩ :=
      Option.isSome_iff_exists.mp (guard.targetHasParent t ht)
    have hBtarget : B ≠ t.owner :=
      fun he => hB (Or.inl (fun t' ht' => by
        rw [ht] at ht'; injection ht' with hh; rw [← hh]; exact he))
    intro hmem
    rcases hmem with hT | hP
    · have hpe : capPre = t := by
        rw [hT, ht] at hPre; injection hPre with h; exact h.symm
      have : capPre.owner = t.owner := by rw [hpe]
      exact hBtarget (hown.symm.trans this)
    · have hcEq : c = pid := hP t ht pid htp
      obtain ⟨p, hp⟩ :=
        Option.isSome_iff_exists.mp (hwf.refs.parentInArena target t ht pid htp)
      have hpown : p.owner = caller := guard.callerOwnsParent t ht pid htp p hp
      have hcap_eq : capPre = p := by
        rw [hcEq, hp] at hPre; injection hPre with h; exact h.symm
      have : capPre.owner = caller := by rw [hcap_eq]; exact hpown
      exact hBcaller (hown.symm.trans this)
  | send guard =>
    rename_i caller receiver cap
    have hBcaller : B ≠ caller := fun he => hB (Or.inl (Or.inl he))
    intro hmem
    have hcap_eq : c = cap := hmem
    obtain ⟨cp, hcp⟩ := Option.isSome_iff_exists.mp guard.capExists
    have hown_caller : capPre.owner = caller := by
      rw [hcap_eq, hcp] at hPre; injection hPre with hpe
      rw [← hpe]; exact guard.callerOwnsCap cp hcp
    exact hBcaller (hown.symm.trans hown_caller)
  | «seal» _ => exact id
  | accept guard =>
    rename_i receiver pid
    have hBrecv : B ≠ receiver := fun he => hB (Or.inl (Or.inl he))
    obtain ⟨dr, hdr⟩ := Option.isSome_iff_exists.mp guard.receiverExists
    obtain ⟨pe, hpe⟩ := Option.isSome_iff_exists.mp (guard.pendingFound dr hdr)
    obtain ⟨cp, hcp⟩ := Option.isSome_iff_exists.mp (guard.capExists dr pe hdr hpe)
    have hBsender : B ≠ pe.senderDomainId :=
      fun he => hB (Or.inl (Or.inr (fun dr' hdr' pe' hpe' => by
        rw [hdr] at hdr'; injection hdr' with hh
        rw [← hh] at hpe'
        rw [hpe] at hpe'; injection hpe' with hhh
        rw [← hhh]; exact he)))
    intro hmem
    have hc_eq : c = pe.capId := hmem dr hdr pe hpe
    have hown_sender : capPre.owner = pe.senderDomainId := by
      rw [hc_eq, hcp] at hPre; injection hPre with hpe2
      rw [← hpe2]; exact guard.capOwnedBySender dr pe hdr hpe cp hcp
    exact hBsender (hown.symm.trans hown_sender)
  | reject _ => exact id
  | sealedSend _ => exact id
  | create _ => exact id
  | revokeDomain _ => exact id
  | setPolicy _ => exact id
  | sendChannel _ => exact id
  | acceptChannel _ => exact id
  | rejectChannel _ => exact id
  | switchReturn _ => exact id
  | switch _ => exact id
  | deliverInterrupt _ => exact id
  | addVp guard =>
    rename_i caller ch cm
    have hBcaller : B ≠ caller :=
      fun he => hB (Or.inr (Or.inr (Or.inl ⟨caller, ch, cm, rfl, he⟩)))
    obtain ⟨d, hd⟩ := Option.isSome_iff_exists.mp guard.callerExists
    obtain ⟨mid, hmid⟩ :=
      Option.isSome_iff_exists.mp (guard.commHandleResolves d hd)
    obtain ⟨cp, hcp⟩ :=
      Option.isSome_iff_exists.mp (guard.commCapExists d hd mid hmid)
    intro hmem
    have hc_eq : c = mid := hmem d hd mid hmid
    have hown_caller : capPre.owner = caller := by
      rw [hc_eq, hcp] at hPre; injection hPre with hpe
      rw [← hpe]; exact guard.commCapOwned d hd mid hmid cp hcp
    exact hBcaller (hown.symm.trans hown_caller)
  | registerComm guard =>
    rename_i caller cm ch vp
    have hBcaller : B ≠ caller :=
      fun he => hB (Or.inr (Or.inr (Or.inr ⟨caller, cm, ch, vp, rfl, he⟩)))
    obtain ⟨d, hd⟩ := Option.isSome_iff_exists.mp guard.callerExists
    obtain ⟨mid, hmid⟩ :=
      Option.isSome_iff_exists.mp (guard.commHandleResolves d hd)
    obtain ⟨cp, hcp⟩ :=
      Option.isSome_iff_exists.mp (guard.commCapExists d hd mid hmid)
    intro hmem
    have hc_eq : c = mid := hmem d hd mid hmid
    have hown_caller : capPre.owner = caller := by
      rw [hc_eq, hcp] at hPre; injection hPre with hpe
      rw [← hpe]; exact guard.commCapOwned d hd mid hmid cp hcp
    exact hBcaller (hown.symm.trans hown_caller)
  | switchSuspended _ => exact id
  | mapSelf _ => exact id
  | attestSelf _ => exact id
  | attest _ => exact id
  | getPolicy _ => exact id
  | getChan _ => exact id
  | getChanSelf _ => exact id
  | getReg _ => exact id
  | setReg _ => exact id
  | sealedSendChannel _ => exact id
  | send_at guard =>
    rename_i caller receiver cap _
    have hBcaller : B ≠ caller := fun he => hB (Or.inl (Or.inl he))
    intro hmem
    have hcap_eq : c = cap := hmem
    obtain ⟨cp, hcp⟩ := Option.isSome_iff_exists.mp guard.toSendGuard.capExists
    have hown_caller : capPre.owner = caller := by
      rw [hcap_eq, hcp] at hPre; injection hPre with hpe
      rw [← hpe]; exact guard.toSendGuard.callerOwnsCap cp hcp
    exact hBcaller (hown.symm.trans hown_caller)
  | accept_at guard =>
    rename_i receiver pid _
    have hBrecv : B ≠ receiver := fun he => hB (Or.inl (Or.inl he))
    obtain ⟨dr, hdr⟩ := Option.isSome_iff_exists.mp guard.toAcceptGuard.receiverExists
    obtain ⟨pe, hpe⟩ := Option.isSome_iff_exists.mp (guard.toAcceptGuard.pendingFound dr hdr)
    obtain ⟨cp, hcp⟩ := Option.isSome_iff_exists.mp (guard.toAcceptGuard.capExists dr pe hdr hpe)
    have hBsender : B ≠ pe.senderDomainId :=
      fun he => hB (Or.inl (Or.inr (fun dr' hdr' pe' hpe' => by
        rw [hdr] at hdr'; injection hdr' with hh
        rw [← hh] at hpe'
        rw [hpe] at hpe'; injection hpe' with hhh
        rw [← hhh]; exact he)))
    intro hmem
    have hc_eq : c = pe.capId := hmem dr hdr pe hpe
    have hown_sender : capPre.owner = pe.senderDomainId := by
      rw [hc_eq, hcp] at hPre; injection hPre with hpe2
      rw [← hpe2]; exact guard.toAcceptGuard.capOwnedBySender dr pe hdr hpe cp hcp
    exact hBsender (hown.symm.trans hown_sender)

end ThemisCapa
