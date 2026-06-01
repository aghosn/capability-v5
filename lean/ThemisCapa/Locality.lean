/-
  ThemisCapa.Locality — Per-action frame lemmas.

  For each action `a`, characterize which domain ids and memcap ids
  can be affected. The unaffected ids satisfy
  `(a_apply ...).getDom did = s.getDom did` (resp. `getMem`).

  These atomic locality properties are the building blocks for
  non-interference style theorems: if a domain B is outside the
  footprint of an action by domain A, then B's view of the state is
  preserved by that action.

  Footprint summary (state-dependent components annotated):

  | Action                              | Dom footprint                          | Mem footprint              |
  |-------------------------------------|----------------------------------------|----------------------------|
  | `carve caller parent _ _`           | `{caller}`                             | `{nextMemCapId, parent}`   |
  | `alias caller parent _`             | `{caller}`                             | `{nextMemCapId, parent}`   |
  | `revoke caller target`              | `{(getMem target).owner}` (state-dep)  | `{target, (getMem target).parent}` |
  | `send caller receiver cap`          | `{caller, receiver}`                   | `{cap}`                    |
  | `seal caller cap`                   | `{(getDomCap cap).targetDom}`          | `∅`                        |
  | `accept receiver pid`               | `{receiver, sender}` (state-dep)       | `{pe.capId}` (state-dep)   |
  | `reject receiver pid`               | `{receiver, sender}` (state-dep)       | `∅`                        |
  | `sealedSend caller receiver _ _`    | `{caller, receiver}`                   | `∅`                        |
  | `create caller _`                   | `{caller, nextDomId}`                  | `∅`                        |
  | `revokeDomain caller handle`        | `{caller, (getDomCap dcId).targetDom}` | `∅`                        |
-/
import ThemisCapa.Step

namespace ThemisCapa
open Arena

/-! ### Carve / Alias -/

theorem carve_frame_dom (s : SpecState) (caller : DomId) (parent : MemCapId)
    (access : Access) (attrs : Attributes) (did : DomId)
    (hdid : did ≠ caller) :
    (carve_apply s caller parent access attrs).getDom did = s.getDom did := by
  show ((carve_apply s caller parent access attrs).domains).find? did = _
  rcases hp : s.getMem parent with _ | p
  · simp [carve_apply, hp]; rfl
  · simp only [carve_apply, hp, SpecState.freshMem, SpecState.updMem,
               SpecState.updDomain]
    exact Arena.find?_update_other _ caller did _ hdid

theorem carve_frame_mem (s : SpecState) (caller : DomId) (parent : MemCapId)
    (access : Access) (attrs : Attributes) (id : MemCapId)
    (h1 : id ≠ s.nextMemCapId) (h2 : id ≠ parent) :
    (carve_apply s caller parent access attrs).getMem id = s.getMem id := by
  show ((carve_apply s caller parent access attrs).memcaps).find? id = _
  rcases hp : s.getMem parent with _ | p
  · simp [carve_apply, hp]; rfl
  · simp only [carve_apply, hp, SpecState.freshMem, SpecState.updMem,
               SpecState.updDomain]
    rw [Arena.find?_update_other _ parent id _ h2,
        Arena.find?_insert_other _ _ _ _ h1]
    rfl

theorem alias_frame_dom (s : SpecState) (caller : DomId) (parent : MemCapId)
    (access : Access) (did : DomId) (hdid : did ≠ caller) :
    (alias_apply s caller parent access).getDom did = s.getDom did := by
  show ((alias_apply s caller parent access).domains).find? did = _
  rcases hp : s.getMem parent with _ | p
  · simp [alias_apply, hp]; rfl
  · simp only [alias_apply, hp, SpecState.freshMem, SpecState.updMem,
               SpecState.updDomain]
    exact Arena.find?_update_other _ caller did _ hdid

theorem alias_frame_mem (s : SpecState) (caller : DomId) (parent : MemCapId)
    (access : Access) (id : MemCapId)
    (h1 : id ≠ s.nextMemCapId) (h2 : id ≠ parent) :
    (alias_apply s caller parent access).getMem id = s.getMem id := by
  show ((alias_apply s caller parent access).memcaps).find? id = _
  rcases hp : s.getMem parent with _ | p
  · simp [alias_apply, hp]; rfl
  · simp only [alias_apply, hp, SpecState.freshMem, SpecState.updMem,
               SpecState.updDomain]
    rw [Arena.find?_update_other _ parent id _ h2,
        Arena.find?_insert_other _ _ _ _ h1]
    rfl

/-! ### Revoke (memcap) -/

theorem revoke_frame_dom (s : SpecState) (caller : DomId) (target : MemCapId)
    (t : MemCap) (ht : s.getMem target = some t)
    (did : DomId) (hdid : did ≠ t.owner) :
    (revoke_apply s caller target).getDom did = s.getDom did := by
  show ((revoke_apply s caller target).domains).find? did = _
  simp only [revoke_apply, ht, SpecState.updMem, SpecState.updDomain]
  rcases htp : t.parent with _ | pid
  · rfl
  · simp only
    exact Arena.find?_update_other _ t.owner did _ hdid

theorem revoke_frame_mem (s : SpecState) (caller : DomId) (target : MemCapId)
    (t : MemCap) (ht : s.getMem target = some t)
    (pid : MemCapId) (htp : t.parent = some pid)
    (id : MemCapId) (h1 : id ≠ target) (h2 : id ≠ pid) :
    (revoke_apply s caller target).getMem id = s.getMem id := by
  show ((revoke_apply s caller target).memcaps).find? id = _
  simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
  rw [Arena.find?_update_other _ pid id _ h2,
      Arena.find?_remove_other _ target id h1]
  rfl

/-! ### Send -/

theorem send_frame_dom (s : SpecState) (caller receiver : DomId) (cap : MemCapId)
    (did : DomId) (h1 : did ≠ caller) (h2 : did ≠ receiver) :
    (send_apply s caller receiver cap).getDom did = s.getDom did := by
  show ((send_apply s caller receiver cap).domains).find? did = _
  simp only [send_apply, SpecState.updMem, SpecState.updDomain]
  rw [Arena.find?_update_other _ receiver did _ h2,
      Arena.find?_update_other _ caller did _ h1]
  rfl

theorem send_frame_mem (s : SpecState) (caller receiver : DomId) (cap : MemCapId)
    (id : MemCapId) (h : id ≠ cap) :
    (send_apply s caller receiver cap).getMem id = s.getMem id := by
  show ((send_apply s caller receiver cap).memcaps).find? id = _
  simp only [send_apply, SpecState.updMem, SpecState.updDomain]
  exact Arena.find?_update_other _ cap id _ h

/-! ### Seal -/

theorem seal_frame_dom (s : SpecState) (caller : DomId) (cap : DomCapId)
    (dc : DomCap) (hdc : s.getDomCap cap = some dc)
    (did : DomId) (hdid : did ≠ dc.targetDom) :
    (seal_apply s caller cap).getDom did = s.getDom did := by
  show ((seal_apply s caller cap).domains).find? did = _
  simp only [seal_apply, hdc, SpecState.updDomain]
  exact Arena.find?_update_other _ dc.targetDom did _ hdid

theorem seal_frame_mem (s : SpecState) (caller : DomId) (cap : DomCapId)
    (id : MemCapId) :
    (seal_apply s caller cap).getMem id = s.getMem id := by
  show ((seal_apply s caller cap).memcaps).find? id = _
  rcases hdc : s.getDomCap cap with _ | dc
  · simp [seal_apply, hdc]; rfl
  · simp only [seal_apply, hdc, SpecState.updDomain]
    rfl

/-! ### Set policy -/

theorem setPolicy_frame_dom (s : SpecState) (caller : DomId) (cap : DomCapId)
    (id : PolicyIdentifier) (value : Nat)
    (dc : DomCap) (hdc : s.getDomCap cap = some dc)
    (did : DomId) (hdid : did ≠ dc.targetDom) :
    (setPolicy_apply s caller cap id value).getDom did = s.getDom did := by
  show ((setPolicy_apply s caller cap id value).domains).find? did = _
  simp only [setPolicy_apply, hdc, SpecState.updDomain]
  exact Arena.find?_update_other _ dc.targetDom did _ hdid

theorem setPolicy_frame_mem (s : SpecState) (caller : DomId) (cap : DomCapId)
    (id : PolicyIdentifier) (value : Nat) (mid : MemCapId) :
    (setPolicy_apply s caller cap id value).getMem mid = s.getMem mid := by
  show ((setPolicy_apply s caller cap id value).memcaps).find? mid = _
  rcases hdc : s.getDomCap cap with _ | dc
  · simp [setPolicy_apply, hdc]; rfl
  · simp only [setPolicy_apply, hdc, SpecState.updDomain]
    rfl

/-! ### Accept / Reject -/

theorem accept_frame_dom (s : SpecState) (receiver : DomId) (pid : PendingId)
    (dr : Domain) (hdr : s.getDom receiver = some dr)
    (pe : PendingMemCap) (hpe : dr.lookupPending pid = some pe)
    (did : DomId) (h1 : did ≠ receiver) (h2 : did ≠ pe.senderDomainId) :
    (accept_apply s receiver pid).getDom did = s.getDom did := by
  show ((accept_apply s receiver pid).domains).find? did = _
  have hbind : (s.getDom receiver).bind (fun d => d.lookupPending pid) = some pe := by
    rw [hdr]; exact hpe
  simp only [accept_apply, hbind, SpecState.updDomain, send_apply, SpecState.updMem]
  rw [Arena.find?_update_other _ pe.senderDomainId did _ h2,
      Arena.find?_update_other _ receiver did _ h1,
      Arena.find?_update_other _ receiver did _ h1,
      Arena.find?_update_other _ pe.senderDomainId did _ h2]
  rfl

theorem accept_frame_mem (s : SpecState) (receiver : DomId) (pid : PendingId)
    (dr : Domain) (hdr : s.getDom receiver = some dr)
    (pe : PendingMemCap) (hpe : dr.lookupPending pid = some pe)
    (id : MemCapId) (h : id ≠ pe.capId) :
    (accept_apply s receiver pid).getMem id = s.getMem id := by
  show ((accept_apply s receiver pid).memcaps).find? id = _
  have hbind : (s.getDom receiver).bind (fun d => d.lookupPending pid) = some pe := by
    rw [hdr]; exact hpe
  simp only [accept_apply, hbind, SpecState.updDomain, send_apply, SpecState.updMem]
  exact Arena.find?_update_other _ pe.capId id _ h

theorem reject_frame_dom (s : SpecState) (receiver : DomId) (pid : PendingId)
    (did : DomId) (h1 : did ≠ receiver)
    (hSender :
      ∀ dr, s.getDom receiver = some dr →
      ∀ pe, dr.lookupPending pid = some pe → did ≠ pe.senderDomainId) :
    (reject_apply s receiver pid).getDom did = s.getDom did := by
  show ((reject_apply s receiver pid).domains).find? did = _
  unfold reject_apply
  rcases hdr : s.getDom receiver with _ | dr
  · simp only [hdr, Option.bind_none, SpecState.updDomain]
    exact Arena.find?_update_other _ receiver did _ h1
  · rcases hpe : dr.lookupPending pid with _ | pe
    · simp only [hdr, hpe, Option.bind_some, SpecState.updDomain]
      exact Arena.find?_update_other _ receiver did _ h1
    · have h2 := hSender dr hdr pe hpe
      simp only [hdr, hpe, Option.bind_some, SpecState.updDomain]
      rw [Arena.find?_update_other _ pe.senderDomainId did _ h2,
          Arena.find?_update_other _ receiver did _ h1]
      rfl

theorem reject_frame_mem (s : SpecState) (receiver : DomId) (pid : PendingId)
    (id : MemCapId) :
    (reject_apply s receiver pid).getMem id = s.getMem id := by
  show ((reject_apply s receiver pid).memcaps).find? id = _
  unfold reject_apply
  rcases hb : (s.getDom receiver).bind (fun d => d.lookupPending pid) with _ | _ <;>
    simp [SpecState.updDomain, hb] <;> rfl

/-! ### SealedSend -/

theorem sealedSend_frame_dom (s : SpecState) (caller receiver : DomId)
    (handle : LocalHandle) (gpaHint : Option Nat)
    (did : DomId) (h1 : did ≠ caller) (h2 : did ≠ receiver) :
    (sealedSend_apply s caller receiver handle gpaHint).getDom did = s.getDom did := by
  show ((sealedSend_apply s caller receiver handle gpaHint).domains).find? did = _
  simp only [sealedSend_apply, SpecState.updDomain]
  rcases (s.getDom caller).bind (fun d => d.lookupMemHandle handle) with _ | _
  · rfl
  · rw [Arena.find?_update_other _ receiver did _ h2,
        Arena.find?_update_other _ caller did _ h1]
    rfl

theorem sealedSend_frame_mem (s : SpecState) (caller receiver : DomId)
    (handle : LocalHandle) (gpaHint : Option Nat) (id : MemCapId) :
    (sealedSend_apply s caller receiver handle gpaHint).getMem id = s.getMem id := by
  show ((sealedSend_apply s caller receiver handle gpaHint).memcaps).find? id = _
  simp only [sealedSend_apply, SpecState.updDomain]
  rcases (s.getDom caller).bind (fun d => d.lookupMemHandle handle) with _ | _ <;>
    rfl

/-! ### Create -/

theorem create_frame_dom (s : SpecState) (caller : DomId) (policy : DomainPolicy)
    (did : DomId) (h1 : did ≠ caller) (h2 : did ≠ s.nextDomId) :
    (create_apply s caller policy).getDom did = s.getDom did := by
  show ((create_apply s caller policy).domains).find? did = _
  simp only [create_apply, SpecState.freshDom, SpecState.freshDomCap,
             SpecState.updDomain]
  rw [Arena.find?_update_other _ caller did _ h1,
      Arena.find?_insert_other _ _ _ _ h2]
  rfl

theorem create_frame_mem (s : SpecState) (caller : DomId) (policy : DomainPolicy)
    (id : MemCapId) :
    (create_apply s caller policy).getMem id = s.getMem id := rfl

/-! ### RevokeDomain -/

theorem revokeDomain_frame_dom (s : SpecState) (caller : DomId) (handle : LocalHandle)
    (dcaller : Domain) (hdc : s.getDom caller = some dcaller)
    (dcId : DomCapId) (hh : dcaller.lookupDomHandle handle = some dcId)
    (dc : DomCap) (hdcap : s.getDomCap dcId = some dc)
    (did : DomId) (h1 : did ≠ caller) (h2 : did ≠ dc.targetDom) :
    (revokeDomain_apply s caller handle).getDom did = s.getDom did := by
  show ((revokeDomain_apply s caller handle).domains).find? did = _
  simp only [revokeDomain_apply, hdc, hh, hdcap, SpecState.updDomain]
  rw [Arena.find?_update_other _ caller did _ h1,
      Arena.find?_remove_other _ dc.targetDom did h2]
  rfl

theorem revokeDomain_frame_mem (s : SpecState) (caller : DomId) (handle : LocalHandle)
    (id : MemCapId) :
    (revokeDomain_apply s caller handle).getMem id = s.getMem id := by
  show ((revokeDomain_apply s caller handle).memcaps).find? id = _
  unfold revokeDomain_apply
  rcases h1 : s.getDom caller with _ | d
  · rfl
  · simp only []
    rcases h2 : d.lookupDomHandle handle with _ | dcId
    · rfl
    · simp only []
      rcases h3 : s.getDomCap dcId with _ | dc
      · rfl
      · simp only [SpecState.updDomain]; rfl

/-! ## Action footprints (state-dependent)

`Action.affectsDom s a did` says that the action `a` *may* modify the
domain record for `did` when run from state `s`. The contrapositive of
the `step_locality_dom` corollary below states: if `did` is outside
this footprint, `did`'s domain record is preserved.

Similarly for `affectsMem`.

These are *over-approximations*: e.g. `carve` lists the new memcap id
`s.nextMemCapId` even though the post-state simply *adds* it (the
pre-state value at that key is `none`, the post-state is `some new`,
so technically equal at `none` is false). The footprint correctly
predicts non-preservation in that case. -/

/-- Set of domain ids that `a` may modify when fired from `s`. -/
def Action.affectsDom (s : SpecState) : Action → DomId → Prop
  | .carve caller _ _ _,         did => did = caller
  | .alias caller _ _,           did => did = caller
  | .revoke _ target,            did =>
      ∀ t, s.getMem target = some t → did = t.owner
  | .send caller receiver _,     did => did = caller ∨ did = receiver
  | .seal _ cap,                 did =>
      ∀ dc, s.getDomCap cap = some dc → did = dc.targetDom
  | .accept receiver pid,        did =>
      did = receiver ∨
      (∀ dr, s.getDom receiver = some dr →
       ∀ pe, dr.lookupPending pid = some pe → did = pe.senderDomainId)
  | .reject receiver pid,        did =>
      did = receiver ∨
      (∀ dr, s.getDom receiver = some dr →
       ∀ pe, dr.lookupPending pid = some pe → did = pe.senderDomainId)
  | .sealedSend caller receiver _ _, did => did = caller ∨ did = receiver
  | .create caller _,            did => did = caller ∨ did = s.nextDomId
  | .revokeDomain caller handle, did =>
      did = caller ∨
      (∀ dc, s.getDom caller = some dc →
       ∀ dcId, dc.lookupDomHandle handle = some dcId →
       ∀ d, s.getDomCap dcId = some d → did = d.targetDom)
  | .setPolicy _ cap _ _,        did =>
      ∀ dc, s.getDomCap cap = some dc → did = dc.targetDom

/-- Set of memcap ids that `a` may modify when fired from `s`. -/
def Action.affectsMem (s : SpecState) : Action → MemCapId → Prop
  | .carve _ parent _ _, id => id = s.nextMemCapId ∨ id = parent
  | .alias _ parent _,   id => id = s.nextMemCapId ∨ id = parent
  | .revoke _ target,    id =>
      id = target ∨
      (∀ t, s.getMem target = some t →
       ∀ pid, t.parent = some pid → id = pid)
  | .send _ _ cap,       id => id = cap
  | .seal _ _,           _  => False
  | .accept receiver pid, id =>
      ∀ dr, s.getDom receiver = some dr →
      ∀ pe, dr.lookupPending pid = some pe → id = pe.capId
  | .reject _ _,         _  => False
  | .sealedSend _ _ _ _, _  => False
  | .create _ _,         _  => False
  | .revokeDomain _ _,   _  => False
  | .setPolicy _ _ _ _,  _  => False

/-! ## Top-level locality theorems.

For any step, any domain id outside the action's `affectsDom` footprint
has its domain record preserved; same for memcaps. -/

theorem step_locality_dom
    {s s' : SpecState} {a : Action} (hstep : step s a s')
    {did : DomId} (h : ¬ a.affectsDom s did) :
    s'.getDom did = s.getDom did := by
  cases hstep with
  | carve guard => exact carve_frame_dom _ _ _ _ _ _ h
  | alias guard => exact alias_frame_dom _ _ _ _ _ h
  | revoke guard =>
    rename_i caller target
    obtain ⟨t, ht⟩ := Option.isSome_iff_exists.mp guard.targetExists
    have hne : did ≠ t.owner := fun heq => h (fun t' ht' => by
      rw [ht'] at ht; injection ht with h'; rw [h']; exact heq)
    exact revoke_frame_dom _ _ _ _ ht _ hne
  | send guard =>
    have h1 : did ≠ _ := fun e => h (Or.inl e)
    have h2 : did ≠ _ := fun e => h (Or.inr e)
    exact send_frame_dom _ _ _ _ _ h1 h2
  | «seal» guard =>
    rename_i caller cap
    obtain ⟨dc, hdc⟩ := Option.isSome_iff_exists.mp guard.capExists
    have hne : did ≠ dc.targetDom := fun heq => h (fun dc' hdc' => by
      rw [hdc'] at hdc; injection hdc with h'; rw [h']; exact heq)
    exact seal_frame_dom _ _ _ _ hdc _ hne
  | accept guard =>
    rename_i receiver pid
    obtain ⟨dr, hdr⟩ := Option.isSome_iff_exists.mp guard.receiverExists
    obtain ⟨pe, hpe⟩ :=
      Option.isSome_iff_exists.mp (guard.pendingFound dr hdr)
    have h1 : did ≠ receiver := fun e => h (Or.inl e)
    have h2 : did ≠ pe.senderDomainId := fun e => h (Or.inr (fun dr' hdr' pe' hpe' => by
      rw [hdr] at hdr'; injection hdr' with hh
      rw [← hh] at hpe'
      rw [hpe] at hpe'; injection hpe' with hh'
      rw [← hh']; exact e))
    exact accept_frame_dom _ _ _ _ hdr _ hpe _ h1 h2
  | reject guard =>
    rename_i receiver pid
    have h1 : did ≠ receiver := fun e => h (Or.inl e)
    apply reject_frame_dom _ _ _ _ h1
    intro dr hdr pe hpe heq
    exact h (Or.inr (fun dr' hdr' pe' hpe' => by
      rw [hdr] at hdr'; injection hdr' with hh
      rw [← hh] at hpe'
      rw [hpe] at hpe'; injection hpe' with hh'
      rw [← hh']; exact heq))
  | sealedSend guard =>
    have h1 : did ≠ _ := fun e => h (Or.inl e)
    have h2 : did ≠ _ := fun e => h (Or.inr e)
    exact sealedSend_frame_dom _ _ _ _ _ _ h1 h2
  | create guard =>
    have h1 : did ≠ _ := fun e => h (Or.inl e)
    have h2 : did ≠ _ := fun e => h (Or.inr e)
    exact create_frame_dom _ _ _ _ h1 h2
  | revokeDomain guard =>
    rename_i caller handle
    obtain ⟨dcaller, hdcaller⟩ := Option.isSome_iff_exists.mp guard.callerExists
    obtain ⟨dcId, hdcId⟩ :=
      Option.isSome_iff_exists.mp (guard.handleResolves dcaller hdcaller)
    obtain ⟨dc, hdc⟩ :=
      Option.isSome_iff_exists.mp (guard.capExists dcaller hdcaller dcId hdcId)
    have h1 : did ≠ caller := fun e => h (Or.inl e)
    have h2 : did ≠ dc.targetDom := fun e =>
      h (Or.inr (fun dcaller' hdc' dcId' hh' d' hdcap' => by
        rw [hdcaller] at hdc'; injection hdc' with hh
        rw [← hh] at hh'
        rw [hdcId] at hh'; injection hh' with hhh
        rw [← hhh] at hdcap'
        rw [hdc] at hdcap'; injection hdcap' with hhhh
        rw [← hhhh]; exact e))
    exact revokeDomain_frame_dom _ _ _ _ hdcaller _ hdcId _ hdc _ h1 h2
  | setPolicy guard =>
    rename_i caller cap id value
    obtain ⟨dc, hdc⟩ := Option.isSome_iff_exists.mp guard.capExists
    have hne : did ≠ dc.targetDom := fun heq => h (fun dc' hdc' => by
      rw [hdc'] at hdc; injection hdc with h'; rw [h']; exact heq)
    exact setPolicy_frame_dom _ _ _ _ _ _ hdc _ hne

theorem step_locality_mem
    {s s' : SpecState} {a : Action} (hstep : step s a s')
    {id : MemCapId} (h : ¬ a.affectsMem s id) :
    s'.getMem id = s.getMem id := by
  cases hstep with
  | carve guard =>
    have h1 : id ≠ _ := fun e => h (Or.inl e)
    have h2 : id ≠ _ := fun e => h (Or.inr e)
    exact carve_frame_mem _ _ _ _ _ _ h1 h2
  | alias guard =>
    have h1 : id ≠ _ := fun e => h (Or.inl e)
    have h2 : id ≠ _ := fun e => h (Or.inr e)
    exact alias_frame_mem _ _ _ _ _ h1 h2
  | revoke guard =>
    rename_i caller target
    obtain ⟨t, ht⟩ := Option.isSome_iff_exists.mp guard.targetExists
    obtain ⟨pid, htp⟩ :=
      Option.isSome_iff_exists.mp (guard.targetHasParent t ht)
    have h1 : id ≠ target := fun e => h (Or.inl e)
    have h2 : id ≠ pid := fun e => h (Or.inr (fun t' ht' pid' htp' => by
      rw [ht] at ht'; injection ht' with hh
      rw [← hh] at htp'
      rw [htp] at htp'; injection htp' with hhh
      rw [← hhh]; exact e))
    exact revoke_frame_mem _ _ _ _ ht _ htp _ h1 h2
  | send guard =>
    have h1 : id ≠ _ := h
    exact send_frame_mem _ _ _ _ _ h1
  | «seal» guard => exact seal_frame_mem _ _ _ _
  | accept guard =>
    rename_i receiver pid
    obtain ⟨dr, hdr⟩ := Option.isSome_iff_exists.mp guard.receiverExists
    obtain ⟨pe, hpe⟩ :=
      Option.isSome_iff_exists.mp (guard.pendingFound dr hdr)
    have h1 : id ≠ pe.capId := fun e => h (fun dr' hdr' pe' hpe' => by
      rw [hdr] at hdr'; injection hdr' with hh
      rw [← hh] at hpe'
      rw [hpe] at hpe'; injection hpe' with hhh
      rw [← hhh]; exact e)
    exact accept_frame_mem _ _ _ _ hdr _ hpe _ h1
  | reject guard => exact reject_frame_mem _ _ _ _
  | sealedSend guard => exact sealedSend_frame_mem _ _ _ _ _ _
  | create guard => exact create_frame_mem _ _ _ _
  | revokeDomain guard => exact revokeDomain_frame_mem _ _ _ _
  | setPolicy guard => exact setPolicy_frame_mem _ _ _ _ _ _

end ThemisCapa
