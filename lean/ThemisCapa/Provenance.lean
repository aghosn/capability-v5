/-
  ThemisCapa.Provenance — Capability Provenance theorems.

  Every change to the existence-or-ownership of a memcap in a single
  step is authorized by exactly one action constructor:

  * **Removal**  (some → none):  `a = .revoke caller c`.
  * **Creation** (none → some):  `a ∈ {.carve, .alias}` with
    `c = s.nextMemCapId` and `newCap.owner = caller`.
  * **Transfer** (owner changed): `a ∈ {.send, .accept}` with the
    new owner matching the action's receiver.

  Together these pin down complete provenance for memcaps: the only
  way to gain authority over a capability is for some prior owner
  (the caller, in the case of `.send`; the sender, in the case of
  `.accept`) to explicitly grant it. Combined with `RevokeGuard`'s
  `callerOwnsParent` hypothesis we get the capability-system slogan
  "only an ancestor's owner can revoke."
-/
import ThemisCapa.Locality
import ThemisCapa.Properties

namespace ThemisCapa
open Arena

/-! ### Helpers: `isSome` is preserved by `insert` and `update`. -/

private theorem Arena.find?_insert_isSome
    {α β : Type} [DecidableEq α]
    (a : Arena α β) (k k' : α) (v : β)
    (h : (a.find? k).isSome) :
    ((a.insert k' v).find? k).isSome := by
  by_cases hk : k = k'
  · subst hk; rw [Arena.find?_insert_same]; rfl
  · rw [Arena.find?_insert_other _ _ _ _ hk]; exact h

private theorem Arena.find?_update_isSome
    {α β : Type} [DecidableEq α]
    (a : Arena α β) (k k' : α) (f : β → β)
    (h : (a.find? k).isSome) :
    ((a.update k' f).find? k).isSome := by
  by_cases hk : k = k'
  · subst hk
    rcases hv : a.find? k with _ | v
    · rw [hv] at h; cases h
    · rw [Arena.find?_update_same _ _ _ hv]; rfl
  · rw [Arena.find?_update_other _ _ _ _ hk]; exact h

/-! ### Per-action: `getMem`/`isSome` is preserved (except for `revoke` at the target). -/

private theorem carve_mem_isSome
    (s : SpecState) (caller : DomId) (parent : MemCapId)
    (access : Access) (attrs : Attributes) (c : MemCapId)
    (h : (s.getMem c).isSome) :
    ((carve_apply s caller parent access attrs).getMem c).isSome := by
  show ((carve_apply s caller parent access attrs).memcaps.find? c).isSome
  rcases hp : s.getMem parent with _ | p
  · simp only [carve_apply, hp]; exact h
  · simp only [carve_apply, hp, SpecState.freshMem, SpecState.updMem, SpecState.updDomain]
    apply Arena.find?_update_isSome
    exact Arena.find?_insert_isSome _ _ _ _ h

private theorem alias_mem_isSome
    (s : SpecState) (caller : DomId) (parent : MemCapId) (access : Access)
    (c : MemCapId) (h : (s.getMem c).isSome) :
    ((alias_apply s caller parent access).getMem c).isSome := by
  show ((alias_apply s caller parent access).memcaps.find? c).isSome
  rcases hp : s.getMem parent with _ | p
  · simp only [alias_apply, hp]; exact h
  · simp only [alias_apply, hp, SpecState.freshMem, SpecState.updMem, SpecState.updDomain]
    apply Arena.find?_update_isSome
    exact Arena.find?_insert_isSome _ _ _ _ h

private theorem revoke_mem_isSome_of_ne
    (s : SpecState) (caller : DomId) (target : MemCapId) (c : MemCapId)
    (hne : c ≠ target) (h : (s.getMem c).isSome) :
    ((revoke_apply s caller target).getMem c).isSome := by
  show ((revoke_apply s caller target).memcaps.find? c).isSome
  rcases ht : s.getMem target with _ | t
  · simp only [revoke_apply, ht]; exact h
  · rcases htp : t.parent with _ | pid
    · simp only [revoke_apply, ht, htp]; exact h
    · simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
      apply Arena.find?_update_isSome
      show ((s.memcaps.remove target).find? c).isSome
      rw [Arena.find?_remove_other _ target c hne]
      exact h

private theorem send_mem_isSome
    (s : SpecState) (caller receiver : DomId) (cap : MemCapId) (c : MemCapId)
    (h : (s.getMem c).isSome) :
    ((send_apply s caller receiver cap).getMem c).isSome := by
  show ((send_apply s caller receiver cap).memcaps.find? c).isSome
  simp only [send_apply, SpecState.updMem, SpecState.updDomain]
  exact Arena.find?_update_isSome _ _ _ _ h

private theorem seal_mem_isSome
    (s : SpecState) (caller : DomId) (cap : DomCapId) (c : MemCapId)
    (h : (s.getMem c).isSome) :
    ((seal_apply s caller cap).getMem c).isSome := by
  rw [seal_frame_mem]; exact h

private theorem accept_mem_isSome
    (s : SpecState) (receiver : DomId) (pid : PendingId) (c : MemCapId)
    (h : (s.getMem c).isSome) :
    ((accept_apply s receiver pid).getMem c).isSome := by
  show ((accept_apply s receiver pid).memcaps.find? c).isSome
  unfold accept_apply
  rcases hb : (s.getDom receiver).bind (fun d => d.lookupPending pid) with _ | pe
  · simp only [hb]; exact h
  · simp only [hb, SpecState.updDomain, send_apply, SpecState.updMem]
    exact Arena.find?_update_isSome _ _ _ _ h

private theorem reject_mem_isSome
    (s : SpecState) (receiver : DomId) (pid : PendingId) (c : MemCapId)
    (h : (s.getMem c).isSome) :
    ((reject_apply s receiver pid).getMem c).isSome := by
  rw [reject_frame_mem]; exact h

private theorem sealedSend_mem_isSome
    (s : SpecState) (caller receiver : DomId) (handle : LocalHandle)
    (gpaHint : Option Nat) (c : MemCapId) (h : (s.getMem c).isSome) :
    ((sealedSend_apply s caller receiver handle gpaHint).getMem c).isSome := by
  rw [sealedSend_frame_mem]; exact h

private theorem create_mem_isSome
    (s : SpecState) (caller : DomId) (policy : DomainPolicy) (c : MemCapId)
    (h : (s.getMem c).isSome) :
    ((create_apply s caller policy).getMem c).isSome := by
  rw [create_frame_mem]; exact h

private theorem revokeDomain_mem_isSome
    (s : SpecState) (caller : DomId) (handle : LocalHandle) (c : MemCapId)
    (h : (s.getMem c).isSome) :
    ((revokeDomain_apply s caller handle).getMem c).isSome := by
  rw [revokeDomain_frame_mem]; exact h

private theorem setPolicy_mem_isSome
    (s : SpecState) (caller : DomId) (cap : DomCapId)
    (id : PolicyIdentifier) (value : Nat) (c : MemCapId)
    (h : (s.getMem c).isSome) :
    ((setPolicy_apply s caller cap id value).getMem c).isSome := by
  rw [setPolicy_frame_mem]; exact h

private theorem sendChannel_mem_isSome
    (s : SpecState) (caller receiver : DomId) (cap : DomCapId) (c : MemCapId)
    (h : (s.getMem c).isSome) :
    ((sendChannel_apply s caller receiver cap).getMem c).isSome := by
  rw [sendChannel_frame_mem]; exact h

private theorem acceptChannel_mem_isSome
    (s : SpecState) (receiver : DomId) (pid : PendingId) (c : MemCapId)
    (h : (s.getMem c).isSome) :
    ((acceptChannel_apply s receiver pid).getMem c).isSome := by
  rw [acceptChannel_frame_mem]; exact h

private theorem rejectChannel_mem_isSome
    (s : SpecState) (receiver : DomId) (pid : PendingId) (c : MemCapId)
    (h : (s.getMem c).isSome) :
    ((rejectChannel_apply s receiver pid).getMem c).isSome := by
  rw [rejectChannel_frame_mem]; exact h

private theorem switchReturn_mem_isSome
    (s : SpecState) (caller : DomId) (core : CoreId) (er : Option Nat)
    (c : MemCapId) (h : (s.getMem c).isSome) :
    ((switchReturn_apply s caller core er).getMem c).isSome := by
  rw [switchReturn_frame_mem]; exact h

private theorem switch_mem_isSome
    (s : SpecState) (caller : DomId) (toHandle : LocalHandle)
    (toVpId : VpId) (core : CoreId) (c : MemCapId)
    (h : (s.getMem c).isSome) :
    ((switch_apply s caller toHandle toVpId core).getMem c).isSome := by
  rw [switch_frame_mem]; exact h

/-! ### Provenance — Removal -/

/-- The only way a memcap can disappear from one step to the next is
    via the `revoke` action, with target equal to the disappeared id. -/
theorem provenance_removal
    {s s' : SpecState} {a : Action} (hstep : step s a s')
    {c : MemCapId} (hPre : (s.getMem c).isSome) (hPost : (s'.getMem c) = none) :
    ∃ caller, a = .revoke caller c := by
  cases hstep with
  | carve guard =>
    rename_i caller parent access attrs
    exfalso
    have h := carve_mem_isSome s caller parent access attrs c hPre
    rw [hPost] at h; cases h
  | alias guard =>
    rename_i caller parent access
    exfalso
    have h := alias_mem_isSome s caller parent access c hPre
    rw [hPost] at h; cases h
  | revoke guard =>
    rename_i caller target
    refine ⟨caller, ?_⟩
    by_cases hc : c = target
    · rw [hc]
    · exfalso
      have h := revoke_mem_isSome_of_ne s caller target c hc hPre
      rw [hPost] at h; cases h
  | send guard =>
    rename_i caller receiver cap
    exfalso
    have h := send_mem_isSome s caller receiver cap c hPre
    rw [hPost] at h; cases h
  | «seal» guard =>
    rename_i caller cap
    exfalso
    have h := seal_mem_isSome s caller cap c hPre
    rw [hPost] at h; cases h
  | accept guard =>
    rename_i receiver pid
    exfalso
    have h := accept_mem_isSome s receiver pid c hPre
    rw [hPost] at h; cases h
  | reject guard =>
    rename_i receiver pid
    exfalso
    have h := reject_mem_isSome s receiver pid c hPre
    rw [hPost] at h; cases h
  | sealedSend guard =>
    rename_i caller receiver handle gpaHint
    exfalso
    have h := sealedSend_mem_isSome s caller receiver handle gpaHint c hPre
    rw [hPost] at h; cases h
  | create guard =>
    rename_i caller policy
    exfalso
    have h := create_mem_isSome s caller policy c hPre
    rw [hPost] at h; cases h
  | revokeDomain guard =>
    rename_i caller handle
    exfalso
    have h := revokeDomain_mem_isSome s caller handle c hPre
    rw [hPost] at h; cases h
  | setPolicy guard =>
    rename_i caller cap id value
    exfalso
    have h := setPolicy_mem_isSome s caller cap id value c hPre
    rw [hPost] at h; cases h
  | sendChannel guard =>
    rename_i caller receiver cap
    exfalso
    have h := sendChannel_mem_isSome s caller receiver cap c hPre
    rw [hPost] at h; cases h
  | acceptChannel guard =>
    rename_i receiver pid
    exfalso
    have h := acceptChannel_mem_isSome s receiver pid c hPre
    rw [hPost] at h; cases h
  | rejectChannel guard =>
    rename_i receiver pid
    exfalso
    have h := rejectChannel_mem_isSome s receiver pid c hPre
    rw [hPost] at h; cases h
  | switchReturn guard =>
    rename_i caller core er
    exfalso
    have h := switchReturn_mem_isSome s caller core er c hPre
    rw [hPost] at h; cases h
  | switch guard =>
    rename_i caller toHandle toVpId core
    exfalso
    have h := switch_mem_isSome s caller toHandle toVpId core c hPre
    rw [hPost] at h; cases h

/-! ### Helpers: `isNone` is preserved by `update` and (under inequality) `remove`/`insert`. -/

private theorem Arena.find?_update_of_none
    {α β : Type} [DecidableEq α]
    (a : Arena α β) (k k' : α) (f : β → β)
    (h : a.find? k = none) :
    (a.update k' f).find? k = none := by
  by_cases hk : k' = k
  · rw [hk, Arena.find?_update_eq_map, h]; rfl
  · rw [Arena.find?_update_other a k' k f (fun he => hk he.symm)]; exact h

private theorem Arena.find?_remove_of_none
    {α β : Type} [DecidableEq α]
    (a : Arena α β) (k k' : α)
    (h : a.find? k = none) :
    (a.remove k').find? k = none := by
  by_cases hk : k' = k
  · rw [hk]; exact Arena.find?_remove_same _ _
  · rw [Arena.find?_remove_other a k' k (fun he => hk he.symm)]; exact h

private theorem Arena.find?_insert_of_none_ne
    {α β : Type} [DecidableEq α]
    (a : Arena α β) (k k' : α) (v : β)
    (hne : k ≠ k') (h : a.find? k = none) :
    (a.insert k' v).find? k = none := by
  rw [Arena.find?_insert_other a k' k v hne]; exact h

/-! ### Per-action: `isNone` preserved by non-creating actions. -/

private theorem revoke_mem_isNone
    (s : SpecState) (caller : DomId) (target : MemCapId) (c : MemCapId)
    (h : s.getMem c = none) :
    (revoke_apply s caller target).getMem c = none := by
  show ((revoke_apply s caller target).memcaps).find? c = none
  rcases ht : s.getMem target with _ | t
  · simp only [revoke_apply, ht]; exact h
  · rcases htp : t.parent with _ | pid
    · simp only [revoke_apply, ht, htp]; exact h
    · simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
      apply Arena.find?_update_of_none
      exact Arena.find?_remove_of_none _ _ _ h

private theorem send_mem_isNone
    (s : SpecState) (caller receiver : DomId) (cap : MemCapId) (c : MemCapId)
    (h : s.getMem c = none) :
    (send_apply s caller receiver cap).getMem c = none := by
  show ((send_apply s caller receiver cap).memcaps).find? c = none
  simp only [send_apply, SpecState.updMem, SpecState.updDomain]
  exact Arena.find?_update_of_none _ _ _ _ h

private theorem seal_mem_isNone
    (s : SpecState) (caller : DomId) (cap : DomCapId) (c : MemCapId)
    (h : s.getMem c = none) :
    (seal_apply s caller cap).getMem c = none := by
  rw [seal_frame_mem]; exact h

private theorem accept_mem_isNone
    (s : SpecState) (receiver : DomId) (pid : PendingId) (c : MemCapId)
    (h : s.getMem c = none) :
    (accept_apply s receiver pid).getMem c = none := by
  show ((accept_apply s receiver pid).memcaps).find? c = none
  unfold accept_apply
  rcases hb : (s.getDom receiver).bind (fun d => d.lookupPending pid) with _ | pe
  · simp only [hb]; exact h
  · simp only [hb, SpecState.updDomain, send_apply, SpecState.updMem]
    exact Arena.find?_update_of_none _ _ _ _ h

private theorem reject_mem_isNone
    (s : SpecState) (receiver : DomId) (pid : PendingId) (c : MemCapId)
    (h : s.getMem c = none) :
    (reject_apply s receiver pid).getMem c = none := by
  rw [reject_frame_mem]; exact h

private theorem sealedSend_mem_isNone
    (s : SpecState) (caller receiver : DomId) (handle : LocalHandle)
    (gpaHint : Option Nat) (c : MemCapId) (h : s.getMem c = none) :
    (sealedSend_apply s caller receiver handle gpaHint).getMem c = none := by
  rw [sealedSend_frame_mem]; exact h

private theorem create_mem_isNone
    (s : SpecState) (caller : DomId) (policy : DomainPolicy) (c : MemCapId)
    (h : s.getMem c = none) :
    (create_apply s caller policy).getMem c = none := by
  rw [create_frame_mem]; exact h

private theorem revokeDomain_mem_isNone
    (s : SpecState) (caller : DomId) (handle : LocalHandle) (c : MemCapId)
    (h : s.getMem c = none) :
    (revokeDomain_apply s caller handle).getMem c = none := by
  rw [revokeDomain_frame_mem]; exact h

private theorem setPolicy_mem_isNone
    (s : SpecState) (caller : DomId) (cap : DomCapId)
    (id : PolicyIdentifier) (value : Nat) (c : MemCapId)
    (h : s.getMem c = none) :
    (setPolicy_apply s caller cap id value).getMem c = none := by
  rw [setPolicy_frame_mem]; exact h

private theorem sendChannel_mem_isNone
    (s : SpecState) (caller receiver : DomId) (cap : DomCapId) (c : MemCapId)
    (h : s.getMem c = none) :
    (sendChannel_apply s caller receiver cap).getMem c = none := by
  rw [sendChannel_frame_mem]; exact h

private theorem acceptChannel_mem_isNone
    (s : SpecState) (receiver : DomId) (pid : PendingId) (c : MemCapId)
    (h : s.getMem c = none) :
    (acceptChannel_apply s receiver pid).getMem c = none := by
  rw [acceptChannel_frame_mem]; exact h

private theorem rejectChannel_mem_isNone
    (s : SpecState) (receiver : DomId) (pid : PendingId) (c : MemCapId)
    (h : s.getMem c = none) :
    (rejectChannel_apply s receiver pid).getMem c = none := by
  rw [rejectChannel_frame_mem]; exact h

private theorem switchReturn_mem_isNone
    (s : SpecState) (caller : DomId) (core : CoreId) (er : Option Nat)
    (c : MemCapId) (h : s.getMem c = none) :
    (switchReturn_apply s caller core er).getMem c = none := by
  rw [switchReturn_frame_mem]; exact h

private theorem switch_mem_isNone
    (s : SpecState) (caller : DomId) (toHandle : LocalHandle)
    (toVpId : VpId) (core : CoreId) (c : MemCapId)
    (h : s.getMem c = none) :
    (switch_apply s caller toHandle toVpId core).getMem c = none := by
  rw [switch_frame_mem]; exact h

/-! ### Per-action: characterization of the freshly-created cap. -/

/-- If `carve_apply` produces a fresh memcap at id `c` that wasn't there before,
    then `c = s.nextMemCapId` and the new cap's owner is `caller`. -/
private theorem carve_creates_at_fresh
    (s : SpecState) (caller : DomId) (parent : MemCapId)
    (access : Access) (attrs : Attributes) (hwf : WellFormed s)
    (c : MemCapId) (newCap : MemCap)
    (hPre : s.getMem c = none)
    (hPost : (carve_apply s caller parent access attrs).getMem c = some newCap) :
    c = s.nextMemCapId ∧ newCap.owner = caller := by
  rcases hp : s.getMem parent with _ | p
  · -- parent missing: carve_apply is identity, contradicts pre = none, post = some
    exfalso
    have : (carve_apply s caller parent access attrs).getMem c = s.getMem c := by
      show ((carve_apply s caller parent access attrs).memcaps).find? c = _
      simp only [carve_apply, hp]; rfl
    rw [this, hPre] at hPost; cases hPost
  · have hgetC := carve_apply_getMem s caller parent access attrs p hp hwf.freshMemCounter c
    simp only at hgetC
    by_cases hidNew : c = s.nextMemCapId
    · refine ⟨hidNew, ?_⟩
      rw [hgetC] at hPost
      simp only [hidNew, if_true] at hPost
      injection hPost with hPost
      rw [← hPost]
    · exfalso
      by_cases hidPar : c = parent
      · -- c = parent: then s.getMem c = some p, contradicts hPre
        rw [hidPar, hp] at hPre; cases hPre
      · -- c ≠ parent, c ≠ nextMemCapId: getMem unchanged
        rw [hgetC] at hPost
        simp only [hidNew, hidPar, if_false] at hPost
        rw [hPre] at hPost; cases hPost

/-- Analogue for `alias_apply`. -/
private theorem alias_creates_at_fresh
    (s : SpecState) (caller : DomId) (parent : MemCapId) (access : Access)
    (hwf : WellFormed s) (c : MemCapId) (newCap : MemCap)
    (hPre : s.getMem c = none)
    (hPost : (alias_apply s caller parent access).getMem c = some newCap) :
    c = s.nextMemCapId ∧ newCap.owner = caller := by
  rcases hp : s.getMem parent with _ | p
  · exfalso
    have : (alias_apply s caller parent access).getMem c = s.getMem c := by
      show ((alias_apply s caller parent access).memcaps).find? c = _
      simp only [alias_apply, hp]; rfl
    rw [this, hPre] at hPost; cases hPost
  · have hgetC := alias_apply_getMem s caller parent access p hp hwf.freshMemCounter c
    simp only at hgetC
    by_cases hidNew : c = s.nextMemCapId
    · refine ⟨hidNew, ?_⟩
      rw [hgetC] at hPost
      simp only [hidNew, if_true] at hPost
      injection hPost with hPost
      rw [← hPost]
    · exfalso
      by_cases hidPar : c = parent
      · rw [hidPar, hp] at hPre; cases hPre
      · rw [hgetC] at hPost
        simp only [hidNew, hidPar, if_false] at hPost
        rw [hPre] at hPost; cases hPost

/-! ### Provenance — Creation -/

/-- The only way a memcap can come into existence in a single step is
    via `carve` or `alias`. The fresh id is `s.nextMemCapId` and the
    new cap's owner is the caller. -/
theorem provenance_creation
    {s s' : SpecState} {a : Action} (hwf : WellFormed s) (hstep : step s a s')
    {c : MemCapId} {newCap : MemCap}
    (hPre : s.getMem c = none) (hPost : s'.getMem c = some newCap) :
    c = s.nextMemCapId ∧
    ((∃ parent access attrs, a = .carve newCap.owner parent access attrs) ∨
     (∃ parent access, a = .alias newCap.owner parent access)) := by
  cases hstep with
  | carve guard =>
    rename_i caller parent access attrs
    obtain ⟨hcEq, hOwner⟩ :=
      carve_creates_at_fresh s caller parent access attrs hwf c newCap hPre hPost
    refine ⟨hcEq, Or.inl ⟨parent, access, attrs, ?_⟩⟩
    rw [hOwner]
  | alias guard =>
    rename_i caller parent access
    obtain ⟨hcEq, hOwner⟩ :=
      alias_creates_at_fresh s caller parent access hwf c newCap hPre hPost
    refine ⟨hcEq, Or.inr ⟨parent, access, ?_⟩⟩
    rw [hOwner]
  | revoke guard =>
    rename_i caller target
    exfalso
    have h := revoke_mem_isNone s caller target c hPre
    rw [hPost] at h; cases h
  | send guard =>
    rename_i caller receiver cap
    exfalso
    have h := send_mem_isNone s caller receiver cap c hPre
    rw [hPost] at h; cases h
  | «seal» guard =>
    rename_i caller cap
    exfalso
    have h := seal_mem_isNone s caller cap c hPre
    rw [hPost] at h; cases h
  | accept guard =>
    rename_i receiver pid
    exfalso
    have h := accept_mem_isNone s receiver pid c hPre
    rw [hPost] at h; cases h
  | reject guard =>
    rename_i receiver pid
    exfalso
    have h := reject_mem_isNone s receiver pid c hPre
    rw [hPost] at h; cases h
  | sealedSend guard =>
    rename_i caller receiver handle gpaHint
    exfalso
    have h := sealedSend_mem_isNone s caller receiver handle gpaHint c hPre
    rw [hPost] at h; cases h
  | create guard =>
    rename_i caller policy
    exfalso
    have h := create_mem_isNone s caller policy c hPre
    rw [hPost] at h; cases h
  | revokeDomain guard =>
    rename_i caller handle
    exfalso
    have h := revokeDomain_mem_isNone s caller handle c hPre
    rw [hPost] at h; cases h
  | setPolicy guard =>
    rename_i caller cap id value
    exfalso
    have h := setPolicy_mem_isNone s caller cap id value c hPre
    rw [hPost] at h; cases h
  | sendChannel guard =>
    rename_i caller receiver cap
    exfalso
    have h := sendChannel_mem_isNone s caller receiver cap c hPre
    rw [hPost] at h; cases h
  | acceptChannel guard =>
    rename_i receiver pid
    exfalso
    have h := acceptChannel_mem_isNone s receiver pid c hPre
    rw [hPost] at h; cases h
  | rejectChannel guard =>
    rename_i receiver pid
    exfalso
    have h := rejectChannel_mem_isNone s receiver pid c hPre
    rw [hPost] at h; cases h
  | switchReturn guard =>
    rename_i caller core er
    exfalso
    have h := switchReturn_mem_isNone s caller core er c hPre
    rw [hPost] at h; cases h
  | switch guard =>
    rename_i caller toHandle toVpId core
    exfalso
    have h := switch_mem_isNone s caller toHandle toVpId core c hPre
    rw [hPost] at h; cases h

/-! ### Per-action: owner preserved (or characterized for send/accept). -/

/-- `carve` doesn't change the owner of any pre-existing cap. -/
private theorem carve_owner_preserved
    (s : SpecState) (caller : DomId) (parent : MemCapId)
    (access : Access) (attrs : Attributes) (hfc : FreshMemCounter s)
    (c : MemCapId) (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (carve_apply s caller parent access attrs).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  rcases hp : s.getMem parent with _ | p
  · have h : (carve_apply s caller parent access attrs).getMem c = s.getMem c := by
      show ((carve_apply s caller parent access attrs).memcaps).find? c = _
      simp only [carve_apply, hp]; rfl
    rw [h, hPre] at hPost
    injection hPost with hpc
    rw [hpc]
  · have hgetC := carve_apply_getMem s caller parent access attrs p hp hfc c
    simp only at hgetC
    have hidNew : c ≠ s.nextMemCapId := by
      intro hidNew
      have hlt := existing_lt_fresh s hfc hPre
      rw [hidNew] at hlt; exact absurd hlt (Nat.lt_irrefl _)
    rw [hgetC] at hPost
    by_cases hidPar : c = parent
    · simp only [if_neg hidNew, if_pos hidPar] at hPost
      injection hPost with hpc
      rw [hidPar, hp] at hPre
      injection hPre with hpre
      rw [← hpc, ← hpre]
    · simp only [if_neg hidNew, if_neg hidPar] at hPost
      rw [hPre] at hPost
      injection hPost with hpc
      rw [hpc]

private theorem alias_owner_preserved
    (s : SpecState) (caller : DomId) (parent : MemCapId) (access : Access)
    (hfc : FreshMemCounter s) (c : MemCapId) (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (alias_apply s caller parent access).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  rcases hp : s.getMem parent with _ | p
  · have h : (alias_apply s caller parent access).getMem c = s.getMem c := by
      show ((alias_apply s caller parent access).memcaps).find? c = _
      simp only [alias_apply, hp]; rfl
    rw [h, hPre] at hPost
    injection hPost with hpc
    rw [hpc]
  · have hgetC := alias_apply_getMem s caller parent access p hp hfc c
    simp only at hgetC
    have hidNew : c ≠ s.nextMemCapId := by
      intro hidNew
      have hlt := existing_lt_fresh s hfc hPre
      rw [hidNew] at hlt; exact absurd hlt (Nat.lt_irrefl _)
    rw [hgetC] at hPost
    by_cases hidPar : c = parent
    · simp only [if_neg hidNew, if_pos hidPar] at hPost
      injection hPost with hpc
      rw [hidPar, hp] at hPre
      injection hPre with hpre
      rw [← hpc, ← hpre]
    · simp only [if_neg hidNew, if_neg hidPar] at hPost
      rw [hPre] at hPost
      injection hPost with hpc
      rw [hpc]

private theorem revoke_owner_preserved
    (s : SpecState) (caller : DomId) (target : MemCapId)
    (c : MemCapId) (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (revoke_apply s caller target).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  rcases ht : s.getMem target with _ | t
  · have h : (revoke_apply s caller target).getMem c = s.getMem c := by
      show ((revoke_apply s caller target).memcaps).find? c = _
      simp only [revoke_apply, ht]; rfl
    rw [h, hPre] at hPost
    injection hPost with hpc; rw [hpc]
  · rcases htp : t.parent with _ | pid
    · have h : (revoke_apply s caller target).getMem c = s.getMem c := by
        show ((revoke_apply s caller target).memcaps).find? c = _
        simp only [revoke_apply, ht, htp]; rfl
      rw [h, hPre] at hPost
      injection hPost with hpc; rw [hpc]
    · have h : ((revoke_apply s caller target).memcaps).find? c =
               ((s.memcaps.remove target).update pid
                  (fun p => { p with
                    childrenIds := p.childrenIds.filter (· ≠ target) })).find? c := by
        simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
      have hcne : c ≠ target := by
        intro he
        subst he
        have hnone :
            ((s.memcaps.remove c).update pid
                (fun p => { p with
                  childrenIds := p.childrenIds.filter (· ≠ c) })).find? c = none :=
          Arena.find?_update_of_none _ c pid _ (Arena.find?_remove_same _ _)
        have hpostNone : (revoke_apply s caller c).getMem c = none := by
          show ((revoke_apply s caller c).memcaps).find? c = _
          rw [h]; exact hnone
        rw [hpostNone] at hPost; cases hPost
      by_cases hcp : c = pid
      · subst hcp
        have hrem : (s.memcaps.remove target).find? c = some capPre := by
          rw [Arena.find?_remove_other _ target c hcne]; exact hPre
        have hupd : ((s.memcaps.remove target).update c
                      (fun p => { p with
                        childrenIds := p.childrenIds.filter (· ≠ target) })).find? c
                    = some { capPre with
                        childrenIds := capPre.childrenIds.filter (· ≠ target) } := by
          rw [Arena.find?_update_eq_map, hrem]; rfl
        have hpc : (revoke_apply s caller target).getMem c =
                   some { capPre with
                     childrenIds := capPre.childrenIds.filter (· ≠ target) } := by
          show ((revoke_apply s caller target).memcaps).find? c = _
          rw [h]; exact hupd
        rw [hpc] at hPost
        injection hPost with heq; rw [← heq]
      · have hpc : (revoke_apply s caller target).getMem c = s.getMem c := by
          show ((revoke_apply s caller target).memcaps).find? c = _
          rw [h]
          rw [Arena.find?_update_other _ pid c _ hcp]
          rw [Arena.find?_remove_other _ target c hcne]
          rfl
        rw [hpc, hPre] at hPost
        injection hPost with heq; rw [heq]

private theorem seal_owner_preserved
    (s : SpecState) (caller : DomId) (cap : DomCapId)
    (c : MemCapId) (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (seal_apply s caller cap).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  rw [seal_frame_mem, hPre] at hPost
  injection hPost with h; rw [h]

private theorem reject_owner_preserved
    (s : SpecState) (receiver : DomId) (pid : PendingId)
    (c : MemCapId) (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (reject_apply s receiver pid).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  rw [reject_frame_mem, hPre] at hPost
  injection hPost with h; rw [h]

private theorem sealedSend_owner_preserved
    (s : SpecState) (caller receiver : DomId) (handle : LocalHandle)
    (gpaHint : Option Nat) (c : MemCapId) (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (sealedSend_apply s caller receiver handle gpaHint).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  rw [sealedSend_frame_mem, hPre] at hPost
  injection hPost with h; rw [h]

private theorem create_owner_preserved
    (s : SpecState) (caller : DomId) (policy : DomainPolicy)
    (c : MemCapId) (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (create_apply s caller policy).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  rw [create_frame_mem, hPre] at hPost
  injection hPost with h; rw [h]

private theorem revokeDomain_owner_preserved
    (s : SpecState) (caller : DomId) (handle : LocalHandle)
    (c : MemCapId) (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (revokeDomain_apply s caller handle).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  rw [revokeDomain_frame_mem, hPre] at hPost
  injection hPost with h; rw [h]

private theorem setPolicy_owner_preserved
    (s : SpecState) (caller : DomId) (cap : DomCapId)
    (id : PolicyIdentifier) (value : Nat)
    (c : MemCapId) (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (setPolicy_apply s caller cap id value).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  rw [setPolicy_frame_mem, hPre] at hPost
  injection hPost with h; rw [h]

private theorem sendChannel_owner_preserved
    (s : SpecState) (caller receiver : DomId) (cap : DomCapId)
    (c : MemCapId) (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (sendChannel_apply s caller receiver cap).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  rw [sendChannel_frame_mem, hPre] at hPost
  injection hPost with h; rw [h]

private theorem acceptChannel_owner_preserved
    (s : SpecState) (receiver : DomId) (pid : PendingId)
    (c : MemCapId) (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (acceptChannel_apply s receiver pid).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  rw [acceptChannel_frame_mem, hPre] at hPost
  injection hPost with h; rw [h]

private theorem rejectChannel_owner_preserved
    (s : SpecState) (receiver : DomId) (pid : PendingId)
    (c : MemCapId) (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (rejectChannel_apply s receiver pid).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  rw [rejectChannel_frame_mem, hPre] at hPost
  injection hPost with h; rw [h]

private theorem switchReturn_owner_preserved
    (s : SpecState) (caller : DomId) (core : CoreId) (er : Option Nat)
    (c : MemCapId) (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (switchReturn_apply s caller core er).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  rw [switchReturn_frame_mem, hPre] at hPost
  injection hPost with h; rw [h]

private theorem switch_owner_preserved
    (s : SpecState) (caller : DomId) (toHandle : LocalHandle)
    (toVpId : VpId) (core : CoreId) (c : MemCapId)
    (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (switch_apply s caller toHandle toVpId core).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  rw [switch_frame_mem, hPre] at hPost
  injection hPost with h; rw [h]

/-! ### `send` and `accept`: characterize the owner change. -/

/-- `send` only changes the owner of `cap`, setting it to `receiver`. -/
private theorem send_owner_change
    (s : SpecState) (caller receiver : DomId) (cap : MemCapId)
    (c : MemCapId) (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (send_apply s caller receiver cap).getMem c = some capPost) :
    (c = cap ∧ capPost.owner = receiver) ∨ capPre.owner = capPost.owner := by
  rw [send_apply_getMem] at hPost
  by_cases hidC : c = cap
  · left
    refine ⟨hidC, ?_⟩
    rw [hidC] at hPre
    simp only [if_pos hidC, hPre, Option.map_some] at hPost
    injection hPost with hpc
    rw [← hpc]
  · right
    rw [if_neg hidC, hPre] at hPost
    injection hPost with hpc
    rw [hpc]

/-- `accept`'s memcap arena update is exactly a `send_apply` with the
    receiver as the new owner; so any owner change pins the new owner
    to the accepting domain. -/
private theorem accept_owner_change
    (s : SpecState) (receiver : DomId) (pid : PendingId)
    (c : MemCapId) (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (accept_apply s receiver pid).getMem c = some capPost) :
    capPost.owner = receiver ∨ capPre.owner = capPost.owner := by
  -- Reduce accept_apply to expose send_apply on the memcap arena.
  rcases hb : (s.getDom receiver).bind (fun d => d.lookupPending pid) with _ | pe
  · have hmem : (accept_apply s receiver pid).memcaps = s.memcaps := by
      simp only [accept_apply, hb]
    have hp : (accept_apply s receiver pid).getMem c = s.getMem c := by
      show ((accept_apply s receiver pid).memcaps).find? c = _; rw [hmem]; rfl
    rw [hp, hPre] at hPost
    injection hPost with hpc
    right; rw [hpc]
  · have hmem :
        (accept_apply s receiver pid).memcaps =
        (send_apply s pe.senderDomainId receiver pe.capId).memcaps := by
      simp only [accept_apply, hb, SpecState.updDomain]
    have hp :
        (accept_apply s receiver pid).getMem c =
        (send_apply s pe.senderDomainId receiver pe.capId).getMem c := by
      show ((accept_apply s receiver pid).memcaps).find? c = _; rw [hmem]; rfl
    rw [hp] at hPost
    rcases send_owner_change s pe.senderDomainId receiver pe.capId c capPre capPost
            hPre hPost with ⟨_, hown⟩ | hown
    · left; exact hown
    · right; exact hown

/-! ### Provenance — Transfer -/

/-- The only way the owner of an existing memcap can change is via
    `send` (where `caller = old owner, receiver = new owner`) or
    `accept` (where the accepting domain is the new owner). -/
theorem provenance_transfer
    {s s' : SpecState} {a : Action} (hwf : WellFormed s) (hstep : step s a s')
    {c : MemCapId} {capPre capPost : MemCap}
    (hPre : s.getMem c = some capPre)
    (hPost : s'.getMem c = some capPost)
    (hOwnerChange : capPre.owner ≠ capPost.owner) :
    (∃ caller, a = .send caller capPost.owner c) ∨
    (∃ pid, a = .accept capPost.owner pid) := by
  cases hstep with
  | carve guard =>
    rename_i caller parent access attrs
    exfalso
    exact hOwnerChange
      (carve_owner_preserved s caller parent access attrs hwf.freshMemCounter
        c capPre capPost hPre hPost)
  | alias guard =>
    rename_i caller parent access
    exfalso
    exact hOwnerChange
      (alias_owner_preserved s caller parent access hwf.freshMemCounter
        c capPre capPost hPre hPost)
  | revoke guard =>
    rename_i caller target
    exfalso
    exact hOwnerChange
      (revoke_owner_preserved s caller target c capPre capPost hPre hPost)
  | send guard =>
    rename_i caller receiver cap
    rcases send_owner_change s caller receiver cap c capPre capPost hPre hPost with
      ⟨hcEq, hOwn⟩ | hPres
    · left
      refine ⟨caller, ?_⟩
      rw [hcEq, hOwn]
    · exfalso; exact hOwnerChange hPres
  | «seal» guard =>
    rename_i caller cap
    exfalso
    exact hOwnerChange
      (seal_owner_preserved s caller cap c capPre capPost hPre hPost)
  | accept guard =>
    rename_i receiver pid
    rcases accept_owner_change s receiver pid c capPre capPost hPre hPost with
      hOwn | hPres
    · right
      refine ⟨pid, ?_⟩
      rw [hOwn]
    · exfalso; exact hOwnerChange hPres
  | reject guard =>
    rename_i receiver pid
    exfalso
    exact hOwnerChange
      (reject_owner_preserved s receiver pid c capPre capPost hPre hPost)
  | sealedSend guard =>
    rename_i caller receiver handle gpaHint
    exfalso
    exact hOwnerChange
      (sealedSend_owner_preserved s caller receiver handle gpaHint
        c capPre capPost hPre hPost)
  | create guard =>
    rename_i caller policy
    exfalso
    exact hOwnerChange
      (create_owner_preserved s caller policy c capPre capPost hPre hPost)
  | revokeDomain guard =>
    rename_i caller handle
    exfalso
    exact hOwnerChange
      (revokeDomain_owner_preserved s caller handle c capPre capPost hPre hPost)
  | setPolicy guard =>
    rename_i caller cap id value
    exfalso
    exact hOwnerChange
      (setPolicy_owner_preserved s caller cap id value c capPre capPost hPre hPost)
  | sendChannel guard =>
    rename_i caller receiver cap
    exfalso
    exact hOwnerChange
      (sendChannel_owner_preserved s caller receiver cap c capPre capPost hPre hPost)
  | acceptChannel guard =>
    rename_i receiver pid
    exfalso
    exact hOwnerChange
      (acceptChannel_owner_preserved s receiver pid c capPre capPost hPre hPost)
  | rejectChannel guard =>
    rename_i receiver pid
    exfalso
    exact hOwnerChange
      (rejectChannel_owner_preserved s receiver pid c capPre capPost hPre hPost)
  | switchReturn guard =>
    rename_i caller core er
    exfalso
    exact hOwnerChange
      (switchReturn_owner_preserved s caller core er c capPre capPost hPre hPost)
  | switch guard =>
    rename_i caller toHandle toVpId core
    exfalso
    exact hOwnerChange
      (switch_owner_preserved s caller toHandle toVpId core c capPre capPost hPre hPost)

end ThemisCapa
