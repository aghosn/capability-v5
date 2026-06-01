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

end ThemisCapa
