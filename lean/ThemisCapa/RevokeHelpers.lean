/-
  ThemisCapa.RevokeHelpers — Framing lemmas for the S4 subtree-cascading
  `revokeDomain_apply`.

  This file proves the *axis-preservation* core: any domain surviving
  one call to `revokeOneDomain s did'` has the same `parent`, `policy`,
  `status`, `vps`, `memHandles`, `domHandles`, and `commBindings`
  fields as in the pre-state. (Only `childrenDoms` may shrink, when
  the surviving domain happens to be `did'`'s parent.)

  This lemma lifts trivially to the full subtree fold and is the
  scaffolding for `revokeDomain_preserves{PolicyMonotonicAncestry,
  CoreAffinity, FreshPending, …}`.
-/
import ThemisCapa.Step
import ThemisCapa.Arena
import ThemisCapa.State

namespace ThemisCapa

/-! ## `revokeOneMemCap` — never touches the domain arena -/

theorem revokeOneMemCap_domains_eq (s : SpecState) (mid : MemCapId) :
    (revokeOneMemCap s mid).domains = s.domains := by
  unfold revokeOneMemCap
  repeat' (first | split | rfl | rename_i _; simp [SpecState.updMem])

theorem revokeOneMemCap_domcaps_eq (s : SpecState) (mid : MemCapId) :
    (revokeOneMemCap s mid).domcaps = s.domcaps := by
  unfold revokeOneMemCap
  repeat' (first | split | rfl | rename_i _; simp [SpecState.updMem])

theorem foldl_revokeOneMemCap_domains_eq
    (s : SpecState) (mids : List MemCapId) :
    (mids.foldl revokeOneMemCap s).domains = s.domains := by
  induction mids generalizing s with
  | nil => rfl
  | cons _ rest ih => simp only [List.foldl_cons]; rw [ih, revokeOneMemCap_domains_eq]

theorem foldl_revokeOneMemCap_domcaps_eq
    (s : SpecState) (mids : List MemCapId) :
    (mids.foldl revokeOneMemCap s).domcaps = s.domcaps := by
  induction mids generalizing s with
  | nil => rfl
  | cons _ rest ih => simp only [List.foldl_cons]; rw [ih, revokeOneMemCap_domcaps_eq]

/-! ## `cancelChannelIfPending` — only `pendingDomCaps` / `frozenHandles` -/

private def cancelChannelStep (cap : DomCapId) (acc : SpecState)
    (entry : DomId × Domain) : SpecState :=
  match entry.2.pendingDomCaps.find? (fun p => p.2.capId = cap) with
  | none           => acc
  | some (_pid, pe) =>
    let acc₁ := acc.updDomain entry.1 (fun rd =>
      { rd with pendingDomCaps :=
          rd.pendingDomCaps.filter (fun p => p.2.capId ≠ cap) })
    acc₁.updDomain pe.senderDomainId (fun sd =>
      { sd with frozenHandles :=
          sd.frozenHandles.filter (· ≠ pe.senderHandle) })

theorem cancelChannelIfPending_eq_foldl (s : SpecState) (cap : DomCapId) :
    cancelChannelIfPending s cap =
      s.domains.entries.foldl (cancelChannelStep cap) s := rfl

private theorem cancelChannelStep_domcaps
    (cap : DomCapId) (acc : SpecState) (entry : DomId × Domain) :
    (cancelChannelStep cap acc entry).domcaps = acc.domcaps := by
  unfold cancelChannelStep
  cases entry.2.pendingDomCaps.find? (fun p => p.2.capId = cap) with
  | none => rfl
  | some pidpe => obtain ⟨_, _⟩ := pidpe; rfl

private theorem cancelChannelStep_memcaps
    (cap : DomCapId) (acc : SpecState) (entry : DomId × Domain) :
    (cancelChannelStep cap acc entry).memcaps = acc.memcaps := by
  unfold cancelChannelStep
  cases entry.2.pendingDomCaps.find? (fun p => p.2.capId = cap) with
  | none => rfl
  | some pidpe => obtain ⟨_, _⟩ := pidpe; rfl

theorem cancelChannelIfPending_domcaps_eq
    (s : SpecState) (cap : DomCapId) :
    (cancelChannelIfPending s cap).domcaps = s.domcaps := by
  rw [cancelChannelIfPending_eq_foldl]
  induction s.domains.entries generalizing s with
  | nil => rfl
  | cons entry rest ih =>
    simp only [List.foldl_cons]
    rw [ih, cancelChannelStep_domcaps]

theorem cancelChannelIfPending_memcaps_eq
    (s : SpecState) (cap : DomCapId) :
    (cancelChannelIfPending s cap).memcaps = s.memcaps := by
  rw [cancelChannelIfPending_eq_foldl]
  induction s.domains.entries generalizing s with
  | nil => rfl
  | cons entry rest ih =>
    simp only [List.foldl_cons]
    rw [ih, cancelChannelStep_memcaps]

/-! ## `clearCommBindings` — only `region.attributes`/`region.commBinding` -/

theorem clearCommBindings_domains_eq (s : SpecState) (cbs : List MemCapId) :
    (clearCommBindings s cbs).domains = s.domains := by
  unfold clearCommBindings
  induction cbs generalizing s with
  | nil => rfl
  | cons _ rest ih => simp only [List.foldl_cons]; rw [ih]; rfl

theorem clearCommBindings_domcaps_eq (s : SpecState) (cbs : List MemCapId) :
    (clearCommBindings s cbs).domcaps = s.domcaps := by
  unfold clearCommBindings
  induction cbs generalizing s with
  | nil => rfl
  | cons _ rest ih => simp only [List.foldl_cons]; rw [ih]; rfl

end ThemisCapa
