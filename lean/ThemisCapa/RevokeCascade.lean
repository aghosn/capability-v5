/-
  ThemisCapa.RevokeCascade — Characterization of the VITAL revocation
  cascade introduced in `revoke_apply` (G1 leaf-only).

  Theorems:
    * `T1 revoke_cascade_locality`
        The only domain whose `status` can flip from `.live` to
        `.revoked` during a single `revoke_apply` call is `t.owner`,
        where `t` is the targeted memcap. Equivalently, no domain
        unrelated to the target's owner is silently killed.

    * `T2 revoke_apply_vital_owner_revoked`
        Forward direction: if the target memcap exists, has a parent,
        and carries `attributes.vital = true`, then after
        `revoke_apply` the owner domain is `.revoked`.

    * `T3 step_preserves_revoked`
        Tombstones are persistent: once `d.status = .revoked`, no step
        transitions it back to `.sealed` or `.unsealed`. (Actions that
        reference revoked domains are blocked by the per-guard
        `*Live` clauses; the cascade only flips toward `.revoked`.)

    * `T4 step_revoked_implies_parent_immutable` (corollary)
        Parent links of revoked tombstones remain stable under any
        step. Direct corollary of `step_parent_immutable`.
-/
import ThemisCapa.ParentStability
import ThemisCapa.Properties

namespace ThemisCapa
open Domain

/-! ### T1: cascade locality -/

/-- The cascade can only flip `t.owner`'s status. Any other domain that
    transitions from `isLive` to `isRevoked` across a `revoke_apply` call
    is impossible — there is none. Stated contrapositively: if some
    domain `did` flipped from live to revoked, then `did = t.owner` and
    the target was vital. -/
theorem revoke_cascade_locality
    (s : SpecState) (caller : DomId) (target : MemCapId)
    (did : DomId) (d d' : Domain)
    (hpre  : s.getDom did = some d)
    (hpost : (revoke_apply s caller target).getDom did = some d')
    (hLive : d.isLive)
    (hRev  : d'.isRevoked) :
    ∃ t pid, s.getMem target = some t ∧ t.parent = some pid ∧
             t.region.attributes.vital = true ∧ did = t.owner := by
  rcases ht : s.getMem target with _ | t
  · -- target absent → revoke_apply = id → d' = d.
    exfalso
    have h : (revoke_apply s caller target).getDom did = s.getDom did := by
      simp [revoke_apply, ht]
    rw [h, hpre] at hpost; injection hpost with heq
    rw [← heq] at hRev; exact hLive hRev
  · rcases htp : t.parent with _ | pid
    · -- target rootless → revoke_apply = id.
      exfalso
      have h : (revoke_apply s caller target).getDom did = s.getDom did := by
        simp [revoke_apply, ht, htp]
      rw [h, hpre] at hpost; injection hpost with heq
      rw [← heq] at hRev; exact hLive hRev
    · -- vital case-split via the `revoke_apply_getDom` characterization.
      have hgD := revoke_apply_getDom s caller target t ht pid htp did
      simp only at hgD
      by_cases hdid : did = t.owner
      · -- did = t.owner: status' = if vital then revoked else d.status.
        by_cases hv : t.region.attributes.vital
        · -- vital: this is the only branch where the cascade fires.
          exact ⟨t, pid, rfl, htp, hv, hdid⟩
        · -- non-vital: d'.status = d.status (still live), contradicting hRev.
          exfalso
          rw [hgD, if_pos hdid] at hpost
          subst hdid
          rw [hpre] at hpost
          simp at hpost
          have hstatus : d'.status = d.status := by
            rw [← hpost]; simp [hv]
          unfold isRevoked at hRev
          unfold isLive at hLive
          rw [hstatus] at hRev
          exact hLive hRev
      · -- did ≠ t.owner: getDom unchanged → d' = d → still live.
        exfalso
        rw [hgD, if_neg hdid] at hpost
        rw [hpre] at hpost; injection hpost with heq
        rw [← heq] at hRev; exact hLive hRev

/-! ### T2: vital ⇒ owner revoked -/

/-- Forward direction of the cascade: if the target is a vital memcap
    with a parent, then after `revoke_apply` the owner domain has
    `status = .revoked`. -/
theorem revoke_apply_vital_owner_revoked
    (s : SpecState) (caller : DomId) (target : MemCapId)
    (t : MemCap) (pid : MemCapId)
    (ht : s.getMem target = some t) (htp : t.parent = some pid)
    (hv : t.region.attributes.vital = true)
    (d : Domain) (hd : s.getDom t.owner = some d) :
    ∃ d', (revoke_apply s caller target).getDom t.owner = some d' ∧
           d'.isRevoked := by
  show ∃ d', ((revoke_apply s caller target).domains).find? t.owner = some d' ∧
              d'.isRevoked
  simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain,
             if_pos hv]
  rw [Arena.find?_update_eq_map, Arena.find?_update_eq_map]
  have hd' : s.domains.find? t.owner = some d := hd
  rw [hd']
  refine ⟨_, rfl, ?_⟩
  unfold isRevoked
  simp

/-! ### T3: tombstones persist -/

/-- `updDomain id f` preserves `isRevoked` on `did` whenever `f`
    preserves `isRevoked` pointwise. The two relevant instances:
      * `f` does not write `.status` at all (so `(f d).status =
        d.status`, hence revoked stays revoked).
      * `f d = { d with status := .revoked }` (idempotent on
        tombstones — the VITAL cascade in `revoke_apply`). -/
private theorem updDomain_preserves_isRevoked
    (s : SpecState) (id : DomId) (f : Domain → Domain)
    (hf : ∀ d, d.isRevoked → (f d).isRevoked)
    (did : DomId) (d d' : Domain)
    (hpre : s.getDom did = some d) (hrev : d.isRevoked)
    (hpost : (s.updDomain id f).getDom did = some d') :
    d'.isRevoked := by
  by_cases hdid : did = id
  · subst hdid
    have h0 : (s.updDomain did f).domains.find? did = some d' := hpost
    simp only [SpecState.updDomain] at h0
    rw [Arena.find?_update_eq_map] at h0
    have hpre' : s.domains.find? did = some d := hpre
    rw [hpre'] at h0; simp at h0
    rw [← h0]; exact hf d hrev
  · have h0 : (s.updDomain id f).domains.find? did = some d' := hpost
    simp only [SpecState.updDomain] at h0
    rw [Arena.find?_update_other _ id did _ hdid] at h0
    have hpre' : s.domains.find? did = some d := hpre
    rw [hpre'] at h0; injection h0 with heq; rw [← heq]; exact hrev

/-- Convenience corollary: when `f` does not touch `.status` at all,
    `updDomain id f` preserves `isRevoked`. -/
private theorem updDomain_preserves_isRevoked_of_status_eq
    (s : SpecState) (id : DomId) (f : Domain → Domain)
    (hf : ∀ d, (f d).status = d.status)
    (did : DomId) (d d' : Domain)
    (hpre : s.getDom did = some d) (hrev : d.isRevoked)
    (hpost : (s.updDomain id f).getDom did = some d') :
    d'.isRevoked :=
  updDomain_preserves_isRevoked s id f
    (fun x hx => by unfold isRevoked at *; rw [hf x]; exact hx)
    did d d' hpre hrev hpost

/-- `updMem` doesn't touch the `domains` arena. -/
private theorem updMem_getDom (s : SpecState) (id : MemCapId) (f : MemCap → MemCap)
    (did : DomId) : (s.updMem id f).getDom did = s.getDom did := rfl

/-- `updDomCap` doesn't touch the `domains` arena. -/
private theorem updDomCap_getDom (s : SpecState) (id : DomCapId)
    (f : DomCap → DomCap) (did : DomId) :
    (s.updDomCap id f).getDom did = s.getDom did := rfl

/-- `updCore` doesn't touch the `domains` arena. -/
private theorem updCore_getDom (s : SpecState) (id : CoreId)
    (f : CoreState → CoreState) (did : DomId) :
    (s.updCore id f).getDom did = s.getDom did := rfl

/-- `freshMem` doesn't touch the `domains` arena. -/
private theorem freshMem_getDom (s : SpecState) (cap : MemCap) (did : DomId) :
    (s.freshMem cap).2.getDom did = s.getDom did := rfl

/-- `freshDomCap` doesn't touch the `domains` arena. -/
private theorem freshDomCap_getDom (s : SpecState) (dc : DomCap) (did : DomId) :
    (s.freshDomCap dc).2.getDom did = s.getDom did := rfl

/-- `domains.remove target` removes only `target`. -/
private theorem remove_target_getDom
    (s : SpecState) (target : DomId) (did : DomId) (hne : did ≠ target) :
    ({ s with domains := s.domains.remove target } : SpecState).getDom did
      = s.getDom did := by
  show (s.domains.remove target).find? did = s.domains.find? did
  exact Arena.find?_remove_other _ target did hne

/-! ### Per-action `isRevoked` preservation lemmas

For every action, the apply function preserves `isRevoked`: starting
from `d.isRevoked` in `s` and an existing post-state lookup `s'.getDom
did = some d'`, we conclude `d'.isRevoked`.

The proof template, mirroring `_apply_preservesParents`:
  1. Case on inner option matches in the apply (no-op vs success).
  2. In the success branch, `simp only` with `[<action>_apply, …,
     updDomain, updMem, updDomCap, updCore, freshMem, freshDom,
     freshDomCap]` reduces the post-state to a chain of
     `Arena.update`/`Arena.insert`/`Arena.remove` calls.
  3. By-case on `did = <each touched actor>`. For status-preserving
     updates, use `Arena.find?_update_eq_map` then read off
     `(f d).status = d.status`. For frame, use
     `Arena.find?_update_other`.
-/

private theorem carve_apply_preservesIsRevoked
    (caller : DomId) (parent : MemCapId) (access : Access) (attrs : Attributes)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain) (hpost : (carve_apply s caller parent access attrs).getDom did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hp : s.getMem parent with _ | p
  · have h : (carve_apply s caller parent access attrs).domains.find? did = some d' := hpost
    simp [carve_apply, hp] at h
    rw [hpre_d] at h; injection h with eq; rw [← eq]; exact hrev
  · have hp' : (carve_apply s caller parent access attrs).domains.find? did = some d' := hpost
    simp only [carve_apply, hp, SpecState.freshMem, SpecState.updMem,
               SpecState.updDomain] at hp'
    by_cases hdid : did = caller
    · subst hdid
      rw [Arena.find?_update_eq_map] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
    · rw [Arena.find?_update_other _ caller did _ hdid] at hp'
      rw [hpre_d] at hp'; injection hp' with eq; rw [← eq]; exact hrev

private theorem alias_apply_preservesIsRevoked
    (caller : DomId) (parent : MemCapId) (access : Access)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain) (hpost : (alias_apply s caller parent access).getDom did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hp : s.getMem parent with _ | p
  · have h : (alias_apply s caller parent access).domains.find? did = some d' := hpost
    simp [alias_apply, hp] at h
    rw [hpre_d] at h; injection h with eq; rw [← eq]; exact hrev
  · have hp' : (alias_apply s caller parent access).domains.find? did = some d' := hpost
    simp only [alias_apply, hp, SpecState.freshMem, SpecState.updMem,
               SpecState.updDomain] at hp'
    by_cases hdid : did = caller
    · subst hdid
      rw [Arena.find?_update_eq_map] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
    · rw [Arena.find?_update_other _ caller did _ hdid] at hp'
      rw [hpre_d] at hp'; injection hp' with eq; rw [← eq]; exact hrev

private theorem revoke_apply_preservesIsRevoked
    (caller : DomId) (target : MemCapId)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain) (hpost : (revoke_apply s caller target).getDom did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  rcases ht : s.getMem target with _ | t
  · have h : (revoke_apply s caller target).domains.find? did = some d' := hpost
    simp [revoke_apply, ht] at h
    rw [hpre_d] at h; injection h with eq; rw [← eq]; exact hrev
  · rcases htp : t.parent with _ | pid
    · have h : (revoke_apply s caller target).domains.find? did = some d' := hpost
      simp [revoke_apply, ht, htp] at h
      rw [hpre_d] at h; injection h with eq; rw [← eq]; exact hrev
    · -- Use the public `revoke_apply_getDom` characterization.
      have hgD := revoke_apply_getDom s caller target t ht pid htp did
      simp only at hgD
      rw [hgD] at hpost
      by_cases hdid : did = t.owner
      · rw [if_pos hdid] at hpost
        subst hdid
        rw [hpre] at hpost; simp at hpost
        rw [← hpost]
        unfold isRevoked at hrev ⊢
        by_cases hv : t.region.attributes.vital
        · simp [hv]
        · simp [hv]; exact hrev
      · rw [if_neg hdid] at hpost
        rw [hpre] at hpost; injection hpost with eq; rw [← eq]; exact hrev

private theorem send_apply_preservesIsRevoked
    (caller receiver : DomId) (cap : MemCapId)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain) (hpost : (send_apply s caller receiver cap).getDom did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  have hp' : (send_apply s caller receiver cap).domains.find? did = some d' := hpost
  simp only [send_apply, SpecState.updDomain, SpecState.updMem] at hp'
  by_cases hdR : did = receiver
  · subst hdR
    rw [Arena.find?_update_eq_map] at hp'
    by_cases hCR : did = caller
    · subst hCR
      rw [Arena.find?_update_eq_map] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
    · rw [Arena.find?_update_other _ caller did _ hCR] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
  · rw [Arena.find?_update_other _ receiver did _ hdR] at hp'
    by_cases hCR : did = caller
    · subst hCR
      rw [Arena.find?_update_eq_map] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
    · rw [Arena.find?_update_other _ caller did _ hCR] at hp'
      rw [hpre_d] at hp'; injection hp' with eq; rw [← eq]; exact hrev

private theorem seal_apply_preservesIsRevoked
    (caller : DomId) (cap : DomCapId)
    (s : SpecState) (guard : SealGuard s caller cap)
    (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain) (hpost : (seal_apply s caller cap).getDom did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hc : s.getDomCap cap with _ | dc
  · have h : (seal_apply s caller cap).domains.find? did = some d' := hpost
    simp [seal_apply, hc] at h
    rw [hpre_d] at h; injection h with eq; rw [← eq]; exact hrev
  · have hp' : (seal_apply s caller cap).domains.find? did = some d' := hpost
    simp only [seal_apply, hc, SpecState.updDomain] at hp'
    by_cases hdid : did = dc.targetDom
    · -- Guard contradiction: targetUnsealed says d.isUnsealed.
      subst hdid
      have hUnsealed := guard.targetUnsealed dc hc d hpre
      unfold isUnsealed at hUnsealed
      unfold isRevoked at hrev
      rw [hUnsealed] at hrev
      cases hrev
    · rw [Arena.find?_update_other _ dc.targetDom did _ hdid] at hp'
      rw [hpre_d] at hp'; injection hp' with eq; rw [← eq]; exact hrev

private theorem reject_apply_preservesIsRevoked
    (receiver : DomId) (pendingId : PendingId)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain) (hpost : (reject_apply s receiver pendingId).getDom did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  have hp' : (reject_apply s receiver pendingId).domains.find? did = some d' := hpost
  simp only [reject_apply, SpecState.updDomain] at hp'
  -- Outer updDomain receiver, then optional updDomain on sender.
  rcases hb : (s.getDom receiver).bind (fun d => d.lookupPending pendingId) with _ | pe
  · simp [hb] at hp'
    by_cases hdR : did = receiver
    · subst hdR
      rw [Arena.find?_update_eq_map] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
    · rw [Arena.find?_update_other _ receiver did _ hdR] at hp'
      rw [hpre_d] at hp'; injection hp' with eq; rw [← eq]; exact hrev
  · simp [hb] at hp'
    by_cases h1 : did = pe.senderDomainId
    · subst h1
      rw [Arena.find?_update_eq_map] at hp'
      by_cases h2 : pe.senderDomainId = receiver
      · subst h2
        rw [Arena.find?_update_eq_map] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
      · rw [Arena.find?_update_other _ receiver _ _ h2] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
    · rw [Arena.find?_update_other _ pe.senderDomainId did _ h1] at hp'
      by_cases h2 : did = receiver
      · subst h2
        rw [Arena.find?_update_eq_map] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
      · rw [Arena.find?_update_other _ receiver did _ h2] at hp'
        rw [hpre_d] at hp'; injection hp' with eq; rw [← eq]; exact hrev

/-! ### Simple per-action lemmas (single updDomain, status-preserving f) -/

private theorem setPolicy_apply_preservesIsRevoked
    (caller : DomId) (cap : DomCapId) (id : PolicyIdentifier) (value : Nat)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain) (hpost : (setPolicy_apply s caller cap id value).getDom did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hc : s.getDomCap cap with _ | dc
  · have h0 : (setPolicy_apply s caller cap id value).domains.find? did = some d' := hpost
    simp [setPolicy_apply, hc] at h0
    rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
  · have hp' : (setPolicy_apply s caller cap id value).domains.find? did = some d' := hpost
    simp only [setPolicy_apply, hc, SpecState.updDomain] at hp'
    by_cases hdid : did = dc.targetDom
    · subst hdid
      rw [Arena.find?_update_eq_map] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
    · rw [Arena.find?_update_other _ dc.targetDom did _ hdid] at hp'
      rw [hpre_d] at hp'; injection hp' with eq; rw [← eq]; exact hrev

private theorem mapSelf_apply_preservesIsRevoked
    (caller : DomId) (capHandle : LocalHandle) (newGpa : Nat)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain) (hpost : (mapSelf_apply s caller capHandle newGpa).getDom did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hd : s.getDom caller with _ | dc
  · have h0 : (mapSelf_apply s caller capHandle newGpa).domains.find? did = some d' := hpost
    simp [mapSelf_apply, hd] at h0
    rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
  · rcases hm : dc.lookupMemHandle capHandle with _ | mid
    · have h0 : (mapSelf_apply s caller capHandle newGpa).domains.find? did = some d' := hpost
      simp [mapSelf_apply, hd, hm] at h0
      rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
    · rcases hg : s.getMem mid with _ | mc
      · have h0 : (mapSelf_apply s caller capHandle newGpa).domains.find? did = some d' := hpost
        simp [mapSelf_apply, hd, hm, hg] at h0
        rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
      · rcases hk : dc.lookupMappedGpa capHandle with _ | oldGpa
        · have h0 :
              (mapSelf_apply s caller capHandle newGpa).domains.find? did = some d' := hpost
          simp [mapSelf_apply, hd, hm, hg, hk] at h0
          rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
        · have hp' :
              (mapSelf_apply s caller capHandle newGpa).domains.find? did = some d' := hpost
          simp only [mapSelf_apply, hd, hm, hg, hk, SpecState.updDomain] at hp'
          by_cases hdid : did = caller
          · subst hdid
            rw [Arena.find?_update_eq_map] at hp'
            rw [hpre_d] at hp'; simp at hp'; rw [← hp']
            unfold Domain.isRevoked Domain.updMappedGpa
            split <;> exact hrev
          · rw [Arena.find?_update_other _ caller did _ hdid] at hp'
            rw [hpre_d] at hp'; injection hp' with eq; rw [← eq]; exact hrev

private theorem sealedSend_apply_preservesIsRevoked
    (caller receiver : DomId) (handle : LocalHandle) (gpaHint : Option Nat)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain)
    (hpost : (sealedSend_apply s caller receiver handle gpaHint).getDom did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hb : (s.getDom caller).bind (fun d => d.lookupMemHandle handle) with _ | capId
  · have h0 :
        (sealedSend_apply s caller receiver handle gpaHint).domains.find? did = some d' := hpost
    simp [sealedSend_apply, hb] at h0
    rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
  · have hp' :
        (sealedSend_apply s caller receiver handle gpaHint).domains.find? did = some d' := hpost
    simp only [sealedSend_apply, hb, SpecState.updDomain] at hp'
    by_cases hd1 : did = receiver
    · subst hd1
      rw [Arena.find?_update_eq_map] at hp'
      by_cases hd2 : did = caller
      · subst hd2
        rw [Arena.find?_update_eq_map] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
      · rw [Arena.find?_update_other _ caller did _ hd2] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
    · rw [Arena.find?_update_other _ receiver did _ hd1] at hp'
      by_cases hd2 : did = caller
      · subst hd2
        rw [Arena.find?_update_eq_map] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
      · rw [Arena.find?_update_other _ caller did _ hd2] at hp'
        rw [hpre_d] at hp'; injection hp' with eq; rw [← eq]; exact hrev

private theorem sendChannel_apply_preservesIsRevoked
    (caller receiver : DomId) (cap : DomCapId)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain)
    (hpost : (sendChannel_apply s caller receiver cap).getDom did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  -- sendChannel ends with updDomCap (preserves domains arena)
  have hp' : (sendChannel_apply s caller receiver cap).domains.find? did = some d' := hpost
  simp only [sendChannel_apply, SpecState.updDomCap, SpecState.updDomain] at hp'
  by_cases hd1 : did = receiver
  · subst hd1
    rw [Arena.find?_update_eq_map] at hp'
    by_cases hd2 : did = caller
    · subst hd2
      rw [Arena.find?_update_eq_map] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
    · rw [Arena.find?_update_other _ caller did _ hd2] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
  · rw [Arena.find?_update_other _ receiver did _ hd1] at hp'
    by_cases hd2 : did = caller
    · subst hd2
      rw [Arena.find?_update_eq_map] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
    · rw [Arena.find?_update_other _ caller did _ hd2] at hp'
      rw [hpre_d] at hp'; injection hp' with eq; rw [← eq]; exact hrev

private theorem rejectChannel_apply_preservesIsRevoked
    (receiver : DomId) (pendingId : PendingId)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain)
    (hpost : (rejectChannel_apply s receiver pendingId).getDom did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  have hp' : (rejectChannel_apply s receiver pendingId).domains.find? did = some d' := hpost
  rcases hb : (s.getDom receiver).bind (fun d => d.lookupPendingDom pendingId) with _ | pe
  · simp only [rejectChannel_apply, hb, SpecState.updDomain] at hp'
    by_cases hd : did = receiver
    · subst hd
      rw [Arena.find?_update_eq_map] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
    · rw [Arena.find?_update_other _ receiver did _ hd] at hp'
      rw [hpre_d] at hp'; injection hp' with eq; rw [← eq]; exact hrev
  · simp only [rejectChannel_apply, hb, SpecState.updDomain] at hp'
    by_cases hd1 : did = pe.senderDomainId
    · subst hd1
      rw [Arena.find?_update_eq_map] at hp'
      by_cases hd2 : pe.senderDomainId = receiver
      · rw [← hd2] at hp'
        rw [Arena.find?_update_eq_map] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
      · rw [Arena.find?_update_other _ receiver pe.senderDomainId _ hd2] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
    · rw [Arena.find?_update_other _ pe.senderDomainId did _ hd1] at hp'
      by_cases hd2 : did = receiver
      · subst hd2
        rw [Arena.find?_update_eq_map] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
      · rw [Arena.find?_update_other _ receiver did _ hd2] at hp'
        rw [hpre_d] at hp'; injection hp' with eq; rw [← eq]; exact hrev

/-! ### Multi-updDomain actions wrapping send_apply / sendChannel_apply -/

private theorem accept_apply_preservesIsRevoked'
    (receiver : DomId) (pendingId : PendingId)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain) (hpost : (accept_apply s receiver pendingId).getDom did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hb : (s.getDom receiver).bind (fun d => d.lookupPending pendingId) with _ | pe
  · have h0 : (accept_apply s receiver pendingId).domains.find? did = some d' := hpost
    simp [accept_apply, hb] at h0
    rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
  · have hp' : (accept_apply s receiver pendingId).domains.find? did = some d' := hpost
    simp only [accept_apply, hb, SpecState.updDomain] at hp'
    by_cases hd1 : did = pe.senderDomainId
    · subst hd1
      rw [Arena.find?_update_eq_map] at hp'
      by_cases hd2 : pe.senderDomainId = receiver
      · rw [← hd2] at hp'
        rw [Arena.find?_update_eq_map] at hp'
        rcases hsend :
            (send_apply s pe.senderDomainId pe.senderDomainId pe.capId).domains.find?
              pe.senderDomainId with _ | dx
        · rw [hsend] at hp'; simp at hp'
        · rw [hsend] at hp'; simp at hp'
          have hsendp :
              (send_apply s pe.senderDomainId pe.senderDomainId pe.capId).getDom
                pe.senderDomainId = some dx := hsend
          have hxrev : dx.isRevoked :=
            send_apply_preservesIsRevoked pe.senderDomainId pe.senderDomainId pe.capId
              s pe.senderDomainId d hpre_d hrev dx hsendp
          rw [← hp']; exact hxrev
      · rw [Arena.find?_update_other _ receiver pe.senderDomainId _ hd2] at hp'
        rcases hsend :
            (send_apply s pe.senderDomainId receiver pe.capId).domains.find? pe.senderDomainId
            with _ | dx
        · rw [hsend] at hp'; simp at hp'
        · rw [hsend] at hp'; simp at hp'
          have hsendp :
              (send_apply s pe.senderDomainId receiver pe.capId).getDom pe.senderDomainId
              = some dx := hsend
          have hxrev : dx.isRevoked :=
            send_apply_preservesIsRevoked pe.senderDomainId receiver pe.capId
              s pe.senderDomainId d hpre_d hrev dx hsendp
          rw [← hp']; exact hxrev
    · rw [Arena.find?_update_other _ pe.senderDomainId did _ hd1] at hp'
      by_cases hd2 : did = receiver
      · subst hd2
        rw [Arena.find?_update_eq_map] at hp'
        rcases hsend :
            (send_apply s pe.senderDomainId did pe.capId).domains.find? did with _ | dx
        · rw [hsend] at hp'; simp at hp'
        · rw [hsend] at hp'; simp at hp'
          have hsendp :
              (send_apply s pe.senderDomainId did pe.capId).getDom did = some dx := hsend
          have hxrev : dx.isRevoked :=
            send_apply_preservesIsRevoked pe.senderDomainId did pe.capId
              s did d hpre_d hrev dx hsendp
          rw [← hp']; exact hxrev
      · rw [Arena.find?_update_other _ receiver did _ hd2] at hp'
        have hsendp :
            (send_apply s pe.senderDomainId receiver pe.capId).getDom did = some d' := hp'
        exact send_apply_preservesIsRevoked pe.senderDomainId receiver pe.capId
                s did d hpre hrev d' hsendp

private theorem acceptChannel_apply_preservesIsRevoked
    (receiver : DomId) (pendingId : PendingId)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain)
    (hpost : (acceptChannel_apply s receiver pendingId).getDom did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hb : (s.getDom receiver).bind (fun d => d.lookupPendingDom pendingId) with _ | pe
  · have h0 : (acceptChannel_apply s receiver pendingId).domains.find? did = some d' := hpost
    simp [acceptChannel_apply, hb] at h0
    rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
  · have hp' : (acceptChannel_apply s receiver pendingId).domains.find? did = some d' := hpost
    simp only [acceptChannel_apply, hb, SpecState.updDomain] at hp'
    by_cases hd1 : did = pe.senderDomainId
    · subst hd1
      rw [Arena.find?_update_eq_map] at hp'
      by_cases hd2 : pe.senderDomainId = receiver
      · rw [← hd2] at hp'
        rw [Arena.find?_update_eq_map] at hp'
        rcases hsend :
            (sendChannel_apply s pe.senderDomainId pe.senderDomainId pe.capId).domains.find?
              pe.senderDomainId with _ | dx
        · rw [hsend] at hp'; simp at hp'
        · rw [hsend] at hp'; simp at hp'
          have hsendp :
              (sendChannel_apply s pe.senderDomainId pe.senderDomainId pe.capId).getDom
                pe.senderDomainId = some dx := hsend
          have hxrev : dx.isRevoked :=
            sendChannel_apply_preservesIsRevoked pe.senderDomainId pe.senderDomainId pe.capId
              s pe.senderDomainId d hpre_d hrev dx hsendp
          rw [← hp']; exact hxrev
      · rw [Arena.find?_update_other _ receiver pe.senderDomainId _ hd2] at hp'
        rcases hsend :
            (sendChannel_apply s pe.senderDomainId receiver pe.capId).domains.find?
              pe.senderDomainId with _ | dx
        · rw [hsend] at hp'; simp at hp'
        · rw [hsend] at hp'; simp at hp'
          have hsendp :
              (sendChannel_apply s pe.senderDomainId receiver pe.capId).getDom
                pe.senderDomainId = some dx := hsend
          have hxrev : dx.isRevoked :=
            sendChannel_apply_preservesIsRevoked pe.senderDomainId receiver pe.capId
              s pe.senderDomainId d hpre_d hrev dx hsendp
          rw [← hp']; exact hxrev
    · rw [Arena.find?_update_other _ pe.senderDomainId did _ hd1] at hp'
      by_cases hd2 : did = receiver
      · subst hd2
        rw [Arena.find?_update_eq_map] at hp'
        rcases hsend :
            (sendChannel_apply s pe.senderDomainId did pe.capId).domains.find? did with _ | dx
        · rw [hsend] at hp'; simp at hp'
        · rw [hsend] at hp'; simp at hp'
          have hsendp :
              (sendChannel_apply s pe.senderDomainId did pe.capId).getDom did = some dx := hsend
          have hxrev : dx.isRevoked :=
            sendChannel_apply_preservesIsRevoked pe.senderDomainId did pe.capId
              s did d hpre_d hrev dx hsendp
          rw [← hp']; exact hxrev
      · rw [Arena.find?_update_other _ receiver did _ hd2] at hp'
        have hsendp :
            (sendChannel_apply s pe.senderDomainId receiver pe.capId).getDom did = some d' := hp'
        exact sendChannel_apply_preservesIsRevoked pe.senderDomainId receiver pe.capId
                s did d hpre hrev d' hsendp

/-! ### addVp / registerComm -/

private theorem addVp_apply_preservesIsRevoked
    (caller : DomId) (childHandle commHandle : LocalHandle)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain)
    (hpost : (addVp_apply s caller childHandle commHandle).getDom did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hb1 : (s.getDom caller).bind (fun d => d.lookupDomHandle childHandle) with _ | cid
  · have h0 : (addVp_apply s caller childHandle commHandle).domains.find? did = some d' := hpost
    simp [addVp_apply, hb1] at h0
    rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
  · rcases hc : s.getDomCap cid with _ | dc
    · have h0 :
          (addVp_apply s caller childHandle commHandle).domains.find? did = some d' := hpost
      simp [addVp_apply, hb1, hc] at h0
      rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
    · rcases ht : s.getDom dc.targetDom with _ | dt
      · have h0 :
            (addVp_apply s caller childHandle commHandle).domains.find? did = some d' := hpost
        simp [addVp_apply, hb1, hc, ht] at h0
        rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
      · rcases hb2 : (s.getDom caller).bind (fun d => d.lookupMemHandle commHandle) with _ | mid
        · have h0 :
              (addVp_apply s caller childHandle commHandle).domains.find? did = some d' := hpost
          simp [addVp_apply, hb1, hc, ht, hb2] at h0
          rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
        · have hp' :
              (addVp_apply s caller childHandle commHandle).domains.find? did = some d' := hpost
          simp only [addVp_apply, hb1, hc, ht, hb2,
                     SpecState.updMem, SpecState.updDomain] at hp'
          by_cases hdid : did = dc.targetDom
          · subst hdid
            rw [Arena.find?_update_eq_map] at hp'
            rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
          · rw [Arena.find?_update_other _ dc.targetDom did _ hdid] at hp'
            rw [hpre_d] at hp'; injection hp' with eq; rw [← eq]; exact hrev

private theorem registerComm_apply_preservesIsRevoked
    (caller : DomId) (commHandle childHandle : LocalHandle) (vpId : VpId)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain)
    (hpost : (registerComm_apply s caller commHandle childHandle vpId).getDom did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hb1 : (s.getDom caller).bind (fun d => d.lookupDomHandle childHandle) with _ | cid
  · have h0 :
        (registerComm_apply s caller commHandle childHandle vpId).domains.find? did = some d' :=
      hpost
    simp [registerComm_apply, hb1] at h0
    rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
  · rcases hc : s.getDomCap cid with _ | dc
    · have h0 :
          (registerComm_apply s caller commHandle childHandle vpId).domains.find? did = some d' :=
        hpost
      simp [registerComm_apply, hb1, hc] at h0
      rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
    · rcases ht : s.getDom dc.targetDom with _ | dt
      · have h0 :
            (registerComm_apply s caller commHandle childHandle vpId).domains.find? did =
              some d' := hpost
        simp [registerComm_apply, hb1, hc, ht] at h0
        rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
      · rcases hb2 : (s.getDom caller).bind (fun d => d.lookupMemHandle commHandle) with _ | mid
        · have h0 :
              (registerComm_apply s caller commHandle childHandle vpId).domains.find? did =
                some d' := hpost
          simp [registerComm_apply, hb1, hc, ht, hb2] at h0
          rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
        · have hp' :
              (registerComm_apply s caller commHandle childHandle vpId).domains.find? did =
                some d' := hpost
          simp only [registerComm_apply, hb1, hc, ht, hb2,
                     SpecState.updMem, SpecState.updDomain] at hp'
          by_cases hdid : did = dc.targetDom
          · subst hdid
            rw [Arena.find?_update_eq_map] at hp'
            rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
          · rw [Arena.find?_update_other _ dc.targetDom did _ hdid] at hp'
            rw [hpre_d] at hp'; injection hp' with eq; rw [← eq]; exact hrev

/-! ### Read-only operations (S1) — identity apply preserves isRevoked trivially -/

private theorem attestSelf_apply_preservesIsRevoked
    (caller : DomId)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain) (hpost : (attestSelf_apply s caller).getDom did = some d') :
    d'.isRevoked := by
  simp only [attestSelf_apply] at hpost
  rw [hpre] at hpost; injection hpost with e; rw [← e]; exact hrev

private theorem attest_apply_preservesIsRevoked
    (caller : DomId) (handle : LocalHandle)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain) (hpost : (attest_apply s caller handle).getDom did = some d') :
    d'.isRevoked := by
  simp only [attest_apply] at hpost
  rw [hpre] at hpost; injection hpost with e; rw [← e]; exact hrev

private theorem getPolicy_apply_preservesIsRevoked
    (caller : DomId) (handle : LocalHandle) (id : PolicyIdentifier)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain) (hpost : (getPolicy_apply s caller handle id).getDom did = some d') :
    d'.isRevoked := by
  simp only [getPolicy_apply] at hpost
  rw [hpre] at hpost; injection hpost with e; rw [← e]; exact hrev

private theorem getChan_apply_preservesIsRevoked
    (caller : DomId) (handle : LocalHandle)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain) (hpost : (getChan_apply s caller handle).getDom did = some d') :
    d'.isRevoked := by
  simp only [getChan_apply] at hpost
  rw [hpre] at hpost; injection hpost with e; rw [← e]; exact hrev

private theorem getChanSelf_apply_preservesIsRevoked
    (caller : DomId)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain) (hpost : (getChanSelf_apply s caller).getDom did = some d') :
    d'.isRevoked := by
  simp only [getChanSelf_apply] at hpost
  rw [hpre] at hpost; injection hpost with e; rw [← e]; exact hrev

/-! ### Helper: `updVp` preserves status -/

private theorem Domain.updVp_status (d : Domain) (vpId : VpId)
    (f : VProcessor → VProcessor) :
    (d.updVp vpId f).status = d.status := rfl

/-! ### `create` (uses `WellFormed.freshDomCounter`) and `revokeDomain` -/

private theorem create_apply_preservesIsRevoked_of_wf
    (caller : DomId) (policy : DomainPolicy) {s : SpecState}
    (hfresh : FreshDomCounter s)
    {did : DomId} {d : Domain} (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    {d' : Domain} (hpost : (create_apply s caller policy).getDom did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  have hdid_in : did ∈ s.domains.keys := Arena.mem_keys_of_find?_some _ _ _ hpre_d
  have hdid_ne : did ≠ s.nextDomId := by
    intro heq
    have := hfresh did hdid_in
    rw [heq] at this; exact Nat.lt_irrefl _ this
  have hp' : (create_apply s caller policy).domains.find? did = some d' := hpost
  simp only [create_apply, SpecState.freshDom, SpecState.freshDomCap,
             SpecState.updDomain] at hp'
  by_cases hdid : did = caller
  · subst hdid
    rw [Arena.find?_update_eq_map] at hp'
    rw [Arena.find?_insert_other _ s.nextDomId did _ hdid_ne] at hp'
    rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
  · rw [Arena.find?_update_other _ caller did _ hdid] at hp'
    rw [Arena.find?_insert_other _ s.nextDomId did _ hdid_ne] at hp'
    rw [hpre_d] at hp'; injection hp' with eq; rw [← eq]; exact hrev

private theorem revokeDomain_apply_preservesIsRevoked
    (caller : DomId) (handle : LocalHandle)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain) (hpost : (revokeDomain_apply s caller handle).getDom did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hcd : s.getDom caller with _ | dc
  · have h0 : (revokeDomain_apply s caller handle).domains.find? did = some d' := hpost
    simp [revokeDomain_apply, hcd] at h0
    rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
  · rcases hh : dc.lookupDomHandle handle with _ | dcId
    · have h0 : (revokeDomain_apply s caller handle).domains.find? did = some d' := hpost
      simp [revokeDomain_apply, hcd, hh] at h0
      rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
    · rcases hdc : s.getDomCap dcId with _ | domcap
      · have h0 : (revokeDomain_apply s caller handle).domains.find? did = some d' := hpost
        simp [revokeDomain_apply, hcd, hh, hdc] at h0
        rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
      · let target := domcap.targetDom
        have hp' : (revokeDomain_apply s caller handle).domains.find? did = some d' := hpost
        simp only [revokeDomain_apply, hcd, hh, hdc, SpecState.updDomain] at hp'
        by_cases hdid_target : did = target
        · rw [hdid_target] at hp' hpre_d
          by_cases hdc' : target = caller
          · rw [← hdc'] at hp'
            rw [Arena.find?_update_eq_map] at hp'
            rw [Arena.find?_remove_same] at hp'
            simp at hp'
          · rw [Arena.find?_update_other _ caller target _ hdc'] at hp'
            rw [Arena.find?_remove_same] at hp'
            cases hp'
        · by_cases hdc : did = caller
          · subst hdc
            rw [Arena.find?_update_eq_map] at hp'
            rw [Arena.find?_remove_other _ target did hdid_target] at hp'
            rw [hpre_d] at hp'; simp at hp'; rw [← hp']; exact hrev
          · rw [Arena.find?_update_other _ caller did _ hdc] at hp'
            rw [Arena.find?_remove_other _ target did hdid_target] at hp'
            rw [hpre_d] at hp'; injection hp' with eq; rw [← eq]; exact hrev

/-! ### `switchReturn` / `switch` / `switchSuspended` (updVp-based) -/

private theorem switchReturn_apply_preservesIsRevoked
    (caller : DomId) (core : CoreId) (exitReason : Option Nat)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain)
    (hpost : (switchReturn_apply s caller core exitReason).getDom did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hb : (s.getDom caller).bind (fun d => d.vpAndPrevCallerOnCore core) with _ | p
  · have h0 :
        (switchReturn_apply s caller core exitReason).domains.find? did = some d' := hpost
    simp [switchReturn_apply, hb] at h0
    rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
  · obtain ⟨vpId, pctx⟩ := p
    have hp' :
        (switchReturn_apply s caller core exitReason).domains.find? did = some d' := hpost
    simp only [switchReturn_apply, hb, SpecState.updCore, SpecState.updDomain] at hp'
    by_cases hd1 : did = pctx.domainId
    · subst hd1
      rw [Arena.find?_update_eq_map] at hp'
      by_cases hd2 : pctx.domainId = caller
      · rw [← hd2] at hp'
        rw [Arena.find?_update_eq_map] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']
        unfold Domain.isRevoked; rw [Domain.updVp_status, Domain.updVp_status]; exact hrev
      · rw [Arena.find?_update_other _ caller pctx.domainId _ hd2] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']
        unfold Domain.isRevoked; rw [Domain.updVp_status]; exact hrev
    · rw [Arena.find?_update_other _ pctx.domainId did _ hd1] at hp'
      by_cases hd2 : did = caller
      · subst hd2
        rw [Arena.find?_update_eq_map] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']
        unfold Domain.isRevoked; rw [Domain.updVp_status]; exact hrev
      · rw [Arena.find?_update_other _ caller did _ hd2] at hp'
        rw [hpre_d] at hp'; injection hp' with eq; rw [← eq]; exact hrev

private theorem switch_apply_preservesIsRevoked
    (caller : DomId) (toHandle : LocalHandle) (toVpId : VpId) (core : CoreId)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain)
    (hpost : (switch_apply s caller toHandle toVpId core).getDom did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hb1 : (s.getDom caller).bind (fun d => d.lookupDomHandle toHandle) with _ | cid
  · have h0 : (switch_apply s caller toHandle toVpId core).domains.find? did = some d' := hpost
    simp [switch_apply, hb1] at h0
    rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
  · rcases hc : s.getDomCap cid with _ | dc
    · have h0 :
          (switch_apply s caller toHandle toVpId core).domains.find? did = some d' := hpost
      simp [switch_apply, hb1, hc] at h0
      rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
    · rcases hb2 : (s.getDom caller).bind (fun d => d.vpAndOptPrevOnCore core) with _ | p
      · have h0 :
            (switch_apply s caller toHandle toVpId core).domains.find? did = some d' := hpost
        simp [switch_apply, hb1, hc, hb2] at h0
        rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
      · obtain ⟨callerVpId, callerPrev⟩ := p
        have hp' :
            (switch_apply s caller toHandle toVpId core).domains.find? did = some d' := hpost
        simp only [switch_apply, hb1, hc, hb2, SpecState.updCore, SpecState.updDomain] at hp'
        by_cases hd1 : did = caller
        · rw [hd1] at hp' hpre_d
          rw [Arena.find?_update_eq_map] at hp'
          by_cases hd2 : caller = dc.targetDom
          · rw [← hd2] at hp'
            rw [Arena.find?_update_eq_map] at hp'
            rw [hpre_d] at hp'; simp at hp'; rw [← hp']
            unfold Domain.isRevoked; rw [Domain.updVp_status, Domain.updVp_status]; exact hrev
          · rw [Arena.find?_update_other _ dc.targetDom caller _ hd2] at hp'
            rw [hpre_d] at hp'; simp at hp'; rw [← hp']
            unfold Domain.isRevoked; rw [Domain.updVp_status]; exact hrev
        · rw [Arena.find?_update_other _ caller did _ hd1] at hp'
          by_cases hd2 : did = dc.targetDom
          · subst hd2
            rw [Arena.find?_update_eq_map] at hp'
            rw [hpre_d] at hp'; simp at hp'; rw [← hp']
            unfold Domain.isRevoked; rw [Domain.updVp_status]; exact hrev
          · rw [Arena.find?_update_other _ dc.targetDom did _ hd2] at hp'
            rw [hpre_d] at hp'; injection hp' with eq; rw [← eq]; exact hrev

private theorem switchSuspended_apply_preservesIsRevoked
    (caller : DomId) (toHandle : LocalHandle) (toVpId : VpId) (core : CoreId)
    (calleeDom : DomId) (calleeVp : VpId)
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain)
    (hpost : (switchSuspended_apply s caller toHandle toVpId core calleeDom calleeVp).getDom
              did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hb1 : (s.getDom caller).bind (fun d => d.lookupDomHandle toHandle) with _ | cid
  · have h0 :
        (switchSuspended_apply s caller toHandle toVpId core calleeDom calleeVp).domains.find?
          did = some d' := hpost
    simp [switchSuspended_apply, hb1] at h0
    rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
  · rcases hc : s.getDomCap cid with _ | dc
    · have h0 :
          (switchSuspended_apply s caller toHandle toVpId core calleeDom calleeVp).domains.find?
            did = some d' := hpost
      simp [switchSuspended_apply, hb1, hc] at h0
      rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
    · rcases hb2 : (s.getDom caller).bind (fun d => d.vpAndOptPrevOnCore core) with _ | p
      · have h0 :
            (switchSuspended_apply s caller toHandle toVpId core calleeDom calleeVp).domains.find?
              did = some d' := hpost
        simp [switchSuspended_apply, hb1, hc, hb2] at h0
        rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
      · obtain ⟨callerVpId, callerPrev⟩ := p
        have hp' :
            (switchSuspended_apply s caller toHandle toVpId core calleeDom calleeVp).domains.find?
              did = some d' := hpost
        simp only [switchSuspended_apply, hb1, hc, hb2,
                   SpecState.updCore, SpecState.updDomain] at hp'
        by_cases hd1 : did = caller
        · rw [hd1] at hp' hpre_d
          rw [Arena.find?_update_eq_map] at hp'
          by_cases hd2 : caller = calleeDom
          · rw [← hd2] at hp'
            rw [Arena.find?_update_eq_map] at hp'
            by_cases hd3 : caller = dc.targetDom
            · rw [← hd3] at hp'
              rw [Arena.find?_update_eq_map] at hp'
              rw [hpre_d] at hp'; simp at hp'; rw [← hp']
              unfold Domain.isRevoked
              rw [Domain.updVp_status, Domain.updVp_status, Domain.updVp_status]; exact hrev
            · rw [Arena.find?_update_other _ dc.targetDom caller _ hd3] at hp'
              rw [hpre_d] at hp'; simp at hp'; rw [← hp']
              unfold Domain.isRevoked
              rw [Domain.updVp_status, Domain.updVp_status]; exact hrev
          · rw [Arena.find?_update_other _ calleeDom caller _ hd2] at hp'
            by_cases hd3 : caller = dc.targetDom
            · rw [← hd3] at hp'
              rw [Arena.find?_update_eq_map] at hp'
              rw [hpre_d] at hp'; simp at hp'; rw [← hp']
              unfold Domain.isRevoked
              rw [Domain.updVp_status, Domain.updVp_status]; exact hrev
            · rw [Arena.find?_update_other _ dc.targetDom caller _ hd3] at hp'
              rw [hpre_d] at hp'; simp at hp'; rw [← hp']
              unfold Domain.isRevoked; rw [Domain.updVp_status]; exact hrev
        · rw [Arena.find?_update_other _ caller did _ hd1] at hp'
          by_cases hd2 : did = calleeDom
          · subst hd2
            rw [Arena.find?_update_eq_map] at hp'
            by_cases hd3 : did = dc.targetDom
            · subst hd3
              rw [Arena.find?_update_eq_map] at hp'
              rw [hpre_d] at hp'; simp at hp'; rw [← hp']
              unfold Domain.isRevoked
              rw [Domain.updVp_status, Domain.updVp_status]; exact hrev
            · rw [Arena.find?_update_other _ dc.targetDom did _ hd3] at hp'
              rw [hpre_d] at hp'; simp at hp'; rw [← hp']
              unfold Domain.isRevoked; rw [Domain.updVp_status]; exact hrev
          · rw [Arena.find?_update_other _ calleeDom did _ hd2] at hp'
            by_cases hd3 : did = dc.targetDom
            · subst hd3
              rw [Arena.find?_update_eq_map] at hp'
              rw [hpre_d] at hp'; simp at hp'; rw [← hp']
              unfold Domain.isRevoked; rw [Domain.updVp_status]; exact hrev
            · rw [Arena.find?_update_other _ dc.targetDom did _ hd3] at hp'
              rw [hpre_d] at hp'; injection hp' with eq; rw [← eq]; exact hrev

/-! ### IsRevokedStable predicate (analogue of `ParentStable`) -/

/-- A state-transformer preserves `isRevoked`: a tombstoned domain stays
    tombstoned. -/
def PreservesIsRevoked (g : SpecState → SpecState) : Prop :=
  ∀ s did d d',
    s.getDom did = some d → d.isRevoked →
    (g s).getDom did = some d' → d'.isRevoked

theorem PreservesIsRevoked.id : PreservesIsRevoked (fun s => s) := by
  intro s did d d' hpre hrev hpost
  rw [hpre] at hpost; injection hpost with eq; rw [← eq]; exact hrev

theorem PreservesIsRevoked.comp_no_remove
    {g h : SpecState → SpecState}
    (hgnr : NeverRemovesDomain g)
    (hg : PreservesIsRevoked g) (hh : PreservesIsRevoked h) :
    PreservesIsRevoked (fun s => h (g s)) := by
  intro s did d d' hpre hrev hpost
  have hmid : ((g s).getDom did).isSome := hgnr s did (by rw [hpre]; rfl)
  rcases hmidcases : (g s).getDom did with _ | dmid
  · rw [hmidcases] at hmid; cases hmid
  · have e1 : dmid.isRevoked := hg s did d dmid hpre hrev hmidcases
    exact hh (g s) did dmid d' hmidcases e1 hpost

/-- Closed under composition combo: preserves `isRevoked` *and* never
    removes a domain. -/
structure IsRevokedStable (g : SpecState → SpecState) : Prop where
  preserves    : PreservesIsRevoked g
  neverRemoves : NeverRemovesDomain g

theorem IsRevokedStable.id : IsRevokedStable (fun s => s) :=
  ⟨PreservesIsRevoked.id, NeverRemovesDomain.id⟩

theorem IsRevokedStable.comp {g h : SpecState → SpecState}
    (hg : IsRevokedStable g) (hh : IsRevokedStable h) :
    IsRevokedStable (fun s => h (g s)) :=
  ⟨PreservesIsRevoked.comp_no_remove hg.neverRemoves hg.preserves hh.preserves,
   fun s did hh' => hh.neverRemoves _ _ (hg.neverRemoves _ _ hh')⟩

/-- `updDomain` is `IsRevokedStable` whenever `f` preserves `isRevoked`
    pointwise. -/
theorem updDomain_isRevokedStable (target : DomId) (f : Domain → Domain)
    (hf : ∀ d, d.isRevoked → (f d).isRevoked) :
    IsRevokedStable (fun s => s.updDomain target f) := by
  refine ⟨?_, updDomain_neverRemoves target f⟩
  intro s did d d' hpre hrev hpost
  exact updDomain_preserves_isRevoked s target f hf did d d' hpre hrev hpost

theorem updCore_isRevokedStable (id : CoreId) (f : CoreState → CoreState) :
    IsRevokedStable (fun s => s.updCore id f) := by
  refine ⟨?_, updCore_neverRemoves id f⟩
  intro s did d d' hpre hrev hpost
  have h0 : (s.updCore id f).getDom did = some d' := hpost
  rw [updCore_getDom] at h0
  rw [hpre] at h0; injection h0 with eq; rw [← eq]; exact hrev

/-- `applyMidsAndHandler` is `IsRevokedStable` for any chain. -/
theorem applyMidsAndHandler_isRevokedStable (core : CoreId) (vector : Nat) :
    ∀ (chain : List (DomId × VpId)) (prev : DomId × VpId),
      IsRevokedStable (fun s => applyMidsAndHandler core vector prev chain s) := by
  intro chain
  induction chain with
  | nil =>
    intro prev
    refine ⟨?_, ?_⟩
    · intro s did d d' hpre hrev hpost
      simp [applyMidsAndHandler] at hpost
      rw [hpre] at hpost; injection hpost with eq; rw [← eq]; exact hrev
    · intro s did h
      simp [applyMidsAndHandler]; exact h
  | cons head tail ih =>
    intro prev
    cases tail with
    | nil =>
      have base :
          IsRevokedStable (fun s => s.updDomain head.1
            (fun d => d.updVp head.2 (fun vp =>
              match vp.runState with
              | .locked _ _ p => { vp with runState := .running core p }
              | other         => { vp with runState := other }))) := by
        apply updDomain_isRevokedStable
        intro d hr
        unfold Domain.isRevoked at *
        rw [Domain.updVp_status]; exact hr
      refine ⟨?_, ?_⟩
      · intro s did d d' hpre hrev hpost
        simp only [applyMidsAndHandler] at hpost
        exact base.preserves s did d d' hpre hrev hpost
      · intro s did h
        simp only [applyMidsAndHandler]
        exact base.neverRemoves s did h
    | cons head' tail' =>
      have base :
          IsRevokedStable (fun s => s.updDomain head.1
            (fun d => d.updVp head.2 (fun vp =>
              { vp with runState := .suspended prev.1 prev.2 vector }))) := by
        apply updDomain_isRevokedStable
        intro d hr
        unfold Domain.isRevoked at *
        rw [Domain.updVp_status]; exact hr
      have rec_step :
          IsRevokedStable (fun s =>
            applyMidsAndHandler core vector head (head' :: tail') s) :=
        ih head
      have combined : IsRevokedStable (fun s =>
          applyMidsAndHandler core vector head (head' :: tail')
            (s.updDomain head.1
              (fun d => d.updVp head.2 (fun vp =>
                { vp with runState := .suspended prev.1 prev.2 vector })))) :=
        IsRevokedStable.comp base rec_step
      refine ⟨?_, ?_⟩
      · intro s did d d' hpre hrev hpost
        simp only [applyMidsAndHandler] at hpost
        exact combined.preserves s did d d' hpre hrev hpost
      · intro s did h
        simp only [applyMidsAndHandler]
        exact combined.neverRemoves s did h

/-- `deliverInterrupt_apply` preserves `isRevoked`. -/
private theorem deliverInterrupt_apply_preservesIsRevoked
    (interrupted handler : DomId) (core : CoreId) (vector : Nat)
    (chain : List (DomId × VpId))
    (s : SpecState) (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain)
    (hpost : (deliverInterrupt_apply s interrupted handler core vector chain).getDom
              did = some d') :
    d'.isRevoked := by
  have hpre_d : s.domains.find? did = some d := hpre
  cases chain with
  | nil =>
    have h0 :
        (deliverInterrupt_apply s interrupted handler core vector []).domains.find?
          did = some d' := hpost
    simp [deliverInterrupt_apply] at h0
    rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
  | cons head tail =>
    cases tail with
    | nil =>
      have h0 :
          (deliverInterrupt_apply s interrupted handler core vector [head]).domains.find?
            did = some d' := hpost
      simp [deliverInterrupt_apply] at h0
      rw [hpre_d] at h0; injection h0 with eq; rw [← eq]; exact hrev
    | cons head' tail' =>
      let leaf := head
      have leafStable :
          IsRevokedStable (fun s => s.updDomain leaf.1
            (fun d => d.updVp leaf.2 (fun vp =>
              { vp with runState := .interrupted vector }))) := by
        apply updDomain_isRevokedStable
        intro d hr
        unfold Domain.isRevoked at *
        rw [Domain.updVp_status]; exact hr
      have midsStable :
          IsRevokedStable (fun s =>
            applyMidsAndHandler core vector leaf (head' :: tail') s) :=
        applyMidsAndHandler_isRevokedStable core vector (head' :: tail') leaf
      have body : IsRevokedStable (fun s =>
          applyMidsAndHandler core vector leaf (head' :: tail')
            (s.updDomain leaf.1
              (fun d => d.updVp leaf.2 (fun vp =>
                { vp with runState := .interrupted vector })))) :=
        IsRevokedStable.comp leafStable midsStable
      have hp' :
          (deliverInterrupt_apply s interrupted handler core vector
            (leaf :: head' :: tail')).domains.find? did = some d' := hpost
      simp only [deliverInterrupt_apply] at hp'
      rcases hgl : (leaf :: head' :: tail' : List (DomId × VpId)).getLast? with _ | hpair
      · rw [hgl] at hp'
        exact body.preserves s did d d' hpre hrev hp'
      · obtain ⟨hDom, hVp⟩ := hpair
        rw [hgl] at hp'
        have core_layer : IsRevokedStable (fun s => s.updCore core (fun _ =>
            CoreState.runningDomain hDom hVp)) :=
          updCore_isRevokedStable _ _
        have full : IsRevokedStable (fun s =>
            (applyMidsAndHandler core vector leaf (head' :: tail')
              (s.updDomain leaf.1
                (fun d => d.updVp leaf.2 (fun vp =>
                  { vp with runState := .interrupted vector })))).updCore core
                    (fun _ => CoreState.runningDomain hDom hVp)) :=
          IsRevokedStable.comp body core_layer
        exact full.preserves s did d d' hpre hrev hp'

theorem step_preserves_revoked
    {s s' : SpecState} {a : Action} (hwf : WellFormed s) (h : step s a s')
    (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain) (hpost : s'.getDom did = some d') :
    d'.isRevoked := by
  cases h with
  | carve _ =>
      exact carve_apply_preservesIsRevoked _ _ _ _ s did d hpre hrev d' hpost
  | alias _ =>
      exact alias_apply_preservesIsRevoked _ _ _ s did d hpre hrev d' hpost
  | revoke _ =>
      exact revoke_apply_preservesIsRevoked _ _ s did d hpre hrev d' hpost
  | send _ =>
      exact send_apply_preservesIsRevoked _ _ _ s did d hpre hrev d' hpost
  | «seal» guard =>
      exact seal_apply_preservesIsRevoked _ _ s guard did d hpre hrev d' hpost
  | accept _ =>
      exact accept_apply_preservesIsRevoked' _ _ s did d hpre hrev d' hpost
  | reject _ =>
      exact reject_apply_preservesIsRevoked _ _ s did d hpre hrev d' hpost
  | sealedSend _ =>
      exact sealedSend_apply_preservesIsRevoked _ _ _ _ s did d hpre hrev d' hpost
  | create _ =>
      exact create_apply_preservesIsRevoked_of_wf _ _ hwf.freshDomCounter hpre hrev hpost
  | revokeDomain _ =>
      exact revokeDomain_apply_preservesIsRevoked _ _ s did d hpre hrev d' hpost
  | setPolicy _ =>
      exact setPolicy_apply_preservesIsRevoked _ _ _ _ s did d hpre hrev d' hpost
  | sendChannel _ =>
      exact sendChannel_apply_preservesIsRevoked _ _ _ s did d hpre hrev d' hpost
  | acceptChannel _ =>
      exact acceptChannel_apply_preservesIsRevoked _ _ s did d hpre hrev d' hpost
  | rejectChannel _ =>
      exact rejectChannel_apply_preservesIsRevoked _ _ s did d hpre hrev d' hpost
  | switchReturn _ =>
      exact switchReturn_apply_preservesIsRevoked _ _ _ s did d hpre hrev d' hpost
  | switch _ =>
      exact switch_apply_preservesIsRevoked _ _ _ _ s did d hpre hrev d' hpost
  | switchSuspended _ =>
      exact switchSuspended_apply_preservesIsRevoked _ _ _ _ _ _ s did d hpre hrev d' hpost
  | deliverInterrupt _ =>
      exact deliverInterrupt_apply_preservesIsRevoked _ _ _ _ _ s did d hpre hrev d' hpost
  | addVp _ =>
      exact addVp_apply_preservesIsRevoked _ _ _ s did d hpre hrev d' hpost
  | registerComm _ =>
      exact registerComm_apply_preservesIsRevoked _ _ _ _ s did d hpre hrev d' hpost
  | mapSelf _ =>
      exact mapSelf_apply_preservesIsRevoked _ _ _ s did d hpre hrev d' hpost
  | attestSelf _ =>
      exact attestSelf_apply_preservesIsRevoked _ s did d hpre hrev d' hpost
  | attest _ =>
      exact attest_apply_preservesIsRevoked _ _ s did d hpre hrev d' hpost
  | getPolicy _ =>
      exact getPolicy_apply_preservesIsRevoked _ _ _ s did d hpre hrev d' hpost
  | getChan _ =>
      exact getChan_apply_preservesIsRevoked _ _ s did d hpre hrev d' hpost
  | getChanSelf _ =>
      exact getChanSelf_apply_preservesIsRevoked _ s did d hpre hrev d' hpost

/-! ### T4: parent immutable across the cascade (corollary) -/

/-- Direct corollary of `step_parent_immutable`: even when a step
    flips a domain into `.revoked` via the VITAL cascade, the domain's
    parent pointer is unchanged. Useful for downstream subtree-stability
    proofs that need to reason across cascade events. -/
theorem step_revoked_implies_parent_immutable
    {s s' : SpecState} {a : Action} (hwf : WellFormed s) (h : step s a s')
    {did : DomId} {d d' : Domain}
    (hpre  : s.getDom did = some d)
    (hpost : s'.getDom did = some d') :
    d'.parent = d.parent :=
  step_parent_immutable hwf h hpre hpost

end ThemisCapa
