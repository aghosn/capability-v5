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

/-- Helper: an `updDomain f` whose update function `f` does not write to
    `.status` preserves `isRevoked` for any pre-revoked domain. -/
private theorem updDomain_preserves_status
    (s : SpecState) (id : DomId) (f : Domain → Domain)
    (hf : ∀ x, (f x).status = x.status)
    (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (d' : Domain) (hpost : (s.updDomain id f).getDom did = some d') :
    d.status = d'.status := by
  show d.status = d'.status
  by_cases hdid : did = id
  · subst hdid
    have h := hpost
    show d.status = d'.status
    have : (s.updDomain did f).domains.find? did = some d' := h
    simp only [SpecState.updDomain] at this
    rw [Arena.find?_update_eq_map] at this
    have hpre' : s.domains.find? did = some d := hpre
    rw [hpre'] at this; simp at this
    rw [← this]; exact (hf d).symm
  · have h := hpost
    have : (s.updDomain id f).domains.find? did = some d' := h
    simp only [SpecState.updDomain] at this
    rw [Arena.find?_update_other _ id did _ hdid] at this
    have hpre' : s.domains.find? did = some d := hpre
    rw [hpre'] at this; injection this with heq; rw [heq]

/-- Tombstones persist: once `d.isRevoked`, no `step` can transition it
    back to `.sealed` or `.unsealed`.

    The proof relies on the invariant that all status-touching actions
    in `step` are guarded:
      * `seal_apply` requires `targetUnsealed` (rules out revoked).
      * `revoke_apply`'s VITAL cascade only sets status to `.revoked`
        (idempotent on tombstones).
      * `revokeDomain_apply` removes the domain from the arena, so the
        post-state lookup fails — the precondition `s'.getDom did =
        some d'` is impossible.
      * Every other action either does not touch `.status`, or only
        touches it for a domain other than `did`.

    Status: scaffolded with `sorry` for the per-action case sweep
    (mechanical but ~150 lines). The two non-trivial cases — seal
    inversion and the revoke cascade idempotence — are handled by
    `revoke_apply_vital_owner_revoked` (T2) and the SealGuard's
    `targetUnsealed` clause; the 19 remaining cases are uniform
    applications of `updDomain_preserves_status`. -/
theorem step_preserves_revoked
    {s s' : SpecState} {a : Action} (h : step s a s')
    (did : DomId) (d : Domain) (hpre : s.getDom did = some d)
    (hrev : d.isRevoked)
    (d' : Domain) (hpost : s'.getDom did = some d') :
    d'.isRevoked := by
  -- See module docstring for full proof outline.
  -- TODO(G1-followup): mechanical per-action sweep across 21
  -- constructors of `step`. Each non-sealing, non-revoking case is a
  -- one-line application of `updDomain_preserves_status`; the sealing
  -- case is discharged by `SealGuard.targetUnsealed`; the cascade case
  -- is discharged by idempotence (revoked → revoked under cascade);
  -- `revokeDomain` is vacuous (`s'.getDom did = none` when `did =
  -- target`).
  sorry

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
