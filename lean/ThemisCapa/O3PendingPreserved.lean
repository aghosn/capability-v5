/-
  ThemisCapa.O3PendingPreserved — Pending-entry preservation across
  third-party steps.

  ## Goal

  Between `sealedSend(c, r, h, g)` and the matching `accept(r, pid)`,
  the pending entry deposited at receiver `r` is unchanged across any
  intervening step whose footprint avoids `r`.

  This is the missing "frame" needed to upgrade the single-step IPC
  integrity theorem (`ipc_sealedSend_accept_transfers_cap`,
  O3IpcIsolation.lean) into a multi-step claim: the cap is delivered
  intact even when arbitrary unrelated activity happens in the meantime.

  ## Structure

  * `step_pending_preserved` — single-step version: if `r`'s record
    holds `(pid, pe)` and a step with `¬ affectsDom r` happens, then
    `r`'s record in the post-state still holds `(pid, pe)`.
  * `steps_pending_preserved` — list-of-steps version: if a trace
    `s₀ →ₐ₀ s₁ →ₐ₁ ⋯ →ₐₙ sₙ` never affects `r` along the way, the
    pending entry is preserved end-to-end.

  ## Proof

  Trivial corollary of `step_locality_dom`: the receiver's domain
  record is byte-identical, so `lookupPending` returns the same
  payload.
-/

import ThemisCapa.Locality

namespace ThemisCapa

open Action

-- ════════════════════════════════════════════════════════════════════
-- § 1.  Single-step pending preservation
-- ════════════════════════════════════════════════════════════════════

/-- A pending-mem entry visible at receiver `r` in `s` survives any
    step whose `affectsDom` footprint avoids `r`. The post-state
    receiver record is identical (in fact, the entire `getDom r`
    projection is preserved by `step_locality_dom`), so
    `lookupPending` returns the same payload. -/
theorem step_pending_preserved
    {s s' : SpecState} {a : Action} (hstep : step s a s')
    {r : DomId} (hr : ¬ a.affectsDom s r)
    {d : Domain} (hd : s.getDom r = some d)
    {pid : PendingId} {pe : PendingMemCap}
    (hpe : d.lookupPending pid = some pe) :
    ∃ d', s'.getDom r = some d' ∧ d'.lookupPending pid = some pe := by
  have hframe : s'.getDom r = s.getDom r := step_locality_dom hstep hr
  refine ⟨d, ?_, hpe⟩
  rw [hframe]; exact hd

/-- Channel-pending analog: a pending-domcap entry at receiver `r` is
    preserved across any step whose footprint avoids `r`. -/
theorem step_pending_dom_preserved
    {s s' : SpecState} {a : Action} (hstep : step s a s')
    {r : DomId} (hr : ¬ a.affectsDom s r)
    {d : Domain} (hd : s.getDom r = some d)
    {pid : PendingId} {pe : PendingDomCap}
    (hpe : d.lookupPendingDom pid = some pe) :
    ∃ d', s'.getDom r = some d' ∧ d'.lookupPendingDom pid = some pe := by
  have hframe : s'.getDom r = s.getDom r := step_locality_dom hstep hr
  refine ⟨d, ?_, hpe⟩
  rw [hframe]; exact hd

-- ════════════════════════════════════════════════════════════════════
-- § 2.  Multi-step traces
-- ════════════════════════════════════════════════════════════════════

/-- Reflexive-transitive closure of `step`: a sequence of zero or more
    steps. Indexed by an explicit list of actions so callers can
    reason about the trace. -/
inductive steps : SpecState → List Action → SpecState → Prop
  | refl  : ∀ s, steps s [] s
  | cons  : ∀ {s s' s'' a as}, step s a s' → steps s' as s'' →
            steps s (a :: as) s''

/-- A trace `s →* s'` along `as` *avoids* domain `r` if no action in
    the trace affects `r` at the state where it is fired. Defined as
    an inductive `Prop` to support pattern-matching elimination. -/
inductive stepsAvoid (r : DomId) :
    ∀ {s : SpecState} {as : List Action} {s' : SpecState},
      steps s as s' → Prop
  | refl : ∀ {s}, stepsAvoid r (steps.refl s)
  | cons : ∀ {s s' s'' a as} {hstep : step s a s'}
             {rest : steps s' as s''},
           ¬ a.affectsDom s r →
           stepsAvoid r rest →
           stepsAvoid r (steps.cons hstep rest)

/-- Multi-step pending-mem preservation: a pending entry visible at
    receiver `r` in `s` is still visible (with identical payload) at
    `r` in any post-state reachable by a trace that avoids `r`. -/
theorem steps_pending_preserved
    {r : DomId} {s s' : SpecState} {as : List Action}
    {htrace : steps s as s'} (havoid : stepsAvoid r htrace)
    {d : Domain} (hd : s.getDom r = some d)
    {pid : PendingId} {pe : PendingMemCap}
    (hpe : d.lookupPending pid = some pe) :
    ∃ d', s'.getDom r = some d' ∧ d'.lookupPending pid = some pe := by
  induction havoid generalizing d with
  | @refl _ => exact ⟨d, hd, hpe⟩
  | @cons _ _ _ _ _ hstep rest hr _ ih =>
    obtain ⟨d', hd', hpe'⟩ := step_pending_preserved hstep hr hd hpe
    exact ih hd' hpe'

/-- Multi-step pending-domcap preservation. -/
theorem steps_pending_dom_preserved
    {r : DomId} {s s' : SpecState} {as : List Action}
    {htrace : steps s as s'} (havoid : stepsAvoid r htrace)
    {d : Domain} (hd : s.getDom r = some d)
    {pid : PendingId} {pe : PendingDomCap}
    (hpe : d.lookupPendingDom pid = some pe) :
    ∃ d', s'.getDom r = some d' ∧ d'.lookupPendingDom pid = some pe := by
  induction havoid generalizing d with
  | @refl _ => exact ⟨d, hd, hpe⟩
  | @cons _ _ _ _ _ hstep rest hr _ ih =>
    obtain ⟨d', hd', hpe'⟩ := step_pending_dom_preserved hstep hr hd hpe
    exact ih hd' hpe'

end ThemisCapa
