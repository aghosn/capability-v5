/-
  ThemisCapa.HandlerCoverage — interrupt routing coverage invariant.

  ## Statement

  Every (live domain, vector) pair has a live `Deliver` handler somewhere
  in its ancestor-or-self chain.

  Mirrors the Rust engine's `route_interrupt` (capa-engine/src/switch.rs):
  the chain walks up from the interrupted (live) domain, skipping
  `NotReport` domains and notifying `Report` domains, until it finds a
  `Deliver` domain. If it walks to root without finding one, the engine
  returns `"No interrupt handler found"` — an error case we forbid by
  invariant.

  Revoked tombstones are excluded from both the source and the witness:
  the engine never routes an interrupt to a tombstone, and the cascade
  invariants (T1/T2) guarantee that a live domain's relevant ancestor
  chain remains live (a revoked ancestor would have cascaded to its
  descendants when its `vital` capability was revoked).

  ## Forced consequence

  Parentless live domains must have visibility = `Deliver` for every
  vector. If a parentless live domain had `Report` or `NotReport`, the
  chain would dead-end without a handler, violating the invariant.

  ## Hierarchy

  Combined with `PolicyMonotonicAncestry` (cores axis) and `CoreAffinity`,
  this yields the high-level theorem:

    HandlerCoreAffinity:
      A domain `d` running on core `c` has a handler `a`
      (HandlerCoverage) whose policy permits `c` (PolicyMonotonicAncestry +
      CoreAffinity transitively give `c ∈ a.policy.cores`).

  Top theorem:
    `step_preservesHandlerCoverage` — preservation across all 21 actions.
-/
import ThemisCapa.Policy
import ThemisCapa.DomainTree

namespace ThemisCapa

/-- Visibility of vector `v` for domain `d` (wrapper around
    `DomainPolicy.visibilityFor`). -/
def Domain.visibilityFor (d : Domain) (vec : Nat) : InterruptVisibility :=
  d.policy.visibilityFor vec

-- ════════════════════════════════════════════════════════════════════
-- § Invariant statement
-- ════════════════════════════════════════════════════════════════════

/-- Every (live domain, vector) pair has a live ancestor-or-self whose
    visibility for that vector is `Deliver`. -/
def HandlerCoverage (s : SpecState) : Prop :=
  ∀ did d, s.getDom did = some d → d.isLive →
  ∀ vec, ∃ aid a,
    IsAncestorOrSelf s aid did ∧
    s.getDom aid = some a ∧
    a.isLive ∧
    a.visibilityFor vec = .deliver

end ThemisCapa
