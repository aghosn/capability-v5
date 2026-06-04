/-
  ThemisCapa.HandlerCoverage — interrupt routing coverage invariant.

  ## Statement

  Every (domain, vector) pair has a `Deliver` handler somewhere in its
  ancestor chain (possibly the domain itself).

  Mirrors the Rust engine's `route_interrupt` (capa-engine/src/switch.rs):
  the chain walks up from the interrupted domain, skipping `NotReport`
  domains and notifying `Report` domains, until it finds a `Deliver`
  domain. If it walks to root without finding one, the engine returns
  `"No interrupt handler found"` — an error case we forbid by invariant.

  ## Forced consequence

  Roots (domains with `parent = none`) must have visibility = `Deliver`
  for every vector. If a root had `Report` or `NotReport`, the chain
  would dead-end without a handler, violating the invariant.

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
import ThemisCapa.Invariants

namespace ThemisCapa

/-- Visibility of vector `v` for domain `d` (wrapper around
    `DomainPolicy.visibilityFor`). -/
def Domain.visibilityFor (d : Domain) (vec : Nat) : InterruptVisibility :=
  d.policy.visibilityFor vec

-- ════════════════════════════════════════════════════════════════════
-- § Invariant statement
-- ════════════════════════════════════════════════════════════════════

/-- Every (domain, vector) pair has a `Deliver` handler in its
    ancestor-or-self chain. -/
def HandlerCoverage (s : SpecState) : Prop :=
  ∀ did d, s.getDom did = some d →
  ∀ vec, ∃ aid a,
    IsAncestorOrSelf s aid did ∧
    s.getDom aid = some a ∧
    a.visibilityFor vec = .deliver

end ThemisCapa
