/-
  ThemisCapa.Policy — refinement order on `DomainPolicy`.

  Defines `instance : LE DomainPolicy` as a per-field conjunction:
  cores ⊆, api ≤, numVps ≤, plus stubs for interrupts/exits/cpuid/msrs
  (always-refines, to be tightened later).

  Used by `PolicyMonotonicAncestry` invariant: every child domain's
  policy refines its parent's. Subsumes per-field axes:
  `CoreMonotonicAncestry`, `ApiMonotonicAncestry`, `NumVpsMonotonicAncestry`,
  derivable as one-line corollaries.
-/
import ThemisCapa.Domain

namespace ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § Per-component refinement (stubs for fields whose semantics is
--   not yet fully fleshed out — tighten as theorems demand it).
-- ════════════════════════════════════════════════════════════════════

instance : LE InterruptPolicy where
  le _ _ := True

instance : LE ExitPolicy where
  le _ _ := True

instance : LE ProcFeatureConfig where
  le _ _ := True

-- ════════════════════════════════════════════════════════════════════
-- § Refinement on `DomainPolicy`
-- ════════════════════════════════════════════════════════════════════

/-- Refinement order on `DomainPolicy`: a child refines its parent
    when every component is no stronger than the parent's. -/
def DomainPolicy.refines (child parent : DomainPolicy) : Prop :=
  child.cores      ⊆ parent.cores      ∧
  child.api        ≤ parent.api        ∧
  child.interrupts ≤ parent.interrupts ∧
  child.exits      ≤ parent.exits      ∧
  child.cpuid      ≤ parent.cpuid      ∧
  child.msrs       ≤ parent.msrs       ∧
  child.numVps     ≤ parent.numVps

instance : LE DomainPolicy where le := DomainPolicy.refines

namespace DomainPolicy

@[simp] theorem le_def (a b : DomainPolicy) :
    (a ≤ b) ↔
      a.cores      ⊆ b.cores      ∧
      a.api        ≤ b.api        ∧
      a.interrupts ≤ b.interrupts ∧
      a.exits      ≤ b.exits      ∧
      a.cpuid      ≤ b.cpuid      ∧
      a.msrs       ≤ b.msrs       ∧
      a.numVps     ≤ b.numVps :=
  Iff.rfl

theorem refl (p : DomainPolicy) : p ≤ p := by
  refine ⟨?_, ?_, trivial, trivial, trivial, trivial, Nat.le_refl _⟩
  · intro c hc; exact hc
  · refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> exact id

theorem cores_le_of_le {a b : DomainPolicy} (h : a ≤ b) : a.cores ⊆ b.cores :=
  h.1

theorem api_le_of_le {a b : DomainPolicy} (h : a ≤ b) : a.api ≤ b.api :=
  h.2.1

theorem numVps_le_of_le {a b : DomainPolicy} (h : a ≤ b) : a.numVps ≤ b.numVps :=
  h.2.2.2.2.2.2

end DomainPolicy

end ThemisCapa
