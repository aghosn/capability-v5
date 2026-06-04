/-
  ThemisCapa.Policy — refinement order on `DomainPolicy`.

  Defines `instance : LE DomainPolicy` as a per-field conjunction
  capturing capability monotonicity: `child ≤ parent` means every
  axis of the child's policy is no more permissive than the parent's.

  Per-axis orderings:

    cores      : ⊆                                    (CoreMask subset)
    api        : ≤                                    (MonitorAPI subset)
    numVps     : ≤                                    (Nat le)
    interrupts : pointwise per vector
                 (visibility chain: notReport ≤ report ≤ deliver;
                  read/write sets dropped — enforced at access time
                  by a separate theorem on suspended-child get/set_reg).
    exits      : pointwise per exit reason
                 (trap-only: parent.trap → child.trap;
                  read/write sets dropped — same access-time rationale).
    cpuid/msrs : pointwise per (leaf, sub, wordIdx)
                 (action distinction: native vs not-native;
                  child = native → parent = native).

  Used by `PolicyMonotonicAncestry`: every (child, parent) edge in
  the domain tree satisfies child.policy ≤ parent.policy. Each axis
  has a one-line corollary derived from this umbrella.
-/
import ThemisCapa.Domain

namespace ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § InterruptVisibility — chain `notReport ≤ report ≤ deliver`
-- ════════════════════════════════════════════════════════════════════

namespace InterruptVisibility

def rank : InterruptVisibility → Nat
  | .notReport => 0
  | .report    => 1
  | .deliver   => 2

end InterruptVisibility

instance : LE InterruptVisibility where
  le a b := a.rank ≤ b.rank

theorem InterruptVisibility.le_refl (v : InterruptVisibility) : v ≤ v :=
  Nat.le_refl _

-- ════════════════════════════════════════════════════════════════════
-- § VectorPolicy — visibility-only refinement
--   readSet/writeSet are NOT in the refinement; they are obligations
--   the parent must respect at set_reg/get_reg time on a suspended
--   child, proved as a separate theorem (TODO).
-- ════════════════════════════════════════════════════════════════════

def VectorPolicy.refines (c p : VectorPolicy) : Prop :=
  c.visibility ≤ p.visibility

instance : LE VectorPolicy where le := VectorPolicy.refines

theorem VectorPolicy.le_refl (v : VectorPolicy) : v ≤ v :=
  InterruptVisibility.le_refl _

-- ════════════════════════════════════════════════════════════════════
-- § InterruptPolicy — pointwise per vector via lookup
-- ════════════════════════════════════════════════════════════════════

def InterruptPolicy.lookup (ip : InterruptPolicy) (vec : Nat) : VectorPolicy :=
  match ip.overrides.find? (fun p => p.1 == vec) with
  | some (_, vp) => vp
  | none         => ip.default

def InterruptPolicy.refines (c p : InterruptPolicy) : Prop :=
  ∀ vec, c.lookup vec ≤ p.lookup vec

instance : LE InterruptPolicy where le := InterruptPolicy.refines

theorem InterruptPolicy.le_refl (ip : InterruptPolicy) : ip ≤ ip :=
  fun _ => VectorPolicy.le_refl _

-- ════════════════════════════════════════════════════════════════════
-- § ExitAction — trap-only refinement
--   `trap = false` (handle locally) is the high-rights state;
--   `trap = true` (forward to parent) is the low-rights state.
--   So child ≤ parent iff: parent.trap → child.trap.
--   readSet/writeSet are NOT in the refinement (enforced at access time).
-- ════════════════════════════════════════════════════════════════════

def ExitAction.refines (c p : ExitAction) : Prop :=
  p.trap = true → c.trap = true

instance : LE ExitAction where le := ExitAction.refines

theorem ExitAction.le_refl (a : ExitAction) : a ≤ a := fun h => h

-- ════════════════════════════════════════════════════════════════════
-- § ExitPolicy — pointwise per exit reason via lookup
-- ════════════════════════════════════════════════════════════════════

def ExitPolicy.lookup (ep : ExitPolicy) (reason : Nat) : ExitAction :=
  match ep.overrides.find? (fun p => p.1 == reason) with
  | some (_, ea) => ea
  | none         => ep.default

def ExitPolicy.refines (c p : ExitPolicy) : Prop :=
  ∀ reason, c.lookup reason ≤ p.lookup reason

instance : LE ExitPolicy where le := ExitPolicy.refines

theorem ExitPolicy.le_refl (ep : ExitPolicy) : ep ≤ ep :=
  fun _ => ExitAction.le_refl _

-- ════════════════════════════════════════════════════════════════════
-- § ProcFeatureAction — unified codomain for cpuid/msrs lookup
--   Capability distinction: native vs not-native.
--   `child = native → parent = native` (child cannot have more
--   hardware exposure than the parent granted).
--   `trap` and `emulate v` are freely interchangeable below `native`;
--   emulate values do NOT need to match (they are a local policy
--   choice, not a capability granule).
-- ════════════════════════════════════════════════════════════════════

inductive ProcFeatureAction where
  | trap
  | native
  | emulate (value : Nat)
deriving DecidableEq, Repr

def ProcFeatureAction.refines (c p : ProcFeatureAction) : Prop :=
  c = .native → p = .native

instance : LE ProcFeatureAction where le := ProcFeatureAction.refines

theorem ProcFeatureAction.le_refl (a : ProcFeatureAction) : a ≤ a := fun h => h

-- DefaultAction injects into ProcFeatureAction (no `emulate` at default).
def DefaultAction.toAction : DefaultAction → ProcFeatureAction
  | .trap   => .trap
  | .native => .native

-- ════════════════════════════════════════════════════════════════════
-- § ProcFeatureConfig — pointwise per (leaf, sub, wordIdx) via lookup
--   Lookup walks `overrides` in order, returning the first matching
--   entry's action; falls back to `default.toAction` if no override.
-- ════════════════════════════════════════════════════════════════════

def ProcFeatureEntry.matchAt
    (e : ProcFeatureEntry) (leaf sub wordIdx : Nat) :
    Option ProcFeatureAction :=
  match e with
  | .trap sL sS eL eS =>
      if sL ≤ leaf ∧ leaf ≤ eL ∧ sS ≤ sub ∧ sub ≤ eS
        then some .trap else none
  | .native sL sS eL eS =>
      if sL ≤ leaf ∧ leaf ≤ eL ∧ sS ≤ sub ∧ sub ≤ eS
        then some .native else none
  | .emulate l s w v =>
      if l = leaf ∧ s = sub ∧ w = wordIdx
        then some (.emulate v) else none

def ProcFeatureConfig.lookup
    (cfg : ProcFeatureConfig) (leaf sub wordIdx : Nat) : ProcFeatureAction :=
  match cfg.overrides.findSome? (fun e => e.matchAt leaf sub wordIdx) with
  | some a => a
  | none   => cfg.default.toAction

def ProcFeatureConfig.refines (c p : ProcFeatureConfig) : Prop :=
  ∀ leaf sub wordIdx,
    c.lookup leaf sub wordIdx ≤ p.lookup leaf sub wordIdx

instance : LE ProcFeatureConfig where le := ProcFeatureConfig.refines

theorem ProcFeatureConfig.le_refl (cfg : ProcFeatureConfig) : cfg ≤ cfg :=
  fun _ _ _ => ProcFeatureAction.le_refl _

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
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, Nat.le_refl _⟩
  · intro c hc; exact hc
  · refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> exact id
  · exact InterruptPolicy.le_refl _
  · exact ExitPolicy.le_refl _
  · exact ProcFeatureConfig.le_refl _
  · exact ProcFeatureConfig.le_refl _

theorem cores_le_of_le {a b : DomainPolicy} (h : a ≤ b) : a.cores ⊆ b.cores :=
  h.1

theorem api_le_of_le {a b : DomainPolicy} (h : a ≤ b) : a.api ≤ b.api :=
  h.2.1

theorem interrupts_le_of_le {a b : DomainPolicy} (h : a ≤ b) :
    a.interrupts ≤ b.interrupts :=
  h.2.2.1

theorem exits_le_of_le {a b : DomainPolicy} (h : a ≤ b) : a.exits ≤ b.exits :=
  h.2.2.2.1

theorem cpuid_le_of_le {a b : DomainPolicy} (h : a ≤ b) : a.cpuid ≤ b.cpuid :=
  h.2.2.2.2.1

theorem msrs_le_of_le {a b : DomainPolicy} (h : a ≤ b) : a.msrs ≤ b.msrs :=
  h.2.2.2.2.2.1

theorem numVps_le_of_le {a b : DomainPolicy} (h : a ≤ b) : a.numVps ≤ b.numVps :=
  h.2.2.2.2.2.2

end DomainPolicy

end ThemisCapa
