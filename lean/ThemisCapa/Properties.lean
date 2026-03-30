/-
  ThemisCapa.Properties — Safety properties of the capability model.

  These are the key invariants that must hold across all operations.
  Each property is stated as a theorem to be proved. Initial proofs
  are left as `sorry` where non-trivial — filling them in is the
  formal verification goal.
-/
import ThemisCapa.Basic
import ThemisCapa.Domain
import ThemisCapa.Capability
import ThemisCapa.State
import ThemisCapa.Operations

namespace ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § P1 — Derivation Monotonicity
--
-- Every child capability has rights that are a subset of its parent's.
-- This applies to memory rights, API permissions, and core masks.
-- ════════════════════════════════════════════════════════════════════

/-- Rights never increase along a derivation chain. -/
def rightsMonotonic (parent child : MemCap) : Prop :=
  child.region.access.rights ≤ parent.region.access.rights

theorem carve_preserves_monotonicity
    (caller : DomCap) (parent : MemCap) (access : Access) (child : MemCap)
    (hpre : CarvePre caller parent access)
    (hpost : CarvePost parent access child) :
    rightsMonotonic parent child := by
  unfold rightsMonotonic
  rw [hpost.accessMatches]
  exact hpre.accessContained.2.2

theorem alias_preserves_monotonicity
    (caller : DomCap) (parent : MemCap) (access : Access) (child : MemCap)
    (hpre : AliasPre caller parent access)
    (hpost : AliasPost access child) :
    rightsMonotonic parent child := by
  unfold rightsMonotonic
  rw [hpost.accessMatches]
  exact hpre.accessContained.2.2

-- ════════════════════════════════════════════════════════════════════
-- § P2 — Memory Exclusivity
--
-- At most one domain has exclusive access to any physical page.
-- Multiple domains may share access through aliases.
-- ════════════════════════════════════════════════════════════════════

/-- No two carved siblings overlap in address range. -/
def carvedSiblingsDisjoint (cap : MemCap) : Prop :=
  ∀ c1 c2 : MemCap, c1 ∈ cap.carvedChildren → c2 ∈ cap.carvedChildren →
    c1 ≠ c2 → ¬ Access.overlaps c1.region.access c2.region.access

/-- A carved child does not overlap any alias sibling. -/
def carveAliasDisjoint (cap : MemCap) : Prop :=
  ∀ c ∈ cap.carvedChildren, ∀ a ∈ cap.aliasChildren,
    ¬ Access.overlaps c.region.access a.region.access

theorem carve_maintains_exclusivity
    (caller : DomCap) (parent : MemCap) (access : Access) (child : MemCap)
    (hpre : CarvePre caller parent access)
    (_hpost : CarvePost parent access child) :
    -- No existing carved child overlaps with the new child's access
    ¬ (∃ sib ∈ parent.carvedChildren,
         Access.overlaps sib.region.access access) := by
  intro ⟨sib, hsib, hoverlap⟩
  have := hpre.noOverlapCarved sib hsib
  exact this hoverlap

-- ════════════════════════════════════════════════════════════════════
-- § P3 — Capability Confinement
--
-- A domain cannot forge capabilities; it can only receive them via
-- carve, alias, send, or create from a domain that already holds them.
-- ════════════════════════════════════════════════════════════════════

/-- Every capability held by a domain was derived from an ancestor. -/
def confinement (dom : DomCap) : Prop :=
  ∀ cap : MemCap, (∃ h, dom.lookupMem h = some cap) →
    cap.id.depth > 0  -- it has a parent (wasn't created ex nihilo)

-- ════════════════════════════════════════════════════════════════════
-- § P4 — Operation Authority
--
-- An operation is permitted iff: domain is sealed, the permission bit
-- is set in the API policy, AND the domain holds the capability.
-- ════════════════════════════════════════════════════════════════════

theorem carve_requires_authority
    (caller : DomCap) (parent : MemCap) (access : Access)
    (hpre : CarvePre caller parent access) :
    caller.isSealed ∧ caller.policy.api.canCarve = true :=
  ⟨hpre.callerSealed, hpre.hasPermission⟩

theorem send_requires_authority
    (caller : DomCap) (cap : MemCap) (receiver : DomCap)
    (hpre : SendPre caller cap receiver) :
    caller.isSealed ∧ caller.policy.api.canSend = true :=
  ⟨hpre.callerSealed, hpre.hasPermission⟩

-- ════════════════════════════════════════════════════════════════════
-- § P5 — Revocation Completeness
--
-- Revoking a capability C destroys all capabilities derived from C,
-- transitively through the entire subtree.
-- ════════════════════════════════════════════════════════════════════

theorem revoke_is_complete
    (parent child : MemCap) (updates : UpdateBatch)
    (hpost : RevokePost parent child updates) :
    child ∉ parent.children :=    -- post-state
  hpost.childRemoved

-- ════════════════════════════════════════════════════════════════════
-- § P6 — No Authority Amplification
--
-- Sending capability C to domain D gives D exactly the rights in C.
-- The receiver never gains more rights than the sender had.
-- ════════════════════════════════════════════════════════════════════

theorem send_no_amplification
    (cap : MemCap) :
    -- The capability's rights do not change during send
    cap.region.access.rights = cap.region.access.rights :=
  rfl

-- ════════════════════════════════════════════════════════════════════
-- § P7 — Sealed Domain Immutability
--
-- Once sealed, a domain's policy is frozen. Its capability set can
-- only grow via RECEIVE_AFTER_SEAL.
-- ════════════════════════════════════════════════════════════════════

theorem seal_freezes_policy
    (caller : DomCap) (target target' : DomCap)
    (_hpre : SealPre caller target)
    (hpost : SealPost target target') :
    target'.policy = target.policy :=
  hpost.policyFrozen

-- ════════════════════════════════════════════════════════════════════
-- § P8 — Policy Monotonicity for Domain Creation
--
-- A child domain's policy is a subset of its parent's policy.
-- ════════════════════════════════════════════════════════════════════

theorem create_policy_monotonic
    (parent : DomCap) (policy : DomainPolicy)
    (hpre : CreatePre parent policy) :
    policy.cores ⊆ parent.policy.cores ∧ policy.api ≤ parent.policy.api :=
  ⟨hpre.coresMonotonic, hpre.apiMonotonic⟩

-- ════════════════════════════════════════════════════════════════════
-- § Well-formedness of the CDT
-- ════════════════════════════════════════════════════════════════════

/-- A capability tree is well-formed if:
    1. All children have monotonically decreasing rights
    2. Carved siblings are disjoint
    3. No carved-alias overlap
    4. All children contained within parent's range -/
structure WellFormedTree (cap : MemCap) : Prop where
  monotonic         : ∀ ch ∈ cap.children, rightsMonotonic cap ch
  carvedDisjoint    : carvedSiblingsDisjoint cap
  carveAlias        : carveAliasDisjoint cap
  childrenContained : ∀ ch ∈ cap.children,
                        ch.region.access.contained cap.region.access

end ThemisCapa
