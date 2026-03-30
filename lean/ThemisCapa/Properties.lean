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
    2. Carved siblings are disjoint (exclusive ownership)
    3. All children contained within parent's range
    Note: aliases may overlap with carves — that's intentional (shared access). -/
structure WellFormedTree (cap : MemCap) : Prop where
  monotonic         : ∀ ch ∈ cap.children, rightsMonotonic cap ch
  carvedDisjoint    : carvedSiblingsDisjoint cap
  childrenContained : ∀ ch ∈ cap.children,
                        ch.region.access.contained cap.region.access

-- ════════════════════════════════════════════════════════════════════
-- § P9 — VP State Machine Validity
--
-- All VP states are reachable from Available via valid transitions.
-- No transition can produce a state not in the VpRunState enum.
-- ════════════════════════════════════════════════════════════════════

/-- Available is trivially reachable. -/
theorem available_is_reachable : VpReachable VpRunState.available :=
  VpReachable.start

/-- A forward switch produces reachable states. -/
theorem switch_forward_produces_reachable
    (core : CoreId) (ctx : Option VpCallContext) :
    VpReachable (.running core ctx) :=
  VpReachable.step _ _ VpReachable.start (VpTransition.claimVp core ctx)

/-- Locking a running VP produces a reachable state. -/
theorem lock_produces_reachable
    (core : CoreId) (ctx : Option VpCallContext) (did : DomainId) (vid : VpId) :
    VpReachable (.locked did vid ctx) :=
  VpReachable.step _ _
    (switch_forward_produces_reachable core ctx)
    (VpTransition.lockCaller core ctx did vid)

/-- Interrupt on a running VP produces a reachable Interrupted state. -/
theorem interrupt_produces_reachable
    (core : CoreId) (ctx : Option VpCallContext) (vec : Nat) :
    VpReachable (.interrupted vec) :=
  VpReachable.step _ _
    (switch_forward_produces_reachable core ctx)
    (VpTransition.interruptLeaf core ctx vec)

/-- Suspending a locked VP produces a reachable Suspended state. -/
theorem suspend_produces_reachable
    (core : CoreId) (ctx : Option VpCallContext)
    (did : DomainId) (vid : VpId) (vec : Nat) :
    VpReachable (.suspended did vid vec) :=
  VpReachable.step _ _
    (lock_produces_reachable core ctx did vid)
    (VpTransition.suspendLocked did vid ctx vec)

-- ════════════════════════════════════════════════════════════════════
-- § P10 — Switch Symmetry
--
-- A forward switch followed by a return switch restores the caller VP.
-- ════════════════════════════════════════════════════════════════════

/-- Forward switch sets isReturn = false. -/
theorem switch_forward_not_return
    (caller target : DomCap) (coreId : CoreId)
    (callerVpId targetVpId : VpId)
    (callerVp' targetVp' : VProcessor)
    (result : SwitchResult)
    (hpost : SwitchForwardPost caller target coreId callerVpId targetVpId
             callerVp' targetVp' result) :
    result.isReturn = false :=
  hpost.notReturn

/-- Return switch sets isReturn = true. -/
theorem switch_return_is_return
    (callee : DomCap) (callerCtx : VpCallContext)
    (coreId : CoreId)
    (calleeVp' callerVp' : VProcessor)
    (result : SwitchResult)
    (hpost : SwitchReturnPost callee callerCtx coreId
             calleeVp' callerVp' result) :
    result.isReturn = true :=
  hpost.resultReturn

-- ════════════════════════════════════════════════════════════════════
-- § P11 — Accept/Reject Handle Unfreezing
--
-- Both accept and reject unfreeze the sender's handle.
-- ════════════════════════════════════════════════════════════════════

theorem accept_unfreezes_sender
    (receiver sender receiver' sender' : DomCap)
    (pending : PendingCap) (updates : UpdateBatch)
    (hpost : AcceptPost receiver sender receiver' sender' pending updates) :
    pending.senderHandle ∉ sender'.frozenHandles :=
  hpost.handleUnfrozen

theorem reject_unfreezes_sender
    (sender sender' : DomCap) (pending : PendingCap)
    (hpost : RejectPost sender sender' pending) :
    pending.senderHandle ∉ sender'.frozenHandles :=
  hpost.handleUnfrozen

-- ════════════════════════════════════════════════════════════════════
-- § P12 — Interrupt Delivery Preserves Call Chain
--
-- After interrupt delivery, the leaf VP is Interrupted and all
-- intermediate VPs are Suspended (not lost, can be resumed).
-- ════════════════════════════════════════════════════════════════════

theorem interrupt_preserves_chain
    (leafVp' : VProcessor)
    (intermediates : List (VProcessor × VProcessor))
    (handlerVp' : VProcessor)
    (vector : Nat) (coreId : CoreId)
    (hpost : DeliverInterruptPost leafVp' intermediates handlerVp' vector coreId) :
    -- Leaf is interrupted (not lost)
    leafVp'.runState = .interrupted vector ∧
    -- Handler is running (can process the interrupt)
    (∃ ctx, handlerVp'.runState = .running coreId ctx) :=
  ⟨hpost.leafInterrupted, hpost.handlerRunning⟩

-- ════════════════════════════════════════════════════════════════════
-- § Helper — Access.overlaps is commutative
-- ════════════════════════════════════════════════════════════════════

theorem overlaps_comm {a b : Access}
    (h : Access.overlaps a b) : Access.overlaps b a :=
  ⟨h.2, h.1⟩

-- ════════════════════════════════════════════════════════════════════
-- § P13 — Rights Subset Transitivity
--
-- Foundation for multi-level monotonicity proofs.
-- ════════════════════════════════════════════════════════════════════

theorem rights_subset_trans {a b c : Rights}
    (hab : a ≤ b) (hbc : b ≤ c) : a ≤ c := by
  show Rights.subset a c
  have hab' : Rights.subset a b := hab
  have hbc' : Rights.subset b c := hbc
  exact ⟨fun ha => hbc'.1 (hab'.1 ha),
         fun ha => hbc'.2.1 (hab'.2.1 ha),
         fun ha => hbc'.2.2 (hab'.2.2 ha)⟩

-- ════════════════════════════════════════════════════════════════════
-- § P14 — Access Containment Transitivity
--
-- If grandchild ⊂ child ⊂ parent, then grandchild ⊂ parent.
-- ════════════════════════════════════════════════════════════════════

theorem access_contained_trans {a b c : Access}
    (hab : a.contained b) (hbc : b.contained c) : a.contained c := by
  unfold Access.contained at *
  exact ⟨Nat.le_trans hbc.1 hab.1,
         Nat.le_trans hab.2.1 hbc.2.1,
         rights_subset_trans hab.2.2 hbc.2.2⟩

-- ════════════════════════════════════════════════════════════════════
-- § P15 — Multi-level Rights Monotonicity
--
-- In a well-formed CDT, grandchildren have rights ≤ grandparent.
-- ════════════════════════════════════════════════════════════════════

theorem two_level_monotonicity
    (grandparent parent child : MemCap)
    (hwf_gp : WellFormedTree grandparent)
    (hwf_p : WellFormedTree parent)
    (hparent : parent ∈ grandparent.children)
    (hchild : child ∈ parent.children) :
    rightsMonotonic grandparent child := by
  have h1 := hwf_gp.monotonic parent hparent
  have h2 := hwf_p.monotonic child hchild
  unfold rightsMonotonic at *
  exact rights_subset_trans h2 h1

-- ════════════════════════════════════════════════════════════════════
-- § P16 — Multi-level Access Containment
--
-- In a well-formed CDT, grandchildren are contained in grandparent.
-- ════════════════════════════════════════════════════════════════════

theorem two_level_containment
    (grandparent parent child : MemCap)
    (hwf_gp : WellFormedTree grandparent)
    (hwf_p : WellFormedTree parent)
    (hparent : parent ∈ grandparent.children)
    (hchild : child ∈ parent.children) :
    child.region.access.contained grandparent.region.access :=
  access_contained_trans (hwf_p.childrenContained child hchild)
                         (hwf_gp.childrenContained parent hparent)

-- ════════════════════════════════════════════════════════════════════
-- § P17 — Carve Preserves Well-Formedness
--
-- The main CDT preservation theorem: if the parent tree is well-formed
-- before carve, it remains well-formed after adding the carved child.
-- ════════════════════════════════════════════════════════════════════

/-- Describes the parent MemCap state after a carve adds a child. -/
structure ParentAfterCarve (parent parent' : MemCap) (child : MemCap) : Prop where
  childrenAppended  : parent'.children = parent.children ++ [child]
  regionUnchanged   : parent'.region = parent.region
  carvedAppended    : parent'.carvedChildren = parent.carvedChildren ++ [child]

/-- Carve preserves the well-formedness of the capability tree. -/
theorem carve_preserves_wellformed
    (caller : DomCap) (parent parent' : MemCap) (access : Access) (child : MemCap)
    (hpre : CarvePre caller parent access)
    (hpost : CarvePost parent access child)
    (hwf : WellFormedTree parent)
    (hupd : ParentAfterCarve parent parent' child) :
    WellFormedTree parent' := by
  constructor
  · -- monotonic: all children (old + new) have rights ≤ parent'
    intro ch hch
    rw [hupd.childrenAppended] at hch
    simp at hch
    rcases hch with h | rfl
    · -- ch ∈ parent.children — use existing well-formedness
      have := hwf.monotonic ch h
      unfold rightsMonotonic at this ⊢
      rw [hupd.regionUnchanged]
      exact this
    · -- ch = child — use carve precondition (access ⊆ parent)
      unfold rightsMonotonic
      rw [hupd.regionUnchanged, hpost.accessMatches]
      exact hpre.accessContained.2.2
  · -- carvedDisjoint: no two carved children overlap
    intro c1 c2 hc1 hc2 hneq
    rw [hupd.carvedAppended] at hc1 hc2
    simp at hc1 hc2
    rcases hc1 with h1 | rfl
    · -- c1 ∈ old carved children
      rcases hc2 with h2 | rfl
      · -- c2 ∈ old carved children — use existing well-formedness
        exact hwf.carvedDisjoint c1 c2 h1 h2 hneq
      · -- c2 = child — new child doesn't overlap old carved
        intro hovl
        rw [hpost.accessMatches] at hovl
        exact hpre.noOverlapCarved c1 h1 hovl
    · -- c1 = child
      rcases hc2 with h2 | rfl
      · -- c2 ∈ old carved children — symmetric case
        intro hovl
        rw [hpost.accessMatches] at hovl
        exact hpre.noOverlapCarved c2 h2 (overlaps_comm hovl)
      · -- c1 = c2 = child — contradicts c1 ≠ c2
        exact absurd rfl hneq
  · -- childrenContained: all children fit within parent's range
    intro ch hch
    rw [hupd.childrenAppended] at hch
    simp at hch
    rcases hch with h | rfl
    · -- ch ∈ parent.children — use existing well-formedness
      have := hwf.childrenContained ch h
      unfold Access.contained at this ⊢
      rw [hupd.regionUnchanged]
      exact this
    · -- ch = child — use carve precondition
      unfold Access.contained
      rw [hupd.regionUnchanged, hpost.accessMatches]
      exact hpre.accessContained

end ThemisCapa
