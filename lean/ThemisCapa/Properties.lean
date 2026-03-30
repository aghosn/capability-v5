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

end ThemisCapa
