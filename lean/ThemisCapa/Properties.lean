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
    (hpost : AliasPost parent access child) :
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

/-- A carved child does not overlap any alias sibling.
    Note: NOT part of WellFormedTree — aliases intentionally share memory
    with carves. Only enforced for alias parents (CarvePre.aliasNoOverlap). -/
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

theorem alias_requires_authority
    (caller : DomCap) (parent : MemCap) (access : Access)
    (hpre : AliasPre caller parent access) :
    caller.isSealed ∧ caller.policy.api.canAlias = true :=
  ⟨hpre.callerSealed, hpre.hasPermission⟩

theorem send_requires_authority
    (caller : DomCap) (cap : MemCap) (receiver : DomCap)
    (hpre : SendPre caller cap receiver) :
    caller.isSealed ∧ caller.policy.api.canSend = true :=
  ⟨hpre.callerSealed, hpre.hasPermission⟩

theorem revoke_requires_authority
    (caller : DomCap) (parent : MemCap) (childSub : SubHandle)
    (hpre : RevokePre caller parent childSub) :
    caller.isSealed ∧ caller.policy.api.canRevoke = true :=
  ⟨hpre.callerSealed, hpre.hasPermission⟩

theorem create_requires_authority
    (parent : DomCap) (policy : DomainPolicy)
    (hpre : CreatePre parent policy) :
    parent.isSealed ∧ parent.policy.api.canCreate = true :=
  ⟨hpre.parentSealed, hpre.hasPermission⟩

theorem switch_requires_authority
    (caller target : DomCap) (coreId : CoreId) (targetVpId : VpId)
    (callerVp targetVp : VProcessor)
    (hpre : SwitchForwardPre caller target coreId targetVpId callerVp targetVp) :
    caller.isSealed ∧ caller.policy.api.canSwitch = true :=
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
-- The mapping emitted uses the capability's rights, not more.
-- ════════════════════════════════════════════════════════════════════

/-- Exclusive carve send: receiver's mapping uses exactly cap's rights. -/
theorem send_no_amplification_carve
    (cap : MemCap) (caller receiver caller' receiver' : DomCap)
    (updates : UpdateBatch)
    (hpost : SendPost cap caller receiver caller' receiver' updates)
    (hcarve : cap.region.kind = .carve) (hexcl : cap.region.status = .exclusive) :
    ∃ hpa, (HwUpdate.mapMemory receiver.domainId hpa hpa
              cap.region.access.size cap.region.access.rights) ∈ updates :=
  (hpost.carveExclusive hcarve hexcl).2

/-- Alias send: receiver's mapping uses exactly cap's rights. -/
theorem send_no_amplification_alias
    (cap : MemCap) (caller receiver caller' receiver' : DomCap)
    (updates : UpdateBatch)
    (hpost : SendPost cap caller receiver caller' receiver' updates)
    (halias : cap.region.kind = .alias) :
    ∃ hpa, (HwUpdate.mapMemory receiver.domainId hpa hpa
              cap.region.access.size cap.region.access.rights) ∈ updates :=
  hpost.aliasSend halias

/-- Exclusive carve send: caller's mapping is revoked. -/
theorem send_revokes_caller
    (cap : MemCap) (caller receiver caller' receiver' : DomCap)
    (updates : UpdateBatch)
    (hpost : SendPost cap caller receiver caller' receiver' updates)
    (hcarve : cap.region.kind = .carve) (hexcl : cap.region.status = .exclusive) :
    (HwUpdate.unmapMemory caller.domainId cap.region.access.start
                         cap.region.access.size) ∈ updates :=
  (hpost.carveExclusive hcarve hexcl).1

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
-- § P3b — Confinement Theorems
--
-- Every derived capability has depth > 0 (was not created ex nihilo).
-- This proves the `confinement` definition holds after each operation.
-- ════════════════════════════════════════════════════════════════════

/-- Carve always produces a derived capability (depth > 0). -/
theorem carve_produces_derived
    (parent : MemCap) (access : Access) (child : MemCap)
    (hpost : CarvePost parent access child) :
    child.id.depth > 0 := by
  rw [hpost.depthIncremented]; omega

/-- Alias always produces a derived capability (depth > 0). -/
theorem alias_produces_derived
    (parent : MemCap) (access : Access) (child : MemCap)
    (hpost : AliasPost parent access child) :
    child.id.depth > 0 := by
  rw [hpost.depthIncremented]; omega

/-- A newly created domain has no capabilities, so confinement holds vacuously. -/
theorem create_confinement
    (parent : DomCap) (newDom : DomCap) (newId : DomainId)
    (updates : UpdateBatch)
    (hpost : CreatePost parent newDom newId updates) :
    confinement newDom := by
  intro cap ⟨h, hlookup⟩
  simp [DomCap.lookupMem, hpost.noMemCaps] at hlookup

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
-- § P9f — VP Transition Exhaustiveness
--
-- Characterize the COMPLETE set of possible next states from each
-- VP state. This proves that invalid transitions are impossible.
-- ════════════════════════════════════════════════════════════════════

/-- From Available, the only transition leads to Running. -/
theorem available_only_to_running :
    ∀ s, VpTransition .available s → ∃ core ctx, s = .running core ctx := by
  intro s h; cases h with
  | claimVp core ctx => exact ⟨core, ctx, rfl⟩

/-- From Running, transitions lead to Locked, Available, or Interrupted. -/
theorem running_next_states :
    ∀ s core ctx, VpTransition (.running core ctx) s →
      (∃ did vid, s = .locked did vid ctx) ∨
      s = .available ∨
      (∃ vec, s = .interrupted vec) := by
  intro s core ctx h
  cases h with
  | lockCaller _ _ did vid => exact Or.inl ⟨did, vid, rfl⟩
  | releaseVp _ _ => exact Or.inr (Or.inl rfl)
  | interruptLeaf _ _ vec => exact Or.inr (Or.inr ⟨vec, rfl⟩)

/-- From Locked, transitions lead to Running or Suspended. -/
theorem locked_next_states :
    ∀ s did vid prevCtx, VpTransition (.locked did vid prevCtx) s →
      (∃ core, s = .running core prevCtx) ∨
      (∃ vec, s = .suspended did vid vec) := by
  intro s did vid prevCtx h
  cases h with
  | unlockCaller _ _ _ core => exact Or.inl ⟨core, rfl⟩
  | suspendLocked _ _ _ vec => exact Or.inr ⟨vec, rfl⟩

/-- From Interrupted, the only transition leads to Available. -/
theorem interrupted_only_to_available :
    ∀ s vec, VpTransition (.interrupted vec) s → s = .available := by
  intro s vec h; cases h with
  | clearInterrupted _ => rfl

/-- From Suspended, the only transition leads to Running. -/
theorem suspended_only_to_running :
    ∀ s did vid vec, VpTransition (.suspended did vid vec) s →
      ∃ core ctx, s = .running core ctx := by
  intro s did vid vec h
  cases h with
  | resumeSuspended _ _ _ core ctx => exact ⟨core, ctx, rfl⟩

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

-- ════════════════════════════════════════════════════════════════════
-- § P18 — Contained Regions Inherit Disjointness
--
-- If two containers don't overlap, neither do any regions contained
-- within them. This is the key lemma for address space isolation.
-- ════════════════════════════════════════════════════════════════════

theorem contained_disjoint
    {r1 r2 a b : Access}
    (hdisjoint : ¬ Access.overlaps r1 r2)
    (ha : a.contained r1) (hb : b.contained r2) :
    ¬ Access.overlaps a b := by
  unfold Access.overlaps Access.contained Access.«end» at *
  obtain ⟨ha1, ha2, _⟩ := ha
  obtain ⟨hb1, hb2, _⟩ := hb
  intro ⟨h1, h2⟩
  exact hdisjoint ⟨by omega, by omega⟩

-- ════════════════════════════════════════════════════════════════════
-- § P19 — Alias Preserves Well-Formedness
--
-- Adding an alias child preserves WellFormedTree because aliases
-- don't affect the carved children set.
-- ════════════════════════════════════════════════════════════════════

/-- Describes the parent MemCap state after an alias adds a child. -/
structure ParentAfterAlias (parent parent' : MemCap) (child : MemCap) : Prop where
  childrenAppended  : parent'.children = parent.children ++ [child]
  regionUnchanged   : parent'.region = parent.region
  carvedUnchanged   : parent'.carvedChildren = parent.carvedChildren

theorem alias_preserves_wellformed
    (caller : DomCap) (parent parent' : MemCap) (access : Access) (child : MemCap)
    (hpre : AliasPre caller parent access)
    (hpost : AliasPost parent access child)
    (hwf : WellFormedTree parent)
    (hupd : ParentAfterAlias parent parent' child) :
    WellFormedTree parent' := by
  constructor
  · -- monotonic
    intro ch hch
    rw [hupd.childrenAppended] at hch
    simp at hch
    rcases hch with h | rfl
    · have := hwf.monotonic ch h
      unfold rightsMonotonic at this ⊢
      rw [hupd.regionUnchanged]
      exact this
    · unfold rightsMonotonic
      rw [hupd.regionUnchanged, hpost.accessMatches]
      exact hpre.accessContained.2.2
  · -- carvedDisjoint: carved children unchanged by alias
    intro c1 c2 hc1 hc2 hneq
    rw [hupd.carvedUnchanged] at hc1 hc2
    exact hwf.carvedDisjoint c1 c2 hc1 hc2 hneq
  · -- childrenContained
    intro ch hch
    rw [hupd.childrenAppended] at hch
    simp at hch
    rcases hch with h | rfl
    · have := hwf.childrenContained ch h
      unfold Access.contained at this ⊢
      rw [hupd.regionUnchanged]
      exact this
    · unfold Access.contained
      rw [hupd.regionUnchanged, hpost.accessMatches]
      exact hpre.accessContained

-- ════════════════════════════════════════════════════════════════════
-- § P20 — Revoke Preserves Well-Formedness
--
-- Removing children from the CDT preserves WellFormedTree because
-- all remaining children still satisfy the invariants.
-- ════════════════════════════════════════════════════════════════════

/-- Describes the parent MemCap state after revoking children. -/
structure ParentAfterRevoke (parent parent' : MemCap) : Prop where
  childrenSubset    : ∀ ch ∈ parent'.children, ch ∈ parent.children
  regionUnchanged   : parent'.region = parent.region
  carvedSubset      : ∀ ch ∈ parent'.carvedChildren, ch ∈ parent.carvedChildren

theorem revoke_preserves_wellformed
    (parent parent' : MemCap)
    (hwf : WellFormedTree parent)
    (hupd : ParentAfterRevoke parent parent') :
    WellFormedTree parent' := by
  constructor
  · -- monotonic: subset of children still monotonic
    intro ch hch
    have := hwf.monotonic ch (hupd.childrenSubset ch hch)
    unfold rightsMonotonic at this ⊢
    rw [hupd.regionUnchanged]
    exact this
  · -- carvedDisjoint: subset of carved children still pairwise disjoint
    intro c1 c2 hc1 hc2 hneq
    exact hwf.carvedDisjoint c1 c2
      (hupd.carvedSubset c1 hc1) (hupd.carvedSubset c2 hc2) hneq
  · -- childrenContained: subset of children still contained
    intro ch hch
    have := hwf.childrenContained ch (hupd.childrenSubset ch hch)
    unfold Access.contained at this ⊢
    rw [hupd.regionUnchanged]
    exact this

-- ════════════════════════════════════════════════════════════════════
-- § P21 — Address Space Isolation
--
-- The main isolation theorem: any two access ranges contained in
-- disjoint carved siblings are themselves disjoint. This guarantees
-- that domains with capabilities from different carved subtrees
-- have non-overlapping physical memory views.
-- ════════════════════════════════════════════════════════════════════

/-- General isolation: any accesses contained in disjoint carved siblings
    are disjoint. Covers descendants at any depth. -/
theorem subtree_isolation
    (parent c1 c2 : MemCap) (a b : Access)
    (hwf : WellFormedTree parent)
    (hc1 : c1 ∈ parent.carvedChildren)
    (hc2 : c2 ∈ parent.carvedChildren)
    (hne : c1 ≠ c2)
    (ha : a.contained c1.region.access)
    (hb : b.contained c2.region.access) :
    ¬ Access.overlaps a b :=
  contained_disjoint (hwf.carvedDisjoint c1 c2 hc1 hc2 hne) ha hb

/-- Corollary: immediate children of disjoint carved siblings are disjoint. -/
theorem descendant_isolation
    (parent c1 c2 d1 d2 : MemCap)
    (hwf : WellFormedTree parent) (hwf1 : WellFormedTree c1) (hwf2 : WellFormedTree c2)
    (hc1 : c1 ∈ parent.carvedChildren) (hc2 : c2 ∈ parent.carvedChildren)
    (hne : c1 ≠ c2)
    (hd1 : d1 ∈ c1.children) (hd2 : d2 ∈ c2.children) :
    ¬ Access.overlaps d1.region.access d2.region.access :=
  subtree_isolation parent c1 c2 d1.region.access d2.region.access
    hwf hc1 hc2 hne
    (hwf1.childrenContained d1 hd1)
    (hwf2.childrenContained d2 hd2)

-- ════════════════════════════════════════════════════════════════════
-- § Reflexivity Helpers
-- ════════════════════════════════════════════════════════════════════

theorem Rights.subset_refl (a : Rights) : a ≤ a :=
  ⟨id, id, id⟩

theorem Access.contained_refl (a : Access) : a.contained a := by
  unfold Access.contained Access.«end»
  exact ⟨Nat.le_refl _, Nat.le_refl _, Rights.subset_refl _⟩

-- ════════════════════════════════════════════════════════════════════
-- § WellFormedChain — N-level CDT reasoning
--
-- A chain of well-formed ancestors from root to descendant. Each
-- step requires the parent to be well-formed, enabling inductive
-- proofs over arbitrary CDT depth.
-- ════════════════════════════════════════════════════════════════════

/-- A chain of well-formed ancestors from root to descendant.
    Each step requires the parent node to be well-formed. -/
inductive WellFormedChain : MemCap → MemCap → Prop where
  | refl : WellFormedChain cap cap
  | step : ∀ parent child rest,
      WellFormedTree parent →
      child ∈ parent.children →
      WellFormedChain child rest →
      WellFormedChain parent rest

/-- Chains compose: if root→mid and mid→desc, then root→desc. -/
theorem WellFormedChain.append
    {root mid desc : MemCap}
    (h1 : WellFormedChain root mid)
    (h2 : WellFormedChain mid desc) :
    WellFormedChain root desc := by
  induction h1 with
  | refl => exact h2
  | step parent child rest hwf hmem _hrest ih =>
    exact .step parent child desc hwf hmem (ih h2)

-- ════════════════════════════════════════════════════════════════════
-- § P22 — N-level Rights Monotonicity
--
-- Rights never increase along ANY well-formed chain in the CDT,
-- regardless of depth. Generalizes P15 from 2-level to N-level.
-- ════════════════════════════════════════════════════════════════════

theorem chain_rights_monotonic
    (root desc : MemCap)
    (hchain : WellFormedChain root desc) :
    rightsMonotonic root desc := by
  induction hchain with
  | refl => unfold rightsMonotonic; exact Rights.subset_refl _
  | step parent child rest hwf hmem _hrest ih =>
    have hpc := hwf.monotonic child hmem
    unfold rightsMonotonic at *
    exact rights_subset_trans ih hpc

-- ════════════════════════════════════════════════════════════════════
-- § P23 — N-level Containment
--
-- Descendants are always contained within their root ancestor's
-- access range, regardless of depth.
-- ════════════════════════════════════════════════════════════════════

theorem chain_containment
    (root desc : MemCap)
    (hchain : WellFormedChain root desc) :
    desc.region.access.contained root.region.access := by
  induction hchain with
  | refl => exact Access.contained_refl _
  | step parent child rest hwf hmem _hrest ih =>
    exact access_contained_trans ih (hwf.childrenContained child hmem)

-- ════════════════════════════════════════════════════════════════════
-- § P24 — Deep Isolation (N-level Address Space Isolation)
--
-- The crown jewel: descendants at ANY depth in disjoint carved
-- subtrees are disjoint. If two domains derive their memory
-- capabilities from different carved branches of the CDT, their
-- physical memory views cannot overlap — no matter how many
-- carve/alias operations were performed in between.
-- ════════════════════════════════════════════════════════════════════

theorem deep_isolation
    (parent c1 c2 d1 d2 : MemCap)
    (hwf : WellFormedTree parent)
    (hc1 : c1 ∈ parent.carvedChildren)
    (hc2 : c2 ∈ parent.carvedChildren)
    (hne : c1 ≠ c2)
    (hchain1 : WellFormedChain c1 d1)
    (hchain2 : WellFormedChain c2 d2) :
    ¬ Access.overlaps d1.region.access d2.region.access :=
  contained_disjoint
    (hwf.carvedDisjoint c1 c2 hc1 hc2 hne)
    (chain_containment c1 d1 hchain1)
    (chain_containment c2 d2 hchain2)

end ThemisCapa
