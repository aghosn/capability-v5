/-
  ThemisCapa.Operations — Formal specification of capability operations.

  Each operation is specified as a relation between pre-state and post-state.
  The specification captures exactly the preconditions and state transitions
  from the Rust implementation (capa-engine/src/capability.rs).
-/
import ThemisCapa.Basic
import ThemisCapa.Domain
import ThemisCapa.Capability
import ThemisCapa.State

namespace ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § CARVE — create exclusive child memory region
-- ════════════════════════════════════════════════════════════════════

/-- Preconditions for `carve(caller, parentHandle, access)`. -/
structure CarvePre (caller : DomCap) (parent : MemCap) (access : Access) : Prop where
  callerSealed     : caller.isSealed
  hasPermission    : caller.policy.api.canCarve = true
  accessContained  : access.contained parent.region.access
  noOverlapCarved  : parent.noOverlapWithCarved access
  -- For alias parents, no overlap with ANY child (carved or alias)
  aliasNoOverlap   : parent.region.kind = .alias → parent.noOverlapWithAny access
  notComm          : parent.region.attributes.comm = false
  notMeta          : parent.region.attributes.meta = false
  notFrozen        : parent.id.subHandle ∉ caller.frozenHandles

/-- Postconditions: the new child capability. -/
structure CarvePost (parent : MemCap) (access : Access) (child : MemCap) : Prop where
  kindIsCarve       : child.region.kind = .carve
  statusInherited   : child.region.status = parent.region.status
  accessMatches     : child.region.access = access
  subHandleAssigned : child.id.subHandle = parent.nextChildSub
  depthIncremented  : child.id.depth = parent.id.depth + 1
  noChildren        : child.children = []

-- ════════════════════════════════════════════════════════════════════
-- § ALIAS — create shared child memory region
-- ════════════════════════════════════════════════════════════════════

structure AliasPre (caller : DomCap) (parent : MemCap) (access : Access) : Prop where
  callerSealed     : caller.isSealed
  hasPermission    : caller.policy.api.canAlias = true
  accessContained  : access.contained parent.region.access
  -- Aliases may NOT overlap with carved children, but MAY overlap with other aliases
  noOverlapCarved  : parent.noOverlapWithCarved access
  notComm          : parent.region.attributes.comm = false
  notMeta          : parent.region.attributes.meta = false
  notFrozen        : parent.id.subHandle ∉ caller.frozenHandles

structure AliasPost (parent : MemCap) (access : Access) (child : MemCap) : Prop where
  kindIsAlias       : child.region.kind = .alias
  statusIsAliased   : child.region.status = .aliased
  accessMatches     : child.region.access = access
  subHandleAssigned : child.id.subHandle = parent.nextChildSub
  depthIncremented  : child.id.depth = parent.id.depth + 1
  noChildren        : child.children = []

-- ════════════════════════════════════════════════════════════════════
-- § SEND — transfer memory capability between domains
-- ════════════════════════════════════════════════════════════════════

/-- Preconditions for `send(caller, capHandle, receiverHandle, attrs)`. -/
structure SendPre (caller : DomCap) (cap : MemCap)
    (receiver : DomCap) : Prop where
  callerSealed       : caller.isSealed
  hasPermission      : caller.policy.api.canSend = true
  callerOwns         : cap.id.domainId = caller.domainId
  notFrozen          : cap.id.subHandle ∉ caller.frozenHandles
  notComm            : cap.attributes.comm = false
  notMeta            : cap.attributes.meta = false
  receiverNotRevoked : receiver.status ≠ .revoked
  -- If receiver is sealed, it must have RECEIVE_AFTER_SEAL permission
  sealedReceiver     : receiver.isSealed → receiver.policy.api.canReceiveAfterSeal = true

/-- After send, ownership transfers and EPT updates are emitted.
    For a carve with exclusive status: caller loses mapping, receiver gains it.
    For an alias: receiver gains mapping, caller keeps access through parent. -/
structure SendPost (cap : MemCap) (caller receiver : DomCap)
    (caller' receiver' : DomCap) (updates : UpdateBatch) : Prop where
  ownerChanged : cap.id.domainId = receiver.domainId  -- in the post-state
  -- Exclusive carve: unmap from caller, map to receiver
  carveExclusive :
    cap.region.kind = .carve → cap.region.status = .exclusive →
      (HwUpdate.unmapMemory caller.domainId cap.region.access.start
                           cap.region.access.size) ∈ updates ∧
      (∃ hpa, (HwUpdate.mapMemory receiver.domainId hpa hpa
                cap.region.access.size cap.region.access.rights) ∈ updates)
  -- Alias: map to receiver only (parent retains access)
  aliasSend :
    cap.region.kind = .alias →
      ∃ hpa, (HwUpdate.mapMemory receiver.domainId hpa hpa
               cap.region.access.size cap.region.access.rights) ∈ updates

-- ════════════════════════════════════════════════════════════════════
-- § REVOKE — destroy capability subtree
-- ════════════════════════════════════════════════════════════════════

/-- Revocation preconditions. -/
structure RevokePre (caller : DomCap) (parent : MemCap)
    (childSub : SubHandle) : Prop where
  callerSealed  : caller.isSealed
  hasPermission : caller.policy.api.canRevoke = true
  callerOwns    : parent.id.domainId = caller.domainId
  notFrozen     : parent.id.subHandle ∉ caller.frozenHandles

/-- Revocation removes the entire subtree rooted at the child.
    For carved children, the parent regains exclusive access.
    For CLEAN children, memory is zeroed.
    For VITAL children, the owning domain is also revoked. -/
structure RevokePost (parent child : MemCap) (updates : UpdateBatch) : Prop where
  childRemoved : child ∉ parent.children  -- post-state parent has no child
  -- If CLEAN attribute set, memory is zeroed
  cleanZeroed :
    child.attributes.clean = true →
      (HwUpdate.zeroMemory child.region.access.start child.region.access.size) ∈ updates
  -- If carved and ownership changed, unmap from child owner, restore to parent owner
  carveRestored :
    child.region.kind = .carve → child.id.domainId ≠ parent.id.domainId →
      (HwUpdate.unmapMemory child.id.domainId child.region.access.start
                           child.region.access.size) ∈ updates

-- ════════════════════════════════════════════════════════════════════
-- § CREATE — create child domain
-- ════════════════════════════════════════════════════════════════════

structure CreatePre (parent : DomCap) (policy : DomainPolicy) : Prop where
  parentSealed       : parent.isSealed
  hasPermission      : parent.policy.api.canCreate = true
  coresMonotonic     : policy.cores ⊆ parent.policy.cores
  apiMonotonic       : policy.api ≤ parent.policy.api

structure CreatePost (parent : DomCap) (newDom : DomCap)
    (newId : DomainId) (updates : UpdateBatch) : Prop where
  idAssigned     : newDom.domainId = newId
  statusUnsealed : newDom.status = .unsealed
  noMemCaps      : newDom.memCaps = []
  noDomCaps      : newDom.domCaps = []
  createEmitted  : (HwUpdate.createDomain newId (some parent.domainId)) ∈ updates

-- ════════════════════════════════════════════════════════════════════
-- § SEAL — freeze domain policy
-- ════════════════════════════════════════════════════════════════════

structure SealPre (caller : DomCap) (target : DomCap) : Prop where
  callerOwns  : target.id.domainId = caller.domainId
  hasPermission : caller.policy.api.canSeal = true
  targetUnsealed : target.isUnsealed

structure SealPost (target target' : DomCap) : Prop where
  statusSealed : target'.status = .sealed
  policyFrozen : target'.policy = target.policy

-- ════════════════════════════════════════════════════════════════════
-- § SWITCH — transfer execution between domains
-- ════════════════════════════════════════════════════════════════════

/-- Forward switch: caller transfers control to a child domain's VP. -/
structure SwitchForwardPre (caller : DomCap) (target : DomCap)
    (coreId : CoreId) (targetVpId : VpId)
    (callerVp targetVp : VProcessor) : Prop where
  callerSealed   : caller.isSealed
  hasPermission  : caller.policy.api.canSwitch = true
  targetSealed   : target.isSealed
  coreAllowed    : coreId ∈ target.policy.cores
  vpExists       : targetVpId < target.policy.numVps
  -- Caller VP must be Running on this core
  callerRunning  : ∃ ctx, callerVp.runState = .running coreId ctx
  -- Target VP must be Available or Suspended
  targetReady    : targetVp.runState = .available ∨
                   (∃ did vid vec, targetVp.runState = .suspended did vid vec)

/-- Forward switch post-conditions: VP state transitions.
    - Caller VP: Running → Locked (waiting for callee to return)
    - Target VP: Available → Running (claimed) or Suspended → Running (resumed) -/
structure SwitchForwardPost (caller target : DomCap)
    (coreId : CoreId) (callerVpId targetVpId : VpId)
    (callerVp' targetVp' : VProcessor)
    (result : SwitchResult) : Prop where
  -- Caller VP transitions to Locked
  callerLocked   : callerVp'.runState =
    .locked target.domainId targetVpId (some ⟨caller.domainId, callerVpId⟩)
  -- Target VP transitions to Running with caller context
  targetRunning  : targetVp'.runState =
    .running coreId (some ⟨caller.domainId, callerVpId⟩)
  -- Result reflects a forward switch
  resultForward  : result.fromDomain = caller.domainId
  resultTarget   : result.toDomain = target.domainId
  notReturn      : result.isReturn = false

/-- Return switch: callee returns control to its caller. -/
structure SwitchReturnPre (callee : DomCap)
    (calleeVp : VProcessor) (coreId : CoreId)
    (callerCtx : VpCallContext) : Prop where
  -- Callee VP is Running with a caller context
  calleeRunning  : calleeVp.runState = .running coreId (some callerCtx)

/-- Return switch post-conditions.
    - Callee VP: Running → Available (released)
    - Caller VP: Locked → Running (resumed) -/
structure SwitchReturnPost (callee : DomCap) (callerCtx : VpCallContext)
    (coreId : CoreId)
    (calleeVp' callerVp' : VProcessor)
    (result : SwitchResult) : Prop where
  -- Callee VP returns to Available
  calleeAvailable : calleeVp'.runState = .available
  -- Caller VP resumes Running (with its own prev_caller)
  callerRunning   : ∃ prevCtx,
    callerVp'.runState = .running coreId prevCtx
  -- Result reflects a return switch
  resultReturn    : result.isReturn = true
  resultFrom      : result.fromDomain = callee.domainId
  resultTo        : result.toDomain = callerCtx.domainId

-- ════════════════════════════════════════════════════════════════════
-- § DELIVER_INTERRUPT_VP — interrupt delivery with lazy-unwind
--
-- When an external interrupt arrives while a child VP is running,
-- the capavisor must route it up the call chain to the handler domain.
-- Intermediate VPs are suspended (preserving the call chain) while
-- the leaf VP is marked interrupted.
-- ════════════════════════════════════════════════════════════════════

/-- A step in the VP call chain: the domain and VP being unwound. -/
structure ChainEntry where
  domainId : DomainId
  vpId     : VpId
deriving DecidableEq, Repr

/-- Preconditions for interrupt delivery. -/
structure DeliverInterruptPre
    (interrupted : DomCap) (handlerDomainId : DomainId)
    (coreId : CoreId) (vector : Nat) (leafVp : VProcessor) : Prop where
  -- The interrupted domain has a VP running on this core
  vpOnCore       : leafVp.runState = .running coreId (some ⟨interrupted.domainId, leafVp.id⟩)
                 ∨ ∃ ctx, leafVp.runState = .running coreId (some ctx)
  -- Handler domain is an ancestor in the call chain (or self)
  handlerExists  : True  -- the call chain walk finds the handler

/-- Post-conditions for interrupt delivery through a call chain.
    The chain is: leaf (interrupted) → ... → handler.
    - Leaf VP: Running → Interrupted(vector)
    - Each intermediate VP: Locked → Suspended(callee, vector)
    - Handler VP: Locked → Running (resumes to handle the interrupt) -/
structure DeliverInterruptPost
    (leafVp' : VProcessor)
    (intermediateVps : List (VProcessor × VProcessor))  -- (before, after) pairs
    (handlerVp' : VProcessor)
    (vector : Nat) (coreId : CoreId) : Prop where
  -- Leaf VP becomes Interrupted
  leafInterrupted : leafVp'.runState = .interrupted vector
  -- Each intermediate VP transitions from Locked to Suspended
  intermediates   : ∀ pair ∈ intermediateVps,
    (∃ did vid prevCtx, pair.1.runState = .locked did vid prevCtx) ∧
    (∃ did vid, pair.2.runState = .suspended did vid vector)
  -- Handler VP becomes Running on this core
  handlerRunning  : ∃ ctx, handlerVp'.runState = .running coreId ctx

-- ════════════════════════════════════════════════════════════════════
-- § VP State Machine — valid transitions
-- ════════════════════════════════════════════════════════════════════

/-- The complete set of valid VP state transitions. -/
inductive VpTransition : VpRunState → VpRunState → Prop where
  -- Switch transitions
  | claimVp : ∀ core ctx,
      VpTransition .available (.running core ctx)
  | lockCaller : ∀ core ctx did vid,
      VpTransition (.running core ctx) (.locked did vid ctx)
  | unlockCaller : ∀ did vid prevCtx core,
      VpTransition (.locked did vid prevCtx) (.running core prevCtx)
  | releaseVp : ∀ core ctx,
      VpTransition (.running core ctx) .available
  -- Interrupt transitions
  | interruptLeaf : ∀ core ctx vec,
      VpTransition (.running core ctx) (.interrupted vec)
  | suspendLocked : ∀ did vid prevCtx vec,
      VpTransition (.locked did vid prevCtx) (.suspended did vid vec)
  | resumeSuspended : ∀ did vid vec core ctx,
      VpTransition (.suspended did vid vec) (.running core ctx)
  | clearInterrupted : ∀ vec,
      VpTransition (.interrupted vec) .available

/-- A VP state is reachable from Available via valid transitions. -/
inductive VpReachable : VpRunState → Prop where
  | start : VpReachable .available
  | step  : ∀ s s', VpReachable s → VpTransition s s' → VpReachable s'

-- ════════════════════════════════════════════════════════════════════
-- § ACCEPT / REJECT — pending capability resolution
-- ════════════════════════════════════════════════════════════════════

/-- A pending capability waiting to be accepted or rejected. -/
structure PendingCap where
  pendingId    : Nat
  senderDomId  : DomainId
  senderHandle : LocalHandle     -- frozen in sender
  cap          : MemCap
deriving Repr

/-- Preconditions for accept: receiver takes ownership of a pending cap. -/
structure AcceptPre (receiver : DomCap) (pending : PendingCap)
    (sender : DomCap) : Prop where
  receiverSealed    : receiver.isSealed
  pendingExists     : True  -- pending.pendingId ∈ receiver.pending_capabilities
  senderNotRevoked  : sender.status ≠ .revoked

/-- Post-conditions for accept. -/
structure AcceptPost (receiver sender : DomCap)
    (receiver' sender' : DomCap)
    (pending : PendingCap) (updates : UpdateBatch) : Prop where
  -- Capability ownership transferred to receiver
  capOwned        : pending.cap.id.domainId = receiver.domainId  -- in post-state
  -- Sender's handle is unfrozen
  handleUnfrozen  : pending.senderHandle ∉ sender'.frozenHandles
  -- Hardware updates: map the region into receiver's address space
  mappingEmitted  : ∃ hpa, (HwUpdate.mapMemory receiver.domainId hpa hpa
                    pending.cap.region.access.size
                    pending.cap.region.access.rights) ∈ updates

/-- Preconditions for reject: receiver declines a pending cap. -/
structure RejectPre (receiver : DomCap) (pending : PendingCap) : Prop where
  pendingExists : True  -- pending.pendingId ∈ receiver.pending_capabilities

/-- Post-conditions for reject.
    No ownership transfer; sender's handle is unfrozen. -/
structure RejectPost (sender sender' : DomCap) (pending : PendingCap) : Prop where
  handleUnfrozen    : pending.senderHandle ∉ sender'.frozenHandles
  ownerUnchanged    : pending.cap.id.domainId = sender.domainId  -- remains with sender
  noUpdates         : True  -- no hardware updates emitted

-- ════════════════════════════════════════════════════════════════════
-- § REVOKE (recursive) — inductive subtree destruction
-- ════════════════════════════════════════════════════════════════════

/-- Recursive revocation: every node in the subtree is revoked.
    We use a predicate form to avoid nested-inductive issues with ∃. -/
def SubtreeRevoked (cap : MemCap) (updates : UpdateBatch) : Prop :=
  -- All memory in this cap's subtree is unmapped
  (cap.id.domainId ≠ 0 →
    (HwUpdate.unmapMemory cap.id.domainId cap.region.access.start
                         cap.region.access.size) ∈ updates) ∧
  -- Clean regions are zeroed
  (cap.attributes.clean = true →
    (HwUpdate.zeroMemory cap.region.access.start cap.region.access.size) ∈ updates) ∧
  -- All children are also covered by the updates
  (∀ ch ∈ cap.children,
    (ch.id.domainId ≠ 0 →
      (HwUpdate.unmapMemory ch.id.domainId ch.region.access.start
                           ch.region.access.size) ∈ updates) ∧
    (ch.attributes.clean = true →
      (HwUpdate.zeroMemory ch.region.access.start ch.region.access.size) ∈ updates))

-- ════════════════════════════════════════════════════════════════════
-- § REVOKE_DOMAIN — destroy domain subtree
-- ════════════════════════════════════════════════════════════════════

structure RevokeDomainPre (caller : DomCap) (target : DomCap) : Prop where
  callerSealed  : caller.isSealed
  hasPermission : caller.policy.api.canRevoke = true
  notRevoked    : target.status ≠ .revoked

structure RevokeDomainPost (target : DomCap) (updates : UpdateBatch) : Prop where
  statusRevoked : target.status = .revoked  -- in post-state
  revokeEmitted : (HwUpdate.revokeDomain target.domainId 0) ∈ updates
  -- All memory capabilities in the domain subtree are revoked
  allMemRevoked : target.memCaps = []  -- in post-state

end ThemisCapa
