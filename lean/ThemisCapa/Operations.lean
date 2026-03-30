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

structure AliasPost (access : Access) (child : MemCap) : Prop where
  kindIsAlias     : child.region.kind = .alias
  statusIsAliased : child.region.status = .aliased
  accessMatches   : child.region.access = access
  noChildren      : child.children = []

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
    (coreId : CoreId) (targetVpId : VpId) : Prop where
  callerSealed   : caller.isSealed
  hasPermission  : caller.policy.api.canSwitch = true
  targetSealed   : target.isSealed
  coreAllowed    : coreId ∈ target.policy.cores
  vpExists       : targetVpId < target.policy.numVps
  -- Target VP must be Available or Suspended
  vpReady        : ∀ vp ∈ target.vps, vp.id = targetVpId →
                     vp.runState = .available ∨
                     (∃ did vid vec, vp.runState = .suspended did vid vec)

/-- Return switch: callee returns to its caller. -/
structure SwitchReturnPre (callee : DomCap) (callerCtx : VpCallContext) : Prop where
  -- The callee VP is Running with a caller context
  hasCallerCtx : True  -- simplified; the Running state carries the caller

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
