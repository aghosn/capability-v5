/-
  LeanExec.Operations.Memory — Memory capability operations.

  Implements init, carve, alias, send, accept, reject, and revoke
  as functions in the CapaM monad. GPA = HPA = access.start for
  simplicity (this is a model, not real address translation).
-/
import LeanExec.Monad

namespace LeanExec

open ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § Helpers
-- ════════════════════════════════════════════════════════════════════

/-- Subtract a single range [cs, ce) from a list of segments,
    producing the remaining visible portions. -/
private def subtractOne (segments : List (Nat × Nat)) (cs ce : Nat)
    : List (Nat × Nat) :=
  segments.flatMap fun (s, sz) =>
    let e := s + sz
    if ce ≤ s || cs ≥ e then [(s, sz)]
    else
      let before := if cs > s then [(s, cs - s)] else []
      let after  := if ce < e then [(ce, e - ce)] else []
      before ++ after

/-- Subtract a list of carved ranges from a base range. -/
private def subtractRanges (start : Nat) (size : Nat)
    (carved : List (Nat × Nat)) : List (Nat × Nat) :=
  carved.foldl (fun segs (cs, csz) => subtractOne segs cs (cs + csz)) [(start, size)]

/-- Compute the visible fragments of a memory cap's range after subtracting
    all carved children. This is needed for correct EPT update generation:
    when a parent is sent/unmapped, only its visible portions (not covered
    by carved children) should be affected. -/
private def visibleFragments (s : ExecState) (cap : ExecMemCap)
    : List (Nat × Nat) :=
  let carvedRanges := cap.childUids.toList.filterMap fun childUid =>
    match s.getMemCap childUid with
    | some child =>
      if child.region.kind == .carve then
        some (child.region.access.start, child.region.access.size)
      else none
    | none => none
  subtractRanges cap.region.access.start cap.region.access.size carvedRanges

/-- Check whether any carved child of `parent` overlaps `access`. -/
private def hasCarveOverlap (s : ExecState) (parent : ExecMemCap)
    (access : Access) : Bool :=
  parent.childUids.any fun uid =>
    match s.getMemCap uid with
    | some child => child.region.kind == .carve &&
                    Access.overlapsB access child.region.access
    | none => false

/-- Check whether any carved child of `parent` overlaps `access` (for alias). -/
private def hasCarveOverlapForAlias (s : ExecState) (parent : ExecMemCap)
    (access : Access) : Bool :=
  parent.childUids.any fun uid =>
    match s.getMemCap uid with
    | some child => child.region.kind == .carve &&
                    Access.overlapsB access child.region.access
    | none => false

/-- Find the local handle for a memcap UID in a domain's memCaps list. -/
private def findHandle (dom : ExecDomain) (uid : CapNodeId) : Option LocalHandle :=
  (dom.memCaps.find? (fun p => p.2 == uid)).map Prod.fst

-- ════════════════════════════════════════════════════════════════════
-- § init — Initialize root domain and root memory capability
-- ════════════════════════════════════════════════════════════════════

/-- Create the root domain (id=0, sealed) and root memory capability
    (start=0, size=memSize, RWX, Carve, Exclusive).
    Returns (domainId, rootCapUid). -/
def init (memSize : Nat) (numCores : Nat) : CapaM (DomainId × CapNodeId) := do
  -- Build initial state
  let initState := ExecState.empty numCores
  CapaM.setState initState

  -- Allocate domain id (will be 0)
  let domId ← CapaM.allocDomainId
  -- Allocate root cap uid (will be 0)
  let rootUid ← CapaM.allocNodeId

  -- Build core list [0, 1, ..., numCores-1]
  let coreList := (List.range numCores)
  -- Build VP array: one VP per core, marked running on their core
  let vps := (List.range numCores).map (fun i =>
    { id := i, runState := VpRunState.running i none : VProcessor })

  let policy : DomainPolicy :=
    { cores := coreList
      api := MonitorAPI.full
      interrupts := { defaultPolicy := .deliver, perVector := [] }
      numVps := numCores }

  let rootDomain : ExecDomain :=
    { (ExecDomain.empty domId none policy) with
      status := .sealed
      vps := vps.toArray
      memCaps := [(0, rootUid)]
      nextMemHandle := 1 }

  CapaM.setDomain domId rootDomain

  -- Schedule root domain on all cores (match Rust init behaviour)
  for i in List.range numCores do
    CapaM.setCoreState i (.runningDomain domId i)

  -- Create root memory capability
  let rootCap : ExecMemCap :=
    { uid := rootUid
      capId := { domainId := domId, subHandle := 0, depth := 0 }
      region :=
        { kind := .carve
          status := .exclusive
          access := { start := 0, size := memSize, rights := Rights.rwx }
          attributes := Attributes.empty }
      attributes := Attributes.empty
      parentUid := none
      childUids := #[]
      nextChildSub := 0 }

  CapaM.setMemCap rootUid rootCap
  pure (domId, rootUid)

-- ════════════════════════════════════════════════════════════════════
-- § carve — Carve an exclusive child region from parent
-- ════════════════════════════════════════════════════════════════════

/-- Carve an exclusive child from a parent memory capability.
    Returns (childLocalHandle, childSubHandle, updateBatch). -/
def carve (callerId : DomainId) (parentHandle : LocalHandle)
    (access : Access) : CapaM (LocalHandle × SubHandle × UpdateBatch) := do
  let caller ← CapaM.getDomain callerId
  -- Preconditions
  CapaM.requireSealed caller
  CapaM.requireApi caller (·.canCarve)
  CapaM.requireNotFrozen caller parentHandle

  let parentUid ← match caller.lookupNodeId parentHandle with
    | some uid => pure uid
    | none => CapaM.throw .notFound
  let parent ← CapaM.getMemCap parentUid

  -- Access must be contained in parent's region
  CapaM.guard (Access.containedB access parent.region.access)
    .invalidAccess

  -- Parent must not be COMM or META (Rust returns permissionDenied)
  CapaM.guard (!parent.attributes.comm) .permissionDenied
  CapaM.guard (!parent.attributes.meta) .permissionDenied

  -- No overlap with existing carved children (Rust returns invalidAccess, not regionOverlap)
  let s ← CapaM.getState
  CapaM.guard (!hasCarveOverlap s parent access) .invalidAccess

  -- Allocate child
  let childUid ← CapaM.allocNodeId
  let childSub := parent.nextChildSub

  let childCap : ExecMemCap :=
    { uid := childUid
      capId := { domainId := callerId
                 subHandle := childSub
                 depth := parent.capId.depth + 1 }
      region :=
        { kind := .carve
          status := .exclusive
          access := access
          attributes := Attributes.empty }
      attributes := Attributes.empty
      parentUid := some parentUid
      childUids := #[]
      nextChildSub := 0 }

  CapaM.setMemCap childUid childCap

  -- Update parent: add child, bump nextChildSub
  let parent' := { parent with
    childUids := parent.childUids.push childUid
    nextChildSub := parent.nextChildSub + 1 }
  CapaM.setMemCap parentUid parent'

  -- Allocate handle in caller domain
  let caller' ← CapaM.getDomain callerId
  let (caller'', handle) := caller'.allocMemHandle
  let caller''' := caller''.addMemCap handle childUid
  CapaM.setDomain callerId caller'''

  -- Generate updates:
  -- Same rights as parent → no visible EPT change (child replaces parent sub-range at same rights)
  -- Different rights → remap the carved range at the child's (reduced) rights
  let updates : UpdateBatch :=
    if access.rights == parent.region.access.rights then
      []
    else
      [HwUpdate.mapMemory callerId access.start access.start access.size access.rights]

  pure (handle, childSub, updates)

-- ════════════════════════════════════════════════════════════════════
-- § alias — Create an aliased (shared) child region
-- ════════════════════════════════════════════════════════════════════

/-- Create an aliased child from a parent memory capability.
    Returns (childLocalHandle, childSubHandle). No UpdateBatch — aliases
    don't change the parent's EPT until sent. -/
def «alias» (callerId : DomainId) (parentHandle : LocalHandle)
    (access : Access) : CapaM (LocalHandle × SubHandle) := do
  let caller ← CapaM.getDomain callerId
  -- Preconditions
  CapaM.requireSealed caller
  CapaM.requireApi caller (·.canAlias)
  CapaM.requireNotFrozen caller parentHandle

  let parentUid ← match caller.lookupNodeId parentHandle with
    | some uid => pure uid
    | none => CapaM.throw .notFound
  let parent ← CapaM.getMemCap parentUid

  -- Access must be contained in parent
  CapaM.guard (Access.containedB access parent.region.access)
    .invalidAccess

  -- Parent must not be COMM or META (Rust returns permissionDenied)
  CapaM.guard (!parent.attributes.comm) .permissionDenied
  CapaM.guard (!parent.attributes.meta) .permissionDenied

  -- Aliases can overlap other aliases but NOT carved children (Rust returns invalidAccess)
  let s ← CapaM.getState
  CapaM.guard (!hasCarveOverlapForAlias s parent access) .invalidAccess

  -- Allocate child
  let childUid ← CapaM.allocNodeId
  let childSub := parent.nextChildSub

  let childCap : ExecMemCap :=
    { uid := childUid
      capId := { domainId := callerId
                 subHandle := childSub
                 depth := parent.capId.depth + 1 }
      region :=
        { kind := .alias
          status := .aliased
          access := access
          attributes := Attributes.empty }
      attributes := Attributes.empty
      parentUid := some parentUid
      childUids := #[]
      nextChildSub := 0 }

  CapaM.setMemCap childUid childCap

  -- Update parent
  let parent' := { parent with
    childUids := parent.childUids.push childUid
    nextChildSub := parent.nextChildSub + 1 }
  CapaM.setMemCap parentUid parent'

  -- Allocate handle in caller domain
  let caller' ← CapaM.getDomain callerId
  let (caller'', handle) := caller'.allocMemHandle
  let caller''' := caller''.addMemCap handle childUid
  CapaM.setDomain callerId caller'''

  pure (handle, childSub)

-- ════════════════════════════════════════════════════════════════════
-- § send — Send a memory capability to another domain
-- ════════════════════════════════════════════════════════════════════

/-- Send a memory capability to another domain.
    If receiver is unsealed: immediate transfer with EPT updates.
    If receiver is sealed: freeze sender's handle and create PendingMemCap. -/
def send (callerId : DomainId) (capHandle : LocalHandle)
    (receiverId : DomainId) (attrs : Attributes) (gpaHint : Option Nat)
    : CapaM UpdateBatch := do
  let caller ← CapaM.getDomain callerId
  CapaM.requireSealed caller
  CapaM.requireApi caller (·.canSend)
  CapaM.requireNotFrozen caller capHandle

  let capUid ← match caller.lookupNodeId capHandle with
    | some uid => pure uid
    | none => CapaM.throw .notFound
  let cap ← CapaM.getMemCap capUid

  -- Cap must not already be COMM or META.
  CapaM.guard (!cap.attributes.comm)
    .permissionDenied
  CapaM.guard (!cap.attributes.meta)
    .permissionDenied

  -- META send requires: exclusive status (which implies carve — only carved
  -- regions can be exclusive) and no children (a parent with children marked
  -- META would be excluded from EPT while its children remain mapped).
  if attrs.meta then do
    CapaM.guard (cap.region.status == .exclusive)
      .permissionDenied
    CapaM.guard cap.childUids.isEmpty
      .permissionDenied

  let receiver ← CapaM.getDomain receiverId
  CapaM.requireNotRevoked receiver

  -- Canonicalize: META → CLEAN+VITAL, COMM → CLEAN
  let attrs := canonicalizeAttrs attrs

  -- Determine GPA for the receiver (use hint or default to access.start)
  let gpa := gpaHint.getD cap.region.access.start

  if receiver.isUnsealed then do
    -- Immediate transfer: remove from caller, add to receiver
    CapaM.modifyDomain callerId (·.removeMemCap capHandle)

    -- Update cap ownership and apply attributes
    let cap' := { cap with
      capId := { cap.capId with domainId := receiverId }
      attributes := attrs }
    CapaM.setMemCap capUid cap'

    -- Allocate handle in receiver
    let recv ← CapaM.getDomain receiverId
    let (recv', recvHandle) := recv.allocMemHandle
    let recv'' := recv'.addMemCap recvHandle capUid
    CapaM.setDomain receiverId recv''

    -- Generate EPT updates using visible fragments (cap range minus carved children).
    -- This ensures carved children retained by the sender are NOT unmapped.
    -- Alias caps: NO unmap from caller (parent's EPT unaffected by alias removal)
    -- META caps: excluded from EPT entirely, no map/unmap
    let s ← CapaM.getState
    let fragments := visibleFragments s cap
    let gpaOffset := gpa - cap.region.access.start
    let callerUnmap : UpdateBatch :=
      if cap.region.kind == .carve then
        fragments.map fun (start, size) =>
          HwUpdate.unmapMemory callerId start size
      else
        []
    let receiverMap : UpdateBatch :=
      if attrs.meta then
        []
      else
        fragments.map fun (start, size) =>
          HwUpdate.mapMemory receiverId (start + gpaOffset) start
            size cap.region.access.rights
    let updates := callerUnmap ++ receiverMap
    pure updates
  else do
    -- Sealed receiver: check canReceiveAfterSeal (Rust returns permissionDenied)
    CapaM.guard receiver.policy.api.canReceiveAfterSeal
      .permissionDenied

    -- Apply attributes at freeze time (matches Rust: attrs set before pending)
    let cap' := { cap with attributes := attrs }
    CapaM.setMemCap capUid cap'

    -- Freeze sender's handle
    CapaM.modifyDomain callerId (·.freeze capHandle)

    -- Create pending entry in receiver
    let recv ← CapaM.getDomain receiverId
    let (recv', pendingId) := recv.allocPendingId
    let pending : PendingMemCap :=
      { pendingId := pendingId
        senderDomId := callerId
        senderHandle := capHandle
        capNodeId := capUid
        attributes := attrs }
    let recv'' := { recv' with pendingMem := recv'.pendingMem ++ [pending] }
    CapaM.setDomain receiverId recv''

    -- No EPT updates yet
    pure []

-- ════════════════════════════════════════════════════════════════════
-- § accept — Accept a pending memory capability
-- ════════════════════════════════════════════════════════════════════

/-- Accept a pending memory capability transfer.
    Removes the pending entry, transfers the cap, unfreezes sender. -/
def accept (receiverId : DomainId) (pendingId : Nat) (gpaOverride : Option Nat)
    : CapaM (LocalHandle × UpdateBatch) := do
  let receiver ← CapaM.getDomain receiverId

  -- Find pending entry
  let pending ← match receiver.pendingMem.find? (fun p => p.pendingId == pendingId) with
    | some p => pure p
    | none => CapaM.throw .notFound

  -- Check sender is not revoked
  let sender ← CapaM.getDomain pending.senderDomId
  CapaM.requireNotRevoked sender

  let cap ← CapaM.getMemCap pending.capNodeId

  -- Remove pending entry
  let receiver' := { receiver with
    pendingMem := receiver.pendingMem.filter (fun p => p.pendingId != pendingId) }

  -- Allocate handle and add cap to receiver
  let (receiver'', recvHandle) := receiver'.allocMemHandle
  let receiver''' := receiver''.addMemCap recvHandle pending.capNodeId
  CapaM.setDomain receiverId receiver'''

  -- Remove cap from sender's memCaps
  CapaM.modifyDomain pending.senderDomId (·.removeMemCap pending.senderHandle)

  -- Unfreeze sender's handle
  CapaM.modifyDomain pending.senderDomId (·.unfreeze pending.senderHandle)

  -- Update cap ownership
  let cap' := { cap with capId := { cap.capId with domainId := receiverId } }
  CapaM.setMemCap pending.capNodeId cap'

  -- Determine GPA
  let gpa := gpaOverride.getD cap.region.access.start

  -- Generate EPT updates using visible fragments (cap range minus carved children).
    -- Carved caps: unmap visible fragments from sender + map to receiver
    -- Alias caps: no unmap from sender (alias doesn't affect parent view)
    -- META caps: excluded from EPT, no map/unmap
    let s ← CapaM.getState
    let fragments := visibleFragments s cap
    let gpaOffset := gpa - cap.region.access.start
    let senderUnmap : UpdateBatch :=
      if cap.attributes.meta then []
      else if cap.region.kind == .carve then
        fragments.map fun (start, size) =>
          HwUpdate.unmapMemory pending.senderDomId start size
      else []
    let receiverMap : UpdateBatch :=
      if cap.attributes.meta then []
      else
        fragments.map fun (start, size) =>
          HwUpdate.mapMemory receiverId (start + gpaOffset) start
            size cap.region.access.rights
    let updates := senderUnmap ++ receiverMap

  pure (recvHandle, updates)

-- ════════════════════════════════════════════════════════════════════
-- § reject — Reject a pending memory capability
-- ════════════════════════════════════════════════════════════════════

/-- Reject a pending memory capability transfer.
    Removes the pending entry and unfreezes sender's handle. -/
def reject (receiverId : DomainId) (pendingId : Nat) : CapaM Unit := do
  let receiver ← CapaM.getDomain receiverId

  -- Find pending entry
  let pending ← match receiver.pendingMem.find? (fun p => p.pendingId == pendingId) with
    | some p => pure p
    | none => CapaM.throw .notFound

  -- Remove pending entry
  let receiver' := { receiver with
    pendingMem := receiver.pendingMem.filter (fun p => p.pendingId != pendingId) }
  CapaM.setDomain receiverId receiver'

  -- Unfreeze sender's handle
  CapaM.modifyDomain pending.senderDomId (·.unfreeze pending.senderHandle)

-- ════════════════════════════════════════════════════════════════════
-- § revoke — Revoke a memory capability subtree
-- ════════════════════════════════════════════════════════════════════

/-- Revoke a child memory capability and its entire subtree.
    Returns UpdateBatch with unmapMemory/zeroMemory for each revoked cap.
    Caps with vital=true trigger domain revocation. -/
partial def revoke (callerId : DomainId) (parentHandle : LocalHandle)
    (childSub : SubHandle) : CapaM UpdateBatch := do
  let caller ← CapaM.getDomain callerId
  CapaM.requireSealed caller
  CapaM.requireApi caller (·.canRevoke)
  CapaM.requireNotFrozen caller parentHandle

  let parentUid ← match caller.lookupNodeId parentHandle with
    | some uid => pure uid
    | none => CapaM.throw .notFound
  let parent ← CapaM.getMemCap parentUid

  -- Find the child by SubHandle
  let s ← CapaM.getState
  let childUid ← match parent.childUids.toList.find? (fun uid =>
      match s.getMemCap uid with
      | some c => c.capId.subHandle == childSub
      | none => false) with
    | some uid => pure uid
    | none => CapaM.throw .notFound

  -- Collect entire subtree
  let s' ← CapaM.getState
  let subtreeUids := s'.collectSubtree childUid

  -- Process each cap in subtree: generate updates and clean up
  let mut updates : UpdateBatch := []
  let mut vitalDomains : List DomainId := []

  for uid in subtreeUids do
    let cap ← CapaM.getMemCap uid
    let ownerId := cap.capId.domainId

    -- Unmap from owning domain (skip META/COMM — not in EPT)
    if !cap.attributes.meta && !cap.attributes.comm then
      updates := updates ++ [HwUpdate.unmapMemory ownerId
        cap.region.access.start cap.region.access.size]

    -- Unregister COMM binding
    if cap.attributes.comm then
      updates := updates ++ [HwUpdate.uncommRegion ownerId ownerId 0
        cap.region.access.start cap.region.access.size]

    -- Zero if CLEAN
    if cap.attributes.clean then
      updates := updates ++ [HwUpdate.zeroMemory
        cap.region.access.start cap.region.access.size]

    -- Track vital domains
    if cap.attributes.vital then
      vitalDomains := vitalDomains ++ [ownerId]

    -- Find and remove the handle from the owning domain
    let owner ← CapaM.getDomain ownerId
    match findHandle owner uid with
    | some h =>
      CapaM.modifyDomain ownerId (·.removeMemCap h)
    | none => pure ()

    -- Remove the cap from global store
    CapaM.modifyState (·.removeMemCap uid)

  -- Remove child from parent's childUids
  let parentRefresh ← CapaM.getMemCap parentUid
  let parent' := { parentRefresh with
    childUids := parentRefresh.childUids.filter (· != childUid) }
  CapaM.setMemCap parentUid parent'

  -- Handle vital domains: revoke the owning domain
  for domId in vitalDomains do
    let dom ← CapaM.getDomain domId
    if !dom.isRevoked then
      let fallback := (← CapaM.getState).findFallback domId
      CapaM.modifyDomain domId (fun d => { d with status := .revoked })
      updates := updates ++ [HwUpdate.revokeDomain domId fallback]

  pure updates

end LeanExec
