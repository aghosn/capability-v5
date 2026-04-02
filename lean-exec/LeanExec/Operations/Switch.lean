/-
  LeanExec.Operations.Switch — VP lifecycle and switch operations.

  Implements the VP state machine: forward/return switch, interrupt delivery,
  and VP/COMM registration.
-/
import LeanExec.Monad

namespace LeanExec

open ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § Helpers
-- ════════════════════════════════════════════════════════════════════

/-- Find the VP index in a domain that is Running on the given core. -/
private def findVpOnCore (dom : ExecDomain) (coreId : CoreId) : Option (Nat × VProcessor) :=
  let rec go (i : Nat) : Option (Nat × VProcessor) :=
    if h : i < dom.vps.size then
      let vp := dom.vps[i]
      match vp.runState with
      | .running c _ => if c == coreId then some (i, vp) else go (i + 1)
      | _ => go (i + 1)
    else none
  go 0

/-- Update a VP at a given index in a domain. -/
private def updateVp (dom : ExecDomain) (idx : Nat) (newState : VpRunState) : ExecDomain :=
  if h : idx < dom.vps.size then
    let vp := dom.vps[idx]
    { dom with vps := dom.vps.set (Fin.mk idx h) { vp with runState := newState } }
  else dom

/-- Find a VP by its VpId in a domain. Returns (array index, vp). -/
private def findVpById (dom : ExecDomain) (vpId : VpId) : Option (Nat × VProcessor) :=
  let rec go (i : Nat) : Option (Nat × VProcessor) :=
    if h : i < dom.vps.size then
      let vp := dom.vps[i]
      if vp.id == vpId then some (i, vp) else go (i + 1)
    else none
  go 0

-- ════════════════════════════════════════════════════════════════════
-- § addVp — Register a virtual processor with COMM page
-- ════════════════════════════════════════════════════════════════════

def addVp (callerId : DomainId) (childHandle : LocalHandle)
    (commHandle : LocalHandle) (vpId : VpId)
    : CapaM UpdateBatch := do
  let caller ← CapaM.getDomain callerId
  CapaM.requireSealed caller
  CapaM.requireApi caller (·.canSet)
  let childId ← match caller.lookupDomId childHandle with
    | some id => pure id
    | none => CapaM.throw .notFound
  let child ← CapaM.getDomain childId
  CapaM.requireUnsealed child
  CapaM.guard (vpId < child.policy.numVps) (.invalidOperation "vpId exceeds policy.numVps")
  CapaM.guard (findVpById child vpId |>.isNone) (.invalidOperation "VP already exists")
  let commUid ← match caller.lookupNodeId commHandle with
    | some uid => pure uid
    | none => CapaM.throw .notFound
  let comm ← CapaM.getMemCap commUid
  CapaM.guard (comm.region.kind == .carve)
    (.invalidOperation "COMM cap must be carved")
  CapaM.guard (comm.region.status == .exclusive)
    (.invalidOperation "COMM cap must be exclusive")
  CapaM.guard (!comm.attributes.comm)
    (.invalidOperation "cap already marked COMM")
  -- Add VP and COMM binding to child
  let child ← CapaM.getDomain childId
  let newVp : VProcessor := { id := vpId, runState := .available }
  let child' := { child with
    vps := child.vps.push newVp
    commBindings := child.commBindings ++ [(callerId, vpId, commUid)] }
  CapaM.setDomain childId child'
  -- Set COMM attribute on memory cap
  let comm ← CapaM.getMemCap commUid
  let comm' := { comm with attributes := { comm.attributes with comm := true } }
  CapaM.setMemCap commUid comm'
  pure [HwUpdate.commRegion callerId childId vpId
    comm.region.access.start comm.region.access.size]

-- ════════════════════════════════════════════════════════════════════
-- § registerComm — Register COMM page for an existing VP
-- ════════════════════════════════════════════════════════════════════

def registerComm (callerId : DomainId) (commHandle : LocalHandle)
    (childDomId : DomainId) (vpId : VpId)
    : CapaM UpdateBatch := do
  let caller ← CapaM.getDomain callerId
  CapaM.requireSealed caller
  CapaM.requireApi caller (·.canSet)
  -- Resolve cap handle and check it is not frozen
  CapaM.requireNotFrozen caller commHandle
  let commUid ← match caller.lookupNodeId commHandle with
    | some uid => pure uid
    | none => CapaM.throw .notFound
  let comm ← CapaM.getMemCap commUid
  CapaM.guard (comm.region.kind == .carve)
    .permissionDenied
  CapaM.guard (comm.region.status == .exclusive)
    .permissionDenied
  CapaM.guard (comm.childUids.isEmpty)
    .permissionDenied
  CapaM.guard (!comm.attributes.meta && !comm.attributes.comm)
    (.invalidOperation "capability already carries the COMM or META attribute")
  -- Validate child domain and VP
  let child ← CapaM.getDomain childDomId
  CapaM.guard (vpId < child.policy.numVps)
    (.invalidOperation "vp_id exceeds child domain VP count")
  -- Check no existing COMM binding for this VP
  CapaM.guard (child.commBindings.all fun (_, vid, _) => vid != vpId)
    (.invalidOperation "VP already has a COMM binding")
  -- Record COMM binding
  let child ← CapaM.getDomain childDomId
  let child' := { child with commBindings := child.commBindings ++ [(callerId, vpId, commUid)] }
  CapaM.setDomain childDomId child'
  -- Mark cap as COMM (canonicalize: COMM implies CLEAN)
  let comm ← CapaM.getMemCap commUid
  let comm' := { comm with attributes := canonicalizeAttrs { comm.attributes with comm := true } }
  CapaM.setMemCap commUid comm'
  pure [HwUpdate.commRegion callerId childDomId vpId
    comm.region.access.start comm.region.access.size]

-- ════════════════════════════════════════════════════════════════════
-- § switchForward — Forward switch to a child domain's VP
-- ════════════════════════════════════════════════════════════════════

def switchForward (callerId : DomainId) (targetHandle : LocalHandle)
    (coreId : CoreId) (targetVpId : VpId)
    : CapaM SwitchResult := do
  let caller ← CapaM.getDomain callerId
  CapaM.requireSealed caller
  CapaM.requireApi caller (·.canSwitch)
  -- Resolve target: domCaps or chanCaps
  let targetId ← match caller.lookupDomId targetHandle with
    | some id => pure id
    | none => match caller.lookupChanTarget targetHandle with
      | some id => pure id
      | none => CapaM.throw .notFound
  let target ← CapaM.getDomain targetId
  CapaM.requireSealed target
  CapaM.guard (target.policy.cores.contains coreId) (.permissionDenied)
  -- Find caller's VP running on this core
  let (callerVpIdx, callerVp) ← match findVpOnCore caller coreId with
    | some v => pure v
    | none => CapaM.throw (.invalidOperation "no caller VP on this core")
  let callerVpId := callerVp.id
  let callerCtx : Option VpCallContext := match callerVp.runState with
    | .running _ ctx => ctx
    | _ => none
  -- Find target VP
  let (targetVpIdx, targetVp) ← match findVpById target targetVpId with
    | some v => pure v
    | none => CapaM.throw .notFound
  -- Check target VP state
  match targetVp.runState with
  | .available =>
    -- Caller: Running → Locked
    let caller' := updateVp caller callerVpIdx
      (.locked targetId targetVpId callerCtx)
    CapaM.setDomain callerId caller'
    -- Target: Available → Running
    let target' := updateVp target targetVpIdx
      (.running coreId (some ⟨callerId, callerVpId⟩))
    CapaM.setDomain targetId target'
    -- Update core
    CapaM.setCoreState coreId (.runningDomain targetId targetVpId)
    pure { fromDomain := callerId, toDomain := targetId, fromVpId := some callerVpId, toVpId := some targetVpId, isReturn := false, vector := none }
  | .suspended suspDomId suspVpId _ =>
    -- Caller: Running → Locked
    let caller' := updateVp caller callerVpIdx
      (.locked targetId targetVpId callerCtx)
    CapaM.setDomain callerId caller'
    -- Target: Suspended → Running
    let target' := updateVp target targetVpIdx
      (.running coreId (some ⟨callerId, callerVpId⟩))
    CapaM.setDomain targetId target'
    -- Clear the interrupted callee VP at (suspDomId, suspVpId) if Interrupted
    let suspDom ← CapaM.getDomain suspDomId
    match findVpById suspDom suspVpId with
    | some (sIdx, sVp) =>
      match sVp.runState with
      | .interrupted _ =>
        let suspDom ← CapaM.getDomain suspDomId
        let suspDom' := updateVp suspDom sIdx .available
        CapaM.setDomain suspDomId suspDom'
      | _ => pure ()
    | none => pure ()
    CapaM.setCoreState coreId (.runningDomain targetId targetVpId)
    pure { fromDomain := callerId, toDomain := targetId, fromVpId := some callerVpId, toVpId := some targetVpId, isReturn := false, vector := none }
  | _ => CapaM.throw (.invalidOperation "target VP is not available")

-- ════════════════════════════════════════════════════════════════════
-- § switchReturn — Return switch to the caller
-- ════════════════════════════════════════════════════════════════════

def switchReturn (calleeDomId : DomainId) (coreId : CoreId)
    : CapaM SwitchResult := do
  let callee ← CapaM.getDomain calleeDomId
  -- Find callee's VP running on this core
  let (calleeVpIdx, calleeVp) ← match findVpOnCore callee coreId with
    | some v => pure v
    | none => CapaM.throw (.invalidOperation "no callee VP on this core")
  -- Must have a caller context
  let callerCtx ← match calleeVp.runState with
    | .running _ (some ctx) => pure ctx
    | _ => CapaM.throw (.invalidOperation "no caller context for return switch")
  -- Find caller domain and its locked VP
  let callerDom ← CapaM.getDomain callerCtx.domainId
  let (callerVpIdx, callerVp) ← match findVpById callerDom callerCtx.vpId with
    | some v => pure v
    | none => CapaM.throw (.invalidOperation "caller VP not found")
  -- Verify caller VP is locked waiting for this callee
  let prevCaller ← match callerVp.runState with
    | .locked did vid prev =>
      if did == calleeDomId && vid == calleeVp.id then pure prev
      else CapaM.throw (.invalidOperation "caller VP locked for different callee")
    | _ => CapaM.throw (.invalidOperation "caller VP not in locked state")
  -- Callee VP: Running → Available
  let callee' := updateVp callee calleeVpIdx .available
  CapaM.setDomain calleeDomId callee'
  -- Caller VP: Locked → Running
  let callerDom' := updateVp callerDom callerVpIdx (.running coreId prevCaller)
  CapaM.setDomain callerCtx.domainId callerDom'
  -- Update core
  CapaM.setCoreState coreId (.runningDomain callerCtx.domainId callerCtx.vpId)
  pure { fromDomain := calleeDomId, toDomain := callerCtx.domainId, fromVpId := some calleeVp.id, toVpId := some callerCtx.vpId, isReturn := true, vector := none }

-- ════════════════════════════════════════════════════════════════════
-- § routeInterrupt — Walk interrupt policies to find the handler
-- ════════════════════════════════════════════════════════════════════

/-- Look up the interrupt policy for a specific vector. -/
private def getVectorPolicy (policy : InterruptPolicy) (vector : Nat) : VectorPolicy :=
  match policy.perVector.find? (fun p => p.1 == vector) with
  | some (_, vis) => vis
  | none => policy.defaultPolicy

/-- Route an interrupt through the domain hierarchy to find the handler.
    Walks from startDomId up through parentDomId, checking interrupt
    policies. Returns the ID of the first domain with Deliver policy
    (VectorPolicy.deliver). Root always delivers if reached. -/
def routeInterrupt (startDomId : DomainId) (vector : Nat) : CapaM DomainId := do
  let mut curDomId := startDomId
  for _ in List.range 100 do
    let dom ← CapaM.getDomain curDomId
    let vis := getVectorPolicy dom.policy.interrupts vector
    match vis with
    | .deliver => return curDomId
    | .deliverAndClear => -- REPORT: note, continue to parent
      match dom.parentDomId with
      | some pid => curDomId := pid
      | none => return curDomId
    | .deny => -- NOTREPORT: skip, continue to parent
      match dom.parentDomId with
      | some pid => curDomId := pid
      | none => return curDomId
  CapaM.throw (.invalidOperation "interrupt routing exceeded max depth")

-- ════════════════════════════════════════════════════════════════════
-- § deliverInterrupt — Lazy-unwind interrupt delivery
-- ════════════════════════════════════════════════════════════════════

/-- Walk the VP call chain from the leaf VP back to the handler domain,
    applying lazy-unwind state transitions along the way. -/
partial def deliverInterrupt (vector : Nat) (handlerDomId : DomainId) (coreId : CoreId)
    : CapaM SwitchResult := do
  let s ← CapaM.getState
  -- Find the leaf: which domain/VP is running on this core
  let (leafDomId, leafVpId) ← match s.getCoreState coreId with
    | some (.runningDomain d v) => pure (d, v)
    | _ => CapaM.throw (.invalidOperation "no VP running on core")
  -- Short-circuit: handler is the leaf itself (self-delivery)
  if leafDomId == handlerDomId then
    CapaM.setCoreState coreId (.runningDomain leafDomId leafVpId)
    return { fromDomain := leafDomId, toDomain := handlerDomId,
             fromVpId := some leafVpId, toVpId := some leafVpId,
             isReturn := true, vector := some vector }
  -- Mark leaf VP as Interrupted
  let leafDom ← CapaM.getDomain leafDomId
  let (leafIdx, leafVp) ← match findVpById leafDom leafVpId with
    | some v => pure v
    | none => CapaM.throw (.invalidOperation "leaf VP not found")
  let callerCtx ← match leafVp.runState with
    | .running _ (some ctx) => pure ctx
    | _ => CapaM.throw (.invalidOperation "leaf VP has no caller context")
  let leafDom' := updateVp leafDom leafIdx (.interrupted vector)
  CapaM.setDomain leafDomId leafDom'
  -- Walk the chain: follow caller contexts through Locked VPs until we find the handler
  let mut curDomId := callerCtx.domainId
  let mut curVpId := callerCtx.vpId
  let mut found := false
  for _ in List.range 100 do  -- bounded iteration for safety
    if found then break
    if curDomId == handlerDomId then
      -- This is the handler — unlock it: Locked → Running
      let hDom ← CapaM.getDomain curDomId
      let (hIdx, hVp) ← match findVpById hDom curVpId with
        | some v => pure v
        | none => CapaM.throw (.invalidOperation "handler VP not found")
      let prevCaller ← match hVp.runState with
        | .locked _ _ prev => pure prev
        | _ => CapaM.throw (.invalidOperation "handler VP not locked")
      let hDom' := updateVp hDom hIdx (.running coreId prevCaller)
      CapaM.setDomain curDomId hDom'
      CapaM.setCoreState coreId (.runningDomain curDomId curVpId)
      found := true
    else
      -- Intermediate VP: Locked → Suspended
      let iDom ← CapaM.getDomain curDomId
      let (iIdx, iVp) ← match findVpById iDom curVpId with
        | some v => pure v
        | none => CapaM.throw (.invalidOperation "intermediate VP not found")
      match iVp.runState with
      | .locked calleeDid calleeVid prevCaller =>
        let iDom' := updateVp iDom iIdx (.suspended calleeDid calleeVid vector)
        CapaM.setDomain curDomId iDom'
        -- Follow the chain to the next caller
        match prevCaller with
        | some ctx =>
          curDomId := ctx.domainId
          curVpId := ctx.vpId
        | none => CapaM.throw (.invalidOperation "chain broken — no previous caller")
      | _ => CapaM.throw (.invalidOperation "intermediate VP not in locked state")
  if !found then
    CapaM.throw (.invalidOperation "handler domain not found in call chain")
  pure { fromDomain := leafDomId, toDomain := handlerDomId, fromVpId := some leafVpId, toVpId := some curVpId, isReturn := true, vector := some vector }

/-- Combined routing + delivery: route the interrupt through policies,
    then walk the VP call chain to deliver it. -/
def handleInterrupt (vector : Nat) (startDomId : DomainId) (coreId : CoreId)
    : CapaM SwitchResult := do
  let handlerDomId ← routeInterrupt startDomId vector
  deliverInterrupt vector handlerDomId coreId

-- ════════════════════════════════════════════════════════════════════
-- § switch — Unified dispatch
-- ════════════════════════════════════════════════════════════════════

def switch (domId : DomainId) (coreId : CoreId) (targetHandle : Option LocalHandle)
    (vpId : Option VpId) : CapaM SwitchResult := do
  match targetHandle, vpId with
  | some th, some vid => switchForward domId th coreId vid
  | none, none => switchReturn domId coreId
  | _, _ => CapaM.throw (.invalidOperation "switch requires both targetHandle and vpId, or neither")

end LeanExec
