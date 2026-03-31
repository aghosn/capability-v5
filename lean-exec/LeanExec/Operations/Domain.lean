/-
  LeanExec.Operations.Domain — Domain lifecycle operations.

  Implements create, seal, and revokeDomain for the executable
  capability engine.
-/
import LeanExec.Monad

namespace LeanExec

open ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § Domain lifecycle operations
-- ════════════════════════════════════════════════════════════════════

/-- Create a child domain.
    Returns (localHandle, newDomainId, updateBatch). -/
def create (callerId : DomainId) (childPolicy : DomainPolicy)
    : CapaM (LocalHandle × DomainId × UpdateBatch) := do
  let caller ← CapaM.getDomain callerId
  CapaM.requireSealed caller
  CapaM.requireApi caller (·.canCreate)
  -- Policy monotonicity: child cores ⊆ caller cores
  CapaM.guard (childPolicy.cores.all (caller.policy.cores.contains ·))
    .monotonicityViolation
  -- Policy monotonicity: child API ⊆ caller API
  CapaM.guard (MonitorAPI.subsetB childPolicy.api caller.policy.api)
    .monotonicityViolation
  -- Allocate new domain
  let newId ← CapaM.allocDomainId
  let newDom := ExecDomain.empty newId (some callerId) childPolicy
  CapaM.modifyState (·.setDomain newId newDom)
  -- Add domain capability handle in caller
  let caller' ← CapaM.getDomain callerId
  let (caller'', handle) := caller'.allocDomHandle
  CapaM.setDomain callerId (caller''.addDomCap handle newId)
  pure (handle, newId, [HwUpdate.createDomain newId (some callerId)])

/-- Seal a domain (freeze its configuration). -/
def «seal» (callerId : DomainId) (childHandle : LocalHandle) : CapaM Unit := do
  let caller ← CapaM.getDomain callerId
  CapaM.requireSealed caller
  CapaM.requireApi caller (·.canSeal)
  let targetId ← match caller.lookupDomId childHandle with
    | some id => pure id
    | none => CapaM.throw .notFound
  let target ← CapaM.getDomain targetId
  CapaM.requireUnsealed target
  -- Set status to sealed
  CapaM.modifyDomain targetId (fun d => { d with status := .sealed })
  -- Create VPs based on policy.numVps (if not already created)
  if target.vps.isEmpty then
    let vps : Array VProcessor := ((List.range target.policy.numVps).map
      (fun i => { id := i, runState := .available })).toArray
    CapaM.modifyDomain targetId (fun d => { d with vps := vps })

/-- Recursive helper: revoke a single domain by ID, collecting all HW updates. -/
private partial def revokeOneDomain (targetId : DomainId) : CapaM UpdateBatch := do
  let target ← CapaM.getDomain targetId
  -- Save lists before modification
  let memCapsList := target.memCaps
  let domCapsList := target.domCaps
  let pendingMemList := target.pendingMem
  let pendingDomList := target.pendingDom
  let commBindingsList := target.commBindings
  -- 1. Set status to revoked
  CapaM.modifyDomain targetId (fun d => { d with status := .revoked })
  -- 2. Process memory caps: collect subtrees, generate unmap/zero updates, remove
  let mut memUpdates : UpdateBatch := []
  for (_, uid) in memCapsList do
    let s ← CapaM.getState
    let subtree := s.collectSubtree uid
    for subUid in subtree do
      let s' ← CapaM.getState
      match s'.getMemCap subUid with
      | some cap =>
        memUpdates := memUpdates ++
          [HwUpdate.unmapMemory targetId cap.region.access.start cap.region.access.size]
        if cap.attributes.clean then
          memUpdates := memUpdates ++
            [HwUpdate.zeroMemory cap.region.access.start cap.region.access.size]
        CapaM.modifyState (·.removeMemCap subUid)
      | none => pure ()
  -- 3. Recursively revoke child domains
  let mut childUpdates : UpdateBatch := []
  for (_, childId) in domCapsList do
    let upd ← revokeOneDomain childId
    childUpdates := childUpdates ++ upd
  -- 4. Unfreeze pending memory cap senders
  for pm in pendingMemList do
    let s ← CapaM.getState
    match s.getDomain pm.senderDomId with
    | some _ => CapaM.modifyDomain pm.senderDomId (·.unfreeze pm.senderHandle)
    | none => pure ()
  -- 5. Unfreeze pending domain cap senders
  for pd in pendingDomList do
    let s ← CapaM.getState
    match s.getDomain pd.senderDomId with
    | some _ => CapaM.modifyDomain pd.senderDomId (·.unfreeze pd.senderHandle)
    | none => pure ()
  -- 6. Process COMM bindings (generate uncommRegion updates)
  let mut commUpdates : UpdateBatch := []
  for (commTargetDom, vpId, memCapUid) in commBindingsList do
    let s ← CapaM.getState
    match s.getMemCap memCapUid with
    | some cap =>
      commUpdates := commUpdates ++
        [HwUpdate.uncommRegion targetId commTargetDom vpId
          cap.region.access.start cap.region.access.size]
    | none => pure ()
  -- 7. Clear target's capability lists
  CapaM.modifyDomain targetId (fun d =>
    { d with memCaps := [], domCaps := [], chanCaps := [],
             pendingMem := [], pendingDom := [], commBindings := [] })
  -- 8. Set cores running this domain to idle
  let s ← CapaM.getState
  for i in List.range s.cores.size do
    let s' ← CapaM.getState
    match s'.getCoreState i with
    | some (.runningDomain d _) =>
      if d == targetId then CapaM.setCoreState i .idle
    | _ => pure ()
  -- 9. Find fallback domain and generate revokeDomain update
  let s ← CapaM.getState
  let fallbackId := s.findFallback targetId
  pure (memUpdates ++ childUpdates ++ commUpdates ++
    [HwUpdate.revokeDomain targetId fallbackId])

/-- Revoke a domain and all its children. -/
partial def revokeDomain (callerId : DomainId) (childHandle : LocalHandle)
    : CapaM UpdateBatch := do
  let caller ← CapaM.getDomain callerId
  CapaM.requireSealed caller
  CapaM.requireApi caller (·.canRevoke)
  -- childHandle must exist in caller's domCaps (not chanCaps)
  let targetId ← match caller.lookupDomId childHandle with
    | some id => pure id
    | none => CapaM.throw .notFound
  let target ← CapaM.getDomain targetId
  CapaM.requireNotRevoked target
  -- Remove handle from caller's domCaps
  CapaM.modifyDomain callerId (·.removeDomCap childHandle)
  -- Recursively revoke the target and its children
  revokeOneDomain targetId

end LeanExec
