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

/-- Recursive helper: revoke a single domain by ID, collecting all HW updates.
    Public so Memory.lean's VITAL cascade can call it. -/
partial def revokeOneDomain (targetId : DomainId) : CapaM UpdateBatch := do
  let target ← CapaM.getDomain targetId
  -- Save lists before modification
  let memCapsList := target.memCaps
  let domCapsList := target.domCaps
  let pendingMemList := target.pendingMem
  let pendingDomList := target.pendingDom
  let commBindingsList := target.commBindings
  -- 1. Set status to revoked
  CapaM.modifyDomain targetId (fun d => { d with status := .revoked })
  -- 2. Process memory caps: collect subtrees, generate unmap/zero updates, remove.
  --    Also remove root cap from external parent's childUids and generate recovery
  --    maps for cross-domain carved caps (matches Rust's revoke_domain_subtree).
  let mut memUpdates : UpdateBatch := []
  for (_, uid) in memCapsList do
    let s ← CapaM.getState
    match s.getMemCap uid with
    | some rootCap =>
      -- Remove root cap from parent's childUids + recovery map
      match rootCap.parentUid with
      | some pUid =>
        let s1 ← CapaM.getState
        match s1.getMemCap pUid with
        | some parentCap =>
          CapaM.setMemCap pUid { parentCap with
            childUids := parentCap.childUids.filter (· != uid) }
          -- Recovery map: carved + cross-domain + parent owner not revoked
          if rootCap.region.kind == .carve then
            let parentOwner := parentCap.capId.domainId
            if parentOwner != rootCap.capId.domainId then
              let pDom ← CapaM.getDomain parentOwner
              if !pDom.isRevoked then
                memUpdates := memUpdates ++ [HwUpdate.mapMemory parentOwner
                  rootCap.region.access.start rootCap.region.access.start
                  rootCap.region.access.size parentCap.region.access.rights]
        | none => pure ()
      | none => pure ()
      -- Collect and process subtree
      let s2 ← CapaM.getState
      let subtree := s2.collectSubtree uid
      for subUid in subtree do
        let s' ← CapaM.getState
        match s'.getMemCap subUid with
        | some cap =>
          let capOwner := cap.capId.domainId
          -- Unmap from owning domain (skip META/COMM — not in EPT).
          -- Also skip caps owned by the target domain itself: RevokeDomain
          -- tears down the entire EPT, so individual unmaps are redundant.
          if capOwner != targetId && !cap.attributes.meta && !cap.attributes.comm then
            memUpdates := memUpdates ++
              [HwUpdate.unmapMemory capOwner cap.region.access.start cap.region.access.size]
          -- Unregister COMM binding
          if cap.attributes.comm then
            memUpdates := memUpdates ++
              [HwUpdate.uncommRegion capOwner capOwner 0
                cap.region.access.start cap.region.access.size]
          -- Zero if CLEAN
          if cap.attributes.clean then
            memUpdates := memUpdates ++
              [HwUpdate.zeroMemory cap.region.access.start cap.region.access.size]
          -- Remove handle from owning domain (if different from target)
          if capOwner != targetId then
            let ownerDom ← CapaM.getDomain capOwner
            match (ownerDom.memCaps.find? (fun p => p.2 == subUid)).map Prod.fst with
            | some h => CapaM.modifyDomain capOwner (·.removeMemCap h)
            | none => pure ()
          CapaM.modifyState (·.removeMemCap subUid)
        | none => pure ()
    | none => pure ()  -- already processed by a previous iteration
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
  for (commTargetDom, vpId, capNodeId) in commBindingsList do
    let s ← CapaM.getState
    match s.getMemCap capNodeId with
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
