/-
  LeanExec.Operations.Channel — Channel capability operations.

  Channels allow domains to communicate: a domain obtains a channel
  capability for a target, then sends it to another domain which can
  accept or reject the pending transfer.
-/
import LeanExec.Monad

namespace LeanExec

open ThemisCapa

/-- Get a channel capability for a target domain.

    Caller must be sealed with GETCHAN API.  `targetHandle` must refer to
    a child domain capability in the caller's `domCaps`, and the target
    domain must itself be sealed.  Returns a new local handle added to
    the caller's `chanCaps`. -/
def getChan (callerId : DomainId) (targetHandle : LocalHandle)
    : CapaM LocalHandle := do
  let caller ← CapaM.getDomain callerId
  CapaM.requireSealed caller
  CapaM.requireApi caller (·.canGetChan)
  -- Resolve targetHandle → target domain id
  let targetId ← match caller.lookupDomId targetHandle with
    | some id => pure id
    | none    => CapaM.throw .notFound
  -- Target must be sealed
  let target ← CapaM.getDomain targetId
  CapaM.requireSealed target
  -- Allocate a channel handle in the caller
  let caller ← CapaM.getDomain callerId
  let (caller, chanHandle) := caller.allocDomHandle
  let caller := caller.addChanCap chanHandle targetId
  CapaM.setDomain callerId caller
  pure chanHandle

/-- Send a channel capability to another domain.

    Caller must be sealed with SEND API.  `chanHandle` must be a valid,
    non-frozen entry in the caller's `chanCaps`.  The receiver must not
    be revoked.

    - **Unsealed receiver**: immediate transfer — the channel cap moves
      from caller to receiver.
    - **Sealed receiver**: the caller's handle is frozen and a
      `PendingDomCap` is created in the receiver's `pendingDom`. -/
def sendChannel (callerId : DomainId) (chanHandle : LocalHandle)
    (receiverId : DomainId) : CapaM Unit := do
  let caller ← CapaM.getDomain callerId
  CapaM.requireSealed caller
  CapaM.requireApi caller (·.canSend)
  -- chanHandle must exist in caller's chanCaps
  let targetId ← match caller.lookupChanTarget chanHandle with
    | some id => pure id
    | none    => CapaM.throw .notFound
  -- chanHandle must not be frozen
  CapaM.requireNotFrozen caller chanHandle
  -- Receiver must not be revoked
  let receiver ← CapaM.getDomain receiverId
  CapaM.requireNotRevoked receiver
  if receiver.isSealed then
    -- Sealed receiver: must have canReceiveAfterSeal
    CapaM.guard receiver.policy.api.canReceiveAfterSeal .permissionDenied
    -- Freeze caller's handle
    let caller ← CapaM.getDomain callerId
    let caller := caller.freeze chanHandle
    CapaM.setDomain callerId caller
    -- Create pending entry in receiver
    let receiver ← CapaM.getDomain receiverId
    let (receiver, pendId) := receiver.allocPendingId
    let pending : PendingDomCap :=
      { pendingId    := pendId
        senderDomId  := callerId
        senderHandle := chanHandle
        targetDomId  := targetId }
    let receiver := { receiver with pendingDom := receiver.pendingDom ++ [pending] }
    CapaM.setDomain receiverId receiver
  else
    -- Unsealed receiver: immediate transfer
    let caller ← CapaM.getDomain callerId
    let caller := caller.removeChanCap chanHandle
    CapaM.setDomain callerId caller
    let receiver ← CapaM.getDomain receiverId
    let (receiver, newHandle) := receiver.allocDomHandle
    let receiver := receiver.addChanCap newHandle targetId
    CapaM.setDomain receiverId receiver

/-- Accept a pending channel capability.

    Removes the `PendingDomCap` matching `pendingId` from the receiver's
    `pendingDom`, adds the channel to the receiver's `chanCaps`, and
    unfreezes the sender's handle.  Returns the new local handle. -/
def acceptChannel (receiverId : DomainId) (pendingId : Nat)
    : CapaM LocalHandle := do
  let receiver ← CapaM.getDomain receiverId
  let pending ← match receiver.pendingDom.find? (fun p => p.pendingId == pendingId) with
    | some p => pure p
    | none   => CapaM.throw .notFound
  -- Remove pending entry
  let receiver := { receiver with
    pendingDom := receiver.pendingDom.filter (fun p => p.pendingId != pendingId) }
  -- Allocate handle & add channel cap
  let (receiver, newHandle) := receiver.allocDomHandle
  let receiver := receiver.addChanCap newHandle pending.targetDomId
  CapaM.setDomain receiverId receiver
  -- Unfreeze sender's handle
  CapaM.modifyDomain pending.senderDomId (·.unfreeze pending.senderHandle)
  pure newHandle

/-- Reject a pending channel capability.

    Removes the `PendingDomCap` matching `pendingId` from the receiver's
    `pendingDom` and unfreezes the sender's handle. -/
def rejectChannel (receiverId : DomainId) (pendingId : Nat) : CapaM Unit := do
  let receiver ← CapaM.getDomain receiverId
  let pending ← match receiver.pendingDom.find? (fun p => p.pendingId == pendingId) with
    | some p => pure p
    | none   => CapaM.throw .notFound
  -- Remove pending entry
  let receiver := { receiver with
    pendingDom := receiver.pendingDom.filter (fun p => p.pendingId != pendingId) }
  CapaM.setDomain receiverId receiver
  -- Unfreeze sender's handle
  CapaM.modifyDomain pending.senderDomId (·.unfreeze pending.senderHandle)

end LeanExec
