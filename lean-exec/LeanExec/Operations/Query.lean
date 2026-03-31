/-
  LeanExec.Operations.Query — Query and attestation operations.

  Implements computeAddressSpace, enumeratePending, attest, and
  attestSelf for inspecting domain state without modification.
-/
import LeanExec.Monad

namespace LeanExec

open ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § Helpers — range subtraction for address space computation
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

-- ════════════════════════════════════════════════════════════════════
-- § computeAddressSpace — merged address space view
-- ════════════════════════════════════════════════════════════════════

/-- Get the merged address space view for a domain.

    Returns (start, size, rights) tuples representing visible memory.
    For each memCap owned by the domain, includes its access range
    minus any carved children. -/
def computeAddressSpace (domId : DomainId) : CapaM (List (Nat × Nat × Rights)) := do
  let dom ← CapaM.getDomain domId
  let s ← CapaM.getState
  let entries := dom.memCaps.filterMap fun (_, uid) =>
    match s.getMemCap uid with
    | some cap =>
      let access := cap.region.access
      let carvedRanges := cap.childUids.toList.filterMap fun childUid =>
        match s.getMemCap childUid with
        | some child =>
          if child.region.kind == .carve then
            some (child.region.access.start, child.region.access.size)
          else none
        | none => none
      let segments := subtractRanges access.start access.size carvedRanges
      some (segments.map fun (st, sz) => (st, sz, access.rights))
    | none => none
  pure entries.flatten

-- ════════════════════════════════════════════════════════════════════
-- § enumeratePending — list pending capabilities
-- ════════════════════════════════════════════════════════════════════

/-- List all pending memory and domain capability transfers for a domain. -/
def enumeratePending (domId : DomainId)
    : CapaM (List PendingMemCap × List PendingDomCap) := do
  let dom ← CapaM.getDomain domId
  pure (dom.pendingMem, dom.pendingDom)

-- ════════════════════════════════════════════════════════════════════
-- § attest / attestSelf — attestation
-- ════════════════════════════════════════════════════════════════════

/-- Compute attestation for a target domain.

    Preconditions: caller sealed, has ATTEST API, target sealed.
    Returns a simple deterministic hash of the domain ID + memory count. -/
def attest (callerId : DomainId) (targetHandle : LocalHandle)
    : CapaM Nat := do
  let caller ← CapaM.getDomain callerId
  CapaM.requireSealed caller
  CapaM.requireApi caller (·.canAttest)
  let targetId ← match caller.lookupDomId targetHandle with
    | some id => pure id
    | none    => CapaM.throw .notFound
  let target ← CapaM.getDomain targetId
  CapaM.requireSealed target
  pure (targetId * 997 + target.memCaps.length * 31)

/-- Self-attestation: hash of the domain's own ID + memory count. -/
def attestSelf (domId : DomainId) : CapaM Nat := do
  let dom ← CapaM.getDomain domId
  CapaM.requireSealed dom
  pure (domId * 997 + dom.memCaps.length * 31)

end LeanExec
