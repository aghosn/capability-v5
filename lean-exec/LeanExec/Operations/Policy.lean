/-
  LeanExec.Operations.Policy — Policy and register operations.

  Implements setPolicy/getPolicy for domain policy fields,
  setRegister/getRegister for VP register access, and
  setInterruptPolicy for per-vector interrupt configuration.
-/
import LeanExec.Monad

namespace LeanExec

open ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § Helpers — bitmask ↔ structured type conversions
-- ════════════════════════════════════════════════════════════════════

/-- Convert a Nat bitmask to a CoreMask (list of set bit positions). -/
private def natToCores (n : Nat) : CoreMask :=
  (List.range 64).filter n.testBit

/-- Convert a CoreMask to a Nat bitmask. -/
private def coresToNat (cores : CoreMask) : Nat :=
  cores.foldl (fun acc c => acc + (1 <<< c)) 0

/-- Convert a Nat bitmask to a MonitorAPI (13-bit encoding). -/
private def natToApi (n : Nat) : MonitorAPI :=
  { canCreate           := n.testBit 0
    canSet              := n.testBit 1
    canGet              := n.testBit 2
    canSend             := n.testBit 3
    canSeal             := n.testBit 4
    canAttest           := n.testBit 5
    canEnumerate        := n.testBit 6
    canSwitch           := n.testBit 7
    canAlias            := n.testBit 8
    canCarve            := n.testBit 9
    canRevoke           := n.testBit 10
    canGetChan          := n.testBit 11
    canReceiveAfterSeal := n.testBit 12 }

/-- Convert a MonitorAPI to a Nat bitmask. -/
private def apiToNat (a : MonitorAPI) : Nat :=
  (if a.canCreate then 1 else 0) +
  (if a.canSet then 2 else 0) +
  (if a.canGet then 4 else 0) +
  (if a.canSend then 8 else 0) +
  (if a.canSeal then 16 else 0) +
  (if a.canAttest then 32 else 0) +
  (if a.canEnumerate then 64 else 0) +
  (if a.canSwitch then 128 else 0) +
  (if a.canAlias then 256 else 0) +
  (if a.canCarve then 512 else 0) +
  (if a.canRevoke then 1024 else 0) +
  (if a.canGetChan then 2048 else 0) +
  (if a.canReceiveAfterSeal then 4096 else 0)

/-- Convert Nat to VectorPolicy.
    Matches Rust InterruptVisibility discriminants:
    0 = DELIVER, 1 = REPORT, 2 = NOTREPORT.
    We map: deliver ↔ DELIVER, deliverAndClear ↔ REPORT, deny ↔ NOTREPORT. -/
private def natToVisibility (n : Nat) : VectorPolicy :=
  if n == 0 then .deliver
  else if n == 1 then .deliverAndClear
  else .deny

/-- Convert VectorPolicy to Nat. -/
private def visibilityToNat (v : VectorPolicy) : Nat :=
  match v with
  | .deliver        => 0
  | .deliverAndClear => 1
  | .deny           => 2

/-- Computable CoreMask subset check. -/
private def coreSubsetB (child parent : CoreMask) : Bool :=
  child.all parent.contains

-- ════════════════════════════════════════════════════════════════════
-- § setPolicy — Set a child domain's policy field
-- ════════════════════════════════════════════════════════════════════

/-- Set a policy field on a child domain.

    Preconditions: caller sealed, has SET API, child exists in domCaps,
    child unsealed.  Monotonicity is enforced for cores and API. -/
def setPolicy (callerId : DomainId) (childHandle : LocalHandle)
    (field : String) (value : Nat) : CapaM Unit := do
  let caller ← CapaM.getDomain callerId
  CapaM.requireSealed caller
  CapaM.requireApi caller (·.canSet)
  let childId ← match caller.lookupDomId childHandle with
    | some id => pure id
    | none    => CapaM.throw .notFound
  let child ← CapaM.getDomain childId
  CapaM.requireUnsealed child
  let policy := child.policy
  let newPolicy ← match field with
    | "cores" =>
      let newCores := natToCores value
      CapaM.guard (coreSubsetB newCores caller.policy.cores) .monotonicityViolation
      pure { policy with cores := newCores }
    | "api-monitor" =>
      let newApi := natToApi value
      CapaM.guard (MonitorAPI.subsetB newApi caller.policy.api) .monotonicityViolation
      pure { policy with api := newApi }
    | "default-visibility" =>
      let vis := natToVisibility value
      pure { policy with interrupts := { policy.interrupts with defaultPolicy := vis } }
    | "num-vps" =>
      pure { policy with numVps := value }
    | "cpuid-default" =>
      let action := if value == 0 then DefaultAction.trap else DefaultAction.native
      pure { policy with cpuid := { policy.cpuid with default := action } }
    | "msr-default" =>
      let action := if value == 0 then DefaultAction.trap else DefaultAction.native
      pure { policy with msrs := { policy.msrs with default := action } }
    | _ => CapaM.throw (.invalidOperation s!"unknown policy field: {field}")
  CapaM.setDomain childId { child with policy := newPolicy }

-- ════════════════════════════════════════════════════════════════════
-- § getPolicy — Get a child domain's policy field
-- ════════════════════════════════════════════════════════════════════

/-- Get a policy field from a child domain.

    Preconditions: caller sealed, has GET API, child exists in domCaps. -/
def getPolicy (callerId : DomainId) (childHandle : LocalHandle)
    (field : String) : CapaM Nat := do
  let caller ← CapaM.getDomain callerId
  CapaM.requireSealed caller
  CapaM.requireApi caller (·.canGet)
  let childId ← match caller.lookupDomId childHandle with
    | some id => pure id
    | none    => CapaM.throw .notFound
  let child ← CapaM.getDomain childId
  match field with
    | "cores"              => pure (coresToNat child.policy.cores)
    | "api-monitor"        => pure (apiToNat child.policy.api)
    | "default-visibility" => pure (visibilityToNat child.policy.interrupts.defaultPolicy)
    | "num-vps"            => pure child.policy.numVps
    | "cpuid-default"      =>
      pure (match child.policy.cpuid.default with | .trap => 0 | .native => 1)
    | "msr-default"        =>
      pure (match child.policy.msrs.default with | .trap => 0 | .native => 1)
    | _ => CapaM.throw (.invalidOperation s!"unknown policy field: {field}")

-- ════════════════════════════════════════════════════════════════════
-- § setRegister / getRegister — VP register access
-- ════════════════════════════════════════════════════════════════════

/-- Set a register on a child domain's VP.

    Preconditions: caller sealed, has SET API, child exists in domCaps,
    vpId < vps.size, regId < registerCount. -/
def setRegister (callerId : DomainId) (childHandle : LocalHandle)
    (vpId : VpId) (regId : Nat) (value : Nat) : CapaM Unit := do
  let caller ← CapaM.getDomain callerId
  CapaM.requireSealed caller
  CapaM.requireApi caller (·.canSet)
  let childId ← match caller.lookupDomId childHandle with
    | some id => pure id
    | none    => CapaM.throw .notFound
  let child ← CapaM.getDomain childId
  CapaM.guard (vpId < child.vps.size) (.invalidOperation "vpId out of bounds")
  let s ← CapaM.getState
  CapaM.guard (regId < s.registerCount) (.invalidOperation "regId out of bounds")
  CapaM.setVpReg childId vpId regId value

/-- Get a register from a child domain's VP.

    Preconditions: caller sealed, has GET API, child exists in domCaps,
    vpId < vps.size, regId < registerCount. -/
def getRegister (callerId : DomainId) (childHandle : LocalHandle)
    (vpId : VpId) (regId : Nat) : CapaM Nat := do
  let caller ← CapaM.getDomain callerId
  CapaM.requireSealed caller
  CapaM.requireApi caller (·.canGet)
  let childId ← match caller.lookupDomId childHandle with
    | some id => pure id
    | none    => CapaM.throw .notFound
  let child ← CapaM.getDomain childId
  CapaM.guard (vpId < child.vps.size) (.invalidOperation "vpId out of bounds")
  let s ← CapaM.getState
  CapaM.guard (regId < s.registerCount) (.invalidOperation "regId out of bounds")
  CapaM.getVpReg childId vpId regId

-- ════════════════════════════════════════════════════════════════════
-- § setInterruptPolicy — Per-vector interrupt policy
-- ════════════════════════════════════════════════════════════════════

/-- Set the interrupt policy for a specific vector on a child domain.

    Preconditions: caller sealed, has SET API, child unsealed.
    Adds or updates (vector, policy) in child's interrupts.perVector. -/
def setInterruptPolicy (callerId : DomainId) (childHandle : LocalHandle)
    (vector : Nat) (visibility : Nat) : CapaM Unit := do
  let caller ← CapaM.getDomain callerId
  CapaM.requireSealed caller
  CapaM.requireApi caller (·.canSet)
  let childId ← match caller.lookupDomId childHandle with
    | some id => pure id
    | none    => CapaM.throw .notFound
  let child ← CapaM.getDomain childId
  CapaM.requireUnsealed child
  let policy := natToVisibility visibility
  let intPolicy := child.policy.interrupts
  -- Remove existing entry for this vector, then add the new one
  let filtered := intPolicy.perVector.filter (fun p => p.1 != vector)
  let newPerVector := filtered ++ [(vector, policy)]
  let newIntPolicy : InterruptPolicy := { intPolicy with perVector := newPerVector }
  CapaM.setDomain childId { child with policy := { child.policy with interrupts := newIntPolicy } }

end LeanExec
