/-
  ThemisCapa.Domain — Domain and policy specifications.
-/
import ThemisCapa.Basic

namespace ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § Monitor API — 13-bit permission bitmap
-- ════════════════════════════════════════════════════════════════════

structure MonitorAPI where
  canCreate           : Bool
  canSet              : Bool
  canGet              : Bool
  canSend             : Bool
  canSeal             : Bool
  canAttest           : Bool
  canEnumerate        : Bool
  canSwitch           : Bool
  canAlias            : Bool
  canCarve            : Bool
  canRevoke           : Bool
  canGetChan          : Bool
  canReceiveAfterSeal : Bool
deriving DecidableEq, Repr

namespace MonitorAPI

def full : MonitorAPI :=
  ⟨true, true, true, true, true, true, true, true, true, true, true, true, true⟩

/-- API subset: every permission in `a` is also in `b`. -/
def subset (a b : MonitorAPI) : Prop :=
  (a.canCreate → b.canCreate) ∧ (a.canSet → b.canSet) ∧ (a.canGet → b.canGet) ∧
  (a.canSend → b.canSend) ∧ (a.canSeal → b.canSeal) ∧ (a.canAttest → b.canAttest) ∧
  (a.canEnumerate → b.canEnumerate) ∧ (a.canSwitch → b.canSwitch) ∧
  (a.canAlias → b.canAlias) ∧ (a.canCarve → b.canCarve) ∧ (a.canRevoke → b.canRevoke) ∧
  (a.canGetChan → b.canGetChan) ∧ (a.canReceiveAfterSeal → b.canReceiveAfterSeal)

instance : LE MonitorAPI where le := subset

end MonitorAPI

-- ════════════════════════════════════════════════════════════════════
-- § Interrupt policy
-- ════════════════════════════════════════════════════════════════════

/-- Per-vector interrupt routing policy. -/
inductive VectorPolicy where
  | deny            -- vector cannot be delivered
  | deliver         -- direct delivery allowed
  | deliverAndClear -- deliver and clear a pending bit
deriving DecidableEq, Repr

structure InterruptPolicy where
  defaultPolicy : VectorPolicy
  perVector     : List (Nat × VectorPolicy)   -- overrides for specific vectors
deriving Repr

-- ════════════════════════════════════════════════════════════════════
-- § Interposition policy (CPUID, MSR)
-- ════════════════════════════════════════════════════════════════════

/-- Default action for processor feature queries not matched by overrides. -/
inductive DefaultAction where
  | trap    -- forward exit to parent domain
  | native  -- execute natively on physical CPU
deriving DecidableEq, Repr

/-- A policy entry for a range of processor feature identifiers. -/
inductive ProcFeatureEntry where
  | trap    (start finish : Nat)
  | native  (start finish : Nat)
  | emulate (start finish : Nat) (value : List Nat)
deriving Repr

/-- Per-domain interposition configuration for a resource class. -/
structure ProcFeatureConfig where
  default   : DefaultAction
  overrides : List ProcFeatureEntry
deriving Repr

-- ════════════════════════════════════════════════════════════════════
-- § Domain policy — frozen at seal time
-- ════════════════════════════════════════════════════════════════════

/-- Core mask as a list of allowed core IDs. -/
abbrev CoreMask := List CoreId

def CoreMask.subset (a b : CoreMask) : Prop :=
  ∀ c ∈ a, c ∈ b

instance : HasSubset CoreMask where Subset := CoreMask.subset

structure DomainPolicy where
  cores      : CoreMask          -- which physical cores the domain may use
  api        : MonitorAPI        -- which hypercall operations are permitted
  interrupts : InterruptPolicy
  numVps     : Nat               -- number of virtual processors
  cpuid      : ProcFeatureConfig -- CPUID interposition policy
  msrs       : ProcFeatureConfig -- MSR interposition policy
deriving Repr

-- ════════════════════════════════════════════════════════════════════
-- § Virtual processor run state
-- ════════════════════════════════════════════════════════════════════

/-- Caller context saved when a VP switches into a child domain. -/
structure VpCallContext where
  domainId : DomainId
  vpId     : VpId
deriving DecidableEq, Repr

/-- State machine for virtual processor scheduling. -/
inductive VpRunState where
  | available
  | running (core : CoreId) (caller : Option VpCallContext)
  | locked (calleeDomainId : DomainId) (calleeVpId : VpId)
           (prevCaller : Option VpCallContext)
  | suspended (calleeDomainId : DomainId) (calleeVpId : VpId)
              (vector : Nat)
  | interrupted (vector : Nat)
deriving Repr

structure VProcessor where
  id       : VpId
  runState : VpRunState
deriving Repr

end ThemisCapa
