/-
  ThemisCapa.State — Abstract system state and hardware update batches.

  The system state captures the global CDT (all domains and their capabilities)
  plus per-core scheduling state. Operations transform one state into the next,
  optionally emitting hardware updates that the platform must apply.
-/
import ThemisCapa.Basic
import ThemisCapa.Domain
import ThemisCapa.Capability

namespace ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § Hardware updates — effects emitted by operations
-- ════════════════════════════════════════════════════════════════════

/-- An individual hardware update that the platform must apply after
    the capability engine validates an operation. These correspond to
    EPT changes, memory zeroing, domain lifecycle, and comm page setup. -/
inductive HwUpdate where
  | mapMemory     (domainId : DomainId) (gpa hpa size : Nat) (rights : Rights)
  | unmapMemory   (domainId : DomainId) (gpa size : Nat)
  | zeroMemory    (hpa size : Nat)
  | createDomain  (domainId : DomainId) (parentId : Option DomainId)
  | revokeDomain  (domainId : DomainId) (fallbackId : DomainId)
  | commRegion    (callerId targetId : DomainId) (vpId : VpId) (hpa size : Nat)
  | uncommRegion  (ownerId targetId : DomainId) (vpId : VpId) (hpa size : Nat)
deriving Repr

abbrev UpdateBatch := List HwUpdate

-- ════════════════════════════════════════════════════════════════════
-- § Per-core state
-- ════════════════════════════════════════════════════════════════════

inductive CoreState where
  | idle
  | runningDomain (domainId : DomainId) (vpId : VpId)
deriving DecidableEq, Repr

-- ════════════════════════════════════════════════════════════════════
-- § System state — the full abstract state of the capability system
-- ════════════════════════════════════════════════════════════════════

/-- The complete state of the Themis capability system. -/
structure SystemState where
  /-- All domains in the system, keyed by domain ID. The root domain
      has id 0 and owns the initial capabilities. -/
  domains     : List DomCap
  /-- Per-core scheduling state. -/
  cores       : List CoreState
  /-- Monotonically increasing domain ID counter. -/
  nextDomainId : DomainId
deriving Repr

namespace SystemState

def lookupDomain (s : SystemState) (id : DomainId) : Option DomCap :=
  s.domains.find? (fun d => d.domainId == id)

def numCores (s : SystemState) : Nat := s.cores.length

end SystemState

-- ════════════════════════════════════════════════════════════════════
-- § Switch context — result of a switch operation
-- ════════════════════════════════════════════════════════════════════

structure SwitchResult where
  fromDomain : DomainId
  toDomain   : DomainId
  fromVpId   : Option VpId
  toVpId     : Option VpId
  isReturn   : Bool
  vector     : Option Nat    -- interrupt vector if returning from interrupt

end ThemisCapa
