/-
  ThemisCapa.Domain — Domain and policy specifications.

  Mirrors the current `capa-engine/src/domain.rs` and
  `capa-engine/src/interposition.rs`. Key Rust types reflected here:

  * `MonitorAPI` — 14-bit (`MAP_SELF` is the 14th, gated by
    `address_translation` feature in Rust; always present in the spec).
  * `InterruptVisibility`, `VectorPolicy`, `InterruptPolicy`
  * `RegBitmap` — 3×u64 register bitmap (192 bits).
  * `ExitAction`, `ExitPolicy`
  * `ProcFeaturePolicy`/`ProcFeatureConfig` (CPUID + MSR interposition)
  * `ResourceKind`, `PolicyIdentifier`
  * `VpCallContext`, `VpRunState`, `VECTOR_AVAILABLE`
  * `DomainPolicy`, `VProcessor`
-/
import ThemisCapa.Basic

namespace ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § Monitor API — 14-bit permission bitmap
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
  canMapSelf          : Bool   -- gated by `address_translation` in Rust
deriving DecidableEq, Repr

namespace MonitorAPI

def full : MonitorAPI :=
  ⟨true, true, true, true, true, true, true, true,
   true, true, true, true, true, true⟩

def none : MonitorAPI :=
  ⟨false, false, false, false, false, false, false, false,
   false, false, false, false, false, false⟩

/-- Channel capability allowed bits: attest + getchan + send. -/
def chanAllowed : MonitorAPI :=
  { none with canAttest := true, canGetChan := true, canSend := true }

/-- API subset: every permission in `a` is also in `b`. -/
def subset (a b : MonitorAPI) : Prop :=
  (a.canCreate → b.canCreate) ∧ (a.canSet → b.canSet) ∧ (a.canGet → b.canGet) ∧
  (a.canSend → b.canSend) ∧ (a.canSeal → b.canSeal) ∧ (a.canAttest → b.canAttest) ∧
  (a.canEnumerate → b.canEnumerate) ∧ (a.canSwitch → b.canSwitch) ∧
  (a.canAlias → b.canAlias) ∧ (a.canCarve → b.canCarve) ∧ (a.canRevoke → b.canRevoke) ∧
  (a.canGetChan → b.canGetChan) ∧ (a.canReceiveAfterSeal → b.canReceiveAfterSeal) ∧
  (a.canMapSelf → b.canMapSelf)

instance : LE MonitorAPI where le := subset

end MonitorAPI

-- ════════════════════════════════════════════════════════════════════
-- § RegBitmap — 192-bit register bitmap (3 × u64)
-- ════════════════════════════════════════════════════════════════════

/-- Three 64-bit words modeled as a list of three `Nat`s.
    Bit `i` of word `w` corresponds to register id `w*64 + i`.
    Matches `capa-engine/src/domain.rs::RegBitmap`. -/
structure RegBitmap where
  word0 : Nat
  word1 : Nat
  word2 : Nat
deriving DecidableEq, Repr

namespace RegBitmap
def none : RegBitmap := ⟨0, 0, 0⟩
/-- All-bits-set as the limit `2^64 - 1`. Modeled symbolically as `Nat.max`. -/
def allWord : Nat := 2 ^ 64 - 1
def all : RegBitmap := ⟨allWord, allWord, allWord⟩
end RegBitmap

-- ════════════════════════════════════════════════════════════════════
-- § Interrupt policy
-- ════════════════════════════════════════════════════════════════════

/-- Visibility of an interrupt vector to a domain.
    Mirrors `InterruptVisibility` in `capa-engine/src/domain.rs`. -/
inductive InterruptVisibility where
  | deliver    -- interrupt delivered directly to the domain
  | report     -- interrupt reported via COMM page, handled by parent
  | notReport  -- interrupt not reported (silently dropped from domain's POV)
deriving DecidableEq, Repr

/-- Per-vector interrupt policy: visibility + register-access bitmaps. -/
structure VectorPolicy where
  visibility : InterruptVisibility
  readSet    : RegBitmap
  writeSet   : RegBitmap
deriving Repr

namespace VectorPolicy
def defaultDeliver : VectorPolicy :=
  ⟨.deliver, .none, .none⟩
def defaultReport : VectorPolicy :=
  ⟨.report, .all, .all⟩
end VectorPolicy

/-- Interrupt routing policy: default + per-vector overrides. -/
structure InterruptPolicy where
  default   : VectorPolicy
  overrides : List (Nat × VectorPolicy)  -- (vector, policy)
deriving Repr

/-- Synthetic vector representing the "VP is available / not interrupted" state.
    Used uniformly with real vectors for register-access policy lookup.
    Matches `VECTOR_AVAILABLE = 0xFF` in Rust. -/
def VECTOR_AVAILABLE : Nat := 0xFF

-- ════════════════════════════════════════════════════════════════════
-- § Interposition policy (CPUID, MSR)
-- ════════════════════════════════════════════════════════════════════
-- Detailed types live in `ThemisCapa.Interposition`. Here we only
-- need an opaque handle on each policy for use inside `DomainPolicy`.

/-- Default action for processor feature queries not matched by overrides. -/
inductive DefaultAction where
  | trap    -- forward exit to parent domain
  | native  -- execute natively on physical CPU
deriving DecidableEq, Repr

/-- A policy entry for a range of processor feature identifiers.
    Encoded uniformly: `(startLeaf, startSub, endLeaf, endSub)` for CPUID
    and `(startMsr, 0, endMsr, 0)` for MSR. -/
inductive ProcFeatureEntry where
  | trap    (sLeaf sSub eLeaf eSub : Nat)
  | native  (sLeaf sSub eLeaf eSub : Nat)
  | emulate (leaf sub wordIdx : Nat) (value : Nat)
deriving Repr

/-- Per-domain interposition configuration for a resource class. -/
structure ProcFeatureConfig where
  default   : DefaultAction
  overrides : List ProcFeatureEntry
deriving Repr

-- ════════════════════════════════════════════════════════════════════
-- § Exit policy — per-exit-reason register gating
-- ════════════════════════════════════════════════════════════════════

/-- Action for a specific VMEXIT reason.
    `trap = true` → forward to parent (read/write sets gate register access);
    `trap = false` → handle locally in the hypervisor. -/
structure ExitAction where
  trap     : Bool
  readSet  : RegBitmap
  writeSet : RegBitmap
deriving Repr

namespace ExitAction
def defaultTrap  : ExitAction := ⟨true,  .all,  .all⟩
def defaultLocal : ExitAction := ⟨false, .none, .none⟩
end ExitAction

/-- VMEXIT routing policy: default action + per-exit-reason overrides. -/
structure ExitPolicy where
  default   : ExitAction
  overrides : List (Nat × ExitAction)  -- (exit_reason, action)
deriving Repr

-- ════════════════════════════════════════════════════════════════════
-- § Policy identifiers (for set_policy / get_policy)
-- ════════════════════════════════════════════════════════════════════

inductive ResourceKind where
  | cpuid
  | msr
deriving DecidableEq, Repr

/-- Identifier for a domain-wide policy field, used by `set_policy` /
    `get_policy`. Mirrors `capa-engine/src/domain.rs::PolicyIdentifier`. -/
inductive PolicyIdentifier where
  | cores
  | apiMonitor
  | defaultInterruptVisibility
  | vectorVisibility (vector : Nat)
  | vectorRegReadSet (vector : Nat) (wordIdx : Nat)
  | vectorRegWriteSet (vector : Nat) (wordIdx : Nat)
  | defaultExitTrap
  | exitReasonTrap (reason : Nat)
  | exitReasonRegReadSet (reason : Nat) (wordIdx : Nat)
  | exitReasonRegWriteSet (reason : Nat) (wordIdx : Nat)
  | procFeatureDefault (kind : ResourceKind)
  | procFeatureRange (kind : ResourceKind)
                     (sLeaf sSub eLeaf eSub : Nat)
  | procFeatureEmulate (kind : ResourceKind)
                       (leaf sub wordIdx : Nat)
deriving Repr

-- ════════════════════════════════════════════════════════════════════
-- § Domain policy — frozen at seal time
-- ════════════════════════════════════════════════════════════════════

/-- Core mask as a list of allowed core IDs. (Rust uses a `u64` bitmap;
    we keep the spec view as a list of explicit core ids.) -/
abbrev CoreMask := List CoreId

def CoreMask.subset (a b : CoreMask) : Prop :=
  ∀ c ∈ a, c ∈ b

instance : HasSubset CoreMask where Subset := CoreMask.subset

structure DomainPolicy where
  cores      : CoreMask          -- allowed physical cores
  api        : MonitorAPI        -- allowed hypercalls
  interrupts : InterruptPolicy
  exits      : ExitPolicy
  cpuid      : ProcFeatureConfig
  msrs       : ProcFeatureConfig
  numVps     : Nat               -- number of virtual processors
deriving Repr

-- ════════════════════════════════════════════════════════════════════
-- § Virtual processor run state
-- ════════════════════════════════════════════════════════════════════

/-- Caller context saved when a VP switches into a child domain.
    Domain reference is by ID — the spec is closed over `SpecState`. -/
structure VpCallContext where
  domainId : DomainId
  vpId     : VpId
deriving DecidableEq, Repr

/-- State machine for virtual processor scheduling. Mirrors the current
    Rust `VpRunState` enum closely; the `Available` case carries the last
    forwarded exit reason for `register_access_check` lookups. -/
inductive VpRunState where
  | available    (lastExitReason : Option Nat)
  | running      (core : CoreId) (caller : Option VpCallContext)
  | locked       (calleeDomainId : DomainId) (calleeVpId : VpId)
                 (prevCaller : Option VpCallContext)
  | suspended    (calleeDomainId : DomainId) (calleeVpId : VpId)
                 (vector : Nat)
  | interrupted  (vector : Nat)
deriving Repr

structure VProcessor where
  id       : VpId
  runState : VpRunState
deriving Repr

end ThemisCapa
