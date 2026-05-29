/-
  ThemisCapa.Switch — Switch and interrupt routing types.

  Mirrors data types from `capa-engine/src/switch.rs`:
    * `CoreContext`        — per-core execution context
    * `SwitchContext`      — a single domain transition
    * `InterruptContext`   — raw interrupt arrival
    * `VpInterruptContext` — outcome of `deliver_interrupt_vp`
    * `SwitchManager`      — collection of `CoreContext`s

  The spec captures these as pure values; the Rust types use
  `RwLock`/`Arc` for shared mutation, which the small-step `step`
  relation makes unnecessary (state is threaded explicitly).
-/
import ThemisCapa.Basic
import ThemisCapa.Domain

namespace ThemisCapa
namespace Switch

/-- Per-core execution context.
    Mirrors `capa-engine/src/switch.rs::CoreContext` (locks erased). -/
structure CoreContext where
  coreId    : CoreId
  domainId  : Option DomId          -- current running domain, if any
  vpId      : Option VpId           -- current running VP, if any
deriving Repr

namespace CoreContext
def idle (coreId : CoreId) : CoreContext :=
  ⟨coreId, none, none⟩
def isIdle (c : CoreContext) : Bool := c.domainId.isNone
end CoreContext

/-- A single domain transition initiated by `switch` (forward or return).
    Mirrors `SwitchContext`. -/
structure SwitchContext where
  fromDomain      : DomId
  toDomain        : DomId
  coreId          : CoreId
  isReturn        : Bool
  fromVpId        : Option VpId
  toVpId          : Option VpId
  /-- If the target VP was `Suspended`, this carries the interrupt vector
      that caused suspension so that the SWITCH return sets `RDI = vector`
      instead of `RDI = exit_reason`. -/
  interruptReturn : Option Nat
deriving Repr

/-- Raw interrupt arrival on a core, before VP-aware routing.
    Mirrors `InterruptContext`. -/
structure InterruptContext where
  vector            : Nat
  interruptedDomain : DomId
  coreId            : CoreId
deriving Repr

/-- VP-aware interrupt delivery outcome (lazy-unwind model).
    Mirrors `VpInterruptContext`. -/
structure VpInterruptContext where
  interruptedDomainId : DomId
  interruptedVpId     : VpId
  handlerDomainId     : DomId
  handlerVpId         : VpId
  coreId              : CoreId
deriving Repr

/-- A switch manager owns a fixed pool of cores; the small-step spec keeps
    them in `SpecState.cores` directly, so this type is mostly for parity
    with the Rust API surface. -/
structure SwitchManager where
  cores : List CoreContext
deriving Repr

end Switch
end ThemisCapa
