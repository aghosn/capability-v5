/-
  LeanExec.Types — Executable type extensions for ThemisCapa types.

  Imports the proof model's core types and adds instances needed for
  computation: BEq, Hashable, ToString, Decidable for predicates.
  Also defines the flat (normalized) data structures used by the
  executable engine.
-/
import ThemisCapa.Basic
import ThemisCapa.Domain
import ThemisCapa.Capability
import ThemisCapa.State
import ThemisCapa.Operations

namespace LeanExec

open ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § BEq / Hashable / ToString instances for proof model types
-- ════════════════════════════════════════════════════════════════════

instance : BEq Rights where
  beq a b := a.read == b.read && a.write == b.write && a.execute == b.execute

instance : Hashable Rights where
  hash r := hash (r.read, r.write, r.execute)

instance : ToString Rights where
  toString r :=
    let rd := if r.read then "R" else "-"
    let wr := if r.write then "W" else "-"
    let ex := if r.execute then "X" else "-"
    s!"{rd}{wr}{ex}"

instance : BEq Attributes where
  beq a b := a.hash == b.hash && a.clean == b.clean && a.vital == b.vital
    && a.meta == b.meta && a.comm == b.comm

instance : Hashable Attributes where
  hash a := hash (a.hash, a.clean, a.vital, a.meta, a.comm)

instance : ToString Attributes where
  toString a :=
    let parts := #[]
      |> (if a.hash then (·.push "HASH") else id)
      |> (if a.clean then (·.push "CLEAN") else id)
      |> (if a.vital then (·.push "VITAL") else id)
      |> (if a.meta then (·.push "META") else id)
      |> (if a.comm then (·.push "COMM") else id)
    if parts.isEmpty then "NONE" else ",".intercalate parts.toList

/-- Canonicalize: META implies CLEAN + VITAL; COMM implies CLEAN only.
    Call at registration/send time so revocation logic needs no special cases. -/
def canonicalizeAttrs (a : Attributes) : Attributes :=
  if a.meta then { a with clean := true, vital := true }
  else if a.comm then { a with clean := true }
  else a

instance : BEq Access where
  beq a b := a.start == b.start && a.size == b.size && a.rights == b.rights

instance : Hashable Access where
  hash a := hash (a.start, a.size)

private def toHex (n : Nat) : String := String.ofList (Nat.toDigits 16 n)

instance : ToString Access where
  toString a := s!"[0x{toHex a.start}..0x{toHex a.end})"

instance : BEq RegionKind where
  beq | .carve, .carve => true | .alias, .alias => true | _, _ => false

instance : ToString RegionKind where
  toString | .carve => "Carve" | .alias => "Alias"

instance : BEq RegionStatus where
  beq | .exclusive, .exclusive => true | .aliased, .aliased => true | _, _ => false

instance : ToString RegionStatus where
  toString | .exclusive => "Exclusive" | .aliased => "Aliased"

instance : BEq DomainStatus where
  beq | .unsealed, .unsealed => true | .sealed, .sealed => true
      | .revoked, .revoked => true | _, _ => false

instance : ToString DomainStatus where
  toString | .unsealed => "Unsealed" | .sealed => "Sealed" | .revoked => "Revoked"

instance : BEq CapaError where
  beq a b := match a, b with
  | .domainRevoked, .domainRevoked => true
  | .invalidAccess, .invalidAccess => true
  | .permissionDenied, .permissionDenied => true
  | .notFound, .notFound => true
  | .domainSealed, .domainSealed => true
  | .domainNotSealed, .domainNotSealed => true
  | .parentRevoked, .parentRevoked => true
  | .regionOverlap, .regionOverlap => true
  | .monotonicityViolation, .monotonicityViolation => true
  | .apiNotAllowed, .apiNotAllowed => true
  | .invalidOperation m1, .invalidOperation m2 => m1 == m2
  | _, _ => false

instance : ToString CapaError where
  toString
  | .domainRevoked => "DomainRevoked"
  | .invalidAccess => "InvalidAccess"
  | .permissionDenied => "PermissionDenied"
  | .notFound => "NotFound"
  | .domainSealed => "DomainSealed"
  | .domainNotSealed => "DomainNotSealed"
  | .parentRevoked => "ParentRevoked"
  | .regionOverlap => "RegionOverlap"
  | .monotonicityViolation => "MonotonicityViolation"
  | .apiNotAllowed => "ApiNotAllowed"
  | .invalidOperation msg => s!"InvalidOperation: {msg}"

instance : BEq MonitorAPI where
  beq a b := a.canCreate == b.canCreate && a.canSet == b.canSet
    && a.canGet == b.canGet && a.canSend == b.canSend
    && a.canSeal == b.canSeal && a.canAttest == b.canAttest
    && a.canEnumerate == b.canEnumerate && a.canSwitch == b.canSwitch
    && a.canAlias == b.canAlias && a.canCarve == b.canCarve
    && a.canRevoke == b.canRevoke && a.canGetChan == b.canGetChan
    && a.canReceiveAfterSeal == b.canReceiveAfterSeal

instance : ToString MonitorAPI where
  toString a :=
    let parts := #[]
      |> (if a.canCreate then (·.push "CREATE") else id)
      |> (if a.canSet then (·.push "SET") else id)
      |> (if a.canGet then (·.push "GET") else id)
      |> (if a.canSend then (·.push "SEND") else id)
      |> (if a.canSeal then (·.push "SEAL") else id)
      |> (if a.canAttest then (·.push "ATTEST") else id)
      |> (if a.canEnumerate then (·.push "ENUMERATE") else id)
      |> (if a.canSwitch then (·.push "SWITCH") else id)
      |> (if a.canAlias then (·.push "ALIAS") else id)
      |> (if a.canCarve then (·.push "CARVE") else id)
      |> (if a.canRevoke then (·.push "REVOKE") else id)
      |> (if a.canGetChan then (·.push "GETCHAN") else id)
      |> (if a.canReceiveAfterSeal then (·.push "RECEIVE_AFTER_SEAL") else id)
    if parts.size == 13 then "ALL" else
    if parts.isEmpty then "NONE" else ",".intercalate parts.toList

def MonitorAPI.none : MonitorAPI :=
  ⟨false, false, false, false, false, false, false, false, false, false, false, false, false⟩

def MonitorAPI.chanAllowed : MonitorAPI :=
  { MonitorAPI.none with canAttest := true, canGetChan := true, canSend := true }

instance : BEq VectorPolicy where
  beq | .deny, .deny => true | .deliver, .deliver => true
      | .deliverAndClear, .deliverAndClear => true | _, _ => false

instance : BEq VpCallContext where
  beq a b := a.domainId == b.domainId && a.vpId == b.vpId

instance : Hashable VpCallContext where
  hash c := hash (c.domainId, c.vpId)

instance : BEq VpRunState where
  beq a b := match a, b with
  | .available, .available => true
  | .running c1 ctx1, .running c2 ctx2 => c1 == c2 && ctx1 == ctx2
  | .locked d1 v1 p1, .locked d2 v2 p2 => d1 == d2 && v1 == v2 && p1 == p2
  | .suspended d1 v1 vec1, .suspended d2 v2 vec2 => d1 == d2 && v1 == v2 && vec1 == vec2
  | .interrupted v1, .interrupted v2 => v1 == v2
  | _, _ => false

instance : ToString VpRunState where
  toString
  | .available => "Available"
  | .running c ctx => s!"Running(core={c}, caller={ctx.map (fun c => s!"({c.domainId},{c.vpId})")})"
  | .locked d v p => s!"Locked(callee=({d},{v}), prev={p.map (fun c => s!"({c.domainId},{c.vpId})")})"
  | .suspended d v vec => s!"Suspended(callee=({d},{v}), vec={vec})"
  | .interrupted v => s!"Interrupted(vec={v})"

instance : BEq VProcessor where
  beq a b := a.id == b.id && a.runState == b.runState

instance : BEq CoreState where
  beq a b := match a, b with
  | .idle, .idle => true
  | .runningDomain d1 v1, .runningDomain d2 v2 => d1 == d2 && v1 == v2
  | _, _ => false

instance : ToString CoreState where
  toString
  | .idle => "idle"
  | .runningDomain d v => s!"domain {d} vp {v}"

instance : BEq HwUpdate where
  beq a b := match a, b with
  | .mapMemory d1 g1 h1 s1 r1, .mapMemory d2 g2 h2 s2 r2 =>
    d1 == d2 && g1 == g2 && h1 == h2 && s1 == s2 && r1 == r2
  | .unmapMemory d1 g1 s1, .unmapMemory d2 g2 s2 => d1 == d2 && g1 == g2 && s1 == s2
  | .zeroMemory h1 s1, .zeroMemory h2 s2 => h1 == h2 && s1 == s2
  | .createDomain d1 p1, .createDomain d2 p2 => d1 == d2 && p1 == p2
  | .revokeDomain d1 f1, .revokeDomain d2 f2 => d1 == d2 && f1 == f2
  | .commRegion c1 t1 v1 h1 s1, .commRegion c2 t2 v2 h2 s2 =>
    c1 == c2 && t1 == t2 && v1 == v2 && h1 == h2 && s1 == s2
  | .uncommRegion o1 t1 v1 h1 s1, .uncommRegion o2 t2 v2 h2 s2 =>
    o1 == o2 && t1 == t2 && v1 == v2 && h1 == h2 && s1 == s2
  | _, _ => false

instance : ToString HwUpdate where
  toString
  | .mapMemory d g h s r => s!"MapMemory(dom={d}, gpa=0x{toHex g}, hpa=0x{toHex h}, size=0x{toHex s}, {r})"
  | .unmapMemory d g s => s!"UnmapMemory(dom={d}, gpa=0x{toHex g}, size=0x{toHex s})"
  | .zeroMemory h s => s!"ZeroMemory(hpa=0x{toHex h}, size=0x{toHex s})"
  | .createDomain d p => s!"CreateDomain(id={d}, parent={p})"
  | .revokeDomain d f => s!"RevokeDomain(id={d}, fallback={f})"
  | .commRegion c t v h s => s!"CommRegion(caller={c}, target={t}, vp={v}, hpa=0x{toHex h}, size=0x{toHex s})"
  | .uncommRegion o t v h s => s!"UncommRegion(owner={o}, target={t}, vp={v}, hpa=0x{toHex h}, size=0x{toHex s})"

-- ════════════════════════════════════════════════════════════════════
-- § Decidable instances for predicates used in executable code
-- ════════════════════════════════════════════════════════════════════

/-- Decidable Rights ≤ (bridge from decSubset to LE instance). -/
instance instDecidableLERights (a b : Rights) : Decidable (a ≤ b) :=
  Rights.decSubset a b

-- ════════════════════════════════════════════════════════════════════
-- § Computable overlap/containment checks
-- ════════════════════════════════════════════════════════════════════

/-- Computable overlap check (uses overlaps'' definition: a.start < b.end ∧ b.start < a.end). -/
def Access.overlapsB (a b : Access) : Bool :=
  a.start < b.end && b.start < a.end

/-- Computable containment check. -/
def Access.containedB (a b : Access) : Bool :=
  b.start ≤ a.start && a.end ≤ b.end && decide (a.rights ≤ b.rights)

/-- Computable rights subset. -/
def Rights.subsetB (a b : Rights) : Bool :=
  (!a.read || b.read) && (!a.write || b.write) && (!a.execute || b.execute)

/-- Computable API subset. -/
def MonitorAPI.subsetB (a b : MonitorAPI) : Bool :=
  (!a.canCreate || b.canCreate) && (!a.canSet || b.canSet) &&
  (!a.canGet || b.canGet) && (!a.canSend || b.canSend) &&
  (!a.canSeal || b.canSeal) && (!a.canAttest || b.canAttest) &&
  (!a.canEnumerate || b.canEnumerate) && (!a.canSwitch || b.canSwitch) &&
  (!a.canAlias || b.canAlias) && (!a.canCarve || b.canCarve) &&
  (!a.canRevoke || b.canRevoke) && (!a.canGetChan || b.canGetChan) &&
  (!a.canReceiveAfterSeal || b.canReceiveAfterSeal)

-- ════════════════════════════════════════════════════════════════════
-- § Executable data structures (flat/normalized)
--
-- The proof model uses recursive trees (DomCap contains List DomCap).
-- For executable code we use a flat representation: all memory caps
-- and domains live in top-level maps, referenced by unique IDs.
-- ════════════════════════════════════════════════════════════════════

/-- Unique identifier for a memory capability in the flat store. -/
abbrev CapNodeId := Nat

/-- A flattened memory capability node. Children are stored as UIDs
    rather than inline subtrees. -/
structure ExecMemCap where
  uid          : CapNodeId
  capId        : CapId
  region       : MemoryRegion
  attributes   : Attributes
  parentUid    : Option CapNodeId
  childUids    : Array CapNodeId
  nextChildSub : SubHandle
deriving Repr

/-- A pending memory capability transfer. -/
structure PendingMemCap where
  pendingId    : Nat
  senderDomId  : DomainId
  senderHandle : LocalHandle
  capNodeId    : CapNodeId
  attributes   : Attributes
deriving Repr

/-- A pending domain capability (channel) transfer. -/
structure PendingDomCap where
  pendingId    : Nat
  senderDomId  : DomainId
  senderHandle : LocalHandle
  targetDomId  : DomainId
deriving Repr

/-- Executable domain — flat structure with handle-based lookups. -/
structure ExecDomain where
  domainId      : DomainId
  status        : DomainStatus
  policy        : DomainPolicy
  vps           : Array VProcessor
  /-- Memory capabilities owned by this domain: LocalHandle → CapNodeId. -/
  memCaps       : List (LocalHandle × CapNodeId)
  /-- Child domain capabilities: LocalHandle → child DomainId. -/
  domCaps       : List (LocalHandle × DomainId)
  /-- Channel capabilities: LocalHandle → target DomainId. -/
  chanCaps      : List (LocalHandle × DomainId)
  frozenHandles : List LocalHandle
  pendingMem    : List PendingMemCap
  pendingDom    : List PendingDomCap
  nextMemHandle : LocalHandle
  nextDomHandle : LocalHandle
  nextPendingId : Nat
  parentDomId   : Option DomainId
  /-- COMM bindings: (target domain, vp_id, memcap uid) -/
  commBindings  : List (DomainId × VpId × CapNodeId)
deriving Repr

namespace ExecDomain

def empty (id : DomainId) (parent : Option DomainId) (policy : DomainPolicy) : ExecDomain :=
  { domainId := id
    status := .unsealed
    policy := policy
    vps := #[]
    memCaps := []
    domCaps := []
    chanCaps := []
    frozenHandles := []
    pendingMem := []
    pendingDom := []
    nextMemHandle := 0
    nextDomHandle := 0
    nextPendingId := 0
    parentDomId := parent
    commBindings := [] }

def lookupNodeId (d : ExecDomain) (h : LocalHandle) : Option CapNodeId :=
  (d.memCaps.find? (fun p => p.1 == h)).map Prod.snd

def lookupDomId (d : ExecDomain) (h : LocalHandle) : Option DomainId :=
  (d.domCaps.find? (fun p => p.1 == h)).map Prod.snd

def lookupChanTarget (d : ExecDomain) (h : LocalHandle) : Option DomainId :=
  (d.chanCaps.find? (fun p => p.1 == h)).map Prod.snd

def isSealed (d : ExecDomain) : Bool := d.status == .sealed
def isUnsealed (d : ExecDomain) : Bool := d.status == .unsealed
def isRevoked (d : ExecDomain) : Bool := d.status == .revoked

def isFrozen (d : ExecDomain) (h : LocalHandle) : Bool :=
  d.frozenHandles.contains h

def allocMemHandle (d : ExecDomain) : ExecDomain × LocalHandle :=
  ({ d with nextMemHandle := d.nextMemHandle + 1 }, d.nextMemHandle)

def allocDomHandle (d : ExecDomain) : ExecDomain × LocalHandle :=
  ({ d with nextDomHandle := d.nextDomHandle + 1 }, d.nextDomHandle)

def allocPendingId (d : ExecDomain) : ExecDomain × Nat :=
  ({ d with nextPendingId := d.nextPendingId + 1 }, d.nextPendingId)

def addMemCap (d : ExecDomain) (h : LocalHandle) (uid : CapNodeId) : ExecDomain :=
  { d with memCaps := d.memCaps ++ [(h, uid)] }

def removeMemCap (d : ExecDomain) (h : LocalHandle) : ExecDomain :=
  { d with memCaps := d.memCaps.filter (fun p => p.1 != h) }

def addDomCap (d : ExecDomain) (h : LocalHandle) (childId : DomainId) : ExecDomain :=
  { d with domCaps := d.domCaps ++ [(h, childId)] }

def removeDomCap (d : ExecDomain) (h : LocalHandle) : ExecDomain :=
  { d with domCaps := d.domCaps.filter (fun p => p.1 != h) }

def addChanCap (d : ExecDomain) (h : LocalHandle) (targetId : DomainId) : ExecDomain :=
  { d with chanCaps := d.chanCaps ++ [(h, targetId)] }

def removeChanCap (d : ExecDomain) (h : LocalHandle) : ExecDomain :=
  { d with chanCaps := d.chanCaps.filter (fun p => p.1 != h) }

def freeze (d : ExecDomain) (h : LocalHandle) : ExecDomain :=
  { d with frozenHandles := h :: d.frozenHandles }

def unfreeze (d : ExecDomain) (h : LocalHandle) : ExecDomain :=
  { d with frozenHandles := d.frozenHandles.filter (· != h) }

end ExecDomain

end LeanExec
