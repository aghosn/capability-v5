/-
  ThemisCapa.Capability — Capability tree (CDT) and memory region structures.
-/
import ThemisCapa.Basic
import ThemisCapa.Domain

namespace ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § Memory region
-- ════════════════════════════════════════════════════════════════════

structure MemoryRegion where
  kind       : RegionKind
  status     : RegionStatus
  access     : Access
  attributes : Attributes
deriving Repr

-- ════════════════════════════════════════════════════════════════════
-- § Capability node — a node in the capability derivation tree
-- ════════════════════════════════════════════════════════════════════

/-- A capability in the CDT, parameterised by the resource type. -/
structure CapId where
  domainId  : DomainId     -- owning domain
  subHandle : SubHandle    -- stable identity among siblings
  depth     : Nat          -- distance from root capability
deriving DecidableEq, Repr

/-- A memory capability node in the abstract CDT. -/
structure MemCap where
  id         : CapId
  region     : MemoryRegion
  attributes : Attributes
  children   : List MemCap    -- ordered list of children
  nextChildSub : SubHandle    -- next sub-handle to allocate
deriving Repr

/-- A domain capability node in the abstract CDT. -/
structure DomCap where
  id            : CapId
  domainId      : DomainId       -- the child domain's globally unique id
  status        : DomainStatus
  policy        : DomainPolicy
  vps           : List VProcessor
  memCaps       : List (LocalHandle × MemCap)     -- domain's memory capabilities
  domCaps       : List (LocalHandle × DomCap)      -- domain's domain capabilities
  frozenHandles : List LocalHandle                 -- handles frozen by pending sends
  children      : List DomCap                       -- child domain capabilities
  nextChildSub  : SubHandle
deriving Repr

-- ════════════════════════════════════════════════════════════════════
-- § Predicates on capabilities
-- ════════════════════════════════════════════════════════════════════

namespace MemCap

/-- All carved children of a memory capability. -/
def carvedChildren (c : MemCap) : List MemCap :=
  c.children.filter (fun ch => ch.region.kind == .carve)

/-- All alias children of a memory capability. -/
def aliasChildren (c : MemCap) : List MemCap :=
  c.children.filter (fun ch => ch.region.kind == .alias)

/-- A child's access does not overlap with any existing carved child. -/
def noOverlapWithCarved (parent : MemCap) (newAccess : Access) : Prop :=
  ∀ ch ∈ parent.carvedChildren, ¬ Access.overlaps ch.region.access newAccess

/-- A child's access does not overlap with any existing child (carved or alias). -/
def noOverlapWithAny (parent : MemCap) (newAccess : Access) : Prop :=
  ∀ ch ∈ parent.children, ¬ Access.overlaps ch.region.access newAccess

end MemCap

namespace DomCap

def isSealed (d : DomCap) : Prop := d.status = .sealed
def isUnsealed (d : DomCap) : Prop := d.status = .unsealed

def lookupMem (d : DomCap) (h : LocalHandle) : Option MemCap :=
  (d.memCaps.find? (fun p => p.1 == h)).map Prod.snd

def lookupDom (d : DomCap) (h : LocalHandle) : Option DomCap :=
  (d.domCaps.find? (fun p => p.1 == h)).map Prod.snd

def hasApiPerm (d : DomCap) (perm : MonitorAPI → Bool) : Prop :=
  perm d.policy.api = true

end DomCap

end ThemisCapa
