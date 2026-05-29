/-
  ThemisCapa.Basic — Core types for the Themis capability model.

  This file defines the fundamental types used throughout the specification:
  rights, attributes, access descriptors, and error types.
-/
namespace ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § Rights — 3-bit permission bitmap
-- ════════════════════════════════════════════════════════════════════

-- TODO: write ∨ execute → read
structure Rights where
  read    : Bool
  write   : Bool
  execute : Bool
deriving DecidableEq, Repr

namespace Rights

def none : Rights := ⟨false, false, false⟩
def r    : Rights := ⟨true,  false, false⟩
def rw   : Rights := ⟨true,  true,  false⟩
def rx   : Rights := ⟨true,  false, true⟩
def rwx  : Rights := ⟨true,  true,  true⟩

/-- Rights subset relation: `a ⊆ b` iff every permission in `a` is also in `b`. -/
def subset (a b : Rights) : Prop :=
  (a.read → b.read) ∧ (a.write → b.write) ∧ (a.execute → b.execute)

instance : LE Rights where le := subset

instance decSubset (a b : Rights) : Decidable (subset a b) :=
  if h1 : a.read → b.read then
    if h2 : a.write → b.write then
      if h3 : a.execute → b.execute then
        isTrue ⟨h1, h2, h3⟩
      else isFalse (fun ⟨_, _, h3'⟩ => h3 h3')
    else isFalse (fun ⟨_, h2', _⟩ => h2 h2')
  else isFalse (fun ⟨h1', _, _⟩ => h1 h1')

end Rights

-- ════════════════════════════════════════════════════════════════════
-- § Attributes — 5-bit capability metadata
-- ════════════════════════════════════════════════════════════════════

structure Attributes where
  hash  : Bool   -- content hashed for attestation
  clean : Bool   -- zeroed on revocation
  vital : Bool   -- revoking region also revokes owning domain
  «meta»  : Bool   -- monitor-only memory; excluded from guest address space
  comm  : Bool   -- parent-owned communication buffer
deriving DecidableEq, Repr

namespace Attributes
def empty : Attributes := ⟨false, false, false, false, false⟩
end Attributes

-- ════════════════════════════════════════════════════════════════════
-- § Access — address range + rights
-- ════════════════════════════════════════════════════════════════════

structure Access where
  start  : Nat
  size   : Nat
  rights : Rights
deriving DecidableEq, Repr

namespace Access

def «end» (a : Access) : Nat := a.start + a.size

def startIncluded (a b : Access) : Prop :=
  (b.start ≤ a.start ∧ a.start < b.end ∧ a.size > 0) ∨
  (b.start < a.end ∧ a.end ≤ b.end ∧ a.size > 0)

/-- Two accesses overlap iff their ranges intersect. -/
def overlaps' (a b : Access) : Prop :=
  let start := max a.start b.start
  let «end» := min a.end b.end
  «end» ≥ start

-- TODO: overlaps and overlaps' are not equivalent

def overlaps (a b : Access) : Prop :=
  ¬ (a.end ≤ b.start ∨ a.start ≥ b.end)

def overlaps'' (a b : Access) : Prop :=
  a.start < b.end ∧ b.start < a.end

example (a b : Access) : overlaps a b ↔ overlaps b a := by
  simp [overlaps]
  grind

example (a b : Access) : overlaps' a b ↔ overlaps' b a := by
  simp [overlaps']
  grind

example (a b : Access) : overlaps a b ↔ overlaps'' a b := by
  simp [overlaps, overlaps'', «end»]
  grind

/-- `a` is contained in `b` iff `a` is a subrange with subset rights. -/
def contained (a b : Access) : Prop :=
  b.start ≤ a.start ∧ a.end ≤ b.end ∧ a.rights ≤ b.rights

end Access

-- ════════════════════════════════════════════════════════════════════
-- § Identifiers
-- ════════════════════════════════════════════════════════════════════

abbrev DomainId    := Nat
abbrev LocalHandle := Nat
abbrev SubHandle   := Nat
abbrev CoreId      := Nat
abbrev VpId        := Nat

-- ════════════════════════════════════════════════════════════════════
-- § Region metadata
-- ════════════════════════════════════════════════════════════════════

inductive RegionKind where
  | carve
  | alias
deriving DecidableEq, Repr

-- TODO: this can be derived from the capa tree and the region kinds
inductive RegionStatus where
  | exclusive
  | aliased
deriving DecidableEq, Repr

-- ════════════════════════════════════════════════════════════════════
-- § Domain status
-- ════════════════════════════════════════════════════════════════════

inductive DomainStatus where
  | unsealed
  | sealed
  | revoked -- TODO: unclear whether needed for the spec
deriving DecidableEq, Repr

-- ════════════════════════════════════════════════════════════════════
-- § Error type
-- ════════════════════════════════════════════════════════════════════

-- TODO: seems implementation specific
inductive CapaError where
  | domainRevoked
  | invalidAccess
  | permissionDenied
  | notFound
  | domainSealed
  | domainNotSealed
  | parentRevoked
  | regionOverlap
  | monotonicityViolation
  | apiNotAllowed
  | invalidOperation (msg : String)
deriving DecidableEq, Repr

abbrev CapaResult (α : Type) := Except CapaError α

-- ════════════════════════════════════════════════════════════════════
-- § Alternative
-- ════════════════════════════════════════════════════════════════════

namespace Alternative

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

  /- Well-formedness:
  - all ids are unique
  - a capa is uniquely owned by a domain
  - conditions on children
  -/
  structure MemCapa where
    id : Nat
    attributes : Attributes
    access : Access
    kind : RegionKind
    children : List MemCapa

  -- TODO: interrupts
  structure DomCapa where
    id : Nat
    monitorAPI : MonitorAPI
    memCaps : List Nat
    children : List DomCapa

end Alternative

end ThemisCapa
