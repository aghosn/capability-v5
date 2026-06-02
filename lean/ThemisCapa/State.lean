/-
  ThemisCapa.State — v2 spec state.

  Flat arena-indexed representation, designed to match the shape of an
  Aeneas extraction of a future `capa-engine-core/` Rust crate.

  Key differences from v1 (`archive-v1/ThemisCapa/Capability.lean`):

    * `MemCap` and `DomCap` are no longer recursive trees. Children are
      referenced by `CapId` / `DomId` and stored in arena finmaps on the
      top-level `SpecState`.
    * A `Domain`'s view of its capabilities is a list of `(LocalHandle ×
      CapId)` pairs; the actual `MemCap`/`DomCap` lives in the arena.
    * Identifiers are globally unique `Nat`s allocated by counters on
      `SpecState`.

  See `docs/capability-engine/aeneas-exploration.md` §10.2 for the design
  rationale.
-/
import ThemisCapa.Basic
import ThemisCapa.Domain
import ThemisCapa.Interposition
import ThemisCapa.Translation
import ThemisCapa.Arena

namespace ThemisCapa

/-- A memory region: kind + observable status + range + attributes,
    plus optional content hash, COMM binding, and cache-coloring bitmap.
    Mirrors `capa-engine/src/memory.rs::MemoryRegion`. -/
structure MemoryRegion where
  kind         : RegionKind
  status       : RegionStatus
  access       : Access
  attributes   : Attributes
  contentHash  : Option (List Nat)            -- 32-byte hash (HASH attr only)
  commBinding  : Option CommBinding           -- COMM attr binding
  colorBitmap  : Option Translation.ColorBitmap  -- cache-coloring (feature-gated)

namespace MemoryRegion
/-- Plain region with no hash, no comm binding, no color pinning. -/
def mk' (kind : RegionKind) (status : RegionStatus)
        (access : Access) (attrs : Attributes) : MemoryRegion :=
  ⟨kind, status, access, attrs, none, none, none⟩
end MemoryRegion

/-- A memory capability node in the flat-arena CDT.

    Parent and children are encoded by `MemCapId` rather than nested
    structures. The `owner` is the domain that currently holds this
    capability through one of its `memHandles` entries. -/
structure MemCap where
  parent       : Option MemCapId
  owner        : DomId
  region       : MemoryRegion
  childrenIds  : List MemCapId
  nextChildSub : SubHandle

/-- A domain capability node in the flat-arena CDT.

    `targetDom` is the `DomId` of the domain this capability refers to.
    `parent` is the parent *domain capability* (not domain). -/
structure DomCap where
  parent     : Option DomCapId
  owner      : DomId        -- holder of this dom-cap
  targetDom  : DomId        -- domain the cap points to
  /-- A *channel* dom-cap can be transferred via `sendChannel` and
      received via `acceptChannel`. Plain (non-channel) dom-caps are
      created by `create` and removed by `revokeDomain`. -/
  isChannel  : Bool := false

/-- A memory cap that has been sent but not yet accepted.
    Mirrors `capa-engine/src/domain.rs::PendingCapability`. -/
structure PendingMemCap where
  capId          : MemCapId
  senderDomainId : DomId
  senderHandle   : LocalHandle
  gpaHint        : Option Nat   -- only meaningful with address_translation

/-- A channel (domain) cap that has been sent but not yet accepted.
    Mirrors `capa-engine/src/domain.rs::PendingDomainCapability`. -/
structure PendingDomCap where
  capId          : DomCapId
  senderDomainId : DomId
  senderHandle   : LocalHandle

/-- A domain's mutable bookkeeping. Memory and domain *capability tables*
    map a domain-local `LocalHandle` to the global arena id. -/
structure Domain where
  parent             : Option DomId
  status             : DomainStatus
  policy             : DomainPolicy
  vps                : List VProcessor
  memHandles         : List (LocalHandle × MemCapId)
  domHandles         : List (LocalHandle × DomCapId)
  frozenHandles      : List LocalHandle
  childrenDoms       : List DomId
  pendingMemCaps     : List (PendingId × PendingMemCap)
  pendingDomCaps     : List (PendingId × PendingDomCap)
  /-- Weak refs to parent-owned COMM caps bound to *this* domain's VPs;
      cleared on revocation. Mirrors `Domain::comm_bindings` in Rust. -/
  commBindings       : List MemCapId
  /-- Per-domain HPA↔GPA translation bookkeeping (gated by
      `address_translation` in Rust; always present in the spec). -/
  addressMap         : Translation.AddressMap
  /-- Per-handle GPA base. Mirrors `Domain::mapped_gpas`. -/
  mappedGpas         : List (LocalHandle × Nat)
  nextHandle         : LocalHandle
  nextPendingId      : PendingId

namespace Domain

def isSealed   (d : Domain) : Prop := d.status = .sealed
def isUnsealed (d : Domain) : Prop := d.status = .unsealed

/-- Resolve a domain-local memory-capability handle to the global arena id. -/
def lookupMemHandle (d : Domain) (h : LocalHandle) : Option MemCapId :=
  (d.memHandles.find? (fun p => p.1 = h)).map Prod.snd

/-- Resolve a domain-local memcap handle to its currently-mapped GPA. -/
def lookupMappedGpa (d : Domain) (h : LocalHandle) : Option Nat :=
  (d.mappedGpas.find? (fun p => p.1 = h)).map Prod.snd

/-- Functionally update (or insert) the GPA bound to handle `h`. -/
def updMappedGpa (d : Domain) (h : LocalHandle) (gpa : Nat) : Domain :=
  let entries := d.mappedGpas.map (fun p =>
    if p.1 = h then (p.1, gpa) else p)
  if d.mappedGpas.any (fun p => p.1 = h) then
    { d with mappedGpas := entries }
  else
    { d with mappedGpas := (h, gpa) :: d.mappedGpas }

/-- Resolve a domain-local domain-capability handle to the global arena id. -/
def lookupDomHandle (d : Domain) (h : LocalHandle) : Option DomCapId :=
  (d.domHandles.find? (fun p => p.1 = h)).map Prod.snd

/-- Resolve a pending-memcap id to the pending entry. -/
def lookupPending (d : Domain) (pid : PendingId) : Option PendingMemCap :=
  (d.pendingMemCaps.find? (fun p => p.1 = pid)).map Prod.snd

/-- Resolve a pending-domcap (channel) id to the pending entry. -/
def lookupPendingDom (d : Domain) (pid : PendingId) : Option PendingDomCap :=
  (d.pendingDomCaps.find? (fun p => p.1 = pid)).map Prod.snd

/-- Find the VP (if any) currently bound to `core` according to its
    `runState`. Mirrors `capa-engine/src/domain.rs::find_vp_on_core`. -/
def findVpOnCore (d : Domain) (core : CoreId) : Option VProcessor :=
  d.vps.find? (fun vp =>
    match vp.runState with
    | .running c _ => decide (c = core)
    | _            => false)

/-- Lookup a VP by its id within this domain. -/
def lookupVp (d : Domain) (vpId : VpId) : Option VProcessor :=
  d.vps.find? (fun vp => decide (vp.id = vpId))

/-- Functionally update the VP with id `vpId` in place. Identity if no
    such VP exists. -/
def updVp (d : Domain) (vpId : VpId) (f : VProcessor → VProcessor) : Domain :=
  { d with vps := d.vps.map (fun vp =>
              if vp.id = vpId then f vp else vp) }

/-- The (caller-VP id, saved previous-caller context) of the VP currently
    running on `core` in this domain, if any. Returns `none` if no VP is
    on this core or that VP is not in `.running _ (some _)`. Used as the
    `affectsDom` projection for `switchReturn`. -/
def vpAndPrevCallerOnCore (d : Domain) (core : CoreId) :
    Option (VpId × VpCallContext) :=
  (d.findVpOnCore core).bind (fun vp =>
    match vp.runState with
    | .running _ (some pctx) => some (vp.id, pctx)
    | _                      => none)

/-- The (VP id, optional saved-caller) of the VP currently running on
    `core` in this domain. Differs from `vpAndPrevCallerOnCore` in that
    it allows the running VP to have `caller = none`. Used by the
    forward-`switch` path which only requires the VP to be in `.running`
    (any prev-caller chain). -/
def vpAndOptPrevOnCore (d : Domain) (core : CoreId) :
    Option (VpId × Option VpCallContext) :=
  (d.findVpOnCore core).bind (fun vp =>
    match vp.runState with
    | .running _ optPrev => some (vp.id, optPrev)
    | _                  => none)

end Domain

/-- Per-core scheduling state. Mirrors `capa-engine/src/switch.rs::CoreState`. -/
inductive CoreState where
  | idle
  | runningDomain (domainId : DomId) (vpId : VpId)
deriving DecidableEq, Repr

/-- The complete v2 spec state.

    All capability cells live in `memcaps` / `domcaps`. Domains live in
    `domains`. Per-core state lives in `cores`. The arenas are unique-key
    finmaps; `nextMemCapId` / `nextDomCapId` / `nextDomId` are monotonic
    counters used to allocate fresh ids.

    `root : DomId` is the bootstrap domain (id 0 in practice). -/
structure SpecState where
  memcaps      : Arena MemCapId MemCap
  domcaps      : Arena DomCapId DomCap
  domains      : Arena DomId Domain
  cores        : Arena CoreId CoreState
  root         : DomId
  nextMemCapId : MemCapId
  nextDomCapId : DomCapId
  nextDomId    : DomId

namespace SpecState

def getMem    (s : SpecState) (id : MemCapId) : Option MemCap := s.memcaps.find? id
def getDom    (s : SpecState) (id : DomId)    : Option Domain := s.domains.find? id
def getDomCap (s : SpecState) (id : DomCapId) : Option DomCap := s.domcaps.find? id

/-- Insert a fresh memory capability and bump the counter. Returns the
    new id and the updated state. -/
def freshMem (s : SpecState) (c : MemCap) : MemCapId × SpecState :=
  let id := s.nextMemCapId
  let s' := { s with
    memcaps := s.memcaps.insert id c,
    nextMemCapId := id + 1 }
  (id, s')

/-- Insert a fresh domain and bump the `nextDomId` counter. -/
def freshDom (s : SpecState) (d : Domain) : DomId × SpecState :=
  let id := s.nextDomId
  let s' := { s with
    domains  := s.domains.insert id d,
    nextDomId := id + 1 }
  (id, s')

/-- Insert a fresh domain-capability and bump the `nextDomCapId` counter. -/
def freshDomCap (s : SpecState) (dc : DomCap) : DomCapId × SpecState :=
  let id := s.nextDomCapId
  let s' := { s with
    domcaps      := s.domcaps.insert id dc,
    nextDomCapId := id + 1 }
  (id, s')

/-- Functionally update a memory capability in place. -/
def updMem (s : SpecState) (id : MemCapId) (f : MemCap → MemCap) : SpecState :=
  { s with memcaps := s.memcaps.update id f }

/-- Functionally update a domain in place. -/
def updDomain (s : SpecState) (id : DomId) (f : Domain → Domain) : SpecState :=
  { s with domains := s.domains.update id f }

/-- Functionally update a domain-capability in place. -/
def updDomCap (s : SpecState) (id : DomCapId) (f : DomCap → DomCap) : SpecState :=
  { s with domcaps := s.domcaps.update id f }

/-- Look up the per-core scheduling state. -/
def getCore (s : SpecState) (id : CoreId) : Option CoreState := s.cores.find? id

/-- Functionally update a core's `CoreState` in place. -/
def updCore (s : SpecState) (id : CoreId) (f : CoreState → CoreState) : SpecState :=
  { s with cores := s.cores.update id f }

end SpecState

end ThemisCapa
