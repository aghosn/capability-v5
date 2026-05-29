/-
  ThemisCapa.Invariants — System-wide well-formedness predicates.

  `WellFormed s` is the conjunction of every invariant the v2 spec
  maintains. Operations in `Step.lean` must preserve it; that is the
  content of the lemmas in `Properties.lean`.

  Vertical slice: only the invariants we need to prove
  `carve_preserves_wellformed`.
-/
import ThemisCapa.Basic
import ThemisCapa.State
import ThemisCapa.Arena

namespace ThemisCapa

/-- Arena keys are all unique. Maintained by always allocating fresh
    ids via the `nextXxxId` counters. -/
structure UniqueArenas (s : SpecState) : Prop where
  memcaps : s.memcaps.UniqueKeys
  domcaps : s.domcaps.UniqueKeys
  domains : s.domains.UniqueKeys

/-- Every memory-capability id mentioned anywhere in the state
    (parents, children, domain handles) resolves to an entry in the
    `memcaps` arena. -/
structure MemRefsResolved (s : SpecState) : Prop where
  parentInArena :
    ∀ id c, s.getMem id = some c →
      ∀ pid, c.parent = some pid → (s.getMem pid).isSome
  childInArena :
    ∀ id c, s.getMem id = some c →
      ∀ cid ∈ c.childrenIds, (s.getMem cid).isSome
  handleInArena :
    ∀ did d, s.getDom did = some d →
      ∀ p ∈ d.memHandles, (s.getMem p.2).isSome

/-- Local rights-and-containment monotonicity along the CDT.

    For every parent → child memory-capability edge, the child's access
    range is contained inside the parent's and its rights are a subset
    of the parent's. This is the per-edge piece; the chain version is a
    consequence (cf. v1's `chain_rights_monotonic`). -/
def CdtMonotonic (s : SpecState) : Prop :=
  ∀ id c, s.getMem id = some c →
    ∀ cid ∈ c.childrenIds,
      ∀ ch, s.getMem cid = some ch →
        ch.region.access.contained c.region.access

/-- A child memory capability's parent pointer agrees with its parent's
    `childrenIds` list. -/
def CdtBidirectional (s : SpecState) : Prop :=
  ∀ id c, s.getMem id = some c →
    ∀ cid ∈ c.childrenIds,
      ∀ ch, s.getMem cid = some ch →
        ch.parent = some id

/-- Invariant tying `nextMemCapId` to actual arena contents: every key
    currently in `memcaps` is strictly less than `nextMemCapId`. This
    makes `nextMemCapId` a *witness* of freshness — `insert s.nextMemCapId`
    is guaranteed to preserve `UniqueKeys`. -/
def FreshMemCounter (s : SpecState) : Prop :=
  ∀ id, id ∈ s.memcaps.keys → id < s.nextMemCapId

/-- Every memory-capability handle held by a domain points to a cap whose
    `owner` field equals that domain. This is Themis's exclusive-ownership
    invariant: a memcap is held by *exactly* its declared owner.

    Carve/alias preserve it by construction (the new handle is given to
    `caller` and the new cap's `owner` is set to `caller`). Send/accept
    (when implemented) will preserve it by transferring both the handle
    and the `owner` field atomically. -/
def HandleOwner (s : SpecState) : Prop :=
  ∀ did d, s.getDom did = some d →
    ∀ p ∈ d.memHandles,
      ∃ c, s.getMem p.2 = some c ∧ c.owner = did

/-- The full well-formedness predicate. -/
structure WellFormed (s : SpecState) : Prop where
  unique           : UniqueArenas s
  refs             : MemRefsResolved s
  cdtMonotonic     : CdtMonotonic s
  cdtBidirectional : CdtBidirectional s
  freshMemCounter  : FreshMemCounter s
  handleOwner      : HandleOwner s

end ThemisCapa
