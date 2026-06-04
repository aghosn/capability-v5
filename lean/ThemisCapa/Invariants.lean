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
import ThemisCapa.DomainTree
import ThemisCapa.Policy

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

/-- Same as `FreshMemCounter` for the domain arena. Required so
    `create` can allocate a fresh `DomId` and preserve `UniqueArenas.domains`. -/
def FreshDomCounter (s : SpecState) : Prop :=
  ∀ id, id ∈ s.domains.keys → id < s.nextDomId

/-- Same as `FreshMemCounter` for the domain-capability arena. Required so
    `create` can allocate a fresh `DomCapId` and preserve `UniqueArenas.domcaps`. -/
def FreshDomCapCounter (s : SpecState) : Prop :=
  ∀ id, id ∈ s.domcaps.keys → id < s.nextDomCapId

/-- Dual of `CdtBidirectional`: if a cap declares a parent, that parent
    actually lists it as a child. Together with `CdtBidirectional` this
    pins down a true bijection between the parent-pointer view and the
    children-list view of the CDT — no orphan pointers, no phantom
    children. Used by revoke to derive: if no cap can have `target` as
    parent (since `target.childrenIds = []`), then removing `target`
    doesn't dangle any `parent` pointer. -/
def ParentChildAgreement (s : SpecState) : Prop :=
  ∀ id c, s.getMem id = some c →
    ∀ pid, c.parent = some pid →
      ∀ p, s.getMem pid = some p → id ∈ p.childrenIds

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

/-- Every domain's `addressMap` is well-formed (pairwise GPA-disjoint).
    Created domains start with `AddressMap.empty` (trivially `Wf`) and
    only `mapSelf` mutates it; `mapSelf`'s guard supplies the disjointness
    side-condition needed to preserve this invariant. -/
def AddressMapsWf (s : SpecState) : Prop :=
  ∀ did d, s.getDom did = some d → d.addressMap.Wf

/-- For every domain `d`, every entry in `d.pendingMemCaps` (resp.
    `d.pendingDomCaps`) has a key strictly less than `d.nextPendingId`.
    Provides freshness of the pending counter — used by sealedSend to
    guarantee a freshly-allocated `pendingId` is unused as a key. -/
def FreshPending (s : SpecState) : Prop :=
  ∀ did d, s.getDom did = some d →
    (∀ p ∈ d.pendingMemCaps, p.1 < d.nextPendingId) ∧
    (∀ p ∈ d.pendingDomCaps, p.1 < d.nextPendingId)

/-- Corollary: a fresh `nextPendingId` is unused as a key in the
    receiver's existing `pendingMemCaps`. This is the form consumed
    by the O3 round-trip theorem. -/
theorem FreshPending.mem_fresh
    {s : SpecState} (h : FreshPending s)
    {did : DomId} {d : Domain} (hd : s.getDom did = some d) :
    ∀ p ∈ d.pendingMemCaps, p.1 ≠ d.nextPendingId := by
  intro p hp heq
  exact Nat.lt_irrefl _ (heq ▸ (h did d hd).1 p hp)

/-- **Core-affinity invariant.** Every VP that is currently in the
    `.running c _` state belongs to a domain whose policy permits
    `c`. Captures the O4 confinement property:
    a domain cannot execute on a core outside its `policy.cores`.

    Other `VpRunState` cases (`.available`, `.locked`, `.suspended`,
    `.interrupted`) carry no core obligation here — the engine enforces
    core membership at the *moment of transition into `.running`*. -/
def CoreAffinity (s : SpecState) : Prop :=
  ∀ did d, s.getDom did = some d →
    ∀ vp ∈ d.vps,
    ∀ c caller, vp.runState = VpRunState.running c caller →
    c ∈ d.policy.cores

/-- **Policy-monotonic-ancestry invariant.** Every child domain's
    policy refines its parent's per-component (`cores ⊆`, `api ≤`,
    `numVps ≤`, plus stubs for the remaining fields). Captures
    the engine's policy-refinement check at `create` time:
    a child cannot have rights the parent doesn't have.

    Subsumes per-field axes (each derivable in one line):
    * `CoreMonotonicAncestry` — every ancestor's `policy.cores`
      contains its descendant's.
    * `ApiMonotonicAncestry`  — same for `policy.api`.
    * `NumVpsMonotonicAncestry` — same for `policy.numVps`. -/
def PolicyMonotonicAncestry (s : SpecState) : Prop :=
  ∀ child parent d_c d_p,
    s.getDom child  = some d_c → d_c.parent = some parent →
    s.getDom parent = some d_p →
    d_c.policy ≤ d_p.policy

/-- Derived: per-core-axis monotonic ancestry. -/
theorem PolicyMonotonicAncestry.cores
    {s : SpecState} (h : PolicyMonotonicAncestry s)
    {child parent : DomId} {d_c d_p : Domain}
    (hc : s.getDom child = some d_c) (hp : d_c.parent = some parent)
    (hpd : s.getDom parent = some d_p) :
    d_c.policy.cores ⊆ d_p.policy.cores :=
  DomainPolicy.cores_le_of_le (h child parent d_c d_p hc hp hpd)

/-- Derived: per-API-axis monotonic ancestry. -/
theorem PolicyMonotonicAncestry.api
    {s : SpecState} (h : PolicyMonotonicAncestry s)
    {child parent : DomId} {d_c d_p : Domain}
    (hc : s.getDom child = some d_c) (hp : d_c.parent = some parent)
    (hpd : s.getDom parent = some d_p) :
    d_c.policy.api ≤ d_p.policy.api :=
  DomainPolicy.api_le_of_le (h child parent d_c d_p hc hp hpd)

/-- Derived: per-numVps-axis monotonic ancestry. -/
theorem PolicyMonotonicAncestry.numVps
    {s : SpecState} (h : PolicyMonotonicAncestry s)
    {child parent : DomId} {d_c d_p : Domain}
    (hc : s.getDom child = some d_c) (hp : d_c.parent = some parent)
    (hpd : s.getDom parent = some d_p) :
    d_c.policy.numVps ≤ d_p.policy.numVps :=
  DomainPolicy.numVps_le_of_le (h child parent d_c d_p hc hp hpd)

/-- The full well-formedness predicate. -/
structure WellFormed (s : SpecState) : Prop where
  unique             : UniqueArenas s
  refs               : MemRefsResolved s
  cdtMonotonic       : CdtMonotonic s
  cdtBidirectional   : CdtBidirectional s
  freshMemCounter    : FreshMemCounter s
  handleOwner        : HandleOwner s
  parentChild        : ParentChildAgreement s
  freshDomCounter    : FreshDomCounter s
  freshDomCapCounter : FreshDomCapCounter s
  addressMapsWf      : AddressMapsWf s
  domainTreeWf       : DomainTreeWf s
  freshPending       : FreshPending s
  coreAffinity       : CoreAffinity s
  policyAncestry     : PolicyMonotonicAncestry s

end ThemisCapa
