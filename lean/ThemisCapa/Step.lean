/-
  ThemisCapa.Step — Small-step transition relation.

  `step s a s'` holds iff action `a` is enabled in state `s` and produces
  state `s'`. Each constructor packages a *guard* predicate (preconditions,
  classically `XxxPre` in v1) with an *apply* function (the state update,
  classically `XxxPost` in v1).

  Vertical slice: `carve` only.
-/
import ThemisCapa.Basic
import ThemisCapa.State
import ThemisCapa.Action

namespace ThemisCapa

/-! ### Carve -/

/-- Preconditions for `carve(caller, parent, access, attrs)`. Mirrors v1's
    `CarvePre` but resolved against `SpecState`. -/
structure CarveGuard (s : SpecState) (caller : DomId) (parent : MemCapId)
    (access : Access) (attrs : Attributes) : Prop where
  callerExists    : (s.getDom caller).isSome
  parentExists    : (s.getMem parent).isSome
  callerSealed    :
    ∀ d, s.getDom caller = some d → d.isSealed
  hasPermission   :
    ∀ d, s.getDom caller = some d → d.policy.api.canCarve = true
  parentOwned     :
    ∀ d, s.getDom caller = some d →
      ∃ h, d.lookupMemHandle h = some parent
  accessContained :
    ∀ p, s.getMem parent = some p → access.contained p.region.access
  noOverlapCarved :
    ∀ p, s.getMem parent = some p →
      ∀ chId ∈ p.childrenIds,
        ∀ ch, s.getMem chId = some ch →
          ch.region.kind = .carve →
          ¬ Access.overlaps ch.region.access access
  aliasNoOverlap  :
    ∀ p, s.getMem parent = some p →
      p.region.kind = .alias →
      ∀ chId ∈ p.childrenIds,
        ∀ ch, s.getMem chId = some ch →
          ¬ Access.overlaps ch.region.access access
  notComm         : ∀ p, s.getMem parent = some p → p.region.attributes.comm = false
  notMeta         : ∀ p, s.getMem parent = some p → p.region.attributes.meta = false

/-- Pure state update for a successful `carve`.

    1. Allocate a fresh `MemCapId` for the child via `freshMem`.
    2. Append it to the parent's `childrenIds` and bump
       `parent.nextChildSub`.
    3. Append a fresh `LocalHandle → childId` entry into the caller's
       `memHandles` and bump `nextHandle`.

    Returns the updated state. The new id is implicit in the resulting
    state (it is `s.nextMemCapId`). -/
def carve_apply (s : SpecState) (caller : DomId) (parent : MemCapId)
    (access : Access) (attrs : Attributes) : SpecState :=
  -- Parent must exist (guarded by CarveGuard); if not, return s unchanged.
  match s.getMem parent with
  | none => s
  | some p =>
    let childCap : MemCap := {
      parent       := some parent,
      owner        := caller,
      region       := MemoryRegion.mk' .carve p.region.status access attrs,
      childrenIds  := [],
      nextChildSub := 0
    }
    let (childId, s₁) := s.freshMem childCap
    let s₂ := s₁.updMem parent (fun pc =>
      { pc with childrenIds := pc.childrenIds ++ [childId],
                nextChildSub := pc.nextChildSub + 1 })
    let s₃ := s₂.updDomain caller (fun d =>
      { d with memHandles := d.memHandles ++ [(d.nextHandle, childId)],
               nextHandle := d.nextHandle + 1 })
    s₃

/-! ### Alias -/

/-- Preconditions for `alias(caller, parent, access)`. Mirrors v1's
    `AliasPre` but resolved against `SpecState`. Differences vs `CarveGuard`:
    `hasPermission` checks `canAlias`, the overlap restriction is only
    against `RegionKind.carve` children, and there is no analogue of
    `aliasNoOverlap` (alias→alias overlap is fine). -/
structure AliasGuard (s : SpecState) (caller : DomId) (parent : MemCapId)
    (access : Access) : Prop where
  callerExists    : (s.getDom caller).isSome
  parentExists    : (s.getMem parent).isSome
  callerSealed    : ∀ d, s.getDom caller = some d → d.isSealed
  hasPermission   : ∀ d, s.getDom caller = some d → d.policy.api.canAlias = true
  parentOwned     :
    ∀ d, s.getDom caller = some d → ∃ h, d.lookupMemHandle h = some parent
  accessContained : ∀ p, s.getMem parent = some p → access.contained p.region.access
  noOverlapCarved :
    ∀ p, s.getMem parent = some p →
      ∀ chId ∈ p.childrenIds,
        ∀ ch, s.getMem chId = some ch →
          ch.region.kind = .carve →
          ¬ Access.overlaps ch.region.access access
  notComm         : ∀ p, s.getMem parent = some p → p.region.attributes.comm = false
  notMeta         : ∀ p, s.getMem parent = some p → p.region.attributes.meta = false

/-- Pure state update for a successful `alias`.  Identical shape to
    `carve_apply`: insert a fresh child, append child id to parent's
    children list, append a fresh handle on the caller domain.  The
    only differences are the child's region kind (`alias`) and status
    (`aliased`); attributes are inherited from the parent. -/
def alias_apply (s : SpecState) (caller : DomId) (parent : MemCapId)
    (access : Access) : SpecState :=
  match s.getMem parent with
  | none => s
  | some p =>
    let childCap : MemCap := {
      parent       := some parent,
      owner        := caller,
      region       := MemoryRegion.mk' .alias .aliased access p.region.attributes,
      childrenIds  := [],
      nextChildSub := 0
    }
    let (childId, s₁) := s.freshMem childCap
    let s₂ := s₁.updMem parent (fun pc =>
      { pc with childrenIds := pc.childrenIds ++ [childId],
                nextChildSub := pc.nextChildSub + 1 })
    let s₃ := s₂.updDomain caller (fun d =>
      { d with memHandles := d.memHandles ++ [(d.nextHandle, childId)],
               nextHandle := d.nextHandle + 1 })
    s₃

/-! ### Revoke

Slice scope: leaf revocation only. The Rust `revoke` deletes a whole
subtree recursively; the spec version requires `target.childrenIds = []`
so the proof can focus on the single-cap removal. Full subtree revocation
will be added later by iterating leaf revoke (postorder) or by
strengthening the guard. -/

/-- Preconditions for `revoke(caller, target)`. -/
structure RevokeGuard (s : SpecState) (caller : DomId) (target : MemCapId) : Prop where
  callerExists      : (s.getDom caller).isSome
  targetExists      : (s.getMem target).isSome
  callerSealed      : ∀ d, s.getDom caller = some d → d.isSealed
  hasPermission     : ∀ d, s.getDom caller = some d → d.policy.api.canRevoke = true
  /-- Slice restriction: `target` must be a leaf. -/
  targetIsLeaf      : ∀ t, s.getMem target = some t → t.childrenIds = []
  /-- `target` must have a parent (root caps are not revocable through this op). -/
  targetHasParent   : ∀ t, s.getMem target = some t → t.parent.isSome
  /-- The caller owns the parent cap (mirrors Rust's `p.owned.owner != owner_id` check). -/
  callerOwnsParent  :
    ∀ t, s.getMem target = some t →
      ∀ pid, t.parent = some pid →
        ∀ p, s.getMem pid = some p → p.owner = caller
  /-- META regions cannot be revoked. -/
  notMeta           :
    ∀ t, s.getMem target = some t → t.region.attributes.meta = false
  /-- Owner of `target` must be live (not yet revoked). Prevents
      double-cascade and re-entering the cascade on a tombstone. -/
  targetOwnerLive   :
    ∀ t, s.getMem target = some t →
      ∀ d, s.getDom t.owner = some d → d.isLive

/-- Pure state update for a successful leaf `revoke`.

    1. Remove `target` from the memcap arena.
    2. Strip `target` from its parent's `childrenIds` list.
    3. Strip any handle to `target` from the owner domain's `memHandles`.
    4. **VITAL cascade (G1, leaf-only)**: if `target` carried
       `attributes.vital = true`, mark the owning domain as
       `revoked`. The full cascade (revoking the owner's children
       domains, root memcaps, channels — G3) is not yet modeled;
       the resulting state is a "tombstone with debris."

    The `HandleOwner` invariant guarantees that *only* `t.owner` holds a
    handle to `target`, so step 3 is local to a single domain.
    Note: when `t.owner = caller`, step 3 and step 4 update the same
    domain in sequence; this matches the engine, where a domain that
    revokes its own vital memcap dies. -/
def revoke_apply (s : SpecState) (caller : DomId) (target : MemCapId) : SpecState :=
  match s.getMem target with
  | none => s
  | some t =>
    match t.parent with
    | none => s
    | some pid =>
      let s₁ : SpecState := { s with memcaps := s.memcaps.remove target }
      let s₂ := s₁.updMem pid (fun p =>
        { p with childrenIds := p.childrenIds.filter (· ≠ target) })
      let s₃ := s₂.updDomain t.owner (fun d =>
        { d with memHandles := d.memHandles.filter (fun h => h.2 ≠ target) })
      if t.region.attributes.vital then
        s₃.updDomain t.owner (fun d => { d with status := .revoked })
      else
        s₃

/-- Preconditions for `send(caller, receiver, cap)`. Slice scope: models
    only the **unsealed** path (immediate ownership transfer). -/
structure SendGuard (s : SpecState) (caller : DomId) (receiver : DomId)
                    (cap : MemCapId) : Prop where
  callerExists      : (s.getDom caller).isSome
  receiverExists    : (s.getDom receiver).isSome
  callerSealed      : ∀ d, s.getDom caller = some d → d.isSealed
  hasPermission     : ∀ d, s.getDom caller = some d → d.policy.api.canSend = true
  capExists         : (s.getMem cap).isSome
  /-- Caller currently owns `cap`. -/
  callerOwnsCap     : ∀ c, s.getMem cap = some c → c.owner = caller
  /-- Send-to-self forbidden (would require a more delicate post-state). -/
  notSelf           : caller ≠ receiver
  /-- META regions cannot be sent (matches Rust `send_at` check). -/
  notMeta           :
    ∀ c, s.getMem cap = some c → c.region.attributes.meta = false
  /-- Receiver must be live (not yet revoked). -/
  receiverLive      :
    ∀ d, s.getDom receiver = some d → d.isLive

/-- Pure state update for a successful unsealed `send`.

    1. Drop *all* handles to `cap` from caller's `memHandles`.
    2. Append a fresh handle `(d.nextHandle, cap)` to receiver's
       `memHandles` and bump `nextHandle`.
    3. Update `cap.owner` to `receiver`.

    Note: caller might hold multiple handles to the same `cap`; we drop
    them all to keep `HandleOwner` simple. The Rust engine in practice
    enforces single-handle-per-cap-per-domain via fresh handle allocation. -/
def send_apply (s : SpecState) (caller : DomId) (receiver : DomId)
               (cap : MemCapId) : SpecState :=
  let s₁ := s.updDomain caller (fun d =>
    { d with memHandles := d.memHandles.filter (fun h => h.2 ≠ cap) })
  let s₂ := s₁.updDomain receiver (fun d =>
    { d with memHandles := d.memHandles ++ [(d.nextHandle, cap)],
             nextHandle := d.nextHandle + 1 })
  let s₃ := s₂.updMem cap (fun c => { c with owner := receiver })
  s₃

/-! ### Seal operation

Seal flips a domain's `status` from `unsealed` to `sealed`. The caller
must hold a domain-cap (`cap : DomCapId`) referencing the target. -/

/-- Preconditions for `seal(caller, cap)`. -/
structure SealGuard (s : SpecState) (caller : DomId) (cap : DomCapId) : Prop where
  callerExists      : (s.getDom caller).isSome
  /-- Caller domain itself must already be sealed (only sealed domains
      issue hypercalls). -/
  callerSealed      : ∀ d, s.getDom caller = some d → d.isSealed
  /-- The domain-cap exists. -/
  capExists         : (s.getDomCap cap).isSome
  /-- The domain-cap is held by the caller. -/
  capOwnedByCaller  : ∀ dc, s.getDomCap cap = some dc → dc.owner = caller
  /-- The target domain (referenced by `cap`) exists. -/
  targetExists      :
    ∀ dc, s.getDomCap cap = some dc → (s.getDom dc.targetDom).isSome
  /-- The target domain is currently unsealed. -/
  targetUnsealed    :
    ∀ dc, s.getDomCap cap = some dc →
    ∀ td, s.getDom dc.targetDom = some td → td.isUnsealed
  /-- The target's `owned` policy permits `SEAL`. Mirrors the engine
      `cap_ref.read().owned.validate_operation(MonitorAPI::SEAL)` check. -/
  hasPermission     :
    ∀ dc, s.getDomCap cap = some dc →
    ∀ td, s.getDom dc.targetDom = some td → td.policy.api.canSeal = true

/-- Pure state update for a successful `seal`: flip the target domain's
    `status` field to `.sealed`. Everything else unchanged. -/
def seal_apply (s : SpecState) (caller : DomId) (cap : DomCapId) : SpecState :=
  match s.getDomCap cap with
  | none    => s
  | some dc => s.updDomain dc.targetDom (fun d => { d with status := .sealed })

/-! ### Set policy -/

/-- Pointwise update on a `DomainPolicy` keyed by `PolicyIdentifier`.

    **Stub.** Mirrors the *structure* of `set_policy` faithfully (the
    update is keyed by the identifier and value), but the per-identifier
    semantics are intentionally left as no-ops for now: locality and
    provenance theorems are insensitive to the exact field update, since
    they only observe *which* domain record is modified. Refining the
    per-case lattice (`cores` monotonicity, `apiMonitor` subset, etc.)
    is independent follow-up work.

    Future refinement: replicate the 13-way case match from
    `capa-engine/src/capability.rs::set_policy`. -/
def applyPolicyValue (p : DomainPolicy) (_id : PolicyIdentifier)
                     (_value : Nat) : DomainPolicy := p

/-- Preconditions for `setPolicy(caller, cap, id, value)`. Mirrors
    `capa-engine/src/capability.rs::set_policy`: caller must own the
    DomCap, the target domain must be unsealed, caller's `MonitorAPI`
    must include `canSet`. Per-identifier monotonicity (value ≤ parent
    value) is intentionally deferred — see `applyPolicyValue`. -/
structure SetPolicyGuard (s : SpecState) (caller : DomId) (cap : DomCapId)
    (_id : PolicyIdentifier) (_value : Nat) : Prop where
  callerExists      : (s.getDom caller).isSome
  callerSealed      : ∀ d, s.getDom caller = some d → d.isSealed
  hasPermission     :
    ∀ d, s.getDom caller = some d → d.policy.api.canSet = true
  capExists         : (s.getDomCap cap).isSome
  capOwnedByCaller  : ∀ dc, s.getDomCap cap = some dc → dc.owner = caller
  targetExists      :
    ∀ dc, s.getDomCap cap = some dc → (s.getDom dc.targetDom).isSome
  targetUnsealed    :
    ∀ dc, s.getDomCap cap = some dc →
    ∀ td, s.getDom dc.targetDom = some td → td.isUnsealed

/-- Pure state update for a successful `setPolicy`: replace the target
    domain's `policy` with `applyPolicyValue old id value`. Everything
    else unchanged. -/
def setPolicy_apply (s : SpecState) (caller : DomId) (cap : DomCapId)
                    (id : PolicyIdentifier) (value : Nat) : SpecState :=
  match s.getDomCap cap with
  | none    => s
  | some dc =>
      s.updDomain dc.targetDom
        (fun d => { d with policy := applyPolicyValue d.policy id value })

/-! ### Accept / Reject (sealed-path completion) -/

/-- Preconditions for `accept(receiver, pid)`. Minimal: only the facts
    actually needed by `send_apply_preserves_wellformed` (cap exists,
    owned by sender, sender ≠ receiver) plus pending-resolution
    obligations. The earlier over-restrictions (`senderSealed`,
    `senderCanSend`, `notMeta`) have been dropped now that the WF lemma
    no longer depends on `SendGuard`'s policy fields. -/
structure AcceptGuard (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    : Prop where
  receiverExists    : (s.getDom receiver).isSome
  receiverSealed    : ∀ d, s.getDom receiver = some d → d.isSealed
  pendingFound      : ∀ d, s.getDom receiver = some d →
                      (d.lookupPending pendingId).isSome
  senderExists      : ∀ d pe, s.getDom receiver = some d →
                      d.lookupPending pendingId = some pe →
                      (s.getDom pe.senderDomainId).isSome
  capExists         : ∀ d pe, s.getDom receiver = some d →
                      d.lookupPending pendingId = some pe →
                      (s.getMem pe.capId).isSome
  capOwnedBySender  : ∀ d pe, s.getDom receiver = some d →
                      d.lookupPending pendingId = some pe →
                      ∀ c, s.getMem pe.capId = some c → c.owner = pe.senderDomainId
  notSelf           : ∀ d pe, s.getDom receiver = some d →
                      d.lookupPending pendingId = some pe →
                      pe.senderDomainId ≠ receiver
  /-- Sender must be live (not yet revoked). -/
  senderLive        : ∀ d pe, s.getDom receiver = some d →
                      d.lookupPending pendingId = some pe →
                      ∀ sd, s.getDom pe.senderDomainId = some sd → sd.isLive

/-- Pure state update for `accept`. No-op when receiver / pending lookup
    fails (well-formedness then preserved trivially). -/
def accept_apply (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    : SpecState :=
  match (s.getDom receiver).bind (fun d => d.lookupPending pendingId) with
  | none    => s
  | some pe =>
    ((send_apply s pe.senderDomainId receiver pe.capId).updDomain receiver
      (fun d' =>
        { d' with pendingMemCaps :=
                    d'.pendingMemCaps.filter (fun p => p.1 ≠ pendingId) })).updDomain
      pe.senderDomainId
      (fun d' =>
        { d' with frozenHandles :=
                    d'.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })

/-- Preconditions for `reject(receiver, pid)`. -/
structure RejectGuard (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    : Prop where
  receiverExists    : (s.getDom receiver).isSome
  pendingFound      : ∀ d, s.getDom receiver = some d →
                      (d.lookupPending pendingId).isSome
  /-- Receiver must be live (not yet revoked). -/
  receiverLive      : ∀ d, s.getDom receiver = some d → d.isLive
  /-- Sender must be live (not yet revoked). -/
  senderLive        : ∀ d pe, s.getDom receiver = some d →
                      d.lookupPending pendingId = some pe →
                      ∀ sd, s.getDom pe.senderDomainId = some sd → sd.isLive

/-- Pure state update for `reject`: remove pending from receiver and
    unfreeze sender's handle. Both affected fields are outside
    `WellFormed`, so this is a no-op at the invariant level. -/
def reject_apply (s : SpecState) (receiver : DomId) (pendingId : PendingId)
    : SpecState :=
  let s₁ := s.updDomain receiver (fun d =>
    { d with pendingMemCaps :=
              d.pendingMemCaps.filter (fun p => p.1 ≠ pendingId) })
  match (s.getDom receiver).bind (fun d => d.lookupPending pendingId) with
  | none    => s₁
  | some pe =>
    s₁.updDomain pe.senderDomainId (fun d =>
      { d with frozenHandles :=
                d.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })

/-! ### Sealed send

The sealed-send path mirrors the engine's `send_memory_sealed`: the cap
is *not* transferred. Instead the sender's handle is frozen and a
`PendingMemCap` entry is enqueued on the receiver. Receiver later calls
`accept` (completes the transfer) or `reject` (rolls back).

Only invariant-invisible fields (`frozenHandles`, `pendingMemCaps`,
`nextPendingId`) are touched, so WF preservation falls out of the
generic `wf_preserved_under_handle_invariant_updDomain` helper. -/

/-- Preconditions for `sealedSend(caller, receiver, handle, gpaHint)`. -/
structure SealedSendGuard (s : SpecState) (caller : DomId) (receiver : DomId)
                          (handle : LocalHandle) : Prop where
  callerExists      : (s.getDom caller).isSome
  receiverExists    : (s.getDom receiver).isSome
  callerSealed      : ∀ d, s.getDom caller = some d → d.isSealed
  hasPermission     : ∀ d, s.getDom caller = some d → d.policy.api.canSend = true
  receiverPermits   : ∀ rd, s.getDom receiver = some rd →
                            rd.policy.api.canReceiveAfterSeal = true
  /-- The local handle resolves to some memcap held by the caller. -/
  handleResolves    : ∀ d, s.getDom caller = some d →
                            (d.lookupMemHandle handle).isSome
  /-- The resolved cap exists in the arena. -/
  capExists         : ∀ d, s.getDom caller = some d →
                            ∀ capId, d.lookupMemHandle handle = some capId →
                            (s.getMem capId).isSome
  /-- The caller actually owns the resolved cap. -/
  callerOwnsCap     : ∀ d, s.getDom caller = some d →
                            ∀ capId, d.lookupMemHandle handle = some capId →
                            ∀ c, s.getMem capId = some c → c.owner = caller
  /-- Send-to-self forbidden (matches `send_at`). -/
  notSelf           : caller ≠ receiver
  /-- META regions cannot be sent. -/
  notMeta           : ∀ d, s.getDom caller = some d →
                            ∀ capId, d.lookupMemHandle handle = some capId →
                            ∀ c, s.getMem capId = some c →
                            c.region.attributes.meta = false
  /-- The handle is not already frozen (mirrors the engine's
      `is_memory_handle_frozen` check). -/
  notFrozen         : ∀ d, s.getDom caller = some d → handle ∉ d.frozenHandles
  /-- Receiver must be live (not yet revoked). -/
  receiverLive      : ∀ d, s.getDom receiver = some d → d.isLive

/-- Pure state update for `sealedSend`.

    1. Append `handle` to the caller's `frozenHandles`.
    2. Append a fresh `(nextPendingId, PendingMemCap{..})` to the
       receiver's `pendingMemCaps` and bump `nextPendingId`.

    No memcap or handle ownership changes. Returns `s` unchanged when
    handle resolution fails. -/
def sealedSend_apply (s : SpecState) (caller receiver : DomId)
                     (handle : LocalHandle) (gpaHint : Option Nat) : SpecState :=
  match (s.getDom caller).bind (fun d => d.lookupMemHandle handle) with
  | none       => s
  | some capId =>
    let s₁ := s.updDomain caller (fun d =>
      { d with frozenHandles := d.frozenHandles ++ [handle] })
    s₁.updDomain receiver (fun d =>
      let pid := d.nextPendingId
      let pe  : PendingMemCap :=
        { capId := capId, senderDomainId := caller,
          senderHandle := handle, gpaHint := gpaHint }
      { d with pendingMemCaps := d.pendingMemCaps ++ [(pid, pe)],
               nextPendingId  := pid + 1 })

/-! ### Create

Allocates a new child domain. Two arena inserts (`Domain` and `DomCap`)
plus one `updDomain` on the caller (new dom-handle + childrenDoms). -/

/-- Preconditions for `create(caller, policy)`. -/
structure CreateGuard (s : SpecState) (caller : DomId) (policy : DomainPolicy)
    : Prop where
  callerExists      : (s.getDom caller).isSome
  callerSealed      : ∀ d, s.getDom caller = some d → d.isSealed
  hasPermission     : ∀ d, s.getDom caller = some d → d.policy.api.canCreate = true
  /-- Engine's policy-monotonicity check: child policy's API is a
      subset of the parent's. -/
  policyApiSubset   : ∀ d, s.getDom caller = some d → policy.api ≤ d.policy.api

/-- Construct the freshly-allocated child domain (unsealed, no caps yet,
    parent = caller). -/
def freshChildDomain (caller : DomId) (policy : DomainPolicy) : Domain :=
  { parent          := some caller,
    status          := .unsealed,
    policy          := policy,
    vps             := [],
    memHandles      := [],
    domHandles      := [],
    frozenHandles   := [],
    childrenDoms    := [],
    pendingMemCaps  := [],
    pendingDomCaps  := [],
    commBindings    := [],
    addressMap      := Translation.AddressMap.empty,
    mappedGpas      := [],
    nextHandle      := 0,
    nextPendingId   := 0 }

/-- Pure state update for `create(caller, policy)`.

    1. Allocate a fresh `Domain` at `s.nextDomId` via `freshDom`.
    2. Allocate a fresh `DomCap` at the (bumped) `nextDomCapId` via
       `freshDomCap`, with `owner := caller` and
       `targetDom := newDomId`.
    3. Append a fresh `(d.nextHandle, newCapId)` to caller's
       `domHandles` and append `newDomId` to caller's `childrenDoms`. -/
def create_apply (s : SpecState) (caller : DomId)
                 (policy : DomainPolicy) : SpecState :=
  let (newDomId, s₁) := s.freshDom (freshChildDomain caller policy)
  let newDomCap : DomCap :=
    { parent := none, owner := caller, targetDom := newDomId }
  let (newCapId, s₂) := s₁.freshDomCap newDomCap
  s₂.updDomain caller (fun d =>
    { d with domHandles   := d.domHandles ++ [(d.nextHandle, newCapId)],
             nextHandle   := d.nextHandle + 1,
             childrenDoms := d.childrenDoms ++ [newDomId] })

/-! ### RevokeDomain (leaf-only)

Slice scope: leaf domain revocation only. The Rust `revoke_domain`
deletes a whole subtree recursively; the spec version requires the
target to have no children, no held memcaps, and no held domcaps,
so the proof reduces to removing one domain + one dom-cap and
patching the caller's `domHandles` / `childrenDoms`. Full subtree
revocation is future work.

Target must differ from caller (you can't revoke yourself through
this op). -/

/-- Preconditions for `revokeDomain(caller, handle)`. -/
structure RevokeDomainGuard (s : SpecState) (caller : DomId) (handle : LocalHandle)
    : Prop where
  callerExists      : (s.getDom caller).isSome
  callerSealed      : ∀ d, s.getDom caller = some d → d.isSealed
  hasPermission     : ∀ d, s.getDom caller = some d → d.policy.api.canRevoke = true
  /-- The local handle resolves to some dom-cap held by the caller. -/
  handleResolves    : ∀ d, s.getDom caller = some d →
                            (d.lookupDomHandle handle).isSome
  /-- The resolved dom-cap exists in the arena. -/
  capExists         : ∀ d, s.getDom caller = some d →
                            ∀ dcId, d.lookupDomHandle handle = some dcId →
                            (s.getDomCap dcId).isSome
  /-- Caller owns the resolved dom-cap. -/
  capOwnedByCaller  : ∀ d, s.getDom caller = some d →
                            ∀ dcId, d.lookupDomHandle handle = some dcId →
                            ∀ dc, s.getDomCap dcId = some dc → dc.owner = caller
  /-- The target domain (referenced by the dom-cap) exists. -/
  targetExists      : ∀ d, s.getDom caller = some d →
                            ∀ dcId, d.lookupDomHandle handle = some dcId →
                            ∀ dc, s.getDomCap dcId = some dc →
                            (s.getDom dc.targetDom).isSome
  /-- You cannot revoke yourself. -/
  notSelf           : ∀ d, s.getDom caller = some d →
                            ∀ dcId, d.lookupDomHandle handle = some dcId →
                            ∀ dc, s.getDomCap dcId = some dc →
                            dc.targetDom ≠ caller
  /-- Slice restriction: target is a leaf with no held caps. -/
  targetIsLeaf      : ∀ d, s.getDom caller = some d →
                            ∀ dcId, d.lookupDomHandle handle = some dcId →
                            ∀ dc, s.getDomCap dcId = some dc →
                            ∀ t, s.getDom dc.targetDom = some t →
                            t.childrenDoms = [] ∧ t.memHandles = [] ∧
                            t.domHandles = []

/-- Pure state update for a successful leaf `revokeDomain`.

    1. Remove the target domain from the `domains` arena.
    2. Remove the dom-cap from the `domcaps` arena.
    3. Strip every handle to the dom-cap from caller's `domHandles`
       and strip the target id from caller's `childrenDoms`. -/
def revokeDomain_apply (s : SpecState) (caller : DomId) (handle : LocalHandle)
    : SpecState :=
  match s.getDom caller with
  | none   => s
  | some d =>
    match d.lookupDomHandle handle with
    | none      => s
    | some dcId =>
      match s.getDomCap dcId with
      | none    => s
      | some dc =>
        let target := dc.targetDom
        let s₁ : SpecState :=
          { s with domains := s.domains.remove target,
                   domcaps := s.domcaps.remove dcId }
        s₁.updDomain caller (fun d =>
          { d with domHandles   := d.domHandles.filter (fun h => h.2 ≠ dcId),
                   childrenDoms := d.childrenDoms.filter (· ≠ target) })

/-! ### Channels (sendChannel / acceptChannel / rejectChannel)

    Mirrors the channel-cap (DomCap with `isChannel = true`) transfer
    family in `capa-engine/src/capability.rs::send_channel` /
    `accept_channel` / `reject_channel`. Only the **unsealed** path of
    `sendChannel` is modeled here; the sealed path (which freezes the
    sender's dom-handle and enqueues a `PendingDomCap` on the receiver)
    is future work (`sealedSendChannel`). -/

/-- Preconditions for `sendChannel(caller, receiver, cap)` — unsealed
    path: receiver must be currently unsealed; cap is a channel cap
    owned by caller. -/
structure SendChannelGuard (s : SpecState) (caller : DomId) (receiver : DomId)
                            (cap : DomCapId) : Prop where
  callerExists      : (s.getDom caller).isSome
  receiverExists    : (s.getDom receiver).isSome
  callerSealed      : ∀ d, s.getDom caller = some d → d.isSealed
  hasPermission     : ∀ d, s.getDom caller = some d → d.policy.api.canSend = true
  capExists         : (s.getDomCap cap).isSome
  capIsChannel      : ∀ dc, s.getDomCap cap = some dc → dc.isChannel = true
  capOwnedByCaller  : ∀ dc, s.getDomCap cap = some dc → dc.owner = caller
  receiverUnsealed  : ∀ d, s.getDom receiver = some d → d.isUnsealed
  notSelf           : caller ≠ receiver

/-- Pure state update for the unsealed `sendChannel`:

    1. Drop all caller handles to `cap`.
    2. Append a fresh handle to receiver's `domHandles`.
    3. Update `cap.owner` to `receiver`. -/
def sendChannel_apply (s : SpecState) (caller : DomId) (receiver : DomId)
                       (cap : DomCapId) : SpecState :=
  let s₁ := s.updDomain caller (fun d =>
    { d with domHandles := d.domHandles.filter (fun h => h.2 ≠ cap) })
  let s₂ := s₁.updDomain receiver (fun d =>
    { d with domHandles := d.domHandles ++ [(d.nextHandle, cap)],
             nextHandle := d.nextHandle + 1 })
  s₂.updDomCap cap (fun c => { c with owner := receiver })

/-- Preconditions for `acceptChannel(receiver, pendingId)`. -/
structure AcceptChannelGuard (s : SpecState) (receiver : DomId)
                              (pendingId : PendingId) : Prop where
  receiverExists    : (s.getDom receiver).isSome
  pendingFound      : ∀ d, s.getDom receiver = some d →
                      (d.lookupPendingDom pendingId).isSome
  senderExists      : ∀ d pe, s.getDom receiver = some d →
                      d.lookupPendingDom pendingId = some pe →
                      (s.getDom pe.senderDomainId).isSome
  capExists         : ∀ d pe, s.getDom receiver = some d →
                      d.lookupPendingDom pendingId = some pe →
                      (s.getDomCap pe.capId).isSome
  notSelf           : ∀ d pe, s.getDom receiver = some d →
                      d.lookupPendingDom pendingId = some pe →
                      pe.senderDomainId ≠ receiver
  /-- Receiver must be live. -/
  receiverLive      : ∀ d, s.getDom receiver = some d → d.isLive
  /-- Sender must be live. -/
  senderLive        : ∀ d pe, s.getDom receiver = some d →
                      d.lookupPendingDom pendingId = some pe →
                      ∀ sd, s.getDom pe.senderDomainId = some sd → sd.isLive

/-- Pure state update for `acceptChannel`:

    1. Transfer dom-cap ownership to receiver and append a fresh handle.
    2. Remove the pending entry from receiver.
    3. Unfreeze sender's domain handle. -/
def acceptChannel_apply (s : SpecState) (receiver : DomId)
                         (pendingId : PendingId) : SpecState :=
  match (s.getDom receiver).bind (fun d => d.lookupPendingDom pendingId) with
  | none    => s
  | some pe =>
    let s₁ := (sendChannel_apply s pe.senderDomainId receiver pe.capId).updDomain
      receiver
      (fun d =>
        { d with pendingDomCaps :=
                  d.pendingDomCaps.filter (fun p => p.1 ≠ pendingId) })
    s₁.updDomain pe.senderDomainId (fun d =>
      { d with frozenHandles :=
                d.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })

/-- Preconditions for `rejectChannel(receiver, pendingId)`. -/
structure RejectChannelGuard (s : SpecState) (receiver : DomId)
                              (pendingId : PendingId) : Prop where
  receiverExists    : (s.getDom receiver).isSome
  pendingFound      : ∀ d, s.getDom receiver = some d →
                      (d.lookupPendingDom pendingId).isSome
  /-- Receiver must be live. -/
  receiverLive      : ∀ d, s.getDom receiver = some d → d.isLive
  /-- Sender must be live. -/
  senderLive        : ∀ d pe, s.getDom receiver = some d →
                      d.lookupPendingDom pendingId = some pe →
                      ∀ sd, s.getDom pe.senderDomainId = some sd → sd.isLive

/-- Pure state update for `rejectChannel`: remove pending from receiver
    and unfreeze sender's handle. -/
def rejectChannel_apply (s : SpecState) (receiver : DomId)
                         (pendingId : PendingId) : SpecState :=
  let s₁ := s.updDomain receiver (fun d =>
    { d with pendingDomCaps :=
              d.pendingDomCaps.filter (fun p => p.1 ≠ pendingId) })
  match (s.getDom receiver).bind (fun d => d.lookupPendingDom pendingId) with
  | none    => s₁
  | some pe =>
    s₁.updDomain pe.senderDomainId (fun d =>
      { d with frozenHandles :=
                d.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })

/-- Preconditions for `switchReturn(caller, core, exitReason)`.

    Mirrors `switch_domain_return` in Rust: caller must be sealed, must
    have a VP on this core in `Running` state with a saved caller
    context, and the previous-caller VP must be in `Locked` state
    waiting for *this* callee. -/
structure SwitchReturnGuard (s : SpecState) (caller : DomId) (core : CoreId) :
    Prop where
  callerExists      : (s.getDom caller).isSome
  callerSealed      : ∀ d, s.getDom caller = some d → d.isSealed
  vpAndPrevFound    : ∀ d, s.getDom caller = some d →
                      (d.vpAndPrevCallerOnCore core).isSome
  prevDomExists     : ∀ d, s.getDom caller = some d →
                      ∀ p, d.vpAndPrevCallerOnCore core = some p →
                      (s.getDom p.2.domainId).isSome
  prevVpLocked      : ∀ d, s.getDom caller = some d →
                      ∀ p, d.vpAndPrevCallerOnCore core = some p →
                      ∀ pd, s.getDom p.2.domainId = some pd →
                      ∀ pvp, pd.lookupVp p.2.vpId = some pvp →
                      ∃ ppc, pvp.runState = .locked caller p.1 ppc
  notSelf           : ∀ d, s.getDom caller = some d →
                      ∀ p, d.vpAndPrevCallerOnCore core = some p →
                      p.2.domainId ≠ caller
  /-- Previous caller domain must be live. -/
  prevDomLive       : ∀ d, s.getDom caller = some d →
                      ∀ p, d.vpAndPrevCallerOnCore core = some p →
                      ∀ pd, s.getDom p.2.domainId = some pd → pd.isLive

/-- Pure state update for `switchReturn`:
    1. Caller's running VP on `core` → `.available exitReason`.
    2. Previous caller's locked VP → `.running core prevPrevCaller`
       (lifted out of the `Locked` state).
    3. Core's `CoreState` is rebound to the previous-caller VP. -/
def switchReturn_apply (s : SpecState) (caller : DomId) (core : CoreId)
                        (exitReason : Option Nat) : SpecState :=
  match (s.getDom caller).bind (fun d => d.vpAndPrevCallerOnCore core) with
  | none           => s
  | some (vpId, pctx) =>
    let s₁ := s.updDomain caller (fun d => d.updVp vpId (fun vp =>
      { vp with runState := .available exitReason }))
    let s₂ := s₁.updDomain pctx.domainId (fun d => d.updVp pctx.vpId (fun vp =>
      match vp.runState with
      | .locked _ _ prevPrev => { vp with runState := .running core prevPrev }
      | other                => { vp with runState := other }))
    s₂.updCore core (fun _ => .runningDomain pctx.domainId pctx.vpId)

/-- Preconditions for forward `switch(caller, toHandle, toVpId, core)`.

    Mirrors `switch_domain_forward` (Available branch only): caller
    sealed with SWITCH perm; `toHandle` resolves to a non-channel
    dom-cap pointing at a sealed target whose policy includes `core`;
    target VP must exist and be in `.available _`; caller must have a
    VP currently in `.running` on `core`. -/
structure SwitchGuard (s : SpecState) (caller : DomId)
                      (toHandle : LocalHandle) (toVpId : VpId)
                      (core : CoreId) : Prop where
  callerExists      : (s.getDom caller).isSome
  callerSealed      : ∀ d, s.getDom caller = some d → d.isSealed
  hasPermission     : ∀ d, s.getDom caller = some d →
                      d.policy.api.canSwitch = true
  handleResolves    : ∀ d, s.getDom caller = some d →
                      (d.lookupDomHandle toHandle).isSome
  capExists         : ∀ d, s.getDom caller = some d →
                      ∀ cid, d.lookupDomHandle toHandle = some cid →
                      (s.getDomCap cid).isSome
  capNotChannel     : ∀ d, s.getDom caller = some d →
                      ∀ cid, d.lookupDomHandle toHandle = some cid →
                      ∀ dc, s.getDomCap cid = some dc →
                      dc.isChannel = false
  targetExists      : ∀ d, s.getDom caller = some d →
                      ∀ cid, d.lookupDomHandle toHandle = some cid →
                      ∀ dc, s.getDomCap cid = some dc →
                      (s.getDom dc.targetDom).isSome
  targetSealed      : ∀ d, s.getDom caller = some d →
                      ∀ cid, d.lookupDomHandle toHandle = some cid →
                      ∀ dc, s.getDomCap cid = some dc →
                      ∀ td, s.getDom dc.targetDom = some td →
                      td.isSealed
  coreAllowed       : ∀ d, s.getDom caller = some d →
                      ∀ cid, d.lookupDomHandle toHandle = some cid →
                      ∀ dc, s.getDomCap cid = some dc →
                      ∀ td, s.getDom dc.targetDom = some td →
                      core ∈ td.policy.cores
  targetVpExists    : ∀ d, s.getDom caller = some d →
                      ∀ cid, d.lookupDomHandle toHandle = some cid →
                      ∀ dc, s.getDomCap cid = some dc →
                      ∀ td, s.getDom dc.targetDom = some td →
                      (td.lookupVp toVpId).isSome
  targetVpAvailable : ∀ d, s.getDom caller = some d →
                      ∀ cid, d.lookupDomHandle toHandle = some cid →
                      ∀ dc, s.getDomCap cid = some dc →
                      ∀ td, s.getDom dc.targetDom = some td →
                      ∀ tvp, td.lookupVp toVpId = some tvp →
                      ∃ ler, tvp.runState = .available ler
  callerVpOnCore    : ∀ d, s.getDom caller = some d →
                      (d.vpAndOptPrevOnCore core).isSome
  notSelf           : ∀ d, s.getDom caller = some d →
                      ∀ cid, d.lookupDomHandle toHandle = some cid →
                      ∀ dc, s.getDomCap cid = some dc →
                      dc.targetDom ≠ caller

/-- Pure state update for forward `switch`:
    1. Target's VP `toVpId` runState ← `.running core (some {caller, callerVpId})`.
    2. Caller's running VP on `core` runState ← `.locked target toVpId callerPrev`.
    3. Core's CoreState ← `.runningDomain target toVpId`. -/
def switch_apply (s : SpecState) (caller : DomId) (toHandle : LocalHandle)
                  (toVpId : VpId) (core : CoreId) : SpecState :=
  match (s.getDom caller).bind (fun d => d.lookupDomHandle toHandle) with
  | none     => s
  | some cid =>
    match s.getDomCap cid with
    | none    => s
    | some dc =>
      match (s.getDom caller).bind (fun d => d.vpAndOptPrevOnCore core) with
      | none                  => s
      | some (callerVpId, callerPrev) =>
        let cctx : VpCallContext := { domainId := caller, vpId := callerVpId }
        let s₁ := s.updDomain dc.targetDom (fun d => d.updVp toVpId (fun vp =>
          { vp with runState := .running core (some cctx) }))
        let s₂ := s₁.updDomain caller (fun d => d.updVp callerVpId (fun vp =>
          { vp with runState := .locked dc.targetDom toVpId callerPrev }))
        s₂.updCore core (fun _ => .runningDomain dc.targetDom toVpId)

/-! ### `switchSuspended` (interrupt-resume branch of `switch`) -/

/-- Preconditions for `switchSuspended(caller, toHandle, toVpId, core, calleeDom, calleeVp)`.
    Mirrors `SwitchGuard` but requires the target VP to be in `.suspended`
    state (instead of `.available`), and pins the witness `(calleeDom,
    calleeVp)` to the values inside that `.suspended` state. -/
structure SwitchSuspendedGuard (s : SpecState) (caller : DomId)
                               (toHandle : LocalHandle) (toVpId : VpId)
                               (core : CoreId)
                               (calleeDom : DomId) (calleeVp : VpId) : Prop where
  callerExists      : (s.getDom caller).isSome
  callerSealed      : ∀ d, s.getDom caller = some d → d.isSealed
  hasPermission     : ∀ d, s.getDom caller = some d →
                      d.policy.api.canSwitch = true
  handleResolves    : ∀ d, s.getDom caller = some d →
                      (d.lookupDomHandle toHandle).isSome
  capExists         : ∀ d, s.getDom caller = some d →
                      ∀ cid, d.lookupDomHandle toHandle = some cid →
                      (s.getDomCap cid).isSome
  capNotChannel     : ∀ d, s.getDom caller = some d →
                      ∀ cid, d.lookupDomHandle toHandle = some cid →
                      ∀ dc, s.getDomCap cid = some dc →
                      dc.isChannel = false
  targetExists      : ∀ d, s.getDom caller = some d →
                      ∀ cid, d.lookupDomHandle toHandle = some cid →
                      ∀ dc, s.getDomCap cid = some dc →
                      (s.getDom dc.targetDom).isSome
  targetSealed      : ∀ d, s.getDom caller = some d →
                      ∀ cid, d.lookupDomHandle toHandle = some cid →
                      ∀ dc, s.getDomCap cid = some dc →
                      ∀ td, s.getDom dc.targetDom = some td →
                      td.isSealed
  coreAllowed       : ∀ d, s.getDom caller = some d →
                      ∀ cid, d.lookupDomHandle toHandle = some cid →
                      ∀ dc, s.getDomCap cid = some dc →
                      ∀ td, s.getDom dc.targetDom = some td →
                      core ∈ td.policy.cores
  targetVpExists    : ∀ d, s.getDom caller = some d →
                      ∀ cid, d.lookupDomHandle toHandle = some cid →
                      ∀ dc, s.getDomCap cid = some dc →
                      ∀ td, s.getDom dc.targetDom = some td →
                      (td.lookupVp toVpId).isSome
  targetVpSuspended : ∀ d, s.getDom caller = some d →
                      ∀ cid, d.lookupDomHandle toHandle = some cid →
                      ∀ dc, s.getDomCap cid = some dc →
                      ∀ td, s.getDom dc.targetDom = some td →
                      ∀ tvp, td.lookupVp toVpId = some tvp →
                      ∃ vec, tvp.runState = .suspended calleeDom calleeVp vec
  callerVpOnCore    : ∀ d, s.getDom caller = some d →
                      (d.vpAndOptPrevOnCore core).isSome
  notSelf           : ∀ d, s.getDom caller = some d →
                      ∀ cid, d.lookupDomHandle toHandle = some cid →
                      ∀ dc, s.getDomCap cid = some dc →
                      dc.targetDom ≠ caller
  calleeDistinctFromCaller : calleeDom ≠ caller
  calleeDistinctFromTarget : ∀ d, s.getDom caller = some d →
                      ∀ cid, d.lookupDomHandle toHandle = some cid →
                      ∀ dc, s.getDomCap cid = some dc →
                      calleeDom ≠ dc.targetDom
  /-- Callee domain must be live. -/
  calleeLive        : ∀ cd, s.getDom calleeDom = some cd → cd.isLive

/-- Pure state update for Suspended-resume `switch`:
    1. Target VP `toVpId` (`.suspended _ _ _`) ← `.running core (some {caller, callerVpId})`.
    2. Callee VP (`.interrupted vec`) ← `.available none` (no-op otherwise).
    3. Caller VP on `core` ← `.locked target toVpId callerPrev`.
    4. Core's CoreState ← `.runningDomain target toVpId`. -/
def switchSuspended_apply (s : SpecState) (caller : DomId) (toHandle : LocalHandle)
                           (toVpId : VpId) (core : CoreId)
                           (calleeDom : DomId) (calleeVp : VpId) : SpecState :=
  match (s.getDom caller).bind (fun d => d.lookupDomHandle toHandle) with
  | none     => s
  | some cid =>
    match s.getDomCap cid with
    | none    => s
    | some dc =>
      match (s.getDom caller).bind (fun d => d.vpAndOptPrevOnCore core) with
      | none                  => s
      | some (callerVpId, callerPrev) =>
        let cctx : VpCallContext := { domainId := caller, vpId := callerVpId }
        let s₁ := s.updDomain dc.targetDom (fun d => d.updVp toVpId (fun vp =>
          { vp with runState := .running core (some cctx) }))
        let s₂ := s₁.updDomain calleeDom (fun d => d.updVp calleeVp (fun vp =>
          match vp.runState with
          | .interrupted _ => { vp with runState := .available none }
          | _              => vp))
        let s₃ := s₂.updDomain caller (fun d => d.updVp callerVpId (fun vp =>
          { vp with runState := .locked dc.targetDom toVpId callerPrev }))
        s₃.updCore core (fun _ => .runningDomain dc.targetDom toVpId)

/-! ### `deliverInterrupt` -/

/-- Walk the chain tail applying `Locked → Suspended` to each intermediate
    VP (using `prev` as the callee witness) and `Locked → Running` to the
    handler at the end. `prev` is the predecessor of the next element to
    be processed; for the first call after the leaf, pass `prev = leaf`. -/
def applyMidsAndHandler (core : CoreId) (vector : Nat)
    (prev : DomId × VpId) : List (DomId × VpId) → SpecState → SpecState
  | [],         s => s
  | [handler],  s =>
    s.updDomain handler.1 (fun d => d.updVp handler.2 (fun vp =>
      match vp.runState with
      | .locked _ _ p => { vp with runState := .running core p }
      | other         => { vp with runState := other }))
  | mid :: rest, s =>
    let s' := s.updDomain mid.1 (fun d => d.updVp mid.2 (fun vp =>
      { vp with runState := .suspended prev.1 prev.2 vector }))
    applyMidsAndHandler core vector mid rest s'

/-- Preconditions for `deliverInterrupt(interrupted, handler, core, vector, chain)`.

    Scope: structural-only. Engine refinement is responsible for proving
    that `chain` matches the live Rust call chain. -/
structure DeliverInterruptGuard
    (s : SpecState) (interrupted handler : DomId) (_core : CoreId)
    (_vector : Nat) (chain : List (DomId × VpId)) : Prop where
  notSelf            : interrupted ≠ handler
  chainLenGe2        : chain.length ≥ 2
  chainHeadLeaf      : ∃ vpId, chain.head? = some (interrupted, vpId)
  chainLastHandler   : ∃ vpId, chain.getLast? = some (handler, vpId)
  interruptedExists  : (s.getDom interrupted).isSome
  handlerExists      : (s.getDom handler).isSome
  /-- Both endpoints must be live (revoked tombstones cannot serve interrupts). -/
  interruptedLive    : ∀ d, s.getDom interrupted = some d → d.isLive
  handlerLive        : ∀ d, s.getDom handler = some d → d.isLive

/-- Pure state update for `deliverInterrupt`. Applies leaf → Interrupted,
    then walks the chain tail with `applyMidsAndHandler` (intermediates
    → Suspended, handler → Running), then rebinds the core. -/
def deliverInterrupt_apply (s : SpecState) (_interrupted _handler : DomId)
    (core : CoreId) (vector : Nat) (chain : List (DomId × VpId)) : SpecState :=
  match chain with
  | []       => s
  | [_]      => s
  | leaf :: tail =>
    let s₀ := s.updDomain leaf.1 (fun d => d.updVp leaf.2 (fun vp =>
      { vp with runState := .interrupted vector }))
    let s₁ := applyMidsAndHandler core vector leaf tail s₀
    match chain.getLast? with
    | none             => s₁
    | some (hDom, hVp) => s₁.updCore core (fun _ => .runningDomain hDom hVp)

/-! ### `addVp`

Allocates a fresh VP in a child domain and pins a parent-owned COMM
memory cap to it. Mirrors `capa-engine/src/capability.rs::add_vp`. -/

/-- Preconditions for `addVp(caller, childHandle, commHandle)`. -/
structure AddVpGuard (s : SpecState) (caller : DomId)
                     (childHandle commHandle : LocalHandle) : Prop where
  callerExists       : (s.getDom caller).isSome
  childHandleResolves : ∀ d, s.getDom caller = some d →
                        (d.lookupDomHandle childHandle).isSome
  childCapExists     : ∀ d, s.getDom caller = some d →
                       ∀ cid, d.lookupDomHandle childHandle = some cid →
                       (s.getDomCap cid).isSome
  childExists        : ∀ d, s.getDom caller = some d →
                       ∀ cid, d.lookupDomHandle childHandle = some cid →
                       ∀ dc, s.getDomCap cid = some dc →
                       (s.getDom dc.targetDom).isSome
  childUnsealed      : ∀ d, s.getDom caller = some d →
                       ∀ cid, d.lookupDomHandle childHandle = some cid →
                       ∀ dc, s.getDomCap cid = some dc →
                       ∀ cd, s.getDom dc.targetDom = some cd →
                       cd.isUnsealed
  childHasVpCapacity : ∀ d, s.getDom caller = some d →
                       ∀ cid, d.lookupDomHandle childHandle = some cid →
                       ∀ dc, s.getDomCap cid = some dc →
                       ∀ cd, s.getDom dc.targetDom = some cd →
                       cd.vps.length < cd.policy.numVps
  commHandleResolves : ∀ d, s.getDom caller = some d →
                       (d.lookupMemHandle commHandle).isSome
  commHandleNotFrozen : ∀ d, s.getDom caller = some d →
                        commHandle ∉ d.frozenHandles
  commCapExists      : ∀ d, s.getDom caller = some d →
                       ∀ mid, d.lookupMemHandle commHandle = some mid →
                       (s.getMem mid).isSome
  commCapOwned       : ∀ d, s.getDom caller = some d →
                       ∀ mid, d.lookupMemHandle commHandle = some mid →
                       ∀ c, s.getMem mid = some c → c.owner = caller
  commCapKindCarve   : ∀ d, s.getDom caller = some d →
                       ∀ mid, d.lookupMemHandle commHandle = some mid →
                       ∀ c, s.getMem mid = some c →
                       c.region.kind = RegionKind.carve
  commCapExclusive   : ∀ d, s.getDom caller = some d →
                       ∀ mid, d.lookupMemHandle commHandle = some mid →
                       ∀ c, s.getMem mid = some c →
                       c.region.status = RegionStatus.exclusive
  commCapNotComm     : ∀ d, s.getDom caller = some d →
                       ∀ mid, d.lookupMemHandle commHandle = some mid →
                       ∀ c, s.getMem mid = some c →
                       c.region.attributes.comm = false

/-- Pure state update for `addVp`.

    1. Resolve childHandle → childCapId → childDomId (= dc.targetDom).
    2. Resolve commHandle → commCapId.
    3. Append `{id := childVps.length, runState := .available none}` to
       child's vps and append commCapId to child's `commBindings`.
    4. Update commCap: set `attributes.comm := true, attributes.clean := true`
       (canonicalize) and `commBinding := some {childDomId, vpId}`.

    Returns `s` unchanged if any resolution fails. -/
def addVp_apply (s : SpecState) (caller : DomId)
                (childHandle commHandle : LocalHandle) : SpecState :=
  match (s.getDom caller).bind (fun d => d.lookupDomHandle childHandle) with
  | none     => s
  | some cid =>
    match s.getDomCap cid with
    | none    => s
    | some dc =>
      match s.getDom dc.targetDom with
      | none    => s
      | some cd =>
        match (s.getDom caller).bind (fun d => d.lookupMemHandle commHandle) with
        | none     => s
        | some mid =>
          let vpId : VpId := cd.vps.length
          let s₁ := s.updDomain dc.targetDom (fun d =>
            { d with vps := d.vps ++
                       [{ id := vpId, runState := .available none }],
                     commBindings := d.commBindings ++ [mid] })
          s₁.updMem mid (fun c =>
            { c with region :=
                { c.region with
                  attributes :=
                    { c.region.attributes with comm := true, clean := true },
                  commBinding := some
                    { targetDomainId := dc.targetDom, vpId := vpId } } })

/-! ### `registerComm`

Binds an existing child VP to a parent-owned COMM memory cap. Mirrors
`capa-engine/src/capability.rs::register_comm`. -/

/-- Preconditions for `registerComm(caller, commHandle, childHandle, vpId)`. -/
structure RegisterCommGuard (s : SpecState) (caller : DomId)
                            (commHandle childHandle : LocalHandle)
                            (vpId : VpId) : Prop where
  callerExists       : (s.getDom caller).isSome
  childHandleResolves : ∀ d, s.getDom caller = some d →
                        (d.lookupDomHandle childHandle).isSome
  childCapExists     : ∀ d, s.getDom caller = some d →
                       ∀ cid, d.lookupDomHandle childHandle = some cid →
                       (s.getDomCap cid).isSome
  childExists        : ∀ d, s.getDom caller = some d →
                       ∀ cid, d.lookupDomHandle childHandle = some cid →
                       ∀ dc, s.getDomCap cid = some dc →
                       (s.getDom dc.targetDom).isSome
  vpIdInRange        : ∀ d, s.getDom caller = some d →
                       ∀ cid, d.lookupDomHandle childHandle = some cid →
                       ∀ dc, s.getDomCap cid = some dc →
                       ∀ cd, s.getDom dc.targetDom = some cd →
                       vpId < cd.policy.numVps
  noExistingBinding  : ∀ d, s.getDom caller = some d →
                       ∀ cid, d.lookupDomHandle childHandle = some cid →
                       ∀ dc, s.getDomCap cid = some dc →
                       ∀ cd, s.getDom dc.targetDom = some cd →
                       ∀ mid' ∈ cd.commBindings,
                       ∀ c', s.getMem mid' = some c' →
                       ∀ b, c'.region.commBinding = some b →
                       b.vpId ≠ vpId
  commHandleResolves : ∀ d, s.getDom caller = some d →
                       (d.lookupMemHandle commHandle).isSome
  commHandleNotFrozen : ∀ d, s.getDom caller = some d →
                        commHandle ∉ d.frozenHandles
  commCapExists      : ∀ d, s.getDom caller = some d →
                       ∀ mid, d.lookupMemHandle commHandle = some mid →
                       (s.getMem mid).isSome
  commCapOwned       : ∀ d, s.getDom caller = some d →
                       ∀ mid, d.lookupMemHandle commHandle = some mid →
                       ∀ c, s.getMem mid = some c → c.owner = caller
  commCapKindCarve   : ∀ d, s.getDom caller = some d →
                       ∀ mid, d.lookupMemHandle commHandle = some mid →
                       ∀ c, s.getMem mid = some c →
                       c.region.kind = RegionKind.carve
  commCapExclusive   : ∀ d, s.getDom caller = some d →
                       ∀ mid, d.lookupMemHandle commHandle = some mid →
                       ∀ c, s.getMem mid = some c →
                       c.region.status = RegionStatus.exclusive
  commCapLeaf        : ∀ d, s.getDom caller = some d →
                       ∀ mid, d.lookupMemHandle commHandle = some mid →
                       ∀ c, s.getMem mid = some c →
                       c.childrenIds = []
  commCapNotMeta     : ∀ d, s.getDom caller = some d →
                       ∀ mid, d.lookupMemHandle commHandle = some mid →
                       ∀ c, s.getMem mid = some c →
                       c.region.attributes.meta = false
  commCapNotComm     : ∀ d, s.getDom caller = some d →
                       ∀ mid, d.lookupMemHandle commHandle = some mid →
                       ∀ c, s.getMem mid = some c →
                       c.region.attributes.comm = false

/-- Pure state update for `registerComm`. Identical to `addVp_apply`
    *except* no new VP is added to the child domain.

    1. Resolve childHandle → childCapId → childDomId (= dc.targetDom).
    2. Resolve commHandle → commCapId.
    3. Append commCapId to child's `commBindings` (no `vps` change).
    4. Update commCap: set `attributes.comm/clean := true` and
       `commBinding := some {childDomId, vpId}`.

    Returns `s` unchanged if any resolution fails. -/
def registerComm_apply (s : SpecState) (caller : DomId)
                       (commHandle childHandle : LocalHandle)
                       (vpId : VpId) : SpecState :=
  match (s.getDom caller).bind (fun d => d.lookupDomHandle childHandle) with
  | none     => s
  | some cid =>
    match s.getDomCap cid with
    | none    => s
    | some dc =>
      match s.getDom dc.targetDom with
      | none   => s
      | some _ =>
        match (s.getDom caller).bind (fun d => d.lookupMemHandle commHandle) with
        | none     => s
        | some mid =>
          let s₁ := s.updDomain dc.targetDom (fun d =>
            { d with commBindings := d.commBindings ++ [mid] })
          s₁.updMem mid (fun c =>
            { c with region :=
                { c.region with
                  attributes :=
                    { c.region.attributes with comm := true, clean := true },
                  commBinding := some
                    { targetDomainId := dc.targetDom, vpId := vpId } } })

/-! ### `mapSelf` (translation map mutation, caller-only) -/

/-- Preconditions for `mapSelf(caller, capHandle, newGpa)`.
    Mirrors `capa-engine/src/capability.rs::map_self` (structural-only —
    semantic overlap-with-remaining-segments check is captured by
    `noOverlap` after the conceptual `removeWithin`). -/
structure MapSelfGuard (s : SpecState) (caller : DomId)
                       (capHandle : LocalHandle) (newGpa : Nat) : Prop where
  callerExists      : (s.getDom caller).isSome
  hasPermission     : ∀ d, s.getDom caller = some d →
                      d.policy.api.canMapSelf = true
  capHandleResolves : ∀ d, s.getDom caller = some d →
                      (d.lookupMemHandle capHandle).isSome
  capExists         : ∀ d, s.getDom caller = some d →
                      ∀ mid, d.lookupMemHandle capHandle = some mid →
                      (s.getMem mid).isSome
  capOwned          : ∀ d, s.getDom caller = some d →
                      ∀ mid, d.lookupMemHandle capHandle = some mid →
                      ∀ c, s.getMem mid = some c →
                      c.owner = caller
  notMetaOrComm     : ∀ d, s.getDom caller = some d →
                      ∀ mid, d.lookupMemHandle capHandle = some mid →
                      ∀ c, s.getMem mid = some c →
                      c.region.attributes.meta = false ∧
                      c.region.attributes.comm = false
  hasOldGpa         : ∀ d, s.getDom caller = some d →
                      (d.lookupMappedGpa capHandle).isSome
  /-- After conceptually removing the entry at `oldGpa`, no remaining
      address-map entry overlaps `[newGpa, newGpa + cap.size)`. -/
  noOverlap         : ∀ d, s.getDom caller = some d →
                      ∀ mid, d.lookupMemHandle capHandle = some mid →
                      ∀ c, s.getMem mid = some c →
                      ∀ oldGpa, d.lookupMappedGpa capHandle = some oldGpa →
                      ¬ (d.addressMap.removeWithin oldGpa c.region.access.size).overlaps
                          newGpa c.region.access.size

/-- Pure state update for `mapSelf`. Caller-only mutation: caller's
    `addressMap` is rewritten and its `mappedGpas[capHandle]` updated. -/
def mapSelf_apply (s : SpecState) (caller : DomId)
                  (capHandle : LocalHandle) (newGpa : Nat) : SpecState :=
  match s.getDom caller with
  | none => s
  | some d =>
    match d.lookupMemHandle capHandle with
    | none => s
    | some mid =>
      match s.getMem mid with
      | none => s
      | some c =>
        match d.lookupMappedGpa capHandle with
        | none => s
        | some oldGpa =>
          let newEntry : Translation.MapEntry :=
            { gpa := newGpa,
              hpa := c.region.access.start,
              size := c.region.access.size,
              rights := c.region.access.rights }
          s.updDomain caller (fun d' =>
            { d' with
                addressMap :=
                  (d'.addressMap.removeWithin oldGpa c.region.access.size).insert newEntry
              }.updMappedGpa capHandle newGpa)

inductive step : SpecState → Action → SpecState → Prop
  | carve {s : SpecState} {caller : DomId} {parent : MemCapId}
          {access : Access} {attrs : Attributes}
    (guard : CarveGuard s caller parent access attrs) :
    step s (.carve caller parent access attrs)
         (carve_apply s caller parent access attrs)
  | alias {s : SpecState} {caller : DomId} {parent : MemCapId}
          {access : Access}
    (guard : AliasGuard s caller parent access) :
    step s (.alias caller parent access)
         (alias_apply s caller parent access)
  | revoke {s : SpecState} {caller : DomId} {target : MemCapId}
    (guard : RevokeGuard s caller target) :
    step s (.revoke caller target) (revoke_apply s caller target)
  | send {s : SpecState} {caller : DomId} {receiver : DomId} {cap : MemCapId}
    (guard : SendGuard s caller receiver cap) :
    step s (.send caller receiver cap) (send_apply s caller receiver cap)
  | seal {s : SpecState} {caller : DomId} {cap : DomCapId}
    (guard : SealGuard s caller cap) :
    step s (.seal caller cap) (seal_apply s caller cap)
  | accept {s : SpecState} {receiver : DomId} {pendingId : PendingId}
    (guard : AcceptGuard s receiver pendingId) :
    step s (.accept receiver pendingId) (accept_apply s receiver pendingId)
  | reject {s : SpecState} {receiver : DomId} {pendingId : PendingId}
    (guard : RejectGuard s receiver pendingId) :
    step s (.reject receiver pendingId) (reject_apply s receiver pendingId)
  | sealedSend {s : SpecState} {caller : DomId} {receiver : DomId}
               {handle : LocalHandle} {gpaHint : Option Nat}
    (guard : SealedSendGuard s caller receiver handle) :
    step s (.sealedSend caller receiver handle gpaHint)
         (sealedSend_apply s caller receiver handle gpaHint)
  | create {s : SpecState} {caller : DomId} {policy : DomainPolicy}
    (guard : CreateGuard s caller policy) :
    step s (.create caller policy) (create_apply s caller policy)
  | revokeDomain {s : SpecState} {caller : DomId} {handle : LocalHandle}
    (guard : RevokeDomainGuard s caller handle) :
    step s (.revokeDomain caller handle) (revokeDomain_apply s caller handle)
  | setPolicy {s : SpecState} {caller : DomId} {cap : DomCapId}
              {id : PolicyIdentifier} {value : Nat}
    (guard : SetPolicyGuard s caller cap id value) :
    step s (.setPolicy caller cap id value)
         (setPolicy_apply s caller cap id value)
  | sendChannel {s : SpecState} {caller : DomId} {receiver : DomId}
                {cap : DomCapId}
    (guard : SendChannelGuard s caller receiver cap) :
    step s (.sendChannel caller receiver cap)
         (sendChannel_apply s caller receiver cap)
  | acceptChannel {s : SpecState} {receiver : DomId} {pendingId : PendingId}
    (guard : AcceptChannelGuard s receiver pendingId) :
    step s (.acceptChannel receiver pendingId)
         (acceptChannel_apply s receiver pendingId)
  | rejectChannel {s : SpecState} {receiver : DomId} {pendingId : PendingId}
    (guard : RejectChannelGuard s receiver pendingId) :
    step s (.rejectChannel receiver pendingId)
         (rejectChannel_apply s receiver pendingId)
  | switchReturn {s : SpecState} {caller : DomId} {core : CoreId}
                 {exitReason : Option Nat}
    (guard : SwitchReturnGuard s caller core) :
    step s (.switchReturn caller core exitReason)
         (switchReturn_apply s caller core exitReason)
  | switch {s : SpecState} {caller : DomId} {toHandle : LocalHandle}
           {toVpId : VpId} {core : CoreId}
    (guard : SwitchGuard s caller toHandle toVpId core) :
    step s (.switch caller toHandle toVpId core)
         (switch_apply s caller toHandle toVpId core)
  | deliverInterrupt {s : SpecState} {interrupted handler : DomId}
                     {core : CoreId} {vector : Nat}
                     {chain : List (DomId × VpId)}
    (guard : DeliverInterruptGuard s interrupted handler core vector chain) :
    step s (.deliverInterrupt interrupted handler core vector chain)
         (deliverInterrupt_apply s interrupted handler core vector chain)
  | addVp {s : SpecState} {caller : DomId} {childHandle commHandle : LocalHandle}
    (guard : AddVpGuard s caller childHandle commHandle) :
    step s (.addVp caller childHandle commHandle)
         (addVp_apply s caller childHandle commHandle)
  | registerComm {s : SpecState} {caller : DomId}
                 {commHandle childHandle : LocalHandle} {vpId : VpId}
    (guard : RegisterCommGuard s caller commHandle childHandle vpId) :
    step s (.registerComm caller commHandle childHandle vpId)
         (registerComm_apply s caller commHandle childHandle vpId)
  | switchSuspended {s : SpecState} {caller : DomId} {toHandle : LocalHandle}
                    {toVpId : VpId} {core : CoreId}
                    {calleeDom : DomId} {calleeVp : VpId}
    (guard : SwitchSuspendedGuard s caller toHandle toVpId core calleeDom calleeVp) :
    step s (.switchSuspended caller toHandle toVpId core calleeDom calleeVp)
         (switchSuspended_apply s caller toHandle toVpId core calleeDom calleeVp)
  | mapSelf {s : SpecState} {caller : DomId} {capHandle : LocalHandle}
            {newGpa : Nat}
    (guard : MapSelfGuard s caller capHandle newGpa) :
    step s (.mapSelf caller capHandle newGpa)
         (mapSelf_apply s caller capHandle newGpa)

end ThemisCapa
