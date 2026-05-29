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

/-- Pure state update for a successful leaf `revoke`.

    1. Remove `target` from the memcap arena.
    2. Strip `target` from its parent's `childrenIds` list.
    3. Strip any handle to `target` from the owner domain's `memHandles`.

    The `HandleOwner` invariant guarantees that *only* `t.owner` holds a
    handle to `target`, so step 3 is local to a single domain. -/
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

end ThemisCapa
