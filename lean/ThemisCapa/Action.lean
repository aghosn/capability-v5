/-
  ThemisCapa.Action — Labelled actions for the small-step semantics.

  Each constructor corresponds to one externally-observable engine
  operation. The `step` relation in `ThemisCapa.Step` defines when each
  action is enabled and what state change it produces.
-/
import ThemisCapa.Basic
import ThemisCapa.State

namespace ThemisCapa

inductive Action where
  /-- `caller` carves a fresh exclusive child out of `parent` with the
      requested `access` and `attrs`. -/
  | carve (caller : DomId) (parent : MemCapId)
          (access : Access) (attrs : Attributes)
  /-- `caller` creates an aliased view of `parent` over `access`.
      Unlike carve, the parent's region is not consumed; multiple aliases
      may overlap each other but must not overlap a carved child. -/
  | alias (caller : DomId) (parent : MemCapId) (access : Access)
  /-- `caller` revokes the memory capability `target`. Slice scope:
      `target` must be a leaf (no children). Full subtree revocation is
      future work. -/
  | revoke (caller : DomId) (target : MemCapId)
  /-- `caller` sends memory capability `cap` to `receiver`. Slice scope:
      models the **unsealed** path only (immediate ownership transfer with
      no pending queue). All of `caller`'s handles to `cap` are dropped; a
      fresh handle to `cap` is appended to `receiver`. The cap's `owner`
      field is updated to `receiver`. -/
  | send (caller : DomId) (receiver : DomId) (cap : MemCapId)
  /-- `caller` seals the domain referenced by domain-cap `cap`. The cap
      must be owned by `caller`, the target domain must be currently
      unsealed, and its `owned` policy must allow `SEAL`. -/
  | seal (caller : DomId) (cap : DomCapId)
  /-- `receiver` accepts the pending memcap identified by `pendingId`.
      Models the sealed-send completion: transfers cap ownership and
      installs a fresh handle on the receiver (using `send_apply`),
      then removes the pending entry and unfreezes the sender's
      handle. -/
  | accept (receiver : DomId) (pendingId : PendingId)
  /-- `receiver` rejects the pending memcap identified by `pendingId`.
      Removes the pending entry and unfreezes the sender's handle.
      No transfer takes place. -/
  | reject (receiver : DomId) (pendingId : PendingId)
  /-- `caller` sends memory handle `handle` to a sealed `receiver` via the
      pending-queue path. The handle is frozen on the sender and a
      `PendingMemCap` entry is appended to the receiver. No ownership
      transfer happens until `accept`. -/
  | sealedSend (caller : DomId) (receiver : DomId) (handle : LocalHandle)
               (gpaHint : Option Nat)
  /-- `caller` creates a fresh child domain bound by `policy`.
      Allocates a new `Domain` (status `.unsealed`, parent = caller),
      a new `DomCap` (owner = caller, targetDom = newDomId), and a
      fresh handle to that dom-cap on caller's `domHandles`. Caller's
      `childrenDoms` is updated to include the new domain. -/
  | create (caller : DomId) (policy : DomainPolicy)
  /-- `caller` revokes a child domain referenced by `handle` (a
      `LocalHandle` into caller's `domHandles`). Slice scope: the
      target must be a **leaf** domain — no children, no held memory
      capabilities, no held domain capabilities. Full subtree
      revocation is future work (analogous to memcap `revoke`).
      Target must not be the caller. -/
  | revokeDomain (caller : DomId) (handle : LocalHandle)
  /-- `caller` updates one field of a child domain's policy, identified by
      `id` with new `value`. The child is referenced by `cap` (a DomCap
      owned by caller targeting the child). Child must be unsealed.
      Mirrors `capa-engine/src/capability.rs::set_policy`. -/
  | setPolicy (caller : DomId) (cap : DomCapId)
              (id : PolicyIdentifier) (value : Nat)
  /-- `caller` transfers a channel domain-cap `cap` to `receiver`
      via the **unsealed** path (immediate ownership transfer).
      `cap` must have `isChannel = true` and be owned by caller; receiver
      must be unsealed. Mirrors `send_channel` (unsealed branch). All
      caller handles to `cap` are dropped; a fresh handle is appended to
      `receiver`; the cap's `owner` field is updated to `receiver`. -/
  | sendChannel (caller : DomId) (receiver : DomId) (cap : DomCapId)
  /-- `receiver` accepts a pending channel domain-cap (referenced by
      `pendingId`) — completes the sealed-path channel transfer:
      transfers cap ownership to `receiver`, removes the pending entry,
      installs a fresh handle on `receiver`, and unfreezes the sender's
      domain handle. Mirrors `accept_channel`. -/
  | acceptChannel (receiver : DomId) (pendingId : PendingId)
  /-- `receiver` rejects a pending channel domain-cap. Removes the
      pending entry and unfreezes the sender's domain handle.
      Mirrors `reject_channel`. No ownership transfer. -/
  | rejectChannel (receiver : DomId) (pendingId : PendingId)
  /-- `caller` returns from a previously-forwarded switch on `core`.
      Mirrors `capa-engine/src/capability.rs::switch_return_with_exit`
      (which delegates to `switch_domain_return`). The VP currently
      running on `core` for `caller` must be in
      `.running core (Some prevCtx)`, and the previous caller's VP
      (identified by `prevCtx`) must be in
      `.locked caller callerVp.id prevPrevCaller`.

      Apply:
      - caller's running VP becomes `.available exitReason`
      - previous caller's VP resumes as `.running core prevPrevCaller`
      - the core's `CoreState` is set to
        `.runningDomain prevCtx.domainId prevCtx.vpId`. -/
  | switchReturn (caller : DomId) (core : CoreId) (exitReason : Option Nat)
  /-- Forward switch: `caller` switches into VP `toVpId` of the domain
      referenced by `toHandle` on `core`. Mirrors
      `capa-engine/src/capability.rs::switch_domain_forward`.

      Scope: models the **Available → Running** branch only (the
      Suspended → Running interrupt-resume branch and Interrupted-callee
      cleanup are deferred to a later batch).

      Apply:
      - target VP becomes `.running core (some {domainId := caller, vpId := callerVpId})`
      - caller VP becomes `.locked targetDom toVpId callerPrevCaller`
      - core's CoreState → `.runningDomain targetDom toVpId`. -/
  | switch (caller : DomId) (toHandle : LocalHandle) (toVpId : VpId)
           (core : CoreId)
  /-- Deliver an external interrupt `vector` raised on `core` (currently
      running a VP of `interrupted`) up the VP call chain to `handler`.
      Mirrors `capa-engine/src/capability.rs::deliver_interrupt_vp`.

      `chain` is the witness of the VP call chain from leaf to handler:
      `chain.head = (interrupted, leafVpId)`, `chain.getLast = (handler,
      handlerVpId)`, with each adjacent pair `(midDom, midVp) → (calleeDom,
      calleeVp)` corresponding to a `Locked` VP. Length must be ≥ 2.

      Scope simplifications vs Rust:
      - Always sets leaf VP → `.interrupted vector` (Rust uses
        `.available none` when chain length = 2; deferred).
      - Short-circuit case `interrupted = handler` not modeled —
        callers must use a no-op action then.

      Apply:
      - leaf VP (`chain[0]`) → `.interrupted vector`
      - intermediates (`chain[1..n-2]`) → `.suspended calleeDom calleeVp vector`
      - handler VP (`chain[n-1]`) → `.running core prev` (lifted from `.locked`)
      - core's `CoreState` → `.runningDomain handlerDom handlerVp`. -/
  | deliverInterrupt (interrupted : DomId) (handler : DomId) (core : CoreId)
                     (vector : Nat) (chain : List (DomId × VpId))
  /-- `caller` allocates a new VP in the child domain referenced by
      `childHandle` (a local dom-handle in caller's `domHandles`) and
      pins the COMM memory cap referenced by `commHandle` (a local
      mem-handle in caller's `memHandles`) to that VP. Mirrors
      `capa-engine/src/capability.rs::add_vp`.

      Preconditions: child is unsealed and has `vps.length < numVps`;
      comm cap is Carve + Exclusive, owned by caller, with COMM bit
      not already set. The COMM cap is *parent-owned*: ownership stays
      with the caller; only attributes + binding change.

      Apply:
      - child's `vps` is extended with `{id := childVps.length,
        runState := .available none}`;
      - child's `commBindings` is extended with the resolved comm cap id;
      - comm memcap's attributes get `comm := true, clean := true`
        (canonicalize), and `commBinding := some {childDomId, vpId}`. -/
  | addVp (caller : DomId) (childHandle : LocalHandle)
          (commHandle : LocalHandle)
  /-- `caller` binds an *existing* VP `vpId` in the child domain
      referenced by `childHandle` to the COMM memory cap referenced by
      `commHandle`. Mirrors `capa-engine/src/capability.rs::register_comm`.

      Differs from `addVp` in that no VP is allocated — `vpId` must be
      a *legal* VP index for the child (`vpId < child.policy.numVps`)
      and must not already have a COMM binding.

      Preconditions on the comm cap match `addVp` plus: leaf (no
      children), not META, and the cap's `MonitorAPI::SET` permission
      is granted (modeled here as `commCapApiSet`).

      Apply:
      - child's `commBindings` is extended with the resolved comm cap id;
      - comm memcap's attributes get `comm := true, clean := true`
        (canonicalize), and `commBinding := some {childDomId, vpId}`. -/
  | registerComm (caller : DomId) (commHandle : LocalHandle)
                 (childHandle : LocalHandle) (vpId : VpId)
  /-- Switch into a target VP that is in the `.suspended` state (resume
      after a previous interrupt-delivery). Mirrors the Suspended branch
      of `capa-engine/src/capability.rs::switch_domain_forward`.

      Parameters mirror `switch`, plus the `(calleeDom, calleeVp)`
      witness that must equal the data in target's `.suspended` state.

      Apply:
      - target VP becomes `.running core (some {caller, callerVpId})`
        (lifted from `.suspended calleeDom calleeVp _`);
      - if the callee VP is `.interrupted vector`, it transitions to
        `.available none` (freeing the lazy-unwind leaf);
      - caller VP becomes `.locked targetDom toVpId callerPrev`;
      - core's CoreState → `.runningDomain targetDom toVpId`.

      Guard requires callee distinct from caller and from targetDom
      to keep frame proofs clean (three distinct domain updates). -/
  | switchSuspended (caller : DomId) (toHandle : LocalHandle) (toVpId : VpId)
                    (core : CoreId)
                    (calleeDom : DomId) (calleeVp : VpId)
  /-- `caller` re-maps the memcap referenced by `capHandle` from its
      current GPA to `newGpa` in the caller's own `AddressMap`.
      Mirrors `capa-engine/src/capability.rs::map_self`.

      Apply (caller-only mutation):
      - caller's `addressMap` has the entry at the cap's current GPA
        removed (`removeWithin oldGpa cap.size`) and a new entry
        `{gpa := newGpa, hpa := cap.hpa, size := cap.size,
          rights := cap.rights}` inserted.
      - caller's `mappedGpas` mapping for `capHandle` is updated to
        `newGpa`. -/
  | mapSelf (caller : DomId) (capHandle : LocalHandle) (newGpa : Nat)
deriving Repr

end ThemisCapa
