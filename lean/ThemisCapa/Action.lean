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
  -- Future:
  -- | switchSuspended … | interrupt …
deriving Repr

end ThemisCapa
