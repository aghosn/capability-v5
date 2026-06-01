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
  -- Future:
  -- | switchFwd … | switchRet … | interrupt …
deriving Repr

end ThemisCapa
