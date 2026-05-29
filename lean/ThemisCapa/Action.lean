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
  -- Future:
  -- | accept … | reject … | create …
  -- | switchFwd … | switchRet … | interrupt …
deriving Repr

end ThemisCapa
