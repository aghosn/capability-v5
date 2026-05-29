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
  -- Future:
  -- | send … | accept … | reject … | create … | seal …
  -- | switchFwd … | switchRet … | interrupt …
deriving Repr

end ThemisCapa
