/-
  ThemisCapa.Action — Labelled actions for the small-step semantics.

  Each constructor corresponds to one externally-observable engine
  operation. The `step` relation in `ThemisCapa.Step` defines when each
  action is enabled and what state change it produces.

  Vertical slice: only `.carve` is populated. Other constructors will be
  added incrementally as the v2 spec is fleshed out.
-/
import ThemisCapa.Basic
import ThemisCapa.State

namespace ThemisCapa

inductive Action where
  /-- `caller` carves a fresh exclusive child out of `parent` with the
      requested `access` and `attrs`. -/
  | carve (caller : DomId) (parent : MemCapId)
          (access : Access) (attrs : Attributes)
  -- Future:
  -- | alias … | send … | accept … | reject … | revoke … | create … | seal …
  -- | switchFwd … | switchRet … | interrupt …
deriving Repr

end ThemisCapa
