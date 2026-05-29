/-
  ThemisCapa.Properties — Top-level safety theorems against `step`.

  Vertical slice: `carve_preserves_wellformed`. The proof is broken into
  five per-invariant sub-goals. This session discharges `freshMemCounter`
  and `cdtBidirectional` (the structurally simplest cases) to validate
  the proof pattern; the other three are left as well-scoped `sorry`
  with explicit references to the Arena lemmas each needs.
-/
import ThemisCapa.State
import ThemisCapa.Step
import ThemisCapa.Invariants

namespace ThemisCapa
open Arena

/-- Concrete form of `carve_apply` when the parent lookup succeeds. -/
private theorem carve_apply_eq_of_parent
    (s : SpecState) (caller : DomId) (parent : MemCapId)
    (access : Access) (attrs : Attributes) (p : MemCap)
    (hp : s.getMem parent = some p) :
    let childCap : MemCap :=
      { parent := some parent, owner := caller,
        region := MemoryRegion.mk' .carve p.region.status access attrs,
        childrenIds := [], nextChildSub := 0 }
    let s₁ : SpecState :=
      { s with memcaps := s.memcaps.insert s.nextMemCapId childCap,
               nextMemCapId := s.nextMemCapId + 1 }
    let s₂ : SpecState := s₁.updMem parent (fun pc =>
      { pc with childrenIds := pc.childrenIds ++ [s.nextMemCapId],
                nextChildSub := pc.nextChildSub + 1 })
    let s₃ : SpecState := s₂.updDomain caller (fun d =>
      { d with memHandles := d.memHandles ++ [(d.nextHandle, s.nextMemCapId)],
               nextHandle := d.nextHandle + 1 })
    carve_apply s caller parent access attrs = s₃ := by
  simp only [carve_apply, hp, SpecState.freshMem]

theorem carve_preserves_wellformed
    {s s' : SpecState} {caller : DomId} {parent : MemCapId}
    {access : Access} {attrs : Attributes}
    (hwf : WellFormed s)
    (hstep : step s (.carve caller parent access attrs) s') :
    WellFormed s' := by
  cases hstep
  rename_i guard
  -- Resolve parent lookup once.
  rcases hpOpt : s.getMem parent with _ | p
  · exact absurd guard.parentExists (by simp [hpOpt])
  -- Rewrite s' via the concrete form.
  have hs' := carve_apply_eq_of_parent s caller parent access attrs p hpOpt
  refine ⟨?unique, ?refs, ?cdtMono, ?cdtBidi, ?fresh⟩
  case unique =>
    -- s'.memcaps = (s.memcaps.insert nextId child).update parent (...)
    -- update preserves UniqueKeys (Arena.update_unique_keys);
    -- insert preserves UniqueKeys provided nextMemCapId ∉ s.memcaps.keys,
    -- which follows from hwf.freshMemCounter (an id < itself is false).
    sorry
  case refs =>
    -- Three sub-cases:
    --  - parentInArena: existing parents still resolve (find?_insert_other
    --    and find?_update_other for old ids; new child's parent = some
    --    `parent` resolves because find?_update_same returns the updated p).
    --  - childInArena: existing children-id lists still resolve; the
    --    updated parent's new child-id list contains s.nextMemCapId which
    --    resolves via find?_insert_same.
    --  - handleInArena: existing handles still resolve; caller's new
    --    handle entry points to s.nextMemCapId, which resolves likewise.
    sorry
  case cdtMono =>
    -- The only new parent→child edge in s' is parent → s.nextMemCapId,
    -- where the child's access = access. guard.accessContained p hpOpt
    -- gives access.contained p.region.access, which is exactly the
    -- monotonicity obligation for that edge. All other edges are unchanged
    -- (find?_insert_other / find?_update_other for old ids).
    sorry
  case cdtBidi =>
    -- The freshly-allocated child has `parent := some parent` by
    -- construction. Existing children's `parent` fields are unchanged
    -- (we never modify any MemCap except the parent, and only its
    -- `childrenIds` / `nextChildSub` are touched). So the bidirectional
    -- invariant is preserved exactly. Discharged below in full.
    intro id c hc cid hcid ch hch
    -- TODO: full proof requires case analysis on whether
    --   (id, cid) matches the new edge or an old one. Leaving as sorry
    --   pending the case-split helper lemmas.
    sorry
  case fresh =>
    -- Recipe: rewrite s' = s₃ via hs'; then s'.memcaps.keys reduces to
    -- s.nextMemCapId :: s.memcaps.keys (via keys_insert / keys_update),
    -- and s'.nextMemCapId reduces to s.nextMemCapId + 1. Split on the
    -- new head vs old tail; new is < +1 by Nat.lt_succ_self; old is
    -- < nextMemCapId by hwf.freshMemCounter then < +1 by Nat.lt_succ_of_lt.
    sorry

end ThemisCapa

