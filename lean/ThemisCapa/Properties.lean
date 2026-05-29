/-
  ThemisCapa.Properties — Top-level safety theorems against `step`.

  Vertical slice: `carve_preserves_wellformed`. The proof is broken into
  five per-invariant sub-goals (unique, refs, cdtMonotonic, cdtBidirectional,
  freshMemCounter), all discharged via a 3-way characterization of the
  post-state's `getMem` and `getDom` lookups (`carve_apply_getMem` /
  `carve_apply_getDom`).
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

/-- Freshness: `nextMemCapId` is never a key already present. -/
private theorem fresh_not_in_keys (s : SpecState) (hfc : FreshMemCounter s) :
    s.nextMemCapId ∉ s.memcaps.keys := fun h =>
  Nat.lt_irrefl _ (hfc _ h)

/-- An existing parent's id is strictly less than `nextMemCapId`. -/
private theorem existing_lt_fresh (s : SpecState) (hfc : FreshMemCounter s)
    {k : MemCapId} {v : MemCap} (h : s.getMem k = some v) :
    k < s.nextMemCapId :=
  hfc _ (Arena.mem_keys_of_find?_some _ _ _ h)

/-- 3-way characterization of `s'.getMem` after `carve_apply`. -/
private theorem carve_apply_getMem
    (s : SpecState) (caller : DomId) (parent : MemCapId)
    (access : Access) (attrs : Attributes) (p : MemCap)
    (hp : s.getMem parent = some p) (hfc : FreshMemCounter s) (id : MemCapId) :
    let childCap : MemCap :=
      { parent := some parent, owner := caller,
        region := MemoryRegion.mk' .carve p.region.status access attrs,
        childrenIds := [], nextChildSub := 0 }
    let updP : MemCap :=
      { p with childrenIds := p.childrenIds ++ [s.nextMemCapId],
               nextChildSub := p.nextChildSub + 1 }
    (carve_apply s caller parent access attrs).getMem id =
      if id = s.nextMemCapId then some childCap
      else if id = parent then some updP
      else s.getMem id := by
  have hpne : parent ≠ s.nextMemCapId :=
    Nat.ne_of_lt (existing_lt_fresh s hfc hp)
  show ((carve_apply s caller parent access attrs).memcaps).find? id = _
  simp only [carve_apply, hp, SpecState.freshMem, SpecState.updMem,
             SpecState.updDomain]
  let fupd : MemCap → MemCap := fun pc =>
    { pc with childrenIds := pc.childrenIds ++ [s.nextMemCapId],
              nextChildSub := pc.nextChildSub + 1 }
  let child : MemCap :=
    { parent := some parent, owner := caller,
      region := MemoryRegion.mk' .carve p.region.status access attrs,
      childrenIds := [], nextChildSub := 0 }
  show ((s.memcaps.insert s.nextMemCapId child).update parent fupd).find? id = _
  by_cases hidNew : id = s.nextMemCapId
  · subst hidNew  -- id replaced by s.nextMemCapId
    rw [Arena.find?_update_other
          (s.memcaps.insert s.nextMemCapId child) parent s.nextMemCapId fupd (Ne.symm hpne)]
    rw [Arena.find?_insert_same s.memcaps s.nextMemCapId child]
    simp [child]
  · by_cases hidPar : id = parent
    · subst hidPar  -- parent replaced by id
      have hins : (s.memcaps.insert s.nextMemCapId child).find? id = some p := by
        rw [Arena.find?_insert_other s.memcaps s.nextMemCapId id child hpne]
        exact hp
      rw [Arena.find?_update_same (s.memcaps.insert s.nextMemCapId child) id fupd hins]
      simp [hidNew, fupd]
    · rw [Arena.find?_update_other
            (s.memcaps.insert s.nextMemCapId child) parent id fupd hidPar]
      rw [Arena.find?_insert_other s.memcaps s.nextMemCapId id child hidNew]
      simp [hidNew, hidPar]
      rfl

/-- Characterization of `getDom` after `carve_apply` when caller exists. -/
private theorem carve_apply_getDom
    (s : SpecState) (caller : DomId) (parent : MemCapId)
    (access : Access) (attrs : Attributes) (p : MemCap) (dc : Domain)
    (hp : s.getMem parent = some p) (hd : s.getDom caller = some dc)
    (did : DomId) :
    let fupd' : Domain → Domain := fun d =>
      { d with memHandles := d.memHandles ++ [(d.nextHandle, s.nextMemCapId)],
               nextHandle := d.nextHandle + 1 }
    (carve_apply s caller parent access attrs).getDom did =
      if did = caller then some (fupd' dc)
      else s.getDom did := by
  show ((carve_apply s caller parent access attrs).domains).find? did = _
  simp only [carve_apply, hp, SpecState.freshMem, SpecState.updMem,
             SpecState.updDomain]
  let fupd' : Domain → Domain := fun d =>
    { d with memHandles := d.memHandles ++ [(d.nextHandle, s.nextMemCapId)],
             nextHandle := d.nextHandle + 1 }
  show (s.domains.update caller fupd').find? did = _
  by_cases hdid : did = caller
  · subst hdid
    rw [Arena.find?_update_same _ _ _ hd]
    simp [fupd']
  · rw [Arena.find?_update_other _ caller did _ hdid]
    simp [hdid]
    rfl

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
  refine ⟨?unique, ?refs, ?cdtMono, ?cdtBidi, ?fresh, ?ho⟩
  case unique =>
    -- s'.memcaps = (s.memcaps.insert next child).update parent fupd
    -- s'.domcaps unchanged; s'.domains = s.domains.update caller fupd'.
    refine ⟨?mc, ?dc, ?ds⟩
    case mc =>
      show ((carve_apply s caller parent access attrs).memcaps).UniqueKeys
      simp only [carve_apply, hpOpt, SpecState.freshMem, SpecState.updMem,
                 SpecState.updDomain]
      apply Arena.update_unique_keys
      apply Arena.insert_unique_keys
      · exact hwf.unique.memcaps
      · exact fresh_not_in_keys s hwf.freshMemCounter
    case dc =>
      show ((carve_apply s caller parent access attrs).domcaps).UniqueKeys
      simp only [carve_apply, hpOpt, SpecState.freshMem, SpecState.updMem,
                 SpecState.updDomain]
      exact hwf.unique.domcaps
    case ds =>
      show ((carve_apply s caller parent access attrs).domains).UniqueKeys
      simp only [carve_apply, hpOpt, SpecState.freshMem, SpecState.updMem,
                 SpecState.updDomain]
      exact Arena.update_unique_keys _ _ _ hwf.unique.domains
  case cdtMono =>
    intro id c hc cid hcid ch hch
    have hgetC := carve_apply_getMem s caller parent access attrs p hpOpt hwf.freshMemCounter id
    have hgetCh := carve_apply_getMem s caller parent access attrs p hpOpt hwf.freshMemCounter cid
    simp only at hgetC hgetCh
    have not_fresh : ∀ {k} {v : MemCap}, s.getMem k = some v → k ≠ s.nextMemCapId := by
      intro k v hk heq; subst heq
      exact Nat.lt_irrefl _ (hwf.freshMemCounter _
        (Arena.mem_keys_of_find?_some _ _ _ hk))
    have child_existing : ∀ {pid pc}, s.getMem pid = some pc →
        ∀ {kid}, kid ∈ pc.childrenIds → kid ≠ s.nextMemCapId := by
      intro pid pc hpid kid hkid heq; subst heq
      have hin := hwf.refs.childInArena _ _ hpid _ hkid
      rcases hkid' : s.getMem s.nextMemCapId with _ | _
      · simp [hkid'] at hin
      · exact Nat.lt_irrefl _ (hwf.freshMemCounter _
          (Arena.mem_keys_of_find?_some _ _ _ hkid'))
    by_cases hidNew : id = s.nextMemCapId
    · -- c = childCap with childrenIds = []. Vacuous.
      rw [hgetC, if_pos hidNew] at hc
      cases hc; simp at hcid
    · by_cases hidPar : id = parent
      · -- c = updP, childrenIds = p.childrenIds ++ [s.nextMemCapId]
        rw [hgetC, if_neg hidNew, if_pos hidPar] at hc
        cases hc
        rw [List.mem_append, List.mem_singleton] at hcid
        rcases hcid with hOld | hNew
        · have hcidNF : cid ≠ s.nextMemCapId := child_existing hpOpt hOld
          rw [hgetCh, if_neg hcidNF] at hch
          by_cases hcidPar : cid = parent
          · rw [if_pos hcidPar] at hch; cases hch
            -- ch = updP. ch.region.access = p.region.access.
            -- updP.region.access = p.region.access (region unchanged).
            -- By hwf.cdtMono on s with edge (parent, p, parent, p):
            exact hwf.cdtMonotonic parent p hpOpt parent (hcidPar ▸ hOld) p hpOpt
          · rw [if_neg hcidPar] at hch
            exact hwf.cdtMonotonic parent p hpOpt cid hOld ch hch
        · -- cid = nextMemCapId, ch = childCap, ch.region.access = access.
          -- updP.region = p.region. Need access.contained p.region.access — guard.
          rw [hgetCh, if_pos hNew] at hch
          cases hch
          show Access.contained _ _
          exact guard.accessContained p hpOpt
      · -- id ≠ {fresh, parent}: c from s.
        rw [hgetC, if_neg hidNew, if_neg hidPar] at hc
        have hcidNF : cid ≠ s.nextMemCapId := child_existing hc hcid
        rw [hgetCh, if_neg hcidNF] at hch
        by_cases hcidPar : cid = parent
        · rw [if_pos hcidPar] at hch; cases hch
          exact hwf.cdtMonotonic id c hc parent (hcidPar ▸ hcid) p hpOpt
        · rw [if_neg hcidPar] at hch
          exact hwf.cdtMonotonic id c hc cid hcid ch hch
  case refs =>
    -- Pull caller's domain once via guard.callerExists.
    rcases hdc : s.getDom caller with _ | dc
    · exact absurd guard.callerExists (by simp [hdc])
    -- Helper: any k with s.getMem k = some v has (s'.getMem k).isSome.
    have hpne : parent ≠ s.nextMemCapId :=
      Nat.ne_of_lt (existing_lt_fresh s hwf.freshMemCounter hpOpt)
    have getMem_preserved : ∀ k v, s.getMem k = some v →
        ((carve_apply s caller parent access attrs).getMem k).isSome := by
      intro k v hk
      have hgk := carve_apply_getMem s caller parent access attrs p hpOpt hwf.freshMemCounter k
      simp only at hgk
      rw [hgk]
      by_cases hkNew : k = s.nextMemCapId
      · simp [hkNew]
      · by_cases hkPar : k = parent
        · subst hkPar; simp [hkNew]
        · simp [hkNew, hkPar, hk]
    have getMem_fresh : ((carve_apply s caller parent access attrs).getMem
        s.nextMemCapId).isSome := by
      have h := carve_apply_getMem s caller parent access attrs p hpOpt
        hwf.freshMemCounter s.nextMemCapId
      simp only at h
      rw [h]; simp
    refine ⟨?pia, ?cia, ?hia⟩
    case pia =>
      intro id c hc pid hcpar
      have hgetC := carve_apply_getMem s caller parent access attrs p hpOpt
        hwf.freshMemCounter id
      simp only at hgetC
      by_cases hidNew : id = s.nextMemCapId
      · rw [hgetC, if_pos hidNew] at hc
        cases hc
        -- c.parent = some parent; need (s'.getMem parent).isSome.
        cases hcpar
        exact getMem_preserved _ _ hpOpt
      · by_cases hidPar : id = parent
        · rw [hgetC, if_neg hidNew, if_pos hidPar] at hc
          cases hc
          -- c = updP, c.parent = p.parent. By hwf.refs.parentInArena on s.
          have hpid := hwf.refs.parentInArena parent p hpOpt pid hcpar
          rcases hk : s.getMem pid with _ | v
          · simp [hk] at hpid
          · exact getMem_preserved _ _ hk
        · rw [hgetC, if_neg hidNew, if_neg hidPar] at hc
          have hpid := hwf.refs.parentInArena id c hc pid hcpar
          rcases hk : s.getMem pid with _ | v
          · simp [hk] at hpid
          · exact getMem_preserved _ _ hk
    case cia =>
      intro id c hc cid hcid
      have hgetC := carve_apply_getMem s caller parent access attrs p hpOpt
        hwf.freshMemCounter id
      simp only at hgetC
      by_cases hidNew : id = s.nextMemCapId
      · rw [hgetC, if_pos hidNew] at hc
        cases hc; simp at hcid
      · by_cases hidPar : id = parent
        · rw [hgetC, if_neg hidNew, if_pos hidPar] at hc
          cases hc
          rw [List.mem_append, List.mem_singleton] at hcid
          rcases hcid with hOld | hNew
          · have := hwf.refs.childInArena parent p hpOpt cid hOld
            rcases hk : s.getMem cid with _ | v
            · simp [hk] at this
            · exact getMem_preserved _ _ hk
          · subst hNew
            exact getMem_fresh
        · rw [hgetC, if_neg hidNew, if_neg hidPar] at hc
          have := hwf.refs.childInArena id c hc cid hcid
          rcases hk : s.getMem cid with _ | v
          · simp [hk] at this
          · exact getMem_preserved _ _ hk
    case hia =>
      intro did d hd ph hph
      have hgetD := carve_apply_getDom s caller parent access attrs p dc hpOpt hdc did
      simp only at hgetD
      by_cases hdid : did = caller
      · rw [hgetD, if_pos hdid] at hd
        cases hd
        -- d = updated dc, d.memHandles = dc.memHandles ++ [(_, s.nextMemCapId)]
        rw [List.mem_append, List.mem_singleton] at hph
        rcases hph with hOld | hNew
        · have := hwf.refs.handleInArena caller dc hdc ph hOld
          rcases hk : s.getMem ph.2 with _ | v
          · simp [hk] at this
          · exact getMem_preserved _ _ hk
        · -- ph = (dc.nextHandle, s.nextMemCapId), so ph.2 = s.nextMemCapId.
          rw [hNew]
          exact getMem_fresh
      · rw [hgetD, if_neg hdid] at hd
        have := hwf.refs.handleInArena did d hd ph hph
        rcases hk : s.getMem ph.2 with _ | v
        · simp [hk] at this
        · exact getMem_preserved _ _ hk
  case cdtBidi =>
    intro id c hc cid hcid ch hch
    have hgetC := carve_apply_getMem s caller parent access attrs p hpOpt hwf.freshMemCounter id
    have hgetCh := carve_apply_getMem s caller parent access attrs p hpOpt hwf.freshMemCounter cid
    simp only at hgetC hgetCh
    -- Helper: any id mapping to `some _` under s.getMem cannot equal s.nextMemCapId.
    have not_fresh : ∀ {k} {v : MemCap}, s.getMem k = some v → k ≠ s.nextMemCapId := by
      intro k v hk heq; subst heq
      have : s.nextMemCapId ∈ s.memcaps.keys :=
        Arena.mem_keys_of_find?_some _ _ _ hk
      exact Nat.lt_irrefl _ (hwf.freshMemCounter _ this)
    -- Helper: any cid in some children-list of an existing parent is in keys
    have child_existing : ∀ {pid pc}, s.getMem pid = some pc →
        ∀ {kid}, kid ∈ pc.childrenIds → kid ≠ s.nextMemCapId := by
      intro pid pc hpid kid hkid heq; subst heq
      have hin := hwf.refs.childInArena _ _ hpid _ hkid
      rcases hkid' : s.getMem s.nextMemCapId with _ | _
      · simp [hkid'] at hin
      · have : s.nextMemCapId ∈ s.memcaps.keys :=
          Arena.mem_keys_of_find?_some _ _ _ hkid'
        exact Nat.lt_irrefl _ (hwf.freshMemCounter _ this)
    -- 3 cases on id.
    by_cases hidNew : id = s.nextMemCapId
    · -- c = childCap, childrenIds = []
      rw [hgetC, if_pos hidNew] at hc
      cases hc; simp at hcid
    · by_cases hidPar : id = parent
      · -- c = updP, childrenIds = p.childrenIds ++ [s.nextMemCapId]
        rw [hgetC, if_neg hidNew, if_pos hidPar] at hc
        cases hc
        rw [List.mem_append, List.mem_singleton] at hcid
        rcases hcid with hOld | hNew
        · -- cid is an old child of p. cid ≠ nextMemCapId.
          have hcidNF : cid ≠ s.nextMemCapId := child_existing hpOpt hOld
          rw [hgetCh, if_neg hcidNF] at hch
          by_cases hcidPar : cid = parent
          · -- cid = parent → ch = updP. updP.parent = p.parent. Need = some id = some parent.
            rw [if_pos hcidPar] at hch
            cases hch
            -- Goal: p.parent = some id.  id = parent. p is in s, parent ∈ p.childrenIds (self-edge).
            -- By hwf.cdtBidi on s with (parent, p, cid=parent, ch=p):
            have := hwf.cdtBidirectional parent p hpOpt parent (hcidPar ▸ hOld) p hpOpt
            rw [hidPar]; exact this
          · rw [if_neg hcidPar] at hch
            -- ch = s.getMem cid. By hwf.cdtBidi on s: ch.parent = some parent = some id.
            rw [hidPar]
            exact hwf.cdtBidirectional parent p hpOpt cid hOld ch hch
        · -- cid = nextMemCapId, ch = childCap, ch.parent = some parent = some id
          rw [hgetCh, if_pos hNew] at hch
          cases hch
          show some parent = some id
          rw [hidPar]
      · -- id ≠ nextMemCapId, id ≠ parent → c from s.
        rw [hgetC, if_neg hidNew, if_neg hidPar] at hc
        -- hc : s.getMem id = some c
        have hcidNF : cid ≠ s.nextMemCapId := child_existing hc hcid
        rw [hgetCh, if_neg hcidNF] at hch
        by_cases hcidPar : cid = parent
        · -- cid = parent → ch = updP. updP.parent = p.parent. By hwf.cdtBidi on s
          --   with (id, c, parent, p): p.parent = some id.
          rw [if_pos hcidPar] at hch
          cases hch
          exact hwf.cdtBidirectional id c hc parent (hcidPar ▸ hcid) p hpOpt
        · rw [if_neg hcidPar] at hch
          exact hwf.cdtBidirectional id c hc cid hcid ch hch
  case fresh =>
    intro id hid
    -- After `cases hstep`, the goal mentions `carve_apply s ...` directly.
    -- Unfold carve_apply: the match on s.getMem parent resolves to the
    -- `some p` branch via hpOpt; `freshMem` produces the insert and bumps
    -- nextMemCapId; updMem/updDomain are field-wise updates that don't
    -- affect either `nextMemCapId` or the *keys* of memcaps.
    simp only [carve_apply, hpOpt, SpecState.freshMem,
               SpecState.updMem, SpecState.updDomain] at hid ⊢
    -- Goal now:  id < s.nextMemCapId + 1
    -- hid:       id ∈ ((s.memcaps.insert s.nextMemCapId _).update parent _).keys
    rw [Arena.keys_update, Arena.keys_insert] at hid
    -- hid: id ∈ s.nextMemCapId :: s.memcaps.keys
    simp only [List.mem_cons] at hid
    rcases hid with rfl | hid
    · exact Nat.lt_succ_self _
    · exact Nat.lt_succ_of_lt (hwf.freshMemCounter _ hid)
  case ho =>
    -- HandleOwner: every handle held by every domain points to a cap whose
    -- owner equals that domain. Carve creates one new handle (in caller's
    -- domain, pointing to childCap whose owner is caller) and may touch
    -- the parent cap's `childrenIds`/`nextChildSub` but never its `owner`.
    intro did d hd ph hph
    rcases hdc : s.getDom caller with _ | dc
    · exact absurd guard.callerExists (by simp [hdc])
    have hgetD := carve_apply_getDom s caller parent access attrs p dc hpOpt hdc did
    simp only at hgetD
    -- Helper: for any pre-state cap, post-state lookup at the same id yields
    -- a cap with the same `owner` field.
    have owner_preserved : ∀ k v, s.getMem k = some v →
        ∃ c', (carve_apply s caller parent access attrs).getMem k = some c' ∧
              c'.owner = v.owner := by
      intro k v hk
      have hgk := carve_apply_getMem s caller parent access attrs p hpOpt
        hwf.freshMemCounter k
      simp only at hgk
      have hkNF : k ≠ s.nextMemCapId := by
        intro heq
        have : k < s.nextMemCapId := existing_lt_fresh s hwf.freshMemCounter hk
        exact Nat.lt_irrefl _ (heq ▸ this)
      rw [hgk, if_neg hkNF]
      by_cases hkPar : k = parent
      · subst hkPar
        rw [if_pos rfl]
        rw [hk] at hpOpt; cases hpOpt
        exact ⟨_, rfl, rfl⟩
      · rw [if_neg hkPar, hk]
        exact ⟨v, rfl, rfl⟩
    by_cases hdid : did = caller
    · rw [hgetD, if_pos hdid] at hd
      cases hd
      simp only [List.mem_append, List.mem_singleton] at hph
      rcases hph with hOld | hNew
      · obtain ⟨c, hwfM, hwfO⟩ := hwf.handleOwner caller dc hdc ph hOld
        obtain ⟨c', hpc, hco⟩ := owner_preserved _ _ hwfM
        rw [hdid]
        exact ⟨c', hpc, hco.trans hwfO⟩
      · rw [hNew]
        have hgN := carve_apply_getMem s caller parent access attrs p hpOpt
          hwf.freshMemCounter s.nextMemCapId
        simp only at hgN
        refine ⟨{ parent := some parent, owner := caller,
                  region := MemoryRegion.mk' .carve p.region.status access attrs,
                  childrenIds := [], nextChildSub := 0 }, ?_, ?_⟩
        · rw [hgN]; simp
        · simp [hdid]
    · rw [hgetD, if_neg hdid] at hd
      obtain ⟨c, hwfM, hwfO⟩ := hwf.handleOwner did d hd ph hph
      obtain ⟨c', hpc, hco⟩ := owner_preserved _ _ hwfM
      exact ⟨c', hpc, hco.trans hwfO⟩

/-! ## Alias

The alias proofs mirror `carve` exactly: same post-state shape (insert fresh
child, update parent children list, append a handle to the caller).  Only
the child's `region.kind`/`region.status`/`attributes` differ, and none of
these fields participate in any invariant.  The characterization lemma and
its 3-way case split are therefore identical in structure. -/

/-- 3-way characterization of `s'.getMem` after `alias_apply`. -/
private theorem alias_apply_getMem
    (s : SpecState) (caller : DomId) (parent : MemCapId) (access : Access)
    (p : MemCap) (hp : s.getMem parent = some p) (hfc : FreshMemCounter s)
    (id : MemCapId) :
    let childCap : MemCap :=
      { parent := some parent, owner := caller,
        region := MemoryRegion.mk' .alias .aliased access p.region.attributes,
        childrenIds := [], nextChildSub := 0 }
    let updP : MemCap :=
      { p with childrenIds := p.childrenIds ++ [s.nextMemCapId],
               nextChildSub := p.nextChildSub + 1 }
    (alias_apply s caller parent access).getMem id =
      if id = s.nextMemCapId then some childCap
      else if id = parent then some updP
      else s.getMem id := by
  have hpne : parent ≠ s.nextMemCapId :=
    Nat.ne_of_lt (existing_lt_fresh s hfc hp)
  show ((alias_apply s caller parent access).memcaps).find? id = _
  simp only [alias_apply, hp, SpecState.freshMem, SpecState.updMem,
             SpecState.updDomain]
  let fupd : MemCap → MemCap := fun pc =>
    { pc with childrenIds := pc.childrenIds ++ [s.nextMemCapId],
              nextChildSub := pc.nextChildSub + 1 }
  let child : MemCap :=
    { parent := some parent, owner := caller,
      region := MemoryRegion.mk' .alias .aliased access p.region.attributes,
      childrenIds := [], nextChildSub := 0 }
  show ((s.memcaps.insert s.nextMemCapId child).update parent fupd).find? id = _
  by_cases hidNew : id = s.nextMemCapId
  · subst hidNew
    rw [Arena.find?_update_other
          (s.memcaps.insert s.nextMemCapId child) parent s.nextMemCapId fupd (Ne.symm hpne)]
    rw [Arena.find?_insert_same s.memcaps s.nextMemCapId child]
    simp [child]
  · by_cases hidPar : id = parent
    · subst hidPar
      have hins : (s.memcaps.insert s.nextMemCapId child).find? id = some p := by
        rw [Arena.find?_insert_other s.memcaps s.nextMemCapId id child hpne]
        exact hp
      rw [Arena.find?_update_same (s.memcaps.insert s.nextMemCapId child) id fupd hins]
      simp [hidNew, fupd]
    · rw [Arena.find?_update_other
            (s.memcaps.insert s.nextMemCapId child) parent id fupd hidPar]
      rw [Arena.find?_insert_other s.memcaps s.nextMemCapId id child hidNew]
      simp [hidNew, hidPar]
      rfl

/-- Characterization of `getDom` after `alias_apply` when caller exists. -/
private theorem alias_apply_getDom
    (s : SpecState) (caller : DomId) (parent : MemCapId) (access : Access)
    (p : MemCap) (dc : Domain)
    (hp : s.getMem parent = some p) (hd : s.getDom caller = some dc)
    (did : DomId) :
    let fupd' : Domain → Domain := fun d =>
      { d with memHandles := d.memHandles ++ [(d.nextHandle, s.nextMemCapId)],
               nextHandle := d.nextHandle + 1 }
    (alias_apply s caller parent access).getDom did =
      if did = caller then some (fupd' dc)
      else s.getDom did := by
  show ((alias_apply s caller parent access).domains).find? did = _
  simp only [alias_apply, hp, SpecState.freshMem, SpecState.updMem,
             SpecState.updDomain]
  let fupd' : Domain → Domain := fun d =>
    { d with memHandles := d.memHandles ++ [(d.nextHandle, s.nextMemCapId)],
             nextHandle := d.nextHandle + 1 }
  show (s.domains.update caller fupd').find? did = _
  by_cases hdid : did = caller
  · subst hdid
    rw [Arena.find?_update_same _ _ _ hd]
    simp [fupd']
  · rw [Arena.find?_update_other _ caller did _ hdid]
    simp [hdid]
    rfl

theorem alias_preserves_wellformed
    {s s' : SpecState} {caller : DomId} {parent : MemCapId} {access : Access}
    (hwf : WellFormed s)
    (hstep : step s (.alias caller parent access) s') :
    WellFormed s' := by
  cases hstep
  rename_i guard
  rcases hpOpt : s.getMem parent with _ | p
  · exact absurd guard.parentExists (by simp [hpOpt])
  refine ⟨?unique, ?refs, ?cdtMono, ?cdtBidi, ?fresh, ?ho⟩
  case unique =>
    refine ⟨?mc, ?dc, ?ds⟩
    case mc =>
      show ((alias_apply s caller parent access).memcaps).UniqueKeys
      simp only [alias_apply, hpOpt, SpecState.freshMem, SpecState.updMem,
                 SpecState.updDomain]
      apply Arena.update_unique_keys
      apply Arena.insert_unique_keys
      · exact hwf.unique.memcaps
      · exact fresh_not_in_keys s hwf.freshMemCounter
    case dc =>
      show ((alias_apply s caller parent access).domcaps).UniqueKeys
      simp only [alias_apply, hpOpt, SpecState.freshMem, SpecState.updMem,
                 SpecState.updDomain]
      exact hwf.unique.domcaps
    case ds =>
      show ((alias_apply s caller parent access).domains).UniqueKeys
      simp only [alias_apply, hpOpt, SpecState.freshMem, SpecState.updMem,
                 SpecState.updDomain]
      exact Arena.update_unique_keys _ _ _ hwf.unique.domains
  case cdtMono =>
    intro id c hc cid hcid ch hch
    have hgetC := alias_apply_getMem s caller parent access p hpOpt
      hwf.freshMemCounter id
    have hgetCh := alias_apply_getMem s caller parent access p hpOpt
      hwf.freshMemCounter cid
    simp only at hgetC hgetCh
    have child_existing : ∀ {pid pc}, s.getMem pid = some pc →
        ∀ {kid}, kid ∈ pc.childrenIds → kid ≠ s.nextMemCapId := by
      intro pid pc hpid kid hkid heq; subst heq
      have hin := hwf.refs.childInArena _ _ hpid _ hkid
      rcases hkid' : s.getMem s.nextMemCapId with _ | _
      · simp [hkid'] at hin
      · exact Nat.lt_irrefl _ (hwf.freshMemCounter _
          (Arena.mem_keys_of_find?_some _ _ _ hkid'))
    by_cases hidNew : id = s.nextMemCapId
    · rw [hgetC, if_pos hidNew] at hc; cases hc; simp at hcid
    · by_cases hidPar : id = parent
      · rw [hgetC, if_neg hidNew, if_pos hidPar] at hc
        cases hc
        rw [List.mem_append, List.mem_singleton] at hcid
        rcases hcid with hOld | hNew
        · have hcidNF : cid ≠ s.nextMemCapId := child_existing hpOpt hOld
          rw [hgetCh, if_neg hcidNF] at hch
          by_cases hcidPar : cid = parent
          · rw [if_pos hcidPar] at hch; cases hch
            exact hwf.cdtMonotonic parent p hpOpt parent (hcidPar ▸ hOld) p hpOpt
          · rw [if_neg hcidPar] at hch
            exact hwf.cdtMonotonic parent p hpOpt cid hOld ch hch
        · -- cid = nextMemCapId, ch = childCap with region.access = access.
          -- updP.region = p.region. Need access.contained p.region.access — guard.
          rw [hgetCh, if_pos hNew] at hch
          cases hch
          show Access.contained _ _
          exact guard.accessContained p hpOpt
      · rw [hgetC, if_neg hidNew, if_neg hidPar] at hc
        have hcidNF : cid ≠ s.nextMemCapId := child_existing hc hcid
        rw [hgetCh, if_neg hcidNF] at hch
        by_cases hcidPar : cid = parent
        · rw [if_pos hcidPar] at hch; cases hch
          exact hwf.cdtMonotonic id c hc parent (hcidPar ▸ hcid) p hpOpt
        · rw [if_neg hcidPar] at hch
          exact hwf.cdtMonotonic id c hc cid hcid ch hch
  case refs =>
    rcases hdc : s.getDom caller with _ | dc
    · exact absurd guard.callerExists (by simp [hdc])
    have hpne : parent ≠ s.nextMemCapId :=
      Nat.ne_of_lt (existing_lt_fresh s hwf.freshMemCounter hpOpt)
    have getMem_preserved : ∀ k v, s.getMem k = some v →
        ((alias_apply s caller parent access).getMem k).isSome := by
      intro k v hk
      have hgk := alias_apply_getMem s caller parent access p hpOpt
        hwf.freshMemCounter k
      simp only at hgk
      rw [hgk]
      by_cases hkNew : k = s.nextMemCapId
      · simp [hkNew]
      · by_cases hkPar : k = parent
        · subst hkPar; simp [hkNew]
        · simp [hkNew, hkPar, hk]
    have getMem_fresh : ((alias_apply s caller parent access).getMem
        s.nextMemCapId).isSome := by
      have h := alias_apply_getMem s caller parent access p hpOpt
        hwf.freshMemCounter s.nextMemCapId
      simp only at h
      rw [h]; simp
    refine ⟨?pia, ?cia, ?hia⟩
    case pia =>
      intro id c hc pid hcpar
      have hgetC := alias_apply_getMem s caller parent access p hpOpt
        hwf.freshMemCounter id
      simp only at hgetC
      by_cases hidNew : id = s.nextMemCapId
      · rw [hgetC, if_pos hidNew] at hc
        cases hc; cases hcpar
        exact getMem_preserved _ _ hpOpt
      · by_cases hidPar : id = parent
        · rw [hgetC, if_neg hidNew, if_pos hidPar] at hc
          cases hc
          have hpid := hwf.refs.parentInArena parent p hpOpt pid hcpar
          rcases hk : s.getMem pid with _ | v
          · simp [hk] at hpid
          · exact getMem_preserved _ _ hk
        · rw [hgetC, if_neg hidNew, if_neg hidPar] at hc
          have hpid := hwf.refs.parentInArena id c hc pid hcpar
          rcases hk : s.getMem pid with _ | v
          · simp [hk] at hpid
          · exact getMem_preserved _ _ hk
    case cia =>
      intro id c hc cid hcid
      have hgetC := alias_apply_getMem s caller parent access p hpOpt
        hwf.freshMemCounter id
      simp only at hgetC
      by_cases hidNew : id = s.nextMemCapId
      · rw [hgetC, if_pos hidNew] at hc; cases hc; simp at hcid
      · by_cases hidPar : id = parent
        · rw [hgetC, if_neg hidNew, if_pos hidPar] at hc
          cases hc
          rw [List.mem_append, List.mem_singleton] at hcid
          rcases hcid with hOld | hNew
          · have := hwf.refs.childInArena parent p hpOpt cid hOld
            rcases hk : s.getMem cid with _ | v
            · simp [hk] at this
            · exact getMem_preserved _ _ hk
          · subst hNew
            exact getMem_fresh
        · rw [hgetC, if_neg hidNew, if_neg hidPar] at hc
          have := hwf.refs.childInArena id c hc cid hcid
          rcases hk : s.getMem cid with _ | v
          · simp [hk] at this
          · exact getMem_preserved _ _ hk
    case hia =>
      intro did d hd ph hph
      have hgetD := alias_apply_getDom s caller parent access p dc hpOpt hdc did
      simp only at hgetD
      by_cases hdid : did = caller
      · rw [hgetD, if_pos hdid] at hd
        cases hd
        rw [List.mem_append, List.mem_singleton] at hph
        rcases hph with hOld | hNew
        · have := hwf.refs.handleInArena caller dc hdc ph hOld
          rcases hk : s.getMem ph.2 with _ | v
          · simp [hk] at this
          · exact getMem_preserved _ _ hk
        · rw [hNew]
          exact getMem_fresh
      · rw [hgetD, if_neg hdid] at hd
        have := hwf.refs.handleInArena did d hd ph hph
        rcases hk : s.getMem ph.2 with _ | v
        · simp [hk] at this
        · exact getMem_preserved _ _ hk
  case cdtBidi =>
    intro id c hc cid hcid ch hch
    have hgetC := alias_apply_getMem s caller parent access p hpOpt
      hwf.freshMemCounter id
    have hgetCh := alias_apply_getMem s caller parent access p hpOpt
      hwf.freshMemCounter cid
    simp only at hgetC hgetCh
    have child_existing : ∀ {pid pc}, s.getMem pid = some pc →
        ∀ {kid}, kid ∈ pc.childrenIds → kid ≠ s.nextMemCapId := by
      intro pid pc hpid kid hkid heq; subst heq
      have hin := hwf.refs.childInArena _ _ hpid _ hkid
      rcases hkid' : s.getMem s.nextMemCapId with _ | _
      · simp [hkid'] at hin
      · exact Nat.lt_irrefl _ (hwf.freshMemCounter _
          (Arena.mem_keys_of_find?_some _ _ _ hkid'))
    by_cases hidNew : id = s.nextMemCapId
    · rw [hgetC, if_pos hidNew] at hc; cases hc; simp at hcid
    · by_cases hidPar : id = parent
      · rw [hgetC, if_neg hidNew, if_pos hidPar] at hc
        cases hc
        rw [List.mem_append, List.mem_singleton] at hcid
        rcases hcid with hOld | hNew
        · have hcidNF : cid ≠ s.nextMemCapId := child_existing hpOpt hOld
          rw [hgetCh, if_neg hcidNF] at hch
          by_cases hcidPar : cid = parent
          · rw [if_pos hcidPar] at hch; cases hch
            have := hwf.cdtBidirectional parent p hpOpt parent (hcidPar ▸ hOld) p hpOpt
            rw [hidPar]; exact this
          · rw [if_neg hcidPar] at hch
            rw [hidPar]
            exact hwf.cdtBidirectional parent p hpOpt cid hOld ch hch
        · rw [hgetCh, if_pos hNew] at hch
          cases hch
          show some parent = some id
          rw [hidPar]
      · rw [hgetC, if_neg hidNew, if_neg hidPar] at hc
        have hcidNF : cid ≠ s.nextMemCapId := child_existing hc hcid
        rw [hgetCh, if_neg hcidNF] at hch
        by_cases hcidPar : cid = parent
        · rw [if_pos hcidPar] at hch; cases hch
          exact hwf.cdtBidirectional id c hc parent (hcidPar ▸ hcid) p hpOpt
        · rw [if_neg hcidPar] at hch
          exact hwf.cdtBidirectional id c hc cid hcid ch hch
  case fresh =>
    intro id hid
    simp only [alias_apply, hpOpt, SpecState.freshMem,
               SpecState.updMem, SpecState.updDomain] at hid ⊢
    rw [Arena.keys_update, Arena.keys_insert] at hid
    simp only [List.mem_cons] at hid
    rcases hid with rfl | hid
    · exact Nat.lt_succ_self _
    · exact Nat.lt_succ_of_lt (hwf.freshMemCounter _ hid)
  case ho =>
    intro did d hd ph hph
    rcases hdc : s.getDom caller with _ | dc
    · exact absurd guard.callerExists (by simp [hdc])
    have hgetD := alias_apply_getDom s caller parent access p dc hpOpt hdc did
    simp only at hgetD
    have owner_preserved : ∀ k v, s.getMem k = some v →
        ∃ c', (alias_apply s caller parent access).getMem k = some c' ∧
              c'.owner = v.owner := by
      intro k v hk
      have hgk := alias_apply_getMem s caller parent access p hpOpt
        hwf.freshMemCounter k
      simp only at hgk
      have hkNF : k ≠ s.nextMemCapId := by
        intro heq
        have : k < s.nextMemCapId := existing_lt_fresh s hwf.freshMemCounter hk
        exact Nat.lt_irrefl _ (heq ▸ this)
      rw [hgk, if_neg hkNF]
      by_cases hkPar : k = parent
      · subst hkPar
        rw [if_pos rfl]
        rw [hk] at hpOpt; cases hpOpt
        exact ⟨_, rfl, rfl⟩
      · rw [if_neg hkPar, hk]
        exact ⟨v, rfl, rfl⟩
    by_cases hdid : did = caller
    · rw [hgetD, if_pos hdid] at hd
      cases hd
      simp only [List.mem_append, List.mem_singleton] at hph
      rcases hph with hOld | hNew
      · obtain ⟨c, hwfM, hwfO⟩ := hwf.handleOwner caller dc hdc ph hOld
        obtain ⟨c', hpc, hco⟩ := owner_preserved _ _ hwfM
        rw [hdid]
        exact ⟨c', hpc, hco.trans hwfO⟩
      · rw [hNew]
        have hgN := alias_apply_getMem s caller parent access p hpOpt
          hwf.freshMemCounter s.nextMemCapId
        simp only at hgN
        refine ⟨{ parent := some parent, owner := caller,
                  region := MemoryRegion.mk' .alias .aliased access p.region.attributes,
                  childrenIds := [], nextChildSub := 0 }, ?_, ?_⟩
        · rw [hgN]; simp
        · simp [hdid]
    · rw [hgetD, if_neg hdid] at hd
      obtain ⟨c, hwfM, hwfO⟩ := hwf.handleOwner did d hd ph hph
      obtain ⟨c', hpc, hco⟩ := owner_preserved _ _ hwfM
      exact ⟨c', hpc, hco.trans hwfO⟩

/-! ## Revoke

Leaf revocation. Unlike carve/alias, revoke *shrinks* the arena: it
removes `target`, strips `target` from its parent's children list, and
strips the matching handle from the owner domain.

The proof structure mirrors carve/alias: prove a 3-way characterization
`revoke_apply_getMem` (none / updP / unchanged) and a 2-way
`revoke_apply_getDom`, then discharge each WellFormed sub-goal by
case-splitting on the lookup key.

The 6-way invariant proof (`revoke_preserves_wellformed`) is **deferred**.
It requires adding a 7th invariant to `WellFormed`:

  ParentChildAgreement : ∀ id c, getMem id = some c →
    ∀ pid, c.parent = some pid →
      ∀ p, getMem pid = some p → id ∈ p.childrenIds

This is the *dual* of `CdtBidirectional` (which only gives child→parent).
Without it, revoke cannot rule out cases like "another cap's parent =
target" — needed to argue `target` is mentioned nowhere as a parent
once it's removed. Adding it requires extending the carve and alias
proofs with one new sub-goal each (both trivial: carve/alias make the
new child a child of `parent` and set its parent to `parent`, matching
trivially). -/

private theorem revoke_apply_getMem
    (s : SpecState) (caller : DomId) (target : MemCapId)
    (t : MemCap) (ht : s.getMem target = some t)
    (pid : MemCapId) (htp : t.parent = some pid)
    (p : MemCap) (hp : s.getMem pid = some p)
    (hpne : pid ≠ target) (id : MemCapId) :
    let updP : MemCap :=
      { p with childrenIds := p.childrenIds.filter (· ≠ target) }
    (revoke_apply s caller target).getMem id =
      if id = target then none
      else if id = pid then some updP
      else s.getMem id := by
  show ((revoke_apply s caller target).memcaps).find? id = _
  simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
  let f : MemCap → MemCap := fun q =>
    { q with childrenIds := q.childrenIds.filter (· ≠ target) }
  show ((s.memcaps.remove target).update pid f).find? id = _
  by_cases hidT : id = target
  · subst hidT
    rw [Arena.find?_update_other _ pid id f (Ne.symm hpne)]
    rw [Arena.find?_remove_same]
    simp
  · by_cases hidP : id = pid
    · subst hidP
      have hpinr : (s.memcaps.remove target).find? id = some p := by
        rw [Arena.find?_remove_other _ target id hpne]
        exact hp
      rw [Arena.find?_update_same _ id f hpinr]
      simp [hidT, f]
    · rw [Arena.find?_update_other _ pid id f hidP]
      rw [Arena.find?_remove_other _ target id hidT]
      simp [hidT, hidP]
      rfl

private theorem revoke_apply_getDom
    (s : SpecState) (caller : DomId) (target : MemCapId)
    (t : MemCap) (ht : s.getMem target = some t)
    (pid : MemCapId) (htp : t.parent = some pid)
    (did : DomId) :
    let fupd : Domain → Domain := fun d =>
      { d with memHandles := d.memHandles.filter (fun h => h.2 ≠ target) }
    (revoke_apply s caller target).getDom did =
      if did = t.owner then (s.getDom t.owner).map fupd
      else s.getDom did := by
  show ((revoke_apply s caller target).domains).find? did = _
  simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
  by_cases hdid : did = t.owner
  · subst hdid
    rw [Arena.find?_update_eq_map]
    simp [SpecState.getDom]
  · rw [Arena.find?_update_other _ t.owner did _ hdid]
    simp [hdid]
    rfl

/-- **Deferred.** Requires adding `ParentChildAgreement` to `WellFormed`
    and extending carve/alias proofs. See section docstring above for plan. -/
theorem revoke_preserves_wellformed
    {s s' : SpecState} {caller : DomId} {target : MemCapId}
    (hwf : WellFormed s)
    (hstep : step s (.revoke caller target) s') :
    WellFormed s' := by
  sorry

end ThemisCapa

