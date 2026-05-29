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
  refine ⟨?unique, ?refs, ?cdtMono, ?cdtBidi, ?fresh, ?ho, ?pca⟩
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
  case pca =>
    -- ParentChildAgreement: dual of cdtBidi. If c.parent = some pid', then
    -- c.id ∈ p.childrenIds (with p = getMem pid'). Carve sets new child's
    -- parent to `parent` and appends new child to parent's childrenIds —
    -- so the new edge is trivially in the agreement. Existing edges are
    -- preserved because the only mutation to a childrenIds list is the
    -- append to parent's list (no deletions).
    intro id c hc pid' hcpar pp hpp
    have hgetC := carve_apply_getMem s caller parent access attrs p hpOpt
      hwf.freshMemCounter id
    have hgetP := carve_apply_getMem s caller parent access attrs p hpOpt
      hwf.freshMemCounter pid'
    simp only at hgetC hgetP
    have hparNF : parent ≠ s.nextMemCapId :=
      Nat.ne_of_lt (existing_lt_fresh s hwf.freshMemCounter hpOpt)
    by_cases hidN : id = s.nextMemCapId
    · rw [hgetC, if_pos hidN] at hc
      cases hc
      -- c.parent = some parent ⇒ pid' = parent
      simp at hcpar; subst hcpar
      rw [hgetP, if_neg hparNF, if_pos rfl] at hpp
      cases hpp
      simp [hidN]
    · rw [hgetC, if_neg hidN] at hc
      by_cases hidP : id = parent
      · rw [if_pos hidP] at hc; cases hc
        -- c = updP. c.parent = p.parent. So hcpar : p.parent = some pid'.
        simp only at hcpar
        have hppPreSome := hwf.refs.parentInArena parent p hpOpt pid' hcpar
        rcases hppPre : s.getMem pid' with _ | pPre
        · simp [hppPre] at hppPreSome
        have pre := hwf.parentChild parent p hpOpt pid' hcpar pPre hppPre
        have hpid'NF : pid' ≠ s.nextMemCapId :=
          Nat.ne_of_lt (existing_lt_fresh s hwf.freshMemCounter hppPre)
        rw [hgetP, if_neg hpid'NF] at hpp
        by_cases hpidPar : pid' = parent
        · subst hpidPar
          rw [if_pos rfl] at hpp; cases hpp
          rw [hppPre] at hpOpt
          obtain rfl : pPre = p := by cases hpOpt; rfl
          rw [List.mem_append]; exact Or.inl (hidP ▸ pre)
        · rw [if_neg hpidPar, hppPre] at hpp
          cases hpp
          rw [hidP]; exact pre
      · rw [if_neg hidP] at hc
        -- c preserved
        have hppPreSome := hwf.refs.parentInArena id c hc pid' hcpar
        rcases hppPre : s.getMem pid' with _ | pPre
        · simp [hppPre] at hppPreSome
        have pre := hwf.parentChild id c hc pid' hcpar pPre hppPre
        have hpid'NF : pid' ≠ s.nextMemCapId :=
          Nat.ne_of_lt (existing_lt_fresh s hwf.freshMemCounter hppPre)
        rw [hgetP, if_neg hpid'NF] at hpp
        by_cases hpidPar : pid' = parent
        · subst hpidPar
          rw [if_pos rfl] at hpp; cases hpp
          rw [hppPre] at hpOpt
          obtain rfl : pPre = p := by cases hpOpt; rfl
          rw [List.mem_append]; exact Or.inl pre
        · rw [if_neg hpidPar, hppPre] at hpp
          cases hpp; exact pre

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
  refine ⟨?unique, ?refs, ?cdtMono, ?cdtBidi, ?fresh, ?ho, ?pca⟩
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
  case pca =>
    -- Identical shape to carve: only mutation to childrenIds is the
    -- append at `parent`; existing edges are preserved; the new child's
    -- edge is in p.childrenIds ++ [nextMemCapId].
    intro id c hc pid' hcpar pp hpp
    have hgetC := alias_apply_getMem s caller parent access p hpOpt
      hwf.freshMemCounter id
    have hgetP := alias_apply_getMem s caller parent access p hpOpt
      hwf.freshMemCounter pid'
    simp only at hgetC hgetP
    have hparNF : parent ≠ s.nextMemCapId :=
      Nat.ne_of_lt (existing_lt_fresh s hwf.freshMemCounter hpOpt)
    by_cases hidN : id = s.nextMemCapId
    · rw [hgetC, if_pos hidN] at hc
      cases hc
      simp at hcpar; subst hcpar
      rw [hgetP, if_neg hparNF, if_pos rfl] at hpp
      cases hpp
      simp [hidN]
    · rw [hgetC, if_neg hidN] at hc
      by_cases hidP : id = parent
      · rw [if_pos hidP] at hc; cases hc
        simp only at hcpar
        have hppPreSome := hwf.refs.parentInArena parent p hpOpt pid' hcpar
        rcases hppPre : s.getMem pid' with _ | pPre
        · simp [hppPre] at hppPreSome
        have pre := hwf.parentChild parent p hpOpt pid' hcpar pPre hppPre
        have hpid'NF : pid' ≠ s.nextMemCapId :=
          Nat.ne_of_lt (existing_lt_fresh s hwf.freshMemCounter hppPre)
        rw [hgetP, if_neg hpid'NF] at hpp
        by_cases hpidPar : pid' = parent
        · subst hpidPar
          rw [if_pos rfl] at hpp; cases hpp
          rw [hppPre] at hpOpt
          obtain rfl : pPre = p := by cases hpOpt; rfl
          rw [List.mem_append]; exact Or.inl (hidP ▸ pre)
        · rw [if_neg hpidPar, hppPre] at hpp
          cases hpp
          rw [hidP]; exact pre
      · rw [if_neg hidP] at hc
        have hppPreSome := hwf.refs.parentInArena id c hc pid' hcpar
        rcases hppPre : s.getMem pid' with _ | pPre
        · simp [hppPre] at hppPreSome
        have pre := hwf.parentChild id c hc pid' hcpar pPre hppPre
        have hpid'NF : pid' ≠ s.nextMemCapId :=
          Nat.ne_of_lt (existing_lt_fresh s hwf.freshMemCounter hppPre)
        rw [hgetP, if_neg hpid'NF] at hpp
        by_cases hpidPar : pid' = parent
        · subst hpidPar
          rw [if_pos rfl] at hpp; cases hpp
          rw [hppPre] at hpOpt
          obtain rfl : pPre = p := by cases hpOpt; rfl
          rw [List.mem_append]; exact Or.inl pre
        · rw [if_neg hpidPar, hppPre] at hpp
          cases hpp; exact pre

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

/-- `revoke_preserves_wellformed` — full proof using ParentChildAgreement.

    The 7-way invariant proof reuses `revoke_apply_getMem` / `getDom`
    characterization lemmas and PCA to dispatch the cases where a cap
    other than the parent could mention `target`: PCA + `targetIsLeaf`
    rules those out by yielding `target ∈ target.childrenIds = []`. -/
theorem revoke_preserves_wellformed
    {s s' : SpecState} {caller : DomId} {target : MemCapId}
    (hwf : WellFormed s)
    (hstep : step s (.revoke caller target) s') :
    WellFormed s' := by
  cases hstep
  rename_i guard
  -- Unpack target.
  rcases ht : s.getMem target with _ | t
  · exact absurd guard.targetExists (by simp [ht])
  -- Target has a parent.
  rcases htp : t.parent with _ | pid
  · have := guard.targetHasParent t ht; rw [htp] at this; cases this
  -- Parent exists in arena.
  have hpSome : (s.getMem pid).isSome :=
    hwf.refs.parentInArena target t ht pid htp
  rcases hp : s.getMem pid with _ | p
  · simp [hp] at hpSome
  -- Derive `pid ≠ target` from PCA + targetIsLeaf.
  have hpne : pid ≠ target := by
    intro heq
    have hleaf := guard.targetIsLeaf t ht
    have : pid ∈ t.childrenIds := by
      have := hwf.parentChild target t ht pid htp
      have hpt : s.getMem pid = some t := heq ▸ ht
      have := hwf.parentChild target t ht pid htp t hpt
      simpa [heq] using this
    rw [hleaf] at this; cases this
  -- Helper: every cap c (≠ t) cannot have `target` as its parent.
  -- If it did, then by PCA, the cap's id ∈ t.childrenIds = []. ⊥.
  have notParentTarget :
      ∀ id c, s.getMem id = some c → c.parent = some target → False := by
    intro id c hc hcpar
    have := hwf.parentChild id c hc target hcpar t ht
    rw [guard.targetIsLeaf t ht] at this; cases this
  -- Now show the post-state.
  refine ⟨?unique, ?refs, ?cdtMono, ?cdtBidi, ?fresh, ?ho, ?pca⟩
  case unique =>
    refine ⟨?mc, ?dc, ?ds⟩
    case mc =>
      show ((revoke_apply s caller target).memcaps).UniqueKeys
      simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
      exact Arena.update_unique_keys _ pid _
        (Arena.remove_unique_keys _ target hwf.unique.memcaps)
    case dc =>
      show ((revoke_apply s caller target).domcaps).UniqueKeys
      simp [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
      exact hwf.unique.domcaps
    case ds =>
      show ((revoke_apply s caller target).domains).UniqueKeys
      simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
      exact Arena.update_unique_keys _ _ _ hwf.unique.domains
  case refs =>
    refine ⟨?pia, ?cia, ?hia⟩
    case pia =>
      intro id c hc pid' hcpar
      have hgetC := revoke_apply_getMem s caller target t ht pid htp p hp hpne id
      have hgetP := revoke_apply_getMem s caller target t ht pid htp p hp hpne pid'
      simp only at hgetC hgetP
      by_cases hidT : id = target
      · rw [hgetC, if_pos hidT] at hc; cases hc
      · rw [hgetC, if_neg hidT] at hc
        -- pid' ≠ target.
        have hpidT : pid' ≠ target := by
          intro heqT
          by_cases hidP : id = pid
          · rw [if_pos hidP] at hc; cases hc
            -- c = updP, c.parent = p.parent. hcpar : p.parent = some target.
            exact notParentTarget pid p hp (heqT ▸ hcpar)
          · rw [if_neg hidP] at hc
            exact notParentTarget id c hc (heqT ▸ hcpar)
        rw [hgetP, if_neg hpidT]
        by_cases hpidP : pid' = pid
        · rw [if_pos hpidP]; simp
        · rw [if_neg hpidP]
          by_cases hidP : id = pid
          · rw [if_pos hidP] at hc; cases hc
            exact hwf.refs.parentInArena pid p hp pid' hcpar
          · rw [if_neg hidP] at hc
            exact hwf.refs.parentInArena id c hc pid' hcpar
    case cia =>
      intro id c hc cid hcid
      have hgetC := revoke_apply_getMem s caller target t ht pid htp p hp hpne id
      have hgetCid := revoke_apply_getMem s caller target t ht pid htp p hp hpne cid
      simp only at hgetC hgetCid
      by_cases hidT : id = target
      · rw [hgetC, if_pos hidT] at hc; cases hc
      · rw [hgetC, if_neg hidT] at hc
        -- cid ≠ target.
        have hcidT : cid ≠ target := by
          intro heq
          by_cases hidP : id = pid
          · rw [if_pos hidP] at hc; cases hc
            -- cid ∈ p.childrenIds.filter (≠target). cid = target ⇒ ⊥.
            have := List.mem_filter.mp hcid
            exact absurd heq (by simpa using this.2)
          · rw [if_neg hidP] at hc
            -- By pre-cdtBidi: getMem cid (= t since cid=target) has parent = some id.
            -- t.parent = some pid. So id = pid. Contradiction with hidP.
            have hcidSome := hwf.refs.childInArena id c hc cid hcid
            rcases hch : s.getMem cid with _ | ch
            · simp [hch] at hcidSome
            have hbi := hwf.cdtBidirectional id c hc cid hcid ch hch
            rw [heq, ht] at hch; cases hch
            rw [htp] at hbi
            exact hidP (Option.some.inj hbi).symm
        rw [hgetCid, if_neg hcidT]
        by_cases hcidP : cid = pid
        · rw [if_pos hcidP]; simp
        · rw [if_neg hcidP]
          by_cases hidP : id = pid
          · rw [if_pos hidP] at hc; cases hc
            -- c = updP, c.childrenIds = p.childrenIds.filter (≠target).
            have := List.mem_filter.mp hcid
            exact hwf.refs.childInArena pid p hp cid this.1
          · rw [if_neg hidP] at hc
            exact hwf.refs.childInArena id c hc cid hcid
    case hia =>
      intro did d hd ph hph
      have hgetD := revoke_apply_getDom s caller target t ht pid htp did
      simp only at hgetD
      by_cases hdid : did = t.owner
      · rw [hgetD, if_pos hdid] at hd
        rcases hdpre : s.getDom t.owner with _ | dpre
        · rw [hdpre] at hd; simp at hd
        rw [hdpre] at hd; simp at hd
        rw [← hd] at hph
        simp at hph
        -- ph.2 ≠ target from filter.
        have hphT : ph.2 ≠ target := hph.2
        have hpre := hwf.refs.handleInArena (t.owner) dpre hdpre ph hph.1
        have hgetH := revoke_apply_getMem s caller target t ht pid htp p hp hpne ph.2
        simp only at hgetH
        rw [hgetH, if_neg hphT]
        by_cases hphP : ph.2 = pid
        · rw [if_pos hphP]; simp
        · rw [if_neg hphP]; exact hpre
      · rw [hgetD, if_neg hdid] at hd
        have hpre := hwf.refs.handleInArena did d hd ph hph
        -- ph.2 ≠ target via HandleOwner.
        have hphT : ph.2 ≠ target := by
          intro heq
          obtain ⟨c, hcM, hco⟩ := hwf.handleOwner did d hd ph hph
          rw [heq, ht] at hcM; cases hcM
          exact hdid hco.symm
        have hgetH := revoke_apply_getMem s caller target t ht pid htp p hp hpne ph.2
        simp only at hgetH
        rw [hgetH, if_neg hphT]
        by_cases hphP : ph.2 = pid
        · rw [if_pos hphP]; simp
        · rw [if_neg hphP]; exact hpre
  case cdtMono =>
    intro id c hc cid hcid ch hch
    have hgetC := revoke_apply_getMem s caller target t ht pid htp p hp hpne id
    have hgetCh := revoke_apply_getMem s caller target t ht pid htp p hp hpne cid
    simp only at hgetC hgetCh
    by_cases hidT : id = target
    · rw [hgetC, if_pos hidT] at hc; cases hc
    rw [hgetC, if_neg hidT] at hc
    -- cid ≠ target (same arg as `cia`).
    have hcidT : cid ≠ target := by
      intro heq
      by_cases hidP : id = pid
      · rw [if_pos hidP] at hc; cases hc
        have := List.mem_filter.mp hcid
        exact absurd heq (by simpa using this.2)
      · rw [if_neg hidP] at hc
        have hcidSome := hwf.refs.childInArena id c hc cid hcid
        rcases hch' : s.getMem cid with _ | ch'
        · simp [hch'] at hcidSome
        have hbi := hwf.cdtBidirectional id c hc cid hcid ch' hch'
        rw [heq, ht] at hch'; cases hch'
        rw [htp] at hbi
        exact hidP (Option.some.inj hbi).symm
    rw [hgetCh, if_neg hcidT] at hch
    by_cases hidP : id = pid
    · rw [if_pos hidP] at hc; cases hc
      -- c = updP. c.region = p.region. cid ∈ p.childrenIds.filter (≠target).
      have hcidIn := (List.mem_filter.mp hcid).1
      by_cases hcidP : cid = pid
      · rw [if_pos hcidP] at hch; cases hch
        -- ch = updP. updP.region = p.region.
        exact hwf.cdtMonotonic pid p hp cid hcidIn p (hcidP ▸ hp)
      · rw [if_neg hcidP] at hch
        exact hwf.cdtMonotonic pid p hp cid hcidIn ch hch
    · rw [if_neg hidP] at hc
      by_cases hcidP : cid = pid
      · rw [if_pos hcidP] at hch; cases hch
        -- ch = updP. updP.region = p.region.
        exact hwf.cdtMonotonic id c hc cid hcid p (hcidP ▸ hp)
      · rw [if_neg hcidP] at hch
        exact hwf.cdtMonotonic id c hc cid hcid ch hch
  case cdtBidi =>
    intro id c hc cid hcid ch hch
    have hgetC := revoke_apply_getMem s caller target t ht pid htp p hp hpne id
    have hgetCh := revoke_apply_getMem s caller target t ht pid htp p hp hpne cid
    simp only at hgetC hgetCh
    by_cases hidT : id = target
    · rw [hgetC, if_pos hidT] at hc; cases hc
    rw [hgetC, if_neg hidT] at hc
    have hcidT : cid ≠ target := by
      intro heq
      by_cases hidP : id = pid
      · rw [if_pos hidP] at hc; cases hc
        have := List.mem_filter.mp hcid
        exact absurd heq (by simpa using this.2)
      · rw [if_neg hidP] at hc
        have hcidSome := hwf.refs.childInArena id c hc cid hcid
        rcases hch' : s.getMem cid with _ | ch'
        · simp [hch'] at hcidSome
        have hbi := hwf.cdtBidirectional id c hc cid hcid ch' hch'
        rw [heq, ht] at hch'; cases hch'
        rw [htp] at hbi
        exact hidP (Option.some.inj hbi).symm
    rw [hgetCh, if_neg hcidT] at hch
    by_cases hidP : id = pid
    · rw [if_pos hidP] at hc; cases hc
      have hcidIn := (List.mem_filter.mp hcid).1
      by_cases hcidP : cid = pid
      · rw [if_pos hcidP] at hch; cases hch
        -- ch = updP. updP.parent = p.parent. Need = some id (= some pid).
        -- By pre-cdtBidi on (pid, p, hp, cid=pid, hcidIn, p, hp): p.parent = some pid.
        exact hidP ▸ hwf.cdtBidirectional pid p hp cid hcidIn p (hcidP ▸ hp)
      · rw [if_neg hcidP] at hch
        exact hidP ▸ hwf.cdtBidirectional pid p hp cid hcidIn ch hch
    · rw [if_neg hidP] at hc
      by_cases hcidP : cid = pid
      · rw [if_pos hcidP] at hch; cases hch
        -- ch = updP. updP.parent = p.parent. Pre: p.parent = some id.
        exact hwf.cdtBidirectional id c hc cid hcid p (hcidP ▸ hp)
      · rw [if_neg hcidP] at hch
        exact hwf.cdtBidirectional id c hc cid hcid ch hch
  case fresh =>
    -- s'.nextMemCapId = s.nextMemCapId. s'.memcaps.keys ⊆ s.memcaps.keys.
    intro id hid
    have hKeys : id ∈ s.memcaps.keys := by
      have heq : ((revoke_apply s caller target).memcaps).keys
                  = (s.memcaps.remove target).keys := by
        simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain,
                   Arena.keys_update]
      rw [heq] at hid
      exact ((Arena.mem_keys_remove_iff _ _ _).mp hid).2
    have : ((revoke_apply s caller target).nextMemCapId) = s.nextMemCapId := by
      simp [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
    rw [this]
    exact hwf.freshMemCounter id hKeys
  case ho =>
    intro did d hd ph hph
    have hgetD := revoke_apply_getDom s caller target t ht pid htp did
    simp only at hgetD
    by_cases hdid : did = t.owner
    · rw [hgetD, if_pos hdid] at hd
      rcases hdpre : s.getDom t.owner with _ | dpre
      · rw [hdpre] at hd; simp at hd
      rw [hdpre] at hd; simp at hd
      rw [← hd] at hph
      simp at hph
      have hphT : ph.2 ≠ target := hph.2
      obtain ⟨c, hcM, hco⟩ :=
        hwf.handleOwner (t.owner) dpre hdpre ph hph.1
      have hgetH := revoke_apply_getMem s caller target t ht pid htp p hp hpne ph.2
      simp only at hgetH
      by_cases hphP : ph.2 = pid
      · refine ⟨{ p with childrenIds := p.childrenIds.filter (· ≠ target) }, ?_, ?_⟩
        · rw [hgetH, if_neg hphT, if_pos hphP]
        · -- ph.2 = pid, so c = p (from pre lookup at pid). p.owner = t.owner = did.
          have hcEq : c = p := by
            have := hcM; rw [hphP, hp] at this; cases this; rfl
          subst hcEq
          rw [hdid]; exact hco
      · refine ⟨c, ?_, ?_⟩
        · rw [hgetH, if_neg hphT, if_neg hphP]; exact hcM
        · rw [hdid]; exact hco
    · rw [hgetD, if_neg hdid] at hd
      obtain ⟨c, hcM, hco⟩ := hwf.handleOwner did d hd ph hph
      have hphT : ph.2 ≠ target := by
        intro heq; rw [heq, ht] at hcM; cases hcM
        exact hdid hco.symm
      have hgetH := revoke_apply_getMem s caller target t ht pid htp p hp hpne ph.2
      simp only at hgetH
      by_cases hphP : ph.2 = pid
      · refine ⟨{ p with childrenIds := p.childrenIds.filter (· ≠ target) }, ?_, ?_⟩
        · rw [hgetH, if_neg hphT, if_pos hphP]
        · have hcEq : c = p := by
            have := hcM; rw [hphP, hp] at this; cases this; rfl
          subst hcEq; exact hco
      · refine ⟨c, ?_, ?_⟩
        · rw [hgetH, if_neg hphT, if_neg hphP]; exact hcM
        · exact hco
  case pca =>
    intro id c hc pid' hcpar pp hpp
    have hgetC := revoke_apply_getMem s caller target t ht pid htp p hp hpne id
    have hgetP := revoke_apply_getMem s caller target t ht pid htp p hp hpne pid'
    simp only at hgetC hgetP
    by_cases hidT : id = target
    · rw [hgetC, if_pos hidT] at hc; cases hc
    rw [hgetC, if_neg hidT] at hc
    -- pid' ≠ target.
    have hpidT : pid' ≠ target := by
      intro heq
      by_cases hidP : id = pid
      · rw [if_pos hidP] at hc; cases hc
        exact notParentTarget pid p hp (heq ▸ hcpar)
      · rw [if_neg hidP] at hc
        exact notParentTarget id c hc (heq ▸ hcpar)
    rw [hgetP, if_neg hpidT] at hpp
    by_cases hidP : id = pid
    · -- c = updP. Derive p.parent = some pid' and pre-PCA.
      have hcEq : c = { p with childrenIds := p.childrenIds.filter (· ≠ target) } := by
        have hc' := hc
        rw [if_pos hidP] at hc'
        exact (Option.some.inj hc').symm
      have hcpar' : p.parent = some pid' := by
        have := hcpar; rw [hcEq] at this; exact this
      have hpidSome := hwf.refs.parentInArena pid p hp pid' hcpar'
      rcases hpidPre : s.getMem pid' with _ | ppre
      · simp [hpidPre] at hpidSome
      have hpreM : pid ∈ ppre.childrenIds :=
        hwf.parentChild pid p hp pid' hcpar' ppre hpidPre
      by_cases hpidPid : pid' = pid
      · subst hpidPid
        rw [hp] at hpidPre; cases hpidPre
        rw [if_pos rfl] at hpp; cases hpp
        rw [hidP]
        show pid' ∈ (p.childrenIds.filter _)
        rw [List.mem_filter]
        exact ⟨hpreM, by simpa using hpne⟩
      · rw [if_neg hpidPid, hpidPre] at hpp
        cases hpp
        rw [hidP]; exact hpreM
    · -- c preserved.
      have hcPre : s.getMem id = some c := by
        have hc' := hc; rw [if_neg hidP] at hc'; exact hc'
      have hpidSome := hwf.refs.parentInArena id c hcPre pid' hcpar
      rcases hpidPre : s.getMem pid' with _ | ppre
      · simp [hpidPre] at hpidSome
      have hpreM : id ∈ ppre.childrenIds :=
        hwf.parentChild id c hcPre pid' hcpar ppre hpidPre
      by_cases hpidPid : pid' = pid
      · subst hpidPid
        rw [hp] at hpidPre; cases hpidPre
        rw [if_pos rfl] at hpp; cases hpp
        show id ∈ (p.childrenIds.filter _)
        rw [List.mem_filter]
        exact ⟨hpreM, by simpa using hidT⟩
      · rw [if_neg hpidPid, hpidPre] at hpp
        cases hpp; exact hpreM

/-! ## Send (unsealed path)

Unlike carve/alias/revoke, send doesn't touch the CDT (parent/children/
region are unchanged). It only:
  * updates `cap.owner` to `receiver`;
  * drops *all* caller handles to `cap`;
  * appends a fresh `(nextHandle, cap)` to receiver's handle list.

Hence CdtBidi, CdtMono, PCA, and freshMemCounter are trivially preserved.
The interesting invariant is `HandleOwner`: the receiver gains a new handle
whose `cap.owner` is now `receiver` (matching the new ownership). Any
*pre-existing* receiver handle to `cap` would contradict pre-`HandleOwner`
(since pre `cap.owner = caller ≠ receiver`), so we don't double-up. -/

/-- Characterization of `send_apply` on the memcap arena: only `cap` changes. -/
private theorem send_apply_getMem
    (s : SpecState) (caller : DomId) (receiver : DomId) (cap : MemCapId)
    (id : MemCapId) :
    (send_apply s caller receiver cap).getMem id =
      if id = cap then (s.getMem cap).map (fun c => { c with owner := receiver })
      else s.getMem id := by
  show ((send_apply s caller receiver cap).memcaps).find? id = _
  simp only [send_apply, SpecState.updMem, SpecState.updDomain]
  by_cases hidC : id = cap
  · subst hidC
    rw [Arena.find?_update_eq_map]; simp; rfl
  · rw [Arena.find?_update_other _ cap id _ hidC]
    simp [hidC]; rfl

/-- Characterization of `send_apply` on the domain arena: caller and
    receiver are updated independently; everyone else is unchanged. -/
private theorem send_apply_getDom
    (s : SpecState) (caller : DomId) (receiver : DomId) (cap : MemCapId)
    (hne : caller ≠ receiver) (did : DomId) :
    let fc : Domain → Domain := fun d =>
      { d with memHandles := d.memHandles.filter (fun h => h.2 ≠ cap) }
    let fr : Domain → Domain := fun d =>
      { d with memHandles := d.memHandles ++ [(d.nextHandle, cap)],
               nextHandle := d.nextHandle + 1 }
    (send_apply s caller receiver cap).getDom did =
      if did = caller then (s.getDom caller).map fc
      else if did = receiver then (s.getDom receiver).map fr
      else s.getDom did := by
  show ((send_apply s caller receiver cap).domains).find? did = _
  simp only [send_apply, SpecState.updMem, SpecState.updDomain]
  by_cases hdidC : did = caller
  · subst hdidC
    -- did = caller. Peel receiver (outer), then caller (inner).
    have hRdid : did ≠ receiver := hne
    rw [Arena.find?_update_other _ receiver did _ hRdid]
    rw [Arena.find?_update_eq_map]
    simp; rfl
  · by_cases hdidR : did = receiver
    · subst hdidR
      -- did = receiver. Peel receiver (outer = map), then caller (inner; ≠).
      rw [Arena.find?_update_eq_map]
      have hCdid : did ≠ caller := hdidC
      rw [Arena.find?_update_other _ caller did _ hCdid]
      simp [hdidC]; rfl
    · have hCdid : did ≠ caller := hdidC
      have hRdid : did ≠ receiver := hdidR
      rw [Arena.find?_update_other _ receiver did _ hRdid]
      rw [Arena.find?_update_other _ caller did _ hCdid]
      simp [hdidC, hdidR]; rfl

theorem send_preserves_wellformed
    {s s' : SpecState} {caller : DomId} {receiver : DomId} {cap : MemCapId}
    (hwf : WellFormed s)
    (hstep : step s (.send caller receiver cap) s') :
    WellFormed s' := by
  cases hstep
  rename_i guard
  rcases hc : s.getMem cap with _ | c
  · exact absurd guard.capExists (by simp [hc])
  have hne := guard.notSelf
  have hCowner : c.owner = caller := guard.callerOwnsCap c hc
  -- For any did ≠ caller, any handle held by did has .2 ≠ cap.
  -- (HandleOwner gives owner = did; if .2 = cap, owner = caller; contradiction.)
  have notHoldsCap :
      ∀ did d, s.getDom did = some d → ∀ ph ∈ d.memHandles,
        did ≠ caller → ph.2 ≠ cap := by
    intro did d hd ph hph hdidC heq
    obtain ⟨cc, hccM, hcco⟩ := hwf.handleOwner did d hd ph hph
    rw [heq, hc] at hccM; cases hccM
    exact hdidC (hcco.symm.trans hCowner)
  -- Helper: bridging post and pre lookups when id ≠ cap.
  have getMem_pre_of_ne :
      ∀ id, id ≠ cap →
        (send_apply s caller receiver cap).getMem id = s.getMem id := by
    intro id hidC
    rw [send_apply_getMem, if_neg hidC]
  refine ⟨?unique, ?refs, ?cdtMono, ?cdtBidi, ?fresh, ?ho, ?pca⟩
  case unique =>
    refine ⟨?mc, ?dc, ?ds⟩
    case mc =>
      show ((send_apply s caller receiver cap).memcaps).UniqueKeys
      simp only [send_apply, SpecState.updMem, SpecState.updDomain]
      exact Arena.update_unique_keys _ _ _ hwf.unique.memcaps
    case dc =>
      show ((send_apply s caller receiver cap).domcaps).UniqueKeys
      simp [send_apply, SpecState.updMem, SpecState.updDomain]
      exact hwf.unique.domcaps
    case ds =>
      show ((send_apply s caller receiver cap).domains).UniqueKeys
      simp only [send_apply, SpecState.updMem, SpecState.updDomain]
      exact Arena.update_unique_keys _ _ _
              (Arena.update_unique_keys _ _ _ hwf.unique.domains)
  case refs =>
    refine ⟨?pia, ?cia, ?hia⟩
    case pia =>
      intro id c' hc' pid' hcpar
      -- Pre cap whose parent pointer is the same as c'.parent.
      have ⟨cpre, hcpre, hParent⟩ :
          ∃ cpre, s.getMem id = some cpre ∧ cpre.parent = c'.parent := by
        by_cases hidC : id = cap
        · subst hidC
          rw [send_apply_getMem, if_pos rfl, hc] at hc'
          refine ⟨c, hc, ?_⟩
          have : c' = { c with owner := receiver } := by
            simp at hc'; exact hc'.symm
          rw [this]
        · refine ⟨c', ?_, rfl⟩
          rw [← getMem_pre_of_ne id hidC]; exact hc'
      have hcparPre : cpre.parent = some pid' := hParent.trans hcpar
      have hsome := hwf.refs.parentInArena id cpre hcpre pid' hcparPre
      -- Post lookup at pid' is also isSome.
      rw [send_apply_getMem]
      by_cases hpidC : pid' = cap
      · rw [if_pos hpidC]
        rw [hpidC] at hsome
        rcases hh : s.getMem cap with _ | _
        · rw [hh] at hsome; simp at hsome
        · simp
      · rw [if_neg hpidC]; exact hsome
    case cia =>
      intro id c' hc' cid hcid
      have ⟨cpre, hcpre, hChildren⟩ :
          ∃ cpre, s.getMem id = some cpre ∧ cpre.childrenIds = c'.childrenIds := by
        by_cases hidC : id = cap
        · subst hidC
          rw [send_apply_getMem, if_pos rfl, hc] at hc'
          refine ⟨c, hc, ?_⟩
          have : c' = { c with owner := receiver } := by simp at hc'; exact hc'.symm
          rw [this]
        · refine ⟨c', ?_, rfl⟩
          rw [← getMem_pre_of_ne id hidC]; exact hc'
      have hcidPre : cid ∈ cpre.childrenIds := hChildren ▸ hcid
      have hsome := hwf.refs.childInArena id cpre hcpre cid hcidPre
      rw [send_apply_getMem]
      by_cases hcidC : cid = cap
      · rw [if_pos hcidC]
        rw [hcidC] at hsome
        rcases hh : s.getMem cap with _ | _
        · rw [hh] at hsome; simp at hsome
        · simp
      · rw [if_neg hcidC]; exact hsome
    case hia =>
      intro did d hd ph hph
      have hgetD := send_apply_getDom s caller receiver cap hne did
      simp only at hgetD
      -- Three cases for did.
      by_cases hdidC : did = caller
      · rw [hgetD, if_pos hdidC] at hd
        rcases hcp : s.getDom caller with _ | dcaller
        · rw [hcp] at hd; simp at hd
        rw [hcp] at hd; simp at hd
        rw [← hd] at hph; simp at hph
        have hphC : ph.2 ≠ cap := by simpa using hph.2
        rw [send_apply_getMem, if_neg hphC]
        exact hwf.refs.handleInArena caller dcaller hcp ph hph.1
      · by_cases hdidR : did = receiver
        · rw [hgetD, if_neg hdidC, if_pos hdidR] at hd
          rcases hrp : s.getDom receiver with _ | drecv
          · rw [hrp] at hd; simp at hd
          rw [hrp] at hd; simp at hd
          rw [← hd] at hph; simp at hph
          rcases hph with hph_in | hph_new
          · -- Old handle: by HO on receiver, ph.2 ≠ cap.
            have hphC : ph.2 ≠ cap :=
              notHoldsCap receiver drecv hrp ph hph_in hne.symm
            rw [send_apply_getMem, if_neg hphC]
            exact hwf.refs.handleInArena receiver drecv hrp ph hph_in
          · -- New (nh, cap) handle: ph.2 = cap, post.getMem cap = some updC.
            rw [send_apply_getMem]
            have hpheq : ph.2 = cap := by rw [hph_new]
            rw [if_pos hpheq, hc]; simp
        · rw [hgetD, if_neg hdidC, if_neg hdidR] at hd
          have hpre := hwf.refs.handleInArena did d hd ph hph
          have hphC : ph.2 ≠ cap := notHoldsCap did d hd ph hph hdidC
          rw [send_apply_getMem, if_neg hphC]; exact hpre
  case cdtMono =>
    intro id c' hc' cid hcid ch hch
    -- Reduce both to pre-state.
    have ⟨cpre, hcpre, hRegion, hChildren⟩ :
        ∃ cpre, s.getMem id = some cpre ∧
          cpre.region = c'.region ∧ cpre.childrenIds = c'.childrenIds := by
      by_cases hidC : id = cap
      · subst hidC
        rw [send_apply_getMem, if_pos rfl, hc] at hc'
        have hceq : c' = { c with owner := receiver } := by
          simp at hc'; exact hc'.symm
        refine ⟨c, hc, ?_, ?_⟩
        · rw [hceq]
        · rw [hceq]
      · refine ⟨c', ?_, rfl, rfl⟩
        rw [← getMem_pre_of_ne id hidC]; exact hc'
    have ⟨chpre, hchpre, hChRegion⟩ :
        ∃ chpre, s.getMem cid = some chpre ∧ chpre.region = ch.region := by
      by_cases hcidC : cid = cap
      · subst hcidC
        rw [send_apply_getMem, if_pos rfl, hc] at hch
        refine ⟨c, hc, ?_⟩
        have : ch = { c with owner := receiver } := by simp at hch; exact hch.symm
        rw [this]
      · refine ⟨ch, ?_, rfl⟩
        rw [← getMem_pre_of_ne cid hcidC]; exact hch
    have hcidPre : cid ∈ cpre.childrenIds := hChildren ▸ hcid
    have := hwf.cdtMonotonic id cpre hcpre cid hcidPre chpre hchpre
    rw [hChRegion, hRegion] at this; exact this
  case cdtBidi =>
    intro id c' hc' cid hcid ch hch
    have ⟨cpre, hcpre, hChildren⟩ :
        ∃ cpre, s.getMem id = some cpre ∧ cpre.childrenIds = c'.childrenIds := by
      by_cases hidC : id = cap
      · subst hidC
        rw [send_apply_getMem, if_pos rfl, hc] at hc'
        refine ⟨c, hc, ?_⟩
        have : c' = { c with owner := receiver } := by simp at hc'; exact hc'.symm
        rw [this]
      · refine ⟨c', ?_, rfl⟩
        rw [← getMem_pre_of_ne id hidC]; exact hc'
    have ⟨chpre, hchpre, hChParent⟩ :
        ∃ chpre, s.getMem cid = some chpre ∧ chpre.parent = ch.parent := by
      by_cases hcidC : cid = cap
      · subst hcidC
        rw [send_apply_getMem, if_pos rfl, hc] at hch
        refine ⟨c, hc, ?_⟩
        have : ch = { c with owner := receiver } := by simp at hch; exact hch.symm
        rw [this]
      · refine ⟨ch, ?_, rfl⟩
        rw [← getMem_pre_of_ne cid hcidC]; exact hch
    have hcidPre : cid ∈ cpre.childrenIds := hChildren ▸ hcid
    have := hwf.cdtBidirectional id cpre hcpre cid hcidPre chpre hchpre
    rw [hChParent] at this; exact this
  case fresh =>
    intro id hid
    have hKeys : id ∈ s.memcaps.keys := by
      have heq : ((send_apply s caller receiver cap).memcaps).keys
                  = s.memcaps.keys := by
        simp only [send_apply, SpecState.updMem, SpecState.updDomain,
                   Arena.keys_update]
      rw [heq] at hid; exact hid
    have hnext : ((send_apply s caller receiver cap).nextMemCapId)
                  = s.nextMemCapId := by
      simp [send_apply, SpecState.updMem, SpecState.updDomain]
    rw [hnext]; exact hwf.freshMemCounter id hKeys
  case ho =>
    intro did d hd ph hph
    have hgetD := send_apply_getDom s caller receiver cap hne did
    simp only at hgetD
    by_cases hdidC : did = caller
    · rw [hgetD, if_pos hdidC] at hd
      rcases hcp : s.getDom caller with _ | dcaller
      · rw [hcp] at hd; simp at hd
      rw [hcp] at hd; simp at hd
      rw [← hd] at hph; simp at hph
      have hphC : ph.2 ≠ cap := by simpa using hph.2
      obtain ⟨cc, hccM, hcco⟩ := hwf.handleOwner caller dcaller hcp ph hph.1
      refine ⟨cc, ?_, ?_⟩
      · rw [send_apply_getMem, if_neg hphC]; exact hccM
      · rw [hdidC]; exact hcco
    · by_cases hdidR : did = receiver
      · rw [hgetD, if_neg hdidC, if_pos hdidR] at hd
        rcases hrp : s.getDom receiver with _ | drecv
        · rw [hrp] at hd; simp at hd
        rw [hrp] at hd; simp at hd
        rw [← hd] at hph; simp at hph
        rcases hph with hph_in | hph_new
        · have hphC : ph.2 ≠ cap :=
            notHoldsCap receiver drecv hrp ph hph_in hne.symm
          obtain ⟨cc, hccM, hcco⟩ :=
            hwf.handleOwner receiver drecv hrp ph hph_in
          refine ⟨cc, ?_, ?_⟩
          · rw [send_apply_getMem, if_neg hphC]; exact hccM
          · rw [hdidR]; exact hcco
        · refine ⟨{ c with owner := receiver }, ?_, ?_⟩
          · rw [send_apply_getMem]
            have hpheq : ph.2 = cap := by rw [hph_new]
            rw [if_pos hpheq, hc]; rfl
          · rw [hdidR]
      · rw [hgetD, if_neg hdidC, if_neg hdidR] at hd
        have hphC : ph.2 ≠ cap := notHoldsCap did d hd ph hph hdidC
        obtain ⟨cc, hccM, hcco⟩ := hwf.handleOwner did d hd ph hph
        refine ⟨cc, ?_, ?_⟩
        · rw [send_apply_getMem, if_neg hphC]; exact hccM
        · exact hcco
  case pca =>
    intro id c' hc' pid' hcpar pp hpp
    -- Reduce to pre.
    have ⟨cpre, hcpre, hParent⟩ :
        ∃ cpre, s.getMem id = some cpre ∧ cpre.parent = c'.parent := by
      by_cases hidC : id = cap
      · subst hidC
        rw [send_apply_getMem, if_pos rfl, hc] at hc'
        refine ⟨c, hc, ?_⟩
        have : c' = { c with owner := receiver } := by simp at hc'; exact hc'.symm
        rw [this]
      · refine ⟨c', ?_, rfl⟩
        rw [← getMem_pre_of_ne id hidC]; exact hc'
    have ⟨ppre, hppre, hPpChildren⟩ :
        ∃ ppre, s.getMem pid' = some ppre ∧ ppre.childrenIds = pp.childrenIds := by
      by_cases hpidC : pid' = cap
      · subst hpidC
        rw [send_apply_getMem, if_pos rfl, hc] at hpp
        refine ⟨c, hc, ?_⟩
        have : pp = { c with owner := receiver } := by simp at hpp; exact hpp.symm
        rw [this]
      · refine ⟨pp, ?_, rfl⟩
        rw [← getMem_pre_of_ne pid' hpidC]; exact hpp
    have hcparPre : cpre.parent = some pid' := hParent.trans hcpar
    have := hwf.parentChild id cpre hcpre pid' hcparPre ppre hppre
    rw [hPpChildren] at this; exact this

end ThemisCapa

