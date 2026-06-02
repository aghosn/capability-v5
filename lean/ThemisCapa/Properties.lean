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

/-! ### Helpers for domain-side fresh counters

Every operation in the current vertical slice (carve, alias, revoke,
send, seal, accept, reject, sealedSend) leaves `nextDomId`,
`nextDomCapId`, `domains.keys`, and `domcaps.keys` unchanged. The
following helpers discharge `FreshDomCounter` and `FreshDomCapCounter`
preservation from those facts, avoiding boilerplate in every proof. -/

private theorem freshDomCounter_of_keys_eq
    {s s' : SpecState} (hwf : WellFormed s)
    (hKeys : s'.domains.keys = s.domains.keys)
    (hNext : s'.nextDomId = s.nextDomId) :
    FreshDomCounter s' := by
  intro id hid
  rw [hKeys] at hid
  rw [hNext]
  exact hwf.freshDomCounter id hid

private theorem freshDomCapCounter_of_keys_eq
    {s s' : SpecState} (hwf : WellFormed s)
    (hKeys : s'.domcaps.keys = s.domcaps.keys)
    (hNext : s'.nextDomCapId = s.nextDomCapId) :
    FreshDomCapCounter s' := by
  intro id hid
  rw [hKeys] at hid
  rw [hNext]
  exact hwf.freshDomCapCounter id hid

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
theorem existing_lt_fresh (s : SpecState) (hfc : FreshMemCounter s)
    {k : MemCapId} {v : MemCap} (h : s.getMem k = some v) :
    k < s.nextMemCapId :=
  hfc _ (Arena.mem_keys_of_find?_some _ _ _ h)

/-- 3-way characterization of `s'.getMem` after `carve_apply`. -/
theorem carve_apply_getMem
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
  refine ⟨?unique, ?refs, ?cdtMono, ?cdtBidi, ?fresh, ?ho, ?pca, ?fDom, ?fDomCap⟩
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
  case fDom =>
    apply freshDomCounter_of_keys_eq hwf <;>
      simp only [carve_apply, hpOpt, SpecState.freshMem, SpecState.updMem,
                 SpecState.updDomain, Arena.keys_update]
  case fDomCap =>
    apply freshDomCapCounter_of_keys_eq hwf <;>
      simp only [carve_apply, hpOpt, SpecState.freshMem, SpecState.updMem,
                 SpecState.updDomain]

/-! ## Alias

The alias proofs mirror `carve` exactly: same post-state shape (insert fresh
child, update parent children list, append a handle to the caller).  Only
the child's `region.kind`/`region.status`/`attributes` differ, and none of
these fields participate in any invariant.  The characterization lemma and
its 3-way case split are therefore identical in structure. -/

/-- 3-way characterization of `s'.getMem` after `alias_apply`. -/
theorem alias_apply_getMem
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
  refine ⟨?unique, ?refs, ?cdtMono, ?cdtBidi, ?fresh, ?ho, ?pca, ?fDom, ?fDomCap⟩
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
  case fDom =>
    apply freshDomCounter_of_keys_eq hwf <;>
      simp only [alias_apply, hpOpt, SpecState.freshMem, SpecState.updMem,
                 SpecState.updDomain, Arena.keys_update]
  case fDomCap =>
    apply freshDomCapCounter_of_keys_eq hwf <;>
      simp only [alias_apply, hpOpt, SpecState.freshMem, SpecState.updMem,
                 SpecState.updDomain]

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

theorem revoke_apply_getMem
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
  let f : MemCap → MemCap := fun q =>
    { q with childrenIds := q.childrenIds.filter (· ≠ target) }
  -- Reduce `(revoke_apply ...).memcaps` to a fixed expression independent of `vital`.
  have hredm : (revoke_apply s caller target).memcaps =
      (s.memcaps.remove target).update pid f := by
    simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
    by_cases hv : t.region.attributes.vital
    · simp only [if_pos hv]; rfl
    · simp only [if_neg hv]; rfl
  rw [hredm]
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

theorem revoke_apply_getDom
    (s : SpecState) (caller : DomId) (target : MemCapId)
    (t : MemCap) (ht : s.getMem target = some t)
    (pid : MemCapId) (htp : t.parent = some pid)
    (did : DomId) :
    let fupd : Domain → Domain := fun d =>
      { d with
        memHandles := d.memHandles.filter (fun h => h.2 ≠ target),
        status := if t.region.attributes.vital then .revoked else d.status }
    (revoke_apply s caller target).getDom did =
      if did = t.owner then (s.getDom t.owner).map fupd
      else s.getDom did := by
  show ((revoke_apply s caller target).domains).find? did = _
  simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
  by_cases hdid : did = t.owner
  · subst hdid
    by_cases hv : t.region.attributes.vital
    · simp only [if_pos hv]
      rw [Arena.find?_update_eq_map, Arena.find?_update_eq_map]
      simp only [SpecState.getDom, Option.map_map]
      congr 1
    · simp only [if_neg hv]
      rw [Arena.find?_update_eq_map]
      simp only [SpecState.getDom]
      rcases hod : s.domains.find? t.owner with _ | dpre
      · rfl
      · simp only [Option.map_some]
        congr 1
  · by_cases hv : t.region.attributes.vital
    · simp only [if_pos hv, SpecState.updDomain]
      rw [Arena.find?_update_other _ t.owner did _ hdid,
          Arena.find?_update_other _ t.owner did _ hdid]
      simp [hdid]; rfl
    · simp only [if_neg hv, SpecState.updDomain]
      rw [Arena.find?_update_other _ t.owner did _ hdid]
      simp [hdid]; rfl

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
  -- Reduce the three arena fields of `revoke_apply` to forms that
  -- don't mention the vital case-split. Defined before `refine` so
  -- they are in scope of all sub-goals.
  have hMemcapsEq : (revoke_apply s caller target).memcaps =
      (s.memcaps.remove target).update pid
        (fun p => { p with childrenIds := p.childrenIds.filter (· ≠ target) }) := by
    simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
    by_cases hv : t.region.attributes.vital <;> simp [hv]
  have hDomcapsEq : (revoke_apply s caller target).domcaps = s.domcaps := by
    simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
    by_cases hv : t.region.attributes.vital <;> simp [hv]
  have hDomsUnique : (revoke_apply s caller target).domains.UniqueKeys := by
    simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
    by_cases hv : t.region.attributes.vital
    · simp only [if_pos hv]
      exact Arena.update_unique_keys _ _ _
              (Arena.update_unique_keys _ _ _ hwf.unique.domains)
    · simp only [if_neg hv]
      exact Arena.update_unique_keys _ _ _ hwf.unique.domains
  refine ⟨?unique, ?refs, ?cdtMono, ?cdtBidi, ?fresh, ?ho, ?pca, ?fDom, ?fDomCap⟩
  case unique =>
    refine ⟨?mc, ?dc, ?ds⟩
    case mc =>
      rw [show ((revoke_apply s caller target).memcaps) = _ from hMemcapsEq]
      exact Arena.update_unique_keys _ pid _
        (Arena.remove_unique_keys _ target hwf.unique.memcaps)
    case dc =>
      rw [show ((revoke_apply s caller target).domcaps) = _ from hDomcapsEq]
      exact hwf.unique.domcaps
    case ds =>
      exact hDomsUnique
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
        rw [hMemcapsEq]; exact Arena.keys_update _ _ _
      rw [heq] at hid
      exact ((Arena.mem_keys_remove_iff _ _ _).mp hid).2
    have : ((revoke_apply s caller target).nextMemCapId) = s.nextMemCapId := by
      simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
      by_cases hv : t.region.attributes.vital <;> simp [hv]
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
  case fDom =>
    apply freshDomCounter_of_keys_eq hwf
    · simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
      by_cases hv : t.region.attributes.vital
      · simp only [if_pos hv, Arena.keys_update]
      · simp only [if_neg hv, Arena.keys_update]
    · simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
      by_cases hv : t.region.attributes.vital <;> simp [hv]
  case fDomCap =>
    apply freshDomCapCounter_of_keys_eq hwf
    · simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
      by_cases hv : t.region.attributes.vital <;> simp [hv]
    · simp only [revoke_apply, ht, htp, SpecState.updMem, SpecState.updDomain]
      by_cases hv : t.region.attributes.vital <;> simp [hv]

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
theorem send_apply_getMem
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

/-- Raw-hypothesis version of `send_preserves_wellformed`. Drops the
    policy fields (`callerSealed`, `hasPermission`, `notMeta`) of
    `SendGuard` which were never used in the WF preservation proof:
    only `capExists`, `notSelf`, and `callerOwnsCap` are needed. This
    is the lemma used by `accept_preserves_wellformed` so that
    `AcceptGuard` doesn't have to carry policy fields. -/
theorem send_apply_preserves_wellformed
    {s : SpecState} {caller : DomId} {receiver : DomId} {cap : MemCapId}
    (hwf : WellFormed s)
    (hcapExists : (s.getMem cap).isSome)
    (hne : caller ≠ receiver)
    (hown : ∀ c, s.getMem cap = some c → c.owner = caller) :
    WellFormed (send_apply s caller receiver cap) := by
  rcases hc : s.getMem cap with _ | c
  · exact absurd hcapExists (by simp [hc])
  have hCowner : c.owner = caller := hown c hc
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
  refine ⟨?unique, ?refs, ?cdtMono, ?cdtBidi, ?fresh, ?ho, ?pca, ?fDom, ?fDomCap⟩
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
  case fDom =>
    apply freshDomCounter_of_keys_eq hwf <;>
      simp only [send_apply, SpecState.updMem, SpecState.updDomain,
                 Arena.keys_update]
  case fDomCap =>
    apply freshDomCapCounter_of_keys_eq hwf <;>
      simp only [send_apply, SpecState.updMem, SpecState.updDomain]

/-- Thin wrapper: `send_preserves_wellformed` discharges WF preservation
    for the labelled step by forwarding to `send_apply_preserves_wellformed`.
    The `SendGuard` provides exactly the three raw hypotheses needed. -/
theorem send_preserves_wellformed
    {s s' : SpecState} {caller : DomId} {receiver : DomId} {cap : MemCapId}
    (hwf : WellFormed s)
    (hstep : step s (.send caller receiver cap) s') :
    WellFormed s' := by
  cases hstep
  rename_i guard
  exact send_apply_preserves_wellformed hwf
          guard.capExists guard.notSelf guard.callerOwnsCap

/-! ### Seal preserves WellFormed

Seal mutates only one field of one domain (`status`). Memory caps and
the handle lists are completely untouched, so every reference-class
invariant reduces to its pre-state counterpart. -/

theorem seal_apply_getMem (s : SpecState) (caller : DomId) (cap : DomCapId)
    (id : MemCapId) :
    (seal_apply s caller cap).getMem id = s.getMem id := by
  unfold seal_apply
  rcases s.getDomCap cap with _ | dc
  · rfl
  · simp [SpecState.getMem, SpecState.updDomain]

theorem seal_apply_getDom (s : SpecState) (caller : DomId) (cap : DomCapId)
    (dc : DomCap) (hdc : s.getDomCap cap = some dc) (did : DomId) :
    (seal_apply s caller cap).getDom did =
      (if did = dc.targetDom then
        (s.getDom did).map (fun d => { d with status := .sealed })
       else s.getDom did) := by
  show ((seal_apply s caller cap).domains).find? did = _
  unfold seal_apply
  rw [hdc]
  simp only [SpecState.updDomain]
  by_cases h : did = dc.targetDom
  · subst h
    rw [Arena.find?_update_eq_map]
    simp; rfl
  · rw [Arena.find?_update_other _ _ _ _ h]
    rw [if_neg h]; rfl

theorem seal_preserves_wellformed
    {s s' : SpecState} {caller : DomId} {cap : DomCapId}
    (hwf : WellFormed s)
    (hstep : step s (.seal caller cap) s') :
    WellFormed s' := by
  cases hstep
  rename_i guard
  rcases hdc : s.getDomCap cap with _ | dc
  · exact absurd guard.capExists (by simp [hdc])
  -- Post-state lookups: memcaps unchanged; domains differ only at targetDom.
  have hMemEq : ∀ id, (seal_apply s caller cap).getMem id = s.getMem id :=
    seal_apply_getMem s caller cap
  have hDomEq := seal_apply_getDom s caller cap dc hdc
  -- Key fact for HandleOwner / handleInArena: only `status` changes on
  -- targetDom; `memHandles` are identical.
  have hHandles : ∀ did d',
      (seal_apply s caller cap).getDom did = some d' →
      ∃ d, s.getDom did = some d ∧ d.memHandles = d'.memHandles := by
    intro did d' hd'
    rw [hDomEq] at hd'
    by_cases h : did = dc.targetDom
    · rw [if_pos h] at hd'
      rcases hpre : s.getDom did with _ | dpre
      · rw [hpre] at hd'; cases hd'
      · rw [hpre] at hd'
        simp only [Option.map_some, Option.some.injEq] at hd'
        exact ⟨dpre, rfl, by rw [← hd']⟩
    · rw [if_neg h] at hd'
      exact ⟨d', hd', rfl⟩
  refine ⟨?unique, ?refs, ?cdtMono, ?cdtBidi, ?fresh, ?ho, ?pca, ?fDom, ?fDomCap⟩
  case unique =>
    refine ⟨?mc, ?dc, ?ds⟩
    case mc =>
      show ((seal_apply s caller cap).memcaps).UniqueKeys
      unfold seal_apply; rw [hdc]
      simp [SpecState.updDomain]
      exact hwf.unique.memcaps
    case dc =>
      show ((seal_apply s caller cap).domcaps).UniqueKeys
      unfold seal_apply; rw [hdc]
      simp [SpecState.updDomain]
      exact hwf.unique.domcaps
    case ds =>
      show ((seal_apply s caller cap).domains).UniqueKeys
      unfold seal_apply; rw [hdc]
      simp only [SpecState.updDomain]
      exact Arena.update_unique_keys _ _ _ hwf.unique.domains
  case refs =>
    refine ⟨?pia, ?cia, ?hia⟩
    case pia =>
      intro id c' hc' pid' hcpar
      rw [hMemEq] at hc'
      have := hwf.refs.parentInArena id c' hc' pid' hcpar
      rw [hMemEq]; exact this
    case cia =>
      intro id c' hc' cid hcid
      rw [hMemEq] at hc'
      have := hwf.refs.childInArena id c' hc' cid hcid
      rw [hMemEq]; exact this
    case hia =>
      intro did d' hd' ph hph
      obtain ⟨d, hd, hHeq⟩ := hHandles did d' hd'
      rw [← hHeq] at hph
      have := hwf.refs.handleInArena did d hd ph hph
      rw [hMemEq]; exact this
  case cdtMono =>
    intro id c' hc' cid hcid ch hch
    rw [hMemEq] at hc' hch
    exact hwf.cdtMonotonic id c' hc' cid hcid ch hch
  case cdtBidi =>
    intro id c' hc' cid hcid ch hch
    rw [hMemEq] at hc' hch
    exact hwf.cdtBidirectional id c' hc' cid hcid ch hch
  case fresh =>
    intro id hid
    have hKeys : id ∈ s.memcaps.keys := by
      have heq : ((seal_apply s caller cap).memcaps).keys
                  = s.memcaps.keys := by
        unfold seal_apply; rw [hdc]
        simp [SpecState.updDomain]
      rw [heq] at hid; exact hid
    have hnext : ((seal_apply s caller cap).nextMemCapId)
                  = s.nextMemCapId := by
      unfold seal_apply; rw [hdc]
      simp [SpecState.updDomain]
    rw [hnext]; exact hwf.freshMemCounter id hKeys
  case ho =>
    intro did d' hd' ph hph
    obtain ⟨d, hd, hHeq⟩ := hHandles did d' hd'
    rw [← hHeq] at hph
    obtain ⟨cc, hccM, hcco⟩ := hwf.handleOwner did d hd ph hph
    refine ⟨cc, ?_, hcco⟩
    rw [hMemEq]; exact hccM
  case pca =>
    intro id c' hc' pid' hcpar pp hpp
    rw [hMemEq] at hc' hpp
    exact hwf.parentChild id c' hc' pid' hcpar pp hpp
  case fDom =>
    apply freshDomCounter_of_keys_eq hwf <;>
      simp only [seal_apply, hdc, SpecState.updDomain, Arena.keys_update]
  case fDomCap =>
    apply freshDomCapCounter_of_keys_eq hwf <;>
      simp only [seal_apply, hdc, SpecState.updDomain]

/-! ### Reject / Accept preserve WellFormed -/

/-- Reusable helper: any `updDomain` that doesn't touch `memHandles`
    preserves every `WellFormed` invariant. `pendingMemCaps`,
    `frozenHandles`, `addressMap`, etc. are outside `WellFormed`, so
    `f` may freely permute them. -/
private theorem wf_preserved_under_handle_invariant_updDomain
    {s : SpecState} (hwf : WellFormed s)
    (did : DomId) (f : Domain → Domain)
    (hHandles : ∀ d, (f d).memHandles = d.memHandles) :
    WellFormed (s.updDomain did f) := by
  have hMem : ∀ id, (s.updDomain did f).getMem id = s.getMem id := by
    intro id; rfl
  have hHandlesBridge : ∀ did' d',
      (s.updDomain did f).getDom did' = some d' →
      ∃ d, s.getDom did' = some d ∧ d.memHandles = d'.memHandles := by
    intro did' d' hd'
    by_cases h : did = did'
    · subst h
      have : (s.updDomain did f).getDom did = (s.getDom did).map f := by
        change ((s.domains.update did f)).find? did = _
        rw [Arena.find?_update_eq_map]; rfl
      rw [this] at hd'
      rcases hpre : s.getDom did with _ | dpre
      · rw [hpre] at hd'; cases hd'
      · rw [hpre] at hd'
        simp only [Option.map_some, Option.some.injEq] at hd'
        refine ⟨dpre, rfl, ?_⟩
        rw [← hd', hHandles]
    · have hne : did' ≠ did := fun heq => h heq.symm
      have : (s.updDomain did f).getDom did' = s.getDom did' := by
        change ((s.domains.update did f)).find? did' = _
        exact Arena.find?_update_other _ _ _ _ hne
      rw [this] at hd'
      exact ⟨d', hd', rfl⟩
  refine ⟨?u, ?r, ?cm, ?cb, ?fr, ?ho, ?pca, ?fDom, ?fDomCap⟩
  case u =>
    refine ⟨hwf.unique.memcaps, hwf.unique.domcaps, ?_⟩
    show ((s.updDomain did f).domains).UniqueKeys
    simp only [SpecState.updDomain]
    exact Arena.update_unique_keys _ _ _ hwf.unique.domains
  case r =>
    refine ⟨?pia, ?cia, ?hia⟩
    case pia =>
      intro id c' hc' pid' hcpar
      rw [hMem] at hc'
      rw [hMem]; exact hwf.refs.parentInArena id c' hc' pid' hcpar
    case cia =>
      intro id c' hc' cid hcid
      rw [hMem] at hc'
      rw [hMem]; exact hwf.refs.childInArena id c' hc' cid hcid
    case hia =>
      intro did' d' hd' ph hph
      obtain ⟨d, hd, hHeq⟩ := hHandlesBridge did' d' hd'
      rw [← hHeq] at hph
      rw [hMem]; exact hwf.refs.handleInArena did' d hd ph hph
  case cm =>
    intro id c' hc' cid hcid ch hch
    rw [hMem] at hc' hch
    exact hwf.cdtMonotonic id c' hc' cid hcid ch hch
  case cb =>
    intro id c' hc' cid hcid ch hch
    rw [hMem] at hc' hch
    exact hwf.cdtBidirectional id c' hc' cid hcid ch hch
  case fr =>
    intro id hid
    show id < (s.updDomain did f).nextMemCapId
    have heqKeys : ((s.updDomain did f).memcaps).keys = s.memcaps.keys := rfl
    rw [heqKeys] at hid
    exact hwf.freshMemCounter id hid
  case ho =>
    intro did' d' hd' ph hph
    obtain ⟨d, hd, hHeq⟩ := hHandlesBridge did' d' hd'
    rw [← hHeq] at hph
    obtain ⟨cc, hccM, hcco⟩ := hwf.handleOwner did' d hd ph hph
    refine ⟨cc, ?_, hcco⟩
    rw [hMem]; exact hccM
  case pca =>
    intro id c' hc' pid' hcpar pp hpp
    rw [hMem] at hc' hpp
    exact hwf.parentChild id c' hc' pid' hcpar pp hpp
  case fDom =>
    apply freshDomCounter_of_keys_eq hwf <;>
      simp only [SpecState.updDomain, Arena.keys_update]
  case fDomCap =>
    apply freshDomCapCounter_of_keys_eq hwf <;>
      simp only [SpecState.updDomain]

theorem reject_preserves_wellformed
    {s s' : SpecState} {receiver : DomId} {pendingId : PendingId}
    (hwf : WellFormed s)
    (hstep : step s (.reject receiver pendingId) s') :
    WellFormed s' := by
  cases hstep
  unfold reject_apply
  have hwf₁ : WellFormed (s.updDomain receiver
      (fun d => { d with pendingMemCaps :=
                          d.pendingMemCaps.filter (fun p => p.1 ≠ pendingId) })) :=
    wf_preserved_under_handle_invariant_updDomain hwf receiver _ (fun _ => rfl)
  rcases h : (s.getDom receiver).bind (fun d => d.lookupPending pendingId)
    with _ | pe
  · simp only [h]; exact hwf₁
  · simp only [h]
    exact wf_preserved_under_handle_invariant_updDomain hwf₁
            pe.senderDomainId _ (fun _ => rfl)

theorem accept_preserves_wellformed
    {s s' : SpecState} {receiver : DomId} {pendingId : PendingId}
    (hwf : WellFormed s)
    (hstep : step s (.accept receiver pendingId) s') :
    WellFormed s' := by
  cases hstep
  rename_i guard
  unfold accept_apply
  rcases hb : (s.getDom receiver).bind (fun d => d.lookupPending pendingId)
    with _ | pe
  · simp only [hb]; exact hwf
  ·
    -- Recover receiver lookup and pending lookup from the bind.
    rcases hrd : s.getDom receiver with _ | d
    · rw [hrd] at hb; simp at hb
    have hpe : d.lookupPending pendingId = some pe := by
      rw [hrd, Option.bind_some] at hb; exact hb
    have hwfSend : WellFormed (send_apply s pe.senderDomainId receiver pe.capId) :=
      send_apply_preserves_wellformed hwf
        (guard.capExists d pe hrd hpe)
        (guard.notSelf d pe hrd hpe)
        (fun c hc => guard.capOwnedBySender d pe hrd hpe c hc)
    have hwf₂ : WellFormed
        ((send_apply s pe.senderDomainId receiver pe.capId).updDomain receiver
          (fun d' => { d' with pendingMemCaps :=
                              d'.pendingMemCaps.filter (fun p => p.1 ≠ pendingId) })) :=
      wf_preserved_under_handle_invariant_updDomain hwfSend
        receiver _ (fun _ => rfl)
    exact wf_preserved_under_handle_invariant_updDomain hwf₂
                    pe.senderDomainId
                    (fun d' => { d' with frozenHandles :=
                              d'.frozenHandles.filter (fun fh => fh ≠ pe.senderHandle) })
                    (fun _ => rfl)

/-! ### Sealed send preserves WellFormed -/

theorem sealedSend_preserves_wellformed
    {s s' : SpecState} {caller receiver : DomId} {handle : LocalHandle}
    {gpaHint : Option Nat}
    (hwf : WellFormed s)
    (hstep : step s (.sealedSend caller receiver handle gpaHint) s') :
    WellFormed s' := by
  cases hstep
  unfold sealedSend_apply
  rcases hb : (s.getDom caller).bind (fun d => d.lookupMemHandle handle)
    with _ | capId
  · exact hwf
  · -- Step 1: freeze handle on caller.
    have hwf₁ : WellFormed (s.updDomain caller
        (fun d => { d with frozenHandles := d.frozenHandles ++ [handle] })) :=
      wf_preserved_under_handle_invariant_updDomain hwf caller _ (fun _ => rfl)
    -- Step 2: enqueue pending entry on receiver.
    exact wf_preserved_under_handle_invariant_updDomain hwf₁ receiver _
            (fun _ => rfl)

/-! ### Create preserves WellFormed

Allocates a new domain and a new dom-cap, plus updates caller's
`domHandles`/`childrenDoms`. Memcaps are entirely untouched, so the
seven memcap-side invariants reduce to their pre-state via
`getMem` equality. The two interesting cases are:

* `unique.domains` and `unique.domcaps`: the fresh inserts go at keys
  `s.nextDomId` and `s.nextDomCapId`, which by `FreshDomCounter` /
  `FreshDomCapCounter` are not in the respective key sets.
* `freshDomCounter` and `freshDomCapCounter`: the new keys are
  `< nextDomId + 1` and `< nextDomCapId + 1`; existing keys satisfied
  by pre-state freshness.

`handleInArena` and `handleOwner` for the new domain are trivial
(its `memHandles = []`); for caller they reduce to the pre-state
because we only modified `domHandles` / `childrenDoms` / `nextHandle`,
not `memHandles`. -/

theorem create_preserves_wellformed
    {s s' : SpecState} {caller : DomId} {policy : DomainPolicy}
    (hwf : WellFormed s)
    (hstep : step s (.create caller policy) s') :
    WellFormed s' := by
  cases hstep
  rename_i guard
  -- Caller exists, so caller ∈ s.domains.keys, so caller < s.nextDomId.
  obtain ⟨dcaller, hdcaller⟩ := Option.isSome_iff_exists.mp guard.callerExists
  have hcallerLt : caller < s.nextDomId :=
    hwf.freshDomCounter _ (Arena.mem_keys_of_find?_some _ _ _ hdcaller)
  have hcallerNeFresh : caller ≠ s.nextDomId := Nat.ne_of_lt hcallerLt
  -- Memcaps lookup unchanged.
  have hMemEq : ∀ id, (create_apply s caller policy).getMem id = s.getMem id := by
    intro id; rfl
  -- Convenience: name the new domain and the new dom-cap.
  let newDom : Domain := freshChildDomain caller policy
  let newCap : DomCap := { parent := none, owner := caller,
                           targetDom := s.nextDomId }
  -- Characterization of `getDom`.
  have hDomEq : ∀ id, (create_apply s caller policy).getDom id =
      (if id = s.nextDomId then some newDom
       else if id = caller then
         (s.getDom id).map (fun d =>
           { d with domHandles   := d.domHandles ++
                                      [(d.nextHandle, s.nextDomCapId)],
                    nextHandle   := d.nextHandle + 1,
                    childrenDoms := d.childrenDoms ++ [s.nextDomId] })
       else s.getDom id) := by
    intro id
    show ((create_apply s caller policy).domains).find? id = _
    simp only [create_apply, SpecState.freshDom, SpecState.freshDomCap,
               SpecState.updDomain]
    by_cases h1 : id = caller
    · rw [h1]
      have hneFreshC : caller ≠ s.nextDomId := hcallerNeFresh
      rw [Arena.find?_update_eq_map,
          Arena.find?_insert_other _ _ _ _ hneFreshC]
      have hnotFreshEqCaller : ¬ caller = s.nextDomId := hneFreshC
      rw [if_neg hnotFreshEqCaller, if_pos rfl]
      rfl
    · rw [Arena.find?_update_other _ _ _ _ h1]
      by_cases h2 : id = s.nextDomId
      · rw [h2, Arena.find?_insert_same]
        rw [if_pos rfl]
      · rw [Arena.find?_insert_other _ _ _ _ h2]
        rw [if_neg h2, if_neg h1]; rfl
  -- Characterization of `getDomCap`.
  have hDomCapEq : ∀ id, (create_apply s caller policy).getDomCap id =
      (if id = s.nextDomCapId then some newCap else s.getDomCap id) := by
    intro id
    show ((create_apply s caller policy).domcaps).find? id = _
    simp only [create_apply, SpecState.freshDom, SpecState.freshDomCap,
               SpecState.updDomain]
    by_cases h : id = s.nextDomCapId
    · rw [h, Arena.find?_insert_same, if_pos rfl]
    · rw [Arena.find?_insert_other _ _ _ _ h, if_neg h]; rfl
  -- Counters.
  have hNextMem : (create_apply s caller policy).nextMemCapId = s.nextMemCapId := rfl
  have hNextDom : (create_apply s caller policy).nextDomId = s.nextDomId + 1 := rfl
  have hNextDomCap :
      (create_apply s caller policy).nextDomCapId = s.nextDomCapId + 1 := rfl
  refine ⟨?unique, ?refs, ?cdtMono, ?cdtBidi, ?fresh, ?ho, ?pca, ?fDom, ?fDomCap⟩
  case unique =>
    refine ⟨?mc, ?dc, ?ds⟩
    case mc =>
      show ((create_apply s caller policy).memcaps).UniqueKeys
      exact hwf.unique.memcaps
    case dc =>
      show ((create_apply s caller policy).domcaps).UniqueKeys
      simp only [create_apply, SpecState.freshDom, SpecState.freshDomCap,
                 SpecState.updDomain]
      apply Arena.insert_unique_keys _ _ _ hwf.unique.domcaps
      intro hin
      exact Nat.lt_irrefl _ (hwf.freshDomCapCounter _ hin)
    case ds =>
      show ((create_apply s caller policy).domains).UniqueKeys
      simp only [create_apply, SpecState.freshDom, SpecState.freshDomCap,
                 SpecState.updDomain]
      apply Arena.update_unique_keys
      apply Arena.insert_unique_keys _ _ _ hwf.unique.domains
      intro hin
      exact Nat.lt_irrefl _ (hwf.freshDomCounter _ hin)
  case refs =>
    refine ⟨?pia, ?cia, ?hia⟩
    case pia =>
      intro id c hc pid hcpar
      rw [hMemEq] at hc; rw [hMemEq]
      exact hwf.refs.parentInArena id c hc pid hcpar
    case cia =>
      intro id c hc cid hcid
      rw [hMemEq] at hc; rw [hMemEq]
      exact hwf.refs.childInArena id c hc cid hcid
    case hia =>
      intro did d hd p hp
      rw [hMemEq]
      rw [hDomEq] at hd
      by_cases h1 : did = s.nextDomId
      · rw [if_pos h1] at hd
        -- hd : some (freshChildDomain caller policy) = some d
        have hdNew : d = freshChildDomain caller policy := by
          injection hd with h; exact h.symm
        rw [hdNew] at hp
        -- p ∈ (freshChildDomain ...).memHandles = []  → False
        exact absurd hp (by intro h; cases h)
      · rw [if_neg h1] at hd
        by_cases h2 : did = caller
        · rw [h2] at hd
          rw [if_pos rfl, hdcaller] at hd
          have hdEq : d.memHandles = dcaller.memHandles := by
            have : d = { dcaller with
                domHandles   := dcaller.domHandles ++
                                  [(dcaller.nextHandle, s.nextDomCapId)],
                nextHandle   := dcaller.nextHandle + 1,
                childrenDoms := dcaller.childrenDoms ++ [s.nextDomId] } := by
              injection hd with h; exact h.symm
            rw [this]
          rw [hdEq] at hp
          exact hwf.refs.handleInArena caller dcaller hdcaller p hp
        · rw [if_neg h2] at hd
          exact hwf.refs.handleInArena did d hd p hp
  case cdtMono =>
    intro id c hc cid hcid ch hch
    rw [hMemEq] at hc hch
    exact hwf.cdtMonotonic id c hc cid hcid ch hch
  case cdtBidi =>
    intro id c hc cid hcid ch hch
    rw [hMemEq] at hc hch
    exact hwf.cdtBidirectional id c hc cid hcid ch hch
  case fresh =>
    intro id hid
    rw [hNextMem]
    -- memcaps.keys unchanged.
    have : ((create_apply s caller policy).memcaps).keys = s.memcaps.keys := rfl
    rw [this] at hid
    exact hwf.freshMemCounter id hid
  case ho =>
    intro did d hd p hp
    rw [hMemEq]
    rw [hDomEq] at hd
    by_cases h1 : did = s.nextDomId
    · rw [if_pos h1] at hd
      have hdNew : d = freshChildDomain caller policy := by
        injection hd with h; exact h.symm
      rw [hdNew] at hp
      exact absurd hp (by intro h; cases h)
    · rw [if_neg h1] at hd
      by_cases h2 : did = caller
      · rw [h2] at hd ⊢
        rw [if_pos rfl, hdcaller] at hd
        have hdEq : d.memHandles = dcaller.memHandles := by
          have : d = { dcaller with
              domHandles   := dcaller.domHandles ++
                                [(dcaller.nextHandle, s.nextDomCapId)],
              nextHandle   := dcaller.nextHandle + 1,
              childrenDoms := dcaller.childrenDoms ++ [s.nextDomId] } := by
            injection hd with h; exact h.symm
          rw [this]
        rw [hdEq] at hp
        exact hwf.handleOwner caller dcaller hdcaller p hp
      · rw [if_neg h2] at hd
        exact hwf.handleOwner did d hd p hp
  case pca =>
    intro id c hc pid hcpar pp hpp
    rw [hMemEq] at hc hpp
    exact hwf.parentChild id c hc pid hcpar pp hpp
  case fDom =>
    intro id hid
    rw [hNextDom]
    have hKeys : ((create_apply s caller policy).domains).keys =
                 s.nextDomId :: s.domains.keys := by
      simp only [create_apply, SpecState.freshDom, SpecState.freshDomCap,
                 SpecState.updDomain, Arena.keys_update, Arena.keys_insert]
    rw [hKeys] at hid
    simp only [List.mem_cons] at hid
    rcases hid with rfl | hid
    · exact Nat.lt_succ_self _
    · exact Nat.lt_succ_of_lt (hwf.freshDomCounter id hid)
  case fDomCap =>
    intro id hid
    rw [hNextDomCap]
    have hKeys : ((create_apply s caller policy).domcaps).keys =
                 s.nextDomCapId :: s.domcaps.keys := by
      simp only [create_apply, SpecState.freshDom, SpecState.freshDomCap,
                 SpecState.updDomain, Arena.keys_insert]
    rw [hKeys] at hid
    simp only [List.mem_cons] at hid
    rcases hid with rfl | hid
    · exact Nat.lt_succ_self _
    · exact Nat.lt_succ_of_lt (hwf.freshDomCapCounter id hid)

/-! ### RevokeDomain preserves WellFormed

Leaf-only domain revocation. Removes the target domain and the
dom-cap, plus strips the handle and `childrenDoms` entry on caller.
Memcaps are entirely untouched, so the seven memcap-side invariants
reduce to their pre-state via `getMem` equality. The interesting
sub-goals are:

* `unique.domains` / `unique.domcaps`: `Arena.remove` preserves
  uniqueness; `update` on top of `remove` likewise.
* `freshDomCounter` / `freshDomCapCounter`: removing a key only
  shrinks the key set; counters unchanged.

`handleInArena` and `handleOwner` reduce by case-split on `did`:
the target case is impossible (its `getDom` is now `none`), the
caller case uses the fact that the caller update doesn't touch
`memHandles`, and the default case is the pre-state. -/

theorem revokeDomain_preserves_wellformed
    {s s' : SpecState} {caller : DomId} {handle : LocalHandle}
    (hwf : WellFormed s)
    (hstep : step s (.revokeDomain caller handle) s') :
    WellFormed s' := by
  cases hstep
  rename_i guard
  obtain ⟨dcaller, hdcaller⟩ := Option.isSome_iff_exists.mp guard.callerExists
  obtain ⟨dcId, hdcId⟩ :=
    Option.isSome_iff_exists.mp (guard.handleResolves dcaller hdcaller)
  obtain ⟨dc, hdc⟩ :=
    Option.isSome_iff_exists.mp (guard.capExists dcaller hdcaller dcId hdcId)
  have hTNeC : dc.targetDom ≠ caller :=
    guard.notSelf dcaller hdcaller dcId hdcId dc hdc
  -- Memcaps and counters untouched.
  have hMemEq : ∀ id, (revokeDomain_apply s caller handle).getMem id = s.getMem id := by
    intro id
    show ((revokeDomain_apply s caller handle).memcaps).find? id = _
    simp only [revokeDomain_apply, hdcaller, hdcId, hdc, SpecState.updDomain]
    rfl
  have hNextMem :
      (revokeDomain_apply s caller handle).nextMemCapId = s.nextMemCapId := by
    simp only [revokeDomain_apply, hdcaller, hdcId, hdc, SpecState.updDomain]
  have hNextDom :
      (revokeDomain_apply s caller handle).nextDomId = s.nextDomId := by
    simp only [revokeDomain_apply, hdcaller, hdcId, hdc, SpecState.updDomain]
  have hNextDomCap :
      (revokeDomain_apply s caller handle).nextDomCapId = s.nextDomCapId := by
    simp only [revokeDomain_apply, hdcaller, hdcId, hdc, SpecState.updDomain]
  -- 3-way characterization of `getDom`.
  have hDomEq : ∀ id, (revokeDomain_apply s caller handle).getDom id =
      (if id = dc.targetDom then none
       else if id = caller then
         (s.getDom id).map (fun d =>
           { d with domHandles   := d.domHandles.filter (fun h => h.2 ≠ dcId),
                    childrenDoms := d.childrenDoms.filter (· ≠ dc.targetDom) })
       else s.getDom id) := by
    intro id
    show ((revokeDomain_apply s caller handle).domains).find? id = _
    simp only [revokeDomain_apply, hdcaller, hdcId, hdc, SpecState.updDomain]
    by_cases h1 : id = dc.targetDom
    · rw [h1, Arena.find?_update_other _ caller dc.targetDom _ hTNeC,
          Arena.find?_remove_same, if_pos rfl]
    · by_cases h2 : id = caller
      · subst h2
        rw [Arena.find?_update_eq_map]
        have : (s.domains.remove dc.targetDom).find? id =
               s.getDom id :=
          Arena.find?_remove_other _ _ _ h1
        rw [this, if_neg h1, if_pos rfl]
      · rw [Arena.find?_update_other _ caller id _ h2,
            Arena.find?_remove_other _ dc.targetDom id h1,
            if_neg h1, if_neg h2]
        rfl
  -- 2-way characterization of `getDomCap`.
  have hDomCapEq : ∀ id, (revokeDomain_apply s caller handle).getDomCap id =
      (if id = dcId then none else s.getDomCap id) := by
    intro id
    show ((revokeDomain_apply s caller handle).domcaps).find? id = _
    simp only [revokeDomain_apply, hdcaller, hdcId, hdc, SpecState.updDomain]
    by_cases h : id = dcId
    · rw [h, Arena.find?_remove_same, if_pos rfl]
    · rw [Arena.find?_remove_other _ _ _ h, if_neg h]
      rfl
  refine ⟨?unique, ?refs, ?cdtMono, ?cdtBidi, ?fresh, ?ho, ?pca, ?fDom, ?fDomCap⟩
  case unique =>
    refine ⟨?mc, ?dc, ?ds⟩
    case mc =>
      show ((revokeDomain_apply s caller handle).memcaps).UniqueKeys
      simp only [revokeDomain_apply, hdcaller, hdcId, hdc, SpecState.updDomain]
      exact hwf.unique.memcaps
    case dc =>
      show ((revokeDomain_apply s caller handle).domcaps).UniqueKeys
      simp only [revokeDomain_apply, hdcaller, hdcId, hdc, SpecState.updDomain]
      exact Arena.remove_unique_keys _ _ hwf.unique.domcaps
    case ds =>
      show ((revokeDomain_apply s caller handle).domains).UniqueKeys
      simp only [revokeDomain_apply, hdcaller, hdcId, hdc, SpecState.updDomain]
      exact Arena.update_unique_keys _ _ _
        (Arena.remove_unique_keys _ _ hwf.unique.domains)
  case refs =>
    refine ⟨?pia, ?cia, ?hia⟩
    case pia =>
      intro id c hc pid hcpar
      rw [hMemEq] at hc; rw [hMemEq]
      exact hwf.refs.parentInArena id c hc pid hcpar
    case cia =>
      intro id c hc cid hcid
      rw [hMemEq] at hc; rw [hMemEq]
      exact hwf.refs.childInArena id c hc cid hcid
    case hia =>
      intro did d hd p hp
      rw [hMemEq]
      rw [hDomEq] at hd
      by_cases h1 : did = dc.targetDom
      · rw [if_pos h1] at hd; cases hd
      · rw [if_neg h1] at hd
        by_cases h2 : did = caller
        · subst h2
          rw [if_pos rfl, hdcaller] at hd
          have hdEq : d.memHandles = dcaller.memHandles := by
            have hd' : d = { dcaller with
                domHandles   := dcaller.domHandles.filter (fun h => h.2 ≠ dcId),
                childrenDoms := dcaller.childrenDoms.filter
                                  (· ≠ dc.targetDom) } := by
              injection hd with h; exact h.symm
            rw [hd']
          rw [hdEq] at hp
          exact hwf.refs.handleInArena did dcaller hdcaller p hp
        · rw [if_neg h2] at hd
          exact hwf.refs.handleInArena did d hd p hp
  case cdtMono =>
    intro id c hc cid hcid ch hch
    rw [hMemEq] at hc hch
    exact hwf.cdtMonotonic id c hc cid hcid ch hch
  case cdtBidi =>
    intro id c hc cid hcid ch hch
    rw [hMemEq] at hc hch
    exact hwf.cdtBidirectional id c hc cid hcid ch hch
  case fresh =>
    intro id hid
    rw [hNextMem]
    have heqKeys :
        ((revokeDomain_apply s caller handle).memcaps).keys = s.memcaps.keys := by
      simp only [revokeDomain_apply, hdcaller, hdcId, hdc, SpecState.updDomain]
    rw [heqKeys] at hid
    exact hwf.freshMemCounter id hid
  case ho =>
    intro did d hd p hp
    rw [hMemEq]
    rw [hDomEq] at hd
    by_cases h1 : did = dc.targetDom
    · rw [if_pos h1] at hd; cases hd
    · rw [if_neg h1] at hd
      by_cases h2 : did = caller
      · subst h2
        rw [if_pos rfl, hdcaller] at hd
        have hdEq : d.memHandles = dcaller.memHandles := by
          have hd' : d = { dcaller with
              domHandles   := dcaller.domHandles.filter (fun h => h.2 ≠ dcId),
              childrenDoms := dcaller.childrenDoms.filter
                                (· ≠ dc.targetDom) } := by
            injection hd with h; exact h.symm
          rw [hd']
        rw [hdEq] at hp
        exact hwf.handleOwner did dcaller hdcaller p hp
      · rw [if_neg h2] at hd
        exact hwf.handleOwner did d hd p hp
  case pca =>
    intro id c hc pid hcpar pp hpp
    rw [hMemEq] at hc hpp
    exact hwf.parentChild id c hc pid hcpar pp hpp
  case fDom =>
    intro id hid
    rw [hNextDom]
    have hKeys : ((revokeDomain_apply s caller handle).domains).keys =
                  (s.domains.remove dc.targetDom).keys := by
      simp only [revokeDomain_apply, hdcaller, hdcId, hdc, SpecState.updDomain,
                 Arena.keys_update]
    rw [hKeys, Arena.mem_keys_remove_iff] at hid
    exact hwf.freshDomCounter id hid.2
  case fDomCap =>
    intro id hid
    rw [hNextDomCap]
    have hKeys : ((revokeDomain_apply s caller handle).domcaps).keys =
                  (s.domcaps.remove dcId).keys := by
      simp only [revokeDomain_apply, hdcaller, hdcId, hdc, SpecState.updDomain]
    rw [hKeys, Arena.mem_keys_remove_iff] at hid
    exact hwf.freshDomCapCounter id hid.2

end ThemisCapa

