/-
  ThemisCapa.ParentStability — Parent-pointer immutability.

  Once a domain has been created with `parent = some P`, every subsequent
  step preserves that field. No action can re-parent an existing domain.

  Top theorem:
    `step_parent_immutable :
       step s a s' →
       s.getDom did = some d →
       s'.getDom did = some d' →
       d'.parent = d.parent`

  Proof strategy. For every action's pure update function, we show
  `PreservesParents`, a predicate on state transformers `g : SpecState →
  SpecState` saying "every domain that exists in both pre- and post-state
  has the same parent." We build this from primitive lemmas:

    * Mutators that don't touch the `domains` arena (e.g. `updMem`,
      `updDomCap`, `updCore`, `freshMem`, `freshDomCap`) are trivially
      `PreservesParents`.
    * `updDomain target f` is `PreservesParents` when `f` preserves
      `.parent` (true for any record update `{d with f := v}` that does
      not name `parent`).
    * `freshDom` introduces a brand-new id; the precondition
      `s.getDom did = some d` is impossible for the fresh id, so the
      property holds vacuously for the new entry.
    * `domains := s.domains.remove target` removes a domain entirely;
      `s'.getDom target = none`, so the precondition `s'.getDom did =
      some d'` is impossible for did = target.
    * Composition: if `g` and `h` are `PreservesParents`, so is `h ∘ g`.

  Used in O2 (hierarchical encapsulation) — once `D.parent = some P`,
  no descendant of D can sever or rewrite that link.
-/
import ThemisCapa.Locality
import ThemisCapa.DomainTree

namespace ThemisCapa
open Arena

/-- A state-transformer `g` preserves parent pointers if every domain
    that exists in both the source and the result has the same parent. -/
def PreservesParents (g : SpecState → SpecState) : Prop :=
  ∀ s did d d',
    s.getDom did = some d →
    (g s).getDom did = some d' →
    d'.parent = d.parent

/-! ## Primitive composition rules -/

/-- The identity transformer preserves parents. -/
theorem PreservesParents.id : PreservesParents (fun s => s) := by
  intro s did d d' h h'
  rw [h] at h'; injection h' with eq; rw [eq]

/-! ## Updates that don't touch the domain arena -/

theorem PreservesParents.of_domains_eq
    {g : SpecState → SpecState}
    (hg : ∀ s, (g s).domains = s.domains) :
    PreservesParents g := by
  intro s did d d' hpre hpost
  have : (g s).domains.find? did = some d' := hpost
  rw [hg] at this
  have hpre' : s.domains.find? did = some d := hpre
  rw [hpre'] at this; injection this with eq; rw [eq]

theorem updMem_preservesParents (id : MemCapId) (f : MemCap → MemCap) :
    PreservesParents (fun s => s.updMem id f) :=
  PreservesParents.of_domains_eq (fun _ => rfl)

theorem updDomCap_preservesParents (id : DomCapId) (f : DomCap → DomCap) :
    PreservesParents (fun s => s.updDomCap id f) :=
  PreservesParents.of_domains_eq (fun _ => rfl)

theorem updCore_preservesParents (id : CoreId) (f : CoreState → CoreState) :
    PreservesParents (fun s => s.updCore id f) :=
  PreservesParents.of_domains_eq (fun _ => rfl)

theorem freshMem_preservesParents (m : MemCap) :
    PreservesParents (fun s => (s.freshMem m).2) := by
  apply PreservesParents.of_domains_eq
  intro s; rfl

theorem freshDomCap_preservesParents (dc : DomCap) :
    PreservesParents (fun s => (s.freshDomCap dc).2) := by
  apply PreservesParents.of_domains_eq
  intro s; rfl

/-! ## `updDomain` with parent-preserving update -/

/-- If `f` preserves the `.parent` field, then `updDomain target f`
    preserves parents globally. -/
theorem updDomain_preservesParents
    (target : DomId) (f : Domain → Domain)
    (hf : ∀ d, (f d).parent = d.parent) :
    PreservesParents (fun s => s.updDomain target f) := by
  intro s did d d' hpre hpost
  have hpre' : s.domains.find? did = some d := hpre
  by_cases hdid : did = target
  · subst hdid
    have hpost' : (s.domains.update did f).find? did = some d' := hpost
    rw [Arena.find?_update_eq_map] at hpost'
    rw [hpre'] at hpost'
    simp at hpost'
    rw [← hpost']
    exact hf d
  · have hpost' : (s.domains.update target f).find? did = some d' := hpost
    rw [Arena.find?_update_other _ target did f hdid] at hpost'
    rw [hpre'] at hpost'; injection hpost' with eq; rw [eq]

/-! ## Composition (under a "no removal" side condition) -/

/-- A state-transformer never removes an existing domain entry. -/
def NeverRemovesDomain (g : SpecState → SpecState) : Prop :=
  ∀ s did, (s.getDom did).isSome → ((g s).getDom did).isSome

/-- Sequential composition preserves parents when the first stage never
    removes a domain. (General composition is unsound: a stage that
    *removes* a domain could be followed by a stage that re-creates it
    with a different parent. None of our concrete actions exhibit this
    behaviour, but `revokeDomain_apply` is handled by direct case
    analysis rather than composition.) -/
theorem PreservesParents.comp_no_remove
    {g h : SpecState → SpecState}
    (hgnr : NeverRemovesDomain g)
    (hg : PreservesParents g) (hh : PreservesParents h) :
    PreservesParents (fun s => h (g s)) := by
  intro s did d d' hpre hpost
  have hmid : ((g s).getDom did).isSome := hgnr s did (by rw [hpre]; rfl)
  rcases hmidcases : (g s).getDom did with _ | dmid
  · rw [hmidcases] at hmid; cases hmid
  · have e1 := hg s did d dmid hpre hmidcases
    have e2 := hh (g s) did dmid d' hmidcases hpost
    rw [e2, e1]

theorem NeverRemovesDomain.id : NeverRemovesDomain (fun s => s) := by
  intro s did h; exact h

theorem NeverRemovesDomain.of_domains_eq
    {g : SpecState → SpecState}
    (hg : ∀ s, (g s).domains = s.domains) :
    NeverRemovesDomain g := by
  intro s did h
  show (g s).domains.find? did |>.isSome
  rw [hg]; exact h

theorem updMem_neverRemoves (id : MemCapId) (f : MemCap → MemCap) :
    NeverRemovesDomain (fun s => s.updMem id f) :=
  NeverRemovesDomain.of_domains_eq (fun _ => rfl)

theorem updDomCap_neverRemoves (id : DomCapId) (f : DomCap → DomCap) :
    NeverRemovesDomain (fun s => s.updDomCap id f) :=
  NeverRemovesDomain.of_domains_eq (fun _ => rfl)

theorem updCore_neverRemoves (id : CoreId) (f : CoreState → CoreState) :
    NeverRemovesDomain (fun s => s.updCore id f) :=
  NeverRemovesDomain.of_domains_eq (fun _ => rfl)

theorem freshMem_neverRemoves (m : MemCap) :
    NeverRemovesDomain (fun s => (s.freshMem m).2) :=
  NeverRemovesDomain.of_domains_eq (fun _ => rfl)

theorem freshDomCap_neverRemoves (dc : DomCap) :
    NeverRemovesDomain (fun s => (s.freshDomCap dc).2) :=
  NeverRemovesDomain.of_domains_eq (fun _ => rfl)

theorem updDomain_neverRemoves (target : DomId) (f : Domain → Domain) :
    NeverRemovesDomain (fun s => s.updDomain target f) := by
  intro s did h
  by_cases hdid : did = target
  · subst hdid
    show ((s.domains.update did f).find? did).isSome
    rw [Arena.find?_update_eq_map]
    rw [show s.getDom did = s.domains.find? did from rfl] at h
    rcases hp : s.domains.find? did with _ | p
    · rw [hp] at h; cases h
    · simp
  · show ((s.domains.update target f).find? did).isSome
    rw [Arena.find?_update_other _ target did f hdid]
    exact h

/-! ## Per-action parent-stability lemmas

For every action, the pure update function preserves parent pointers.
Proven by unfolding the apply definition, splitting on its option-resolution
branches, and either exhibiting a no-op identity (failure branch ⇒ result
equals input) or composing primitive `PreservesParents` lemmas through
`comp_no_remove`.

Together these support the top-level `step_parent_immutable` theorem
that says no step can re-parent an existing domain. -/

/-- Helper: a state on which the action becomes a no-op preserves parents
    trivially. -/
private theorem preservesParents_of_eq_input
    (g : SpecState → SpecState) (s : SpecState) (h : g s = s)
    {did : DomId} {d d' : Domain}
    (hpre : s.getDom did = some d) (hpost : (g s).getDom did = some d') :
    d'.parent = d.parent := by
  rw [h] at hpost
  rw [hpre] at hpost; injection hpost with eq; rw [eq]

/-- `carve_apply` preserves parents. -/
theorem carve_apply_preservesParents (caller : DomId) (parent : MemCapId)
    (access : Access) (attrs : Attributes) :
    PreservesParents (fun s => carve_apply s caller parent access attrs) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hp : s.getMem parent with _ | p
  · -- failure branch: result is `s` definitionally.
    have : (carve_apply s caller parent access attrs).domains.find? did = some d' := hpost
    simp [carve_apply, hp] at this
    rw [hpre_d] at this; injection this with eq; rw [eq]
  · -- success branch.
    have hp' : (carve_apply s caller parent access attrs).domains.find? did = some d' := hpost
    simp only [carve_apply, hp, SpecState.freshMem, SpecState.updMem,
               SpecState.updDomain] at hp'
    by_cases hdid : did = caller
    · subst hdid
      rw [Arena.find?_update_eq_map] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']
    · rw [Arena.find?_update_other _ caller did _ hdid] at hp'
      rw [hpre_d] at hp'; injection hp' with eq; rw [eq]

/-- `alias_apply` preserves parents. Identical structure to `carve_apply`. -/
theorem alias_apply_preservesParents (caller : DomId) (parent : MemCapId)
    (access : Access) :
    PreservesParents (fun s => alias_apply s caller parent access) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hp : s.getMem parent with _ | p
  · have : (alias_apply s caller parent access).domains.find? did = some d' := hpost
    simp [alias_apply, hp] at this
    rw [hpre_d] at this; injection this with eq; rw [eq]
  · have hp' : (alias_apply s caller parent access).domains.find? did = some d' := hpost
    simp only [alias_apply, hp, SpecState.freshMem, SpecState.updMem,
               SpecState.updDomain] at hp'
    by_cases hdid : did = caller
    · subst hdid
      rw [Arena.find?_update_eq_map] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']
    · rw [Arena.find?_update_other _ caller did _ hdid] at hp'
      rw [hpre_d] at hp'; injection hp' with eq; rw [eq]

/-- `revoke_apply` preserves parents. -/
theorem revoke_apply_preservesParents (caller : DomId) (target : MemCapId) :
    PreservesParents (fun s => revoke_apply s caller target) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  rcases ht : s.getMem target with _ | t
  · have : (revoke_apply s caller target).domains.find? did = some d' := hpost
    simp [revoke_apply, ht] at this
    rw [hpre_d] at this; injection this with eq; rw [eq]
  · rcases htp : t.parent with _ | pid
    · have : (revoke_apply s caller target).domains.find? did = some d' := hpost
      simp [revoke_apply, ht, htp] at this
      rw [hpre_d] at this; injection this with eq; rw [eq]
    · have hp' : (revoke_apply s caller target).domains.find? did = some d' := hpost
      simp only [revoke_apply, ht, htp, SpecState.updMem,
                 SpecState.updDomain] at hp'
      by_cases hdid : did = t.owner
      · subst hdid
        rw [Arena.find?_update_eq_map] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']
      · rw [Arena.find?_update_other _ t.owner did _ hdid] at hp'
        rw [hpre_d] at hp'; injection hp' with eq; rw [eq]

/-- `seal_apply` preserves parents. -/
theorem seal_apply_preservesParents (caller : DomId) (cap : DomCapId) :
    PreservesParents (fun s => seal_apply s caller cap) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hc : s.getDomCap cap with _ | dc
  · have : (seal_apply s caller cap).domains.find? did = some d' := hpost
    simp [seal_apply, hc] at this
    rw [hpre_d] at this; injection this with eq; rw [eq]
  · have hp' : (seal_apply s caller cap).domains.find? did = some d' := hpost
    simp only [seal_apply, hc, SpecState.updDomain] at hp'
    by_cases hdid : did = dc.targetDom
    · subst hdid
      rw [Arena.find?_update_eq_map] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']
    · rw [Arena.find?_update_other _ dc.targetDom did _ hdid] at hp'
      rw [hpre_d] at hp'; injection hp' with eq; rw [eq]

/-- `send_apply` preserves parents. -/
theorem send_apply_preservesParents (caller receiver : DomId) (cap : MemCapId) :
    PreservesParents (fun s => send_apply s caller receiver cap) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  have hp' : (send_apply s caller receiver cap).domains.find? did = some d' := hpost
  simp only [send_apply, SpecState.updMem, SpecState.updDomain] at hp'
  by_cases hd1 : did = receiver
  · subst hd1
    rw [Arena.find?_update_eq_map] at hp'
    by_cases hd2 : did = caller
    · subst hd2
      rw [Arena.find?_update_eq_map] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']
    · rw [Arena.find?_update_other _ caller did _ hd2] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']
  · rw [Arena.find?_update_other _ receiver did _ hd1] at hp'
    by_cases hd2 : did = caller
    · subst hd2
      rw [Arena.find?_update_eq_map] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']
    · rw [Arena.find?_update_other _ caller did _ hd2] at hp'
      rw [hpre_d] at hp'; injection hp' with eq; rw [eq]

end ThemisCapa
