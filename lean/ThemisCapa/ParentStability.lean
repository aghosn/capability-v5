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
import ThemisCapa.Invariants
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
      by_cases hv : t.region.attributes.vital
      · simp only [if_pos hv] at hp'
        by_cases hdid : did = t.owner
        · subst hdid
          rw [Arena.find?_update_eq_map, Arena.find?_update_eq_map] at hp'
          rw [hpre_d] at hp'; simp at hp'; rw [← hp']
        · rw [Arena.find?_update_other _ t.owner did _ hdid,
              Arena.find?_update_other _ t.owner did _ hdid] at hp'
          rw [hpre_d] at hp'; injection hp' with eq; rw [eq]
      · simp only [if_neg hv] at hp'
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

/-- `setPolicy_apply` preserves parents. -/
theorem setPolicy_apply_preservesParents (caller : DomId) (cap : DomCapId)
    (id : PolicyIdentifier) (value : Nat) :
    PreservesParents (fun s => setPolicy_apply s caller cap id value) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hc : s.getDomCap cap with _ | dc
  · have : (setPolicy_apply s caller cap id value).domains.find? did = some d' := hpost
    simp [setPolicy_apply, hc] at this
    rw [hpre_d] at this; injection this with eq; rw [eq]
  · have hp' :
        (setPolicy_apply s caller cap id value).domains.find? did = some d' := hpost
    simp only [setPolicy_apply, hc, SpecState.updDomain] at hp'
    by_cases hdid : did = dc.targetDom
    · subst hdid
      rw [Arena.find?_update_eq_map] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']
    · rw [Arena.find?_update_other _ dc.targetDom did _ hdid] at hp'
      rw [hpre_d] at hp'; injection hp' with eq; rw [eq]

/-- `sealedSend_apply` preserves parents. -/
theorem sealedSend_apply_preservesParents
    (caller receiver : DomId) (handle : LocalHandle) (gpaHint : Option Nat) :
    PreservesParents (fun s => sealedSend_apply s caller receiver handle gpaHint) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hb : (s.getDom caller).bind (fun d => d.lookupMemHandle handle) with _ | capId
  · have : (sealedSend_apply s caller receiver handle gpaHint).domains.find? did = some d' :=
      hpost
    simp [sealedSend_apply, hb] at this
    rw [hpre_d] at this; injection this with eq; rw [eq]
  · have hp' : (sealedSend_apply s caller receiver handle gpaHint).domains.find? did = some d' :=
      hpost
    simp only [sealedSend_apply, hb, SpecState.updDomain] at hp'
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

/-- `reject_apply` preserves parents. -/
theorem reject_apply_preservesParents (receiver : DomId) (pendingId : PendingId) :
    PreservesParents (fun s => reject_apply s receiver pendingId) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  have hp' : (reject_apply s receiver pendingId).domains.find? did = some d' := hpost
  rcases hb : (s.getDom receiver).bind (fun d => d.lookupPending pendingId) with _ | pe
  · simp only [reject_apply, hb, SpecState.updDomain] at hp'
    by_cases hd : did = receiver
    · subst hd
      rw [Arena.find?_update_eq_map] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']
    · rw [Arena.find?_update_other _ receiver did _ hd] at hp'
      rw [hpre_d] at hp'; injection hp' with eq; rw [eq]
  · simp only [reject_apply, hb, SpecState.updDomain] at hp'
    by_cases hd1 : did = pe.senderDomainId
    · subst hd1
      rw [Arena.find?_update_eq_map] at hp'
      by_cases hd2 : pe.senderDomainId = receiver
      · rw [← hd2] at hp'
        rw [Arena.find?_update_eq_map] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']
      · rw [Arena.find?_update_other _ receiver pe.senderDomainId _ hd2] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']
    · rw [Arena.find?_update_other _ pe.senderDomainId did _ hd1] at hp'
      by_cases hd2 : did = receiver
      · subst hd2
        rw [Arena.find?_update_eq_map] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']
      · rw [Arena.find?_update_other _ receiver did _ hd2] at hp'
        rw [hpre_d] at hp'; injection hp' with eq; rw [eq]

/-- `accept_apply` preserves parents. -/
theorem accept_apply_preservesParents (receiver : DomId) (pendingId : PendingId) :
    PreservesParents (fun s => accept_apply s receiver pendingId) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hb : (s.getDom receiver).bind (fun d => d.lookupPending pendingId) with _ | pe
  · have : (accept_apply s receiver pendingId).domains.find? did = some d' := hpost
    simp [accept_apply, hb] at this
    rw [hpre_d] at this; injection this with eq; rw [eq]
  · have hp' : (accept_apply s receiver pendingId).domains.find? did = some d' := hpost
    simp only [accept_apply, hb, SpecState.updDomain] at hp'
    by_cases hd1 : did = pe.senderDomainId
    · subst hd1
      rw [Arena.find?_update_eq_map] at hp'
      by_cases hd2 : pe.senderDomainId = receiver
      · rw [← hd2] at hp'
        rw [Arena.find?_update_eq_map] at hp'
        rcases hsend :
            (send_apply s pe.senderDomainId pe.senderDomainId pe.capId).domains.find?
              pe.senderDomainId with _ | dx
        · rw [hsend] at hp'; simp at hp'
        · rw [hsend] at hp'; simp at hp'
          have hsendp :
              (send_apply s pe.senderDomainId pe.senderDomainId pe.capId).getDom
                pe.senderDomainId = some dx := hsend
          have :=
            send_apply_preservesParents pe.senderDomainId pe.senderDomainId pe.capId
              s pe.senderDomainId d dx hpre_d hsendp
          rw [← hp', this]
      · rw [Arena.find?_update_other _ receiver pe.senderDomainId _ hd2] at hp'
        rcases hsend :
            (send_apply s pe.senderDomainId receiver pe.capId).domains.find? pe.senderDomainId
            with _ | dx
        · rw [hsend] at hp'; simp at hp'
        · rw [hsend] at hp'; simp at hp'
          have hsendp :
              (send_apply s pe.senderDomainId receiver pe.capId).getDom pe.senderDomainId
              = some dx := hsend
          have :=
            send_apply_preservesParents pe.senderDomainId receiver pe.capId
              s pe.senderDomainId d dx hpre_d hsendp
          rw [← hp', this]
    · rw [Arena.find?_update_other _ pe.senderDomainId did _ hd1] at hp'
      by_cases hd2 : did = receiver
      · subst hd2
        rw [Arena.find?_update_eq_map] at hp'
        rcases hsend :
            (send_apply s pe.senderDomainId did pe.capId).domains.find? did with _ | dx
        · rw [hsend] at hp'; simp at hp'
        · rw [hsend] at hp'; simp at hp'
          have hsendp :
              (send_apply s pe.senderDomainId did pe.capId).getDom did = some dx := hsend
          have :=
            send_apply_preservesParents pe.senderDomainId did pe.capId s did d dx hpre hsendp
          rw [← hp', this]
      · rw [Arena.find?_update_other _ receiver did _ hd2] at hp'
        have hsendp : (send_apply s pe.senderDomainId receiver pe.capId).getDom did
            = some d' := hp'
        exact
          send_apply_preservesParents pe.senderDomainId receiver pe.capId s did d d' hpre hsendp

/-- `sendChannel_apply` preserves parents. -/
theorem sendChannel_apply_preservesParents (caller receiver : DomId) (cap : DomCapId) :
    PreservesParents (fun s => sendChannel_apply s caller receiver cap) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  have hp' : (sendChannel_apply s caller receiver cap).domains.find? did = some d' := hpost
  simp only [sendChannel_apply, SpecState.updDomCap, SpecState.updDomain] at hp'
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

/-- `rejectChannel_apply` preserves parents. -/
theorem rejectChannel_apply_preservesParents (receiver : DomId) (pendingId : PendingId) :
    PreservesParents (fun s => rejectChannel_apply s receiver pendingId) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  have hp' : (rejectChannel_apply s receiver pendingId).domains.find? did = some d' := hpost
  rcases hb : (s.getDom receiver).bind (fun d => d.lookupPendingDom pendingId) with _ | pe
  · simp only [rejectChannel_apply, hb, SpecState.updDomain] at hp'
    by_cases hd : did = receiver
    · subst hd
      rw [Arena.find?_update_eq_map] at hp'
      rw [hpre_d] at hp'; simp at hp'; rw [← hp']
    · rw [Arena.find?_update_other _ receiver did _ hd] at hp'
      rw [hpre_d] at hp'; injection hp' with eq; rw [eq]
  · simp only [rejectChannel_apply, hb, SpecState.updDomain] at hp'
    by_cases hd1 : did = pe.senderDomainId
    · subst hd1
      rw [Arena.find?_update_eq_map] at hp'
      by_cases hd2 : pe.senderDomainId = receiver
      · rw [← hd2] at hp'
        rw [Arena.find?_update_eq_map] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']
      · rw [Arena.find?_update_other _ receiver pe.senderDomainId _ hd2] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']
    · rw [Arena.find?_update_other _ pe.senderDomainId did _ hd1] at hp'
      by_cases hd2 : did = receiver
      · subst hd2
        rw [Arena.find?_update_eq_map] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']
      · rw [Arena.find?_update_other _ receiver did _ hd2] at hp'
        rw [hpre_d] at hp'; injection hp' with eq; rw [eq]

/-- `acceptChannel_apply` preserves parents. -/
theorem acceptChannel_apply_preservesParents (receiver : DomId) (pendingId : PendingId) :
    PreservesParents (fun s => acceptChannel_apply s receiver pendingId) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hb : (s.getDom receiver).bind (fun d => d.lookupPendingDom pendingId) with _ | pe
  · have : (acceptChannel_apply s receiver pendingId).domains.find? did = some d' := hpost
    simp [acceptChannel_apply, hb] at this
    rw [hpre_d] at this; injection this with eq; rw [eq]
  · have hp' : (acceptChannel_apply s receiver pendingId).domains.find? did = some d' := hpost
    simp only [acceptChannel_apply, hb, SpecState.updDomain] at hp'
    -- Outer = updDomain pe.senderDomainId, then updDomain receiver, then sendChannel_apply.
    by_cases hd1 : did = pe.senderDomainId
    · subst hd1
      rw [Arena.find?_update_eq_map] at hp'
      by_cases hd2 : pe.senderDomainId = receiver
      · rw [← hd2] at hp'
        rw [Arena.find?_update_eq_map] at hp'
        rcases hsend :
            (sendChannel_apply s pe.senderDomainId pe.senderDomainId pe.capId).domains.find?
              pe.senderDomainId with _ | dx
        · rw [hsend] at hp'; simp at hp'
        · rw [hsend] at hp'; simp at hp'
          have hsendp :
              (sendChannel_apply s pe.senderDomainId pe.senderDomainId pe.capId).getDom
                pe.senderDomainId = some dx := hsend
          have :=
            sendChannel_apply_preservesParents pe.senderDomainId pe.senderDomainId pe.capId
              s pe.senderDomainId d dx hpre_d hsendp
          rw [← hp', this]
      · rw [Arena.find?_update_other _ receiver pe.senderDomainId _ hd2] at hp'
        rcases hsend :
            (sendChannel_apply s pe.senderDomainId receiver pe.capId).domains.find?
              pe.senderDomainId with _ | dx
        · rw [hsend] at hp'; simp at hp'
        · rw [hsend] at hp'; simp at hp'
          have hsendp :
              (sendChannel_apply s pe.senderDomainId receiver pe.capId).getDom
                pe.senderDomainId = some dx := hsend
          have :=
            sendChannel_apply_preservesParents pe.senderDomainId receiver pe.capId
              s pe.senderDomainId d dx hpre_d hsendp
          rw [← hp', this]
    · rw [Arena.find?_update_other _ pe.senderDomainId did _ hd1] at hp'
      by_cases hd2 : did = receiver
      · subst hd2
        rw [Arena.find?_update_eq_map] at hp'
        rcases hsend :
            (sendChannel_apply s pe.senderDomainId did pe.capId).domains.find? did
            with _ | dx
        · rw [hsend] at hp'; simp at hp'
        · rw [hsend] at hp'; simp at hp'
          have hsendp :
              (sendChannel_apply s pe.senderDomainId did pe.capId).getDom did
              = some dx := hsend
          have :=
            sendChannel_apply_preservesParents pe.senderDomainId did pe.capId
              s did d dx hpre hsendp
          rw [← hp', this]
      · rw [Arena.find?_update_other _ receiver did _ hd2] at hp'
        have hsendp : (sendChannel_apply s pe.senderDomainId receiver pe.capId).getDom did
            = some d' := hp'
        exact
          sendChannel_apply_preservesParents pe.senderDomainId receiver pe.capId
            s did d d' hpre hsendp

/-- `mapSelf_apply` preserves parents (caller-only mutation). -/
theorem mapSelf_apply_preservesParents
    (caller : DomId) (capHandle : LocalHandle) (newGpa : Nat) :
    PreservesParents (fun s => mapSelf_apply s caller capHandle newGpa) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hcd : s.getDom caller with _ | dc
  · have : (mapSelf_apply s caller capHandle newGpa).domains.find? did = some d' := hpost
    simp [mapSelf_apply, hcd] at this
    rw [hpre_d] at this; injection this with eq; rw [eq]
  · rcases hh : dc.lookupMemHandle capHandle with _ | mid
    · have : (mapSelf_apply s caller capHandle newGpa).domains.find? did = some d' := hpost
      simp [mapSelf_apply, hcd, hh] at this
      rw [hpre_d] at this; injection this with eq; rw [eq]
    · rcases hm : s.getMem mid with _ | c
      · have : (mapSelf_apply s caller capHandle newGpa).domains.find? did = some d' := hpost
        simp [mapSelf_apply, hcd, hh, hm] at this
        rw [hpre_d] at this; injection this with eq; rw [eq]
      · rcases hg : dc.lookupMappedGpa capHandle with _ | oldGpa
        · have : (mapSelf_apply s caller capHandle newGpa).domains.find? did = some d' := hpost
          simp [mapSelf_apply, hcd, hh, hm, hg] at this
          rw [hpre_d] at this; injection this with eq; rw [eq]
        · have hp' :
              (mapSelf_apply s caller capHandle newGpa).domains.find? did = some d' := hpost
          simp only [mapSelf_apply, hcd, hh, hm, hg, SpecState.updDomain] at hp'
          by_cases hd : did = caller
          · subst hd
            rw [Arena.find?_update_eq_map] at hp'
            rw [hpre_d] at hp'; simp at hp'; rw [← hp']
            -- Show that updMappedGpa preserves .parent on the witnessed record.
            unfold Domain.updMappedGpa
            by_cases hany : (d.mappedGpas.any (fun p => p.1 = capHandle))
            · simp [hany]
            · simp [hany]
          · rw [Arena.find?_update_other _ caller did _ hd] at hp'
            rw [hpre_d] at hp'; injection hp' with eq; rw [eq]

/-! ### Helpers for record-update-style domain mutators -/

private theorem Domain.updVp_parent (d : Domain) (vpId : VpId)
    (f : VProcessor → VProcessor) :
    (d.updVp vpId f).parent = d.parent := rfl

private theorem Domain.updMappedGpa_parent (d : Domain) (h : LocalHandle) (gpa : Nat) :
    (d.updMappedGpa h gpa).parent = d.parent := by
  unfold Domain.updMappedGpa
  by_cases hany : d.mappedGpas.any (fun p => p.1 = h)
  · simp [hany]
  · simp [hany]

/-- `switchReturn_apply` preserves parents. -/
theorem switchReturn_apply_preservesParents
    (caller : DomId) (core : CoreId) (exitReason : Option Nat) :
    PreservesParents (fun s => switchReturn_apply s caller core exitReason) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hb : (s.getDom caller).bind (fun d => d.vpAndPrevCallerOnCore core) with _ | p
  · have : (switchReturn_apply s caller core exitReason).domains.find? did = some d' := hpost
    simp [switchReturn_apply, hb] at this
    rw [hpre_d] at this; injection this with eq; rw [eq]
  · obtain ⟨vpId, pctx⟩ := p
    have hp' :
        (switchReturn_apply s caller core exitReason).domains.find? did = some d' := hpost
    simp only [switchReturn_apply, hb, SpecState.updCore, SpecState.updDomain] at hp'
    -- Outer = updDomain pctx.domainId
    by_cases hd1 : did = pctx.domainId
    · subst hd1
      rw [Arena.find?_update_eq_map] at hp'
      by_cases hd2 : pctx.domainId = caller
      · rw [← hd2] at hp'
        rw [Arena.find?_update_eq_map] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']
        exact Domain.updVp_parent _ _ _
      · rw [Arena.find?_update_other _ caller pctx.domainId _ hd2] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']
        exact Domain.updVp_parent _ _ _
    · rw [Arena.find?_update_other _ pctx.domainId did _ hd1] at hp'
      by_cases hd2 : did = caller
      · subst hd2
        rw [Arena.find?_update_eq_map] at hp'
        rw [hpre_d] at hp'; simp at hp'; rw [← hp']
        exact Domain.updVp_parent _ _ _
      · rw [Arena.find?_update_other _ caller did _ hd2] at hp'
        rw [hpre_d] at hp'; injection hp' with eq; rw [eq]

/-- `switch_apply` preserves parents. -/
theorem switch_apply_preservesParents
    (caller : DomId) (toHandle : LocalHandle) (toVpId : VpId) (core : CoreId) :
    PreservesParents (fun s => switch_apply s caller toHandle toVpId core) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hb1 : (s.getDom caller).bind (fun d => d.lookupDomHandle toHandle) with _ | cid
  · have : (switch_apply s caller toHandle toVpId core).domains.find? did = some d' := hpost
    simp [switch_apply, hb1] at this
    rw [hpre_d] at this; injection this with eq; rw [eq]
  · rcases hc : s.getDomCap cid with _ | dc
    · have : (switch_apply s caller toHandle toVpId core).domains.find? did = some d' := hpost
      simp [switch_apply, hb1, hc] at this
      rw [hpre_d] at this; injection this with eq; rw [eq]
    · rcases hb2 : (s.getDom caller).bind (fun d => d.vpAndOptPrevOnCore core) with _ | p
      · have : (switch_apply s caller toHandle toVpId core).domains.find? did = some d' := hpost
        simp [switch_apply, hb1, hc, hb2] at this
        rw [hpre_d] at this; injection this with eq; rw [eq]
      · obtain ⟨callerVpId, callerPrev⟩ := p
        have hp' :
            (switch_apply s caller toHandle toVpId core).domains.find? did = some d' := hpost
        simp only [switch_apply, hb1, hc, hb2, SpecState.updCore, SpecState.updDomain] at hp'
        by_cases hd1 : did = caller
        · rw [hd1] at hp' hpre_d
          rw [Arena.find?_update_eq_map] at hp'
          by_cases hd2 : caller = dc.targetDom
          · rw [← hd2] at hp'
            rw [Arena.find?_update_eq_map] at hp'
            rw [hpre_d] at hp'; simp at hp'; rw [← hp']
            exact Domain.updVp_parent _ _ _
          · rw [Arena.find?_update_other _ dc.targetDom caller _ hd2] at hp'
            rw [hpre_d] at hp'; simp at hp'; rw [← hp']
            exact Domain.updVp_parent _ _ _
        · rw [Arena.find?_update_other _ caller did _ hd1] at hp'
          by_cases hd2 : did = dc.targetDom
          · subst hd2
            rw [Arena.find?_update_eq_map] at hp'
            rw [hpre_d] at hp'; simp at hp'; rw [← hp']
            exact Domain.updVp_parent _ _ _
          · rw [Arena.find?_update_other _ dc.targetDom did _ hd2] at hp'
            rw [hpre_d] at hp'; injection hp' with eq; rw [eq]

/-- `switchSuspended_apply` preserves parents. -/
theorem switchSuspended_apply_preservesParents
    (caller : DomId) (toHandle : LocalHandle) (toVpId : VpId) (core : CoreId)
    (calleeDom : DomId) (calleeVp : VpId) :
    PreservesParents (fun s =>
      switchSuspended_apply s caller toHandle toVpId core calleeDom calleeVp) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hb1 : (s.getDom caller).bind (fun d => d.lookupDomHandle toHandle) with _ | cid
  · have :
        (switchSuspended_apply s caller toHandle toVpId core calleeDom calleeVp).domains.find?
          did = some d' := hpost
    simp [switchSuspended_apply, hb1] at this
    rw [hpre_d] at this; injection this with eq; rw [eq]
  · rcases hc : s.getDomCap cid with _ | dc
    · have :
          (switchSuspended_apply s caller toHandle toVpId core calleeDom calleeVp).domains.find?
            did = some d' := hpost
      simp [switchSuspended_apply, hb1, hc] at this
      rw [hpre_d] at this; injection this with eq; rw [eq]
    · rcases hb2 : (s.getDom caller).bind (fun d => d.vpAndOptPrevOnCore core) with _ | p
      · have :
            (switchSuspended_apply s caller toHandle toVpId core calleeDom calleeVp).domains.find?
              did = some d' := hpost
        simp [switchSuspended_apply, hb1, hc, hb2] at this
        rw [hpre_d] at this; injection this with eq; rw [eq]
      · obtain ⟨callerVpId, callerPrev⟩ := p
        have hp' :
            (switchSuspended_apply s caller toHandle toVpId core calleeDom calleeVp).domains.find?
              did = some d' := hpost
        simp only [switchSuspended_apply, hb1, hc, hb2,
                   SpecState.updCore, SpecState.updDomain] at hp'
        -- Outer: updDomain caller
        by_cases hd1 : did = caller
        · rw [hd1] at hp' hpre_d
          rw [Arena.find?_update_eq_map] at hp'
          by_cases hd2 : caller = calleeDom
          · rw [← hd2] at hp'
            rw [Arena.find?_update_eq_map] at hp'
            by_cases hd3 : caller = dc.targetDom
            · rw [← hd3] at hp'
              rw [Arena.find?_update_eq_map] at hp'
              rw [hpre_d] at hp'; simp at hp'; rw [← hp']
              rw [Domain.updVp_parent, Domain.updVp_parent, Domain.updVp_parent]
            · rw [Arena.find?_update_other _ dc.targetDom caller _ hd3] at hp'
              rw [hpre_d] at hp'; simp at hp'; rw [← hp']
              rw [Domain.updVp_parent, Domain.updVp_parent]
          · rw [Arena.find?_update_other _ calleeDom caller _ hd2] at hp'
            by_cases hd3 : caller = dc.targetDom
            · rw [← hd3] at hp'
              rw [Arena.find?_update_eq_map] at hp'
              rw [hpre_d] at hp'; simp at hp'; rw [← hp']
              rw [Domain.updVp_parent, Domain.updVp_parent]
            · rw [Arena.find?_update_other _ dc.targetDom caller _ hd3] at hp'
              rw [hpre_d] at hp'; simp at hp'; rw [← hp']
              exact Domain.updVp_parent _ _ _
        · rw [Arena.find?_update_other _ caller did _ hd1] at hp'
          by_cases hd2 : did = calleeDom
          · subst hd2
            rw [Arena.find?_update_eq_map] at hp'
            by_cases hd3 : did = dc.targetDom
            · subst hd3
              rw [Arena.find?_update_eq_map] at hp'
              rw [hpre_d] at hp'; simp at hp'; rw [← hp']
              rw [Domain.updVp_parent, Domain.updVp_parent]
            · rw [Arena.find?_update_other _ dc.targetDom did _ hd3] at hp'
              rw [hpre_d] at hp'; simp at hp'; rw [← hp']
              exact Domain.updVp_parent _ _ _
          · rw [Arena.find?_update_other _ calleeDom did _ hd2] at hp'
            by_cases hd3 : did = dc.targetDom
            · subst hd3
              rw [Arena.find?_update_eq_map] at hp'
              rw [hpre_d] at hp'; simp at hp'; rw [← hp']
              exact Domain.updVp_parent _ _ _
            · rw [Arena.find?_update_other _ dc.targetDom did _ hd3] at hp'
              rw [hpre_d] at hp'; injection hp' with eq; rw [eq]

/-- `addVp_apply` preserves parents. -/
theorem addVp_apply_preservesParents
    (caller : DomId) (childHandle commHandle : LocalHandle) :
    PreservesParents (fun s => addVp_apply s caller childHandle commHandle) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hb1 : (s.getDom caller).bind (fun d => d.lookupDomHandle childHandle) with _ | cid
  · have : (addVp_apply s caller childHandle commHandle).domains.find? did = some d' := hpost
    simp [addVp_apply, hb1] at this
    rw [hpre_d] at this; injection this with eq; rw [eq]
  · rcases hc : s.getDomCap cid with _ | dc
    · have : (addVp_apply s caller childHandle commHandle).domains.find? did = some d' := hpost
      simp [addVp_apply, hb1, hc] at this
      rw [hpre_d] at this; injection this with eq; rw [eq]
    · rcases ht : s.getDom dc.targetDom with _ | cd
      · have : (addVp_apply s caller childHandle commHandle).domains.find? did = some d' :=
          hpost
        simp [addVp_apply, hb1, hc, ht] at this
        rw [hpre_d] at this; injection this with eq; rw [eq]
      · rcases hb2 : (s.getDom caller).bind (fun d => d.lookupMemHandle commHandle) with _ | mid
        · have : (addVp_apply s caller childHandle commHandle).domains.find? did = some d' :=
            hpost
          simp [addVp_apply, hb1, hc, ht, hb2] at this
          rw [hpre_d] at this; injection this with eq; rw [eq]
        · have hp' :
              (addVp_apply s caller childHandle commHandle).domains.find? did = some d' := hpost
          simp only [addVp_apply, hb1, hc, ht, hb2, SpecState.updMem, SpecState.updDomain] at hp'
          by_cases hd : did = dc.targetDom
          · subst hd
            rw [Arena.find?_update_eq_map] at hp'
            rw [hpre_d] at hp'; simp at hp'; rw [← hp']
          · rw [Arena.find?_update_other _ dc.targetDom did _ hd] at hp'
            rw [hpre_d] at hp'; injection hp' with eq; rw [eq]

/-- `registerComm_apply` preserves parents. -/
theorem registerComm_apply_preservesParents
    (caller : DomId) (commHandle childHandle : LocalHandle) (vpId : VpId) :
    PreservesParents (fun s => registerComm_apply s caller commHandle childHandle vpId) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hb1 : (s.getDom caller).bind (fun d => d.lookupDomHandle childHandle) with _ | cid
  · have :
        (registerComm_apply s caller commHandle childHandle vpId).domains.find? did = some d' :=
      hpost
    simp [registerComm_apply, hb1] at this
    rw [hpre_d] at this; injection this with eq; rw [eq]
  · rcases hc : s.getDomCap cid with _ | dc
    · have :
          (registerComm_apply s caller commHandle childHandle vpId).domains.find? did = some d' :=
        hpost
      simp [registerComm_apply, hb1, hc] at this
      rw [hpre_d] at this; injection this with eq; rw [eq]
    · rcases ht : s.getDom dc.targetDom with _ | cd
      · have :
            (registerComm_apply s caller commHandle childHandle vpId).domains.find? did =
              some d' := hpost
        simp [registerComm_apply, hb1, hc, ht] at this
        rw [hpre_d] at this; injection this with eq; rw [eq]
      · rcases hb2 : (s.getDom caller).bind (fun d => d.lookupMemHandle commHandle) with _ | mid
        · have :
              (registerComm_apply s caller commHandle childHandle vpId).domains.find? did =
                some d' := hpost
          simp [registerComm_apply, hb1, hc, ht, hb2] at this
          rw [hpre_d] at this; injection this with eq; rw [eq]
        · have hp' :
              (registerComm_apply s caller commHandle childHandle vpId).domains.find? did =
                some d' := hpost
          simp only [registerComm_apply, hb1, hc, ht, hb2,
                     SpecState.updMem, SpecState.updDomain] at hp'
          by_cases hd : did = dc.targetDom
          · subst hd
            rw [Arena.find?_update_eq_map] at hp'
            rw [hpre_d] at hp'; simp at hp'; rw [← hp']
          · rw [Arena.find?_update_other _ dc.targetDom did _ hd] at hp'
            rw [hpre_d] at hp'; injection hp' with eq; rw [eq]

/-! ## `ParentStable` — combined predicate closed under composition -/

/-- A state-transformer is "parent-stable" if it both preserves parent
    pointers and never removes a domain. This combination is closed
    under composition without side conditions, which is essential for
    inductive proofs over chains (e.g., `applyMidsAndHandler`). -/
structure ParentStable (g : SpecState → SpecState) : Prop where
  preserves    : PreservesParents g
  neverRemoves : NeverRemovesDomain g

theorem ParentStable.id : ParentStable (fun s => s) :=
  ⟨PreservesParents.id, NeverRemovesDomain.id⟩

theorem ParentStable.comp {g h : SpecState → SpecState}
    (hg : ParentStable g) (hh : ParentStable h) :
    ParentStable (fun s => h (g s)) :=
  ⟨PreservesParents.comp_no_remove hg.neverRemoves hg.preserves hh.preserves,
   fun s did hh' => hh.neverRemoves _ _ (hg.neverRemoves _ _ hh')⟩

theorem updDomain_parentStable (target : DomId) (f : Domain → Domain)
    (hf : ∀ d, (f d).parent = d.parent) :
    ParentStable (fun s => s.updDomain target f) :=
  ⟨updDomain_preservesParents target f hf, updDomain_neverRemoves target f⟩

theorem updMem_parentStable (id : MemCapId) (f : MemCap → MemCap) :
    ParentStable (fun s => s.updMem id f) :=
  ⟨updMem_preservesParents id f, updMem_neverRemoves id f⟩

theorem updCore_parentStable (id : CoreId) (f : CoreState → CoreState) :
    ParentStable (fun s => s.updCore id f) :=
  ⟨updCore_preservesParents id f, updCore_neverRemoves id f⟩

/-- `applyMidsAndHandler` is parent-stable for any chain. -/
theorem applyMidsAndHandler_parentStable (core : CoreId) (vector : Nat) :
    ∀ (chain : List (DomId × VpId)) (prev : DomId × VpId),
      ParentStable (fun s => applyMidsAndHandler core vector prev chain s) := by
  intro chain
  induction chain with
  | nil =>
    intro prev
    -- nil branch: identity.
    refine ⟨?_, ?_⟩
    · intro s did d d' hpre hpost
      simp [applyMidsAndHandler] at hpost
      rw [hpre] at hpost; injection hpost with eq; rw [eq]
    · intro s did h
      simp [applyMidsAndHandler]; exact h
  | cons head tail ih =>
    intro prev
    cases tail with
    | nil =>
      -- single-element [handler]: one updDomain head.1.
      have base :
          ParentStable (fun s => s.updDomain head.1
            (fun d => d.updVp head.2 (fun vp =>
              match vp.runState with
              | .locked _ _ p => { vp with runState := .running core p }
              | other         => { vp with runState := other }))) :=
        updDomain_parentStable head.1 _
          (fun d => Domain.updVp_parent d head.2 _)
      refine ⟨?_, ?_⟩
      · intro s did d d' hpre hpost
        simp only [applyMidsAndHandler] at hpost
        exact base.preserves s did d d' hpre hpost
      · intro s did h
        simp only [applyMidsAndHandler]
        exact base.neverRemoves s did h
    | cons head' tail' =>
      -- mid :: rest: outer updDomain head.1, then recurse on (head' :: tail') with prev = head.
      have base :
          ParentStable (fun s => s.updDomain head.1
            (fun d => d.updVp head.2 (fun vp =>
              { vp with runState := .suspended prev.1 prev.2 vector }))) :=
        updDomain_parentStable head.1 _
          (fun d => Domain.updVp_parent d head.2 _)
      have rec_step :
          ParentStable (fun s =>
            applyMidsAndHandler core vector head (head' :: tail') s) :=
        ih head
      have combined : ParentStable (fun s =>
          applyMidsAndHandler core vector head (head' :: tail')
            (s.updDomain head.1
              (fun d => d.updVp head.2 (fun vp =>
                { vp with runState := .suspended prev.1 prev.2 vector })))) :=
        ParentStable.comp base rec_step
      refine ⟨?_, ?_⟩
      · intro s did d d' hpre hpost
        simp only [applyMidsAndHandler] at hpost
        exact combined.preserves s did d d' hpre hpost
      · intro s did h
        simp only [applyMidsAndHandler]
        exact combined.neverRemoves s did h

/-- `deliverInterrupt_apply` preserves parents. -/
theorem deliverInterrupt_apply_preservesParents
    (interrupted handler : DomId) (core : CoreId) (vector : Nat)
    (chain : List (DomId × VpId)) :
    PreservesParents (fun s =>
      deliverInterrupt_apply s interrupted handler core vector chain) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  cases chain with
  | nil =>
    have : (deliverInterrupt_apply s interrupted handler core vector []).domains.find? did
        = some d' := hpost
    simp [deliverInterrupt_apply] at this
    rw [hpre_d] at this; injection this with eq; rw [eq]
  | cons head tail =>
    cases tail with
    | nil =>
      have :
          (deliverInterrupt_apply s interrupted handler core vector [head]).domains.find? did
            = some d' := hpost
      simp [deliverInterrupt_apply] at this
      rw [hpre_d] at this; injection this with eq; rw [eq]
    | cons head' tail' =>
      -- Build the parent-stable composition for the body.
      let leaf := head
      have leafStable :
          ParentStable (fun s => s.updDomain leaf.1
            (fun d => d.updVp leaf.2 (fun vp =>
              { vp with runState := .interrupted vector }))) :=
        updDomain_parentStable leaf.1 _
          (fun d => Domain.updVp_parent d leaf.2 _)
      have midsStable :
          ParentStable (fun s =>
            applyMidsAndHandler core vector leaf (head' :: tail') s) :=
        applyMidsAndHandler_parentStable core vector (head' :: tail') leaf
      have body : ParentStable (fun s =>
          applyMidsAndHandler core vector leaf (head' :: tail')
            (s.updDomain leaf.1
              (fun d => d.updVp leaf.2 (fun vp =>
                { vp with runState := .interrupted vector })))) :=
        ParentStable.comp leafStable midsStable
      have hp' :
          (deliverInterrupt_apply s interrupted handler core vector
            (leaf :: head' :: tail')).domains.find? did = some d' := hpost
      -- Now examine the trailing `match chain.getLast? with`.
      simp only [deliverInterrupt_apply] at hp'
      rcases hgl : (leaf :: head' :: tail' : List (DomId × VpId)).getLast? with _ | hpair
      · rw [hgl] at hp'
        exact body.preserves s did d d' hpre hp'
      · obtain ⟨hDom, hVp⟩ := hpair
        rw [hgl] at hp'
        -- final layer: updCore (no domain change)
        have core_layer : ParentStable (fun s => s.updCore core (fun _ =>
            CoreState.runningDomain hDom hVp)) :=
          updCore_parentStable _ _
        have full : ParentStable (fun s =>
            (applyMidsAndHandler core vector leaf (head' :: tail')
              (s.updDomain leaf.1
                (fun d => d.updVp leaf.2 (fun vp =>
                  { vp with runState := .interrupted vector })))).updCore core
                    (fun _ => CoreState.runningDomain hDom hVp)) :=
          ParentStable.comp body core_layer
        exact full.preserves s did d d' hpre hp'

/-! ## Special cases: `create` and `revokeDomain`

`create` allocates a fresh domain at `s.nextDomId`. The fresh-counter
invariant (`FreshDomCounter`, part of `WellFormed`) ensures
`s.getDom s.nextDomId = none`, so the theorem's precondition cannot
be met at the new id and no contradiction arises. For all other ids,
only `caller` is touched by record-update preserving parent.

`revokeDomain` removes the target domain from the arena. For did =
target, `s'.getDom did = none`, so the post-state hypothesis fails
vacuously. For all other ids, only `caller` is touched. -/

/-- `create_apply` preserves parents, given `FreshDomCounter`. -/
theorem create_apply_preservesParents_of_wf
    (caller : DomId) (policy : DomainPolicy) {s : SpecState}
    (hfresh : FreshDomCounter s)
    {did : DomId} {d d' : Domain}
    (hpre  : s.getDom did = some d)
    (hpost : (create_apply s caller policy).getDom did = some d') :
    d'.parent = d.parent := by
  have hpre_d : s.domains.find? did = some d := hpre
  -- did ≠ s.nextDomId because did is a domain key, hence < s.nextDomId.
  have hdid_in : did ∈ s.domains.keys := Arena.mem_keys_of_find?_some _ _ _ hpre_d
  have hdid_ne : did ≠ s.nextDomId := by
    intro heq
    have := hfresh did hdid_in
    rw [heq] at this; exact Nat.lt_irrefl _ this
  have hp' : (create_apply s caller policy).domains.find? did = some d' := hpost
  simp only [create_apply, SpecState.freshDom, SpecState.freshDomCap,
             SpecState.updDomain] at hp'
  by_cases hdid : did = caller
  · subst hdid
    rw [Arena.find?_update_eq_map] at hp'
    rw [Arena.find?_insert_other _ s.nextDomId did _ hdid_ne] at hp'
    rw [hpre_d] at hp'; simp at hp'; rw [← hp']
  · rw [Arena.find?_update_other _ caller did _ hdid] at hp'
    rw [Arena.find?_insert_other _ s.nextDomId did _ hdid_ne] at hp'
    rw [hpre_d] at hp'; injection hp' with eq; rw [eq]

/-- `revokeDomain_apply` preserves parents. -/
theorem revokeDomain_apply_preservesParents (caller : DomId) (handle : LocalHandle) :
    PreservesParents (fun s => revokeDomain_apply s caller handle) := by
  intro s did d d' hpre hpost
  have hpre_d : s.domains.find? did = some d := hpre
  rcases hcd : s.getDom caller with _ | dc
  · have : (revokeDomain_apply s caller handle).domains.find? did = some d' := hpost
    simp [revokeDomain_apply, hcd] at this
    rw [hpre_d] at this; injection this with eq; rw [eq]
  · rcases hh : dc.lookupDomHandle handle with _ | dcId
    · have : (revokeDomain_apply s caller handle).domains.find? did = some d' := hpost
      simp [revokeDomain_apply, hcd, hh] at this
      rw [hpre_d] at this; injection this with eq; rw [eq]
    · rcases hdc : s.getDomCap dcId with _ | domcap
      · have : (revokeDomain_apply s caller handle).domains.find? did = some d' := hpost
        simp [revokeDomain_apply, hcd, hh, hdc] at this
        rw [hpre_d] at this; injection this with eq; rw [eq]
      · -- success branch: state = (s with domains := domains.remove target,
        -- domcaps := domcaps.remove dcId).updDomain caller f.
        let target := domcap.targetDom
        have hp' : (revokeDomain_apply s caller handle).domains.find? did = some d' := hpost
        simp only [revokeDomain_apply, hcd, hh, hdc, SpecState.updDomain] at hp'
        -- The intermediate state's `domains` is `s.domains.remove target`.
        by_cases hdid_target : did = target
        · -- removed: s'.find? did = none, contradiction with hpost.
          rw [hdid_target] at hp' hpre_d
          by_cases hdc' : target = caller
          · rw [← hdc'] at hp'
            rw [Arena.find?_update_eq_map] at hp'
            rw [Arena.find?_remove_same] at hp'
            simp at hp'
          · rw [Arena.find?_update_other _ caller target _ hdc'] at hp'
            rw [Arena.find?_remove_same] at hp'
            cases hp'
        · by_cases hdc : did = caller
          · subst hdc
            rw [Arena.find?_update_eq_map] at hp'
            rw [Arena.find?_remove_other _ target did hdid_target] at hp'
            rw [hpre_d] at hp'; simp at hp'; rw [← hp']
          · rw [Arena.find?_update_other _ caller did _ hdc] at hp'
            rw [Arena.find?_remove_other _ target did hdid_target] at hp'
            rw [hpre_d] at hp'; injection hp' with eq; rw [eq]

/-! ## Top-level theorem: `step` preserves parent pointers -/

/-- **Parent immutability under `step`.**

    Once a domain has been allocated, its `parent` field never changes.
    For any well-formed state `s` and any step `s ⟶[a] s'`, if a domain
    `did` exists in both `s` and `s'`, its `parent` field is identical. -/
theorem step_parent_immutable
    {s s' : SpecState} {a : Action} (hwf : WellFormed s) (hstep : step s a s')
    {did : DomId} {d d' : Domain}
    (hpre  : s.getDom did = some d)
    (hpost : s'.getDom did = some d') :
    d'.parent = d.parent := by
  cases hstep with
  | carve _             => exact carve_apply_preservesParents             _ _ _ _ s did d d' hpre hpost
  | alias _             => exact alias_apply_preservesParents             _ _ _ s did d d' hpre hpost
  | revoke _            => exact revoke_apply_preservesParents            _ _ s did d d' hpre hpost
  | send _              => exact send_apply_preservesParents              _ _ _ s did d d' hpre hpost
  | «seal» _            => exact seal_apply_preservesParents              _ _ s did d d' hpre hpost
  | accept _            => exact accept_apply_preservesParents            _ _ s did d d' hpre hpost
  | reject _            => exact reject_apply_preservesParents            _ _ s did d d' hpre hpost
  | sealedSend _        => exact sealedSend_apply_preservesParents        _ _ _ _ s did d d' hpre hpost
  | create _            => exact create_apply_preservesParents_of_wf      _ _ hwf.freshDomCounter hpre hpost
  | revokeDomain _      => exact revokeDomain_apply_preservesParents      _ _ s did d d' hpre hpost
  | setPolicy _         => exact setPolicy_apply_preservesParents         _ _ _ _ s did d d' hpre hpost
  | sendChannel _       => exact sendChannel_apply_preservesParents       _ _ _ s did d d' hpre hpost
  | acceptChannel _     => exact acceptChannel_apply_preservesParents     _ _ s did d d' hpre hpost
  | rejectChannel _     => exact rejectChannel_apply_preservesParents     _ _ s did d d' hpre hpost
  | switchReturn _      => exact switchReturn_apply_preservesParents      _ _ _ s did d d' hpre hpost
  | switch _            => exact switch_apply_preservesParents            _ _ _ _ s did d d' hpre hpost
  | deliverInterrupt _  => exact deliverInterrupt_apply_preservesParents  _ _ _ _ _ s did d d' hpre hpost
  | addVp _             => exact addVp_apply_preservesParents             _ _ _ s did d d' hpre hpost
  | registerComm _      => exact registerComm_apply_preservesParents      _ _ _ _ s did d d' hpre hpost
  | switchSuspended _   => exact switchSuspended_apply_preservesParents   _ _ _ _ _ _ s did d d' hpre hpost
  | mapSelf _           => exact mapSelf_apply_preservesParents           _ _ _ s did d d' hpre hpost

end ThemisCapa
