/-
  ThemisCapa.RevokeHelpers — Framing lemmas for the S4 subtree-cascading
  `revokeDomain_apply`.

  This file proves the *axis-preservation* core: any domain surviving
  one call to `revokeOneDomain s did'` has the same `parent`, `policy`,
  `status`, `vps`, `memHandles`, `domHandles`, and `commBindings`
  fields as in the pre-state. (Only `childrenDoms` may shrink, when
  the surviving domain happens to be `did'`'s parent.)

  This lemma lifts trivially to the full subtree fold and is the
  scaffolding for `revokeDomain_preserves{PolicyMonotonicAncestry,
  CoreAffinity, FreshPending, …}`.
-/
import ThemisCapa.Step
import ThemisCapa.Arena
import ThemisCapa.State

namespace ThemisCapa

/-! ## `revokeOneMemCap` — never touches the domain arena -/

theorem revokeOneMemCap_domains_eq (s : SpecState) (mid : MemCapId) :
    (revokeOneMemCap s mid).domains = s.domains := by
  unfold revokeOneMemCap
  repeat' (first | split | rfl | rename_i _; simp [SpecState.updMem])

theorem revokeOneMemCap_domcaps_eq (s : SpecState) (mid : MemCapId) :
    (revokeOneMemCap s mid).domcaps = s.domcaps := by
  unfold revokeOneMemCap
  repeat' (first | split | rfl | rename_i _; simp [SpecState.updMem])

theorem foldl_revokeOneMemCap_domains_eq
    (s : SpecState) (mids : List MemCapId) :
    (mids.foldl revokeOneMemCap s).domains = s.domains := by
  induction mids generalizing s with
  | nil => rfl
  | cons _ rest ih => simp only [List.foldl_cons]; rw [ih, revokeOneMemCap_domains_eq]

theorem foldl_revokeOneMemCap_domcaps_eq
    (s : SpecState) (mids : List MemCapId) :
    (mids.foldl revokeOneMemCap s).domcaps = s.domcaps := by
  induction mids generalizing s with
  | nil => rfl
  | cons _ rest ih => simp only [List.foldl_cons]; rw [ih, revokeOneMemCap_domcaps_eq]

/-! ## `cancelChannelIfPending` — only `pendingDomCaps` / `frozenHandles` -/

private def cancelChannelStep (cap : DomCapId) (acc : SpecState)
    (entry : DomId × Domain) : SpecState :=
  match entry.2.pendingDomCaps.find? (fun p => p.2.capId = cap) with
  | none           => acc
  | some (_pid, pe) =>
    let acc₁ := acc.updDomain entry.1 (fun rd =>
      { rd with pendingDomCaps :=
          rd.pendingDomCaps.filter (fun p => p.2.capId ≠ cap) })
    acc₁.updDomain pe.senderDomainId (fun sd =>
      { sd with frozenHandles :=
          sd.frozenHandles.filter (· ≠ pe.senderHandle) })

theorem cancelChannelIfPending_eq_foldl (s : SpecState) (cap : DomCapId) :
    cancelChannelIfPending s cap =
      s.domains.entries.foldl (cancelChannelStep cap) s := rfl

private theorem cancelChannelStep_domcaps
    (cap : DomCapId) (acc : SpecState) (entry : DomId × Domain) :
    (cancelChannelStep cap acc entry).domcaps = acc.domcaps := by
  unfold cancelChannelStep
  cases entry.2.pendingDomCaps.find? (fun p => p.2.capId = cap) with
  | none => rfl
  | some pidpe => obtain ⟨_, _⟩ := pidpe; rfl

private theorem cancelChannelStep_memcaps
    (cap : DomCapId) (acc : SpecState) (entry : DomId × Domain) :
    (cancelChannelStep cap acc entry).memcaps = acc.memcaps := by
  unfold cancelChannelStep
  cases entry.2.pendingDomCaps.find? (fun p => p.2.capId = cap) with
  | none => rfl
  | some pidpe => obtain ⟨_, _⟩ := pidpe; rfl

theorem cancelChannelIfPending_domcaps_eq
    (s : SpecState) (cap : DomCapId) :
    (cancelChannelIfPending s cap).domcaps = s.domcaps := by
  rw [cancelChannelIfPending_eq_foldl]
  induction s.domains.entries generalizing s with
  | nil => rfl
  | cons entry rest ih =>
    simp only [List.foldl_cons]
    rw [ih, cancelChannelStep_domcaps]

theorem cancelChannelIfPending_memcaps_eq
    (s : SpecState) (cap : DomCapId) :
    (cancelChannelIfPending s cap).memcaps = s.memcaps := by
  rw [cancelChannelIfPending_eq_foldl]
  induction s.domains.entries generalizing s with
  | nil => rfl
  | cons entry rest ih =>
    simp only [List.foldl_cons]
    rw [ih, cancelChannelStep_memcaps]

/-! ## `clearCommBindings` — only `region.attributes`/`region.commBinding` -/

theorem clearCommBindings_domains_eq (s : SpecState) (cbs : List MemCapId) :
    (clearCommBindings s cbs).domains = s.domains := by
  unfold clearCommBindings
  induction cbs generalizing s with
  | nil => rfl
  | cons _ rest ih => simp only [List.foldl_cons]; rw [ih]; rfl

theorem clearCommBindings_domcaps_eq (s : SpecState) (cbs : List MemCapId) :
    (clearCommBindings s cbs).domcaps = s.domcaps := by
  unfold clearCommBindings
  induction cbs generalizing s with
  | nil => rfl
  | cons _ rest ih => simp only [List.foldl_cons]; rw [ih]; rfl

/-! ## Survivor lemmas for `revokeOneDomain`

For any domain that survives a single `revokeOneDomain s did'`
(i.e. lookups still return `some d`), the **policy, parent, status,
vps** fields agree with the pre-state. Channel cancellation only
touches `pendingDomCaps`/`frozenHandles`; the parent's `childrenDoms`
patch leaves the four axes alone. -/

/-- Generic: `updDomain` with a function that preserves the four axes
    transports those axes through `getDom`. -/
theorem updDomain_dom_axes
    (s : SpecState) (id : DomId) (f : Domain → Domain)
    (hf : ∀ d, (f d).policy = d.policy ∧ (f d).parent = d.parent ∧
                (f d).status = d.status ∧ (f d).vps = d.vps)
    (did : DomId) (d : Domain)
    (h : (s.updDomain id f).getDom did = some d) :
    ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.policy = d.policy ∧ d_pre.parent = d.parent ∧
      d_pre.status = d.status ∧ d_pre.vps = d.vps := by
  by_cases hne : did = id
  · subst hne
    simp only [SpecState.getDom, SpecState.updDomain] at h
    rcases hs : s.domains.find? did with _ | d_pre
    · rw [Arena.find?_update_eq_map, hs] at h; cases h
    · rw [Arena.find?_update_same _ _ _ hs] at h
      have heq := Option.some.inj h
      have ⟨hp, hpar, hst, hv⟩ := hf d_pre
      refine ⟨d_pre, hs, ?_, ?_, ?_, ?_⟩
      · rw [← heq]; exact hp.symm
      · rw [← heq]; exact hpar.symm
      · rw [← heq]; exact hst.symm
      · rw [← heq]; exact hv.symm
  · simp only [SpecState.getDom, SpecState.updDomain] at h
    rw [Arena.find?_update_other _ _ _ _ hne] at h
    exact ⟨d, h, rfl, rfl, rfl, rfl⟩

/-- One `cancelChannelStep` preserves `policy`/`parent`/`status`/`vps`
    for any domain. -/
private theorem cancelChannelStep_dom_axes
    (cap : DomCapId) (acc : SpecState) (entry : DomId × Domain)
    (did : DomId) (d : Domain)
    (h : (cancelChannelStep cap acc entry).getDom did = some d) :
    ∃ d_pre, acc.getDom did = some d_pre ∧
      d_pre.policy = d.policy ∧ d_pre.parent = d.parent ∧
      d_pre.status = d.status ∧ d_pre.vps = d.vps := by
  unfold cancelChannelStep at h
  rcases hfind : entry.2.pendingDomCaps.find? (fun p => p.2.capId = cap) with _ | ⟨_pid, pe⟩
  · rw [hfind] at h
    exact ⟨d, h, rfl, rfl, rfl, rfl⟩
  · rw [hfind] at h
    -- Apply updDomain_dom_axes twice (sender then receiver).
    obtain ⟨d_mid, h_mid, hp1, hpar1, hst1, hv1⟩ :=
      updDomain_dom_axes _ pe.senderDomainId
        (fun sd => { sd with frozenHandles :=
                      sd.frozenHandles.filter (· ≠ pe.senderHandle) })
        (fun _ => ⟨rfl, rfl, rfl, rfl⟩) did d h
    obtain ⟨d_pre, h_pre, hp2, hpar2, hst2, hv2⟩ :=
      updDomain_dom_axes acc entry.1
        (fun rd => { rd with pendingDomCaps :=
                      rd.pendingDomCaps.filter (fun p => p.2.capId ≠ cap) })
        (fun _ => ⟨rfl, rfl, rfl, rfl⟩) did d_mid h_mid
    exact ⟨d_pre, h_pre, hp2.trans hp1, hpar2.trans hpar1, hst2.trans hst1, hv2.trans hv1⟩

private theorem foldl_cancelChannelStep_dom_axes
    (cap : DomCapId) (entries : List (DomId × Domain))
    (s : SpecState) (did : DomId) (d : Domain)
    (h : (entries.foldl (cancelChannelStep cap) s).getDom did = some d) :
    ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.policy = d.policy ∧ d_pre.parent = d.parent ∧
      d_pre.status = d.status ∧ d_pre.vps = d.vps := by
  induction entries generalizing s with
  | nil => exact ⟨d, h, rfl, rfl, rfl, rfl⟩
  | cons entry rest ih =>
    simp only [List.foldl_cons] at h
    obtain ⟨d_mid, h_mid, hp, hpar, hst, hv⟩ := ih (cancelChannelStep cap s entry) h
    obtain ⟨d_pre, h_pre, hp', hpar', hst', hv'⟩ :=
      cancelChannelStep_dom_axes cap s entry did d_mid h_mid
    exact ⟨d_pre, h_pre, hp'.trans hp, hpar'.trans hpar, hst'.trans hst, hv'.trans hv⟩

theorem cancelChannelIfPending_dom_axes
    (s : SpecState) (cap : DomCapId) (did : DomId) (d : Domain)
    (h : (cancelChannelIfPending s cap).getDom did = some d) :
    ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.policy = d.policy ∧ d_pre.parent = d.parent ∧
      d_pre.status = d.status ∧ d_pre.vps = d.vps := by
  rw [cancelChannelIfPending_eq_foldl] at h
  exact foldl_cancelChannelStep_dom_axes cap _ s did d h

/-- `revokeOneMemCap` does not touch the domain arena (transports the
    axes trivially). -/
theorem revokeOneMemCap_dom_axes
    (s : SpecState) (mid : MemCapId) (did : DomId) (d : Domain)
    (h : (revokeOneMemCap s mid).getDom did = some d) :
    ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.policy = d.policy ∧ d_pre.parent = d.parent ∧
      d_pre.status = d.status ∧ d_pre.vps = d.vps := by
  have := revokeOneMemCap_domains_eq s mid
  simp [SpecState.getDom, this] at h
  exact ⟨d, h, rfl, rfl, rfl, rfl⟩

theorem foldl_revokeOneMemCap_dom_axes
    (s : SpecState) (mids : List MemCapId) (did : DomId) (d : Domain)
    (h : (mids.foldl revokeOneMemCap s).getDom did = some d) :
    ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.policy = d.policy ∧ d_pre.parent = d.parent ∧
      d_pre.status = d.status ∧ d_pre.vps = d.vps := by
  have := foldl_revokeOneMemCap_domains_eq s mids
  simp [SpecState.getDom, this] at h
  exact ⟨d, h, rfl, rfl, rfl, rfl⟩

theorem clearCommBindings_dom_axes
    (s : SpecState) (cbs : List MemCapId) (did : DomId) (d : Domain)
    (h : (clearCommBindings s cbs).getDom did = some d) :
    ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.policy = d.policy ∧ d_pre.parent = d.parent ∧
      d_pre.status = d.status ∧ d_pre.vps = d.vps := by
  have := clearCommBindings_domains_eq s cbs
  simp [SpecState.getDom, this] at h
  exact ⟨d, h, rfl, rfl, rfl, rfl⟩

/-- The `ownedDomCaps.foldl` over channel-cancel ops preserves the four
    axes for any surviving domain. -/
theorem foldl_channelOps_dom_axes
    (caps : List DomCapId) (s : SpecState) (did : DomId) (d : Domain)
    (h : (caps.foldl (fun acc cap =>
            match acc.getDomCap cap with
            | some dc => if dc.isChannel then cancelChannelIfPending acc cap else acc
            | none    => acc) s).getDom did = some d) :
    ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.policy = d.policy ∧ d_pre.parent = d.parent ∧
      d_pre.status = d.status ∧ d_pre.vps = d.vps := by
  induction caps generalizing s with
  | nil => exact ⟨d, h, rfl, rfl, rfl, rfl⟩
  | cons cap rest ih =>
    simp only [List.foldl_cons] at h
    obtain ⟨d_mid, h_mid, hp1, hpar1, hst1, hv1⟩ := ih _ h
    rcases hdc : s.getDomCap cap with _ | dc
    · -- step s cap = s
      have hstep : (match s.getDomCap cap with
                    | some dc => if dc.isChannel then cancelChannelIfPending s cap else s
                    | none    => s) = s := by rw [hdc]
      rw [hstep] at h_mid
      exact ⟨d_mid, h_mid, hp1, hpar1, hst1, hv1⟩
    · by_cases hch : dc.isChannel
      · have hstep : (match s.getDomCap cap with
                      | some dc => if dc.isChannel then cancelChannelIfPending s cap else s
                      | none    => s) = cancelChannelIfPending s cap := by
          rw [hdc]; simp [hch]
        rw [hstep] at h_mid
        obtain ⟨d_pre, h_pre, hp2, hpar2, hst2, hv2⟩ :=
          cancelChannelIfPending_dom_axes s cap did d_mid h_mid
        exact ⟨d_pre, h_pre, hp2.trans hp1, hpar2.trans hpar1, hst2.trans hst1, hv2.trans hv1⟩
      · have hstep : (match s.getDomCap cap with
                      | some dc => if dc.isChannel then cancelChannelIfPending s cap else s
                      | none    => s) = s := by
          rw [hdc]; simp [hch]
        rw [hstep] at h_mid
        exact ⟨d_mid, h_mid, hp1, hpar1, hst1, hv1⟩

/-- **Main survivor lemma.** Any domain that survives one
    `revokeOneDomain s did'` has the same policy, parent, status, vps
    as in the pre-state, and is necessarily not `did'`. -/
theorem revokeOneDomain_dom_axes
    (s : SpecState) (did' did : DomId) (d : Domain)
    (h : (revokeOneDomain s did').getDom did = some d) :
    did ≠ did' ∧ ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.policy = d.policy ∧ d_pre.parent = d.parent ∧
      d_pre.status = d.status ∧ d_pre.vps = d.vps := by
  unfold revokeOneDomain at h
  rcases hd' : s.getDom did' with _ | d'
  · rw [hd'] at h
    refine ⟨?_, d, h, rfl, rfl, rfl, rfl⟩
    intro heq; subst heq
    rw [hd'] at h; cases h
  · rw [hd'] at h
    -- Stage 6: domain removal.
    simp only [SpecState.getDom] at h
    by_cases hne : did = did'
    · subst hne; rw [Arena.find?_remove_same] at h; cases h
    refine ⟨hne, ?_⟩
    rw [Arena.find?_remove_other _ _ _ hne] at h
    -- Re-package as a `.getDom` statement on s₅.
    -- Stage 5: parent's childrenDoms patch (or no-op).
    -- Stage 4: domcaps filter (preserves domains).
    -- Stage 3: clearCommBindings (preserves domains).
    -- Stages 1-2: memcap fold + channel-op fold (need dom_axes lemmas).
    let s_memcap := (d'.memHandles.map Prod.snd).foldl revokeOneMemCap s
    let s_chan := (d'.domHandles.map Prod.snd).foldl (fun acc cap =>
        match acc.getDomCap cap with
        | some dc => if dc.isChannel then cancelChannelIfPending acc cap else acc
        | none    => acc) s_memcap
    let s_comm := clearCommBindings s_chan d'.commBindings
    -- After stages 1-3, getDom of survivor maps back to s.
    have stages123 : ∀ {did : DomId} {d : Domain},
        s_comm.getDom did = some d →
        ∃ d_pre, s.getDom did = some d_pre ∧
          d_pre.policy = d.policy ∧ d_pre.parent = d.parent ∧
          d_pre.status = d.status ∧ d_pre.vps = d.vps := by
      intro did d hh
      obtain ⟨d3, h3, hp3, hpar3, hst3, hv3⟩ :=
        clearCommBindings_dom_axes _ _ _ _ hh
      obtain ⟨d2, h2, hp2, hpar2, hst2, hv2⟩ :=
        foldl_channelOps_dom_axes _ _ _ _ h3
      obtain ⟨d1, h1, hp1, hpar1, hst1, hv1⟩ :=
        foldl_revokeOneMemCap_dom_axes _ _ _ _ h2
      exact ⟨d1, h1, hp1.trans (hp2.trans hp3), hpar1.trans (hpar2.trans hpar3),
                     hst1.trans (hst2.trans hst3), hv1.trans (hv2.trans hv3)⟩
    -- Now handle stages 4-5.
    rcases hp : d'.parent with _ | pid
    · rw [hp] at h
      exact stages123 (show s_comm.getDom did = some d from h)
    · rw [hp] at h
      have hh : (s_comm.updDomain pid (fun pd =>
          { pd with childrenDoms := pd.childrenDoms.filter (· ≠ did') })).getDom did = some d := h
      obtain ⟨d5, h5, hp5, hpar5, hst5, hv5⟩ :=
        updDomain_dom_axes s_comm pid
          (fun pd => { pd with childrenDoms := pd.childrenDoms.filter (· ≠ did') })
          (fun _ => ⟨rfl, rfl, rfl, rfl⟩) did d hh
      obtain ⟨d_pre, h_pre, hp', hpar', hst', hv'⟩ := stages123 h5
      exact ⟨d_pre, h_pre, hp'.trans hp5, hpar'.trans hpar5,
                           hst'.trans hst5, hv'.trans hv5⟩

/-- Foldl version: any survivor of `foldl revokeOneDomain dids s` has the
    four axes equal to its pre-state value and is not in `dids`. -/
theorem foldl_revokeOneDomain_dom_axes
    (s : SpecState) (dids : List DomId) (did : DomId) (d : Domain)
    (h : (dids.foldl revokeOneDomain s).getDom did = some d) :
    did ∉ dids ∧ ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.policy = d.policy ∧ d_pre.parent = d.parent ∧
      d_pre.status = d.status ∧ d_pre.vps = d.vps := by
  induction dids generalizing s with
  | nil => exact ⟨List.not_mem_nil, d, h, rfl, rfl, rfl, rfl⟩
  | cons did' rest ih =>
    simp only [List.foldl_cons] at h
    obtain ⟨hnotin, d_mid, h_mid, hp, hpar, hst, hv⟩ := ih (revokeOneDomain s did') h
    obtain ⟨hne, d_pre, h_pre, hp', hpar', hst', hv'⟩ :=
      revokeOneDomain_dom_axes s did' did d_mid h_mid
    refine ⟨?_, d_pre, h_pre, hp'.trans hp, hpar'.trans hpar, hst'.trans hst, hv'.trans hv⟩
    simp only [List.mem_cons, not_or]
    exact ⟨hne, hnotin⟩

/-- Final survivor lemma for the public action `revokeDomain_apply`. -/
theorem revokeDomain_apply_dom_axes
    (s : SpecState) (caller : DomId) (handle : LocalHandle)
    (did : DomId) (d : Domain)
    (h : (revokeDomain_apply s caller handle).getDom did = some d) :
    ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.policy = d.policy ∧ d_pre.parent = d.parent ∧
      d_pre.status = d.status ∧ d_pre.vps = d.vps := by
  unfold revokeDomain_apply at h
  rcases hc : s.getDom caller with _ | d_c
  · rw [hc] at h; exact ⟨d, h, rfl, rfl, rfl, rfl⟩
  rw [hc] at h
  rcases hlh : d_c.lookupDomHandle handle with _ | dcId
  · simp [hlh] at h; exact ⟨d, h, rfl, rfl, rfl, rfl⟩
  simp [hlh] at h
  rcases hdcp : s.getDomCap dcId with _ | dc
  · simp [hdcp] at h; exact ⟨d, h, rfl, rfl, rfl, rfl⟩
  simp [hdcp] at h
  -- h : (foldl rev. subtree).updDomain caller (filter) .getDom did = some d
  obtain ⟨d1, h1, hp1, hpar1, hst1, hv1⟩ :=
    updDomain_dom_axes (collectSubtree s dc.targetDom |>.foldl revokeOneDomain s) caller
      (fun d => { d with domHandles := d.domHandles.filter (fun h => !decide (h.snd = dcId)) })
      (fun _ => ⟨rfl, rfl, rfl, rfl⟩) did d h
  obtain ⟨_, d_pre, h_pre, hp2, hpar2, hst2, hv2⟩ :=
    foldl_revokeOneDomain_dom_axes s (collectSubtree s dc.targetDom) did d1 h1
  exact ⟨d_pre, h_pre, hp2.trans hp1, hpar2.trans hpar1, hst2.trans hst1, hv2.trans hv1⟩

/-! ## Pending-axes helpers (for FreshPending)

The fields {pendingMemCaps, nextPendingId} are preserved by EVERY stage
of `revokeDomain_apply` for surviving domains. The field
{pendingDomCaps} is preserved by every stage except channel
cancellation, which can only filter (shrink) it. -/

/-- Generic `updDomain` lift for pending fields. -/
private theorem updDomain_pending
    (s : SpecState) (id : DomId) (f : Domain → Domain)
    (hf : ∀ d, (f d).pendingMemCaps = d.pendingMemCaps ∧
               (f d).nextPendingId = d.nextPendingId ∧
               (∀ p, p ∈ (f d).pendingDomCaps → p ∈ d.pendingDomCaps))
    (did : DomId) (d : Domain)
    (h : (s.updDomain id f).getDom did = some d) :
    ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.pendingMemCaps = d.pendingMemCaps ∧
      d_pre.nextPendingId = d.nextPendingId ∧
      (∀ p, p ∈ d.pendingDomCaps → p ∈ d_pre.pendingDomCaps) := by
  by_cases hne : did = id
  · subst hne
    simp only [SpecState.getDom, SpecState.updDomain] at h
    rcases hs : s.domains.find? did with _ | d_pre
    · rw [Arena.find?_update_eq_map, hs] at h; cases h
    · rw [Arena.find?_update_same _ _ _ hs] at h
      have heq := Option.some.inj h
      have ⟨hpm, hnp, hpd⟩ := hf d_pre
      refine ⟨d_pre, hs, ?_, ?_, ?_⟩
      · rw [← heq]; exact hpm.symm
      · rw [← heq]; exact hnp.symm
      · intro p hp; rw [← heq] at hp; exact hpd p hp
  · simp only [SpecState.getDom, SpecState.updDomain] at h
    rw [Arena.find?_update_other _ _ _ _ hne] at h
    exact ⟨d, h, rfl, rfl, fun _ hp => hp⟩

private theorem cancelChannelStep_pending
    (cap : DomCapId) (acc : SpecState) (entry : DomId × Domain)
    (did : DomId) (d : Domain)
    (h : (cancelChannelStep cap acc entry).getDom did = some d) :
    ∃ d_pre, acc.getDom did = some d_pre ∧
      d_pre.pendingMemCaps = d.pendingMemCaps ∧
      d_pre.nextPendingId = d.nextPendingId ∧
      (∀ p, p ∈ d.pendingDomCaps → p ∈ d_pre.pendingDomCaps) := by
  unfold cancelChannelStep at h
  rcases hfind : entry.2.pendingDomCaps.find? (fun p => p.2.capId = cap) with _ | ⟨_pid, pe⟩
  · rw [hfind] at h
    exact ⟨d, h, rfl, rfl, fun _ hp => hp⟩
  · rw [hfind] at h
    obtain ⟨d_mid, h_mid, hpm1, hnp1, hpd1⟩ :=
      updDomain_pending _ pe.senderDomainId
        (fun sd => { sd with frozenHandles :=
                      sd.frozenHandles.filter (· ≠ pe.senderHandle) })
        (fun _ => ⟨rfl, rfl, fun _ hp => hp⟩) did d h
    obtain ⟨d_pre, h_pre, hpm2, hnp2, hpd2⟩ :=
      updDomain_pending acc entry.1
        (fun rd => { rd with pendingDomCaps :=
                      rd.pendingDomCaps.filter (fun p => p.2.capId ≠ cap) })
        (fun rd => ⟨rfl, rfl, fun p hp => (List.mem_filter.mp hp).1⟩)
        did d_mid h_mid
    exact ⟨d_pre, h_pre, hpm2.trans hpm1, hnp2.trans hnp1,
           fun p hp => hpd2 p (hpd1 p hp)⟩

private theorem foldl_cancelChannelStep_pending
    (cap : DomCapId) (entries : List (DomId × Domain))
    (s : SpecState) (did : DomId) (d : Domain)
    (h : (entries.foldl (cancelChannelStep cap) s).getDom did = some d) :
    ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.pendingMemCaps = d.pendingMemCaps ∧
      d_pre.nextPendingId = d.nextPendingId ∧
      (∀ p, p ∈ d.pendingDomCaps → p ∈ d_pre.pendingDomCaps) := by
  induction entries generalizing s with
  | nil => exact ⟨d, h, rfl, rfl, fun _ hp => hp⟩
  | cons entry rest ih =>
    simp only [List.foldl_cons] at h
    obtain ⟨d_mid, h_mid, hpm, hnp, hpd⟩ := ih (cancelChannelStep cap s entry) h
    obtain ⟨d_pre, h_pre, hpm', hnp', hpd'⟩ :=
      cancelChannelStep_pending cap s entry did d_mid h_mid
    exact ⟨d_pre, h_pre, hpm'.trans hpm, hnp'.trans hnp,
           fun p hp => hpd' p (hpd p hp)⟩

theorem cancelChannelIfPending_pending
    (s : SpecState) (cap : DomCapId) (did : DomId) (d : Domain)
    (h : (cancelChannelIfPending s cap).getDom did = some d) :
    ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.pendingMemCaps = d.pendingMemCaps ∧
      d_pre.nextPendingId = d.nextPendingId ∧
      (∀ p, p ∈ d.pendingDomCaps → p ∈ d_pre.pendingDomCaps) := by
  rw [cancelChannelIfPending_eq_foldl] at h
  exact foldl_cancelChannelStep_pending cap _ s did d h

theorem foldl_channelOps_pending
    (caps : List DomCapId) (s : SpecState) (did : DomId) (d : Domain)
    (h : (caps.foldl (fun acc cap =>
            match acc.getDomCap cap with
            | some dc => if dc.isChannel then cancelChannelIfPending acc cap else acc
            | none    => acc) s).getDom did = some d) :
    ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.pendingMemCaps = d.pendingMemCaps ∧
      d_pre.nextPendingId = d.nextPendingId ∧
      (∀ p, p ∈ d.pendingDomCaps → p ∈ d_pre.pendingDomCaps) := by
  induction caps generalizing s with
  | nil => exact ⟨d, h, rfl, rfl, fun _ hp => hp⟩
  | cons cap rest ih =>
    simp only [List.foldl_cons] at h
    obtain ⟨d_mid, h_mid, hpm, hnp, hpd⟩ := ih _ h
    rcases hdc : s.getDomCap cap with _ | dc
    · have hstep : (match s.getDomCap cap with
                    | some dc => if dc.isChannel then cancelChannelIfPending s cap else s
                    | none    => s) = s := by rw [hdc]
      rw [hstep] at h_mid
      exact ⟨d_mid, h_mid, hpm, hnp, hpd⟩
    · by_cases hch : dc.isChannel
      · have hstep : (match s.getDomCap cap with
                      | some dc => if dc.isChannel then cancelChannelIfPending s cap else s
                      | none    => s) = cancelChannelIfPending s cap := by
          rw [hdc]; simp [hch]
        rw [hstep] at h_mid
        obtain ⟨d_pre, h_pre, hpm', hnp', hpd'⟩ :=
          cancelChannelIfPending_pending s cap did d_mid h_mid
        exact ⟨d_pre, h_pre, hpm'.trans hpm, hnp'.trans hnp,
               fun p hp => hpd' p (hpd p hp)⟩
      · have hstep : (match s.getDomCap cap with
                      | some dc => if dc.isChannel then cancelChannelIfPending s cap else s
                      | none    => s) = s := by
          rw [hdc]; simp [hch]
        rw [hstep] at h_mid
        exact ⟨d_mid, h_mid, hpm, hnp, hpd⟩

theorem revokeOneMemCap_pending
    (s : SpecState) (mid : MemCapId) (did : DomId) (d : Domain)
    (h : (revokeOneMemCap s mid).getDom did = some d) :
    ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.pendingMemCaps = d.pendingMemCaps ∧
      d_pre.nextPendingId = d.nextPendingId ∧
      (∀ p, p ∈ d.pendingDomCaps → p ∈ d_pre.pendingDomCaps) := by
  have := revokeOneMemCap_domains_eq s mid
  simp [SpecState.getDom, this] at h
  exact ⟨d, h, rfl, rfl, fun _ hp => hp⟩

theorem foldl_revokeOneMemCap_pending
    (s : SpecState) (mids : List MemCapId) (did : DomId) (d : Domain)
    (h : (mids.foldl revokeOneMemCap s).getDom did = some d) :
    ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.pendingMemCaps = d.pendingMemCaps ∧
      d_pre.nextPendingId = d.nextPendingId ∧
      (∀ p, p ∈ d.pendingDomCaps → p ∈ d_pre.pendingDomCaps) := by
  have := foldl_revokeOneMemCap_domains_eq s mids
  simp [SpecState.getDom, this] at h
  exact ⟨d, h, rfl, rfl, fun _ hp => hp⟩

theorem clearCommBindings_pending
    (s : SpecState) (cbs : List MemCapId) (did : DomId) (d : Domain)
    (h : (clearCommBindings s cbs).getDom did = some d) :
    ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.pendingMemCaps = d.pendingMemCaps ∧
      d_pre.nextPendingId = d.nextPendingId ∧
      (∀ p, p ∈ d.pendingDomCaps → p ∈ d_pre.pendingDomCaps) := by
  have := clearCommBindings_domains_eq s cbs
  simp [SpecState.getDom, this] at h
  exact ⟨d, h, rfl, rfl, fun _ hp => hp⟩

theorem revokeOneDomain_pending
    (s : SpecState) (did' did : DomId) (d : Domain)
    (h : (revokeOneDomain s did').getDom did = some d) :
    ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.pendingMemCaps = d.pendingMemCaps ∧
      d_pre.nextPendingId = d.nextPendingId ∧
      (∀ p, p ∈ d.pendingDomCaps → p ∈ d_pre.pendingDomCaps) := by
  unfold revokeOneDomain at h
  rcases hd' : s.getDom did' with _ | d'
  · rw [hd'] at h; exact ⟨d, h, rfl, rfl, fun _ hp => hp⟩
  · rw [hd'] at h
    simp only [SpecState.getDom] at h
    by_cases hne : did = did'
    · subst hne; rw [Arena.find?_remove_same] at h; cases h
    rw [Arena.find?_remove_other _ _ _ hne] at h
    let s_memcap := (d'.memHandles.map Prod.snd).foldl revokeOneMemCap s
    let s_chan := (d'.domHandles.map Prod.snd).foldl (fun acc cap =>
        match acc.getDomCap cap with
        | some dc => if dc.isChannel then cancelChannelIfPending acc cap else acc
        | none    => acc) s_memcap
    let s_comm := clearCommBindings s_chan d'.commBindings
    have stages123 : ∀ {did : DomId} {d : Domain},
        s_comm.getDom did = some d →
        ∃ d_pre, s.getDom did = some d_pre ∧
          d_pre.pendingMemCaps = d.pendingMemCaps ∧
          d_pre.nextPendingId = d.nextPendingId ∧
          (∀ p, p ∈ d.pendingDomCaps → p ∈ d_pre.pendingDomCaps) := by
      intro did d hh
      obtain ⟨d3, h3, hpm3, hnp3, hpd3⟩ := clearCommBindings_pending _ _ _ _ hh
      obtain ⟨d2, h2, hpm2, hnp2, hpd2⟩ := foldl_channelOps_pending _ _ _ _ h3
      obtain ⟨d1, h1, hpm1, hnp1, hpd1⟩ := foldl_revokeOneMemCap_pending _ _ _ _ h2
      exact ⟨d1, h1, hpm1.trans (hpm2.trans hpm3), hnp1.trans (hnp2.trans hnp3),
             fun p hp => hpd1 p (hpd2 p (hpd3 p hp))⟩
    rcases hp : d'.parent with _ | pid
    · rw [hp] at h
      exact stages123 (show s_comm.getDom did = some d from h)
    · rw [hp] at h
      have hh : (s_comm.updDomain pid (fun pd =>
          { pd with childrenDoms := pd.childrenDoms.filter (· ≠ did') })).getDom did = some d := h
      obtain ⟨d5, h5, hpm5, hnp5, hpd5⟩ :=
        updDomain_pending s_comm pid
          (fun pd => { pd with childrenDoms := pd.childrenDoms.filter (· ≠ did') })
          (fun _ => ⟨rfl, rfl, fun _ hp => hp⟩) did d hh
      obtain ⟨d_pre, h_pre, hpm', hnp', hpd'⟩ := stages123 h5
      exact ⟨d_pre, h_pre, hpm'.trans hpm5, hnp'.trans hnp5,
             fun p hp => hpd' p (hpd5 p hp)⟩

theorem foldl_revokeOneDomain_pending
    (s : SpecState) (dids : List DomId) (did : DomId) (d : Domain)
    (h : (dids.foldl revokeOneDomain s).getDom did = some d) :
    ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.pendingMemCaps = d.pendingMemCaps ∧
      d_pre.nextPendingId = d.nextPendingId ∧
      (∀ p, p ∈ d.pendingDomCaps → p ∈ d_pre.pendingDomCaps) := by
  induction dids generalizing s with
  | nil => exact ⟨d, h, rfl, rfl, fun _ hp => hp⟩
  | cons did' rest ih =>
    simp only [List.foldl_cons] at h
    obtain ⟨d_mid, h_mid, hpm, hnp, hpd⟩ := ih (revokeOneDomain s did') h
    obtain ⟨d_pre, h_pre, hpm', hnp', hpd'⟩ :=
      revokeOneDomain_pending s did' did d_mid h_mid
    exact ⟨d_pre, h_pre, hpm'.trans hpm, hnp'.trans hnp,
           fun p hp => hpd' p (hpd p hp)⟩

theorem revokeDomain_apply_pending
    (s : SpecState) (caller : DomId) (handle : LocalHandle)
    (did : DomId) (d : Domain)
    (h : (revokeDomain_apply s caller handle).getDom did = some d) :
    ∃ d_pre, s.getDom did = some d_pre ∧
      d_pre.pendingMemCaps = d.pendingMemCaps ∧
      d_pre.nextPendingId = d.nextPendingId ∧
      (∀ p, p ∈ d.pendingDomCaps → p ∈ d_pre.pendingDomCaps) := by
  unfold revokeDomain_apply at h
  rcases hc : s.getDom caller with _ | d_c
  · rw [hc] at h; exact ⟨d, h, rfl, rfl, fun _ hp => hp⟩
  rw [hc] at h
  rcases hlh : d_c.lookupDomHandle handle with _ | dcId
  · simp [hlh] at h; exact ⟨d, h, rfl, rfl, fun _ hp => hp⟩
  simp [hlh] at h
  rcases hdcp : s.getDomCap dcId with _ | dc
  · simp [hdcp] at h; exact ⟨d, h, rfl, rfl, fun _ hp => hp⟩
  simp [hdcp] at h
  obtain ⟨d1, h1, hpm1, hnp1, hpd1⟩ :=
    updDomain_pending (collectSubtree s dc.targetDom |>.foldl revokeOneDomain s) caller
      (fun d => { d with domHandles := d.domHandles.filter (fun h => !decide (h.snd = dcId)) })
      (fun _ => ⟨rfl, rfl, fun _ hp => hp⟩) did d h
  obtain ⟨d_pre, h_pre, hpm2, hnp2, hpd2⟩ :=
    foldl_revokeOneDomain_pending s (collectSubtree s dc.targetDom) did d1 h1
  exact ⟨d_pre, h_pre, hpm2.trans hpm1, hnp2.trans hnp1,
         fun p hp => hpd2 p (hpd1 p hp)⟩

/-! ## Survivor full-equality lemmas (S4 Locality frame support)

These lemmas extend the per-axis survivor pattern to **full record
equality** for domains/memcaps outside the cascade footprint. They are
the building blocks for `Locality.revokeDomain_frame_dom` and
`revokeDomain_frame_mem`. -/

/-- `updDomain f` at `id` leaves any other domain's record unchanged. -/
theorem updDomain_other_eq (s : SpecState) (id : DomId) (f : Domain → Domain)
    (did : DomId) (hne : did ≠ id) :
    (s.updDomain id f).getDom did = s.getDom did := by
  simp only [SpecState.getDom, SpecState.updDomain]
  exact Arena.find?_update_other _ _ _ _ hne

/-- `revokeOneMemCap` never touches the domain arena. -/
theorem revokeOneMemCap_getDom_eq (s : SpecState) (mid : MemCapId) (did : DomId) :
    (revokeOneMemCap s mid).getDom did = s.getDom did := by
  simp [SpecState.getDom, revokeOneMemCap_domains_eq]

theorem foldl_revokeOneMemCap_getDom_eq
    (s : SpecState) (mids : List MemCapId) (did : DomId) :
    (mids.foldl revokeOneMemCap s).getDom did = s.getDom did := by
  simp [SpecState.getDom, foldl_revokeOneMemCap_domains_eq]

/-- `clearCommBindings` never touches the domain arena. -/
theorem clearCommBindings_getDom_eq
    (s : SpecState) (cbs : List MemCapId) (did : DomId) :
    (clearCommBindings s cbs).getDom did = s.getDom did := by
  simp [SpecState.getDom, clearCommBindings_domains_eq]

/-- `cancelChannelStep` leaves `did` untouched when, for any match on
    the pending list, `did` is neither the receiver nor the sender. -/
theorem cancelChannelStep_other_eq
    (cap : DomCapId) (acc : SpecState) (entry : DomId × Domain) (did : DomId)
    (h : ∀ pid pe, entry.2.pendingDomCaps.find? (fun p => p.2.capId = cap)
                   = some (pid, pe) → did ≠ entry.1 ∧ did ≠ pe.senderDomainId) :
    (cancelChannelStep cap acc entry).getDom did = acc.getDom did := by
  unfold cancelChannelStep
  rcases hfind : entry.2.pendingDomCaps.find? (fun p => p.2.capId = cap)
    with _ | ⟨pid, pe⟩
  · rw [hfind]
  · rw [hfind]
    obtain ⟨hRecv, hSend⟩ := h pid pe hfind
    rw [updDomain_other_eq _ pe.senderDomainId _ did hSend,
        updDomain_other_eq _ entry.1 _ did hRecv]

theorem foldl_cancelChannelStep_other_eq
    (cap : DomCapId) (entries : List (DomId × Domain))
    (s : SpecState) (did : DomId)
    (h : ∀ entry ∈ entries, ∀ pid pe,
          entry.2.pendingDomCaps.find? (fun p => p.2.capId = cap)
            = some (pid, pe) → did ≠ entry.1 ∧ did ≠ pe.senderDomainId) :
    (entries.foldl (cancelChannelStep cap) s).getDom did = s.getDom did := by
  induction entries generalizing s with
  | nil => rfl
  | cons entry rest ih =>
    simp only [List.foldl_cons]
    rw [ih _ (fun e he => h e (List.mem_cons_of_mem _ he))]
    exact cancelChannelStep_other_eq cap s entry did
            (h entry List.mem_cons_self)

/-- `cancelChannelIfPending cap` leaves `did` untouched when, for every
    entry in the domain arena, neither the holder nor the sender of
    any matching pending entry is `did`. (Premise is stated directly
    over `s.domains.entries`; downstream callers bridge from `getDom`
    via `UniqueKeys` from `WellFormed`.) -/
theorem cancelChannelIfPending_getDom_eq
    (s : SpecState) (cap : DomCapId) (did : DomId)
    (h : ∀ entry ∈ s.domains.entries, ∀ pid pe,
          entry.2.pendingDomCaps.find? (fun p => p.2.capId = cap)
            = some (pid, pe) → did ≠ entry.1 ∧ did ≠ pe.senderDomainId) :
    (cancelChannelIfPending s cap).getDom did = s.getDom did := by
  rw [cancelChannelIfPending_eq_foldl]
  exact foldl_cancelChannelStep_other_eq cap _ s did h

/-! ## `revokeOneDomain` survivor equality

Stage-wise breakdown of `revokeOneDomain s did'` (see Step.lean:816):
  1. Revoke owned memcaps — never touches domain arena.
  2. Cancel channels on owned dom-caps — may touch `did` if `did` is
     the holder or sender of a pending entry for a cancelled cap.
  3. Clear COMM bindings — never touches domain arena.
  4. Filter domcaps — never touches domain arena.
  5. Patch parent's `childrenDoms` — touches `pid` if `d.parent = some pid`.
  6. Remove `did'` from the domain arena — touches `did` iff `did = did'`.

The premises below enumerate the survivors. -/

/-- Single channel-ops step preserves `did`'s domain when no current
    pending entry for `cap` has `did` as holder or sender.

    NOTE: this is the *current-state* premise. Lifting to an
    initial-state premise that survives the channel-ops fold is left
    as a TODO (`foldl_channelOps_getDom_eq`); see the stage-2 sorry
    in `revokeOneDomain_getDom_eq` below. -/
private theorem channelOpsStep_other_eq
    (acc : SpecState) (cap : DomCapId) (did : DomId)
    (h : ∀ entry ∈ acc.domains.entries, ∀ pid pe,
          entry.2.pendingDomCaps.find? (fun p => p.2.capId = cap)
            = some (pid, pe) → did ≠ entry.1 ∧ did ≠ pe.senderDomainId) :
    (match acc.getDomCap cap with
     | some dc => if dc.isChannel then cancelChannelIfPending acc cap else acc
     | none    => acc).getDom did = acc.getDom did := by
  rcases hdc : acc.getDomCap cap with _ | dc
  · rfl
  · show (if dc.isChannel then cancelChannelIfPending acc cap else acc).getDom did
          = acc.getDom did
    by_cases hch : dc.isChannel
    · rw [if_pos hch]; exact cancelChannelIfPending_getDom_eq acc cap did h
    · rw [if_neg hch]

/-- Single-step `revokeOneDomain s did'` preserves `did`'s domain record
    when `did` is outside the cascade footprint for this step. -/
theorem revokeOneDomain_getDom_eq
    (s : SpecState) (did' : DomId) (did : DomId)
    (hNe : did ≠ did')
    (hNotParent : ∀ d, s.getDom did' = some d → d.parent ≠ some did)
    (hNoChan : ∀ d, s.getDom did' = some d →
                ∀ cap ∈ d.domHandles.map Prod.snd,
                  ∀ entry ∈ s.domains.entries, ∀ pid pe,
                    entry.2.pendingDomCaps.find?
                      (fun p => p.2.capId = cap) = some (pid, pe) →
                    did ≠ entry.1 ∧ did ≠ pe.senderDomainId) :
    (revokeOneDomain s did').getDom did = s.getDom did := by
  unfold revokeOneDomain
  rcases hgd : s.getDom did' with _ | d
  · rfl
  -- Stage 1
  let ownedMems := d.memHandles.map Prod.snd
  let ownedCaps := d.domHandles.map Prod.snd
  show (let s₁ := ownedMems.foldl revokeOneMemCap s
        let s₂ := ownedCaps.foldl (fun (acc : SpecState) cap =>
          match acc.getDomCap cap with
          | some dc => if dc.isChannel then cancelChannelIfPending acc cap else acc
          | none    => acc) s₁
        let s₃ := clearCommBindings s₂ d.commBindings
        let s₄ : SpecState :=
          { s₃ with domcaps :=
              ⟨s₃.domcaps.entries.filter
                (fun entry => entry.2.owner ≠ did' ∧ entry.2.targetDom ≠ did')⟩ }
        let s₅ : SpecState :=
          match d.parent with
          | none     => s₄
          | some pid =>
              s₄.updDomain pid (fun pd =>
                { pd with childrenDoms := pd.childrenDoms.filter (· ≠ did') })
        { s₅ with domains := s₅.domains.remove did' }).getDom did = s.getDom did
  -- Final `domains.remove did'`: did ≠ did' so this is identity on getDom.
  show ((_ : SpecState).getDom did) = s.getDom did
  -- Unfold inner lets stepwise.
  simp only []
  -- Stage 6: remove did' from domains
  have step6 : ∀ (st : SpecState),
      ({ st with domains := st.domains.remove did' } : SpecState).getDom did
        = st.getDom did := by
    intro st
    simp only [SpecState.getDom]
    exact Arena.find?_remove_other _ _ _ hNe
  rw [step6]
  -- Stage 5: parent childrenDoms patch
  have step5 : ∀ (st : SpecState),
      (match d.parent with
       | none     => st
       | some pid =>
           st.updDomain pid (fun pd =>
             { pd with childrenDoms := pd.childrenDoms.filter (· ≠ did') })
      ).getDom did = st.getDom did := by
    intro st
    rcases hpar : d.parent with _ | pid
    · rfl
    · have hpne : did ≠ pid := by
        intro heq
        exact hNotParent d hgd (heq ▸ hpar)
      exact updDomain_other_eq _ _ _ _ hpne
  rw [step5]
  -- Stage 4: domcaps filter — preserves domain arena
  have step4 : ∀ (st : SpecState),
      ({ st with domcaps :=
            ⟨st.domcaps.entries.filter
              (fun entry => entry.2.owner ≠ did' ∧ entry.2.targetDom ≠ did')⟩ }
       : SpecState).getDom did = st.getDom did := by
    intro st; rfl
  rw [step4]
  -- Stage 3: clearCommBindings
  rw [clearCommBindings_getDom_eq]
  -- Stage 2: channel cancellation fold
  -- The fold is over ownedCaps in the *stage-1* state s₁, but
  -- pendingDomCaps queries happen against the evolving state.
  -- We need a lemma showing the fold preserves `getDom did` provided
  -- the initial entries' pending lists don't contain matches with
  -- did as holder/sender. Use `foldl_channelOps_getDom_eq` below.
  have step2 : (ownedCaps.foldl (fun acc cap =>
      match acc.getDomCap cap with
      | some dc => if dc.isChannel then cancelChannelIfPending acc cap else acc
      | none    => acc) (ownedMems.foldl revokeOneMemCap s)).getDom did
      = (ownedMems.foldl revokeOneMemCap s).getDom did := by
    sorry
  rw [step2]
  -- Stage 1: revokeOneMemCap fold
  exact foldl_revokeOneMemCap_getDom_eq s ownedMems did

/-! ## Cascade owner preservation

For the owner field, every cascade modification either removes a memcap
or modifies fields other than `owner`. -/

/-- `updMem` with an owner-preserving function preserves the owner of
    any surviving memcap. -/
theorem updMem_owner_preserved
    (s : SpecState) (id : MemCapId) (f : MemCap → MemCap)
    (hf : ∀ m, (f m).owner = m.owner)
    (c : MemCapId) (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (s.updMem id f).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  show capPre.owner = capPost.owner
  by_cases hc : c = id
  · subst hc
    have : (s.updMem c f).getMem c = some (f capPre) := by
      show (s.memcaps.update c f).find? c = some (f capPre)
      exact Arena.find?_update_same _ _ _ hPre
    rw [this] at hPost
    injection hPost with heq; rw [← heq]; exact (hf capPre).symm
  · have : (s.updMem id f).getMem c = some capPre := by
      show (s.memcaps.update id f).find? c = some capPre
      rw [Arena.find?_update_other _ _ _ _ hc]; exact hPre
    rw [this] at hPost
    injection hPost with heq; rw [heq]

/-- `remove id` from memcaps preserves the owner of any surviving memcap
    (because survivors at `c` must have `c ≠ id`). -/
theorem remove_memcap_owner_preserved
    (s : SpecState) (id : MemCapId)
    (c : MemCapId) (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : ({ s with memcaps := s.memcaps.remove id } : SpecState).getMem c
              = some capPost) :
    capPre.owner = capPost.owner := by
  by_cases hc : c = id
  · subst hc
    have : ({ s with memcaps := s.memcaps.remove c } : SpecState).getMem c = none := by
      show (s.memcaps.remove c).find? c = none
      exact Arena.find?_remove_same _ _
    rw [this] at hPost; cases hPost
  · have : ({ s with memcaps := s.memcaps.remove id } : SpecState).getMem c
            = some capPre := by
      show (s.memcaps.remove id).find? c = some capPre
      rw [Arena.find?_remove_other _ _ _ hc]; exact hPre
    rw [this] at hPost
    injection hPost with heq; rw [heq]

/-- `revokeOneMemCap` preserves the `owner` field of any surviving memcap. -/
theorem revokeOneMemCap_owner_preserved
    (s : SpecState) (mid : MemCapId) (c : MemCapId)
    (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (revokeOneMemCap s mid).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  unfold revokeOneMemCap at hPost
  rcases hm : s.getMem mid with _ | m
  · simp only [hm] at hPost
    rw [hPre] at hPost; injection hPost with heq; rw [heq]
  · simp only [hm] at hPost
    rcases hpar : m.parent with _ | pid
    · simp only [hpar] at hPost
      exact remove_memcap_owner_preserved s mid c capPre capPost hPre hPost
    · simp only [hpar] at hPost
      -- Two-stage: first remove, then updMem
      rcases hmid :
        ({ s with memcaps := s.memcaps.remove mid } : SpecState).getMem c
        with _ | capMid
      · -- post = none ⇒ contradicts hPost
        exfalso
        have hnone :
          (({ s with memcaps := s.memcaps.remove mid } : SpecState).updMem pid
              (fun p => { p with childrenIds := p.childrenIds.filter (· ≠ mid) })).getMem c
            = none := by
          show ((s.memcaps.remove mid).update pid _).find? c = none
          by_cases hcp : c = pid
          · subst hcp
            rw [Arena.find?_update_eq_map]
            rw [show (s.memcaps.remove mid).find? c = none from hmid]; rfl
          · rw [Arena.find?_update_other _ _ _ _ hcp]; exact hmid
        rw [hnone] at hPost; cases hPost
      · have h1 : capPre.owner = capMid.owner :=
          remove_memcap_owner_preserved s mid c capPre capMid hPre hmid
        have h2 : capMid.owner = capPost.owner := by
          let s' : SpecState := { s with memcaps := s.memcaps.remove mid }
          let f : MemCap → MemCap := fun p =>
            { p with childrenIds := p.childrenIds.filter (· ≠ mid) }
          have hp : (s'.updMem pid f).getMem c = some capPost := hPost
          exact updMem_owner_preserved s' pid f
            (fun _ => rfl) c capMid capPost hmid hp
        exact h1.trans h2

theorem foldl_revokeOneMemCap_owner_preserved
    (s : SpecState) (mids : List MemCapId) (c : MemCapId)
    (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (mids.foldl revokeOneMemCap s).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  induction mids generalizing s capPre with
  | nil =>
    simp only [List.foldl_nil] at hPost
    rw [hPre] at hPost; injection hPost with heq; rw [heq]
  | cons mid rest ih =>
    simp only [List.foldl_cons] at hPost
    rcases hmid : (revokeOneMemCap s mid).getMem c with _ | capMid
    · -- if c removed, later folds can't make it some
      exfalso
      have hnone_pres : ∀ (s' : SpecState) (ms : List MemCapId),
              s'.getMem c = none →
              (ms.foldl revokeOneMemCap s').getMem c = none := by
        intro s' ms hn
        induction ms generalizing s' with
        | nil => simpa using hn
        | cons m rest' ih' =>
          simp only [List.foldl_cons]
          apply ih'
          unfold revokeOneMemCap
          rcases hg : s'.getMem m with _ | mcap
          · simp only [hg]; exact hn
          · simp only [hg]
            rcases hp : mcap.parent with _ | pp
            · simp only [hp]
              show (s'.memcaps.remove m).find? c = none
              by_cases hcm : c = m
              · subst hcm; exact Arena.find?_remove_same _ _
              · rw [Arena.find?_remove_other _ _ _ hcm]; exact hn
            · simp only [hp]
              show (((s'.memcaps.remove m) : Arena _ _).update pp _).find? c = none
              by_cases hcp : c = pp
              · subst hcp
                rw [Arena.find?_update_eq_map]
                by_cases hcm : c = m
                · subst hcm
                  show Option.map _ ((s'.memcaps.remove c).find? c) = none
                  rw [Arena.find?_remove_same]; rfl
                · show Option.map _ ((s'.memcaps.remove m).find? c) = none
                  rw [Arena.find?_remove_other _ _ _ hcm]
                  have hn' : s'.memcaps.find? c = none := hn
                  rw [hn']; rfl
              · rw [Arena.find?_update_other _ _ _ _ hcp]
                by_cases hcm : c = m
                · subst hcm; exact Arena.find?_remove_same _ _
                · rw [Arena.find?_remove_other _ _ _ hcm]; exact hn
      rw [hnone_pres _ rest hmid] at hPost; cases hPost
    · have h1 := revokeOneMemCap_owner_preserved s mid c capPre capMid hPre hmid
      have h2 := ih (revokeOneMemCap s mid) capMid hmid hPost
      exact h1.trans h2

/-- `clearCommBindings` preserves the `owner` field of any surviving memcap. -/
theorem clearCommBindings_owner_preserved
    (s : SpecState) (cbs : List MemCapId) (c : MemCapId)
    (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (clearCommBindings s cbs).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  unfold clearCommBindings at hPost
  induction cbs generalizing s capPre with
  | nil =>
    simp only [List.foldl_nil] at hPost
    rw [hPre] at hPost; injection hPost with heq; rw [heq]
  | cons mid rest ih =>
    simp only [List.foldl_cons] at hPost
    rcases hmid : (s.updMem mid (fun m =>
        { m with region :=
            { m.region with
                attributes := { m.region.attributes with comm := false },
                commBinding := none } })).getMem c with _ | capMid
    · -- If updMem produces none on c, then it must've been none originally
      -- (updMem doesn't remove). Contradicts hPre.
      exfalso
      have hsome : ∃ v, (s.updMem mid (fun m =>
          { m with region :=
              { m.region with
                  attributes := { m.region.attributes with comm := false },
                  commBinding := none } })).getMem c = some v := by
        show ∃ v, (s.memcaps.update mid _).find? c = some v
        by_cases hcm : c = mid
        · subst hcm
          refine ⟨_, Arena.find?_update_same _ _ _ hPre⟩
        · rw [Arena.find?_update_other _ _ _ _ hcm]
          exact ⟨capPre, hPre⟩
      rcases hsome with ⟨v, hv⟩
      rw [hv] at hmid; cases hmid
    · have h1 : capPre.owner = capMid.owner := by
        let f : MemCap → MemCap := fun m =>
          { m with region :=
              { m.region with
                  attributes := { m.region.attributes with comm := false },
                  commBinding := none } }
        have hp : (s.updMem mid f).getMem c = some capMid := hmid
        exact updMem_owner_preserved s mid f (fun _ => rfl) c capPre capMid hPre hp
      have h2 : capMid.owner = capPost.owner := ih _ capMid hmid hPost
      exact h1.trans h2

/-- `cancelChannelIfPending` never touches memcaps. -/
theorem cancelChannelIfPending_owner_preserved
    (s : SpecState) (cap : DomCapId) (c : MemCapId)
    (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (cancelChannelIfPending s cap).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  have hmm := cancelChannelIfPending_memcaps_eq s cap
  have : (cancelChannelIfPending s cap).getMem c = s.getMem c := by
    simp [SpecState.getMem, hmm]
  rw [this, hPre] at hPost
  injection hPost with heq; rw [heq]

/-- `updMem` preserves `none` lookup at any key. -/
theorem updMem_getMem_none_preserved
    (s : SpecState) (id : MemCapId) (f : MemCap → MemCap)
    (c : MemCapId) (h : s.getMem c = none) :
    (s.updMem id f).getMem c = none := by
  show (s.memcaps.update id f).find? c = none
  by_cases hc : c = id
  · subst hc
    rw [Arena.find?_update_eq_map]
    have h' : s.memcaps.find? c = none := h
    rw [h']; rfl
  · rw [Arena.find?_update_other _ _ _ _ hc]; exact h

/-- `clearCommBindings` preserves `none` lookup. -/
theorem clearCommBindings_getMem_none_preserved
    (s : SpecState) (cbs : List MemCapId) (c : MemCapId)
    (h : s.getMem c = none) :
    (clearCommBindings s cbs).getMem c = none := by
  unfold clearCommBindings
  induction cbs generalizing s with
  | nil => simpa using h
  | cons mid rest ih =>
    simp only [List.foldl_cons]
    apply ih
    exact updMem_getMem_none_preserved s mid _ c h

/-- The channel-cancel fold body used in `revokeOneDomain` stage 2
    preserves `memcaps`. -/
theorem foldl_channelCancel_memcaps_eq (s : SpecState) (caps : List DomCapId) :
    (caps.foldl (fun acc cap =>
        match acc.getDomCap cap with
        | some dc => if dc.isChannel then cancelChannelIfPending acc cap else acc
        | none    => acc) s).memcaps = s.memcaps := by
  induction caps generalizing s with
  | nil => rfl
  | cons cap rest ih =>
    simp only [List.foldl_cons]
    rw [ih]
    rcases hg : s.getDomCap cap with _ | dc
    · simp [hg]
    · simp only [hg]
      by_cases hch : dc.isChannel
      · rw [if_pos hch]; exact cancelChannelIfPending_memcaps_eq _ _
      · rw [if_neg hch]

/-- Stage-2 fold preserves `getMem c`. -/
theorem foldl_channelCancel_getMem_eq (s : SpecState) (caps : List DomCapId)
    (c : MemCapId) :
    (caps.foldl (fun acc cap =>
        match acc.getDomCap cap with
        | some dc => if dc.isChannel then cancelChannelIfPending acc cap else acc
        | none    => acc) s).getMem c = s.getMem c := by
  show _ = _
  unfold SpecState.getMem
  rw [foldl_channelCancel_memcaps_eq]

/-- Real `revokeOneDomain s did'` owner preservation. -/
theorem revokeOneDomain_owner_preserved
    (s : SpecState) (did' : DomId) (c : MemCapId)
    (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (revokeOneDomain s did').getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  rcases hgd : s.getDom did' with _ | d
  · have hno : revokeOneDomain s did' = s := by
      unfold revokeOneDomain; rw [hgd]
    rw [hno] at hPost
    rw [hPre] at hPost
    injection hPost with heq; rw [heq]
  · -- Local abbreviations
    let s₁ : SpecState := (d.memHandles.map Prod.snd).foldl revokeOneMemCap s
    let s₂ : SpecState := (d.domHandles.map Prod.snd).foldl
        (fun acc cap => match acc.getDomCap cap with
                        | some dc => if dc.isChannel
                                     then cancelChannelIfPending acc cap
                                     else acc
                        | none => acc) s₁
    let s₃ : SpecState := clearCommBindings s₂ d.commBindings
    have hPost_eq : (revokeOneDomain s did').getMem c = s₃.getMem c := by
      show (revokeOneDomain s did').memcaps.find? c = s₃.memcaps.find? c
      have hmm : (revokeOneDomain s did').memcaps = s₃.memcaps := by
        unfold revokeOneDomain
        simp only [hgd]
        cases d.parent <;> rfl
      rw [hmm]
    rw [hPost_eq] at hPost
    rcases h2 : s₂.getMem c with _ | cap2
    · have h3none : s₃.getMem c = none :=
        clearCommBindings_getMem_none_preserved s₂ d.commBindings c h2
      rw [h3none] at hPost; cases hPost
    · have e23 : cap2.owner = capPost.owner :=
        clearCommBindings_owner_preserved s₂ d.commBindings c cap2 capPost h2 hPost
      have h12 : s₂.getMem c = s₁.getMem c :=
        foldl_channelCancel_getMem_eq s₁ _ c
      rw [h12] at h2
      have e12 : capPre.owner = cap2.owner :=
        foldl_revokeOneMemCap_owner_preserved s _ c capPre cap2 hPre h2
      exact e12.trans e23

/-- `revokeOneMemCap` preserves `none` lookup. -/
theorem revokeOneMemCap_getMem_none_preserved
    (s : SpecState) (mid : MemCapId) (c : MemCapId)
    (h : s.getMem c = none) :
    (revokeOneMemCap s mid).getMem c = none := by
  unfold revokeOneMemCap
  rcases hgm : s.getMem mid with _ | mcap
  · simp [hgm]; exact h
  · simp only [hgm]
    rcases hpp : mcap.parent with _ | pid
    · simp only [hpp]
      show ({ s with memcaps := s.memcaps.remove mid } : SpecState).getMem c = none
      show (s.memcaps.remove mid).find? c = none
      by_cases hcm : c = mid
      · subst hcm; exact Arena.find?_remove_same _ _
      · rw [Arena.find?_remove_other _ _ _ hcm]; exact h
    · simp only [hpp]
      show (({ s with memcaps := s.memcaps.remove mid } : SpecState).updMem pid _).getMem c = none
      apply updMem_getMem_none_preserved
      show (s.memcaps.remove mid).find? c = none
      by_cases hcm : c = mid
      · subst hcm; exact Arena.find?_remove_same _ _
      · rw [Arena.find?_remove_other _ _ _ hcm]; exact h

/-- A fold of `revokeOneMemCap` preserves `none` lookup. -/
theorem foldl_revokeOneMemCap_getMem_none_preserved
    (s : SpecState) (mids : List MemCapId) (c : MemCapId)
    (h : s.getMem c = none) :
    (mids.foldl revokeOneMemCap s).getMem c = none := by
  induction mids generalizing s with
  | nil => simpa using h
  | cons mid rest ih =>
    simp only [List.foldl_cons]
    exact ih (revokeOneMemCap s mid) (revokeOneMemCap_getMem_none_preserved s mid c h)

/-- `none` propagates along a fold of `revokeOneDomain` over a list. -/
theorem foldl_revokeOneDomain_getMem_none_preserved
    (s : SpecState) (dids : List DomId) (c : MemCapId)
    (h : s.getMem c = none) :
    (dids.foldl revokeOneDomain s).getMem c = none := by
  induction dids generalizing s with
  | nil => simpa using h
  | cons did rest ih =>
    simp only [List.foldl_cons]
    apply ih
    -- show (revokeOneDomain s did).getMem c = none, given s.getMem c = none
    rcases hg : s.getDom did with _ | d
    · have : revokeOneDomain s did = s := by
        unfold revokeOneDomain; rw [hg]
      rw [this]; exact h
    · -- Re-use the memcaps chain established above.
      let s₁ : SpecState := (d.memHandles.map Prod.snd).foldl revokeOneMemCap s
      let s₂ : SpecState := (d.domHandles.map Prod.snd).foldl
          (fun acc cap => match acc.getDomCap cap with
                          | some dc => if dc.isChannel
                                       then cancelChannelIfPending acc cap
                                       else acc
                          | none => acc) s₁
      let s₃ : SpecState := clearCommBindings s₂ d.commBindings
      have hmm : (revokeOneDomain s did).memcaps = s₃.memcaps := by
        unfold revokeOneDomain
        simp only [hg]
        cases d.parent <;> rfl
      have hres : (revokeOneDomain s did).getMem c = s₃.getMem c := by
        show (revokeOneDomain s did).memcaps.find? c = s₃.memcaps.find? c
        rw [hmm]
      rw [hres]
      -- s₃ = clearCommBindings s₂ d.commBindings; s₂.memcaps = s₁.memcaps
      apply clearCommBindings_getMem_none_preserved
      rw [show s₂.getMem c = s₁.getMem c from
            foldl_channelCancel_getMem_eq s₁ _ c]
      exact foldl_revokeOneMemCap_getMem_none_preserved s _ c h

/-- A fold of `revokeOneDomain` over a list of dids preserves the owner
    of any memcap that survives the fold. -/
theorem foldl_revokeOneDomain_owner_preserved
    (s : SpecState) (dids : List DomId) (c : MemCapId)
    (capPre capPost : MemCap)
    (hPre : s.getMem c = some capPre)
    (hPost : (dids.foldl revokeOneDomain s).getMem c = some capPost) :
    capPre.owner = capPost.owner := by
  induction dids generalizing s capPre with
  | nil => simp at hPost; rw [hPre] at hPost; injection hPost with h; rw [h]
  | cons did rest ih =>
    simp only [List.foldl_cons] at hPost
    rcases hmid : (revokeOneDomain s did).getMem c with _ | capMid
    · -- cap removed → can't come back
      have : (rest.foldl revokeOneDomain (revokeOneDomain s did)).getMem c = none :=
        foldl_revokeOneDomain_getMem_none_preserved _ _ _ hmid
      rw [this] at hPost; cases hPost
    · have h1 : capPre.owner = capMid.owner :=
        revokeOneDomain_owner_preserved s did c capPre capMid hPre hmid
      have h2 : capMid.owner = capPost.owner := ih _ capMid hmid hPost
      exact h1.trans h2

end ThemisCapa
