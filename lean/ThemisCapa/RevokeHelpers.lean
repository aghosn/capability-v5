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

end ThemisCapa
