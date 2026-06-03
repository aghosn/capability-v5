/-
  ThemisCapa.O3PairIsolation — Step-level pair-isolation theorems for
  the six IPC actions: sealedSend / accept / reject / sendChannel /
  acceptChannel / rejectChannel.

  ## Goal

  Each IPC action affects only the domains in a named "pair" (sender +
  receiver). For any third-party domain `did` outside that pair, the
  domain record is preserved by the step. These are wrappers around
  `step_locality_dom` (and `step_locality_mem` when applicable),
  packaging the `¬ affectsDom` discharge with the natural pair witness.

  ## Why these wrappers exist

  `step_locality_dom` takes `¬ a.affectsDom s did` — a per-action shape
  that requires the caller to thread guard witnesses for `accept`-style
  actions whose footprint is computed from `s`. The wrappers here pin
  the witnesses up front so callers see the simpler form

      did ≠ sender → did ≠ receiver → s'.getDom did = s.getDom did

  which is what downstream confidentiality / round-trip proofs need.

  ## Memcap side

  `sealedSend`, `reject`, `sendChannel`, `acceptChannel`,
  `rejectChannel` all have `affectsMem ≡ False`, so memcaps are
  globally preserved (no pair witness needed). `accept` is the only
  IPC action that touches memcaps — it transfers exactly `pe.capId` to
  the receiver, so for any other id memcaps are preserved.
-/

import ThemisCapa.Locality

namespace ThemisCapa

open Action

-- ════════════════════════════════════════════════════════════════════
-- § 1.  sealedSend
-- ════════════════════════════════════════════════════════════════════

/-- `sealedSend(caller, receiver, _, _)` only affects `caller` and
    `receiver`'s domain records. -/
theorem sealedSend_pair_isolation_dom
    {s s' : SpecState} {caller receiver : DomId}
    {handle : LocalHandle} {gpaHint : Option Nat}
    (hstep : step s (.sealedSend caller receiver handle gpaHint) s')
    {did : DomId} (h1 : did ≠ caller) (h2 : did ≠ receiver) :
    s'.getDom did = s.getDom did := by
  apply step_locality_dom hstep
  rintro (e | e)
  · exact h1 e
  · exact h2 e

/-- `sealedSend` never modifies memcaps. -/
theorem sealedSend_mem_unchanged
    {s s' : SpecState} {caller receiver : DomId}
    {handle : LocalHandle} {gpaHint : Option Nat}
    (hstep : step s (.sealedSend caller receiver handle gpaHint) s') :
    ∀ id, s'.getMem id = s.getMem id := by
  intro id
  exact step_locality_mem hstep (a := .sealedSend caller receiver handle gpaHint)
    (id := id) (fun h => h.elim)

-- ════════════════════════════════════════════════════════════════════
-- § 2.  accept
-- ════════════════════════════════════════════════════════════════════

/-- `accept(receiver, pid)` only affects `receiver` and the
    pending-entry's `senderDomainId`. -/
theorem accept_pair_isolation_dom
    {s s' : SpecState} {receiver : DomId} {pid : PendingId}
    (hstep : step s (.accept receiver pid) s')
    {d_recv : Domain} (hdr : s.getDom receiver = some d_recv)
    {pe : PendingMemCap} (hpe : d_recv.lookupPending pid = some pe)
    {did : DomId} (h1 : did ≠ receiver) (h2 : did ≠ pe.senderDomainId) :
    s'.getDom did = s.getDom did := by
  apply step_locality_dom hstep
  rintro (e | f)
  · exact h1 e
  · exact h2 (f d_recv hdr pe hpe)

/-- `accept(receiver, pid)` only modifies memcap `pe.capId`; any other
    memcap is preserved. -/
theorem accept_mem_isolation
    {s s' : SpecState} {receiver : DomId} {pid : PendingId}
    (hstep : step s (.accept receiver pid) s')
    {d_recv : Domain} (hdr : s.getDom receiver = some d_recv)
    {pe : PendingMemCap} (hpe : d_recv.lookupPending pid = some pe)
    {id : MemCapId} (h : id ≠ pe.capId) :
    s'.getMem id = s.getMem id := by
  apply step_locality_mem hstep
  intro f
  exact h (f d_recv hdr pe hpe)

-- ════════════════════════════════════════════════════════════════════
-- § 3.  reject
-- ════════════════════════════════════════════════════════════════════

/-- `reject(receiver, pid)` only affects `receiver` and the
    pending-entry's `senderDomainId`. -/
theorem reject_pair_isolation_dom
    {s s' : SpecState} {receiver : DomId} {pid : PendingId}
    (hstep : step s (.reject receiver pid) s')
    {d_recv : Domain} (hdr : s.getDom receiver = some d_recv)
    {pe : PendingMemCap} (hpe : d_recv.lookupPending pid = some pe)
    {did : DomId} (h1 : did ≠ receiver) (h2 : did ≠ pe.senderDomainId) :
    s'.getDom did = s.getDom did := by
  apply step_locality_dom hstep
  rintro (e | f)
  · exact h1 e
  · exact h2 (f d_recv hdr pe hpe)

/-- `reject` never modifies memcaps. -/
theorem reject_mem_unchanged
    {s s' : SpecState} {receiver : DomId} {pid : PendingId}
    (hstep : step s (.reject receiver pid) s') :
    ∀ id, s'.getMem id = s.getMem id := by
  intro id
  exact step_locality_mem hstep (a := .reject receiver pid) (id := id)
    (fun h => h.elim)

-- ════════════════════════════════════════════════════════════════════
-- § 4.  sendChannel
-- ════════════════════════════════════════════════════════════════════

/-- `sendChannel(caller, receiver, _)` only affects `caller` and
    `receiver`'s domain records. -/
theorem sendChannel_pair_isolation_dom
    {s s' : SpecState} {caller receiver : DomId} {cap : DomCapId}
    (hstep : step s (.sendChannel caller receiver cap) s')
    {did : DomId} (h1 : did ≠ caller) (h2 : did ≠ receiver) :
    s'.getDom did = s.getDom did := by
  apply step_locality_dom hstep
  rintro (e | e)
  · exact h1 e
  · exact h2 e

/-- `sendChannel` never modifies memcaps. -/
theorem sendChannel_mem_unchanged
    {s s' : SpecState} {caller receiver : DomId} {cap : DomCapId}
    (hstep : step s (.sendChannel caller receiver cap) s') :
    ∀ id, s'.getMem id = s.getMem id := by
  intro id
  exact step_locality_mem hstep (a := .sendChannel caller receiver cap)
    (id := id) (fun h => h.elim)

-- ════════════════════════════════════════════════════════════════════
-- § 5.  acceptChannel
-- ════════════════════════════════════════════════════════════════════

/-- `acceptChannel(receiver, pid)` only affects `receiver` and the
    pending-entry's `senderDomainId`. -/
theorem acceptChannel_pair_isolation_dom
    {s s' : SpecState} {receiver : DomId} {pid : PendingId}
    (hstep : step s (.acceptChannel receiver pid) s')
    {d_recv : Domain} (hdr : s.getDom receiver = some d_recv)
    {pe : PendingDomCap} (hpe : d_recv.lookupPendingDom pid = some pe)
    {did : DomId} (h1 : did ≠ receiver) (h2 : did ≠ pe.senderDomainId) :
    s'.getDom did = s.getDom did := by
  apply step_locality_dom hstep
  rintro (e | f)
  · exact h1 e
  · exact h2 (f d_recv hdr pe hpe)

/-- `acceptChannel` never modifies memcaps. -/
theorem acceptChannel_mem_unchanged
    {s s' : SpecState} {receiver : DomId} {pid : PendingId}
    (hstep : step s (.acceptChannel receiver pid) s') :
    ∀ id, s'.getMem id = s.getMem id := by
  intro id
  exact step_locality_mem hstep (a := .acceptChannel receiver pid)
    (id := id) (fun h => h.elim)

-- ════════════════════════════════════════════════════════════════════
-- § 6.  rejectChannel
-- ════════════════════════════════════════════════════════════════════

/-- `rejectChannel(receiver, pid)` only affects `receiver` and the
    pending-entry's `senderDomainId`. -/
theorem rejectChannel_pair_isolation_dom
    {s s' : SpecState} {receiver : DomId} {pid : PendingId}
    (hstep : step s (.rejectChannel receiver pid) s')
    {d_recv : Domain} (hdr : s.getDom receiver = some d_recv)
    {pe : PendingDomCap} (hpe : d_recv.lookupPendingDom pid = some pe)
    {did : DomId} (h1 : did ≠ receiver) (h2 : did ≠ pe.senderDomainId) :
    s'.getDom did = s.getDom did := by
  apply step_locality_dom hstep
  rintro (e | f)
  · exact h1 e
  · exact h2 (f d_recv hdr pe hpe)

/-- `rejectChannel` never modifies memcaps. -/
theorem rejectChannel_mem_unchanged
    {s s' : SpecState} {receiver : DomId} {pid : PendingId}
    (hstep : step s (.rejectChannel receiver pid) s') :
    ∀ id, s'.getMem id = s.getMem id := by
  intro id
  exact step_locality_mem hstep (a := .rejectChannel receiver pid)
    (id := id) (fun h => h.elim)

end ThemisCapa
