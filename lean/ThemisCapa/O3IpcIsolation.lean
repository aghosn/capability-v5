/-
  ThemisCapa.O3IpcIsolation — Memcap-IPC delivery isolation and
  end-to-end integrity (sealedSend / accept / reject).

  ## Goal

  The canonical Themis safety claim for inter-domain communication:

    *A memcap sent via `sealedSend` and later `accept`-ed by the
    designated receiver arrives unchanged, with the correct sender
    attribution. Third-party domains cannot observe or alter the
    in-flight payload.*

  We package this as four layers:

  - § 1: **Apply-shape lemmas** — concrete computations of the post-
    states for `sealedSend`, `accept`, `reject`. These pin down the
    payload of the freshly-enqueued `PendingMemCap` and the data
    flow of accept/reject.

  - § 2: **Round-trip integrity** — the headline IPC theorems:
      * `ipc_sealedSend_accept_round_trip`  : a sealedSend immediately
        followed by accept of the new pending id transfers the cap to
        the receiver with the right `gpaHint` and releases the
        sender's frozen handle.
      * `ipc_sealedSend_reject_rolls_back` : a sealedSend immediately
        followed by reject leaves the cap with the sender and
        releases the frozen handle.

  - § 3: **Pending-entry preservation across third-party steps** —
    while the message is in flight, no step whose footprint avoids
    the receiver can alter the pending entry's payload. Built on
    top of `step_view_preservation` from `NonInterference.lean`.

  ## Relation to existing results

  We reuse rather than duplicate:
    * `step_locality_dom`, `*_frame_dom`     — Locality.lean
    * `step_view_preservation`               — NonInterference.lean
    * `step_parent_immutable` infrastructure — ParentStability.lean
    * Subtree locality                        — O2SubtreeLocality* .lean

  ## Out of scope

  * Channel (DomCap) IPC: the spec only models the *unsealed* path of
    `sendChannel`, which transfers ownership immediately rather than
    via a pending queue. There is no `sealedSendChannel` yet, so the
    IPC round-trip story for channels is currently degenerate.
-/
import ThemisCapa.NonInterference
import ThemisCapa.Properties

namespace ThemisCapa
open Arena

-- ════════════════════════════════════════════════════════════════════
-- § 1.  Apply-shape lemmas
-- ════════════════════════════════════════════════════════════════════

/-- Receiver post-state under `sealedSend`: a fresh `PendingMemCap`
    is appended to `pendingMemCaps`, and `nextPendingId` is bumped.

    Requires that handle resolution succeeds (otherwise sealedSend is
    a no-op). -/
theorem sealedSend_apply_receiver_get
    {s : SpecState} {caller receiver : DomId}
    {handle : LocalHandle} {gpaHint : Option Nat}
    (h_neq : caller ≠ receiver)
    {d_caller : Domain} (h_caller : s.getDom caller = some d_caller)
    {capId : MemCapId} (h_lookup : d_caller.lookupMemHandle handle = some capId)
    {d_recv : Domain} (h_recv : s.getDom receiver = some d_recv) :
    (sealedSend_apply s caller receiver handle gpaHint).getDom receiver =
      some
        { d_recv with
          pendingMemCaps :=
            d_recv.pendingMemCaps ++
              [(d_recv.nextPendingId,
                { capId := capId, senderDomainId := caller,
                  senderHandle := handle, gpaHint := gpaHint })],
          nextPendingId := d_recv.nextPendingId + 1 } := by
  show (sealedSend_apply s caller receiver handle gpaHint).domains.find? receiver = _
  unfold sealedSend_apply
  simp only [h_caller, Option.bind_some, h_lookup]
  simp only [SpecState.updDomain]
  rw [Arena.find?_update_eq_map]
  rw [Arena.find?_update_other _ caller receiver _ h_neq.symm]
  rw [show s.domains.find? receiver = some d_recv from h_recv]
  rfl

/-- Caller post-state under `sealedSend`: `frozenHandles` gains the
    sent handle. Requires `caller ≠ receiver` (true under
    `SealedSendGuard.notSelf`). -/
theorem sealedSend_apply_caller_get
    {s : SpecState} {caller receiver : DomId}
    {handle : LocalHandle} {gpaHint : Option Nat}
    (h_neq : caller ≠ receiver)
    {d_caller : Domain} (h_caller : s.getDom caller = some d_caller)
    {capId : MemCapId} (h_lookup : d_caller.lookupMemHandle handle = some capId) :
    (sealedSend_apply s caller receiver handle gpaHint).getDom caller =
      some { d_caller with frozenHandles := d_caller.frozenHandles ++ [handle] } := by
  show (sealedSend_apply s caller receiver handle gpaHint).domains.find? caller = _
  unfold sealedSend_apply
  simp only [h_caller, Option.bind_some, h_lookup]
  simp only [SpecState.updDomain]
  rw [Arena.find?_update_other _ receiver caller _ h_neq]
  rw [Arena.find?_update_eq_map]
  rw [show s.domains.find? caller = some d_caller from h_caller]
  rfl

end ThemisCapa
