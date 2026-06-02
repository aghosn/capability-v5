# Lean v2 — Coverage Gaps Inventory

**Last updated:** 2026-06-02
**Scope:** What the Rust `capa-engine` does that the Lean v2 spec does
**not** model, or models in a simplified ("slice") form.

This document exists because we caught a real false-confidence bug:
the spec was about to be used for an O2 hierarchical-encapsulation
theorem under the assumption that "domain-CDT outsiders cannot affect
insiders' state." That assumption is **false** in our spec — even
without any of the gaps below — because revoke authority follows the
**memcap parent chain**, not the domain CDT (a sibling who holds an
upstream memcap can revoke a sibling's alias). The gaps below make the
divergence even more severe and need to be either **modeled** or
**explicitly excluded by hypothesis** in every theorem statement.

The classification:

- 🔴 **Critical** — affects soundness of any non-trivial NI / encapsulation theorem.
- 🟠 **Significant** — alters reachable state space; must be cited in theorem hypotheses if not modeled.
- 🟡 **Minor / structural** — affects expressiveness or proof shape but not soundness of current theorems.
- ⚪ **Out-of-scope by design** — explicitly deferred / orthogonal layer.

---

## 🔴 Critical gaps (block O2 / O3 / O5 as currently framed)

### G1. VITAL cascade on memcap revocation
- **Rust:** `capability.rs::revoke_subtree` lines 388–587. When a memcap with `attributes.vital = true` is revoked, the **owning domain is also revoked** (via `revoke_domain_subtree`). This cascades transitively: the dead domain's children domains are revoked, its memcaps are unmapped from parents, its channels are cancelled, COMM bindings cleaned up.
- **Lean:** `Step.lean::revoke_apply` only removes the memcap and strips it from the owner's `memHandles`. The `vital` attribute is *defined* in `Basic.lean` but never *consulted*.
- **Impact:** A sibling holding an ancestor memcap can today (in the spec) revoke a vital alias held by another sibling — the alias goes away, but the owning domain *does not die*, contrary to the engine's actual behavior. Any "subtree isolation" theorem proved against the current spec would be **vacuously false against the real engine** when the cascade fires.
- **Fix size:** Medium. Need to add a recursive update step inside `revoke_apply` that mirrors `revoke_domain_subtree`. Need to extend the action's footprint significantly (touches the whole transitive child-domain tree).

### G2. Recursive memcap-subtree revocation
- **Rust:** `revoke_subtree` recurses into `capa.children`. Revoking a non-leaf memcap removes the entire memcap subtree.
- **Lean:** `RevokeGuard.targetIsLeaf` requires `t.childrenIds = []`. Non-leaf revocation is **simply rejected** by the guard.
- **Impact:** Sequences that the engine handles atomically (revoke a region → cascade through aliases/carves) are inexpressible in the spec. Theorems that quantify over "all engine-reachable states" are missing transitions.
- **Fix size:** Medium-large. Recursion in the apply function plus invariant preservation across the whole subtree at once.

### G3. Recursive domain-subtree revocation
- **Rust:** `revoke_domain_subtree` lines 726–810. Revoking a domain recursively revokes child domains, root memcaps, channels.
- **Lean:** `RevokeDomainGuard.targetIsLeaf` requires the target domain to have **zero children, zero memHandles, zero domHandles**. Only fully-quiesced leaf domains can be revoked.
- **Impact:** Same as G2 but for the domain tree. The non-trivial revocation case (e.g. parent revokes a child that itself owns memcaps and channels) is not modeled.
- **Fix size:** Medium-large. Co-recursive with G1 (the cascade).

### G4. Domain "revoked" status
- **Rust:** `Domain::revoke` flips a state bit; the engine then treats the domain as a tombstone (skips ChangeRights into it, etc.). Multiple revocation paths converge through this bit.
- **Lean:** No `revoked` state. Domains are either present in the arena or removed entirely. Cascades that would touch a "marked-but-not-yet-removed" domain are not representable.
- **Impact:** Subtle but matters for any "ordering of effects within a single hypercall" reasoning. Less critical than G1–G3 but tied to them.
- **Fix size:** Small (add a status variant) but ripples into every guard.

---

## 🟠 Significant gaps (alter state space; must be cited if relied on)

### G5. CLEAN attribute / zero-on-revocation
- **Rust:** `revoke_subtree` line 487 — emits `ZeroMemory(hpa, size)` to the platform when `attributes.clean = true`.
- **Lean:** No platform-update layer is modeled in `revoke_apply`. The attribute exists in `Basic.lean::Attributes` but its consequence is not.
- **Impact:** Any "memory contents are scrubbed before reuse" property (a confidentiality story of its own) is unstateable. If we ever do L3 runtime-memory theorems, this is required.
- **Fix size:** Small in isolation, but needs an `Update` algebra to live somewhere.

### G6. COMM binding lifecycle
- **Lean:** `register_comm` is modeled; **unregistering / cleanup** on domain or memcap revocation is not (cascades from G1/G3).
- **Impact:** COMM bindings survive their target domain's revocation in the spec. Pinning semantics are partial.
- **Fix size:** Falls out of G3 once that's done.

### G7. Channel pending-cap cancellation on revocation
- **Rust:** `revoke_domain_subtree` lines 793–840 cancel pending receiver entries and unfreeze sender handles when a channel domain is revoked mid-transit.
- **Lean:** `revokeDomain_apply` doesn't touch `pending` or `frozen` state on related domains.
- **Impact:** Reachable states with stale pending entries / orphaned frozen senders exist in the engine but not in the spec.
- **Fix size:** Falls out of G3.

### G8. Multiple handles per cap per domain
- **Rust:** A domain can hold multiple `LocalHandle`s pointing to the same underlying memcap/domcap.
- **Lean:** `send_apply` strips **all** caller handles to the cap (lines 200–214 comment). The simplification was acknowledged at the time as a HandleOwner convenience.
- **Impact:** A real multi-handle scenario (caller holds two handles, sends "the cap" via one) becomes lossy in the spec — the second handle is dropped, but in the engine it would persist as an alias of the same underlying cap until separately revoked.
- **Fix size:** Small (per-handle strip), but invariant `HandleOwner` may need adjustment.

### G9. Send-to-self
- **Rust:** Allowed (the engine has explicit handling for `caller == receiver`, especially in send_at).
- **Lean:** `SendGuard.notSelf : caller ≠ receiver`. Forbidden by guard.
- **Impact:** A reachable sub-state of the engine is unreachable in the spec.
- **Fix size:** Medium — handling self-send requires careful stateupdate ordering.

### G10. `send_at` (positional sends) and address-translation interaction
- **Rust:** `capability.rs::send_at` allows sending a memcap to a receiver *and pinning it at a specific GPA in the receiver's address map*. Used heavily by VMM for guest memory layout.
- **Lean:** Modeled as `mapSelf` only (caller maps in their own AS). The cross-domain `send_at` variant — caller sends to receiver while specifying receiver's GPA — is not modeled.
- **Impact:** A whole class of cross-domain mapping installations is missing. Affects any address-map locality theorem.
- **Fix size:** Medium. Builds on Translation.lean.

### G11. Domain's "pending revocation" / drop ordering
- **Rust:** Drop semantics interact with the revoked bit (try_read patterns); the engine carefully orders `domain.revoke()` *before* recursing so memcap-side cascade detects "child already revoked" and skips ChangeRights.
- **Lean:** No analogue; cascades aren't modeled at all (G1–G3).
- **Impact:** Once we model cascades, the *ordering* of marks vs removals will be a source of proof complexity. Worth flagging now.

### G12. Policy enforcement on switch / interrupt / scheduling
- **Rust:** `policy_cores`, `policy_interrupts`, `canSwitch`, `canSchedule` are checked at multiple points: `switch.rs`, `deliver_interrupt_vp`.
- **Lean:** Some checks are present in guards (`hasPermission`, `canSend`, `canRevoke`, `canAlias`). Others (e.g. core affinity in `switch`, vector legality in `deliverInterrupt`) are **partial or absent** as guard preconditions.
- **Impact:** O4 (core affinity), O5 (sched authority), O6 (IRQ routing) cannot be cleanly stated until guards reflect the real policy checks.
- **Fix size:** Per-action audit; small per case but many cases.

---

## 🟡 Minor / structural gaps

### G13. Attestation / measurement (O1)
- **Lean:** `Attestation.lean` is 67 LOC — a stub.
- **Rust:** `attest.rs` is 856 LOC — full hash-tree computation over a domain's CDT subtree.
- **Impact:** O1 cannot be stated without modeling the measurement function.
- **Fix size:** Medium. Pure functional; no cascade complexity.

### G14. Cache coloring
- **Lean:** Translation.lean retains `ColorBitmap` as a stub; semantics not modeled.
- **Status:** ⚪ deferred by explicit decision (orthogonal layer).

### G15. Reserved memory map entries
- **Lean:** Translation.lean drops the `Reserved` `MapEntry` variant.
- **Status:** ⚪ deferred.

### G16. `set_register` / `get_register` / vCPU register state
- **Lean:** Not modeled.
- **Impact:** L3 runtime-memory theorems may eventually need this. None of O1–O8 do.
- **Status:** ⚪ deferred.

### G17. `interposition.rs` semantics
- **Lean:** `Interposition.lean` is 64 LOC — minimal.
- **Rust:** Full per-vector interposition with notify/forward variants.
- **Impact:** O6 (IRQ routing) needs more here.

### G18. Switch chain (multi-hop call/return)
- **Lean:** `Switch.lean` is 76 LOC. Modeled actions are `switch`, `switchReturn`, `switchSuspended` — but the chain semantics (deeper call-return stacks across multiple domains) are simplified.
- **Rust:** `switch.rs` 310 LOC.

### G19. Carve-overlap rules across alias children
- **Lean:** `AliasGuard.noOverlapCarved` checks against `RegionKind = .carve` siblings only.
- **Rust:** May enforce additional overlap rules between alias children.
- **Impact:** A reachability gap; possibly admits states the engine rejects.

### G20. Send-while-receiver-unsealed semantics
- **Lean:** Models the **unsealed** send paths only for many channel actions; sealed paths (sealedSendChannel etc.) are noted as future work.
- **Rust:** Both paths.

### G21. Address-map writes other than `mapSelf`
- **Lean:** Only `mapSelf` mutates `mappedGpas`.
- **Rust:** Several actions touch the address map (carve in receiver's view, send_at, register_comm side effects).

---

## ⚪ Explicitly out-of-scope by design

- **G14, G15, G16** above.
- **Concurrency / `Arc<RwLock>` model.** v2 is sequential. Concurrency is a separate research phase.
- **Hardware platform / ept / iommu page-table writes.** TCB.
- **Capavisor (L0) outside the engine.** Themis-side state machines are not the engine spec.

---

## What this means for the theorem agenda

1. **O1 (attestation)** — blocked on G13. Pure additive work; no cross-cutting impact.
2. **O2 (hierarchical encapsulation)** — **fundamentally affected by G1, G2, G3**. The "outsider can affect insider through memcap-tree authority and vital cascade" path is real. Any O2 statement must either:
   - explicitly **exclude** revoke-family actions and cap-graph reachability from "outsider" actions, or
   - first **model** G1–G3 and then state O2 in the form *"outsider with no capability-graph path to insider's resources cannot affect insider"*. The latter is the honest statement.
3. **O3 (nested confidentiality)** — depends on O2; same blockers.
4. **O4 (core affinity)** — partial, blocked on G12 for clean statement.
5. **O5 (scheduling authority)** — blocked on G12.
6. **O6 (IRQ routing)** — blocked on G12, partially G17.
7. **O7** — composes O4 + O6.
8. **O8** — meta-statement; not blocked, but vacuous until at least one NI theorem exists.

## Recommended next moves

1. **Model G1 (VITAL cascade) + G2 (recursive memcap revoke) together.** They share the same recursive update structure. Start here because it's the smallest scope that fixes the soundness story and unblocks O2 statement work.
2. **Then G3 + G4 (recursive domain revoke + revoked status).** Falls out of the same machinery.
3. **Then re-examine the existing 21 per-action `*_apply_preservesParents` lemmas.** Recursive revoke will turn `revokeDomain` from "removes-one" into "removes-many"; the parent-stability proof for it will need to generalize. `step_parent_immutable` itself should still hold (a domain whose parent is removed has no successor record, so the conclusion is vacuously true), but the proof shape changes.
4. **Then attempt the carefully-scoped O2 reformulation** with capability-graph "no-path" hypothesis.

## Process change going forward

The fact that we proved 21 per-action stability lemmas before noticing this gap is a process failure, not a Lean failure. From now on:

- **Every new action / spec extension must come with a "what's not modeled" note** in the file header. Future readers should see the gap before the proofs.
- **Every theorem statement must include an explicit "modulo gaps" clause** referencing this document by section number until the gap is closed.
- **Spec gaps are tracked here, not just in `todo.md`.** This document is the single source of truth for divergence from the Rust engine.
