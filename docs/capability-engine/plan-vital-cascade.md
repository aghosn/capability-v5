# Plan: Model VITAL cascade (G1) + revoked-domain status (G4)

**Status:** PLAN ONLY — not yet implemented.
**Scope (this iteration):** G1 leaf-only + G4. Defers G2 (recursive
memcap revoke) and G3 (recursive domain revoke) to a follow-up.

## Why this scope

- The motivating bug (sibling 1 holds memcap M, alias M' is given to
  sibling 2 with `vital=true`, sibling 1 calls `revoke(M')`, kills 2)
  is **a leaf revocation**. G1 leaf-only addresses the exact scenario.
- G4 (the `revoked` status bit) is the foundational primitive that
  G2/G3 will need — introducing it now sets up the type discipline
  before recursion piles on.
- Avoids confronting recursion + cascade + invariant-preservation in
  one giant change. We can verify the cascade mechanism on the leaf
  case, then generalize.

## Engine reference behaviour (Rust, simplified to leaf-only)

```
revoke(caller, target_handle):
  cap := caller.lookup_mem(target_handle)
  require cap.is_leaf and cap.has_parent and caller owns cap.parent

  # G2 (recursive case): revoke_subtree(cap.children) first — DEFERRED.

  remove cap from cap.parent.children_ids
  remove cap from memcaps
  for each h ∈ cap.owner.mem_handles where h.cap = cap: remove h

  # G1: vital cascade (leaf version)
  if cap.attributes.vital and not cap.owner.is_revoked:
    # G3 (recursive on cap.owner's children domains, root memcaps,
    # channels, COMM bindings) — DEFERRED.
    cap.owner.status := revoked
```

## What changes in the spec

### State changes

1. `DomainStatus.revoked` — already an enum case (`Basic.lean:173`,
   currently TODO). Keep it; remove the TODO comment.

2. New predicates on `Domain`:
   - `def isRevoked (d : Domain) : Prop := d.status = .revoked`
   - `def isLive    (d : Domain) : Prop := ¬ d.isRevoked`
   - `def isActive  (d : Domain) : Prop := d.status = .unsealed ∨ d.status = .sealed` — same as `isLive` but framed positively.

### Guard changes

For every guard that currently looks up a domain by id, we need to
decide what "revoked target/caller" should do. Two policies:

- **Strict:** `d.isLive` is required for any reference. Acting on a
  revoked domain is a guard violation; revoked domains are tombstones.
- **Permissive:** Only the *caller* needs to be live. Revoked targets
  are silently no-op'd inside `apply`.

**Decision: strict.** Reasons:
- Matches the engine's `Domain::is_revoked` early-return checks at the
  hypercall boundary.
- Cleaner refinement story: every `step` either rejects (guard fails)
  or makes monotone progress; no silent no-ops.
- Existing `callerSealed : d.isSealed` already implies `isLive` for
  the caller (since `revoked ≠ sealed`). So the **caller** side needs
  no new check.

Concretely, the change is:
- For each guard with a clause of the form
  `... s.getDom <other_id> = some d → ...`, add the conjunct
  `d.isLive`.
- This affects: `send`, `sendChannel`, `sealedSend`, `accept`,
  `reject`, `acceptChannel`, `rejectChannel`, `switch`,
  `switchSuspended`, `switchReturn` (callee), `addVp` (child),
  `registerComm` (child), `revokeDomain` (target), `deliverInterrupt`
  (interrupted, handler, chain elements), `seal` (target via
  domain-cap).
- Does NOT affect: `carve`, `alias`, `revoke`, `mapSelf`, `setPolicy`,
  `create` (these are caller-only, no other-domain reference).

### `revoke_apply` change (G1 leaf-only)

Add a single conditional update at the end:
```lean
if target.attributes.vital then
  s.updDomain target.owner (fun d => { d with status := .revoked })
else
  s
```
(after the existing leaf-revoke updates).

### Invariant changes (`Invariants.lean`)

Existing invariants must be re-examined:

| Invariant | Affected? | How |
|---|---|---|
| `UniqueArenas` | no | structural; status doesn't matter |
| `MemRefsResolved` | **yes** | a revoked domain may still own memcaps; the `find?` must still succeed. **Revoked domains stay in the arena**, so `MemRefsResolved` continues to hold trivially. |
| `CdtMonotonic` | **yes** | revoking the owning domain means a domcap pointing to it now references a `revoked` domain. We need to decide: is that a violation? Probably **no** — same logic as MemRefsResolved. Revoked ≠ removed. |
| `CdtBidirectional` | no | tree shape unchanged |
| `FreshMemCounter` | no | counter unchanged on vital cascade (we don't allocate) |
| `HandleOwner` | **yes** | a revoked domain's `memHandles` still exists. The handle invariant should still hold; need to check the proof. |
| `ParentChildAgreement` | **yes — needs careful look** | this is the domain-CDT invariant. A revoked-but-still-present domain has its parent and children fields untouched, so the structural agreement should still hold. |
| `FreshDomCounter` | no | unchanged |
| `FreshDomCapCounter` | no | unchanged |

**New invariant candidate (later, not now):** `RevokedIsTombstone` —
a revoked domain has empty `vps`, `memHandles`, `domHandles`,
`childrenDoms`, etc. **NOT TRUE in this iteration** because G3 isn't
done; the revoked owner still has all its caps. We will add this
invariant only after G3.

For now, the working assumption is: **a revoked domain is a passive
tombstone whose state is frozen but possibly non-empty.** Document
this clearly.

### Existing 21 `*_apply_preservesParents` lemmas

For each action, the question is: does the action ever mutate a
domain's `parent` field? `parent` is set on `create` and never written
elsewhere. The vital cascade only flips `status`, not `parent`. So:

- `revoke_apply` — adds the cascade; `parent` still untouched. Proof
  needs a small extra step to handle the new `updDomain target.owner`.
- All other 20 lemmas — unchanged.

So `step_parent_immutable` survives intact; only the `revoke` proof
needs an extra case.

### Tests

`Properties.lean` has 36 tests. Need to enumerate which ones touch
`revoke` semantics or assume guards are weaker than the new strict
form.

Likely-affected tests:
- Anything using `revoke_apply` on a vital cap will now ALSO mutate
  the owner domain.
- Tests that act on a revoked domain after a previous revoke will
  now hit guard failures.

We'll need to read through `Properties.lean` and either update test
states or accept that some tests are now testing against a more
faithful model.

## Refinement / theorem statements affected

Now, here's the **theorem-review** part the user asked for explicitly.

### `step_parent_immutable` — UNCHANGED

Statement: under `WellFormed s`, if `step s a s'` and
`s.getDom did = some d` and `s'.getDom did = some d'`, then
`d'.parent = d.parent`.

After G1+G4: a revoked domain still has `getDom did = some d`. The
cascade only flips `.status`, not `.parent`. So the theorem still
holds and the proof needs only a one-liner extension in the
revoke case.

### O2 (hierarchical encapsulation) — STILL BLOCKED, but for a different reason now

Even with G1 modeled, the user's scenario remains true: sibling 1
**can** mutate sibling 2's state (now: by flipping their status to
revoked, in addition to dropping their alias handle). This is the
expected, faithful behavior — the engine genuinely allows it.

So the honest O2 statement remains:
> *Outsiders w.r.t. capability-graph reachability* — not just
> domain-CDT outsiders — cannot affect insider state.

Modeling G1 makes the spec faithful; it does not change which O2
formulation is the right one. We still need the capability-graph
"no path" hypothesis for any non-trivial O2.

### What G1 unblocks immediately

- A clean **inversion lemma**: "a revoked domain's status didn't flip
  spontaneously — there exists a vital-memcap revocation in the trace
  whose owner was that domain." This is a small but real locality
  result.
- A **trace-level provenance result**: parent-pointer immutability
  combined with G1 modeling gives "if `did` is revoked at time `t`,
  some prior step `t' < t` was a `revoke` of a vital memcap owned by
  `did`." Useful for audit / attestation.

## Theorem statements I commit to writing under this iteration

After implementing G1+G4, write and prove:

**T1 (revoke-cascade locality):**
> For `step s (revoke caller target) s'`, if
> `s.getMem target = some t` and `t.attributes.vital = true` and
> `t.owner = D` and `s.getDom D = some d` with `d.status ≠ revoked`,
> then `s'.getDom D = some d'` with `d'.status = .revoked`.
> If `t.attributes.vital = false`, then `(s'.getDom D).map status =
> (s.getDom D).map status` (status unchanged).

**T2 (vital implies prior revoke):**
> For `step s a s'`, if there exists `did` with
> `(s.getDom did).map status = some sealed` (or `unsealed`) but
> `(s'.getDom did).map status = some revoked`, then `a` is a
> `revoke caller target` for some `target` whose memcap has
> `vital = true` and `owner = did`.

**T3 (revoked status persists — sketched, depends on G3 for full statement):**
> Once `status = revoked`, no future step flips it back. **TRIVIAL
> in this iteration** because no spec action transitions out of
> revoked. Add as a one-line corollary.

**T4 (parent immutability extends across cascade):** — corollary of
the unchanged `step_parent_immutable`.

These four are all small. They are sub-results, not headline O2
theorems.

## Implementation order

1. Lift `TODO` comment on `DomainStatus.revoked`.
2. Add `Domain.isRevoked`, `Domain.isLive` predicates.
3. Add `notRevoked` clauses to the 14 affected guards (per list
   above). **Do this carefully — small batches, build between.**
4. Modify `revoke_apply` to add the leaf-vital cascade.
5. Re-prove `revoke_apply_preservesParents` (one extra case).
6. Verify all 21 per-action lemmas still compile.
7. Verify `step_parent_immutable` still compiles.
8. Read `Properties.lean`, fix or accept changes.
9. Write T1, T2 in a new file `lean/ThemisCapa/RevokeCascade.lean`.
10. Update `docs/.../lean-v2-coverage-gaps.md`: G1 → ✅ leaf-only,
    note G2/G3 still pending.
11. Update `docs/.../aeneas-exploration.md` §11.5 status block.
12. Commit.

## Risks / unknowns

- **Risk:** Adding `notRevoked` to guards may break cases in the
  existing 36 Properties tests if any test actually constructs a
  state with a revoked-but-referenced domain. Likely zero, since
  no current action produces revoked domains.
- **Risk:** The `revoke_apply` cascade operates on `target.owner`,
  but `target` is fetched via `s.getMem`. If `target.owner` is the
  same as `caller`, and we do `updDomain caller (filter handle) ;
  updDomain target.owner (status := revoked)` — these are the SAME
  domain. Order matters. Need to verify the resulting state is
  what the engine produces. Engine: caller revokes a vital memcap
  *that caller itself owns* → caller dies. Spec must match.
- **Risk:** Existing `revoke_apply_preservesParents` proof passes
  because `parent` field is never touched. Adding a status-only
  update preserves this. Should be fine, but verify.

## Out of scope this iteration (explicit)

- G2 (recursive memcap subtree revoke) — guard still requires leaf.
- G3 (recursive domain subtree revoke) — vital cascade only marks
  the owner; doesn't propagate to its children, channels, or other
  memcaps. The result is a "tombstone with debris." Documented as
  known partiality.
- G5 (CLEAN / ZeroMemory updates) — orthogonal; punt.
- O2 reformulation — separate work, depends on capability-graph
  reachability infra not yet built.
