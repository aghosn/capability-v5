# Lean v2 — Address-Space Modeling Roadmap

> Companion to `lean-v2-coverage-gaps.md` (gaps G10, G14, G15) and
> `aeneas-exploration.md`. Records the address-space fidelity gap
> between the Lean v2 spec and `capa-engine/`, and the work required
> to close it.
>
> Status as of 2026-06-02: **deferred**. This document captures the
> analysis so it does not have to be re-derived later, plus the small
> hardening step we *do* take now (adding `addressMap.Wf` to
> `WellFormed`).

## 1. Where we stand today

The spec models `Domain.addressMap : Translation.AddressMap` as a flat
list of `MapEntry { gpa, hpa, size, rights }` with a disjointness
invariant `Wf` and 10 algebraic theorems (`Translation.lean`, 243 LOC,
zero sorries). It is wired into `Domain` (`State.lean:105`) and into
`mapSelf_apply` (the only action that mutates it).

`Translation.AddressMap.Wf` is **not** part of `WellFormed`. The
comment at `Properties.lean:1920` records the omission. The 10
algebraic theorems are not connected to any state-level preservation
property.

## 2. What `capa-engine` actually does

The Rust engine's address-space machinery is substantially richer.

### 2.1 Data structure (`translation.rs`, 1119 LOC)

- `AddressMap` is a `BTreeMap<gpa, MapEntry>` (sorted, gpa-keyed).
- `MapEntry` has **three** variants:
  - `Mapped { hpa, size, refcount: RightsRefCount }` — a contributing,
    visible mapping.
  - `Blocked { hpa, size, refcount: u64 }` — a contribution that is
    *visible to layout / disjointness* but is currently revoked or
    carved away.
  - `Reserved` — host reservations (not modeled in v2 by design,
    G15).
- `RightsRefCount` is a per-right counter, not a boolean. Multiple
  capability views of the same range stack additively;
  `effective_rights()` is the OR of present rights.
- Operations: `add_contribution` / `remove_contribution` (the heart —
  performs splitting, coalescing, refcount math), `block` / `unblock`
  (revocation flip), `split` (used by `change_rights`),
  `try_coalesce` / `coalesce_range`, `find_gpa_for_hpa`,
  `mapped_snapshot`. `address_map_diff` produces an `UpdateBatch` of
  hardware deltas.

### 2.2 View computation (`view.rs`, 367 LOC)

- `compute_view(cap)` walks the **memory-capability tree below
  `cap`** to compute the visible HPA ranges (with carved-out holes
  subtracted). Used by every footprint-modifying operation.
- The Lean spec has no analogue.

### 2.3 Integration in `capability.rs`

| Action      | What it does to `address_map` |
|-------------|-------------------------------|
| `carve`     | walks the parent's cached view, calls `add_footprint` on the child to insert mapped+blocked segments per visible range; on the parent it `split`s entries to drop rights for the carved-out region |
| `alias`     | `add_footprint` on the caller (alias child shares HPA, refcount goes up) |
| `send`      | computes view, checks `overlaps(gpa_base, cap_size)` on receiver, `block`s on sender, `add_footprint` on receiver |
| `send_at`   | sender supplies an explicit `gpa_base` hint (G10) |
| `accept`    | mirror of `send` on the receiver side |
| `map_self`  | `remove_footprint` at old GPA, `add_footprint` at new GPA, then `address_map_diff` |
| `revoke`    | for each removed segment, `unblock` on the owner using `find_gpa_for_hpa` |

### 2.4 Lean spec coverage

| Engine concept                  | Lean v2 status |
|---------------------------------|----------------|
| `Mapped` / `Blocked` / `Reserved` discriminator | flat — only one shape of entry |
| `RightsRefCount`                | absent |
| `add_contribution` (split + coalesce + refcount) | absent — `insert` is just `cons` |
| `remove_contribution`           | absent |
| `block` / `unblock`             | absent |
| `split` (on `change_rights`)    | absent |
| `try_coalesce` / `coalesce_range` | absent |
| `find_gpa_for_hpa`              | absent |
| `compute_view` (carved holes)   | absent |
| `address_map_diff` / hardware deltas | absent |
| Address-space mutation by `send`/`accept`/`carve`/`alias`/`revoke` | absent (only `mapSelf` mutates) |
| `addressMap.Wf` in `WellFormed` | absent (this doc adds it) |
| `send_at` (positional sends) | absent (gap G10) |
| Cache coloring (`ColorBitmap`)  | stubbed (gap G14, deferred by decision) |
| `Reserved` MapEntry variant     | dropped (gap G15, deferred by decision) |

## 3. Three layers for closing the gap

### 3.1 Layer A — Faithful semantics

Mirror the engine: refcount-augmented entries with mapped/blocked
split, `compute_view`, footprint add/remove on every action that
touches memory.

1. Rewrite `Translation.lean` from a flat list to a `Mapped`/`Blocked`
   model with a refcount type. ~600–900 LOC. Rebuild all 10 algebraic
   theorems plus ~20 new ones (`add_contribution_*`,
   `remove_contribution_*`, `block_*`, `unblock_*`, `split_*`,
   `coalesce_*`).
2. Add a `View.lean` module mirroring `view.rs`. ~150 LOC plus
   structural lemmas about the memcap tree walk.
3. Wire into 6 actions: `carve_apply`, `alias_apply`, `send_apply`,
   `accept_apply`, `mapSelf_apply`, `revoke_apply`.
4. Add `addressMap.Wf` to `WellFormed`; prove preservation across all
   21 actions (20 trivial, 6 substantive).
5. Re-discharge the cascade lemmas (`*_preservesParents`,
   `*_preservesIsRevoked`, etc.) for the 6 affected actions — the
   structural induction is unchanged but every per-action arm gets
   longer because state shape changes.
6. Model `send_at` (G10) as either a separate action constructor or a
   parameterized `Action.send`.

**Cost estimate:** 2–3 weeks of focused work. Comparable in scope to
everything done in v2 to date (cascade work, parent-stability,
provenance, channel ops). The refcount + split/coalesce logic is
genuinely intricate; expect non-trivial proof debt.

### 3.2 Layer B — Minimal faithful

Keep the flat-list shape, but add a `Mapped`/`Blocked` discriminator
and a boolean refcount-as-presence-bit. Wire send/accept/carve/alias/
revoke to add/remove single mapped/blocked entries. Skip
`compute_view` — pretend each capability contributes one footprint of
its own range. Add `Wf` to `WellFormed`. Defer G10.

**Cost:** ~1 week. Captures most of the cross-action `addressMap`
activity. Loses fidelity on aliased/carved overlapping regions —
strictly speaking the disjointness invariant `Wf` would not even hold
in Rust without the refcount model, so Layer B is structurally
simpler than reality but useful for theorems that do not require
coalescing.

**Risk:** the rewrite forces re-proving every existing
`addressMap`-touching theorem (~10) plus `mapSelf_apply` plus all
cascade `_preserves*` lemmas for the 6 affected actions.

### 3.3 Layer C — Hook only (rejected)

Have `send_apply`, `accept_apply`, `revoke_apply`, `carve_apply`,
`alias_apply` perform a `removeWithin` / `insert` similar to
`mapSelf_apply`. Add `Wf` to `WellFormed`.

**Cost:** ~2–3 days. **Rejected** because it bakes wrong semantics
into the spec: every theorem written against Layer C would be
invalidated when Layer A or B replaces it.

## 4. Why we are not doing Layer A or B now

Three reasons:

1. **Tier-4 theorems (O2, O4, O5, O6) are insensitive to address-map
   detail.** O2 is about subtree locality of `getDom`/`hasCapability`
   /`memHandles`; O4–O5 are CPU/scheduling state; O6 is interrupts.
   None of them turn on whether `addressMap` faithfully refcounts.
   Address-space confinement / runtime-memory NI is a *separate*
   theorem family (call it O9 if needed) which we have not yet
   committed to.

2. **Refinement is the natural forcing function for Layer A.** When
   Aeneas matures and we extract the Rust engine to a Lean
   functional model, we will have to align `Translation.lean` with
   the extracted code anyway. Doing Layer A now risks doing it
   twice — once as a hand model, once aligned to extraction. The
   hand-model would invariably diverge in subtle ways from what
   Aeneas produces.

3. **No theorem currently planned in O1–O8 is blocked on
   address-space modeling.** O1 (attestation) needs G13, not address
   maps. O2–O7 need their respective machinery, not address maps.

## 5. What we *do* now: `addressMap.Wf` as a `WellFormed` field

Cheap immediate win:

- Define `AddressMapsWf (s : SpecState) : Prop :=
    ∀ did d, s.getDom did = some d → d.addressMap.Wf`.
- Add a field `addressMapsWf : AddressMapsWf s` to `WellFormed`.
- Prove preservation across all 21 actions. For the 19 actions that
  don't touch `addressMap` and the `create` arm (which gets
  `empty.Wf`, trivial), preservation falls out structurally. The
  `mapSelf_apply` arm is the only substantive case: it requires that
  `Wf` is preserved by `removeWithin` and that the `noOverlap` guard
  feeds `Wf_insert`.

Estimated scope: ~150–250 LOC across `Invariants.lean`,
`Properties.lean`, and `Translation.lean`. No proof debt elsewhere.

This buys us:

- Whatever address-space theorems we eventually state (Layer A or B)
  can rely on disjointness as an invariant rather than a
  precondition.
- The `mapSelf` chain (`Wf_insert` → state-level `Wf`) becomes a
  reusable template for the 5 other actions when Layer B or A is
  taken.
- One less "outside `WellFormed`" carve-out comment in the codebase.

## 6. When to reopen this document

Reopen and pick a layer when **any** of the following becomes true:

- Aeneas extraction of `translation.rs` lands and we need to align a
  hand model with it (forces Layer A).
- We commit to an O9-style "address-space confinement / runtime-memory
  NI" theorem (forces Layer A or B depending on faithfulness needed).
- A refinement attempt for `send` / `accept` / `revoke` / `carve` /
  `alias` blocks because the Lean spec doesn't touch `addressMap` for
  those actions (forces Layer B at least).

Until one of those triggers fires, Tier-4 work proceeds without
address-space hardening beyond Section 5.

## 7. Cross-references

- `lean/ThemisCapa/Translation.lean` — current address-space algebra.
- `capa-engine/src/translation.rs` — the engine implementation we are
  measuring against.
- `capa-engine/src/view.rs` — `compute_view`, the missing module.
- `capa-engine/src/capability.rs:943` — `add_footprint`.
- `capa-engine/src/capability.rs:991` — `remove_footprint`.
- `capa-engine/src/capability.rs:1038` — `compute_address_space`.
- `docs/capability-engine/lean-v2-coverage-gaps.md` — gaps G10, G14,
  G15.
- `docs/capability-engine/aeneas-exploration.md` — refinement
  roadmap.
