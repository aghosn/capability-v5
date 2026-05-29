# Verifying `capa-engine` with Aeneas — Exploration & Plan

**Status:** Draft / exploration. No code changes yet.
**Audience:** Engineers considering formal verification of the Rust capability
engine (`capa-engine/`).
**Companion artifacts:**
- `lean/` — relational Lean 4 proof model (83 theorems)
- `lean-exec/` — executable Lean 4 model (computable functions, REPL)
- `capa-engine/` — production Rust implementation (~9.7k LoC, `no_std`)

---

## 1. Goal

Investigate whether [Aeneas](https://github.com/AeneasVerif/aeneas) can be used
to **translate the Rust capability engine into Lean 4** and bridge it to the
existing relational proof model in `lean/`, closing the gap between
"verified spec" and "executed code".

The end state we want to evaluate the feasibility of:

```
   capa-engine (Rust)               lean/ (relational spec)
          │                                  │
          │ Charon  →  LLBC                  │ 83 hand-written
          │ Aeneas  →  pure λ-calc           │ safety theorems
          ▼                                  ▼
   Lean 4 functional model  ──refinement──►  Spec
```

If achievable, this gives us *machine-checked* evidence that the executable
Rust implementation refines the existing Lean specification, replacing the
current `lean-exec/` differential-testing bridge with a proof.

---

## 2. Background on Aeneas

Aeneas is a verification toolchain built on top of [Charon](https://github.com/AeneasVerif/charon):

1. **Charon** compiles a Rust crate to LLBC (Low-Level Borrow Calculus), an
   MIR-derived IR with explicit loans/borrows.
2. **Aeneas** translates LLBC into a **pure λ-calculus** term in one of four
   backends: Lean 4, F\*, Coq, HOL4. The translation eliminates references
   using **backward functions** (giving-back continuations for `&mut`).
3. Proofs are then done *in the backend* using ordinary functional reasoning
   — no separation logic, no heap model.

The price for this simplicity is a **strict subset of Rust**:

| Feature | Aeneas support | Implication for us |
|---|---|---|
| Owned data, `&T`, `&mut T` | ✅ Full | Fine for value types |
| `Box<T>`, `Vec<T>` | ✅ Full | Fine |
| `Arc<T>` (immutable) | ⚠️ Recently improving; treated as shared owned | Usable if `T` is immutable |
| `Rc<RefCell<T>>` / `Arc<RwLock<T>>` | ❌ Not supported | **Blocker for current engine** |
| `Cell`/`RefCell`/atomics | ❌ Not supported | Blocker |
| `dyn Trait` objects | ⚠️ Partial / experimental | Affects `Platform` trait |
| `unsafe` blocks | ❌ Not supported | We have 1; trivial to isolate |
| Threads, `Send`/`Sync` | ❌ Out of scope | Must be argued externally |
| Loops, recursion | ✅ Full (loops lifted to recursion) | Fine |
| `no_std` + `alloc` | ✅ Fine (translation is on MIR) | Matches our config |

Confirmed by Aeneas docs and recent talks (2024–2025): interior mutability
patterns like `Arc<RwLock<T>>` are explicitly **outside** Aeneas's scope.
This is the single biggest design tension for our codebase.

---

## 3. Where `capa-engine` Stands Today

```
capa-engine/src/        LoC      Aeneas-friendliness
─────────────────────────────────────────────────────────────────────
error.rs                106      ✅ Pure value type
memory.rs               361      ✅ Pure value types (Rights, Region, …)
interposition.rs        275      ✅ Pure (CPUID/MSR policy bitmaps)
update.rs               440      ⚠️ Plain enums + Arc Weak references
attest.rs               856      ⚠️ Walks CDT via Arc
view.rs                 367      ⚠️ Reads CDT via Arc
translation.rs        1 119      ⚠️ Pure logic, but threaded via Arc
domain.rs             1 077      ❌ Heavy Arc<RwLock<…>>, Weak<…>
switch.rs               310      ❌ Per-core mutable state, dyn Platform
platform.rs             443      ❌ `dyn Platform`, lock guard trait
capability.rs         4 011      ❌ Core CDT: Arc<RwLock<Capability<T>>>,
                                    Weak parents, mutex-protected children
sync.rs                  70      ❌ RwLock abstraction
                       ─────
                      9 751
```

**Counts of shared-state primitives** (`Arc<`, `Weak<`, `RwLock`, `dyn`):

| File              | Count |
|-------------------|------:|
| `capability.rs`   |    25 |
| `domain.rs`       |    21 |
| `sync.rs`         |    18 |
| `switch.rs`       |     7 |
| `update.rs`       |     5 |
| `attest.rs`       |     4 |
| `platform.rs`     |     3 |
| others            |     2 |

The engine is **fundamentally structured around `Arc<RwLock<Capability<T>>>`
with weak back-edges** for the CDT. That data structure cannot be translated
by Aeneas as-is.

Good news: we already have an **Aeneas-shaped twin** — `lean-exec/` — which
re-encodes the same state machine as flat maps indexed by IDs, in a pure
`CapaM = ExceptT (StateM ExecState)` monad. That tells us a refactor *is*
possible; the question is whether we want to refactor the Rust side, port the
Lean executable model up to Rust, or do something in between.

---

## 4. Strategic Options

### Option A — Refactor `capa-engine` into an Aeneas-friendly form

Replace `Arc<RwLock<Capability<T>>>` and `Weak<…>` with **arena indices**
(`Vec<Capability<T>>` + `CapId(u32)` handles, mirroring `lean-exec/`).
Concurrency moves *outside* the verified core: a thin shell holds the global
RW lock and calls into the pure core.

- ➕ Aeneas can translate the result directly.
- ➕ Matches `lean-exec/` 1-for-1, so the bridge to `lean/` is short.
- ➕ Removes a class of `Arc` cycle / `Weak` upgrade bugs.
- ➖ Large refactor (~4 kLoC in `capability.rs` alone).
- ➖ Risks regressions in the production hypervisor path.
- ➖ Performance: arena indexing vs. pointer chasing — almost certainly fine
  (and probably faster) but needs benchmarking.

### Option B — Build a parallel "verified core" sub-crate

Carve a new crate `capa-engine-core/` containing **only** the pure state
machine (no `Arc`, no `RwLock`, no `dyn`). Today's `capa-engine/` keeps the
concurrent wrapper and delegates the actual tree mutation to the core. Apply
Aeneas to `capa-engine-core/` only.

- ➕ No risk to the in-tree engine.
- ➕ Smaller verified TCB; sharp boundary between verified/unverified code.
- ➕ Mirrors the `lean/` ⇄ `lean-exec/` split (spec vs. executable).
- ➖ Two implementations to keep in sync — we already have this problem with
  `lean-exec/`, and have invested in differential testing to cope.
- ➖ Doesn't directly verify the *deployed* code, only an isomorphic core.

### Option C — Verify only leaf modules

Apply Aeneas only to value-typed leaves (`memory.rs`, `interposition.rs`,
parts of `update.rs`, `attest.rs`'s pure helpers). Treat the rest as
trusted.

- ➕ Tractable in days, not months.
- ➕ Demonstrates the toolchain works in our setup.
- ➖ Doesn't prove the interesting safety properties (revocation soundness,
  capability monotonicity, send/accept atomicity), which live in
  `capability.rs`.

### Recommendation

**Phase the work**: start with Option C as a *spike* to validate the
toolchain on our codebase, then commit to Option B as the medium-term plan.
Option A is attractive long-term but should only be considered after Option B
has produced concrete refinement proofs that justify the disruption.

---

## 5. Phased Plan

### Phase 0 — Tooling setup (1–2 days)

1. Install Charon (`make setup-charon`) at the commit pinned by Aeneas.
2. Install Aeneas; verify `make test` of upstream passes locally.
3. Align Lean toolchains: `lean/`, `lean-exec/`, and Aeneas backend all use
   Lean 4. Confirm a single `lean-toolchain` version works for all three
   (today: `v4.29.0` in `lean-exec/`; check Aeneas requirements).
4. Decide repo layout: new `aeneas/` directory under repo root (mirrors
   `lean/`, `lean-exec/`) containing
   - generated `.llbc` artifacts,
   - generated Lean translations,
   - hand-written proof scripts.

**Exit criterion:** `charon cargo --preset=aeneas` runs on a trivial leaf
file (e.g. an extracted copy of `memory.rs::Rights`) and Aeneas emits Lean.

### Phase 1 — Leaf-module spike (Option C, 1 week)

Apply Aeneas to:
- `memory.rs` — `Rights`, `Access`, `Attributes`, `MemoryRegion` carve/alias
  logic. Pure value types and arithmetic; ideal first target.
- `interposition.rs` — CPUID/MSR policy bitmaps and `ProcFeatureConfig` —
  pure data + small lookups.
- `error.rs` — trivial; mostly a sanity check that Charon handles the crate.

Write Lean lemmas in the new `aeneas/` tree, e.g.:
- `Rights.is_subset_of` is reflexive, transitive, antisymmetric.
- `MemoryRegion.carve` preserves bounds and rights monotonicity.

**Exit criterion:** at least 5 non-trivial lemmas about extracted Rust
functions are mechanically checked in Lean.

### Phase 2 — Pure core extraction (Option B, 4–8 weeks)

Create `capa-engine-core/` exporting a side-effect-free state machine:

```rust
pub struct CoreState { /* arena vectors, like lean-exec's ExecState */ }

impl CoreState {
    pub fn carve(&mut self, …) -> Result<CapId, CapaError> { … }
    pub fn send(&mut self, …) -> Result<UpdateBatch, CapaError> { … }
    pub fn revoke(&mut self, …) -> Result<UpdateBatch, CapaError> { … }
    // …all CapaM operations from lean-exec/Operations/*.lean
}
```

Then refactor `capa-engine/`:
- Keep `Arc<RwLock<…>>` wrappers and `Platform` trait at the surface.
- On each operation: take the lock → `CoreState::op(&mut self, …)` → apply
  the resulting `UpdateBatch` through the existing IPI/barrier protocol →
  release.

Apply Aeneas to `capa-engine-core/`. Differential-test against the production
engine using the existing `capa-cli` regression harness (and against
`lean-exec/` via the existing FFI bridge).

**Exit criterion:**
1. Production hypervisor still boots dom0 + L2 guest (no regressions).
2. Aeneas successfully translates `capa-engine-core/` end-to-end.
3. The core CDT invariant ("rights monotonically decrease parent→child")
   is proved in Lean against the Aeneas extraction.

### Phase 3 — **Rewritten** relational spec + refinement (8–12 weeks)

See [§10 — Relational spec rebuild](#10--relational-spec-rebuild-for-refinement)
and [§11 — Target theorem inventory](#11--target-theorem-inventory) below for the
detailed plan. Summary:

1. The current `lean/` spec was written before refinement was a goal; its
   shape (`CarvePre/CarvePost : Prop` on nested inductive trees with no
   global state) is not the right target for an Aeneas extraction that
   produces a *state transformer* `s → Result (s', a)` over flat arenas.
   We need to rewrite the spec around a small-step transition relation
   `step : SpecState → Action → SpecState → Prop`.
2. Build a refinement relation `R : ExecState → SpecState → Prop` and prove,
   per operation, a square commutation:
   ```
   ∀ s s_spec a s'. R s s_spec  →  op_exec s a = Ok s'  →
        ∃ s_spec'. step s_spec a s_spec' ∧ R s' s_spec'
   ```
3. Re-prove the 83 properties on the new spec — most carry over with
   cosmetic changes; the global ones (`SystemInvariant`, `system_isolation`,
   the `ExecutePhase`/lock-protocol family) need restating.

**Exit criterion:** all P-numbered properties from the current spec hold on
the new spec, **and** every operation has a refinement lemma against the
Aeneas extraction.

### Phase 4 — Concurrency (research; potentially out of scope)

Aeneas does not model `Send`/`Sync`/threading. The argument for the engine is
that the global RW lock + IPI two-barrier protocol gives **sequentially
consistent** semantics: all observed states are reachable by some sequential
interleaving of operations. We have evidence for this from `loom` runs
(`cargo loom`, ~15 min, 49 tests).

Possible directions, none committed:
- Treat the lock + barrier protocol as an *axiom* and only verify the
  sequential core (pragmatic, matches what we'd get).
- Combine with an Iris-style separation-logic proof of the lock harness
  (huge effort, separate project).
- Wait for tooling — recent work like Mendel targets exactly this gap, but
  is not yet production-ready.

---

## 6. Risks & Unknowns

| Risk | Mitigation |
|---|---|
| Aeneas chokes on something innocuous (custom allocators, exotic generics, `const` arithmetic). | Spike (Phase 1) exists for this. Cap at 1 week and reassess. |
| `dyn Platform` not translatable. | The core never sees `dyn Platform` — only the outer wrapper does. Keep `Platform` outside the verified crate. |
| Two-implementation drift between `capa-engine` and `capa-engine-core`. | Reuse existing differential test harness (`capa-cli` + `lean-exec` bridge); extend it to drive the core directly. |
| `lean/` and Aeneas pin incompatible Lean versions. | Check in Phase 0; worst case, version-pin per sub-project and bridge via Lean's `lake` dependency mechanism. |
| Refinement proofs (Phase 3) blow up in complexity for `revoke`. | Stage by operation. If `revoke` proves intractable, ship Phases 0–2 + carve/alias/send refinement as a milestone. |
| Concurrency story remains informal. | Be honest about scope: "sequential core verified; concurrency wrapper argued via loom + design review." This is still a large improvement over today. |

---

## 7. Concrete First Steps (when work begins)

1. Open a tracking issue and link this document.
2. Phase 0 setup PR: add `aeneas/` directory, `charon-pin`, build script,
   CI job that runs Charon + Aeneas on a single throwaway file.
3. Phase 1 spike PR: extract `memory.rs` value types into an isolated
   compilation unit (`#[cfg]`-gated or a tiny sub-crate), translate, and
   prove ≥5 lemmas.
4. Write a short report in this directory summarising what Aeneas accepted,
   what it rejected, and any quirks. Update Section 6 of this document with
   the findings before deciding to commit to Phase 2.

---

## 8. Open Questions for the Team

- Are we willing to maintain a third Lean artifact (`aeneas/` extraction) on
  top of `lean/` (spec) and `lean-exec/` (executable model)? Or should the
  Aeneas extraction *replace* `lean-exec/` once it reaches parity?
- Is there appetite for the Phase 2 refactor (carving out
  `capa-engine-core/`)? Or do we prefer to keep Aeneas confined to leaf
  modules indefinitely?
- Who owns the Lean proof effort in Phase 3? It requires Lean expertise
  comparable to what produced the 83 theorems in `lean/`.

---

## 9. References

- Aeneas — <https://github.com/AeneasVerif/aeneas>
- Charon — <https://github.com/AeneasVerif/charon>
- Aeneas Lean tutorial — `aeneas/tests/lean/Tutorial` in the upstream repo
- Galois write-up: "Aeneas: Rust Verification by Functional Translation"
- This repo: `lean/` (spec), `lean-exec/` (executable model),
  `capa-cli/regression/` (differential testing harness)

---

## 10 — Relational spec rebuild for refinement

### 10.1 Why the current spec is the wrong target

The 83-theorem `lean/ThemisCapa/` corpus was authored as a stand-alone proof
artifact and predates the goal of refining a Rust implementation. Concretely:

| Issue | Why it blocks refinement against Aeneas output |
|---|---|
| Per-operation `XxxPre/XxxPost : Prop` on **local** capability trees | Aeneas produces a *state transformer* `s → Result (s', a)`. There is no global state to match `Post` against. |
| State is **implicit** (`SystemState` is "abstract only", per `current-specification.md`) | A refinement relation needs an explicit spec state to relate to the exec state. |
| `MemCap` / `DomCap` are nested inductive trees with structural recursion. | Aeneas extraction uses flat arenas with `CapId(u32)` handles. The structural mismatch is exactly where refinement work concentrates. |
| Several operations missing or partially specified (see §1.2 of `current-specification.md`: `add_vp`, `register_comm`, `set_register`, `get_chan`, `attest`, …). | Refinement must cover **every** operation Aeneas extracts, or the extraction is incomplete. |
| Concurrency is "out of scope" (informal note). | Acceptable, but the spec must at least *state* the sequential reduction it assumes. |

### 10.2 Shape of the new spec

Re-cast the spec as a **small-step labelled transition system**:

```lean
structure SpecState where
  domains   : Finmap DomId Domain
  memcaps   : Finmap CapId MemCap        -- with parent/children fields
  domcaps   : Finmap CapId DomCap
  cores     : Finmap CoreId CoreState
  pending   : Finmap DomId (List PendingCap)
  root      : DomId

inductive Action where
  | carve      (caller : DomId) (parent : CapId) (acc : Access) (attrs : Attributes)
  | alias      (caller : DomId) (parent : CapId) (acc : Access) (attrs : Attributes)
  | send       (caller : DomId) (cap : CapId) (receiver : DomId)
  | accept     (caller : DomId) (id : PendingId) (gpa : Option GPA)
  | reject     (caller : DomId) (id : PendingId)
  | revoke     (caller : DomId) (cap : CapId)
  | create     (caller : DomId) (cores : CoreMask) (api : MonitorAPI)
  | seal       (caller : DomId) (child : DomId)
  | switch_fwd (core : CoreId) (target : DomId) (vp : VpId)
  | switch_ret (core : CoreId)
  | interrupt  (vector : Vec) (domain : DomId) (core : CoreId)
  | …

inductive step : SpecState → Action → SpecState → Prop
  | carve  : CarveGuard s c p acc attrs → step s (.carve c p acc attrs) (carve_apply s c p acc attrs)
  | …
```

Each `step` constructor is built from the *old* `XxxPre/XxxPost` predicates,
reused verbatim where possible. The transition relation is what the
refinement targets:

```lean
def R (e : ExecState) (s : SpecState) : Prop := …  -- arena ↔ tree bisim

theorem refinement_carve :
  R e s → op_carve_exec e c p acc attrs = .ok e' →
    ∃ s', step s (.carve c p acc attrs) s' ∧ R e' s'
```

### 10.3 Migration of the 83 existing theorems

Each existing property `P` falls in one of three buckets:

| Bucket | Examples | Migration effort |
|---|---|---|
| **A. Pure-functional, state-agnostic.** Stated over `Rights`, `Access`, `MemCap`/`DomCap` algebraically. | `rights_subset_trans`, `access_contained_trans`, `chain_rights_monotonic`, `two_level_*`, `subtree_isolation` | Trivial — re-statement is the same; reuse proof. |
| **B. Per-operation pre/post invariance.** Stated as "if `XxxPre` then `XxxPost` preserves Q". | `carve_preserves_wellformed`, `send_preserves_wellformed`, `revoke_preserves_wellformed`, `*_requires_authority` | Mechanical — re-state as "`step s a s' → Q s → Q s'`"; reuse proof body modulo a few rewrites. |
| **C. Global / system-level.** Reason about `SystemInvariant`, `ExecutePhase`, the lock protocol. | `system_isolation`, `cdt_wellformed_frame`, `a1_validate_before_modify`, `lock_hierarchy_strict`, the `execute_*` family. | Need rework — these are the ones that benefit most from being restated against the new `SpecState`. |

Estimate: ~60 % of the 83 theorems migrate in bucket A/B with mostly
mechanical changes; the remaining ~40 % (bucket C) take real proof work,
because the new spec gives us a sharper way to state them.

### 10.4 Plan for the rewrite — archive v1, build v2 direct

We **do not** build v2 alongside v1 and prove equivalence. That would
double the work and the equivalence proof itself would be substantial.
Instead:

1. **Snapshot** today's `lean/` into `lean/archive-v1/` in a single commit.
   Git history is the regression mechanism — we can always revisit a
   v1 theorem statement when we want to mirror it in v2.
2. **Replace** the contents of `lean/ThemisCapa/` with the v2 spec
   (built fresh from the structure in §10.2). The directory layout is:
   - `State.lean` — `SpecState`, finmaps, well-formedness predicates.
   - `Action.lean` — the `Action` GADT (one constructor per public op).
   - `Step.lean` — `step : SpecState → Action → SpecState → Prop`, one
     constructor per `Action`, reusing the v1 `XxxPre`/`XxxPost` predicates
     as building blocks where convenient.
   - `Invariants.lean` — `WellFormed`, `Isolated`, `MonotonicAuthority`,
     `LockProtocol`, etc.
   - `Properties.lean` — the Tier-1 theorem suite (T1–T8 in §11.2),
     plus the lemmas that discharge them. We port v1 lemmas as needed,
     looking them up in `lean/archive-v1/` on demand.
3. Update `lean-exec/` to import the v2 types (currently imports
   `ThemisCapa.Basic`, `.Domain`, etc.). Most v1 types — `Rights`,
   `Access`, `MonitorAPI`, `VpRunState`, `DomainStatus` — carry over
   unchanged, so the impact on `lean-exec/` is limited.
4. Add a one-shot `lean/archive-v1/README.md` documenting which v1
   theorems map to which v2 theorems (and which were intentionally
   dropped). This is the audit trail.

### 10.5 Effort estimate for v2

For one experienced Lean 4 engineer familiar with this codebase, working
roughly full-time on it:

| Workstream | Scope | Effort |
|---|---|---|
| **W1. Snapshot v1, scaffold v2 dirs.** | One commit; new file skeleton. | 0.5 week |
| **W2. State + Invariants.** | `SpecState` (finmaps for domains/memcaps/domcaps/cores/pending), `WellFormed`, `UniqueIds`, `CoreExclusive`, `PolicyMonotonic` — restated globally. ~300–500 LoC. | 1.5 weeks |
| **W3. Action GADT + Step relation.** | ~14 actions × small constructor each. Heavy reuse of v1 `XxxPre`/`XxxPost`. ~500 LoC. | 2 weeks |
| **W4. Re-port type library.** | `Rights`, `Access`, `Attributes`, `RegionKind`, `MonitorAPI`, `VpRunState`, `VpCallContext`, `DomainPolicy` — mostly cut-and-paste from v1. | 1 week |
| **W5. Re-prove Bucket A** (algebraic). | `rights_subset_*`, `access_contained_*`, `chain_*`, `two_level_*`, `deep_isolation`, `overlaps_*`, `WellFormedChain.append` — ~25 theorems. Proofs largely reusable. | 1.5 weeks |
| **W6. Re-prove Bucket B** (per-op invariance, lifted to `step`). | `*_preserves_wellformed`, `*_requires_authority`, `*_no_amplification`, `*_nondestructive`, `seal_freezes_policy`, `create_policy_monotonic`, VP transition exhaustiveness, switch symmetry, accept/reject unfreeze, `interrupt_preserves_chain` — ~35 theorems. Bodies need adapting to `step`, but the *mathematical* arguments are unchanged. | 3 weeks |
| **W7. Restate + re-prove Bucket C** (global / system-level). | `SystemInvariant` (now stated over `SpecState`), `system_isolation`, `cdt_wellformed_frame`, `*_preserves_cdt`, the `ExecutePhase` / `LockLevel` / `ValidExecute` family, `a1_validate_before_modify`, `lock_hierarchy_strict`, `atomicity_window`, `execute_*`, `*_justified` — ~25 theorems. This is the most interesting work: the new spec lets us state several of them more sharply (especially the `execute_*` family). | 4 weeks |
| **W8. Add operations missing from v1.** | `add_vp`, `register_comm`, `set_register`/`get_register`, channel ops (`get_chan`, `send_channel`, `accept_channel`, `reject_channel`), `attest`/`attest_self`, `set_policy`/`get_policy`, `send_at`/`accept_at`. Per `current-specification.md` Phase 2/3 of the existing roadmap. ~12 new step constructors + lemmas. | 3 weeks |
| **W9. Tier-1 theorems** (T1–T8 in §11.2 — except T1 refinement, which is Phase 3 of the Aeneas plan, not the spec rewrite). | Lift Bucket-B theorems to system-trace statements: monotonic authority, CDT preservation across traces, revocation completeness as a trace property, etc. ~8 top-level theorems backed by the W5–W8 lemmas. | 2 weeks |
| **W10. Update `lean-exec/` imports + buffer.** | Re-point imports, fix breakage, address review feedback. | 1.5 weeks |
| **Total** |  | **≈ 20 weeks (≈ 5 calendar months)** for one engineer. |

A two-engineer team could collapse this to ~3 months by parallelising
W5/W6 (Bucket A/B reproofs) with W7 (Bucket C restatement) and W8 (new
operations), since those workstreams touch disjoint files.

**Sensitivity:**
- Optimistic (−25 %, ~15 weeks): Bucket B reproofs really are mechanical
  and v1's `omega`/`simp`/`decide` calls just work after rewrites.
- Pessimistic (+50 %, ~30 weeks): Bucket C requires several spec
  iterations as we discover that the v1 `Execute*` formulation doesn't
  generalise cleanly; the finmap encoding triggers automation slowdowns
  that we have to engineer around (this happens in Lean 4 with large
  proof terms).

**De-risking suggestion.** Before committing to the full 20-week plan,
spend **1 week on a vertical slice**: pick a single operation (`carve`),
do W2/W3/W6/W9 *for that one op only*, and see how the resulting state +
step + theorem statements feel. The decision to go forward is then
informed rather than speculative.

### 10.6 What we explicitly do *not* do in v2

- **No equivalence proof v1 ⇔ v2.** Git is the audit trail.
- **No refinement to Aeneas extraction yet.** That is Phase 3 of the
  outer plan; v2 just *enables* it by providing the right shape of spec.
- **No concurrency model.** Sequential `step` only. Tier-2 theorem T11
  (linearizability) is out of scope.
- **No information-flow framework** (no Tier-2 T10). Standard unwinding
  conditions are easy to bolt on later once the small-step spec exists.

---

## 11 — Target theorem inventory

This section answers the question: *given Themis-specific design choices,
which theorems do we actually want to prove, and which can we borrow
formulations for?*

### 11.1 What related projects prove

| Project | Top-level theorem(s) | Property class |
|---|---|---|
| **seL4** (Klein 2009 + Murray 2013) | (1) Functional correctness: implementation refines abstract spec. (2) Integrity: state changes are bounded by the access-control policy. (3) Authority confinement: subjects cannot gain authority beyond what was explicitly delegated. (4) Information-flow noninterference. | Refinement; integrity; confinement; IFC. |
| **CertiKOS** (Gu et al., OSDI 16 / CACM 19) | Contextual refinement at every abstraction layer; process isolation under fine-grained concurrent execution. | Layered refinement; concurrent isolation. |
| **Komodo** (Ferraiuolo et al., SOSP 17) | Enclave confidentiality + integrity at the assembly level; noninterference between mutually-distrusting enclaves. | Refinement; IFC; assembly-level guarantees. |
| **Hyperkernel** (Nelson et al., SOSP 17) | Per-operation push-button refinement against a finite-state spec. | Refinement (automated). |
| **Verismo** (Zhou et al., OSDI 24, AMD SEV-SNP) | Confidentiality + integrity of guest VMs against a Byzantine hypervisor, given hardware assumptions. | IFC under attacker model. |
| **CHERI** (Cerberus-BMC, Nienhuis 2020) | Capability monotonicity; provenance; reachable-capabilities-only execution. | Capability-specific algebraic laws. |

The pattern is consistent: **refinement against a small-step spec is the
backbone**, with **integrity / confinement / monotonicity** as cross-cutting
state-machine invariants, and **information-flow noninterference** as the
high-water mark.

### 11.2 What Themis specifically needs

Themis is closer to seL4 (capability kernel) than to CertiKOS (concurrent
process OS) or Verismo (SEV-SNP-specific). We target three tiers:

#### Tier 1 — Tractable now (≤ 12 months)

| Theorem | Statement (informal) | Status today |
|---|---|---|
| **T1. Refinement** | Every reachable trace of the Rust engine corresponds to a trace of the spec under `step`. | New (Phase 3) |
| **T2. Monotonic authority** | The authority of a domain `d` cannot increase except via an explicit `accept` of an incoming `send` from a domain that already had that authority. | Strengthen P6 (`send_no_amplification_*`) and state globally. |
| **T3. CDT well-formedness preservation** | Every `step` preserves `WellFormedTree`, `UniqueIds`, `CoreExclusive`, `PolicyMonotonic`. | Already proved per-op (P17/P19/P20/P25/P40-P42); restate against `step`. |
| **T4. Revocation completeness** | After `revoke c` returns, every descendant capability of `c` is gone and every hardware mapping derived from `c` is unmapped (and zeroed for `CLEAN`). | Today's P5/P33–P37; tighten to a global state-machine statement. |
| **T5. Validate-before-modify (A1)** | No hardware update is applied before the validating `step` succeeds. | Today's P43/P53–P56; restate at the exec/spec interface. |
| **T6. Sealed-domain immutability (A2 corollary)** | Once a domain is sealed, no `step` modifies its `DomainPolicy`. | Today's P7; restate. |
| **T7. Lock protocol soundness** | Every `execute` call respects the `LockLevel` ordering — no deadlock, no two writers, no writer overlapping a reader. | Today's P44/P48/`atomicity_window`; restate against new ExecState. |
| **T8. VP state-machine soundness** | Only the 8 enumerated transitions occur; no VP reaches an unreachable state. | Today's P9a–f; restate. |

#### Tier 2 — Reach for, plan separately

| Theorem | What it would say | Why it's harder |
|---|---|---|
| **T9. Spatial isolation** | If domain `d₁` has no capability derived from a memory region `m`, then no `step` initiated by `d₁` changes any byte of `m`. | Requires a memory model on top of the spec (today's spec is byte-free). |
| **T10. Sequential noninterference** | For any two states `s₁ ≈_d s₂` (indistinguishable to domain `d`), an action by another domain `d' ≠ d` leaves `s₁` and `s₂` `d`-indistinguishable. | Standard unwinding-conditions proof; needs an observation function. |
| **T11. Linearizability of concurrent ops** | Every concurrent execution permitted by the global RW lock is equivalent to *some* sequential execution under `step`. | Needs an Iris-style concurrency framework, or a hand proof for the lock+barrier protocol. We have `loom` evidence today, not a proof. |

#### Tier 3 — Aspirational

| Theorem | Comment |
|---|---|
| **T12. End-to-end IFC against a malicious dom0** | seL4-grade; requires modeling the hardware boundary, IOMMU, EPT, and an attacker. Multi-year effort. |
| **T13. Liveness / progress** | Every well-formed call terminates / produces a response. Themis has no waits today, but `pending` queues complicate this. |
| **T14. Attestation soundness** | The attestation hash uniquely identifies the CDT subtree. Needs a cryptographic axiom. |

### 11.3 Mapping to the existing 83 properties

Almost every Tier-1 theorem above is *already represented* in `lean/` —
typically as a per-operation lemma. The Phase 3 work is to **lift these
from per-operation to per-system-trace** statements and connect them to
Aeneas-extracted code via refinement. The 83-theorem corpus is not thrown
away; it becomes the lemma library used to discharge the new global
theorems.

### 11.4 What we deliberately do *not* aim for

- We do not aim to verify the **bare-metal capavisor** (`themis/capavisor/`)
  itself. Aeneas does not handle inline assembly, VMCS programming, or
  IOMMU register I/O.
- We do not aim to verify **Linux dom0**, `thhv.ko`, or
  `cloud-hypervisor/`. These are part of the TCB by design.
- We do not aim to verify the **`Platform` trait implementation**. It is
  the trust boundary between verified engine and unverified hardware.

---

## 12 — Abstracting `Arc<RwLock<…>>` away from Aeneas — **deferred**

> **Update (2026-05-29).** The Aeneas team is reportedly working on first-class
> `Arc<RwLock<T>>` support. The full structural refactor described below
> remains on the table as a contingency, but we should not invest in it
> until that upstream work has landed (or been confirmed to stall). Until
> then, use the workarounds in §12.0.

### 12.0 Workarounds while waiting for upstream support

We have three pragmatic levers, in increasing order of effort, to keep the
verification effort moving without committing to the full split:

1. **Stay in the leaves.** Apply Aeneas only to `error.rs`, `memory.rs`,
   `interposition.rs`, and the pure helpers in `update.rs`/`attest.rs`.
   These never touch `Arc` or `RwLock`. This is Phase 1 of the existing
   plan and is valuable on its own — it lets us prove the algebraic
   properties (rights subset, access containment, chain monotonicity)
   directly against the production Rust, today.
2. **Axiomatise the locking layer.** Charon supports marking functions as
   *opaque* (translated as uninterpreted symbols on the Lean side). We
   can mark the `Arc::new` / `RwLock::read` / `RwLock::write` boundary as
   opaque and prove properties about the body of operations modulo those
   axioms. This is brittle (every call site needs review) but unlocks
   verification of `capability.rs` internals without waiting.
3. **Maintain a small `unsafe`-isolation shim** that exposes the
   capability cells as `&mut Capability<T>` to the engine, using the
   global RW lock as the *external* witness that aliasing is safe. The
   shim itself is unverified; everything downstream of it sees Aeneas-
   friendly types.

Whichever lever we pull, we keep the production `capa-engine/` source
unchanged. The structural refactor (§12.1–§12.6 below) becomes a
contingency we land only if upstream Aeneas support is delayed past the
Tier-1 theorem milestone.

---

### 12.1 (Contingency) why the full split would be needed

The user's original question: *can we hide the `Arc<RwLock<T>>` behind a
trait and feature-select an Aeneas-friendly implementation?*

**Short answer:** the **locking** is easy to abstract away; the **sharing**
is the hard part. `Arc` gives us *aliased mutable references*, which Rust
fundamentally cannot express without interior mutability — and Aeneas
fundamentally cannot translate. So a literal "swap `Arc<RwLock<T>>` for
something else" trait is not viable. We need a slightly bigger surgery,
but it is well-bounded.

### 12.2 What `sync.rs` already does

The codebase already feature-selects the `RwLock` implementation
(`loom` / `parking_lot` / `spin`) in `sync.rs`. This precedent is helpful
but only addresses **half** the problem — the lock — and Aeneas's blocker
is the **interior-mutability cell** (`UnsafeCell` inside the lock).

### 12.3 The real shape of the problem

The CDT today is `Arc<RwLock<Capability<T>>>` with `Weak` back-edges. The
key uses are:

1. Two siblings (or a parent and a child) may both hold references to the
   same cell at the same time.
2. The capability operation walks the tree, takes write locks on cells it
   mutates, and read locks on cells it reads.
3. Cells may be aliased from multiple containers (`children`,
   `memory_capabilities`, `pending`, etc.).

In an Aeneas-friendly setting, the only way to keep arbitrary aliasing
*and* mutability is to put the cells in an **arena** and replace pointers
with arena indices. That is exactly what `lean-exec/` does.

### 12.4 Proposed two-layer architecture (contingency)

```
┌─────────────────────────────────────────────────────────────────┐
│  capa-engine  (existing crate, unchanged API to callers)        │
│                                                                 │
│  Arc<RwLock<State>>                                             │
│        │                                                        │
│        ▼  takes lock once per operation, then:                  │
│  fn execute(state: &mut State, op: Op) -> Result<UpdateBatch>   │
│                              │                                  │
│                              ▼                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  capa-engine-core  (new crate, NO Arc / NO RwLock)        │  │
│  │                                                           │  │
│  │  pub struct State {                                       │  │
│  │    memcaps : Arena<CapId, MemCap>,                        │  │
│  │    domcaps : Arena<CapId, DomCap>,                        │  │
│  │    domains : Arena<DomId, Domain>,                        │  │
│  │    …                                                      │  │
│  │  }                                                        │  │
│  │  impl State {                                             │  │
│  │    pub fn carve(&mut self, …) -> Result<CapId> { … }      │  │
│  │    pub fn send (&mut self, …) -> Result<UpdateBatch> { …} │  │
│  │  }                                                        │  │
│  │  // Only owned values, &T, &mut T, Vec, Box, BTreeMap.    │  │
│  │  // Charon-and-Aeneas friendly.                           │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

The outer `capa-engine` keeps **all** the concurrency primitives and the
`Platform` trait. The inner `capa-engine-core` is what Aeneas sees. No
trait is needed at the interior — `&mut State` *is* the abstraction.

The cost we pay: parent/child links in capabilities become `CapId`s rather
than `Arc`/`Weak`. Lookups become `state.memcaps.get(id)` instead of
`arc.read()`. Removal becomes "free the slot and walk the children list"
rather than "drop the last `Arc`".

This is the same transformation `lean-exec/` already validated; we are
porting that design back into Rust under a verification banner.

### 12.5 Why a trait won't get us all the way

We could *try* the following:

```rust
pub trait Cell<T> {
    fn read<R>(&self,  f: impl FnOnce(&T) -> R) -> R;
    fn write<R>(&self, f: impl FnOnce(&mut T) -> R) -> R;
}

#[cfg(not(feature = "verified"))]
impl<T> Cell<T> for Arc<RwLock<T>> { … }

#[cfg(feature = "verified")]
impl<T> Cell<T> for ??? { … }      // ← stuck here
```

There is no `???` that:
- gives you `&mut T` from `&self` (no interior mutability),
- supports arbitrary aliasing (parent + multiple children),
- compiles under Aeneas.

Any single-owner alternative (`Box`, `&mut T`, `Rc` without `RefCell`)
violates aliasing. Any aliasing-friendly alternative (`Cell`, `RefCell`,
`Arc<Mutex<>>`, atomics) is rejected by Aeneas. The trait abstraction
breaks down at the type signature.

**Conclusion:** abstract at the **state-machine boundary** (outer wrapper
vs. inner pure core), not at the **cell boundary**.

### 12.6 Migration path that keeps both worlds working

The split lets us migrate incrementally:

1. **Step 1.** Create `capa-engine-core/` as a thin façade that internally
   still calls `capa-engine/`. Public API: pure functions on a `State`
   stub. Nothing verified yet.
2. **Step 2.** Move `error.rs`, `memory.rs`, `interposition.rs` (pure
   value types) wholesale into the core. Run Aeneas on those (Phase 1
   spike target).
3. **Step 3.** Introduce `Arena<Id, T>` and re-implement `update.rs` and
   `attest.rs`'s pure helpers against it.
4. **Step 4.** Re-implement `Capability<T>` over arena handles. This is
   the bulk of the work (~4 kLoC equivalent in `capability.rs`).
5. **Step 5.** Re-implement the operations (`carve`, `alias`, `send`,
   `accept`, `reject`, `revoke`, `create`, `seal`). Differential-test
   each against the existing engine and against `lean-exec/`.
6. **Step 6.** Replace `capa-engine/`'s capability tree with an
   `Arc<RwLock<core::State>>`. The outer crate becomes ~500 LoC of
   locking, IPI, and `Platform` glue. The inner crate is the verified
   core.

At every step both crates compile and the production hypervisor keeps
booting. The cut from old engine to new is the day step 6 lands.

### 12.7 What happens to `lean-exec/`?

Once `capa-engine-core/` exists and Aeneas extracts it, `lean-exec/`
becomes redundant (its job — being a pure single-threaded Lean model — is
now done by the extracted Rust). We can either:

- **Retire** `lean-exec/` after parity (one fewer artifact to maintain).
- **Keep** it as a third oracle for differential testing (Rust core vs.
  Aeneas-extracted Lean vs. hand-written Lean exec). Robust but
  expensive.

Recommend retiring after parity, but defer the decision until Phase 3 is
underway.

---

## 13 — Updated open questions for the team

In addition to §8:

- §10.5 estimates **≈ 20 weeks (5 months) for one engineer** to land v2,
  including the 8 new operations missing from v1. Two engineers in
  parallel can compress to ≈ 3 months. Is that budget available?
- Are we comfortable with the **archive-not-equivalence** approach in
  §10.4? Once v1 is archived, the 83 v1 theorems are no longer
  machine-checked against the current spec — we rely on git history and
  the audit-trail README. This is a real loss of automation in exchange
  for not paying for the equivalence proof.
- Tier 1 theorems (T1–T8) are reachable once v2 lands. Tier 2 (esp. T11
  concurrent linearizability) needs separate planning and possibly a
  different proof framework. Do we commit to Tier 1 only?
- If upstream Aeneas `Arc<RwLock<T>>` support **stalls**, are we willing
  to land the `capa-engine-core/` split (§12.1–§12.6) anyway? That work
  is invasive and only pays off once Phase 3 refinement starts.
