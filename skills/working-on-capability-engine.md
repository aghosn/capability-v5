# Skill: Working on the Capability Engine (capa-engine/)

## When to Use

Use this skill when you need to:
- Modify, extend, or debug the `capa-engine/` capability engine crate.
- Add new capability operations or extend existing ones.
- Write or update tests for the engine.
- Verify that changes do not regress the capa-cli simulator.
- Understand the locking model before touching concurrent paths.

---

## Background: What the Capability Engine Is

`capa-engine/` is a `no_std`-compatible Rust library (`capa-engine`) that implements
a capability-based security system for managing trust domains with composable isolation.
It is platform-independent and hardware-agnostic — the only hardware contact point is the
`Platform` trait (see below).

**Key rule (Axiom A1 from `CONTEXT.md`)**: the engine validates all operations before any
hardware state changes. Hardware changes happen only through `Platform::apply_update`,
called after the capability tree mutation succeeds.

---

## Module Map

```
capa-engine/src/
  lib.rs           — crate root; all public re-exports
  capability.rs    — Capability<T> tree nodes; CDT ops; extension traits
  domain.rs        — Domain, DomainPolicy, MonitorAPI, VP states, interrupt policy
  memory.rs        — MemoryRegion, Access, Rights, Attributes, RegionKind
  update.rs        — Update enum, UpdateBatch, UpdateProcessor (simulation helper)
  platform.rs      — Platform trait; execute() entry point
  switch.rs        — SwitchManager, CoreContext, interrupt routing up the domain CDT
  view.rs          — compute_address_space; merged AddressSpaceView
  attest.rs        — attestation reports, enumerate_domain_tree
  sync.rs          — internal RwLock alias (parking_lot / loom / spin)
  error.rs         — CapaError enum, Result<T>
  translation.rs   — AddressMap, GPA→HPA mapping (feature: address_translation)
```

---

## The External Interface: Domain-Mediated API (Axiom A9)

**Only use the domain-mediated API.** Internal primitives (methods marked `#[doc(hidden)]`)
are for the engine's own use. External callers — including capavisor's `platform.rs` and
all tests — must go through the domain-mediated layer.

The domain-mediated functions live as associated functions on `Capability<Domain>` in
`capability.rs`. All of them:
1. Verify the calling domain is sealed and holds the required `MonitorAPI` bit.
2. Perform the tree mutation.
3. Return an `UpdateBatch` for the caller to apply.

| Operation | Function | Required API bit | Lock |
|-----------|----------|-----------------|------|
| Create child domain | `Capability::<Domain>::create(parent, policy)` | `CREATE` | Shared |
| Seal domain | `Capability::<Domain>::seal(caller, handle)` | `SEAL` | Shared |
| Carve memory | `Capability::<Domain>::carve(caller, mem, access)` | `CARVE` | Shared |
| Alias memory | `Capability::<Domain>::alias(caller, mem, access)` | `ALIAS` | Shared |
| Send memory | `Capability::<Domain>::send(caller, mem, target, attrs)` | `SEND` | Shared |
| Revoke memory | `Capability::<Domain>::revoke(caller, handle)` | `REVOKE` | **Exclusive** |
| Revoke domain | `Capability::<Domain>::revoke_domain(caller, handle)` | `REVOKE` | **Exclusive** |
| Register COMM page | `Capability::<Domain>::register_comm(caller, mem, child, vp)` | `SEND` | Shared |
| Get channel | `Capability::<Domain>::get_chan(caller, target)` | `GETCHAN` | Shared |
| Send channel | `Capability::<Domain>::send_channel(caller, chan, target)` | `SEND` | Shared |
| Accept channel | `Capability::<Domain>::accept_channel(receiver, id)` | — | Shared |
| Attest domain | `Capability::<Domain>::attest(caller, target)` | `ATTEST` | Shared |
| Switch | `Capability::<Domain>::switch(caller, target, core, vp)` | `SWITCH` | Shared |
| Set interrupt policy | `Capability::<Domain>::set_policy(caller, target, ...)` | `SET` | Shared |

Every call must be wrapped in `execute()` (see Locking Model below).

---

## Locking Model

### Overview

Two levels of locking exist:

1. **Per-node lock**: every `Capability<T>` is `Arc<RwLock<Capability<T>>>`. Concurrent
   readers share; writers (adding/removing children) take an exclusive lock on that node
   only. Engine code acquires these locks internally — callers never touch them directly.

2. **Global operation lock (via `Platform` trait)**: a single coarse-grained RW lock
   serialises all tree mutations. This is the primary concurrency primitive.

### Shared vs. Exclusive

| Category | Lock | Operations |
|----------|------|-----------|
| Non-destructive | **Shared** | carve, alias, send, create, seal, get-chan, attest, switch |
| Destructive | **Exclusive** | any revoke (memory or domain) |

Multiple non-destructive operations run concurrently. Any revoke takes an exclusive lock
and blocks until all shared holders have released.

### The `execute()` Entry Point

**All capability operations must go through `execute()`**. Never call the domain-mediated
functions directly without `execute()` — they do not acquire the global lock themselves.

```rust
use capability_engine::{execute, Platform};

// Non-destructive (shared lock, exclusive = false)
let (result, _batch) = execute(&platform, /*exclusive=*/false, || {
    Capability::<Domain>::carve(&caller, &mem_ref, access)
        .map(|batch| (child_ref, batch))
})?;

// Destructive (exclusive lock, exclusive = true)
execute(&platform, /*exclusive=*/true, || {
    Capability::<Domain>::revoke(&caller, child_handle)
        .map(|batch| ((), batch))
})?;
```

`execute()` runs the full protocol:
1. Acquire shared or exclusive lock.
2. Run the closure (pure tree mutation) → get `(result, UpdateBatch)`.
3. For each core running an affected domain: send IPI → barrier 0 → apply updates → barrier 1.
4. Call `on_domain_revoked` for each `RevokeDomain` in the batch.
5. Release lock.

For platforms with only one core or in simulation, steps 3–4 reduce to a simple
`apply_update` call per entry (no IPI, no barrier).

### Destructive vs. Non-Destructive Paths

**Non-destructive path** (shared lock, most operations):
- Tree grows: new child nodes are created and linked.
- `UpdateBatch` typically contains `ChangeRights` entries granting access.
- Multiple non-destructive operations on different domains are safe to run in parallel.

**Destructive path** (exclusive lock, any revoke):
- Tree shrinks: child nodes and their entire subtrees are unlinked and dropped.
- `UpdateBatch` contains `ChangeRights` (remove), `ZeroMemory` (if `CLEAN`), 
  `RevokeDomain` (if `VITAL` or domain revoke), `UncommRegion` (if `COMM`).
- Update ordering within a batch is guaranteed: leaves first, then
  `UncommRegion` → `ZeroMemory` → `ChangeRights` (restore parent) → `RevokeDomain`.
- Exclusive lock guarantees the entire subtree teardown is atomic with respect to all
  other operations — no TOCTOU checks needed.

### UpdateBatch Lifecycle

```
capability_op() → UpdateBatch         (pure tree mutation, no hardware)
  └─ execute() passes batch to Platform::apply_update() per entry
      └─ Platform::on_domain_revoked() for any RevokeDomain entries
```

After `execute()` returns, the `UpdateBatch` is consumed. The caller does not need to
apply it manually — `execute()` handles that. The batch is visible to tests via
`TestPlatform::drain_updates()`.

---

## Running Tests

### ⚠️ Mandatory Pre-Commit Checklist

**All three commands must pass before committing any capa-engine change:**

```bash
cd capa-engine/
cargo test          # unit + integration tests (~0.1 s)
cargo loom      # ALL loom suites including address_translation (~3 min)
```

Do NOT use `cargo loom` (without `-all`) as your final check — it skips the
`address_translation` concurrency tests. **Always use `cargo loom`.**

### Standard Tests (unit + integration)

```bash
cd capa-engine/
cargo test
```

This runs all 30+ unit and integration tests in ~0.1 s. **Always run this first** after
any change.

To run a specific test file:
```bash
cargo test --test unit_memory
cargo test --test integration_revoke
```

To run the `address_translation`-gated tests:
```bash
cargo test --features address_translation
```

### Loom Concurrency Tests (exhaustive interleaving)

Loom systematically explores every valid thread interleaving. Run with `--release` — loom's
bookkeeping is CPU-intensive and release mode is 5–10× faster.

```bash
cd capa-engine/

# Run all loom suites (includes address_translation)
cargo loom
```

This is a cargo alias defined in `capa-engine/.cargo/config.toml`. Expanded form:

```bash
# cargo loom expands to:
cargo test --features loom,address_translation --release \
  --test loom_concurrency \
  --test loom_e2e \
  --test loom_vp_switch \
  --test loom_meta \
  --test loom_translation
```

`loom_concurrency` takes ~54 s; the full suite takes a few minutes.

**Performance regression check**: if any loom test takes significantly longer than
expected or the run hangs, it indicates a new interleaving is not terminating — treat
this as a concurrency bug.

### Loom Test Coverage

| File | What it explores |
|------|----------------|
| `loom_concurrency.rs` | Raw RW lock scenarios, concurrent carve/revoke/send, update-application lock protocol |
| `loom_e2e.rs` | End-to-end carve+send+revoke under all interleavings |
| `loom_vp_switch.rs` | VP switch and interrupt delivery under concurrent revocation |
| `loom_meta.rs` | Domain metadata operations under concurrent access |
| `loom_translation.rs` | GPA→HPA mapping operations under concurrent revocation |

---

## Test Policy

- **Every code change** → run `cargo test` **and** `cargo loom` before committing.
  Both must pass. No exceptions. Do NOT substitute `cargo loom` for `cargo loom`.
- **Logic bug fixes** → add a regression test that fails without the fix and passes with it.
  Every validation check (guard, error return) in the engine must have a corresponding
  unit test that exercises that specific rejection path.
- **Add a new feature** → add at least one unit or integration test in the appropriate
  `tests/unit/` or `tests/integration/` file. For any new concurrent code path, add a
  loom scenario in `tests/concurrency/`.
- **Address-translation changes** → add to `tests/unit/translation.rs` and/or
  `tests/integration/translation.rs`; run `cargo loom`.
- **Loom tests must always pass without timeout** — a hanging loom test means a
  new interleaving does not terminate, which is a bug.

---

## Verifying the capa-cli Still Works

`capa-cli/` is the reference interactive simulator for the capability engine. It depends
on `capa-engine/` with the `address_translation` feature enabled. After any engine change:

```bash
cd capa-cli/
cargo build --release
```

A successful build means the public API is still compatible. For functional verification:

```bash
cargo run
```

Then exercise the change interactively. The CLI provides tab completion and 13 built-in
tutorials (`tutorial <n>` at the `cap>` prompt). Core flows to spot-check:

```
cap> init root 0x1000000
cap> create-domain root child 0b1111 CREATE,SEAL,CARVE,SEND,REVOKE,ATTEST
cap> carve r0 mem1 0x0 0x100000 RWX
cap> send mem1 child
cap> seal child
cap> view child
cap> revoke r0 mem1
```

If `view child` shows the correct address space and `revoke` completes without error,
the core pipeline is intact.

---

## Adding a New Platform Backend

To wire the engine into a new hardware target (e.g., ARM capavisor):

1. Define a struct holding your lock primitive, IPI mechanism, and domain-parent map.
2. Implement the `Platform` trait:
   - `acquire_shared_lock` / `acquire_exclusive_lock` → RAII guards around your hardware RW spinlock.
   - `apply_update` → match on `Update` variant: `ChangeRights` → modify page tables;
     `ZeroMemory` → zero physical pages; `RevokeDomain` → handled by `on_domain_revoked`;
     `CommRegion` / `UncommRegion` → update HHDM mapping; `FlushTLB` → TLB shootdown.
   - `register_domain` / `on_domain_revoked` → maintain parent map; redirect cores on revocation.
   - `set_core_domain` / `clear_core_domain` / `domain_core` → core→domain tracking.
   - For multi-core: implement `send_ipi`, `sync_barrier`, `try_acquire_update_lock`,
     `release_update_lock`, `poll_and_respond_cross_core`.
3. Single-core or simulation platforms can leave `send_ipi`, `sync_barrier`,
   `try_acquire_update_lock`, `release_update_lock`, and `poll_and_respond_cross_core` as
   their default no-op / always-true implementations.

Reference implementations to study:
- `tests/common/mod.rs` — `TestPlatform` (minimal, single-core, used by all unit tests)
- `capa-cli/src/platform.rs` — `CliPlatform` (hosted, multi-core simulation, uses `UpdateProcessor`)
- `themis/capavisor/src/platform.rs` — `ThemisPlatform` (x86 bare-metal, VT-x, EPT)

---

## Reference Table

| What | Where | Command |
|------|-------|---------|
| All public exports | `capa-engine/src/lib.rs` | — |
| Domain-mediated ops | `capa-engine/src/capability.rs` | — |
| Platform trait | `capa-engine/src/platform.rs` | — |
| Locking design | `docs/capability-engine/implementation.md` | — |
| Update variants | `docs/capability-engine/implementation.md` | — |
| API lifecycle | `docs/capability-engine/semantics.md` | — |
| Module overview | `docs/capability-engine/implementation.md` | — |
| Run all tests | `capa-engine/` | `cargo test` |
| Run loom suite | `capa-engine/` | `cargo loom` |
| Run loom + translation | `capa-engine/` | `cargo loom` |
| Build CLI | `capa-cli/` | `cargo build --release` |
| Run CLI interactively | `capa-cli/` | `cargo run` |
