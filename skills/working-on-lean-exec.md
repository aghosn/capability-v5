# Skill: Working on the Lean Executable Model (lean-exec/)

## When to Use

Use this skill when you need to:
- Modify, extend, or debug the `lean-exec/` Lean 4 executable model.
- Add new operations or fix behavioral differences vs the Rust engine.
- Work on the FFI bridge between Lean and the `capa-cli` Rust binary.
- Compare Lean vs Rust backend outputs (differential testing).

---

## Hard Invariant: lean-exec Models capa-engine and Nothing Else

**The lean-exec package is an executable model of the `capa-engine/` Rust library.**
It must mirror the engine's semantics, data structures, and operation logic.
It must NOT contain CLI-layer concerns.

### What belongs in lean-exec

- Capability tree operations (carve, alias, send, accept, revoke, etc.)
- Domain lifecycle (create, seal, revoke_domain)
- VP state machine and switch semantics
- Core state tracking
- Channel operations (get_chan, send_channel, accept_channel)
- Policy and interrupt policy
- Address space computation
- The `ExecState` and `ExecDomain` structures (modeling engine-internal state)
- `LocalHandle` per-domain allocation (models `Domain::allocate_memory_handle`)
- `CapNodeId` as internal flat-store key (models Arc pointer identity in Rust)

### What does NOT belong in lean-exec (CLI-layer concerns)

- **User-facing UIDs** (`MemCapUid` as returned to the CLI) — manage in `lean_backend.rs`
- **Capability or domain names** — manage in `capa-cli/src/` (`CliState`)
- **Channel synthetic IDs** — manage in `lean_backend.rs`
- **JSON serialization** — keep in `FFI.lean` only for marshalling, never in Operations
- **Display formatting** — CLI responsibility
- **Session/history tracking** — CLI responsibility

### Boundary rule

```
lean-exec engine    →  returns LocalHandle, CapNodeId (internal)
FFI.lean            →  passes them through as u64 to C boundary
lean_backend.rs     →  maps CapNodeId → MemCapUid (CLI-facing ID)
                       maps channel handles → ChanId (CLI-facing ID)
                       manages name→ID lookups
```

This mirrors the Rust architecture:
```
capa-engine          →  returns LocalHandle, Arc pointers (internal)
rust_backend.rs      →  maps Arc → MemCapUid (CLI-facing ID)
                        manages name→ID lookups
```

If you're about to add a field to `ExecState` or `ExecDomain`, ask: "Does the Rust
engine (`capa-engine/src/domain.rs`, `capa-engine/src/capability.rs`) have this?"
If not, it doesn't belong in the Lean engine model.

---

## Module Map

```
lean-exec/
  LeanExec.lean              — Package root, imports all modules
  Main.lean                  — Standalone Lean REPL entry point

  LeanExec/
    Types.lean               — ExecDomain, ExecMemCap, PendingMemCap, helpers
    State.lean               — ExecState (flat capability store, cores, registers)
    Monad.lean               — CapaM monad (ExceptT + StateM), helper combinators
    Engine.lean              — Standalone REPL engine (CliState — Lean CLI only)
    Cli.lean                 — Lean REPL command parsing (standalone mode only)
    FFI.lean                 — C FFI exports (@[export]) for capa-cli integration

    Operations/
      Memory.lean            — carve, alias, send, accept, reject, revoke
      Domain.lean            — create, seal, revoke_domain (recursive)
      Channel.lean           — getChan, sendChannel, acceptChannel
      Switch.lean            — switchForward, switchReturn, addVp, registerComm
      Policy.lean            — setPolicy, getPolicy, setRegister, getRegister
      Query.lean             — computeAddressSpace, enumerate, attest
```

### Standalone REPL vs FFI mode

- **Standalone mode** (`Main.lean` + `Engine.lean` + `Cli.lean`): The Lean binary
  runs as its own REPL. `CliState` in `Engine.lean` wraps `ExecState` with name
  mappings. This is fine — it's the Lean CLI, separate from the engine model.

- **FFI mode** (`FFI.lean`): The Lean code is compiled to a static library and
  linked into the Rust `capa-cli` binary via C FFI. `FFI.lean` contains `@[export]`
  functions that bridge between C calling convention and the Lean engine operations.
  The Rust side (`capa-cli/src/lean_backend.rs`) handles CLI concerns.

**These two modes must not be conflated.** `Engine.lean` and `Cli.lean` may hold
CLI state for standalone mode. `FFI.lean` should only marshal data — all CLI-layer
logic belongs in `lean_backend.rs`.

---

## Key Type Correspondences

| Rust Engine | Lean Engine | Notes |
|-------------|-------------|-------|
| `Arc<RwLock<Capability<MemoryRegion>>>` | `CapNodeId` (flat store key) | Lean can't do Arc; uses flat store |
| `LocalHandle` (u64) | `LocalHandle` (Nat) | Per-domain, allocated by monotonic counter |
| `SubHandle` (u64) | Not modeled | Stable tree identity; Lean uses CapNodeId |
| `Domain` struct | `ExecDomain` struct | Fields should correspond 1:1 |
| `DomainPolicy` | `DomainPolicy` | From ThemisCapa proof model |
| `CapabilityInner.children` | `ExecMemCap.childUids` | Tree edges |
| `CapabilityInner.parent` | `ExecMemCap.parentUid` | Weak back-pointer |
| `Domain.memory_capabilities` | `ExecDomain.memCaps` | `BTreeMap<LH, Weak>` vs `List (LH × NodeId)` |
| `Domain.frozen_handles` | `ExecDomain.frozenHandles` | Handles in transit |
| `Domain.pending_capabilities` | `ExecDomain.pendingMem` | Pending transfers |

---

## LocalHandle Allocation

The Lean model uses a **monotonic counter** per domain (`nextMemHandle`, `nextDomHandle`).
The Rust engine uses a **linear scan** that reuses freed handles. Both are correct.

Key properties that must hold:
- Handles are **per-domain** (two domains can have the same handle value)
- A new handle is allocated on **carve**, **alias**, **accept**, and **send-to-unsealed**
- Frozen handles are never deallocated until accept/reject completes
- The Lean counter never collides with frozen handles (monotonic guarantee)

---

## Differential Testing

To compare Lean vs Rust outputs on tutorials:

```bash
cd capa-cli/

# Run with Rust backend
cargo run --release -- --backend rust < tutos/01-basic-carve.txt 2>&1 | \
  sed 's/\x1b\[[0-9;]*m//g' > /tmp/01_rust.txt

# Run with Lean backend
cargo run --release --features lean-backend -- --backend lean < tutos/01-basic-carve.txt 2>&1 | \
  sed 's/\x1b\[[0-9;]*m//g' > /tmp/01_lean.txt

# Compare
diff /tmp/01_rust.txt /tmp/01_lean.txt
```

When fixing diffs, always ask: is this a **Lean engine bug** (wrong semantics) or a
**CLI adapter bug** (wrong formatting/mapping in `FFI.lean` or `lean_backend.rs`)?

---

## Build Commands

```bash
# Build standalone Lean REPL
cd lean-exec/ && lake build

# Build as FFI library for capa-cli integration
cd capa-cli/ && cargo build --release --features lean-backend

# Run Lean REPL standalone
cd lean-exec/ && lake exe lean-exec

# Run via capa-cli with Lean backend
cd capa-cli/ && cargo run --release --features lean-backend -- --backend lean
```

---

## Checklist Before Committing Changes

1. [ ] Does every new field in `ExecState`/`ExecDomain` have a counterpart in `capa-engine/src/`?
2. [ ] Are CLI concerns (names, UIDs, formatting) kept out of `Operations/*.lean`?
3. [ ] Does `FFI.lean` only marshal data, not implement CLI logic?
4. [ ] Does `lake build` succeed?
5. [ ] Does `cargo build --release --features lean-backend` succeed in `capa-cli/`?
6. [ ] Have you run differential tests on affected tutorials?
