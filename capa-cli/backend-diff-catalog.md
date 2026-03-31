# Backend Differential Catalog

Systematic comparison of `--backend rust` vs `--backend lean` output across
all 15 tutorials. Generated 2026-03-31.

**Status:** All 15 tutorials show differences. The issues are categorized below
from most impactful (breaks many tests) to least.

---

## Category 1: Core State After Init (affects ALL tutorials)

**Symptom:** After `init`, Rust shows the root domain running on all cores;
Lean shows all cores as `idle`.

```
Rust:  ✓ Core 0: root (ID: 0)
Lean:  ○ Core 0: idle
```

**Root cause:** Rust `init` assigns the root domain to all cores via
`CreateDomain` updates. Lean `init` creates the domain but does not set
`CoreState.runningDomain` for any core.

**Impact:** High — blocks all `switch` and `interrupt` operations since
they require "no domain on core" to be false.

**Fix location:** `lean-exec/LeanExec/Operations/Domain.lean` (`init`) or
`lean-exec/LeanExec/FFI.lean` (`ffiInit`). After creating root domain,
set `cores[i] = .runningDomain rootId 0` for all cores.

**Tutorials affected:** 1–15 (all)

---

## Category 2: Rights Display Format (affects ALL tutorials)

**Symptom:** Lean appends `-` for missing rights; Rust omits them.

```
Rust:  RW
Lean:  RW-
```

Also sometimes raw `Rights { bits: 1 }` instead of `R`.

**Root cause:** Lean `ToString Rights` instance prints all three positions
(`R--`, `RW-`, `RWX`). Rust `Rights::fmt` omits missing flags (`R`, `RW`, `RWX`).

**Impact:** Low — cosmetic only, but breaks textual diffing.

**Fix location:** `lean-exec/LeanExec/Types.lean` — change the `ToString Rights`
instance to omit trailing dashes. OR: `lean-exec/LeanExec/FFI.lean` — format
rights strings to match Rust convention in JSON output.

**Tutorials affected:** 1–15 (all)

---

## Category 3: Carve Produces Unmap Instead of Map (affects most tutorials)

**Symptom:** After `carve`, Lean reports an `unmap` update; Rust reports a `map`.

```
Rust:  ℹ MMU updates: 1 map(s), 0 unmap(s), 0 zero(s)
Lean:  ℹ MMU updates: 0 map(s), 1 unmap(s), 0 zero(s)
```

Also: Lean emits an extra unmap on initial `carve` from root.

**Root cause:** The Lean `carve` operation produces an `unmapMemory` update
(to shrink the parent) instead of a `mapMemory` update (to create the child
mapping). The Rust engine produces `MapMemory` for newly carved regions.

**Impact:** High — update semantics inverted.

**Fix location:** `lean-exec/LeanExec/Operations/Memory.lean` — the `carve`
function's update generation logic.

**Tutorials affected:** 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15

---

## Category 4: Switch Fails ("no domain on core") (affects tutos 4, 5, 9+)

**Symptom:** `switch` commands fail in Lean:

```
Lean:  ✗ Failed to VP-switch: Invalid operation: InvalidOperation: no domain on core
```

**Root cause:** Consequence of Category 1 — since init doesn't place root on
cores, `getCoreState` returns `idle`, and `switchForward` can't find the
caller domain.

**Impact:** High — blocks all context switching tutorials.

**Fix location:** Resolves automatically when Category 1 is fixed.

**Tutorials affected:** 4, 5, 9, 10, 12, 13, 14, 15

---

## Category 5: Memory Ownership Not Transferred on Send (affects tutos 4, 8+)

**Symptom:** After `send mem child`, memory still shows `owner: root` in Lean.

```
Rust:  • app1_mem [0x80000..0xc0000) RWX (owner: app1, ...)
Lean:  • app1_mem [0x80000..0xc0000) RWX (owner: root, ...)
```

**Root cause:** The Lean `send` operation transfers the capability to the
receiver's pending queue but the query JSON serialization reports the original
owner from `ExecMemCap.capId.domainId` rather than the new owner after
acceptance.

**Impact:** Medium — affects display correctness, may indicate deeper
ownership tracking issue.

**Fix location:** `lean-exec/LeanExec/Operations/Memory.lean` (send/accept)
or `lean-exec/LeanExec/FFI.lean` (query serialization).

**Tutorials affected:** 4, 8, 10, 11, 12, 13

---

## Category 6: VP Registration Fails (affects tutos 9)

**Symptom:** `register-comm` and `add-vp` fail in Lean:

```
Lean:  ✗ register-comm failed: Invalid operation: InvalidOperation: VP does not exist
```

**Root cause:** The Lean model requires VPs to be added to a domain before
comm pages can be registered, but `addVp` may also be failing or the VP
tracking logic differs.

**Impact:** Medium — blocks COMM page tutorials.

**Fix location:** `lean-exec/LeanExec/Operations/Switch.lean` (`addVp`,
`registerComm`). Check VP creation and lookup logic.

**Tutorials affected:** 9

---

## Category 7: `view` Output Format Differs (affects tutos 7, 10+)

**Symptom:** Rust `view` shows detailed domain info (status, API flags,
interrupt policy, children, registers). Lean `view` shows much less or
nothing.

```
Rust:  d0 = Sealed domain(m0, m1)
       Domain ID: 1
       Status: Sealed
       Cores: 0b11
       API: ...
Lean:  (nothing / truncated)
```

**Root cause:** The `view` command calls `get_domain_dom_caps` and then
formats capability tree info. The Lean backend returns the data via JSON,
but the Rust CLI's `view` command handler may be looking for fields that
the Lean JSON doesn't provide, or the data is formatted differently.

**Impact:** Medium — information display issue.

**Fix location:** Compare `view` handler in `commands/info.rs` with Lean
`ffiGetDomainDomCaps` JSON output.

**Tutorials affected:** 7, 10, 11, 12, 13, 14, 15

---

## Category 8: Error Message Differences (minor, affects several tutorials)

**Symptom:** Same error condition, different error variant reported:

```
Rust:  ✗ Failed to carve: Invalid access
Lean:  ✗ Failed to carve: Region overlap

Rust:  ✗ Failed to send: Permission denied
Lean:  ✗ Failed to send: Invalid operation: InvalidOperation: sealed receiver lacks canReceiveAfterSeal
```

**Root cause:** The Lean model uses different error variants for the same
conditions. The Rust engine maps overlapping carves to `InvalidAccess`;
Lean maps them to `RegionOverlap`.

**Impact:** Low — same behavior (operation rejected), just different message.

**Fix location:** Align error selection in Lean operations to match Rust.

**Tutorials affected:** 1, 5, 6, 9

---

## Category 9: COMM Attribute Not Set (affects tuto 9)

**Symptom:** After `register-comm`, Lean doesn't set the COMM attribute:

```
Rust:  • comm0 [0x0..0x1000) RW (attrs: CLEAN,COMM, ...)
Lean:  • comm0 [0x0..0x1000) RW- (attrs: NONE, ...)
```

**Root cause:** Lean's `registerComm` doesn't mark the memory capability
with the COMM attribute.

**Impact:** Low — attribute tracking gap.

**Fix location:** `lean-exec/LeanExec/Operations/Switch.lean` (`registerComm`).

**Tutorials affected:** 9

---

## Category 10: Accepted MemCap UID Differs (affects tuto 7)

**Symptom:** After accepting a pending capability, Lean assigns a different
UID than Rust:

```
Rust:  ✓ Accepted pending memory capability 0 as uid 3
Lean:  ✓ Accepted pending memory capability 0 as uid 2
```

**Root cause:** Different UID allocation counters. Lean may allocate UIDs
differently during `accept`.

**Impact:** Low — internal ID assignment, doesn't affect correctness if
consistent within the backend.

**Tutorials affected:** 7

---

## Category 11: Carve Permission Check Differs (affects tuto 9)

**Symptom:** Lean allows a carve that Rust rejects:

```
Rust:  ✗ Failed to carve: Permission denied
Lean:  ✓ Carved memory region 'bad_carve' [0x0..0x100) Rights { bits: 1 }
```

**Root cause:** Lean doesn't check that carved regions can't overlap COMM
pages, or doesn't enforce the same permission checks on COMM-attributed
memory.

**Impact:** Medium — security-relevant difference.

**Fix location:** `lean-exec/LeanExec/Operations/Memory.lean` (`carve`).

**Tutorials affected:** 9

---

## Category 12: Create-Domain API Monotonicity (affects tuto 5)

**Symptom:** Lean rejects a `create-domain` that Rust allows:

```
Rust:  ✓ Created domain 'child' (ID: 2, ...)
Lean:  ✗ Failed to create child: API not allowed
```

**Root cause:** The parent domain has enough API bits in Rust, but the Lean
model's API monotonicity check is stricter or encodes the CREATE bit
differently.

**Impact:** Medium — blocks nested domain creation in some scenarios.

**Fix location:** `lean-exec/LeanExec/Operations/Domain.lean` (`create`),
specifically the API flag subset check.

**Tutorials affected:** 5

---

## Priority Order for Fixes

1. **Category 1** (core state after init) — fixes Categories 1 + 4, unblocks switching
2. **Category 3** (carve update type) — fixes MMU update semantics
3. **Category 2** (rights format) — fixes all cosmetic rights diffs
4. **Category 5** (ownership transfer) — fixes display after send
5. **Category 12** (create-domain API check) — fixes nested creation
6. **Category 6** (VP registration) — fixes COMM page support
7. **Category 11** (carve permission) — security fix
8. **Categories 7–10** — lower priority display/cosmetic issues
