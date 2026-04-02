# Differential Testing — Rust vs Lean Backends

The `capa-cli` supports two backends: `--backend rust` (reference, production
engine) and `--backend lean` (executable Lean 4 model). Both should produce
identical output for the same input script.

## Quick Start

```bash
# 1. Build the CLI with both backends enabled
cd capa-cli/
cargo build --release --features lean-backend

# 2. Run regression tests only (fast, targeted)
bash regression/run-diff.sh

# 3. Run regression + tutorial scenarios (full suite)
bash regression/run-diff.sh --with-tutos

# 4. Run a single test file
bash regression/run-diff.sh regression/attest-report.txt
bash regression/run-diff.sh tutos/03-basic-send.txt
```

## How It Works

`run-diff.sh` feeds each `.txt` test file as stdin to the CLI binary twice —
once with `--backend rust`, once with `--backend lean` — then diffs the outputs.
Lines containing build artifacts (`Backend:`, `Compiling`, etc.) are stripped
before comparison.

```
test.txt ──stdin──▶ capability-cli --backend rust  ──▶ rust_output
         ──stdin──▶ capability-cli --backend lean  ──▶ lean_output
                                                        diff ──▶ ✅ / ❌
```

Exit code is 0 if all tests pass, 1 if any differ.

## Test Files

### Regression tests (`regression/`)

Targeted tests for specific bugs that were fixed. Each tests one or two
behaviors in isolation. These run by default (no flags needed).

| File | What it tests |
|------|---------------|
| `attest-report.txt` | Full attestation report format: API flags, interrupt policy, memory caps with carved/aliased children, recursive child expansion |
| `attr-propagation.txt` | META/CLEAN/VITAL attribute propagation through send, canonicalization |
| `comm-register-guards.txt` | COMM page registration validation: carved-only, exclusive, no META, VP bounds, duplicate binding |
| `interrupt-routing.txt` | Interrupt policy chain walk, switch encapsulation, VP recovery after interrupt |
| `meta-send-guards.txt` | META send rejection: alias (non-exclusive), exclusive with children, exclusive leaf (succeeds) |
| `send-view-subtraction.txt` | Address space view subtracts carved children correctly after send |

### Tutorial scenarios (`tutos/`)

End-to-end scenarios (01–15) that exercise full workflows. Included with
`--with-tutos`. These are more comprehensive but slower and some test behaviors
not yet implemented in the Lean backend.

## Writing a New Test

A test file is a sequence of CLI commands, one per line. Comments (`#` lines)
and annotation lines (`@msg`) are passed through to both backends — they produce
identical `Error: Unknown command` output on both sides, so they don't affect
the diff.

```bash
# Regression: describe what you're testing
# Verifies: specific behavior under test

# Setup
init root 0x100000
carve r0 m1 0x0 0x10000 RWX

# Action
create-domain root child 0b11 GET,SEND,ATTEST
seal child
send m1 child

# Verify (output from these commands is what gets diffed)
attest child
list
```

Save as `regression/<name>.txt`. It will be picked up automatically by
`run-diff.sh`.

## Reading Failures

Failed tests show a unified diff (first 30 lines):

```
❌ my-test
--- rust_clean.txt
+++ lean_clean.txt
@@ -10,7 +10,7 @@
-  Handle 1: m0 = [0x0..0x10000) RWX (kind: Carve, attrs: CLEAN|VITAL)
+  Handle 1: m0 = [0x0..0x10000) RWX (kind: Carve, attrs: CLEAN,VITAL)
```

Lines prefixed with `-` are Rust output (expected), `+` are Lean output (actual).

## Current Status

**16/21 passing** (6 regression + 10 tutorials).

Remaining failures are tracked in `todo.md` under "lean-exec differential
testing" with per-category status (Cat D, F, H, K).

## Rebuilding After Changes

If you modify `lean-exec/` sources:

```bash
cd lean-exec/ && lake build           # rebuild Lean library
cd capa-cli/ && cargo build --release --features lean-backend
bash regression/run-diff.sh --with-tutos
```

If you modify only `capa-engine/` (Rust engine), the `--features lean-backend`
build will relink automatically — just `cargo build --release --features
lean-backend` and re-run.
