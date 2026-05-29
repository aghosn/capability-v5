# ThemisCapa — v1 Archive (no longer built)

This directory contains the **first generation** of the Themis capability
formal model: 83 hand-written safety theorems organised around per-operation
`XxxPre`/`XxxPost : Prop` predicates over a nested inductive CDT.

It has been **archived** in favour of v2 (`lean/ThemisCapa/`), which is
restructured around an explicit `SpecState`, a small-step `step` relation,
and flat-arena finmaps — the shape needed to drive a refinement proof
against an Aeneas-extracted Rust core.

## Status

- **Not part of the default Lake build.** The files in this directory are
  reference material; `lake build` from `lean/` no longer type-checks them.
- **Git history is the audit trail.** To inspect what was proved, see the
  history of `lean/ThemisCapa/` prior to the v2 cutover, or check out a
  pre-cutover commit.
- **`current-specification.md`** documents the v1 coverage matrix
  (83 theorems, gaps, suggested next steps). Kept here for reference.

## Why no equivalence proof v1 ⇔ v2?

By design — see `docs/capability-engine/aeneas-exploration.md` §10.4–§10.6.
Building v2 alongside v1 and proving them equivalent would roughly double
the effort with limited verification value. We accept the small loss of
automation (v1 theorems are no longer machine-checked against the current
spec) in exchange for a faster path to refinement-ready v2.

## If you need to revive v1

1. `git log --follow lean/archive-v1/` to find the file you want.
2. Either copy the file into the active `lean/ThemisCapa/` tree and adapt
   it to the v2 types, or add an `archive-v1` `lean_lib` entry to
   `lakefile.toml` and re-import from there.
