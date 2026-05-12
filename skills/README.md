# Skills — AI Agent Instructions

This directory contains task-specific instruction files for AI coding agents
(Copilot, Claude, etc.) working on Themis. They are **not** human-facing
documentation — see [`docs/`](../docs/) for that.

Each skill file provides context, invariants, and procedures for a specific
area of the codebase. Agents read the relevant skill before making changes.

| File | When to read |
|------|--------------|
| `agent-workflow.md` | **Every session** — startup ritual, todo.md maintenance, build hygiene, end-of-session checklist |
| `working-on-capability-engine.md` | Modifying `capa-engine/` — API, locking, `execute()`, tests, loom |
| `working-on-lean-exec.md` | Modifying `lean-exec/` — Lean 4 model, FFI bridge, differential testing |
| `working-on-capavisor.md` | Modifying `themis/capavisor/` — vmexit handlers, hypercalls, `apply_update` |
| `running-inside-dom0.md` | Booting Themis + dom0 under QEMU, SSH, capturing traces |
| `debugging-dom-boot.md` | Debugging guest boot hangs — `themis_trace()`, trace code registry |
| `code-review.md` | Reviewing code changes — checklist, axiom compliance |

Human contributors can ignore this directory. If you're looking for build
instructions, see [`docs/building.md`](../docs/building.md). For architecture
and design, see [`docs/architecture/`](../docs/architecture/).
