# Themis Capability Hypervisor — Agent Instructions

You are working on **Themis**, a capability-based bare-metal hypervisor (x86-64,
Rust `no_std`). Before writing any code, you **must** read the context files listed
below. Skipping them leads to axiom violations and wasted sessions.

## Mandatory Reading (every session)

1. **Read `CONTEXT.md`** — the full authoritative reference: axioms A1–A11,
   architecture, component map, design decisions. (~28 KB, read it all.)
2. **Read `todo.md`** — current project status, active phase, debugging state.
3. **Read `skills/agent-workflow.md`** — session hygiene: startup ritual, how to
   maintain `todo.md`, end-of-session checklist.

## Task-Specific Skills (read before touching that area)

| Area | Skill file |
|------|-----------|
| `2026/` (capability engine) | @skills/working-on-capability-engine.md |
| `themis/capavisor/` | @skills/working-on-capavisor.md |
| Booting / testing in dom0 | @skills/running-inside-dom0.md |
| Debugging guest boot hangs | @skills/debugging-dom-boot.md |

## Architecture (quick reference)

```
L2  Nested Guest (Linux VM)      — managed by cloud-hypervisor
L1  Dom0 (Ubuntu + thhv.ko)      — first domain, NOT privileged
L0  Capavisor (Themis)           — bare-metal, capability-enforced
    Hardware (x86-64 VT-x/VT-d)
```

## Axioms — Hard Invariants (never violate)

- **A1** Capability engine validates before any hardware change. Pattern: `execute() → apply_update()`.
- **A2** Dom0 is not privileged. Same hypercall ABI as any child domain.
- **A3** EOI-exit bitmaps are always zero. Lazy-unwind interrupt model.
- **A4** IOVA = GPA for all child domains (IOMMU mirrors EPT).
- **A5** META pool is capavisor-only. Never in any domain's EPT.
- **A6** VpCommPage allocated by userspace, pinned by driver.
- **A7** thhv.ko is the only dom0↔capavisor interface. All hypercalls go through it.
- **A8** `inject_via_pid` for cross-core interrupt injection. No direct PIR writes.
- **A9** All domain interactions go through the capability engine interface. No direct tree access.
- **A10** Always update `todo.md` when work is completed.
- **A11** KISS: simplest solution first. Understand root cause before implementing.

## Workflow Rules

- **Plan before implementing.** For anything beyond a one-line fix, create a plan
  and confirm with the user before writing code.
- **Never leave the repo with a broken build.** Revert and document if you can't fix it.
- **Update `todo.md`** at session end with: completed items, in-progress debugging
  notes (with "Next step"), and files modified with reasons.
- **Build commands:**
  - `cd 2026/ && cargo test` — after any engine change
  - `cd 2026/ && cargo loom` — after any concurrent code change
  - `cd CLI-2026/ && cargo build --release` — after any engine API change
  - `cargo build-bins` — after any capavisor/thhv/CHV change (from repo root)

## Sub-Agent Guidance

When using sub-agents (Claude Code headless mode, or tool-use agents):
- Give each sub-agent **only the axioms + skill file** relevant to its task, not the full 28KB context.
- The orchestrator reviews all sub-agent output before committing.
- Each sub-agent must run the relevant build/test command before reporting success.
