# Themis Capability Hypervisor — Copilot Instructions

You are working on **Themis**, a capability-based bare-metal hypervisor (x86-64,
Rust `no_std`). This is a security-critical systems project. Before writing any
code, you **must** read the context files listed below.

## Mandatory Reading (every session)

1. **`CONTEXT.md`** at repo root — the full authoritative reference: axioms A1–A11,
   three-tier architecture (L0 capavisor / L1 dom0 / L2 nested guest), component
   map, design decisions, known issues. Read the entire file.
2. **`todo.md`** at repo root — current project status, active phase, last debugging
   state. Check "Current Status" first.
3. **`skills/agent-workflow.md`** — session hygiene: startup ritual, how to maintain
   `todo.md`, build hygiene, end-of-session checklist.

## Task-Specific Skills (read the relevant file before touching that area)

- `skills/working-on-capability-engine.md` — when modifying `2026/` (domain-mediated
  API, locking model, `execute()`, tests, loom)
- `skills/working-on-capavisor.md` — when modifying `themis/capavisor/` (core
  invariants, vmexit/hypercall handlers, `apply_update`, `ThemisPlatform`)
- `skills/running-inside-dom0.md` — when booting Themis + dom0 under QEMU, SSH,
  capturing traces
- `skills/debugging-dom-boot.md` — when debugging early guest boot hangs
  (`themis_trace()` instrumentation, trace code registry)

## Architecture (quick reference)

```
L2  Nested Guest (Linux VM)      — managed by cloud-hypervisor
L1  Dom0 (Ubuntu + thhv.ko)      — first domain, NOT privileged
L0  Capavisor (Themis)           — bare-metal, capability-enforced
    Hardware (x86-64 VT-x/VT-d)
```

## Axioms — Hard Invariants (NEVER violate)

- **A1** Capability engine validates before any hardware change. `execute() → apply_update()`.
- **A2** Dom0 is not privileged. Same hypercall ABI as any child. No special-casing.
- **A3** EOI-exit bitmaps always zero. Lazy-unwind interrupt model.
- **A4** IOVA = GPA for all child domains (IOMMU mirrors EPT exactly).
- **A5** META pool is capavisor-only. Never appears in any domain's EPT.
- **A6** VpCommPage allocated by userspace (VMM), pinned by driver.
- **A7** thhv.ko is the only dom0↔capavisor interface.
- **A8** `inject_via_pid` for cross-core interrupt injection.
- **A9** All domain interactions through capability engine interface. No direct tree access.
- **A10** Always update `todo.md` when work is completed or state changes.
- **A11** KISS: simplest solution first. Understand root cause before implementing.

## Key Design Decisions (settled — do not change)

- EOI-exit bitmaps: all-zero (lazy-unwind)
- COMM page: userspace-allocated, driver pins
- GSI = vector (simplified, no routing table yet)
- Sync switch model only (`THHV_SCHED_SYNC`)
- CPUID policy owned by CHV (dom0 userspace)

## Workflow

- **Plan first.** For anything beyond a trivial fix, outline the approach and confirm
  before writing code. Use `[[PLAN]]` mode if available.
- **Never leave a broken build.** Revert and document if you can't fix in-session.
- **Update `todo.md`** at session end: mark completed items, write debugging stack
  notes for in-progress work, list all modified files with reasons.

## Build & Test Commands

| What | Command | When |
|------|---------|------|
| Engine unit tests | `cd 2026/ && cargo test` | After any `2026/` change |
| Loom concurrency | `cd 2026/ && cargo loom` | After concurrent code change |
| CLI build check | `cd CLI-2026/ && cargo build --release` | After engine API change |
| Full bin rebuild | `cargo build-bins` (repo root) | After capavisor/thhv/CHV change |
| Boot stack | `cd themis/ && cargo themis 2>&1 \| tee /tmp/out.txt` | Integration test |

## Component Map

```
capability-v5/
├── 2026/                    # Capability engine (no_std Rust library)
├── CLI-2026/                # Interactive CLI simulator for engine
├── themis/capavisor/        # Bare-metal hypervisor (L0)
├── thhv/                    # Dom0 kernel module (Linux driver)
├── cloud-hypervisor/        # VMM fork (Themis backend)
├── CONTEXT.md               # Full reference (READ THIS)
├── todo.md                  # Task tracker (MAINTAIN THIS)
└── skills/                  # Task-specific agent instructions
```
