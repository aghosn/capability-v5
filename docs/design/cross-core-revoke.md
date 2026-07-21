# Cross-core domain revocation protocol

Status: draft. Iterate. Keep terse.

## Actors

- **I** — initiator core, drives the batch.
- **Tₖ** (k = 1..n) — target cores currently running a VP in the revoked subtree.
- **B0, B1** — `sync_barrier[0]`, `sync_barrier[1]` (`n+1` participants).

## Vocabulary

- `Update::RevokeDomain{d}` — engine batch entry; consumed by initiator only.
- `CoreUpdate::Switch{cap, vp}` — per-core queue entry; drained by owning core.
- **return target** — per-core, produced by walking that core's own VP caller
  chain (`VpRunState::Running{caller}` / `Locked{prev_caller}`) to the nearest
  ancestor VP whose domain is not in the revoked subtree. Same semantics as
  the normal switch-return path; revocation just triggers the unwind. There is
  **no domain-global return target** — different cores get different targets.

## Barrier semantics (Tyche-aligned)

| Barrier | Meaning when released |
|--------|-----------------------|
| **B0** | Every Tₖ has drained its queue: VMCLEAR of doomed VMCS is done, Tier‑1 (`domain_id`, `vp_id`, `domain_cap`) already points at the return target. **No core references `d`.** |
| **B1** | Initiator has finished all `apply_update` mutations. Targets may resume guest execution. |

**Consequence:** `apply_update(RevokeDomain{d})` runs between B0 and B1, while
all Tₖ are parked. Destroying `d`'s EPT / IOMMU SLPT / VP slots is unconditionally
safe — no live reference exists.

## Sequence diagram (with locks held per side)

```
    I                                           Tₖ
    │                                           │
    │ execute(op):                              │  (running guest d)
    │   ── acquire op_lock ─────────┐           │
    │   ── acquire Capability guard ─┤          │
    │      compute batch             │          │
    │      walk caller chains → target   │          │
    │   ── acquire update_lock ──────┤          │
    │      for each Tₖ:              │          │
    │        push TlbShootdown       │          │
    │        push Switch(target, vp)   ──┤          │
    │      for each Tₖ:              │          │
    │        send_ipi(Tₖ) ─IPI──────►│─► INIT VMEXIT → classify
    │                                │          poll_and_respond:
    │                                │            drain queue:      ← Tₖ holds:
    │                                │              TlbShootdown       core_updates[k] mutex
    │                                │              Switch:             (briefly, per pop)
    │                                │                VMCLEAR old
    │                                │                VMPTRLD target
    │                                │                write Tier-1
    │                                │          B0.wait(0) ─────┐
    │   B0.wait(n+1) ═══════════════ ═══════════════════════════┘
    │   ── still hold: op_lock,      │          (parked in B1.wait — no locks held)
    │      Capability guard,         │
    │      update_lock ──────────────┤
    │   apply_update loop:           │
    │     RevokeDomain{d}:           │
    │       destroy EPT/IOMMU/VP    │
    │     ChangeRights, GiveMem ...  │
    │   B1.wait(n+1) ══════════════════════════════════════════ B1.wait(0)
    │   ── release update_lock ──────┤          │
    │   ── release Capability guard ─┤          resume in target VP
    │   ── release op_lock ──────────┘          │
```

## Lock inventory

**Initiator (I) across the full window (send_ipi → B1 release):**
- `op_lock` (shared or exclusive, engine-level, `platform.rs`)
- one or more `Capability<T>` write guards (`_guard` in `execute`)
- `update_lock` (atomic bool, engine-level; serialises cross-core batches)

**Target Tₖ in C1 (was in guest):**
- No engine locks at any point.
- `core_updates[k]` mutex briefly per queue pop.
- Domain-local VMCS ownership only during VMCLEAR/VMPTRLD.

**Target Tₖ in C2 (was in root, spinning on `try_acquire_update_lock`):**
- Holds its own hypercall's `op_lock` + Capability guards.
- Does **not** hold `update_lock` (that's what it's waiting for).
- No cycle: I holds update_lock; T holds op_lock/cap; neither waits on the other's set.

## Invariants

**INV-1** Tier‑1 cells (`domain_id`, `vp_id`, `domain_cap`) written only by owning core.

**INV-2** Push to `Tₖ`'s queue happens‑before `send_ipi(Tₖ)`.

**INV-3** `apply_update(RevokeDomain{d})` runs strictly between B0 and B1.

**INV-4** Between B0 release and B1 release, every Tₖ is parked in `B1.wait` and
holds no engine locks.

## Case matrix (target state when IPI fires)

| # | Tₖ state | Path |
|---|---|---|
| C1 | non‑root (guest) | INIT VMEXIT → classify → poll → drain → B0 → B1 → resume in target VP |
| C2 | root, spinning `try_acquire_update_lock` | poll inside spin → drain → B0 → B1 → returns to its own execute retry |
| C3 | root, pure work, will VMENTER | VMENTER delivers pending IPI → immediate VMEXIT → C1 path |
| C4 | root, no VMENTER, no update_lock spin | **hazard**, must not exist (Audit A1) |

## Engine flow (pseudocode)

```rust
// inside execute(), after batch is built and caller chains walked:
for each RevokeDomain{d} in batch:
    for tk in domain_cores(d):
        target = walk_caller_chain(tk.vp)   // per-core, skips revoked ancestors
        push_core_switch(tk, target.cap, target.vp_id, target.resume_state)

acquire update_lock (spin + poll)
send_ipi(all affected)
B0.wait(n+1)
for update in batch: apply_update(update)
B1.wait(n+1)
release update_lock
```

Note: `domain_cores` continues to push `TlbShootdown` inline (pre‑IPI). Queue order
per core: `TlbShootdown` before `Switch`. On drain, TlbShootdown INVEPTs the old
EPTP (harmless, VMCS still points to it); Switch then VMCLEARs and VMPTRLDs target.

## Audit results (2026-07-21)

**A1** ✓ No C4 hazard. All root-mode paths either reach `execute()` (which
polls while spinning on `update_lock`) or return to `vp.run()`/VMENTER within
bounded work. `EXIT_REASON_INIT_SIGNAL` routes directly to
`poll_and_respond_cross_core`.

**A2** ✓ Initiator's `apply_update(RevokeDomain{d})` locks only `self.domains`
map (brief), ROOT PlatformDomain mutex (meta reclaim), and the doomed domain's
owned arch state. Target's Switch handler locks `core_updates[t]`, new target
domain's PlatformDomain mutex, and its own `CoreContext.domain_cap`. Domains
disjoint (target = fb, initiator = d ≠ fb). No cycles. Root may contend if fb
is root, but no deadlock.

**A3** ⚠ Blocker for implementation. `Platform::poll_and_respond_cross_core(&self)`
has no access to `ActiveVcpu`, so it cannot VMCLEAR/VMPTRLD, so it cannot
honor B0's "targets switched off" invariant. **Refactor:** promote
`poll_and_respond_cross_core` onto `ArchVpOps` (has `&mut VpHandle`); the
generic `Platform` keeps the sync-barrier primitives.

The ancestor observes the switch as a new **exit reason** on its resumption
(e.g. `CalleeRevoked`), same delivery path as any other child→parent exit.
No special return payload — the existing exit-forwarding pipeline handles it.
Vp<A> stack lifetime is fine: only its internal fields (`vmcs_phys`,
`vapic_phys`, `msr_bitmap_phys`, `pid_phys`, `vpid`, `launched=false`) are
rebound by the Switch handler.

**A4** ✓ INVEPT single-context on a well-formed EPTP whose backing pages were
freed is a no-op (flushes cached mappings tagged with that EPTP). Draining
stale `TlbShootdown{revoked_d}` after a Switch on the same core is wasted
work but harmless. No filter needed.

## Open decisions (resolved)

**D1** ✓ Root (dom0) unrevokable. Chain walk always terminates at a non-revoked
ancestor. Any deviation ⇒ engine invariant violation ⇒ `execute()` returns
`CapaError`.

**D2** ✓ New `Platform::push_core_switch(core, cap, vp_id, resume_state)`
trait method (distinct semantics from `domain_cores`).

**D3** ✓ No new `SemanticExit` variant. `poll_and_respond_cross_core` (now on
`ArchVpOps`) returns a `PollOutcome` enum; the INIT_SIGNAL classify site
inspects it and either resumes, unwinds, or halts the core.

## Test outline

Engine-level, TestPlatform instrumented with `pushed_core_switches` +
existing `call_log`.

- **T-basic** — root + child, CORE_1 bound to child, revoke child.
  Assert `push_core_switch(CORE_1, root_cap, 0)` recorded **before**
  `apply_update(RevokeDomain{child})` in call_log.
- **T-chain** — A→B→C, CORE_1 running C, revoke B.
  Assert target = A (B skipped as it is in the revoked subtree).
- **T-multi** — two siblings on two cores, revoke one.
  Only the affected core has a push.
- **T-none** — revoke domain bound to no core. Zero pushes, zero IPIs.

## Implementation order

1. Audits A1..A4 (read-only investigation, may need small poll-point patches).
2. Add `Platform::push_core_switch` trait method + TestPlatform recorder.
3. Engine: chain walk + push_core_switch inside `execute()` before `send_ipi`.
4. T-basic passes; add T-chain, T-multi, T-none.
5. Capavisor: implement `push_core_switch` (delegate to `push_core_update`);
   flip `poll_and_respond_cross_core` to drain-before-B0; fill `CoreUpdate::Switch`
   arm (VMCLEAR/VMPTRLD/Tier‑1 writeback); shrink `on_domain_revoked` to
   routing‑table update only.
6. Integration test: revoke a running domain on a remote core under QEMU.
