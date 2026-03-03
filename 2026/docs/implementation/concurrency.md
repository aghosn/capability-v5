# Concurrency

## Overview

The capability engine is designed to run safely across multiple cores. Concurrency is managed at two levels:

1. **Per-node locking**: each `Capability<T>` node is wrapped in `Arc<RwLock<>>`. Concurrent readers can hold simultaneous read locks; any write (e.g., adding a child) takes the write lock.

2. **Global operation lock**: a single coarse-grained RW lock serialises all capability tree mutations. This is exposed through the `Platform` trait and is the primary concurrency primitive for the engine.

---

## Global RW Lock — Shared vs. Exclusive

All capability operations fall into one of two categories:

| Category | Lock type | Operations |
|----------|-----------|------------|
| Non-destructive | **Shared** | carve, alias, send |
| Destructive | **Exclusive** | any revoke (memory or domain) |

Multiple non-destructive operations can run concurrently. Any revoke takes an exclusive lock — it blocks until all shared-lock holders have released, then runs alone.

**Why exclusive for revoke?** Revocation cascades through an arbitrarily deep subtree whose nodes and domain IDs are not known to the caller in advance. An exclusive lock ensures the full traversal is atomic with respect to every other operation. No TOCTOU checks or domain-set enumeration are required.

On bare metal these map directly to a hardware RW spinlock (`rwlock_read_lock` / `rwlock_write_lock`).

---

## The `execute()` Function

`execute()` in `platform.rs` is the single entry point that wraps a capability tree mutation in the full cross-core atomicity protocol:

```
execute(platform, exclusive, op):

  1. LOCK     acquire shared or exclusive lock (exclusive=true for revoke)
  2. OPERATE  (result, batch) = op()              ← pure tree mutation
  3. SYNC     for each core running an affected domain:
                  send_ipi(core)                  ← preempt affected cores
                  sync_barrier(0, n)              ← wait: all cores paused
                  apply_update(u) for u in batch  ← EPT / page-table changes
                  sync_barrier(1, n)              ← release: cores flush TLBs
              (if no remote cores affected, skip IPI/barrier entirely)
  4. REVOKE   on_domain_revoked(id, fallback)      ← for each RevokeDomain in batch
  5. UNLOCK   drop lock guard
```

The local path (step 3 `else` branch — no remote cores) skips IPI/barrier overhead entirely. This is the common case when operating on domains that are not currently running on another core.

**Usage**:

```rust
// Non-destructive (shared lock)
execute(&platform, /*exclusive=*/false, || {
    Capability::send_to(&cap, caller, new_owner, handle, Attributes::NONE)
        .map(|batch| ((), batch))
})?;

// Destructive (exclusive lock)
execute(&platform, /*exclusive=*/true, || {
    Capability::revoke_child_domain(&root, child_handle)
        .map(|batch| ((), batch))
})?;
```

---

## Lock Acquisition Order and TOCTOU

When multiple domain locks must be held simultaneously (e.g., sender + receiver for `send`), locks are always acquired in **ascending domain-ID order** to prevent deadlocks.

After each lock is acquired, the implementation checks whether the domain was revoked while waiting. If so, all already-acquired locks are released and `CapaError::DomainRevoked` is returned. This prevents operating on stale state without needing any additional TOCTOU checks.

---

## `sync.rs` — Lock Backend Abstraction

All internal engine code uses `crate::sync::RwLock` rather than any concrete lock type. `sync.rs` resolves this alias based on compile-time configuration:

| Condition | Backend |
|-----------|---------|
| `feature = "hosted"` (default) | `parking_lot::RwLock` — OS-backed, efficient, writer-preferring |
| `feature = "loom"` | `loom::sync::RwLock` — cooperative scheduler for exhaustive testing |
| neither | `spin::RwLock` — pure busy-wait, `no_std` compatible |

`Arc` and atomic types are similarly aliased, so the loom backend can intercept all synchronisation operations without any `#[cfg(loom)]` annotations in engine logic.

---

## Loom: Exhaustive Interleaving Testing

[loom](https://github.com/tokio-rs/loom) replaces `std::sync` with a cooperative scheduler and systematically explores every valid thread interleaving. Because each scenario involves 2–3 threads and a small number of synchronisation points, the state space is tractable.

```bash
cargo test --test loom_concurrency --features loom --release
cargo test --test loom_e2e        --features loom --release
cargo test --test loom_vp_switch  --features loom --release
```

The `--release` flag is important: loom's bookkeeping is CPU-intensive and release mode is 5–10× faster.

The loom test files live in `tests/concurrency/`. They cover:
- `loom_concurrency.rs` — raw RW lock scenarios (exclusive blocks shared, shared concurrency, revoke ordering).
- `loom_e2e.rs` — end-to-end capability operations (carve + send + revoke) under loom.
- `loom_vp_switch.rs` — VP switch and interrupt delivery under concurrent revocation.

---

## Scenario Reference

| Scenario | Expected behaviour |
|----------|--------------------|
| Two concurrent carves (shared + shared) | Both succeed in parallel |
| Revoke while carve in flight (exclusive vs. shared) | Carve blocks until revoke completes |
| Two concurrent revokes (exclusive + exclusive) | Serialised; second revoke sees the result of the first |
| Carve after domain revoked | Returns `CapaError::DomainRevoked` |
| Send while receiver is running on a remote core | IPI preempts receiver; update applied; receiver resumes |
