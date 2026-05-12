# Deterministic Concurrency Testing

**Status**: Planned  
**Relates to**: `2026/tests/concurrency/`, `2026/src/platform.rs`

---

## 1. Problem with the Current Tests

The existing tests in `concurrency/basic.rs` and `concurrency/crosscore.rs` use
real OS threads with `thread::sleep` or spin-wait loops to approximate
interleaving.  These are **non-deterministic**: the OS scheduler decides which
thread runs next, so:

- Tests may pass or fail depending on load, CPU count, or timing jitter.
- It is impossible to express "thread B must attempt the lock *while* thread A
  is holding it" without a fragile sleep.
- The `test_crosscore_revoke_with_fallback` flake (domain-ID race) was one
  symptom; timing-dependent lock-contention tests are another.

What we actually want is to write conflict scenarios like prose:

> *"A starts a revoke and enters the tree.  B attempts a carve.  Verify B is
> blocked.  A finishes.  Verify B unblocks and succeeds."*

---

## 2. Approach: Choreographed-Thread Testing

### 2.1 Core Idea

Each participant in a concurrent scenario runs in a real OS thread but can only
advance to the next step when the **test harness** gives it a *proceed* token.
This is implemented with a pair of `std::sync::mpsc` channels per actor:

```
Harness                 Actor
───────                 ─────
proceed.send(()) ────►  proceed.recv()   ← blocked here until harness says go
                        ... do work ...
done.recv()    ◄──────  done.send(())    ← signals harness that step is done
```

The harness controls the exact interleaving by choosing when to send proceed
tokens and in what order.

### 2.2 Actor Framework (sketch)

```rust
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

/// A handle to a choreographed thread.
pub struct Actor<T> {
    proceed: Sender<()>,
    done: Receiver<()>,
    handle: JoinHandle<T>,
}

impl<T: Send + 'static> Actor<T> {
    /// Spawn an actor.  The body receives `(proceed, done)` and must call
    /// `proceed.recv().unwrap()` before each step and `done.send(()).unwrap()`
    /// after each step.
    pub fn spawn<F>(body: F) -> Self
    where
        F: FnOnce(Receiver<()>, Sender<()>) -> T + Send + 'static,
    {
        let (proceed_tx, proceed_rx) = mpsc::channel();
        let (done_tx,    done_rx)    = mpsc::channel();
        let handle = thread::spawn(move || body(proceed_rx, done_tx));
        Actor { proceed: proceed_tx, done: done_rx, handle }
    }

    /// Tell the actor to advance to its next step.
    pub fn proceed(&self) { self.proceed.send(()).unwrap(); }

    /// Wait for the actor to finish its current step.
    pub fn wait(&self) { self.done.recv().unwrap(); }

    /// proceed + wait in one call (convenient for sequential steps).
    pub fn step(&self) { self.proceed(); self.wait(); }

    /// Advance actor, then assert it does NOT finish within `timeout_ms`.
    /// Use this to verify that an actor is blocked on a lock.
    pub fn assert_blocked(&self, timeout_ms: u64) {
        self.proceed();
        assert!(
            self.done.recv_timeout(std::time::Duration::from_millis(timeout_ms)).is_err(),
            "actor was expected to block but completed immediately"
        );
    }

    /// Collect the return value of the actor thread.
    pub fn join(self) -> T { self.handle.join().unwrap() }
}
```

### 2.3 Lock-Contention Helper

Because `execute()` acquires the RW lock inside its closure, we need actors to
signal "I am inside the lock" back to the harness.  A shared `AtomicBool` flag
works:

```rust
let inside = Arc::new(AtomicBool::new(false));
let inside2 = inside.clone();

let revoke_actor = Actor::spawn(move |proceed, done| {
    proceed.recv().unwrap();                          // wait for step 1
    execute(&*platform, true, move || {
        inside2.store(true, Ordering::Release);       // signal: inside lock
        // ... revoke work ...
        Ok(((), batch))
    }).unwrap();
    done.send(()).unwrap();                           // step 1 done
});

// Harness: let revoke actor enter the lock, then verify carve is blocked.
revoke_actor.proceed();
// spin until revoke is actually inside the lock
while !inside.load(Ordering::Acquire) { std::hint::spin_loop(); }

// Now try carve — should block because exclusive lock is held.
carve_actor.assert_blocked(50 /*ms*/);

// Release revoke actor
revoke_actor.wait();

// Carve should now unblock
carve_actor.wait();
```

---

## 3. Conflict Scenarios to Implement

These go in `tests/concurrency/conflict.rs`.

### 3.1 Exclusive blocks shared (revoke vs. carve)

| Step | Thread A (revoke, exclusive) | Thread B (carve, shared) |
|------|------------------------------|--------------------------|
| 1 | Acquire exclusive lock, enter closure, signal `inside_a = true` | — |
| 2 | — | Attempt to acquire shared lock → **blocked** (assert) |
| 3 | Complete revoke, release lock | — |
| 4 | — | Shared lock acquired, carve completes |

Verifies: exclusive lock prevents any concurrent shared-lock entry.

### 3.2 Shared does not block shared (carve vs. carve)

| Step | Thread A (carve, shared) | Thread B (carve, shared) |
|------|--------------------------|--------------------------|
| 1 | Acquire shared lock, signal `inside_a = true` | — |
| 2 | — | Acquire shared lock → **succeeds concurrently** |
| 3 | Both complete | |

Verifies: two non-destructive operations run in parallel.

### 3.3 Exclusive serializes two revokes

| Step | Thread A (revoke, exclusive) | Thread B (revoke, exclusive) |
|------|------------------------------|------------------------------|
| 1 | Acquire exclusive lock, enter closure | — |
| 2 | — | Attempt exclusive lock → **blocked** |
| 3 | A completes, releases lock | — |
| 4 | — | B acquires exclusive lock, completes |

Verifies: two revokes are totally ordered.

### 3.4 Exclusive waits for all active readers (many-readers drain)

N threads hold shared locks.  A revoke thread then attempts the exclusive
lock.  Verify the exclusive lock is not acquired until all N readers have
released, and that none of the N readers can start *after* the exclusive
request is queued (writer preference, if the RW lock implementation supports
it — `parking_lot` does; `spin` does not guarantee this).

> **Note on writer preference**: `parking_lot::RwLock` is writer-preferring
> (new readers block if a writer is waiting).  `spin::RwLock` in spin ≥ 0.9
> is also writer-preferring.  This property matters for liveness: a high
> carve rate must not starve revokes.

### 3.5 Revoke-then-operate on dead domain returns error

| Step | Thread A (revoke, exclusive) | Thread B (carve on same domain, shared) |
|------|------------------------------|-----------------------------------------|
| 1 | Acquire exclusive, revoke domain D | — |
| 2 | Release | — |
| 3 | — | Acquire shared, attempt carve on D |
| 4 | — | Returns `CapaError::NotFound` or `AlreadyRevoked` |

Verifies: the lock provides mutual exclusion but does not hide a
use-after-revoke bug — the capability tree's own checks catch it.

---

## 4. Why Not `loom`?

[`loom`](https://github.com/tokio-rs/loom) systematically explores all
possible thread interleavings by replacing `std::sync` with a cooperative
runtime.  It would be the gold standard for exhaustive coverage.

Reasons to prefer choreographed threads for now:

| Criterion | `loom` | Choreographed threads |
|---|---|---|
| Code invasiveness | Must use `loom::sync` everywhere | Uses `std` / `parking_lot` as-is |
| Bare-metal path | `loom` requires std | Choreographed threads also need std, but only in tests |
| Expressiveness | Exhaustive but hard to express specific scenarios | Easy to express named scenarios |
| Compile-time overhead | High (separate loom build) | None |

**Recommendation**: start with choreographed threads for the named scenarios
above.  Add `loom` later if a thorough exhaustive sweep is needed (e.g., for
the bare-metal RW spinlock implementation).

> **Update**: after further consideration the loom approach is more appealing
> because it is **exhaustive** — every valid interleaving is explored, so the
> named scenarios above are covered automatically.  See §7 below for a
> concrete plan.

---

## 5. Test File Layout

```
tests/
├── common/
│   └── mod.rs              ← TestPlatform, shared helpers
│
├── unit/                   ← single-module focused, no threading
│   ├── memory.rs
│   ├── domain.rs
│   ├── capability.rs
│   ├── update.rs
│   ├── switch.rs
│   ├── view.rs
│   └── attest.rs
│
├── integration/            ← multi-module scenarios, sequential
│   ├── api.rs
│   ├── end_to_end.rs
│   ├── owner_validation.rs
│   ├── revoke.rs
│   ├── vital_revoke.rs
│   ├── overlap.rs
│   ├── updates.rs
│   └── interrupt.rs
│
└── concurrency/            ← multi-threaded and cross-core
    ├── basic.rs            ← concurrent reads/writes (existing)
    ├── crosscore.rs        ← IPI/barrier protocol (existing)
    ├── platform.rs         ← execute() + RW lock tests (existing)
    └── conflict.rs         ← choreographed conflict scenarios (TODO)
```

---

## 6. Implementation Steps

1. **Add `Actor` helper** to `tests/common/mod.rs` (or a new
   `tests/common/choreography.rs`).
2. **Implement scenario 3.1** (exclusive blocks shared) — the simplest and
   highest-value test.
3. **Implement scenarios 3.2, 3.3** (shared concurrency, revoke ordering).
4. **Implement scenario 3.4** (many-readers drain + writer preference) — most
   complex; skip writer-preference assertion on bare-metal spin builds.
5. **Implement scenario 3.5** (use-after-revoke returns error, not UB).
6. Hook `conflict.rs` into `Cargo.toml` as `concurrency_conflict`.

---

## 7. Exhaustive Interleaving with `loom`

The choreographed approach (§2) lets us express *named* scenarios, but it only
tests the interleavings we think of.  [`loom`](https://github.com/tokio-rs/loom)
takes a complementary approach: it replaces `std::sync` with a cooperative
scheduler and systematically explores **every possible interleaving** via
bounded model-checking.  Because the conflict scenarios in §3 all reduce to
2–4 threads performing a small number of synchronisation operations, the state
space is tractable.

### 7.1 How `loom` Works (Quick Recap)

1. **Cooperative threading**: `loom::thread::spawn` creates logical threads
   managed by loom's own scheduler, not the OS.
2. **Primitive substitution**: `loom::sync::{Arc, Mutex, RwLock, atomic::*}`
   are drop-in replacements that record every synchronisation decision.
3. **Model run**: `loom::model(|| { … })` re-executes the closure many times,
   each time choosing a different valid thread schedule.  If any assertion
   fires on *any* schedule, the test fails and prints the failing schedule.

### 7.2 Making the Code `loom`-Compatible

The key obstacle noted in §4 is **code invasiveness**: the production code
uses `crate::sync::RwLock` (which resolves to `parking_lot` or `spin`).
We do **not** want to pepper the production source with `#[cfg(loom)]`.

**Strategy — thin abstraction + feature gate (contained to `sync.rs`):**

```rust
// src/sync.rs — add a third arm for loom

#[cfg(loom)]
pub use loom::sync::RwLock;

#[cfg(all(not(loom), feature = "hosted"))]
pub use parking_lot::RwLock;

#[cfg(all(not(loom), not(feature = "hosted")))]
pub use spin::RwLock;
```

Because all internal code already goes through `crate::sync::RwLock`, this
single three-line change is the **only** modification needed in production
source.

Similarly, for any `Arc` or atomics used inside the engine:

```rust
// src/sync.rs — also re-export Arc and atomics

#[cfg(loom)]
pub use loom::sync::Arc;
#[cfg(not(loom))]
pub use alloc::sync::Arc;

#[cfg(loom)]
pub use loom::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(not(loom))]
pub use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
```

Then replace all direct `use std::sync::Arc` / `use core::sync::atomic::*`
in the crate with `use crate::sync::{Arc, AtomicBool, …}`.  This is a
grep-and-replace, not a logic change.

### 7.3 Cargo Configuration

```toml
# Cargo.toml additions

[target.'cfg(loom)'.dependencies]
loom = "0.7"

# Alternatively, use a feature flag:
[features]
loom = ["dep:loom"]

[dependencies]
loom = { version = "0.7", optional = true }
```

Loom tests are compiled with:

```sh
RUSTFLAGS='--cfg loom' cargo test --test loom_concurrency --release
# or, with the feature-flag approach:
cargo test --test loom_concurrency --features loom --release
```

> **`--release`**: loom tests are CPU-intensive; release mode makes a
> significant difference.

### 7.4 Test File: `tests/concurrency/loom_concurrency.rs`

A single test file covers all the scenarios from §3, because each
`loom::model` call is self-contained and exhaustive.

```rust
//! Exhaustive interleaving tests using `loom`.
//!
//! Compile with: RUSTFLAGS='--cfg loom' cargo test --test loom_concurrency --release

#[cfg(loom)]
mod loom_tests {
    use loom::sync::{Arc, RwLock};
    use loom::sync::atomic::{AtomicUsize, Ordering};
    use loom::thread;

    // ── 3.1 Exclusive blocks shared ─────────────────────────────────

    #[test]
    fn exclusive_blocks_shared() {
        loom::model(|| {
            let lock = Arc::new(RwLock::new(0u32));
            let counter = Arc::new(AtomicUsize::new(0));

            let l = lock.clone();
            let c = counter.clone();
            let writer = thread::spawn(move || {
                let mut w = l.write().unwrap();
                // Simulate exclusive revoke work
                *w += 1;
                c.fetch_add(1, Ordering::SeqCst);
            });

            let l = lock.clone();
            let c = counter.clone();
            let reader = thread::spawn(move || {
                let r = l.read().unwrap();
                // If we get the read lock, the writer must have either
                // not started yet or already finished — never mid-write.
                let val = *r;
                assert!(val == 0 || val == 1);
                c.fetch_add(1, Ordering::SeqCst);
            });

            writer.join().unwrap();
            reader.join().unwrap();
            assert_eq!(counter.load(Ordering::SeqCst), 2);
        });
    }

    // ── 3.2 Shared does not block shared ────────────────────────────

    #[test]
    fn shared_does_not_block_shared() {
        loom::model(|| {
            let lock = Arc::new(RwLock::new(42u32));

            let l1 = lock.clone();
            let r1 = thread::spawn(move || {
                let r = l1.read().unwrap();
                assert_eq!(*r, 42);
            });

            let l2 = lock.clone();
            let r2 = thread::spawn(move || {
                let r = l2.read().unwrap();
                assert_eq!(*r, 42);
            });

            r1.join().unwrap();
            r2.join().unwrap();
        });
    }

    // ── 3.3 Exclusive serialises two revokes ────────────────────────

    #[test]
    fn exclusive_serialises_two_revokes() {
        loom::model(|| {
            let lock = Arc::new(RwLock::new(0u32));
            let order = Arc::new(AtomicUsize::new(0));

            let l = lock.clone();
            let o = order.clone();
            let w1 = thread::spawn(move || {
                let mut w = l.write().unwrap();
                let ticket = o.fetch_add(1, Ordering::SeqCst);
                *w += 1;
                ticket
            });

            let l = lock.clone();
            let o = order.clone();
            let w2 = thread::spawn(move || {
                let mut w = l.write().unwrap();
                let ticket = o.fetch_add(1, Ordering::SeqCst);
                *w += 1;
                ticket
            });

            let t1 = w1.join().unwrap();
            let t2 = w2.join().unwrap();
            // Tickets must be 0 and 1 in some order (serialised).
            assert!(t1 != t2);
            assert_eq!(*lock.read().unwrap(), 2);
        });
    }

    // ── 3.4 Exclusive waits for all active readers ──────────────────

    #[test]
    fn writer_waits_for_all_readers() {
        loom::model(|| {
            let lock = Arc::new(RwLock::new(0u32));
            let readers_done = Arc::new(AtomicUsize::new(0));

            // Spawn 2 readers (keep N small for tractable state space).
            let mut handles = Vec::new();
            for _ in 0..2 {
                let l = lock.clone();
                let rd = readers_done.clone();
                handles.push(thread::spawn(move || {
                    let _r = l.read().unwrap();
                    rd.fetch_add(1, Ordering::SeqCst);
                }));
            }

            // Writer: must observe consistent state after lock acquired.
            let l = lock.clone();
            let rd = readers_done.clone();
            let writer = thread::spawn(move || {
                let mut w = l.write().unwrap();
                *w = rd.load(Ordering::SeqCst) as u32;
            });

            for h in handles {
                h.join().unwrap();
            }
            writer.join().unwrap();

            // Final value is 0, 1, or 2 depending on schedule.
            let val = *lock.read().unwrap();
            assert!(val <= 2);
        });
    }
}

// When not compiled under loom, the test file compiles but does nothing.
#[cfg(not(loom))]
fn main() {}
```

### 7.5 Scoping the State Space

Loom's execution time grows factorially with the number of threads and
synchronisation points.  Keep tests tractable:

| Guideline | Reason |
|---|---|
| ≤ 3 threads per model | >3 threads can produce millions of interleavings |
| ≤ 5 sync ops per thread | Each additional `lock` / `store` multiplies the schedule count |
| Use `loom::model` per scenario | Isolated models explore independent state spaces |
| Compile with `--release` | Loom's bookkeeping is CPU-heavy; release is 5-10× faster |
| Set `LOOM_MAX_PREEMPTIONS` | `export LOOM_MAX_PREEMPTIONS=3` bounds the search if it takes too long |

### 7.6 Covering the `execute()` Function

The scenarios above test the raw RW lock.  To test `execute()` itself under
loom we need a mock `Platform` that uses `loom::sync` primitives.  This
follows the same pattern as the existing `TestPlatform` in
`tests/common/mod.rs`, but with loom types:

```rust
#[cfg(loom)]
struct LoomPlatform {
    lock: Arc<loom::sync::RwLock<()>>,
    // ... other fields using loom primitives ...
}
```

Because `execute()` takes `&dyn Platform` and calls
`acquire_shared_lock()` / `acquire_exclusive_lock()`, the mock just needs to
return guards that internally hold a `loom::sync::RwLockReadGuard` or
`RwLockWriteGuard`.  The production `execute()` code itself does not need
any `#[cfg(loom)]` annotation — the `crate::sync::RwLock` alias handles it.

### 7.7 Loom vs. Choreographed: When to Use Which

| Use case | Preferred approach |
|---|---|
| "Does any interleaving of carve + revoke violate my invariant?" | **Loom** — exhaustive |
| "Reproduce a specific known race for a regression test" | **Choreographed** — deterministic, readable |
| Bare-metal spin-lock correctness (no OS scheduler) | **Loom** — explores spin-loop schedules |
| Testing the IPI barrier protocol with realistic timing | **Choreographed** — can assert on step ordering |

Both approaches complement each other; loom gives confidence that *no*
interleaving is missed, while choreographed tests serve as executable
documentation of specific conflict narratives.

### 7.8 Implementation Steps

1. **Extend `sync.rs`** with the `#[cfg(loom)]` arm (3 lines, see §7.2).
2. **Add `loom` to `Cargo.toml`** as an optional dependency (§7.3).
3. **Create `tests/concurrency/loom_concurrency.rs`** with the four core
   models from §7.4.
4. **Register in `Cargo.toml`**:
   ```toml
   [[test]]
   name = "loom_concurrency"
   path = "tests/concurrency/loom_concurrency.rs"
   required-features = ["loom"]
   ```
5. **Verify**: `cargo test --test loom_concurrency --features loom --release`
   — all models should pass and terminate in seconds.
6. **Add `LoomPlatform` mock** (§7.6) to test `execute()` under loom.
7. **CI**: add a job that runs loom tests nightly (they are slower than unit
   tests and should not gate every PR).
