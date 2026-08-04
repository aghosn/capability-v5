## Themis — Implementation Status & Plan

> **Archives**: Previous todo content archived to:
> - [`docs/archive/todos/archived_todo_09_03_2026.md`](docs/archive/todos/archived_todo_09_03_2026.md) — phases 0–15, BUG-1–15, dom0 bringup
> - [`docs/archive/session-notes/27_03_2026.md`](docs/archive/session-notes/27_03_2026.md) — full history through dom1 multi-core debugging
> - [`docs/archive/session-notes/07_04_2026.md`](docs/archive/session-notes/07_04_2026.md) — differential testing, VITAL cascade fix, TPM, code review

## Current Status

- **2026-08-04 — LAPIC-timer policy bypass: root-caused, attempted fix caused a
  live hang, reverted to baseline. Now auditing capavisor broadly for ad-hoc
  mechanisms that don't map to the capa-engine model — this is the current
  active work on this branch.**

  **Confirmed bug (still unfixed, capavisor at baseline)**: `msr_emulator.rs`'s
  `deliver_timer_vector()` (IA32_TSC_DEADLINE / vector `0xEC` emulation)
  injects directly into the running domain **unconditionally**, never
  consulting `InterruptVisibility` at all (doc comment says so on purpose —
  "the guest never round-trips through CHV's userspace timerfd path"). This is
  purely an MSR-policy-driven emulated device; the fix belongs entirely inside
  capavisor (no CHV/thhv changes needed, unlike the original 2026-08-03 plan
  below which is now superseded).

  **First fix attempt (reverted)**: delegated `deliver_timer_vector` straight to
  `forward_interrupt_to_handler` (the same lazy-unwind path used for real
  external interrupts). Live-tested on hardware: **both** the `Deliver` and
  `Suppress` test policies (`eunomia/policies/timer/{deliver,suppress}.json`)
  hung the whole stack — dom0 became fully unreachable (SSH timeout) while
  `qemu-system-x86_64` spun at ~106% CPU (livelock, not a data hang or clean
  guest-side failure). Root cause: `forward_interrupt_to_handler`'s full
  cross-domain VP-swap (`swap_active_vp` + `write_swap_reply`) is designed for
  *rare, asynchronous* real interrupts; delegating the *frequent, synchronous,
  same-VP* emulated timer tick to it forces a full swap on every tick instead
  of the batching/quantum-boundary real interrupts get — this is what
  livelocked. **Reverted** `msr_emulator.rs` to the original (still-buggy but
  safe) unconditional-inject baseline via `git checkout`. Confirmed
  `quantum-sched` was NOT enabled during the hang (opt-in feature, off by
  default — verified via build fingerprints), so the hang is not
  quantum-sched-specific; it's inherent to reusing the full-swap path at
  timer-tick frequency regardless.

  **Also fixed in passing**: `update-bins.sh`'s eunomia-policy packaging did
  `cp -r` into `bins.img` without ever clearing the destination first, so
  deleted/renamed policy JSON files accumulated forever across
  `cargo build-bins` runs. Added `rm -rf` before repackaging. (Same
  `cp -r`-without-clean pattern may exist elsewhere in that script — not
  audited.)

  **Current direction (audit-first, per user)**: rather than patch this one
  path again, doing a full inventory of capavisor for mechanisms that
  duplicate/bypass the capa-engine's policy model instead of projecting it.
  Findings so far (not yet acted on):
  1. **`quantum-sched` feature** (`platform/vcpu_slot.rs` `CoreContext::
     deferred_vector: AtomicU16`, `platform/mod.rs` `set_deferred`/
     `take_deferred`, `monitor.rs` handlers, `hypercall/switch.rs` child-exit
     drain) — a second, capa-engine-external interrupt-scheduling axis, opt-in,
     explicitly documented (`docs/architecture/interrupt-virtualization.md`)
     as a nested-virt-dev-environment-only shim ("should NOT be enabled on
     bare metal"). Candidate for full removal.
  2. **`SwitchContext::interrupt_inject` discarded** (`hypercall/switch.rs`
     ~L242: `let _ = switch_ctx.interrupt_inject;`) — a real, tested capa-engine
     field (lazy-unwind re-injection into the true leaf on `SWITCH`-return),
     disabled by a 2026-07-30 stop-gap that says it's safe to re-enable now
     that `policy_walker` wires `InterruptVisibility` correctly. Likely the
     *correct* mechanism to route timer (and other) delivery through instead
     of quantum-sched's defer hack.
  3. **Duplicated interrupt-injection mechanisms**: `vcpu_ext.rs`
     `inject_external_vector`, `pid.rs` `inject_via_pid`, and
     `hypercall/switch.rs` `drain_pir_inject_lowest` all implement "deliver a
     vector to a VP" independently; the `guest_can_accept_external() ? direct
     : pid-inject` idiom is copy-pasted in `msr_emulator.rs`,
     `forward_interrupt_to_handler`, and `doorbell.rs`.
  4. **Overlapping policy axes**: `InterruptVisibility`, `injectable`,
     quantum-sched's defer flag, and `guest_can_accept_external()` all
     interact at `forward_interrupt_to_handler`/`doorbell.rs` without one
     documented unified model.
  5. **Parallel non-policy-driven MSR trapping**: `msr_virt.rs`'s
     `TRAPPED_RANGES` (perf-counter MSRs) is a hardcoded, global table applied
     identically to every domain via `alloc_msr_bitmap` — entirely separate
     from `msr_bitmap.rs`'s real per-domain `MsrPolicy` projection.
  6. **MSR `Emulate` WRMSR fallback mutates policy as scratch storage**
     (`monitor.rs`): when no internal emulator claims an `Emulate` MSR, the
     guest's write value is stored directly into the domain's policy object
     as ad-hoc scratch state.

  **Next steps**: work through items 1-4 (interrupt/timer-scoped, this
  branch's stated goal) first, then 5-6 as follow-up. Plan to be built next.

- **2026-08-03 — `interrupt_semantics` branch: added per-vector `injectable`
  policy bit (item 2) + wired `policies.interrupts` config plumbing
  (closes the item-1 prerequisite bug noted below) + unit/config-level
  tests (item 3). No commit yet — pending final review.**

  **Design resolved with user**: `InterruptVisibility` (`Deliver`/`Report`/
  `NotReport`) governs ONLY the automatic real-hardware-interrupt routing
  decision (`forward_interrupt_to_handler`/chain-walk/resume). It says
  nothing about explicit, parent-initiated injection via
  `THEMIS_INJECT_INTERRUPT`. That's now a second, independent axis: a new
  `VectorPolicy::injectable: bool` field. This lets a parent set a vector
  to `NotReport` (child gets zero automatic/ambient exposure to it — no
  timing side-channel, no stray redelivery) while *keeping* `injectable:
  true`, so the parent retains sole, deliberate, software-controlled
  authority over when that vector ever reaches the child (e.g. acting as
  an emulated interrupt controller for it) — this was the user's explicit
  correction to an earlier (wrong) proposal that `NotReport` should be an
  absolute blind spot blocking injection too.

  **Changes**:
  1. `capa-engine/src/domain.rs`: `VectorPolicy` gained `injectable: bool`.
     `default_deliver()` → `injectable: true`; `default_report()` →
     `injectable: true` (kept true for now — see prerequisite note below on
     why flipping the *default* to `false` is deferred).
  2. `PolicyIdentifier::VectorInjectable(u8)` / `PolicyChange::VectorInjectable
     { vector, injectable }` added end-to-end: `domain_api.rs` set_policy
     (NOT monotonicity-checked, like the register bitmaps) / get_policy,
     `update.rs`, wire constant `policy_kind::VECTOR_INJECTABLE = 16` in
     `themis-abi`, `cloud-hypervisor/.../consts.rs`, and `thhv/inc/thhv.h`,
     capavisor's `hypercall/capa.rs::do_set_policy` match, and a no-op
     (policy read directly at call time, no derived HW state) arm in
     `platform/mod.rs::apply_policy_change`.
  3. `themis/capavisor/src/arch/x86_64/hypercall/doorbell.rs::do_inject_interrupt`
     now rejects (`ERR_NOPERM`) if `policy.interrupts.get_policy(vector)
     .injectable` is false — this is the only enforcement point; ownership
     of the child capability is still required as before (A9).
  4. **Fixed the config-plumbing bug called out in the 2026-07-30 entry
     below**: added `policy_walker.rs::walk_interrupts()` (mirrors
     `walk_exits`) and wired it into `vm_state.rs`'s pre-seal sequence, so
     `ThemisConfig.policies.interrupts` (`default` + per-vector `overrides`,
     now including the new `injectable` field in `config.rs`'s
     `VectorPolicyConfig`) actually reaches `THHV_SET_POLICY` today. Config
     default for `injectable` is `true` (matches the engine default —
     preserves existing `THEMIS_INJECT_INTERRUPT` behavior for anyone not
     using the new field yet).
  5. Added `eunomia/policies/timer/01-suppress-with-injectable.json`
     demonstrating the pattern: default vector policy `Suppress` +
     `injectable: false` (fully silent/non-injectable by default), with
     vector 236 (`0xEC`, LAPIC timer) overridden to stay `injectable: true`.
     Not yet live-booted (no hardware in this session) — parses/validates
     cleanly (`eunomia_timer_interrupt_policies_parse` in `config.rs`);
     user should live-test via `run-eunomia.sh --themis timer --themis-config
     eunomia/policies/timer/01-suppress-with-injectable.json` next.
  6. Tests added: 5 new `capa-engine/tests/unit/set_get.rs` cases
     (`test_set_get_vector_injectable`,
     `test_vector_injectable_independent_of_visibility`,
     `test_vector_injectable_not_monotone`, + 2 helpers/assertions inline);
     4 new `cloud-hypervisor/hypervisor/src/themis/{config,policy_walker}.rs`
     tests (JSON parse/validate + `walk_interrupts` op-stream checks). All
     pass; full existing `capa-engine`/`hypervisor --features themis`/
     `capavisor` builds and test suites still pass (verified this session).
  7. **Still open / not done this session**: item (1)'s broader question
     (should `default_report()`'s blanket-`Report` default itself change to
     `NotReport`, now that config can actually apply overrides?) was
     deliberately NOT changed — kept `Report`/`injectable: true` as the
     engine default to avoid a second simultaneous behavior change; worth
     a dedicated follow-up decision once the `VpRunState::Waiting`
     redesign (see 2026-07-30 entry, item 2) is scoped. No eunomia
     boot-level (hardware) validation of the new `injectable` gate itself
     was performed this session (sandboxed dev environment, no KVM) —
     needs a live run before merge.

- **2026-07-30 — Root-caused eunomia-timer intermittent `#GP` + nested-Linux
  spurious LAPIC-timer storm to `do_switch`'s "6a" `interrupt_inject` wiring
  (added in the DomainComm-adjacent session below); applied a narrow
  stop-gap, NOT a full fix.**

  **Root cause**: `do_switch` step "6a" (`themis/capavisor/src/arch/x86_64/hypercall/switch.rs`)
  re-injects `SwitchContext.interrupt_inject`'s vector raw into a resuming
  domain's own PIR whenever `capa-engine` left it `Waiting{report:true,
  unlocks:None}`. That state arises for ANY real external interrupt landing
  on the core while a `Report`-policy domain (the default for every
  non-root domain) is running — the vector gets fully routed to and
  handled by a `Deliver`-policy ancestor (dom0) via `deliver_interrupt_vp`'s
  lazy-unwind, but step 6a then redelivers the SAME vector a second time
  once the domain resumes. `capa-engine/src/domain.rs` documents `Report`
  as "reported to domain but handled by parent" — i.e. NOT meant to be
  redelivered raw — so this is a genuine discrepancy between the doc'd
  semantics and step 6a's behavior.
  - For `eunomia-timer` (whose guest IDT only covers vectors 0-31 and its
    own `0xEC`): a stray legacy vector (`0x23`/`0x24`, real COM1/IRQ4
    hardware interrupts, matching the trapped `0x3F8-0x3FF` serial port)
    gets redelivered into a domain with no handler for it → `#GP`
    (`error_code` decodes to `EXT=1,IDT=1,index=35or36`; IDT[36]'s gate
    type is `0` — invalid, not just not-present — hence `#GP` not `#NP`).
    Only `timer` (not `coco`/`domcomm`/etc.) hits this because it's the
    only eunomia workload that ever executes `sti` (`eunomia/workloads/timer/src/main.rs:29`)
    and busy-waits with IF=1 for ~100ms; other workloads run entirely with
    IF=0 so the CPU never actually takes an externally-injected vector.
  - For a nested Linux (L2) guest (full IDT, so no crash): the SAME
    mechanism instead produces a continuous spurious duplicate-interrupt
    storm (real IPIs `0xfb`/`0xfd`, legacy IRQs, and `0xec` all getting
    redelivered on every SWITCH resume) — this is what "dom1 getting
    spurious LAPIC timer interrupts all the time" turned out to be.
  - **Confirmed orthogonal / unaffected**: the domain's OWN emulated LAPIC
    timer (`0xEC` via `msr_emulator.rs`'s `deliver_timer_vector`, gated by
    `MsrPolicy` on `IA32_TSC_DEADLINE`/`0x6E0`) injects directly, bypassing
    `InterruptPolicy`/`Report`/`Deliver` entirely — never touches step 6a.
    This is why the timer workload's own tick delivery always "worked"
    even before/regardless of this bug.

  **Stop-gap applied (final, after two failed config-based attempts —
  see below for why they didn't work) — `switch.rs`'s step 6a raw
  re-injection is now disabled outright**:
  - First attempt (`standard.json` interrupts override `{vector: 236,
    visibility: Deliver}`) and second attempt (a per-workload
    `--themis-config` for `timer` setting `interrupts.default: Suppress`,
    plus a `run-eunomia.sh` auto-select for it) were BOTH live-tested and
    had **zero effect** — `eunomia-timer` still `#GP`'d on other stray
    vectors (`0x20`/`0x23`) and dom1's spurious LAPIC-timer storm persisted
    unchanged.
  - **Why they were inert**: `cloud-hypervisor/hypervisor/src/themis/
    policy_walker.rs` (which turns a parsed `ThemisConfig` into the
    `THHV_SET_POLICY` ops actually applied to a domain) walks `msrs`,
    `cpuid`, and `exits` — but NEVER `policies.interrupts`.
    `InterruptsConfig`/`Visibility` (`config.rs`) are parsed, validated,
    and unit-tested, but are otherwise completely dead: **no code path
    anywhere applies them to a domain's runtime `InterruptPolicy`.** Every
    child domain's `InterruptPolicy` is therefore always whatever
    `DomainPolicy::new_restricted()` defaults to (`Report` for every
    vector), no matter what any `--themis-config`/`standard.json` says.
    This is a separate, real bug in its own right (config schema exists,
    is user-facing, and silently does nothing) — tracked below as a
    prerequisite for the real fix.
  - Given config can't help today, `switch.rs`'s step 6a now unconditionally
    discards `switch_ctx.interrupt_inject` (`let _ = ...;`) instead of
    calling `inject_via_pid` — i.e. `Report` now actually behaves as
    documented ("reported to domain but handled by parent", never
    redelivered), for every vector, unconditionally. Comment above the
    line updated accordingly (still explains the full discrepancy and
    points at the two things needed for a real fix).
  - `standard.json` and the per-workload `eunomia/policies/timer/
    no-report.json` + `run-eunomia.sh` auto-select from the two failed
    attempts were all **reverted** (they did nothing and would only add
    confusion) — this branch's diff is now just the `switch.rs` disable +
    docs.
  - **NOT fixed / deferred to a follow-up branch** (per-user direction:
    document, stop-gap now, dedicated branch for semantics next):
    1. Wire `policy_walker.rs` to actually apply `InterruptsConfig` (the
       config plumbing bug above) — needed before ANY per-vector
       `Deliver`/`Report`/`Suppress` policy can matter at all.
    2. The deeper `capa-engine` design question: `VpRunState::Waiting`
       needs a discriminant distinguishing "external-interrupt-routed,
       already delivered to ancestor" (must never redeliver) from "genuine
       SWITCH-chain preemption, callee should observe this" (legitimate
       re-injection case that step 6a was originally meant to serve) —
       needs design review before touching `capa-engine`'s state machine
       (security-critical, see
       `.github/instructions/capability-engine.instructions.md`).
  - **Live-validated 2026-07-30**: with step 6a's injection disabled,
    both `eunomia-timer` and dom1 run correctly (user-confirmed) — no more
    `#GP`, no more spurious LAPIC-timer storm. Cleared to commit/merge per
    plan below. Still an open risk long-term: whatever legitimate
    re-injection case step 6a originally existed for (if any) is now also
    disabled — not observed to regress anything in this round of testing,
    but not proven absent either; worth keeping an eye out for in the
    follow-up branch.
  - Stripped all `[TEMP-DEBUG]` logging (4 call sites: `switch.rs` x2,
    `msr_emulator.rs`, `vmexit/mod.rs`) — final diff for this branch is
    now just `switch.rs` (step 6a disabled) + `todo.md`.
  - Plan (per user, 2026-07-30): if live-validated, commit and merge this
    branch as-is (step 6a disabled + docs), then open a NEW branch
    dedicated solely to the interrupt-policy semantics (both the
    `policy_walker.rs` plumbing gap and the `VpRunState::Waiting`
    discriminant design).

- **2026-07-29 — DomainComm ring alignment + pointer-corruption fix, landed
  and live-verified (UNCOMMITTED prior to this entry, now being committed).**
  Follows on from the doorbell/interrupt redesign entry below — this is a
  separate bug hit while retesting eunomia after that work.

  **Bugs found and fixed in `themis/capavisor/src/platform/domain.rs`**:
  1. **Alignment panic**: `domcomm_rx_enqueue`/`domcomm_tx_dequeue` wrote
     `MsgHeader` (8-byte-aligned, has a `u64` field) through a typed
     `&mut MsgHeader` reference at byte-packed ring offsets that aren't
     guaranteed 8-aligned (ring has no per-message padding by design —
     `total_size` must stay exact, see prior off-by-one history). Triggered
     reliably whenever `test_attestation` ran first (attestation payload
     lengths aren't 8-byte multiples, drifting the cursor). Fixed by
     switching to `core::ptr::write_unaligned`/`copy_nonoverlapping`
     everywhere instead of typed dereferences — also correct because this
     memory is domain-shared, so forming an exclusive `&mut` over it is
     unsound regardless of alignment.
  2. **Untrusted-cursor hardening**: the DomainComm header page holds both
     RX and TX `RingMeta` together, so it's entirely domain-writable — a
     malicious/buggy domain could scribble on `rx.head`/`tx.tail`, the
     fields capavisor considers authoritative. Fixed by adding
     `DomainCommRing::local_cursor: u32`, a capavisor-private producer/
     consumer cursor; capavisor now only ever *writes* its own cursor into
     shared memory, never reads it back. Only the domain's own cursors
     (`rx.tail`, `tx.head`) are read from shared memory (still via
     `read_volatile` + fence).
  3. **Bounds-checked pointers**: added `DomainCommRing::checked_ptr(offset,
     len, hhdm_offset) -> Option<*mut u8>`, validating offset/len stay
     within one ring page and within the ring's actual backing pages before
     handing back a pointer — closes a real pre-existing OOB-read gap in
     `domcomm_tx_dequeue` (a crafted domain-supplied `total_size` near a
     page boundary could previously read past the ring page into unrelated
     HHDM-mapped memory).
  4. **Bug introduced then fixed within this same session**: initial
     `checked_ptr` implementation computed `page_off` for the boundary
     check but forgot to add it to the returned pointer — every access
     silently landed at page offset 0 instead of the real offset, which
     is what caused the "corrupted attestation nonce" symptom seen live
     (TX payload copy read raw `MsgHeader` bytes at page start instead of
     the actual nonce 16 bytes further in). Fixed: `checked_ptr` now
     returns `page_hpa + hhdm_offset + page_off`.

  **Validation**: `cargo build --release -p capavisor` clean, `cargo
  build-bins` (repo root) clean, `capa-engine cargo test --release` all
  green. Live-tested by user: `test_attestation` now passes end-to-end
  (previously failed nonce mismatch), full eunomia suite (`coco`, `smoke`,
  `sched`, `hypercall`, etc.) runs correctly including
  `test_attestation`-first ordering that previously panicked.

  **Also reviewed/cleaned this session**: debug-print artifacts from the
  live crash-hunting session — reverted an accidental `serial_debug!` →
  `serial_println!` downgrade in `arch/x86_64/hypercall/switch.rs` (kept
  the added message detail), reverted `cloud-hypervisor`'s vcpu.rs
  "log every VM exit" back to "first 5 exits only" (kept new `qual`/`gpa`
  fields and the new I/O-error-path `eprintln!`s, which are legitimate).
  Audited all `thhv/src/*.c` debug/log call sites — all pre-existing ones
  already follow correct conventions (`pr_debug`/`pr_warn_ratelimited` for
  hot paths, `pr_err`/`pr_warn` for genuine errors, `pr_info` for one-shot
  setup) — nothing to clean up there. `tools/toggle-debug` (checked-in
  binary) gets non-deterministically rebuilt by every `cargo build-bins`
  run even with unchanged source — must `git checkout -- tools/toggle-debug`
  before finalizing any diff that ran `build-bins`.

  **Known outstanding, not yet done (low priority, not blocking this
  commit)**: `send_grow_ack` (×2, `hypercall/domcomm.rs`) and the doorbell
  notify path (`arch/x86_64/hypercall/doorbell.rs:~97`) silently discard
  `enqueue_rx`'s return value on ring-full — should at least log a warning
  for diagnosability; not a hang risk today since callers already degrade
  to a clean error on failed dequeue, just harder to debug when it happens.

- **2026-07-28 — doorbell/interrupt redesign: `blocked` flag on `Waiting` VP
  state landed, fully validated, UNCOMMITTED (`fixing_domain_revocation`
  branch).** Continues the interrupt lazy-unwind chain work (separate arc
  from the P7/P8 code-quality audit below — that arc is paused, not
  abandoned; resume it after this one).

  **The bug**: under the `VpRunState::Waiting` unification (`unlocks`,
  `report` fields, from an earlier segment), a VP was "uniformly
  claimable" by any VP holding a capability handle to it. User caught a
  concrete counter-example: two independent call chains sharing a common
  intermediate domain B — `A1 -> B1 -> C1` (interrupted, frozen) and
  `A2 -> B2` (separate, unrelated, concurrently-active). B2 holds a valid
  handle to C (handles are domain-level, not per-VP), so it could illegally
  claim C1 before B1 (its own chain's frame) had itself resumed.

  **Fix** (user-specified): added `blocked: bool` to `VpRunState::Waiting`
  (`capa-engine/src/domain.rs`); removed the now-unused `prev_caller` field
  entirely (confirmed via grep it was never read for logic).
  - **Up walk** = `deliver_interrupt_vp` (`capa-engine/src/domain_api.rs`):
    walks leaf→handler via `core_ctx.peek_at`. Only the frame directly
    called by the handler (`chain[n-2]`) starts `blocked: false`; every
    deeper frame starts `blocked: true`.
  - **Down walk** = `switch_domain_forward` (same file): rejects a claim on
    `blocked == true`; otherwise walks down collapsing `report == false`
    frames until a `report == true` frame or the true leaf resumes. After
    resuming, clears `blocked` on the next frame down (`unlocks`'s callee)
    — exactly one hop, regardless of who performs the resume.
  - Cleaned up all stale `prev_caller`-referencing doc comments in
    `domain_api.rs` and `switch.rs` (`CoreContext::call_stack`, `peek_at`,
    `find_interrupt_handler`) — reworded to established vocabulary only
    (`blocked`, `unlocks`, `report`, `resume_chain`, `Waiting`/`Running`/
    `Locked`, `chain`, `handler`, `leaf`). **User explicitly rejected
    invented terms** ("entry gate", "stopping frame", "propagate") —
    stick to established vocabulary in any future comments/explanations
    here.

  **Tests**: rewrote `tests/unit/switch.rs::test_waiting_vp_resumable_by_different_vp_same_domain`
  (was asserting the wrong/buggy behavior — a different VP stealing a
  *deeper* frame should succeed; now correctly tests a different VP
  resuming the frame directly called by the handler, the real
  eunomia-crash regression). Added
  `test_deep_waiting_vp_blocked_until_caller_resumes` and
  `test_independent_chain_cannot_steal_deeper_waiting_frame` (the exact
  A1/B1/C1 vs A2/B2 scenario). Fixed
  `tests/concurrency/loom_vp_switch.rs::vp_two_cores_race_waiting_vp`'s
  manual `Waiting` construction for the new field.

  **Validation — all green**: `cargo test` (default), `cargo test
  --features address_translation`, `cargo loom` (plain, 50/50),
  `RUSTFLAGS="-C debug-assertions=on" cargo loom` (50/50), `themis/capavisor`
  `cargo build --release` (clean), `capa-cli cargo test --release`
  (**15/15 tutorials pass**, including `tutorial_05_basic_interrupts` which
  was a previously-tracked P6 failure — not confirmed *why* it now passes,
  worth a quick look but not a blocker), `cargo build-bins` at repo root
  (full success).

  **NOT yet done / next steps, in order**:
  1. `update-do-switch-injection` (SQL todo id): wire capavisor's
     `do_switch` handler to actually perform PIR injection based on
     `SwitchContext.interrupt_inject: Option<u8>`, symmetric to the
     existing `interrupt_return` handling. This is the last piece before a
     live eunomia retest.
  2. Live-boot eunomia CoCo retest end-to-end to confirm the original
     doorbell/interrupt bug this whole redesign was chasing is actually
     fixed in practice (not just at the capa-engine unit/loom level).
  3. `lean-exec` sync: the executable Lean 4 model has **not** been
     updated for `unlocks`/`report`/`blocked`/interrupt-chain semantics —
     needs differential-testing parity once the Rust side is fully settled.
  4. Debug-instrumentation cleanup (any `themis_trace()` scaffolding added
     while chasing this bug) — sweep before committing.
  5. **Nothing in this arc has been committed.** `git status` currently
     shows modified: `capa-engine/src/domain.rs`, `domain_api.rs`,
     `switch.rs`, `tests/concurrency/loom_vp_switch.rs`,
     `tests/unit/switch.rs` (this segment) — plus other
     already-modified-but-uncommitted files from earlier segments:
     `themis/capavisor/src/arch/x86_64/hypercall/switch.rs`,
     `themis/capavisor/src/platform/domain.rs`, `thhv/inc/thhv.h`,
     `thhv/src/thhv_vp.c`; and an untracked `question.md`. **User standing
     rule: do not commit automatically — wait for explicit go-ahead after
     they inspect diffs and run tests themselves.** Likely a bundled commit
     once (1)-(2) above land and eunomia is confirmed fixed live.

  **Resume next session**: re-read this entry, then `git status` / `git
  log --oneline -10` to confirm nothing drifted, then start on
  `update-do-switch-injection` (item 1 above). The P7/P8 code-quality
  audit entry directly below this one is a separate, paused arc — resume
  it only after this doorbell/interrupt work is committed.

- **2026-07-27 — code-quality redesign audit: P7 landed (`fixing_domain_revocation` branch).**
  Fixed `capa-cli/src/session.rs`'s `export-as-unit-test` codegen, which
  generated Rust regression tests that didn't compile at all: every
  `Capability::*` call was missing the required `platform: &dyn Platform`
  first arg, several calls had wrong return-tuple destructuring, Rights/
  Attributes were bare undefined identifiers, `MonitorAPI` bits were
  double-wrapped, `Command::Switch`/`Interrupt` used a disconnected
  throwaway `SwitchManager::new(4)` instead of the real engine API, and
  `cmd_init`'s hardcoded `"r0"` root-memory name didn't match the codegen's
  derived key. Rewrote codegen for every `Command` variant against
  `rust_backend.rs`/`domain_api.rs` as reference. Also fixed
  `AcceptCapability` silently dropping its optional `at <gpa>` override.
  Validated: all 17 tutorial scripts' generated tests compile and pass
  under `capa-engine/tests/unit/`; capa-cli's own 15 runtime tests still
  pass. Committed as `cf604b45e`.

  Confirmed along the way (no changes needed): `capa-cli`'s live
  `CliPlatform` already owns and correctly uses the engine's real
  `SwitchManager` (not a duplicate) for both switch and interrupt
  delivery — this was already done in the earlier P3 capa-cli cutover.
  Simulated core count is hardcoded to `4` in `capa-cli/src/main.rs:66`
  but every layer below it (`CliPlatform`, `RustBackend`, `Domain::new_root`)
  is already parametrized, so raising it later is a one-line change plus
  optionally exposing a CLI flag.

  **Next**: P8 — code-style review (`&CapabilityRef<T>` non-idiomatic
  reference-to-Copy-type convention; whether `acquire_shared_lock(&self)
  -> Result<Box<dyn OpLockGuard>>` needs the `Box<dyn _>` or could avoid
  the allocation/dynamic dispatch). Then the merge-gate pass over all
  tutorials. Order agreed with user; do not start without discussing first
  (standing process rule — do not commit or start new work without
  explicit go-ahead).

- **2026-07-22 — deterministic cross-core revoke C3 (IN PROGRESS).**
  Goal: revoke a child that is continuously running on core 0 from dom0
  core 1, then audit that all per-domain/per-VP state is reclaimed.

  Root cause found and fixed in the test setup: CHV parsed
  `policies.exits` from `--themis-config` but `policy_walker.rs` emitted
  only MSR and CPUID policy operations. The child therefore silently kept
  the engine default `exits.default.trap=true` and was `Available` at
  revoke time. CHV now emits `DEFAULT_EXIT_TRAP` and per-reason exit policy
  operations before sealing. The revoke harness no longer waits for serial
  heartbeats because serial PIO is intentionally local under `trap=false`.

  Last known trace before the fix:
  ```
  [REVOKE-XCORE] child dom_id=1 #vps=1
  [REVOKE-XCORE]   vp=0 state=Available
  ```

  Next step: rerun the pinned revoke test. Expected host trace starts with
  `vp=0 state=Running core=0 caller=Some`, followed by
  `push_core_switch`, `apply_switch`, and `swap complete`.

  First true cross-core run exposed the lifecycle corruption behind the
  second-run hang: `Platform::on_domain_revoked()` was writing the remote
  core's Tier-1 `domain_id=dom0` before that core drained its queued switch.
  Hardware still had the child VMCS loaded, so the swap was misidentified
  as dom0→dom0 and the deactivated child VMCS was returned into dom0's
  occupied `VcpuSlot`. Fixed by making `on_domain_revoked()` Tier-3 routing
  cleanup only; only the owning core now updates Tier 1 during the actual
  VMCS swap. A same-source/destination revoke-swap assertion prevents this
  class of corruption from becoming a delayed hang again.

  The ownership protocol has now been refactored end-to-end:
  - Every queued revoke switch carries the exact source domain/VP and target
    domain/VP. The owner core verifies the source before touching hardware.
  - The engine includes every switch core in the IPI/barrier set and rejects
    duplicate orders for one core.
  - Target metadata is committed only after the VMCS/VcpuSlot swap succeeds;
    `on_domain_revoked()` is residual routing cleanup after barrier 0.
  - Revoke preflight rejects a running doomed VP with no caller before
    detaching or marking any subtree node.
  - The unused parallel `CoreUpdate::Revoke` path was removed.

  Engine tests, full loom concurrency tests, capa-cli release build, capavisor
  release build, and `cargo build-bins` all pass. The pinned no-exit Eunomia
  revoke harness also passed twice consecutively in one Themis boot. Both
  owner-core transitions named the actual running child as the source:
  ```
  apply_switch core=0 src=(dom=1,vp=0) dst=(dom=0,vp=0)
  swap complete core=0
  apply_switch core=0 src=(dom=2,vp=0) dst=(dom=0,vp=0)
  swap complete core=0
  ```
  There was no second-run hang and no `VcpuSlot::put` panic, so the explicit
  VP/VMCS ownership transition is fixed. However, roughly 60 seconds later
  dom0 reported an RCU stall on CPU 0 in `pv_native_safe_halt`; timer progress
  on the revoke target core had stopped.

  Two hypotheses remain and must be distinguished before changing design:
  1. the INIT IPI used for cross-core wakeup perturbs processor/LAPIC state;
  2. the emulated TSC deadline is incorrectly stored per physical core, so a
     dom0 deadline can expire while the child is active and be injected into
     the child before dom0 resumes.

  A temporary ownership diagnostic now records which domain/VP armed each
  per-core deadline and prints `[TIMER-OWNER-MISMATCH]` only if that deadline
  fires on a different active domain/VP. The first rerun produced no marker,
  then domain 2 hung before revoke and dom0 reported another CPU0 RCU stall.

  The next diagnostic recorded:
  ```
  [EXTINT-DROPPED] core=0 active=(dom=1,vp=0) vector=0xec
  ```
  Vector `0xec` is dom0's local timer. The generic monitor was consulting
  `ExitPolicy` for an external-interrupt VM exit and returning immediately
  when `trap=false`, bypassing `InterruptPolicy` and lazy-unwind entirely.
  This branch originated in `5f5f9d215` from a dom0-only assumption that
  `trap=false` implied external-interrupt exiting was disabled.

  The interrupt-policy audit also found that `c2820b5ec` integrated
  `SwitchManager::route_interrupt()` but discarded its `reported_to` result.
  Consequently the current VP unwind stores the vector in every intermediate
  `Suspended` VP, so `NotReport` is not transparent, while the intended
  Report/NotReport distinction is absent from the resume state machine.

  Required fix:
  - External interrupts are governed only by `InterruptPolicy`.
  - Route selection and VP-chain mutation become one atomic engine operation;
    the current route-then-deliver split can observe different policy/chain
    states.
  - Lazy-unwind records which suspended call frames must observe the event.
  - On descent, the engine restores `NotReport` frames directly to `Locked`
    without executing them, then performs one switch to the first `Report`
    frame or directly to the interrupted leaf if no report is required.
  - The interrupted leaf remains reserved until that atomic descent; it must
    never become globally `Available` while the handler is still running.
  - Remove the unused parallel `resume_after_interrupt()` list API once the
    VP state machine is the single authority.

  **Engine/capavisor correction implemented (uncommitted, ready for review):**
  - Removed the external-interrupt `ExitPolicy` gate. Interrupt routing now
    always follows `InterruptPolicy`.
  - Combined handler selection and VP-chain unwind in
    `deliver_interrupt_vp()` under one engine operation.
  - `Suspended` and `Interrupted` states retain exact caller ownership and
    per-frame `Report` disposition.
  - Descent skips `NotReport` frames atomically, stopping at the first
    `Report` frame or restoring the original leaf directly.
  - The interrupted leaf remains reserved; unrelated VPs cannot claim it.
  - Capavisor swaps to the engine-selected actual destination VP, publishes
    an interrupt intercept message, fails closed on routing errors, and queues
    blocked injection in PIR with interrupt-window exiting.
  - Removed the obsolete `resume_after_interrupt()` list API.
  - Restored the explicit source→target cross-core revoke ownership changes
    that were lost during the formatter incident.

  Validation: full engine suite passes; 32 interrupt/switch unit tests pass;
  all 5 VP loom tests pass; capa-cli release build and capavisor release check
  pass. No formatter was run. Nested A→B→C Eunomia coverage remains a separate
  integration task.

  Integration acceptance requires a reusable three-domain Eunomia topology
  A→B→C, not only dom0→child. The preferred harness is a small bare-metal
  nested-monitor workload for B that uses the Themis hypercall ABI to create,
  seal, and switch to a spinning C. One launcher should run a policy matrix:
  A=`Deliver`, B=`Report` must expose a synthetic SWITCH return; B=`NotReport`
  must resume C transparently. This topology should become reusable for
  nested switch, interrupt, and revocation tests.

  Remaining cleanup is separate from the ownership fix:
  `REVOKE_MEM parent=14 sub=24 failed (-2)` is the known redundant per-memory
  revoke attempted after whole-domain revocation.

  Files modified for this step:
  - `cloud-hypervisor/hypervisor/src/themis/policy_walker.rs` — emit VMEXIT policy operations and test default/override encoding.
  - `cloud-hypervisor/hypervisor/src/themis/vm_state.rs` — push VMEXIT policy before partition seal.
  - `eunomia/policies/revoke/no-exit.json` — select local handling for all VMEXITs.
  - `themis/scripts/run-eunomia.sh` — auto-select no-exit policy and use a fixed boot window rather than invisible serial markers.
  - `themis/capavisor/src/hypercall/capa.rs` — temporary pre-revoke VP-state diagnostic.
  - `themis/capavisor/src/platform/mod.rs` — preserve remote Tier-1 binding until its owning core performs the revoke switch.
  - `themis/capavisor/src/platform/maps.rs` — retain one explicit source→target switch command; remove the unused revoke variant.
  - `capa-engine/src/capability.rs` — emit exact source→target orders and preflight invalid running VPs before mutation.
  - `capa-engine/src/domain_api.rs` — make revoke-return transition engine state only; owner metadata commits after hardware.
  - `capa-engine/src/platform.rs` — include switch cores in barriers and perform residual revoke cleanup after barrier 0.
  - `capa-engine/src/update.rs` — carry source domain/VP in `CoreSwitch`.
  - `capa-engine/tests/common/mod.rs` — record complete switch orders.
  - `capa-engine/tests/concurrency/platform.rs` — assert exact transitions, ordering, and mutation-free invalid-caller rejection.

- **2026-07-20 — MSR interposition end-to-end (wrmsr suite 4/4 PASS)** ✅ DONE.
  Completed Phase 2 (hardware VMCS MSR entry-load/exit-store lists), Emulate
  WRMSR store-to-policy fallback, and Option B (CHV per-vCPU shadow for
  Trap-forwarded RDMSR/WRMSR).  Trap semantic finalized as *"parent owns
  the guest-visible value"* — physical MSR untouched; workload assertions
  updated to match (`rd1=Ok(0), wr=Ok(()), rd2=Ok(magic)`).

  Commits: `add32b6fd` (capavisor), `077d2d6de` (kernel bump), `c91e1e104`
  (workload + CHV bump).  CHV internal commits: `fd7e4161c`, `452708120`.

- **2026-07-17 — capa-cli migration to platform-first domain API** ✅ DONE. Fixed `capa-cli/src/rust_backend.rs` to match the refactored `capa-engine` domain-mediated API (platform as first arg, tuple returns). `cd capa-cli && cargo build --release` now succeeds with 0 errors.

  Files modified this session:
  - `capa-cli/src/rust_backend.rs` — migrated all `Capability::*` call sites to platform-first signature; removed 8 double-lock `execute()` wrappers (carve, send_at, accept_at, revoke, revoke_domain, register_comm, switch_forward, switch_return); added `platform` arg and tuple destructuring to carve/alias/create/seal/revoke/revoke_domain/get_chan/get_chan_self/send_channel/accept_channel/reject_channel/register_comm/switch/deliver_interrupt_vp/set_policy/get_policy/set_register/get_register; removed `execute` from imports.

- **2026-07-17 — capa-engine domain API test migration** ✅ DONE. Updated default-feature tests for the platform-first `Capability::<Domain>` API and tuple-return signatures; `cd capa-engine && cargo test --no-run` now succeeds.

  Files modified this session:
  - `capa-engine/tests/concurrency/platform.rs` — passed `TestPlatform` into domain API calls under default features.
  - `capa-engine/tests/integration/api.rs` — migrated create/seal/carve/alias/send/revoke/revoke_domain calls and tuple destructuring.
  - `capa-engine/tests/integration/comm.rs` — migrated register_comm/carve/alias/create/seal/revoke/send calls and tuple destructuring.
  - `capa-engine/tests/integration/end_to_end.rs` — migrated create/seal/carve/alias/switch calls and tuple destructuring.
  - `capa-engine/tests/integration/interrupt.rs` — migrated create/seal call sites to the platform-first API.
  - `capa-engine/tests/integration/meta.rs` — migrated send/carve/alias/accept/revoke call sites and tuple destructuring.
  - `capa-engine/tests/integration/overlap.rs` — migrated carve/alias call sites and 3-tuple destructuring.
  - `capa-engine/tests/integration/revoke.rs` — migrated create/send/seal/carve/alias/revoke call sites and tuple destructuring.
  - `capa-engine/tests/integration/send_bugs.rs` — migrated create/seal/carve/send call sites.
  - `capa-engine/tests/integration/send_pending.rs` — finished remaining platform-first send/accept/reject/carve/revoke calls.
  - `capa-engine/tests/integration/translation.rs` — migrated translation tests to the platform-first domain API and updated tuple destructuring.
  - `capa-engine/tests/integration/vital_cascade.rs` — migrated create/seal/carve/send/revoke call sites.
  - `capa-engine/tests/integration/vital_revoke.rs` — migrated create/carve/alias/send/seal/revoke call sites.
  - `capa-engine/tests/unit/attest.rs` — added shared test platform usage for create/seal call sites.
  - `capa-engine/tests/unit/channel.rs` — migrated get_chan/attest/send_channel/accept_channel/switch and related tuple destructuring.
  - `capa-engine/tests/unit/domain.rs` — migrated create/seal/revoke_domain/set_policy/get_policy call sites.
  - `capa-engine/tests/unit/set_get.rs` — migrated helper/test set_policy/get_policy/set_register/get_register usage.
  - `capa-engine/tests/unit/switch.rs` — migrated switch/deliver_interrupt_vp call order and helper create/seal usage.

---

## RESUME NEXT: port + build dom1 (CoCo guest kernel) on this machine (2026-06-23)

Status on this machine: eunomia + attestation work. dom1 **root disk** and
**firmware** auto-fetch, but the **CoCo guest kernel is NOT built yet**:
`../linux` fork absent, `themis/guest/kernel/bzImage` absent, `/nested` empty in
`bins.img`. dom1 boots from `/opt/bins/nested/bzImage` (built-in virtio/ext4/9p,
no initramfs) + `/opt/bins/dom1/dom1.raw`.

Steps to run when resuming:

1. **Clone the kernel fork** next to the repo (default `LINUX_DIR=../linux`):
   ```bash
   cd ~/Documents/Programs/MSR        # parent of capability-v5
   git clone https://github.com/aghosn/linux.git
   cd linux && git checkout v6.19.14-themis
   ```
2. **Install kernel build deps** (host is jammy 22.04; gcc-11/12 builds 6.19 fine):
   ```bash
   sudo apt install -y build-essential flex bison libssl-dev libelf-dev bc dwarves
   ```
3. **Build the bzImage** from repo root → installs to `themis/guest/kernel/bzImage`:
   ```bash
   cd ~/Documents/Programs/MSR/capability-v5
   cargo build-kernel                 # KERNEL_PROFILE=minimal (default)
   # add modules if dom1 needs them:  TARGETS=all cargo build-kernel
   ```
4. **Pack into bins.img** — `update-bins.sh` auto-detects `guest/kernel/bzImage`
   and copies it to `/nested/bzImage`:
   ```bash
   cargo build-bins-docker            # repacks bins.img (includes nested kernel)
   # or just: NESTED_KERNEL=themis/guest/kernel/bzImage bash themis/scripts/update-bins.sh
   ```
5. **Reboot the stack** (`cargo themis`), then **inside dom0**:
   ```bash
   sudo /opt/bins/cloud-hypervisor/run-dom1.sh           # --themis auto if /dev/thhv
   ```
   Auto-picks `/opt/bins/nested/bzImage` + `dom1.raw`. Use `--kvm` to isolate
   kernel vs Themis if it panics.

Refs: `themis/scripts/build-kernel.sh`, `themis/scripts/README.md:183-251`,
`docs/building.md:144`. Fork branch `v6.19.14-themis` has `CONFIG_THEMIS_COCO=y`.
This is also where x2APIC fast-path boot validation gets exercised (per-child,
when dom1 boots — watch capavisor `CPU features:` + `FEATURE_X2APIC_VIRT`, no
`VIRTUALIZE_X2APIC_MODE`/`VID not supported` WARN).

---

## x2APIC fast-path — bare-metal prerequisites CONFIRMED (2026-06-23)

Context: commit `24c29d37e` added the child x2APIC fast path (children boot in
x2APIC mode so self-IPI `WRMSR(0x83F)` is hardware-handled under VID, zero
exits). It was **dormant on the WSL2/Hyper-V dev box** because nested L0 there
does not expose the APICv VMX bits. Gating lives in
`capavisor/src/arch/x86_64/vmcs/controls.rs:109-112` (`x2apic_virt_hw` =
`IA32_VMX_PROCBASED_CTLS2` allowed-1 bits **4** `VIRT_X2APIC_MODE`, **8**
`APIC_REGISTER_VIRT`, **9** `VID`) and `crates/vmx/src/features.rs`
(`has_x2apic_virt()`); `vmexit/cpuid.rs:83` advertises `FEATURE_X2APIC_VIRT`
to dom0/CHV only when all three are present.

On **this bare-metal machine** (asmodai), all prerequisites are GREEN:
* No `hypervisor` CPUID flag (true bare metal); host has `vmx` + `x2apic`.
* `IA32_VMX_PROCBASED_CTLS2` (0x48B) allowed-1 = `0x0f5d7fff` → bits 4, 8, 9
  (and 0) all **SET**.
* KVM: `kvm_intel` `nested=Y`, `enable_apicv=Y`, `ept=Y` — so KVM should pass
  APICv through to capavisor (L1) under `cargo themis` (`-enable-kvm -cpu host`).

Probe script saved at `/tmp/check-x2apic-bits.sh` (reads + decodes the cap MSR;
exit 0 = fast path will activate).

**Next step (deferred):** boot `cd themis && cargo themis 2>&1 | tee /tmp/out.txt`
and confirm in the capavisor serial: (a) `CPU features:` shows x2APIC virt,
(b) NO `[WARN] VIRTUALIZE_X2APIC_MODE not supported` / `VID not supported`
(controls.rs:138-148), (c) `FEATURE_X2APIC_VIRT` advertised. Fast path is
per-**child**, so it's exercised when **dom1** boots.

---

## Build-env fix (2026-06-23) — `cargo build-bins-docker` resilience

After syncing missing commits, `build-bins-docker` failed in four independent
spots; all fixed (uncommitted). Modified files:

* **`themis/scripts/build-bins-docker.sh`** — a host-side header **prefetch**
  was tried and **reverted**. The container is `ubuntu:24.04` (noble), the same
  distro as dom0, so it is the *authoritative* source for the noble headers that
  must match dom0's noble kernel. Prefetching on the host (asmodai = jammy 22.04)
  pulled **jammy-HWE** headers (`~22.04.1`) → distro mismatch. The fix was simply
  to rebuild the `themis-build:latest` image so its apt index is fresh enough to
  see `6.8.0-124`; the container then fetches **noble** headers itself.
* **`themis/scripts/fetch-kheaders.sh`** — now also fetches the **common**
  headers package, discovered from the `-generic` package's `Depends`
  (noble GA: `linux-headers-<abi>`). Both are extracted side-by-side under
  `usr/src/` so the relative symlinks (e.g. `scripts/Makefile.ubsan`) resolve;
  added a check that verifies this. Confirmed pulling noble `6.8.0-124.124` from
  `noble-updates/main` (not jammy).
* **`Dockerfile.build`** — added `gcc-12` (harmless; noble `6.8.0-124` is
  actually built with **gcc-13**, which the image already ships, so the compiler
  now matches the kernel — no vermagic/ABI issue).
* **`themis/scripts/update-bins.sh`** — auto `e2fsck -fp` on `guest/bins.img`
  before the fuse2fs mount; interrupted builds left it unclean and fuse2fs
  refused to mount it.

Result: full `cargo build-bins-docker` is green — `thhv.ko` (2.1 MB, vermagic
`6.8.0-124-generic`, noble) builds and `guest/bins.img` repacks. Verified the
`.ko` packed into `themis/guest/bins.img` is byte-identical to the build output.

### thhv/dom0 kernel reconciliation (2026-06-23)
dom0 ran noble `6.8.0-107-generic`; thhv built/pinned at `6.8.0-124-generic` →
`insmod` failed (modversions CRC mismatch, no `/dev/thhv`). Chose **option B**:
upgraded dom0. Installed `linux-image/linux-modules-extra-6.8.0-124-generic` in
dom0, `update-grub` (124 = top entry, `GRUB_DEFAULT=0`). Pin stays `6.8.0-124`.
**Next:** reboot the stack so dom0 boots 124, then
`sudo insmod /opt/bins/thhv/thhv.ko`, confirm `/dev/thhv`, run eunomia.

---

## Current State (2026-06-04)

### Just-completed CHV-themis cleanup arc (committed)

The cloud-hypervisor Themis backend is fully refactored and deduped:

* **File split** (Phases 1–8): `cloud-hypervisor/hypervisor/src/themis/` is now
  10 focused files (`mod.rs` 52 LOC façade, `vcpu.rs` 1362, `vm_impl.rs` 509,
  `hypervisor_impl.rs` 175, `vm_state.rs` 375, `consts.rs` 145, `abi.rs` 278,
  `helpers.rs` 117, `mmap.rs` 53, `emulator.rs` 218).
* **Dedup vs `themis-abi`**: VpRegister, REALMODE access-rights,
  THEMIC_MSG_*, `vmx_exit_reasons` (SDM basic exit reasons), and synthetic
  exits all flow from `themis-abi` — the CHV backend re-exports rather than
  redefines.
* **Inline magic named**: LAPIC_MMIO_{BASE,SIZE,END,OFFSET_MASK},
  CPUID_LEAF_TSC_FREQ/PROC_FREQ, THEMIS_MAX_VCPUS.
* **TSC kHz from CPUID**: `handle_wrmsr_exit` no longer hardcodes 3 GHz; reads
  the same OnceLock-cached CPUID-derived value as `Vcpu::tsc_khz()` (with a
  warned fallback only if both leaves return nothing).  Also fixed a
  pre-existing rounding bug (integer-divide through GHz → exact u128 ns math).
* Build with `themis,kvm,ivshmem`: 0 warnings, 0 errors.

Latest committed: CHV `7891cba82`, outer `d6fac441b`.

### In progress — thhv refactor + magic-number dedup (UNCOMMITTED)

Mirrors the CHV cleanup on the kernel-module side.  See
`~/.copilot/session-state/2d26c842-6034-4eb0-8eed-042885dd1a1a/plan.md` for
the full inventory; summary:

* `thhv_part.c` (1308 LOC) split into `thhv_part.c` (733, lifecycle + ioctl
  dispatch) + `thhv_part_mem.c` (597, rb-tree + SET_GUEST_MEMORY +
  send_meta_pages).
* `inc/thhv.h` (1418 LOC) split: kernel-only block extracted to private
  `src/thhv_internal.h` (375); `inc/thhv.h` is now 1071 LOC of pure UAPI.
  All 10 `src/*.c` files now `#include "thhv_internal.h"`.
* Magic numbers named: `THHV_MAX_VPS_PER_DOMAIN` (256), `THHV_MAX_GSI` (255),
  `THHV_PA_MAP_MAX_ENTRIES` (4096).  The 256 vCPU cap is now a single
  source-of-truth via `themis_abi::MAX_VPS_PER_DOMAIN`; CHV `THEMIS_MAX_VCPUS`
  re-exports from there, and `THHV_MAX_VPS_PER_DOMAIN` carries a comment
  cross-link.
* All three components build clean (`thhv.ko`, CHV themis+kvm+ivshmem,
  capavisor).  **No boot test yet** — that's tomorrow's first step before
  committing in 3 logical pieces.

### Next session resume order
1. Deploy + boot-test the uncommitted thhv work
   (`cd themis && cargo themis 2>&1 | tee /tmp/out.txt`).
2. Commit in 3 logical commits (split, header split, magic dedup) — see
   session plan.md for exact file lists.
3. Investigate the pre-existing `dom1-not-reaching-login` issue (deferred
   throughout the refactor so debug effort wasn't wasted on code about to
   be moved).

---

## Current State (2026-05-26)

### What works

- **Dom0**: boots to login on 4 CPUs. Ubuntu Noble 6.8.0-107-generic. Stable.
- **Dom1 Linux (1 CPU)**: full systemd boot under Themis (emergency.target on local
  QEMU due to missing fstab — known, not a regression).
- **Dom1 Linux (2 CPUs)**: full systemd boot to login prompt. Verified 2026-04-14.
- **Eunomia as dom1**: ✅ boots under full Themis stack (capavisor + dom0 + CHV).
  All 33/33 tests pass (incl. timer via TSC-deadline, CPUID). 7 workloads.
  `cargo build-bins` now rebuilds Eunomia workloads before packaging.
- **ivshmem doorbell pipeline**: ✅ **end-to-end working (2026-05-26)**. CHV
  ivshmem multi-device, CPUID discovery, deferred IOEVENTFD (with fd-clone
  fix), shmem ALIAS mapping, RING_DOORBELL VMCALL → synthetic exit →
  DomainComm notify → thhv RX drain → CHV listener. All 5 eunomia
  doorbell rings delivered, clean ACPI shutdown.
- **Platform modularization**: complete. Opaque ArchDomainState/ArchPlatformState,
  aarch64 cross-check 0 errors. Generic monitor loop with SemanticExit dispatch.
- **AArch64 M1–M5c**: boot → memory → EL2 → GICv3 → guest → PSCI → Linux initramfs.
  M6 partial (full Ubuntu boot blocked by QEMU TCG overhead, needs real ARM HW).
- **Capability engine**: MAP_SELF implemented (refcounted projections, 33 tests).
  83 Lean theorems, 0 sorry. lean-exec 21/21 differential tests passing.
  GPA-aware view_diff with lazy dirty-flag caching.
- **TPM attested boot**: Ed25519 + SHA-256 + TPM PCR extend. CRB/TIS auto-select.
- **CoCo guest kernel**: CC_VENDOR_THEMIS patch in `../linux`.  Minimal config
  (245 modules), virtio/ext4/9p built-in.
- **MAP_SELF hypercall**: wired across themis-abi (0x1f), capavisor handler, thhv.
- **COMM-as-SEND + DomainComm**: ✅ COMM pages provisioned via CARVE+SEND (commit
  `1d9867d8d`). CHV slot splitting for confidential memory (commit `235ed4c81`).
  `domcomm_discover` and `attest_dequeue` Eunomia tests pass.
- **Compound allocation batching** (uncommitted): thhv uses `alloc_pages(order)` for
  META and COMM pages. Contiguous runs merged into single CARVE+SEND. Reduces
  attestation cap count from ~128 to ~24.
- **CPUID/MSR interposition policy**: ✅ fully policy-driven. All CPUID leaves
  (including hypervisor range) go through PolicyDriven path. No ArchHandled special
  case. CHV pushes Native/Emulate overrides for dom1. CoCo leaf (0x40000100)
  returns dynamic VTOM bit = MAXPHYADDR-1.
  `cargo diff-test` (from capa-cli/) runs automated Rust-vs-Lean differential
  testing on all 16 tutorials.
- **Dom1 CoCo detection**: ✅ kernel detects CC_VENDOR_THEMIS, reads VTOM bit 38.
- **MMIO VTOM stripping**: ✅ IO-APIC reads correctly (`version 17, GSI 0-23`)
  after stripping VTOM bit in CHV's handle_mmio_exit and emulator translate_gva.
- **VTOM EBDA double-map**: ✅ CHV double-maps ACPI/EBDA region at VTOM-offset GPA
  so CoCo kernel can access firmware tables with VTOM bit set.
- **GPA-native view computation**: ✅ ViewRegion carries both GPA (`access.start`)
  and HPA (`physical_start`). `ensure_view_fresh()` translates HPA→GPA via
  address_map entries (identity fallback when uncovered). `view_diff` produces
  {GPA, HPA} ChangeRights directly. Same-HPA-at-two-GPAs (VTOM double-map)
  naturally produces two view regions. Tutorial 17 validates. Removed
  `snapshot_view`, `translate_view_to_gpa`, `fixup_domain_addresses` from
  carve/send/accept (kept in revoke for tree-walk updates).
- **Lazy view caching**: ✅ `Domain.view_dirty` flag — mutations mark dirty,
  `ensure_view_fresh()` recomputes only when read. Eliminates redundant
  double-recomputation. No loom gate — full correctness under loom.
- **Cross-domain revoke cleanup**: ✅ `remove_memory_capability_by_ref()` eagerly
  removes capability from child domain's table using `Weak::ptr_eq` (can't use
  prune since Arc is still alive on revoke_child's stack).

### What doesn't work / known issues

- **Dom1 virtio-blk rootfs failure**: kernel boots fully (ACPI, PCI, 2 CPUs) but
  panics at VFS mount — `/dev/vda1` shows as `unknown-block(0,0)` error -6.
  Virtio-blk not registering; likely transport negotiation or IOMMU/DMA issue.
  **Must fix before CoCo e2e.**
- **Unguarded interrupt injection**: 2 fallback paths without RFLAGS.IF check.
- **Posted interrupts**: hardware PI disabled (software PIR drain instead).
- **Dom1 on real hardware**: not yet tested.
- **KVM nested dom1**: CHV FailEntry under nested QEMU — only Themis backend works.
- **CoCo share-back**: MAP_SELF wired, channels wired (GET/SEND/ACCEPT).
  Not yet tested end-to-end. Need Eunomia workload first.

### Recent commits

- `985c1bf83` — **Slim intercept message: ExitPolicy.read_set enforcement**:
  InterceptMessage 120B→64B (exit metadata only), thhv assembles full msg
  from slim + COMM page regs. Registers gated by read_set. Dom1 boots OK.
- `9c13207af` — **Structured attestation API and CoCo workload fixes**:
  `build_structured_attestation()` in engine as single source of truth,
  `to_bytes()` binary serialization, capavisor `do_attest_self` rewritten
  to use engine API, eunomia CoCo tests all 4 pass
- `1d9867d8d` — **COMM-as-SEND redesign**: DomainComm pages provisioned via
  CARVE+SEND, domcomm finalization on first hypercall, CHV confidential cleanup
- `235ed4c81` — **CHV: confidential memory slot splitting** (cloud-hypervisor submodule)
- `HEAD` — **CHV: gate CoCo features on confidential mode**
  (vtom_bit=0 when !confidential, EBDA/CoCo-CPUID/VTOM-stripping gated)
- `8d3dd56f` — **CHV: confidential mode — CARVE guest RAM instead of ALIAS**
  (`--platform confidential=on`, MMIO classification, run-dom1.sh flag)
- `7ec460f` — **Wire channel hypercalls: GET_CHAN, SEND_CHAN, ACCEPT_CHAN**
  (capavisor handlers, thhv wrappers, auto-provision parent-back-channel)
- `e962a89` — **capa-engine: GPA-native view computation redesign**
  (ViewRegion carries {GPA, HPA}, ensure_view_fresh translates via address_map,
  removed snapshot_view/translate_view_to_gpa, cleaned fixup from carve/send/accept)

---

---

### ~~BUG-16: vtom_double_map~~ ✅ Fixed

Fixed in commit `9c13207af`. Root causes: (1) attestation reported HPA in both
GPA and HPA fields — fixed by using `mapped_gpas` via structured attestation API;
(2) unnecessary `map_4k` call on identity-mapped addresses — removed;
(3) `send_chan` vs `send` confusion in bounce_buffer_send — corrected.

---

## Tech Debt (must address)

- **(RESOLVED 2026-07-20)** CHV forwarded-WRMSR/RDMSR trap handler:
  implemented as a per-vCPU shadow `HashMap<u32, u64>` in
  `cloud-hypervisor/hypervisor/src/themis/vcpu.rs` (commits
  `fd7e4161c`, `452708120`).  Trap semantic finalised as
  *"parent owns the guest-visible value"*: WRMSR records in the
  shadow, RDMSR returns the shadowed value (default 0) via
  RAX/RDX through the dirty-COMM path, the physical MSR is never
  touched.  Wrmsr policy suite passes 4/4.  Future work:
  optional #GP-on-access policy action if a stricter contract is
  ever wanted (would require a new capavisor exception-injection
  primitive; not currently needed).

## Tech Debt (previously listed)

- **Coco isolation test — host access attempt after CARVE+SEND**:
  add a eunomia test (or extend `eunomia/workloads/coco/`) where dom0
  deliberately tries to read/write the guest RAM after CARVE+SEND has
  transferred ownership to the confidential child.  The original mmap
  pointers in CHV/dom0 are still valid VAs, but the underlying physical
  pages must no longer be reachable from dom0's EPT (that's the whole
  point of CARVE — see `docs/architecture/confidential-vm.md`).
  Expected outcome: dom0 access faults / EPT violation, child memory
  contents remain confidential.  Without this test we have no automated
  proof that CARVE actually revokes dom0 access end-to-end (capa-engine
  `send_region` → capavisor `apply_update` → EPT unmap → IOMMU mirror
  update).  Should also verify: (a) reads return zero/fault, not stale
  data; (b) writes don't leak into child; (c) IOMMU side is updated so
  a dom0-controlled device can't DMA into the carved region either.

- **APIC virtualization regression to design intent (child VMs)**:
  the intended design (`docs/architecture/interrupt-virtualization.md`
  §Child Domains) is `APIC_REGISTER_VIRT=1` + `VID=1`, leaving the
  hardware to handle most LAPIC accesses and shipping only ICR-IPI
  policy to CHV.  Commit `d21dc8241` ("fix: child APIC virtualization
  for multi-vCPU dom1", 2026-04-03) disabled both bits as a workaround
  because *"CHV doesn't yet provide VAPIC page state synchronisation"*
  and added a child-side software LAPIC emulator in capavisor.  This
  emulator (`arch/x86_64/vmexit.rs::handle_apic_access_exit` plus
  `decode_apic_write_value`) requires capavisor to decode the guest's
  MOV instruction at RIP every time the child touches the LAPIC, plus
  maintain a full software VAPIC mirror (read/write/EOI ISR walk).
  Decoding guest instructions in capavisor violates the design
  principle that decoding belongs in CHV (host-side `iced-x86`).

  **What needs to be done**, in order:
    1. Re-enable `APIC_REGISTER_VIRT` (sec bit 8) and `VID` (sec bit 9)
       for child VMs in `arch/x86_64/vmcs.rs`.
    2. Implement VAPIC-page state synchronisation on the
       capavisor↔CHV boundary — initial state at child VP create, and
       any state CHV needs at SWITCH-in / SWITCH-out.  The page lives
       in HHDM on the capavisor side and is already mapped into dom0
       via thhv, so this is cheap.
    3. For ICR writes that still need exit-based policy: ship the
       raw instruction bytes + access offset to CHV (same path as the
       EPT-MMIO forward today), let CHV decode using iced-x86 and
       forward the IPI request back through the normal hypercall ABI.
    4. Delete from capavisor: `handle_apic_access_exit`,
       `decode_apic_write_value`, and the `gpr_by_index` CR-decode
       helper in `arch/x86_64/vmexit.rs`; the page-walk helpers
       (`ept_gpa_to_hpa`, `guest_gva_to_gpa`) and instruction-byte
       fetch in `hypercall.rs` *stay* — they support the
       EPT-violation forward path, which is honest forwarding (CHV
       does the decode).
    5. Verify dom1 multi-vCPU boot (the workload that motivated
       `d21dc8241` in the first place) still works after the change.

  **Security and performance considerations** (raised when this debt
  was identified, 2026-05-28):
    - *Security*: CHV already maps the guest's physical memory via
      thhv (the EPT-MMIO forward path reads `instruction_bytes` and
      ships them to CHV today), so giving CHV the few bytes needed to
      decode an ICR write is no new authority.
    - *Performance*: with bits 8 + 9 enabled, most LAPIC accesses
      (reads, EOI, TPR writes) take **no exit at all** instead of one
      capavisor round-trip per access.  Only ICR / unhandled-offset
      writes still exit, and those go to CHV — fewer L0↔L1
      ping-pongs than today, not more.

  Doc updated 2026-05-28: see warning callout in
  `docs/architecture/interrupt-virtualization.md` §Child Domains.

- **capavisor/src/hypercall.rs cleanup**: `forward_child_exit`, `do_switch`,
  and `forward_interrupt_to_handler` have grown into multi-hundred-line
  functions mixing capa-engine calls, COMM-page marshaling, I/O-qual decoding,
  VMCS swap, and ad-hoc debug instrumentation. Extract helpers (COMM-page
  marshal, IO exit-qual decode, VMCS swap) and rip out the DB-* trace
  scaffolding once the doorbell bug is fixed. Quality is not acceptable as-is.

- **Dom1 cross-core IPI delivery slowdown after VcpuSwap refactor**
  (Phase 4 of capavisor cleanup): after extracting `swap_active_vp` and
  unifying the three swap sites in `themis/capavisor/src/hypercall.rs`,
  dom1 boot reaches PCI BAR 0 enumeration and then progresses extremely
  slowly. Symptom seen via SSH into dom0, tail of `/tmp/chv-stdout.log`
  (guest printk) vs `/tmp/chv-stderr.log` (CHV diags):
    * Guest stdout frozen for many minutes mid-PCI-probe.
    * CHV stderr keeps spinning: `[LAPIC-IPI] vp=1 ... vector=0xfd ...
      dest_apic=0` (Linux RESCHEDULE_VECTOR), `[THEMIS-MSR] WRMSR
      msr=0x6e0` (TSC_DEADLINE) at same RIP repeatedly, many
      `[THEMIS-TIMER] delta_tsc=0` (deadlines already past).
    * CHV process at 99% CPU; counters keep incrementing (#11000 →
      #14800 over ~8 min) so it's slow, not deadlocked.
  Hypothesis: cross-core notification IPI / PIR-drain latency increased
  for resched IPI delivery to vp0 (the BSP doing PCI probe), so vp0
  doesn't wake from idle promptly and vp1 spins reprogramming the
  TSC-deadline. Smoke tests and Eunomia got FASTER; only dom1's
  long-running cross-core workload exposes this. Code review of the
  refactor diff shows: `pid_set_ndst` still called on every swap (3 sites
  → helper), `sync_irte_ndst` unchanged (still only in `do_switch`), PIR
  drain logic byte-identical, register dispatch identical. The only
  ordering change is that `swap_active_vp` does `take(dst)` BEFORE
  `VMCLEAR src` (vs OLD which did `VMCLEAR src` → `put(src)` →
  `take(dst)`); intuitively this should not affect IPI latency but is
  worth checking under instrumentation. Investigation plan: defer until
  the rest of the refactor (phases 5–10) is in, then add timing probes
  around `inject_via_pid`, the PIR drain block, and `swap_active_vp`
  step boundaries; compare against pre-refactor commit `f95148ece`.
  See also session checkpoint `011-designing-vcpuswap-helper-api`.

- **Cleanup / teardown invariants need real tests**: after the capavisor
  refactor (VcpuSwap helper, RIP invariant, etc.), we observed that
  re-running dom1 after Eunomia in the same boot causes unexpected CHV
  exits; a fresh reboot fixes it. This strongly suggests leftover state on
  domain destroy — candidates: IRTE entries not torn down, PID/PIR words
  retaining bits, shmem pages still mapped in dom0, thhv refcounts, child
  VcpuSlot not emptied, EPT pages not reclaimed. We need tests that
  exercise create→destroy→create cycles on the same boot for each domain
  type (smoke child, Eunomia, dom1 with CHV) and assert all per-domain
  resources are released. Without these, refactor regressions in the
  cleanup path will keep surfacing as flaky integration runs.

## Active Work Streams

### 1. Eunomia — minimal micro-kernel guest ✅ Phase A complete

Design docs: [`docs/architecture/eunomia.md`](docs/architecture/eunomia.md),
[`docs/architecture/eunomia-roadmap.md`](docs/architecture/eunomia-roadmap.md)

Eunomia is the test vehicle for core-gapping and CoCo before tackling Linux dom1
complexity.  ~1200 LOC, boots in <50ms, 6 workloads / 24 tests.

**Completed (E1–E7, Phase A)**:
- Boot (PVH 32→64, GDT/TSS, IDT, LAPIC timer, bump allocator, scheduler)
- HypervisorInterface trait (ThemisBackend VMCALL, StubBackend)
- Workload model (independent crates, `app_main` entry point)
- CHV PVH boot + ACPI shutdown exit path
- `cargo run-chv` alias, `run-eunomia.sh` for dom0
- pvh-info workload (validates hvm_start_info, memmap, RSDP)
- ✅ Timer: TSC-deadline mode, vector 0xEC (matches CHV's irqfd injection)
- ✅ All 24/24 tests pass under QEMU, CHV, and full Themis stack
- ✅ `cargo build-bins` rebuilds Eunomia workloads before packaging
- ✅ Clean serial output (CR+LF)

**Next**:
- [ ] Phase B: CoCo integration (shared.rs, MAP_SELF, CHANNEL_SEND workload)
- [ ] Phase C: Core-gapping workload (Forward policy, VMX preemption timer)

### 2. Core-gapping (design complete, implementation pending)

Design doc: [`docs/architecture/core-gapping.md`](docs/architecture/core-gapping.md)

Run child domain on dedicated core, events forwarded to dom0 on separate core
via shared pages + IPI.  Eliminates cache side channels and single-stepping.

**Design decisions (settled)**:
- `Forward { target_core, synchronous }` policy variant
- VMX preemption timer for local timer delivery (2 exits/tick, zero IPIs)
- Shared notification area = existing VpCommPage / meta page
- Policy-driven: core-gapping emerges from per-event Forward policies

**Implementation plan**:
- [ ] `InterruptPolicy::Forward` variant in capa-engine + tests
- [ ] Capavisor Forward handler (write event → IPI → poll response → VMRESUME)
- [ ] thhv.ko doorbell ISR on core 0
- [ ] VMX preemption timer for TSC-deadline → local timer delivery
- [ ] Core isolation in dom0 (cpu offline, watchdog disable, pin switch thread)
- [ ] Eunomia core-gap workload for end-to-end validation

### 3. Confidential VMs — CoCo (active)

Design doc: [`docs/architecture/confidential-vm.md`](docs/architecture/confidential-vm.md)

Dom1 memory private by default.  VTOM address-space split for explicit sharing.
No hardware encryption needed — EPT isolation provides equivalent protection.

**What already works**:
- CARVE+SEND removes pages from sender (dom0) EPT → dom1 memory is exclusive ✅
- MAP_SELF engine operation implemented (refcounted projections, 33 tests) ✅
- MAP_SELF hypercall wired: themis-abi (0x1f), capavisor handler, thhv ✅
- CC_VENDOR_THEMIS kernel patch exists in `../linux` (CPUID detection, cc_mkenc/cc_mkdec, VTOM) ✅
- CoCo guest kernel config (245 modules, virtio/ext4/9p built-in) ✅
- CPUID/MSR interposition policy framework in capa-engine ✅
  - Generic ProcFeature trait, ProcFeatureConfig<T>, Cpuid/Msr types
  - DomainPolicy extended with CpuidPolicy + MsrPolicy
  - Attestation includes CPUID/MSR policies
  - capa-cli: set-policy parsing for all interposition variants
  - lean-exec: DefaultAction/ProcFeatureConfig types, setPolicy/getPolicy support
  - Design doc: `docs/architecture/cpuid-policy.md`

**What needs implementation (interposition wiring)**: ✅ DONE
- [x] themis-abi: policy_kind constants for CPUID/MSR PolicyIdentifier variants
- [x] Capavisor: all CPUID leaves through PolicyDriven path
- [x] CHV: push Native/Emulate CPUID policy during domain setup
- [x] VTOM bit stripping in handle_mmio_exit + emulator translate_gva

**What needs implementation (ACPI firmware double-map)**:
- [x] CHV: double-map EBDA (0xA0000–0xFFFFF) at VTOM-offset GPA during
      initialization (committed CHV `bc2ccfe`)
- [x] Engine: GPA-aware view_diff handles same-HPA-at-two-GPAs correctly
      (committed `2b34aad`, `84bfaed`, `53d7b1e`)
- [ ] **NEXT**: Boot dom0 + CoCo dom1, verify kernel gets past ACPI table parsing

**What needs implementation (CoCo end-to-end)**:
- [x] CHV: `--platform confidential=on` flag. Guest RAM → CARVE, MMIO → ALIAS.
- [x] Capavisor: wire CHANNEL GET/SEND/ACCEPT hypercalls (0x1e, 0x20, 0x21)
- [x] thhv: auto-provision parent-back-channel at domain creation
- [x] CHV: gate VTOM/EBDA/CoCo-CPUID on confidential mode (vtom_bit=0 when off)
- [ ] Eunomia CoCo workload: domcomm+attest+vtom_double_map+bounce_send all pass ✅
      Structured attestation API in engine (single source of truth).
- [ ] thhv: receive pending capability from child (wait for event, ACCEPT_CHAN)
- [ ] CHV: receive shared regions back from dom1 (accept alias via channel)
- [ ] Dom1 kernel: early init share-back — create aliases of swiotlb pool,
      MAP_SELF at VTOM GPA, CHANNEL_SEND the other to dom0
- [ ] End-to-end: Linux dom1 boots with CC_VENDOR_THEMIS, swiotlb active,
      virtio works through shared bounce buffers

**Open questions**:
- Channel revocation semantics (does revoking endpoint cascade to sent caps?)
  → Resolved: yes, CDT cascades naturally (see design doc §9.8)
- [x] **Intercept message register leak fix** (commit `985c1bf83`):
  Slim `InterceptMessage` (120B → 64B, exit metadata only). thhv assembles
  full message from slim + COMM page registers. `ExitPolicy.read_set` is now
  the single gate for register exposure. Dom1 Linux boots successfully.
- [x] **ExitPolicy in attestation** (uncommitted):
  Added Exit Policy section to attestation reports (both Rust engine and Lean
  executable model). Shows default action + per-reason overrides with trap/read_set/
  write_set bitmaps. Lean `setPolicy`/`getPolicy` supports `exit-default-trap`.
  Differential test passes (15/17 tutorials — 2 pre-existing view failures).
  Rust CLI `parse_policy_id` supports `exit-default-trap`, `exit-reason-trap:<N>`,
  `exit-read:<reason>:<word>`, `exit-write:<reason>:<word>`.
- **Refine per-exit-reason policies for confidential mode**: The default
  ExitPolicy uses `RegBitmap::ALL` (read & write) for child domains.
  When booting dom1 Linux in confidential mode, the child (or its
  creation policy) should restrict read_set/write_set per exit reason
  so the parent can only see/modify the registers actually needed
  (e.g., IO exits → RAX only; CPUID → RAX/RCX; MSR → RCX/RAX/RDX).
  Infrastructure is fully wired (`set_policy` hypercall, `ExitReasonRegReadSet`,
  `ExitReasonRegWriteSet`); only needs concrete policy definitions.
- **Future optimization**: mmap COMM page to CHV userspace so CHV reads
  registers directly without ioctl round-trips. Would eliminate thhv
  register-assembly step entirely.

### 4. Contiguous physical memory for VMs (research needed)

**Problem**: VMs need physically contiguous memory regions for efficient EPT
mapping (2M/1G pages) and DMA.  Currently CHV allocates guest memory via
mmap which gives scattered 4K pages.  This matters for:
- EPT performance (fewer page table entries with large pages)
- IOMMU mapping (IOVA=GPA requires contiguous backing, axiom A4)
- Core-gapping shared notification area (meta pages)

**Questions to investigate**:
- [ ] Can CHV use hugetlbfs (2M/1G hugepages) for guest memory?
- [ ] Does the Themis CARVE+SEND flow preserve contiguity?
- [ ] Do we need a capavisor-side contiguous allocator for meta/notification pages?
- [ ] Impact on memory fragmentation under multiple domains

### 5. Inter-domain shared memory / ivshmem doorbell (active)

**Design doc**: [`docs/architecture/ivshmem-doorbell.md`](docs/architecture/ivshmem-doorbell.md)

**What works**:
- [x] CHV ivshmem multi-device support + capability-backed shmem (ALIAS)
- [x] Shmem registration folded into SET_GUEST_MEMORY (shmem_mode flag)
- [x] thhv REGISTER_DOORBELL VMCALL + DomainComm notification pipeline
- [x] CPUID leaf 0x40000004 for ivshmem device discovery (BAR0/BAR2 GPAs)
- [x] Eunomia ivshmem module: discover devices, read BAR0/BAR2
- [x] Deferred IOEVENTFD registration (after domain creation, before seal)
- [x] CHV doorbell eventfd listener thread
- [x] Doorbell registration reaches capavisor (doorbells matched correctly)
- [x] CHV squashed to 2 logical commits (CoCo gating + doorbell pipeline)
- [x] RING_DOORBELL VMCALL → synthetic exit → context switch to parent
- [x] **End-to-end doorbell pipeline working (2026-05-26)**:
      eunomia rings → capavisor exits to dom0 → thhv drains DomainComm RX →
      signals matching eventfd → CHV listener fires → all 5 rings (0x42..0x46)
      delivered. All 5 eunomia tests pass, clean ACPI shutdown.

**Root cause of the multi-week shutdown bug (fixed 2026-05-26)**:
In `cloud-hypervisor/hypervisor/src/themis/mod.rs::register_ioevent` deferred
path, `ThhvIoeventfd.fd` stored the *original* caller-supplied raw fd. The
caller (e.g. `add_ivshmem_device`) dropped its `EventFd` immediately on
return, closing that fd number. During the ~600 ms window before
`ensure_initialized()` flushed pending ioeventfds, the closed fd number got
reassigned to a clone of `exit_evt`. At flush time, `THHV_IOEVENTFD` ioctl
did `eventfd_ctx_fdget(stale_fd)` and registered the doorbell against
`exit_evt`'s `eventfd_ctx`. First doorbell ring → `eventfd_signal()` on
`exit_evt` → `EpollDispatch::Exit` → `Vm::shutdown` → vcpu killed.

**Fix**: store `fd_clone.as_raw_fd()` in `ioevent.fd` for the deferred path.
The clone is kept alive in `pending_ioeventfds._owner` until flush, so its
fd number remains valid. Diagnosed via strace timing (600 ms gap between
defer and flush) + thhv-side `ctx` pointer logging.

### 6. AArch64 backend (blocked on hardware)

Design doc: [`docs/architecture/arm-porting.md`](docs/architecture/arm-porting.md)

M1–M5c complete.  M6 (full Ubuntu boot) blocked by QEMU TCG Stage-2 overhead.
Needs real ARM hardware with KVM to validate.

### 7. Posted interrupts / hardware PI (deferred)

Requires `intel_iommu=on` and IOMMU intremap support.  Currently using software
PIR drain.  Not blocking any active work stream.

### ~~TODO: Platform modularization~~ ✅ Complete
### ~~TODO: Implement VITAL cascade in Lean~~ ✅ Complete
### ~~TODO: Full TPM attestation~~ ✅ Complete

---

## Reference

### Design documents

| Document | Path | Content |
|----------|------|---------|
| **Interrupt Virtualization** | `docs/architecture/interrupt-virtualization.md` | Single source of truth: goals, HW background, routing model, gap analysis, nested-virt scheduling, quantum-sched, Directvisor reference, 3 delivery bugs |
| **Attestation** | `docs/architecture/attestation.md` | Two-layer TPM + Ed25519 model |
| **Address Translation** | `docs/architecture/address-translation.md` | EPT/IOMMU design |
| **ARM Porting** | `docs/architecture/arm-porting.md` | ARM GICv4 as PI equivalent |

### Key files

| File | Role |
|------|------|
| `themis/capavisor/src/vmexit.rs` | VMEXIT dispatch, child interrupt handling, preemption timer |
| `themis/capavisor/src/hypercall.rs` | `do_switch`, `forward_interrupt_to_handler`, `do_inject_interrupt` |
| `thhv/src/thhv_vp.c` | `thhv_run_vp` — the critical VP run loop with EAGAIN retry |
| `thhv/inc/thhv.h` | ioctl structs (irqfd, VP state), shared constants |
| `cloud-hypervisor/hypervisor/src/themis/mod.rs` | CHV Themis backend, timer emulation, irqfd, SIPI |
| `themis/scripts/run-dom1.sh` | CHV launch script (CHV_CPUS=2, serial, init=/bin/bash) |

### Key functions

| Function | File | What it does |
|----------|------|-------------|
| `thhv_run_vp` | thhv_vp.c:38 | Run loop: wait-for-SIPI → SWITCH → EAGAIN retry → intercept msg |
| `do_switch` | hypercall.rs:~643 | VMCALL handler: VMCLEAR dom0, VMPTRLD child, drain PIR (step 7b), VMRESUME |
| `forward_interrupt_to_handler` | hypercall.rs:~1400 | Uses route_interrupt() to find handler, context switch child→handler, inject vector |
| `forward_child_exit` | hypercall.rs:~1070 | Forward non-interrupt exits to dom0 |
| `inject_via_pid` | hypercall.rs:~1314 | Set PIR bit + optional notification IPI |
| `route_interrupt` | platform.rs:~979 | Delegates to SwitchManager::route_interrupt() for policy-based routing |

### Build commands

```bash
# Capavisor
cd themis && cargo build --release && cargo themis   # build + pack ISO

# CHV (inside cloud-hypervisor/)
cargo build --release --features themis

# thhv.ko (inside VM, at /opt/thhv or /home/cloud/thhv)
make   # needs liblibthemis.a, kernel headers for 6.8.0-101-generic

# Pack bins.img
cd themis && cargo build-bins

# SCP files to VM
scp -P 2222 thhv/inc/thhv.h thhv/src/thhv_irqfd.c thhv/src/thhv_vp.c cloud@localhost:/home/cloud/thhv/tmp_upload/
# password: cloud123
```

### VM details

- QEMU port forwarding: host 2222 → guest 22 (SSH)
- Serial console: `-serial mon:stdio` in QEMU, `-serial tty=/dev/ttyS0` in CHV
- Dom1 kernel: custom 6.8.0-dirty at `/home/cloud/bzImage`
- Dom1 rootfs: `/home/cloud/rootfs.ext4`
- Dom1 launch: `sudo /home/cloud/run-dom1.sh` (loads thhv.ko + runs CHV)

### VMCS constants

| Name | Value | Notes |
|------|-------|-------|
| PREEMPTION_TIMER_TICKS | 60_000_000 (~20ms) | Restored from 3M after cleanup |
| Timer rate divisor | 5 | 1 tick ≈ 10.67ns at 3GHz |
| ACK_INTERRUPT_ON_EXIT | enabled | Vector in VMEXIT_INTERRUPTION_INFO |

### VM exit reasons (common)

| Code | Reason | Notes |
|------|--------|-------|
| 1 | EXTERNAL_INTERRUPT | Timer, IPI — the scheduling-critical exit |
| 10 | CPUID | Emulated by CHV |
| 12 | HLT | Blocked in thhv via halt_wq |
| 28 | CR_ACCESS | CR0/CR4 writes during boot |
| 30 | IO_INSTRUCTION | Serial port (dominant during boot) |
| 48 | EPT_VIOLATION | MMIO (IOAPIC, platform devices) |
| 52 | VMX_PREEMPTION_TIMER | Backup scheduling mechanism |
