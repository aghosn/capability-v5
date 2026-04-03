# Skill: Code Review & Cleanup

## When to Use

Use this skill when:
- A milestone is reached and the codebase needs consolidation
- Before a handoff or a merge to a shared branch
- After a debugging session that introduced ad-hoc instrumentation
- When refactoring for clarity, removing dead code, or enforcing conventions

---

## 1. Code Style

### Constants over magic numbers

Never embed numeric literals in logic. Define named constants at module level
or in a shared constants block. Prefer `const` items or enums.

```rust
// BAD
if pin_val & (1 << 7) == 0 { ... }
if offset == 0x300 { ... }

// GOOD
const PROCESS_POSTED_INTERRUPTS: u64 = 1 << 7;
const APIC_ICR_LOW: usize = 0x300;
if pin_val & PROCESS_POSTED_INTERRUPTS == 0 { ... }
if offset == APIC_ICR_LOW { ... }
```

VMCS field encodings, APIC register offsets, exit reasons, MSR numbers,
interrupt vectors — all must be named constants. Group related constants
together with a section comment.

### Enums over integer flags

When a value has a fixed set of meanings, use an enum (even `#[repr(u32)]`)
instead of bare integers with comments.

```rust
// BAD
let acc_type = (qual >> 12) & 0xF; // 0=read, 1=write, ...

// GOOD
#[repr(u8)]
enum ApicAccessType { Read = 0, Write = 1, InstrFetch = 2, EventDelivery = 3 }
```

### Comments

- Comment *why*, not *what*. The code shows what; comments explain intent
  and non-obvious constraints.
- Cite Intel SDM section numbers for hardware-mandated behaviour.
- Remove stale TODO/FIXME/HACK comments once resolved. Track open items
  in `todo.md`, not in source comments.
- Delete diagnostic `serial_println!` / `eprintln!` after debugging. Use
  the `verbose` feature or `serial_rtdbg!` for persistent optional tracing.

### Function size and structure

- Functions over ~80 lines should be split into helpers with descriptive
  names.
- Each match arm in a large dispatcher (e.g., `handle_vmexit`) should
  delegate to a named function, not contain inline logic.
- Avoid deeply nested `if`/`match` blocks (>3 levels). Extract inner
  logic into functions.

### Formatting

Run `cargo fmt` before committing. All Rust code must pass `cargo fmt --check`
with no diffs. Do not mix formatting fixes with logic changes — format first
in a separate commit if needed.

---

## 2. Modularity & Separation of Concerns

### Capavisor layers

The capavisor has clear layers. Do not mix them:

| Layer | Files | Responsibility |
|-------|-------|----------------|
| VMEXIT dispatch | `vmexit.rs` | Decode exit reason, delegate to handler |
| Hypercall handlers | `hypercall.rs` | `do_switch`, `do_add_vp`, `forward_*` |
| Platform state | `platform.rs` | Domain/core/VP metadata, `ThemisPlatform` |
| VMCS setup | `vmcs.rs` | Control field configuration, host/guest state |
| EPT management | `ept/` crate | Page table build/walk |

A VMEXIT handler should not directly manipulate `ThemisPlatform` internals.
A VMCS setup function should not contain interrupt routing logic.

### Shared logic between dom0 and child domains

**Axiom A2**: dom0 is not privileged. The same hypercall ABI applies to
all domains. Concretely:

- `handle_vmexit` must not have `if domain_id == 0` special-casing.
  The dispatch logic for VMCALLs, APIC accesses, interrupt forwarding,
  etc. applies identically to all domains. Dom1 can create sub-domains
  and issue the same hypercalls as dom0.
- The only legitimate dom0-specific behaviour is at boot time (passthrough
  APIC, passthrough devices) and is configured via the capability engine's
  policy — not via `if domain_id == 0` checks in exit handlers.
- Child exit forwarding (`forward_child_exit`, `forward_interrupt_to_handler`)
  uses the capability engine's interrupt policy — no hardcoded vector ranges.
- LAPIC emulation (APIC_ACCESS handler, APIC_WRITE handler) should use the
  same code path for all child domains.
- New hypercalls must work for any domain, not just dom0's children.

### VMEXIT dispatch: single table, not dom0-vs-child split

**Current problem**: `handle_vmexit` has two separate `match basic_reason`
blocks — one for "child" domains (gated on `domain_id != 0`) and one for
dom0. This duplicates handlers for VMCALL, CPUID, XSETBV, INIT_SIGNAL,
APIC_ACCESS, EPT_VIOLATION, etc. The duplication makes it easy to fix a
bug in one path and miss the other.

**Target architecture**: one dispatch table. Each handler receives a
context that includes:

- Whether the domain has a parent (i.e., exits can be forwarded).
  This replaces the `domain_id != 0` check with a capability-driven
  query: "does this domain have a parent switch context?"
- The domain's interrupt policy (from the capability engine).
- The domain's VAPIC/PID/EPT configuration.

Exits that behave identically for all domains (VMCALL, XSETBV,
INIT_SIGNAL, PREEMPTION_TIMER reset, TRIPLE_FAULT) should be handled
once. Exits that need parent-forwarding (HLT, IO, RDMSR, WRMSR,
CR_ACCESS, EPT_VIOLATION for MMIO) check "has parent?" and forward;
if no parent, they're handled locally (dom0 passthrough behaviour).

**What to check during review**:
- Any new exit handler must be added to ONE dispatch table, not two.
- Duplicated match arms across child/dom0 blocks are a review failure.
- The `domain_id != 0` guard should eventually become
  `platform.domain_has_parent(core_id)` or similar capability-driven check.

### CHV ↔ Capavisor interface

The intercept message (`ThemicInterceptMessage`) is the only data channel
from capavisor to CHV for child exits. When adding new data:

- Use existing fields where semantically appropriate (e.g., `rax` for
  decoded write values, `msr_number` for auxiliary data like ICR_HIGH).
- Document which fields carry what for each exit reason.
- Do not add capavisor-internal state to the intercept message.

---

## 3. Capability Engine Driven (Axiom A1 & A9)

**Every hardware state change must be validated by the capability engine
first.** The pattern is always `execute() → apply_update()`.

- No direct EPT manipulation outside `apply_update`.
- No domain metadata changes without going through the engine API.
- Interrupt routing uses `route_interrupt()` via the `SwitchManager`,
  which consults the domain's `InterruptPolicy`.
- VP state transitions (Running/Suspended/Interrupted) go through
  `deliver_interrupt_vp` / `switch_vp` — never set directly.

When adding new functionality, ask: *does the capability engine know
about this?* If not, the feature is either missing engine support
(add it) or bypassing the engine (don't).

---

## 4. Regression Protection

### Before committing

1. **1-vCPU dom1 boot**: `CHV_CPUS=1` → must reach `Run /bin/bash` or
   login prompt (stock kernel + initramfs).
2. **2-vCPU dom1 boot**: `CHV_CPUS=2` → must show `Brought up 1 node, 2 CPUs`
   and reach login prompt.
3. **Dom0 stability**: SSH must remain responsive throughout dom1 boot.
4. **Engine tests**: `cd capa-engine/ && cargo test` must pass.
5. **Build clean**: `cargo build -p capavisor` with no errors.

### Test matrix (manual, run before milestone commits)

| Test | Command | Success criteria |
|------|---------|-----------------|
| Engine unit tests | `cd capa-engine && cargo test` | All pass |
| Capavisor build | `cd themis && cargo build -p capavisor` | No errors |
| CHV build | `cd cloud-hypervisor && cargo build --release --features themis,kvm` | No errors |
| thhv build | Docker: `BINS_TARGETS=thhv bash themis/scripts/build-bins-docker.sh` | thhv.ko produced |
| 1-vCPU systemd | `CHV_CPUS=1 run-dom1.sh` | Login prompt |
| 2-vCPU systemd | `CHV_CPUS=2 run-dom1.sh` | Login prompt, 2 CPUs |
| Dom0 SSH | `ssh -p 2222 cloud@localhost` during dom1 boot | Responsive |

### After debugging sessions

- Remove all diagnostic `serial_println!` / `eprintln!` additions.
- Revert any `#[cfg(feature = "verbose")]`-bypassing debug prints.
- Check `git diff` for leftover instrumentation before committing.
- Ensure `todo.md` is updated with findings and current status.

---

## 5. Documentation

### What to update and when

| Document | Update when |
|----------|-------------|
| `todo.md` | Every session: completed items, new bugs, status changes |
| `CONTEXT.md` | Architecture changes, new axioms, settled design decisions |
| `HANDOFF.md` | Before handoff: what works, what doesn't, how to test |
| Skill files (`skills/`) | New workflows, changed procedures, new conventions |
| Design docs (`capa-engine/docs/design/`) | New subsystem designs, protocol changes |

### Documentation standards

- Keep `todo.md` "Current State" section accurate — it's the first thing
  read each session.
- Design decisions that are **settled** go in `CONTEXT.md` §Key Design
  Decisions. Do not re-litigate them in code comments.
- Trace code registries, VMCS constant tables, and similar reference
  material belong in skill files, not scattered in source comments.

---

## 6. Code Review Checklist

When reviewing changes (own or others), check:

- [ ] No magic numbers — all constants named
- [ ] No `if domain_id == 0` bypasses (A2)
- [ ] All hardware changes go through capability engine (A1, A9)
- [ ] Functions under ~80 lines, match arms delegate to named functions
- [ ] No leftover debug prints / diagnostic logging
- [ ] Stale comments removed, new comments explain *why*
- [ ] `todo.md` updated if status changed
- [ ] All regression tests pass (build + boot)
- [ ] No `unsafe` without a `// SAFETY:` comment explaining the invariant
