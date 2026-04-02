## Themis — Implementation Status & Plan

> **Archives**: Previous todo content archived to:
> - [`2026/docs/archived/09-03-2026/archived_todo.md`](capa-engine/docs/archived/09-03-2026/archived_todo.md) — phases 0–15, BUG-1–15, dom0 bringup
> - [`themis/docs/archive/27_03_2026.md`](themis/docs/archive/27_03_2026.md) — full history through dom1 multi-core debugging

---

## Current State (2026-04-02)

### What works

- **Dom0**: boots to login on 4 CPUs. Ubuntu Noble 6.8.0-101-generic. Stable.
- **Dom1 (1 CPU, local QEMU)**: **boots to /bin/bash shell** (~204s guest time).
  virtio-blk: partition table read, ext4 mount. Kernel fully initializes.
  Uses `init=/bin/bash` (dom1.raw rootfs), not full systemd.
- **Lean formal spec**: 83 proved theorems, zero `sorry`. Covers CDT preservation,
  N-level isolation, execute protocol, global system invariant, deep revocation cascade.
- **TPM attested boot (P20)**: Ed25519 keygen + SHA-256 measurement + TPM PCR extend
  at capavisor _start(). Signed attestation hypercall (ATTEST_SELF with nonce).
  On-demand domain config via ATTEST_SELF(nonce=0). TPM driver supports both
  **CRB** (default) and **TIS** transports, auto-selected via ACPI StartMethod.
  QEMU swtpm integration (CRB default, `QEMU_TIS=1` for TIS). thhv ioctls for
  ATTEST_SELF + READ_PCR. Full crypto verification test (Ed25519 + TPM RSA-2048
  via OpenSSL EVP).
  **Verified end-to-end**: boot + ATTEST_SELF → 52 mem_caps + 1 dom_cap +
  50 PA map entries loaded by thhv driver with zero errors.

### What doesn't work

- **Dom1 (2 CPUs)**: AP boots through real→protected→long mode but gets stuck.
  This is a nested-virtualization scheduling artifact. See "Nested-virt scheduling" below.
- **Dom1 on real hardware**: not yet tested with the interrupt-window fix.

### Recent commits

- `c33e9bd` — **fix: Lean interrupt routing + visibility mapping + switch encapsulation (Cat E)**
- `b07697a` — **fix: Lean send/accept uses visible fragments (child subtraction)**
- `7bfa833` — **fix: Lean META send guards — require exclusive leaf, add regression test**
- `bc04fe5` — **chore: make CRB the default TPM transport**
- `9779e4a` — **feat(P20k): CRB transport support for TPM driver**

### Uncommitted changes

None — all changes committed.

---

## The Problem: Child VP Scheduling on Nested Virtualization

### Architecture reminder

```
QEMU+KVM (actual L0, physical host)
  └─ Capavisor (L0 logical, VMX root inside KVM guest)
       └─ Dom0 (L1, Ubuntu, 4 CPUs) → thhv.ko
            └─ CHV (userspace) → ioctls
                 └─ Dom1 (L2, custom Linux, 2 CPUs) → the child VM
```

**Critical**: We develop on QEMU+KVM. Our "L0" capavisor is actually an L1 guest in KVM.
Dom1 is L2 in KVM terms. On real hardware, the capavisor would be true L0.

### The scheduling loop

1. CHV calls `ioctl(RUN_VP)` → `thhv_run_vp()` in kernel
2. thhv calls `themis_switch()` VMCALL → capavisor
3. Capavisor: VMCLEAR dom0 VMCS, VMPTRLD child VMCS, VMRESUME child
4. Child runs until VM exit
5. On exit: capavisor handles exit, returns control to dom0 (ERR_RETRY) or CHV (intercept message)
6. thhv: if EAGAIN, `cond_resched()` then goto retry_switch

### What goes wrong — three approaches tried, all fail

**Approach A: Defer AP interrupts + preemption timer yield**
- Child external interrupt → ACK vector → store in DEFERRED_HOST_VECTOR → VMRESUME child immediately
- Preemption timer fires → yield to dom0, inject deferred vector
- **Result at 20ms quantum**: AP reaches cpuhp_ap_sync_alive, but dom0 starves → RCU stall at ~688s
- **Result at 1ms quantum**: Dom0 hung_task warnings, SSH unresponsive. Too much VMCLEAR/VMPTRLD overhead.
- **Why it fails**: dom0's timer interrupt is consumed by capavisor (ACK_INTERRUPT_ON_EXIT), never
  delivered to dom0's IDT → scheduler_tick() never runs → TIF_NEED_RESCHED never set → dom0 starves

**Approach B: Forward ALL child interrupts to dom0** (mirrors KVM's local_irq_enable)
- Child external interrupt → `forward_interrupt_to_handler` → switch to dom0 VMCS, inject vector
- Dom0 IDT handles the interrupt → scheduler runs naturally
- **Result**: Dom0 stays healthy (SSH alive!) but AP stuck at RIP=0x0 — never executes one instruction
- **Why it fails**: The interrupt is vector 0xEC = dom0's LAPIC timer (scheduler tick at ~250Hz).
  In nested virt, KVM always has dom0's LAPIC timer pending or about to fire. The VMCLEAR/VMPTRLD/
  VMRESUME sequence for the child takes so long in nested virt that dom0's timer deadline is already
  past by the time the child's VMRESUME completes → KVM immediately exits → AP executes 0 instructions.
  This is a **nested virtualization artifact** — on real hardware, VMRESUME is ~microseconds and
  the child would execute thousands of instructions between 250Hz ticks.

**Approach C: Deferred + 1ms preemption timer (hybrid)**
- Defer AP interrupts (like A) but with 1ms quantum (3M ticks at 3GHz, rate divisor 5)
- **Result**: Dom0 shows hung_task warnings. SSH intermittently responsive. Child may be making
  some progress but very slowly. The 1ms quantum may cause too much context-switch overhead.

### Key insight: this is a nested virtualization problem

On real hardware:
- VMRESUME is ~1μs, child runs ~4ms between 250Hz timer ticks = ~4000 instructions minimum
- With posted interrupts (PI), dom0's timer would NOT cause a child VM exit at all
- The "forward every interrupt" approach (B) would work perfectly

On QEMU+KVM (our dev env):
- Our VMRESUME is a nested VMRESUME → KVM overhead → ~100s of μs or more
- Dom0's LAPIC timer fires before the child executes ANY instruction
- Posted interrupts are not available (nested PI not supported by KVM)

### User's suggestion to explore

**"Flush writes to child, return to dom0, let dom0 drain interrupts, then do a pure switch"**

The idea: after SET_VP_STATE writes the child's registers, return to dom0. Dom0 handles its
pending LAPIC timer (scheduler tick fires, gets rearmed for next tick). THEN call SWITCH.
The child now has a full quantum until the next timer tick.

Current flow: SET_VP_STATE (ioctl) → RUN_VP (ioctl) → SWITCH vmcall → child runs
With this change: between RUN_VP and SWITCH, dom0 would drain pending interrupts first.

This could translate to: in `thhv_run_vp`, instead of `cond_resched()` on EAGAIN,
do `schedule_timeout(1)` (sleep 1 jiffy = 1-4ms) to guarantee dom0 gets a full timer
tick before retrying. Or: have the capavisor itself do `sti; nop; cli` in VMX root
before the child VMRESUME to drain pending LAPIC interrupts.

### Other observations

- The timerfd/irqfd path for dom1's timer is NOT the cause of the 0xEC flood.
  The flood is dom0's OWN scheduler tick (hrtimer → LAPIC), not the irqfd injection.
  Dom1's timerfd fires ~1/sec during boot (large TSC deltas).
- Dom1 uses TSC-deadline mode (WRMSR 0x6E0). CHV arms a timerfd. When it fires:
  timerfd → eventfd → thhv workqueue → INJECT_INTERRUPT vmcall → capavisor sets PIR bit.
  PIR is drained by do_switch step 7b on next VMRESUME (software fallback, not hardware PI).
- `inject_via_pid` changed to is_remote=false to avoid notification IPI causing immediate exit.

---

## Action Plan

### Done: Interrupt handling cleanup (commit c2820b5)

- [x] Code review of ad-hoc interrupt mechanisms (8 findings, 3 critical)
- [x] Phase 1: Integrate SwitchManager into ThemisPlatform
- [x] Phase 2: Remove DEFERRED_HOST_VECTOR, yield_child_to_dom0, hardcoded routing,
  debug logs. Use route_interrupt() + vector-in-RDI. Net -191 lines.

### Done: VMCS control violation fix (commits 74a6157, 7f86f38)

- [x] Diagnosed dom0 freeze: VIRTUALIZE_APIC_ACCESSES + VIRTUALIZE_X2APIC both set for
  child VPs (SDM 26.2.1.1 violation). VM_INSTRUCTION_ERROR=7, halt_forever, dom0 loses core.
- [x] Fixed: VIRTUALIZE_APIC_ACCESSES only set when `!child` in vmcs.rs
- [x] Added toggle-debug tool for runtime VMCALL testing
- [x] Added usleep_range(50,100) to thhv VP retry loop (prevents tight spin)
- [x] Cleaned debug instrumentation into separate commit

### Done: Lean 4 formal specification (83 theorems, 0 sorry)

- [x] Phase 1: Core operation specs (carve, alias, send, revoke, create, seal, switch, accept, reject, interrupt)
- [x] Phase 1: VP transitions (all 8) + reachability + exhaustiveness (12 theorems)
- [x] Phase 2: CDT preservation — carve/alias/revoke/send preserve WellFormedTree
- [x] Phase 2: Transitivity, multi-level monotonicity, containment, address space isolation
- [x] Phase 3: Fix proof gaps G1-G4, add confinement theorems
- [x] Phase 3: N-level inductive proofs (WellFormedChain, deep isolation)
- [x] Phase 4: GloballyWellFormed + deep revocation cascade (FullDomainRevocation)
- [x] Phase 4: SystemInvariant (CDT, CoreExclusive, UniqueIds, PolicyMonotonic)
- [x] Phase 4: Master system isolation theorem
- [x] Phase 4: Execute protocol model (7 phases, lock hierarchy, A1, non-destructive ops)
- [x] CDT frame rule: create/seal/revoke_domain preserve CdtWellFormed

### Done: Virtio_blk interrupt delivery fix (commits 50ae665, fcbc04f)

- [x] Root cause: PIR drain in do_switch only runs at SWITCH time when guest IF is
  almost always 0 (inside timer handler). Device interrupts deferred indefinitely.
- [x] Fix 1 (50ae665): scan PIR low→high so device vectors (word 0) checked before
  timer (word 3). Snapshot-and-restore for un-injected vectors.
- [x] Fix 2 (fcbc04f): interrupt-window exiting — when PIR has pending vectors but
  IF=0, set PRIMARY_PROCBASED bit 2. On VMEXIT reason 7 (interrupt window), drain
  PIR and inject. Clears bit when PIR empty.
- [x] Result: dom1 boots to /bin/bash shell. virtio-blk partition table read, ext4
  mount, kernel init all succeed.

### Done: TPM attested boot (Phase 20, commits b19ceb7..1931c23)

Design doc: [`capa-engine/docs/design/attestation/attestation.md`](capa-engine/docs/design/attestation/attestation.md)

- [x] P20a: ABI types — SignedAttestReport (192B), BootAttestation (128B), THEMIS_READ_PCR
- [x] P20b: Capavisor _start() keygen — RDRAND-seeded Ed25519 + SHA-256(binary ‖ pub_key)
- [x] P20c: Minimal no_std TPM 2.0 TIS MMIO driver crate (themis/crates/tpm2)
- [x] P20d: Boot integration — AttestationState in spin::Once, PCR 11 extend
- [x] P20e: Signed attestation hypercall (ATTEST_SELF with nonce) + TPM PCR read
- [x] P20f: QEMU swtpm integration (QEMU_TPM=1 env var, setup-swtpm.sh)
- [x] P20g: thhv ioctls — THHV_ATTEST_SELF (0x05), THHV_READ_PCR (0x06)
- [x] P20h: On-demand attestation — removed boot-time push, driver requests via ATTEST_SELF

**Architecture**: TPM is capavisor-exclusive (MMIO at 0xFED40000 in META pool, never in
any domain's EPT). Ed25519 keys are ephemeral (fresh each boot). Nonce=0 returns domain
config (mem_caps, dom_caps, PA map). Nonce≠0 returns Ed25519-signed report.

**Tested end-to-end (no TPM)**: Driver loads attestation at `insmod` time via ATTEST_SELF
VMCALL. 52 mem_caps + 1 dom_cap + 50 PA map entries loaded, zero errors. Full dom0 boot
stable. **With TPM**: fully working — ACPI-based discovery, PCR[11] extended,
dom0 excluded (EPT + ACPI stripping). See P20i below.

#### Bugs fixed during TPM attestation testing

- **Safe TPM probe (c7c669e)**: MMIO read at unmapped 0xFED40000 → #PF → triple fault.
  Fixed: check Limine memory map for TPM region before probe.
- **Binary size calculation (c7c669e)**: `EXECUTABLE_AND_MODULES` includes vmlinuz+initrd;
  taking max(end) gave ~4 GB. Fixed: find entry containing `phys_base`.
- **LocalHandle vs SubHandle (0c8c7ac)**: `do_attest_self` used `c.sub_handle` (tree identity)
  instead of `*handle` (domain-local BTreeMap key) — two caps from different parents
  could share `sub_handle`, causing duplicate handle=1 in attestation report.
- **PCI BAR overlap (8d91531)**: Passthrough regions from e820 RESERVED and PCI BARs
  overlapped at 0x80000000. Fixed: merge overlapping regions (take union).
- **COMM PA map duplicate (8d91531)**: COMM cap and underlying carved memory share same
  GPA; both appeared in PA entries. Fixed: exclude COMM-attributed caps from PA map.

### Next: Quantum scheduling for multi-core dom1 (`quantum-sched`)

Design doc: [`themis/docs/quantum-sched.md`](themis/docs/quantum-sched.md)

Dom1 AP can't boot in nested virt — dom0's timer preempts the child after ~10
instructions per 4ms period. Fix: defer parent-bound interrupts and re-enter
the child. Deliver on preemption timer expiry (~20ms quantum). Gated behind
`feature = "quantum-sched"`.

- [ ] Add `quantum-sched` feature flag to capavisor Cargo.toml
- [ ] Add per-core `deferred_vector` storage to CoreContext
- [ ] Modify EXTERNAL_INTERRUPT handler: defer parent-bound vectors
- [ ] Modify PREEMPTION_TIMER handler: flush deferred vector via lazy-unwind
- [ ] Handle multiple deferred interrupts (flush-before-store)
- [ ] Test with CHV_CPUS=2

### Next: Test on real hardware + stock kernel boot

- [ ] Test interrupt-window fix + PIR drain on real hardware (posted interrupts)
- [ ] Boot dom1 with stock Ubuntu kernel (not custom bzImage)

### Done: lean-exec — Executable Lean 4 model (commit ec3ebc4)

- [x] Project setup: lakefile.toml, lean-toolchain, ThemisCapa dependency
- [x] Core types: BEq/Hashable/ToString/Decidable instances for all ThemisCapa types
- [x] ExecState with flat domain/memcap maps, CapaM monad (ExceptT+StateM)
- [x] Memory operations: init, carve, alias, send, accept, reject, revoke
- [x] Domain operations: create, seal, revoke_domain (recursive)
- [x] Channel operations: getChan, send/accept/reject channel
- [x] VP & switch: state machine, switch fwd/ret, deliver interrupt (lazy-unwind)
- [x] Policy & registers: set/get policy, set/get register, interrupt policy
- [x] Query & attestation: compute address space, enumerate, attest
- [x] Engine dispatch (30 command variants) + CLI REPL with session file loading
- [x] FFI bridge: @[export] functions + Rust lean-backend feature in capa-cli
- [x] Boundary fix: MemCapUid → CapNodeId rename, UID mapping moved to lean_backend.rs
- [x] Cat J fix: accept reuses UID (stable identity across transfers)
- [ ] Testing: differential testing vs Rust engine — 12 categories remaining (see below)

**3034 lines of Lean 4.** REPL supports same command syntax as capa-cli.
Imports ThemisCapa proof model types; refinement proofs can bridge executable
functions to the 83 existing safety theorems.

### In progress: lean-exec differential testing

Comparing capa-cli outputs between `--backend rust` and `--backend lean` across
15 tutorial scenarios + 5 regression tests. **12/20 tests now match** (01–06, 11–13 + 3 regression).

| Cat | Issue | Tutos | Status |
|-----|-------|-------|--------|
| A | Carve/send/accept/revoke MMU update semantics | 12 | ✅ Fixed (7bc3429, 5dbddcc, a3854d8) |
| I | Attributes (CLEAN/VITAL/META) not propagated | 2 | ✅ Fixed (1c5e218) |
| C | Source VP index shows "?" | 2 | ✅ Fixed (c4edf0b) |
| J | UID allocation | — | ✅ Fixed (e9b869a) |
| L | Error messages differ | several | ✅ Mostly fixed (c4edf0b) |
| E | Interrupt routing + chain walk + switch encapsulation | 1 | ✅ Fixed (c33e9bd) |
| G | Attest succeeds on unsealed domain (should reject) | 1 | ✅ Fixed (0464477) |
| D | Send to sealed domain queued as pending | 3 | ❌ |
| B | View/attest shows only hash (no full domain info) | 5 | ❌ Biggest remaining blocker |
| F | Revoke doesn't cascade (domain + children not cleaned) | 1 | ❌ |
| H | Domain owner names wrong in display | 2 | ❌ |
| K | GPA overlap check missing in send | 1 | ❌ |

**Remaining tutos by difficulty:**
- **09** (1 line): cosmetic — enumerate tree missing `uid:1` line
- **07, 10** (smaller): dominated by Cat B (attest output format)
- **08** (smaller): Cat B + Cat K (GPA overlap check)
- **14, 15** (larger): Cat B + Cat D + Cat H

**⚠ Validation audit needed (discovered via Cat L):** Investigating error message
differences revealed that `register_comm` was missing 4 validation checks that
all other mutation operations (carve/alias/send) enforce. Fixed in `90f4807` with
regression tests. **A systematic audit of all operation validation checks is needed**
to ensure every operation enforces the complete set of guards (sealed, API, frozen,
ownership, attribute constraints). This should be done by comparing each operation's
checks against the canonical pattern established by carve/alias/send.

### Future work

- [ ] Per-VP irqfd: struct updated, needs end-to-end test
- [ ] Paravirt timer (PV MMIO hypercall, P16.6d3)
- [ ] Reduce serial I/O overhead
- [ ] CPUID policy in DomainPolicy (P16.6c)
- [ ] Stock cloud image kernel
- [ ] Attestation: test with real TPM (bare metal or working swtpm probe)

### Next: Full TPM attestation with user binding (P20j)

Design doc: [`capa-engine/docs/design/attestation/attestation.md §14`](capa-engine/docs/design/attestation/attestation.md)

**Goal**: Complete the two-layer attestation model — TPM2_Quote (platform proof)
bundled with Ed25519-signed domain reports (capavisor proof), with user public key
binding to prevent cross-user attestation replay.

**Two-layer model**:
- **Layer 1 (Platform)**: TPM2_Quote(AK, nonce, PCR[11]) — TPM signs PCR values
  with an RSA-2048 Attestation Key. Proves the capavisor binary + pub_key are
  running on genuine hardware.
- **Layer 2 (Domain)**: Ed25519 sign SHA-256(report ‖ nonce ‖ user_pub_key) — the
  capavisor signs the domain configuration for a specific verifier.

**Key design decisions**:
- `ATTEST_SELF` nonce=0 path unchanged (unsigned PA map for thhv init)
- Signed path uses DomainComm TX ring to pass `{nonce, user_pub_key}` (64 bytes)
- VMCALL `arg0=1, arg1=sequence` — flag + TX ring sequence number
- Defense in depth: thhv mutex (cooperative) + capavisor sequence verification (A2)
- RSA-2048 AK under Owner hierarchy
- Graceful degradation: no TPM → Ed25519-only (tpm_quote_size=0)

**Todos**:
- [ ] P20j-1: TPM driver — `TPM2_CreatePrimary` (RSA-2048) + `TPM2_Quote` commands
- [ ] P20j-2: Capavisor — AK creation at boot after PCR_Extend in `try_tpm()`
- [ ] P20j-3: ABI — extend `SignedAttestReport` with user_pub_key + TPM quote fields
- [ ] P20j-4: Hypercall — `do_attest_self` reads `AttestRequest` from TX ring, sequence verify
- [ ] P20j-5: thhv — mutex + TX enqueue + RX dequeue for signed attestation ioctl
- [x] P20j-6: Userspace test — Ed25519 + RSA-2048 crypto verification (test_attestation.c)
- [x] P20j-7: Documentation — attestation.md + todo.md updated

### Done: TPM MMIO probe fix (P20i, commit 65f3283)

Design doc: [`capa-engine/docs/design/attestation/attestation.md §13`](capa-engine/docs/design/attestation/attestation.md)

TPM probe fixed — discovered from ACPI TPM2 table, MMIO mapped explicitly,
excluded from dom0 EPT + ACPI tables stripped. End-to-end verified with swtpm.

- [x] P20i-1: Parse ACPI TPM2 table in `acpi.rs` (TpmInfo struct, same pattern as DMAR)
- [x] P20i-2: Split `attestation::init()` / `try_tpm()`, AtomicBool for tpm_available
- [x] P20i-3: Rewire `main.rs` — remove memmap scan, call `try_tpm()` after `platform()`
- [x] P20i-4: Exclude TPM region from dom0 passthrough in `boot.rs`
- [x] P20i-5: Switch QEMU from `tpm-crb` to `tpm-tis` in `run-qemu.sh`
- [x] P20i-6: Strip TPM2 from dom0's ACPI tables (alongside DMAR)
- [x] P20i-7: Test end-to-end — `QEMU_TPM=1`, PCR extend + dom0 boot verified
- [x] VPID bug: child VPID double-incremented — fixed in `d508c22`.
  `write_control_fields` now takes final 1-based vpid directly.

---

## Reference

### Key files

| File | Role |
|------|------|
| `themis/capavisor/src/vmexit.rs` | VMEXIT dispatch, child interrupt handling, preemption timer |
| `themis/capavisor/src/hypercall.rs` | `do_switch`, `forward_interrupt_to_handler`, `yield_child_to_dom0`, `do_inject_interrupt` |
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
