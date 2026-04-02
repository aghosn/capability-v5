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

- **Dom1 (1 CPU) — bash hang**: kernel fully initializes and drops into
  `init=/bin/bash`, but the shell is non-functional (`ls` hangs). Likely cause:
  `init=/bin/bash` doesn't mount `/proc`, `/sys`, or `/dev`, and missing `PATH`.
  Could also be marginal interrupt delivery for user-space disk I/O. Needs a
  quick diagnostic (mount filesystems, try commands) before deeper investigation.
- **Dom1 (2 CPUs)**: AP boots through real→protected→long mode but gets stuck.
  This is a nested-virtualization scheduling artifact. See "Nested-virt scheduling" below.
- **Dom1 stock kernel + systemd**: not yet attempted. Currently uses custom
  instrumented bzImage with `init=/bin/bash`. Goal: full Ubuntu boot with stock
  6.8.0-101-generic kernel and systemd init.
- **Dom1 on real hardware**: not yet tested with the interrupt-window fix.

### Recent commits

- `ce8da26` — **fix: attest GPA heuristic + regression test (Cat B)**
- `99fa5aa` — **feat: full attestation report in Lean engine (Cat B)**
- `c33e9bd` — **fix: Lean interrupt routing + visibility mapping + switch encapsulation (Cat E)**
- `b07697a` — **fix: Lean send/accept uses visible fragments (child subtraction)**
- `7bfa833` — **fix: Lean META send guards — require exclusive leaf, add regression test**
- `bc04fe5` — **chore: make CRB the default TPM transport**

### Uncommitted changes

None — all changes committed.

---

## Nested Virtualization Scheduling Problem

Full analysis, approaches tried, and the `quantum-sched` solution are documented in
the consolidated design document:

> **[`capa-engine/docs/design/interrupt-virtualization.md`](capa-engine/docs/design/interrupt-virtualization.md)**
> §Nested Virtualization Scheduling

**TL;DR**: On QEMU+KVM, nested VMRESUME takes ~100μs. Dom0's LAPIC timer (250Hz)
fires before child executes any instructions → AP can't boot. Three approaches
failed (A: defer all/starve dom0, B: forward all/0 instructions, C: hybrid/overhead).
Fix: `quantum-sched` feature — defer only parent-bound interrupts, re-enter child
(same VMCS, cheap), deliver deferred vector on preemption timer (~20ms).

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

### Next: Phase 0 — Quick diagnostic: 1-CPU bash hang

Before tackling multi-core, verify whether the hang is a real I/O bug or just
`init=/bin/bash` environment limitations. Boot 1-CPU dom1 and try:

```bash
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
export PATH=/usr/bin:/usr/sbin:/bin:/sbin
ls /
```

- [ ] If `ls` works after mounts → hang was missing filesystems (not a bug)
- [ ] If `ls` still hangs → interrupt delivery issue, must investigate before Phase 1

### Next: Phase 1 — Quantum scheduling for multi-core dom1 (`quantum-sched`)

Design doc: [`capa-engine/docs/design/interrupt-virtualization.md` §Nested Virtualization Scheduling](capa-engine/docs/design/interrupt-virtualization.md)

**Problem**: Dom1 AP can't boot in nested virt — dom0's LAPIC timer (0xEC,
250Hz) preempts the child after ~0 instructions per VMRESUME. The current code
does VMCLEAR child → VMPTRLD dom0 → inject timer → dom0 runs → thhv retries
→ VMCLEAR dom0 → VMPTRLD child → VMRESUME child. That's 2 expensive VMCS
switches (each ~100µs+ on nested virt) for 0 useful child instructions.

**Fix**: Defer parent-bound interrupts and re-enter the child via the same
VMCS (cheap — no VMCLEAR/VMPTRLD). The child gets ~4ms of real execution
until the next timer tick. Deferred vectors are delivered via the preemption
timer or flush-before-store. Gated behind `feature = "quantum-sched"`.

**Why this avoids Approach A's failure**: Approach A consumed vectors (ACK'd
from LAPIC) but never re-injected them into dom0. This design uses the proven
`forward_interrupt_to_handler()` path for delivery — just delayed to the
quantum boundary.

#### Implementation steps

- [x] **1.1**: Add `quantum-sched = []` feature to `themis/capavisor/Cargo.toml`
- [x] **1.2**: Add `deferred_vector: AtomicU16` to `CoreContext` in `platform.rs`
  (0 = none, 1–255 = vector). Add `set_deferred(core_id, vector)` and
  `take_deferred(core_id) -> Option<u8>` helpers on `ThemisPlatform`.
- [x] **1.3**: Visibility check inlined in vmexit.rs EXTERNAL_INTERRUPT handler.
  Reads child's interrupt policy via `get_core_cap(core_id)` — parent-bound
  means visibility ≠ `InterruptVisibility::Deliver`.
- [x] **1.4**: Modified `EXIT_REASON_EXTERNAL_INTERRUPT` handler (vmexit.rs, child path).
  When `quantum-sched` enabled and vector is parent-bound:
  - If `deferred_vector` empty → store vector, `return` (re-enter child, same VMCS)
  - If `deferred_vector` set → flush old via `forward_interrupt_to_handler`
    (dom0 switch), store new vector as deferred
  When vector is child-owned → forward immediately (unchanged).
- [x] **1.5**: Modified `EXIT_REASON_VMX_PREEMPTION_TIMER` handler (vmexit.rs, child path).
  When `quantum-sched` enabled and deferred vector exists → flush via
  `forward_interrupt_to_handler` (dom0 switch, child suspended).
  When no deferred vector → reset timer (unchanged).
- [x] **1.6**: Drain deferred in `do_switch` — before activating child VMCS,
  check for leftover deferred vector. If set, inject into dom0 (already active)
  and return `ERR_RETRY`. Ensures dom0 is caught up before child gets new quantum.
- [ ] **1.7**: Build and test. Enable `quantum-sched` in build script / ISO.
  Boot with `CHV_CPUS=2`. **Success criteria**: AP completes SMP init, dom0 stays
  responsive (SSH works), kernel prints "SMP: Total of 2 processors activated".

#### Files modified

| File | Change |
|------|--------|
| `themis/capavisor/Cargo.toml` | `quantum-sched = []` feature |
| `themis/capavisor/src/platform.rs` | `deferred_vector` in CoreContext + helpers |
| `themis/capavisor/src/vmexit.rs` | Conditional deferral in ext-intr + preemption-timer handlers |
| `themis/capavisor/src/hypercall.rs` | `is_parent_bound_vector()` helper + optional do_switch drain |

### Next: Phase 2 — Stock kernel + systemd boot

**Goal**: Boot dom1 with unmodified Ubuntu 6.8.0-101-generic kernel and full
systemd init (no `init=/bin/bash`).

- [ ] **2.1**: Modify `run-dom1.sh`: remove `init=/bin/bash` from kernel cmdline.
  Stock kernel already has `CONFIG_VIRTIO_BLK=y`, `CONFIG_EXT4_FS=y`,
  `CONFIG_VIRTIO_NET=y` built-in — no initramfs needed for basic boot.
  Kernel fallback path in run-dom1.sh already selects `/boot/vmlinuz-*`.
- [ ] **2.2**: Test 1-CPU stock kernel boot (`CHV_CPUS=1`). Watch for:
  CPUID panics, module loading issues, systemd startup, cloud-init,
  network setup (tap-dom1, IP 192.168.100.2/24).
- [ ] **2.3**: Fix issues as they surface. Likely candidates:
  - CPUID emulation gaps (CHV owns policy, `cloud-hypervisor/arch/src/x86_64/mod.rs`)
  - initramfs (extract from dom1.raw boot partition if modules needed)
  - MMIO emulation (systemd probes more devices)
- [ ] **2.4**: Test multi-core stock kernel (`CHV_CPUS=2` + `quantum-sched`).

### Next: Phase 3 — Stabilization + real hardware

- [ ] Tune quantum size (`PREEMPTION_TIMER_TICKS`) if dom0 responsiveness degrades
- [ ] Test with 4 CPUs
- [ ] Test interrupt-window fix + PIR drain on real hardware (posted interrupts)
- [ ] Document what works on nested vs real hardware
- [ ] Update `HANDOFF.md`

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
15 tutorial scenarios + 6 regression tests. **16/21 tests now match** (01–06, 10–13 + 5 regression).

| Cat | Issue | Tutos | Status |
|-----|-------|-------|--------|
| A | Carve/send/accept/revoke MMU update semantics | 12 | ✅ Fixed (7bc3429, 5dbddcc, a3854d8) |
| I | Attributes (CLEAN/VITAL/META) not propagated | 2 | ✅ Fixed (1c5e218) |
| C | Source VP index shows "?" | 2 | ✅ Fixed (c4edf0b) |
| J | UID allocation | — | ✅ Fixed (e9b869a) |
| L | Error messages differ | several | ✅ Fixed (c4edf0b, ce8da26) |
| E | Interrupt routing + chain walk + switch encapsulation | 1 | ✅ Fixed (c33e9bd) |
| G | Attest succeeds on unsealed domain (should reject) | 1 | ✅ Fixed (0464477) |
| B | View/attest shows only hash (no full domain info) | 5 | ✅ Fixed (99fa5aa, ce8da26) |
| D | Send to sealed domain queued as pending | 3 | ❌ |
| F | Revoke doesn't cascade (domain + children not cleaned) | 1 | ❌ |
| H | Domain owner names wrong in display | 2 | ❌ |
| K | GPA overlap check missing in send | 1 | ❌ |

**Also fixed in Cat B batch:**
- Child domain default interrupt policy: `.deliverAndClear` (Report), was `.deliver` (Deliver)
- Local handles start at 1 (matching Rust), was 0
- Attribute separator in attest reports: pipe `|` (matching Rust `Display`)
- GPA address space sorted by start address
- COMM `register-comm` error messages match Rust (PermissionDenied for guards, exact wording)
- GPA line/address space: only shown for child domains (root has no address_map)

**Remaining tutos by difficulty:**
- **09** (1 line): cosmetic — enumerate tree missing `uid:1` line
- **07** (small): MMU update on accept, error "API not allowed" vs "Permission denied"
- **08** (medium): Cat K (GPA overlap check, explicit GPA mapping)
- **14, 15** (larger): Cat D (channel attestation) + Cat H (domain owner names)

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

### Design documents

| Document | Path | Content |
|----------|------|---------|
| **Interrupt Virtualization** | `capa-engine/docs/design/interrupt-virtualization.md` | Single source of truth: goals, HW background, routing model, gap analysis, nested-virt scheduling, quantum-sched, Directvisor reference, 3 delivery bugs |
| **Attestation** | `capa-engine/docs/design/attestation/attestation.md` | Two-layer TPM + Ed25519 model |
| **Address Translation** | `capa-engine/docs/design/address_translation/address_translation.md` | EPT/IOMMU design |
| **ARM Porting** | `themis/docs/arm-porting-design.md` | ARM GICv4 as PI equivalent |

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
