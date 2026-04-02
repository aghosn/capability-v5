## Themis — Implementation Status & Plan

> **Archives**: Previous todo content archived to:
> - [`2026/docs/archived/09-03-2026/archived_todo.md`](capa-engine/docs/archived/09-03-2026/archived_todo.md) — phases 0–15, BUG-1–15, dom0 bringup
> - [`themis/docs/archive/27_03_2026.md`](themis/docs/archive/27_03_2026.md) — full history through dom1 multi-core debugging

---

## Current State (2026-04-03)

### What works

- **Dom0**: boots to login on 4 CPUs. Ubuntu Noble 6.8.0-107-generic. Stable.
- **Dom1 (1 CPU, bare-metal Linux/KVM)**: **full systemd boot to login prompt**.
  Stock Ubuntu 6.8.0-107-generic kernel + initramfs. virtio-blk, virtio-net,
  ext4 mount, systemd services all complete.
- **Dom1 (2 CPUs, bare-metal Linux/KVM)**: **full systemd boot to login prompt**.
  Both CPUs activated (12000 BogoMIPS), SMP bringup succeeds via SIPI through
  APIC_ACCESS exit interception and IPI routing.
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

### What doesn't work / known issues

- **Dom1 bash intermittent hang**: with `init=/bin/bash`, interactive commands
  sometimes hang (timing-dependent interrupt delivery). Full systemd boot works
  reliably. The `init=/bin/bash` path lacks `/proc`/`/sys`/`/dev` mounts.
- **Posted interrupts**: hardware PI is disabled (software PIR drain used instead).
  The host advertises PI support but L2 delivery is unreliable under nested KVM.
  Requires `intel_iommu=on` on host kernel cmdline + QEMU IOMMU flags. See
  `testing-posted.md` for details.
- **Dom1 on real hardware**: not yet tested.

### Recent commits

- `d9720fe` — **chore: bump CHV submodule (code review cleanup)**
- `788ae02` — **style: cargo fmt capavisor**
- `fe94852` — **refactor: replace magic numbers with named constants, remove debug prints**
- `1dc3abd` — **docs: add code review skill file**
- `5fc31fe` — **feat: dom1 full systemd boot with stock kernel**
- `dc48a67` — **fix: lost-wakeup race in thhv HLT + irqfd VP routing**
- `4968b9a` — **fix: 2-vCPU dom1 boot — APIC emulation, EOI, IPI routing**
- `d21dc82` — **fix: child APIC virtualization for multi-vCPU dom1**
- `f6eb224` — **fix: disable posted interrupts, always use software PIR drain**
- `4fccf1c` — **fix: Lean META revoke, GPA mapping, overlap check — 21/21 tests pass**
- `e2e935e` — **fix: Lean channel attest, forwarding, accept-removes-sender (19/21)**
- `294af31` — **fix: Lean carve/alias guard ordering — ownership+META before API check**
- `470caf7` — **fix: CLI prunes stale mem_caps after memory revoke**
- `0b432b6` — **fix: prune stale handles from domain table after memory revoke**
- `fb35948` — **docs: add README for differential testing regression suite**
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

### Done: Phase 0 — 1-CPU dom1 boot (2026-04-03)

Root cause: hardware posted interrupts broken under nested KVM. Software
PIR drain was gated on PI bit 7, skipped when PI appeared enabled.

- [x] Disable posted interrupts (never set bit 7 in child pin-based controls)
- [x] Remove PI guard on software PIR drain in `do_switch` and `drain_pir_on_interrupt_window`
- [x] Result: 1-vCPU dom1 boots to bash with stock 6.8.0-107 kernel

### Done: Phase 1 — 2-CPU dom1 boot (2026-04-03, no quantum-sched needed)

On bare-metal Linux/KVM (not WSL), 2-vCPU boot works without quantum-sched.
Four bugs fixed:

- [x] Enable VIRTUALIZE_APIC_ACCESSES (bit 0) for child VMs so LAPIC MMIO
  writes (ICR for SIPI) cause exits instead of going to memory silently
- [x] Add instruction decode (`decode_apic_write_value`) for APIC-access write
  exits — writel() uses arbitrary registers, not just RAX
- [x] Initialize VAPIC page per-VP (APIC_ID, SVR, masked LVTs)
- [x] EOI emulation: clear highest ISR bit on EOI write (offset 0xB0)
- [x] Fix IPI destination routing: capavisor reads ICR_HIGH from VAPIC[0x310],
  CHV extracts dest APIC ID from MSI address for irqfd vp_index
- [x] Fix thhv lost-wakeup race: `pending_inject` atomic counter prevents
  missed wakeups between HLT exit read and halted=1 set
- [x] Result: 2-vCPU dom1 boots, both CPUs activated (12000 BogoMIPS)

### Done: Phase 2 — Stock kernel + systemd boot (2026-04-03)

- [x] Remove `init=/bin/bash` from run-dom1.sh kernel cmdline
- [x] Add initramfs auto-detection (stock kernel needs it for modules)
- [x] Result: 1-vCPU and 2-vCPU dom1 boot to login prompt with full systemd

### Done: Code review cleanup (2026-04-03)

- [x] Added `skills/code-review.md` with conventions
- [x] Replaced magic numbers with named constants in vmexit.rs and CHV mod.rs
- [x] Removed stale TODOs and unconditional debug prints
- [x] `cargo fmt` for capavisor
- [x] Identified VMEXIT dispatch unification as next refactor target

### Next: Phase 3 — VMEXIT dispatch unification

**Goal**: Merge the two `match basic_reason` blocks in `handle_vmexit` (child
vs dom0) into a single dispatch table per `skills/code-review.md`.

**Approach** (incremental, avoid the all-at-once rewrite that broke dom0):
1. Extract dom0-specific local handlers into named functions (`handle_rdmsr_local`,
   `handle_cr_access_local`, `handle_ept_violation_dom0`, etc.)
2. Test each extracted function independently (dom0 must still boot)
3. Add `has_parent` flag and merge the dispatch, calling shared handlers from
   both paths
4. Remove the old child block once all handlers are merged

**Key pitfall** (discovered 2026-04-03): dom0 EPT violation handler has IOAPIC
MMIO emulation logic. Calling `forward_child_exit` for dom0 deadlocks because
dom0 has no parent. Must handle locally.

### Next: Phase 4 — Posted interrupts (hardware PI)

**Goal**: Enable hardware posted interrupts for child VMs.

**Prerequisites** (from `testing-posted.md`):
- [ ] Add `intel_iommu=on` to host kernel cmdline (requires reboot)
- [ ] QEMU: `intel-iommu,intremap=on,caching-mode=on,device-iotlb=on,aw-bits=48`
- [ ] QEMU: `-cpu host,host-phys-bits=on`
- [ ] QEMU: virtio devices with `iommu_platform=on,ats=on`
- [ ] Re-enable PI bit 7 in vmcs.rs child pin-based controls
- [ ] Remove software PIR drain guard (or keep as fallback)
- [ ] Test 1-vCPU and 2-vCPU dom1 boot with hardware PI

### Next: Phase 5 — Stabilization + real hardware

- [ ] Test with 4 CPUs
- [ ] Test on real hardware (not nested KVM)
- [ ] Dom1 networking (ping 192.168.100.2 from dom0)
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
15 tutorial scenarios + 6 regression tests. **21/21 tests now match — ALL PASSING.**

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
| — | Stale handles after revoke (engine + CLI) | 09 | ✅ Fixed (0b432b6, 470caf7) |
| — | Lean carve/alias guard ordering (ownership before API) | 07 | ✅ Fixed (294af31) |
| — | Channel attest/forwarding/accept-removes-sender | 14,15 | ✅ Fixed (e2e935e) |
| D | Accept unmap, revoke re-map parent, META handling | 07 | ✅ Fixed (4fccf1c) |
| K | GPA mapping + overlap check in send | 08 | ✅ Fixed (4fccf1c) |

**Also fixed in Cat B batch:**
- Child domain default interrupt policy: `.deliverAndClear` (Report), was `.deliver` (Deliver)
- Local handles start at 1 (matching Rust), was 0
- Attribute separator in attest reports: pipe `|` (matching Rust `Display`)
- GPA address space sorted by start address
- COMM `register-comm` error messages match Rust (PermissionDenied for guards, exact wording)
- GPA line/address space: only shown for child domains (root has no address_map)

**Also fixed in channel batch (e2e935e):**
- gChanMap stores target domain ID directly (avoids stale lookups)
- acceptChannel removes sender's channel handle (matching Rust)
- Attest Children count includes channels targeting domain (CDT scan)
- ch0 = Channel → d0 expansion in attest report
- Channel "domains" appear in list output with correct ordering
- list_domains sorted by ID (matching Rust)

**Fixed in 4fccf1c (tutos 07 + 08):**
- Accept: removed incorrect META check from sender unmap (sender always unmapped for carved caps)
- Revoke: parent re-map with `parentOwner != childOwner` guard (skips same-owner e.g. COMM)
- Revoke: VITAL trigger only emits RevokeDomain — **WRONG**: matches Rust bug, needs cascade (see TODO below)
- computeAddressSpace: `excludeMeta` parameter — view excludes META, attest includes it
- memCapToJson: skip children owned by revoked domains — **WORKAROUND**: remove after cascade is implemented
- Sorted "Removed memory capability" messages for deterministic output
- GPA support: `gpa` field in PendingMemCap, `gpaOverrides` in ExecDomain
- GPA stored on send (direct + pending) and accept, applied in computeAddressSpace
- View command uses identity mapping (GPA=HPA), attest shows actual GPA
- GPA overlap check uses full cap ranges including carved-out blocked entries

### BUG: VITAL memory revocation does not cascade domain cleanup

**Severity**: High — causes permanent memory range loss.

**Summary**: When a VITAL memory capability is revoked (e.g., a META region),
the owning domain is killed (EPT torn down, cores redirected), but the domain's
memory capabilities are never cleaned up. Memory ranges sent to the dead domain
become permanently inaccessible zombies.

**Two paths to domain death — only one cascades:**

1. **Explicit `revoke-domain parent child_handle`** → calls `revoke_domain_subtree`
   → recursively revokes child domains, revokes all root memory caps, generates
   re-map updates so parent domains regain their carved ranges. **Works correctly.**

2. **VITAL trigger** (from `revoke_subtree` when revoking a VITAL memory cap) →
   only emits `Update::RevokeDomain` in the batch → `execute()` calls
   `apply_update` (EPT freed) + `on_domain_revoked` (cores redirected) →
   **no cascade**. Memory caps owned by the dead domain remain as zombies in the
   CDT tree. Parent domains never get re-map updates for ranges they carved and
   sent to the dead domain.

**Concrete example:**
```
init root 0x40000
create-domain root app ...
carve r0 app_code 0x0 0x10000 RWX
send app_code app
seal app
carve r0 monitor_scratch 0x20000 0x4000 RW
send monitor_scratch app META       # META implies VITAL
accept-capability app 0
revoke r0 monitor_scratch           # VITAL fires → app killed
# Result: app_code [0x0..0x10000) is a zombie.
# Root's EPT does not map [0x0..0x10000). Nobody can access it.
# `attest root` still shows app as a child domain.
```

**Root cause**: `revoke_subtree` (capability.rs:554-555) emits `RevokeDomain` as
a batch update but does not call `revoke_domain_subtree`. The update tells the
platform to tear down the EPT and redirect cores (the immediate safety part), but
nobody triggers the cascade that reclaims memory caps.

**Why the barrier matters**: The two-phase design (emit update → platform applies)
exists because cores running the dead domain must be stopped and synchronized
before the domain's state can be fully dismantled. The VITAL path handles phase 1
(barrier + EPT teardown) but is missing phase 2 (cascade cleanup).

**Possible fixes** (needs design discussion):
- (a) After `execute` returns in `do_revoke_mem` / the CLI's `revoke_mem`, scan
  the batch for `RevokeDomain` entries and call `revoke_domain_subtree` for each.
  The barrier already happened so it's safe, but this adds a second `execute` call.
- (b) Have `revoke_subtree` call `revoke_domain_subtree` directly when VITAL fires
  (instead of just emitting the update). This would produce the cascade updates in
  the same batch, but needs careful lock analysis (domain write lock may conflict).
- (c) Add a platform callback or notification so the monitor (dom0) knows a domain
  died and can explicitly call `revoke-domain` to clean up.

**Affected code:**
- `capa-engine/src/capability.rs:554-555` — VITAL trigger (only emits update)
- `capa-engine/src/capability.rs:695-760` — `revoke_domain_subtree` (the cascade that should run)
- `capa-engine/src/platform.rs:414-417` — `on_domain_revoked` (only redirects cores)
- `themis/capavisor/src/hypercall.rs:331-336` — `do_revoke_mem` (doesn't post-process batch)
- `themis/capavisor/src/platform.rs:1563-1572` — `apply_update(RevokeDomain)` (only frees EPT)

**Impact on Lean model**: The Lean model should implement the CORRECT behavior
(cascade on VITAL), not match Rust's bug. See next section.

---

### TODO: Implement VITAL cascade in Lean + revert workarounds

**Context**: During differential testing, Lean was "fixed" to match Rust's buggy
VITAL behavior (no cascade). This is wrong — the Lean model should be the
reference for correct behavior. Three changes need to be made:

**1. Add `revokeDomainCascade` to Lean (Memory.lean)**

Implement the cascade that Rust's `revoke_domain_subtree` does (but that the
VITAL trigger skips). When a VITAL cap triggers domain death:

1. Mark domain + all descendants as revoked (early — prevents VITAL duplicates)
2. Emit `RevokeDomain` for each with proper fallback
3. Recursively revoke child domains (DFS)
4. Process "root memory caps" (parent owned by different domain) — call
   `revoke` on them from the parent to restore parent's access via re-map
5. Clean up channels and COMM bindings

Reference: Rust's `revoke_domain_subtree` (capability.rs:695-829) does exactly
this in 5 phases: early revocation, recursive children, root cap revocation,
channel cleanup, COMM cleanup.

**2. Remove DTO workaround: filter revoked children from memCapToJson (FFI.lean ~line 669-679)**

This filter hides zombie memory caps (children owned by revoked domains) from
the attestation DTO. With proper cascade, zombies won't exist — they'll be
properly revoked and removed from the CDT. Remove the filter.

**3. Review: filter revoked domains from ffiListDomains (FFI.lean ~line 649-650)**

This filter hides revoked domains from list_domains output. This one may actually
be correct independently — it mirrors what the CLI's `update_processor` does when
it receives a `RevokeDomain` update (removes the domain from `state.domains`).
Review whether to keep it as defense-in-depth or remove it.

**Expected outcome**: Lean diverges from Rust on tuto 07 (Lean correct, Rust
buggy). The diff test should be marked as expected-divergence until the Rust bug
is fixed.

**Review of all other fixes (15+ changes)**: All other fixes from commits
`e2e935e` and `4fccf1c` are independently correct:
- GPA mapping support (Types, Memory, Query, FFI, Engine) — correct
- GPA overlap check — correct
- Parent re-map after revoke (childOwner != parentOwner guard) — correct
- Channel forwarding, accept-removes-sender, attest children — correct
- Sorted "Removed memory capability" messages — correct (determinism)
- Accept META unmap fix — correct

---

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
