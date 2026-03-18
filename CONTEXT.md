# Themis Capability Hypervisor — Agent Context

This document is the authoritative reference for AI agents and developers working
on this codebase.  It is structured as **axioms first** (hard invariants that must
never be violated), followed by component descriptions, conventions, and operational
knowledge.  Read the axioms before making any change.

---

## 1. Axioms — Hard Invariants

These are non-negotiable constraints.  Violating any of them introduces security
holes or correctness bugs.  When in doubt, re-read this section.

### A1 — Capability engine validates before hardware

**The capability engine is the single source of truth.**
No hardware state may be changed before the capability engine has validated the
operation.  The only permitted pattern is:

```
capability_engine.validate(op) → apply_update() → hardware_write
```

Never write hardware first and validate later.  Never bypass `apply_update`.
Files: `themis/capavisor/src/capability.rs` (validation),
`themis/capavisor/src/platform.rs` (`apply_update` — the only hardware write site).

Always use the domain-mediated interface of the capability engine, never attempt to bypass it or access trees directly. If an interface/operation is missing for the current task, ask the user for help on the design.

### A2 — Dom0 is not privileged

Dom0 is the *first domain created*, nothing more.  It has no special trust level.

- Dom0 uses the same hypercall ABI as any child domain.
- Dom0 **must never have EPT mappings into capavisor memory** (the META pool).
- Dom0 can be revoked and capability-restricted like any other domain.
- Any domain holding child-creation capabilities can spawn further children — there
  is no unique recursive privilege belonging to dom0.

### A3 — EOI-exit bitmaps are always zero

Themis uses a **lazy-unwind interrupt model**, not EOI exits.
When a physical interrupt arrives while a child VP runs, the SWITCH call returns early
with RDI = preempting vector.  The parent handles it via its own interrupt handler.
Physical EOI is handled transparently by dom0's Linux kernel.

**Consequence**: never set any EOI-exit bitmap bit.  Never add code to handle
`EXIT_REASON_EOI_INDUCED` as a real policy mechanism.  P9f is closed as not needed.

### A4 — IOVA = GPA for all child domains

The IOMMU SLPT mirrors the EPT exactly.  When a device DMA's to address X,
the IOMMU and the CPU both translate X through the same page tables.
Never set up a child domain where IOVA ≠ GPA.

### A5 — META pool is capavisor-only

The META pool (hypervisor-internal pages: EPT tables, VMCS, VAPIC, PID, COMM pages)
must never appear in any domain's EPT.  It is physically separate from all guest
memory.  `apply_update::GiveMetaMem` is the only path that touches META, and it
never maps META into guest EPT.

### A6 — VpCommPage ownership

The VP COMM page is **allocated by userspace** (the VMM), not by the driver.
The driver pins it with `pin_user_pages_fast` and registers the HPA with capavisor.
**Never allocate the COMM page in kernel space and remap it.**  The existing pattern
(`THHV_CREATE_VP` ioctl takes `comm_uaddr` from userspace) is correct.

### A7 — thhv.ko is the only dom0↔capavisor interface

All hypercalls from dom0 userspace go through `thhv_hvcall.c` wrappers in the
`thhv` kernel module.  Never call VMCALL inline in userspace code.  Never add a
new capavisor hypercall without also adding the corresponding wrapper in
`thhv/src/thhv_hvcall.c` and declaring it in `thhv/inc/thhv.h`.

### A8 — inject_via_pid for cross-core interrupt injection

When injecting an interrupt to a VP running on a different core (or available/idle),
use `inject_via_pid(pid_phys, hhdm, vector, is_remote)` in capavisor.
Never write directly to the PIR or Posted Interrupt Descriptor from another core
without going through this path — it handles the ON/SN bits and NV IPI protocol.

### A9 — All domain interactions are mediated through the capability interface

Within capavisor, operations on domains **must go through the capability engine
interface** (`Capability::*`, `apply_update`, hypercall handlers in `hypercall.rs`).

- Never traverse the capability tree (e.g. `platform.domains`, `cap_table`) directly
  to read or mutate domain state from outside the engine's sanctioned paths.
- Never add ad-hoc methods that reach into `PlatformDomain` internals by bypassing
  `apply_update` or the capability lookup (`resolve_cap`, `child_ref`, etc.).
- The correct pattern for any new operation is: hypercall handler receives a
  capability handle → engine resolves it to a domain ref → engine validates the
  operation → `apply_update` materialises the change.
- This axiom exists because direct tree access breaks the invariant that all
  state transitions are auditable through a single validation point (A1), and
  because capability revocation relies on the engine owning all references.

### A10 — Always update todo.md when work is completed

After completing any task — whether it was pre-planned or discovered during
implementation — update `todo.md` at the repo root:

- If the item already exists: mark it `[x]` and add a brief ✅ DONE note with
  what was implemented and which files were changed.
- If the item does not exist: insert it under the appropriate phase with
  `[x]` and a DONE note. Never leave completed work undocumented.
- If a task was determined to be not needed or superseded: mark it with
  `[x] ✅ NOT NEEDED` or `[x] ✅ SUPERSEDED` with a one-line explanation.

This keeps `todo.md` as a living record of both planned and emergent work,
and ensures any future agent can reconstruct what was done and why.

### A11 — KISS: always seek the simplest solution first

Before implementing a fix, understand the root cause fully. Prefer the simplest
explanation and the smallest change. If a one-line fix exists, take it — do not
reach for architectural changes, new abstractions, or workarounds before
exhausting simple options. Two examples of violations: adding `isa-debug-exit`
and port-detection logic when removing `-no-shutdown` was the fix; fighting fstab
timing with systemd unit files when `/dev/vdb` directly was sufficient.

When debugging: **read the diff between the working and broken configuration
first**, before reasoning about internals.

---

## 2. Design Decisions (Settled — Do Not Relitigate)

These decisions were made after explicit discussion.  Do not change them without
a new explicit discussion with the user.

| Decision | Choice | Reason |
|----------|--------|--------|
| EOI-exit bitmaps | All-zero, unused | Lazy-unwind model handles Report policy via SWITCH return |
| COMM page allocation | Userspace-allocated, driver pins | Driver can register HPA with capavisor; VMM retains ownership |
| IRQFD poll mechanism | `fget` + `eventfd_ctx_fileget` + poll waitqueue | `eventfd_wq()` / `eventfd_fget` may not be exported in all kernels |
| IRQFD teardown | `cancel_work_sync` | Cancels if pending, waits if running — safer than `flush_work` |
| GSI = vector | Direct mapping (no routing table) | Simplified; full `THHV_SET_MSI_ROUTING` is future work (P15i) |
| Async VP exit | Deferred (P15-dc-m5) | Sync switch model sufficient for current use cases |
| Dom0 IRQ model | Deliver all vectors (passthrough policy) | Dom0 is trusted with all hardware initially |
| bins.img format | ext2 raw image + fuse2fs | Self-contained, no extra daemon, sudo-free |
| Docker build layer | Build-only (no QEMU) | QEMU needs KVM hardware access; only the build needs a stable toolchain env |

---

## 3. Component Map

```
capability-v5/
├── themis/                     # Capavisor (bare-metal hypervisor, Rust no_std)
│   ├── capavisor/src/
│   │   ├── capability.rs       # Capability engine — validates all operations (A1)
│   │   ├── platform.rs         # PlatformDomain, apply_update, hardware writes (A1)
│   │   ├── hypercall.rs        # Hypercall dispatch (do_* handlers)
│   │   ├── vmexit.rs           # VMEXIT handlers (interrupts, EPT, APIC, I/O)
│   │   ├── vmcs.rs             # VMCS field constants + per-VP setup
│   │   ├── domain.rs           # Domain lifecycle, VAPIC/PID/COMM allocation
│   │   └── boot.rs             # Early boot, IOMMU init, dom0 creation
│   ├── crates/
│   │   ├── ept/                # EPT mapper — also reused for IOMMU SLPT
│   │   └── themis-abi/src/lib.rs  # Shared ABI: hypercall numbers, structs
│   └── scripts/                # Build and boot scripts (see §6)
│
├── thhv/                       # mshv-compatible Linux kernel module (dom0 side)
│   ├── inc/thhv.h              # UAPI: all ioctl defs, structs, VP reg names
│   ├── src/thhv_part.c         # Partition lifecycle + ioctl dispatch
│   ├── src/thhv_vp.c           # VP lifecycle, RUN_VP loop, COMM page drain
│   ├── src/thhv_hvcall.c       # All VMCALL wrappers — THE only VMCALL site (A7)
│   ├── src/thhv_ioeventfd.c    # IOEVENTFD: doorbell GPA → eventfd signal
│   ├── src/thhv_irqfd.c        # IRQFD: eventfd → INJECT_INTERRUPT VMCALL
│   └── build-guest.sh          # Build thhv.ko + tests; copy to dom0 disk
│
├── cloud-hypervisor/           # Fork of cloud-hypervisor (git submodule)
│   └── hypervisor/src/themis/mod.rs  # Themis backend ~1250 lines, --features themis
│
├── 2026/                       # CLI / integration test workspace (Rust)
├── todo.md                     # Authoritative task tracker — read before any work
└── CONTEXT.md                  # This file
```

---

## 4. Hypercall ABI

All hypercall numbers are defined in `themis/crates/themis-abi/src/lib.rs` AND
mirrored in `thhv/inc/thhv.h` as `THEMIS_HC_*` / `THEMIS_OP_*`.  When adding a
new hypercall, update **both** files.

| Constant | Number | Description |
|----------|--------|-------------|
| `THEMIS_CREATE_DOMAIN`     | 0x01 | Create child domain |
| `THEMIS_CARVE_MEM`         | 0x02 | Carve memory into child (exclusive) |
| `THEMIS_SEND_MEM`          | 0x03 | Alias memory into child (shared) |
| `THEMIS_SEAL_DOMAIN`       | 0x04 | Seal domain (programs VMCS, IRTEs, IOMMU) |
| `THEMIS_SWITCH`            | 0x05 | Synchronous domain switch (run child VP) |
| `THEMIS_REVOKE_DOMAIN`     | 0x06 | Revoke child domain |
| `THEMIS_ADD_VP`            | 0x08 | Add VP to domain |
| `THEMIS_GET_REG`           | 0x09 | Get VP register via COMM page |
| `THEMIS_SET_REG`           | 0x0A | Set VP register via COMM page |
| `THEMIS_REGISTER_DOORBELL` | 0x10 | Register EPT-violation doorbell fast-path |
| `THEMIS_REVOKE_MEM`        | 0x11 | Revoke memory capability |
| `THEMIS_ASSIGN_DEVICE`     | 0x12 | Assign PCI device to child domain (IOMMU) |
| `THEMIS_RELEASE_DEVICE`    | 0x1A | Release PCI device back to dom0 |
| `THEMIS_INJECT_INTERRUPT`  | 0x1B | Inject interrupt via Posted Interrupt Descriptor |

---

## 5. Key Data Flows

### IOEVENTFD — guest write → VMM wakeup
```
guest write to doorbell GPA
  → EPT violation in capavisor
  → handle_ept_doorbell: writes DoorbellNotify to parent DomainComm RX ring,
    advances child RIP, resumes child immediately (no VP stop)
  → thhv_vp.c: thhv_drain_domcomm_rx(part) called after themis_switch returns
  → DOMCOMM_MSG_DOORBELL_NOTIFY matched → eventfd_signal → VMM worker wakes
```

### IRQFD — VMM write → guest interrupt
```
VMM writes to eventfd
  → poll waitqueue wakeup in thhv_irqfd.c
  → schedule_work → thhv_irqfd_inject workqueue
  → themis_inject_interrupt(domain, vp=0, vector) VMCALL
  → do_inject_interrupt: validates child cap, gets pid_phys
  → inject_via_pid(pid_phys, hhdm, vector, false)
  → PIR bit set in Posted Interrupt Descriptor → delivered on VMRESUME
```

### VP register set (bulk path via COMM page)
```
VMM writes register values + sets dirty_mask bits in VpCommPage (userspace memory)
  → THHV_SET_VP_STATE ioctl → driver writes to pinned COMM page kernel mapping
  → capavisor reads dirty_mask at SWITCH time → applies to VMCS before VMENTRY
```

---

## 6. Scripts & Commands Reference

### Build commands (from repo root)

| Command | What it does |
|---------|-------------|
| `cargo themis` | Build capavisor ISO + boot Themis + dom0 under QEMU |
| `cargo dom0` | Boot dom0 standalone under QEMU (no Themis) |
| `SEED=1 cargo dom0` | First boot: attach cloud-init seed to provision `cloud` user |
| `cargo fetch-dom0` | Download Ubuntu Noble cloud image + create seed.img |

### Script environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROFILE` | `debug` | `release` for optimised builds |
| `QEMU_CPUS` | `4`/`2` | vCPU count (run-qemu / run-dom0) |
| `QEMU_MEM` | `4G` | Guest RAM |
| `QEMU_ENABLE_KVM` | `1` | Use KVM acceleration |
| `QEMU_BIOS` | `0` | `1` = legacy BIOS |
| `SEED` | `` | `1` = attach cloud-init seed |
| `DOM0_VERSION` | `noble` | `noble` or `jammy` |
| `COPY_TO_GUEST` | `` | Guest home dir for binary copy (e.g. `/root`) |
| `BINS_SIZE` | `2G` | Size of bins.img (Phase 16.5) |
| `BINS_TARGETS` | `all` | `thhv,chv,2026` subset builds |

### Dom0 access
- User: `cloud` / Password: `cloud123` (provisioned by cloud-init on first boot)
- SSH: `ssh -p 2222 cloud@localhost`
- Test binaries land in `~/executables/` (populated by `build-guest.sh`)

### thhv.ko build
```bash
# With NBD mount (legacy, needs sudo):
sudo COPY_TO_GUEST=/root bash thhv/build-guest.sh

# Planned (Phase 16.5, no sudo):
bash themis/scripts/fetch-kheaders.sh   # download headers from Ubuntu apt
bash themis/scripts/build-bins.sh       # build everything + pack into bins.img
```

### cloud-hypervisor build
```bash
cd cloud-hypervisor
cargo build --features themis           # Themis backend
cargo build --features kvm              # KVM backend (must stay clean)
```

---

## 7. Coding Conventions

### Rust (capavisor)
- `no_std` environment — no heap allocation outside the META allocator.
- RwLockReadGuard lifetime: always use an explicit `let` binding before using
  the value, e.g. `let id = guard.read().data.id; id` — the guard drops before
  the binding is returned.  Inline use of `.read().field` as a return value
  keeps the guard alive too long and causes borrow checker errors.
- New hypercall handlers follow the pattern in `do_register_doorbell` /
  `do_add_vp`: validate child capability → extract fields → hardware write.
- Error return: `Err(ThemisError::ERR_PERM)` for capability failures,
  `Err(ThemisError::ERR_INVAL)` for bad arguments.

### C (thhv kernel module)
- All new source files must be added to `thhv/Kbuild`.
- Kernel-internal structs (`thhv_irqfd_entry`, `thhv_ioeventfd_entry`) go inside
  `#ifdef __KERNEL__` guards in `thhv/inc/thhv.h`.
- Use `cancel_work_sync` not `flush_work` in teardown paths.
- Use `fget` + `eventfd_ctx_fileget` not `eventfd_fget` / `eventfd_wq`
  (portability — not exported in all kernel versions).
- Nested struct pattern for list+lock: `struct { struct list_head list; struct mutex lock; }`.

### Rust (cloud-hypervisor Themis backend)
- All new code is gated `#[cfg(all(feature = "themis", target_arch = "x86_64"))]`.
- Never change KVM or mshv paths.
- Stubs that are genuinely not applicable return `Ok(())` (e.g. `set_fpu`,
  `set_lapic`).  Stubs that will be implemented later return a typed error.
- The `--features kvm` build must stay clean after every change.

---

## 8. Known Issues & Gotchas

| Issue | Detail |
|-------|--------|
| Double kernel log lines | Guest has `console=ttyS0` and `console=tty0`; both write to serial under `-serial mon:stdio`. Expected, not a bug. |
| Stale test binaries in guest | `~/executables/` was populated manually from old stubs. Refresh: `sudo COPY_TO_GUEST=/root bash thhv/build-guest.sh` |
| thhv.ko ABI mismatch | Building against wrong kernel headers produces an incompatible module that insmod silently rejects. Always match headers to `uname -r` of the guest. |
| `eventfd_wq()` not exported | Some kernel versions don't export this symbol. thhv_irqfd.c uses the poll_table callback approach instead — do not change this. |
| SWITCH returns EAGAIN | Normal under interrupt preemption — the driver retry loop in `thhv_vp.c` handles this. Not an error. |
| GSI = vector | `THHV_IRQFD.gsi` is treated as the interrupt vector directly. Full MSI routing is future work (P15i). |

---

## 9. Open Work (summary — see todo.md for details)

| Phase | Description | Blocked on |
|-------|-------------|-----------|
| 16.5 | Automated build & deploy (bins.img, no-sudo, Docker) | Nothing — **next** |
| 16f  | Verify virtio backends work end-to-end | 16h |
| 16h  | Boot Linux guest under cloud-hypervisor on Themis | 16.5 |
| 16e  | Device passthrough (`THHV_ASSIGN_DEVICE`) | 16h |
| 15-dc-m5 | Async VP exit delivery via DomainComm | Deferred |
| 17   | Dom0 networking | Independent |

---

## 2. Component Map

```
capability-v5/
├── themis/                     # Capavisor (bare-metal hypervisor, Rust)
│   ├── capavisor/src/
│   │   ├── capability.rs       # Capability engine — THE source of truth
│   │   ├── platform.rs         # PlatformDomain, apply_update, hardware writes
│   │   ├── hypercall.rs        # Hypercall dispatch (VMCALL handlers)
│   │   ├── vmexit.rs           # VMEXIT handlers
│   │   ├── vmcs.rs             # VMCS field constants + setup helpers
│   │   ├── domain.rs           # Domain lifecycle, VAPIC/PID allocation
│   │   └── boot.rs             # Early boot, IOMMU init, dom0 creation
│   ├── crates/
│   │   ├── ept/                # EPT mapper (reused for IOMMU SLPT)
│   │   └── themis-abi/         # Shared ABI constants (hypercall numbers, etc.)
│   └── scripts/                # Build, boot, and guest management scripts
│       ├── run-qemu.sh         # Boot Themis ISO + dom0 under QEMU
│       ├── run-dom0.sh         # Boot dom0 standalone (sanity check)
│       ├── build-iso.sh        # Build capavisor + Limine ISO
│       ├── fetch-dom0.sh       # Download Ubuntu cloud image + cloud-init seed
│       ├── dom0-versions.conf  # Pinned dom0 image versions + kernel paths
│       └── dom0-lib.sh         # Shared shell library for scripts
│
├── thhv/                       # mshv-compatible Linux kernel module (dom0 driver)
│   ├── inc/thhv.h              # Full UAPI: ioctl defs, structs, VP register names
│   ├── src/
│   │   ├── thhv_part.c         # Partition lifecycle + ioctl dispatch
│   │   ├── thhv_vp.c           # VP lifecycle + RUN_VP loop
│   │   ├── thhv_hvcall.c       # VMCALL wrappers (themis_switch, inject_interrupt…)
│   │   ├── thhv_ioeventfd.c    # IOEVENTFD: doorbell → eventfd signal
│   │   └── thhv_irqfd.c        # IRQFD: eventfd → INJECT_INTERRUPT VMCALL
│   └── build-guest.sh          # Build thhv.ko + test bins; copy to dom0 disk
│
├── cloud-hypervisor/           # Fork of cloud-hypervisor (git submodule)
│   └── hypervisor/src/themis/  # Themis backend: ThemisHypervisor/Vm/Vcpu
│       └── mod.rs              # Full backend (~1250 lines)
│
├── 2026/                       # CLI / integration tests (Rust workspace)
└── todo.md                     # Authoritative task tracker
```

---

## 3. Key Implemented Hypercalls

| Constant | Number | Description |
|----------|--------|-------------|
| `THEMIS_CREATE_DOMAIN`     | 0x01 | Create child domain (returns capability handle) |
| `THEMIS_CARVE_MEM`         | 0x02 | Carve memory into child domain |
| `THEMIS_SEND_MEM`          | 0x03 | Send (alias) memory to child domain |
| `THEMIS_SEAL_DOMAIN`       | 0x04 | Seal domain (programs VMCS, IRTEs, IOMMU) |
| `THEMIS_SWITCH`            | 0x05 | Synchronous domain switch (RUN child VP) |
| `THEMIS_REVOKE_DOMAIN`     | 0x06 | Revoke child domain (tears down EPT, SLPT, IRTEs) |
| `THEMIS_ADD_VP`            | 0x08 | Add VP to domain |
| `THEMIS_GET_REG`           | 0x09 | Get VP register (via COMM page) |
| `THEMIS_SET_REG`           | 0x0A | Set VP register (via COMM page) |
| `THEMIS_REGISTER_DOORBELL` | 0x10 | Register EPT-violation doorbell fast-path |
| `THEMIS_REVOKE_MEM`        | 0x11 | Revoke memory capability |
| `THEMIS_ASSIGN_DEVICE`     | 0x12 | Assign PCI device to child domain (IOMMU) |
| `THEMIS_RELEASE_DEVICE`    | 0x1A | Release PCI device back to dom0 |
| `THEMIS_INJECT_INTERRUPT`  | 0x1B | Inject interrupt via Posted Interrupt Descriptor |

---

## 4. IOEVENTFD / IRQFD Flow

### IOEVENTFD (guest → VMM notification)
1. Guest writes to doorbell GPA → EPT violation in capavisor
2. `handle_ept_doorbell` matches GPA, writes `DoorbellNotify` to parent DomainComm RX ring,
   advances child RIP, resumes child immediately
3. `thhv_vp.c`: after `themis_switch` returns, `thhv_drain_domcomm_rx(part)` is called
4. Driver matches `DOMCOMM_MSG_DOORBELL_NOTIFY` → `eventfd_signal` wakes VMM worker thread

### IRQFD (VMM → guest interrupt injection)
1. VMM writes to eventfd → kernel poll waitqueue wakeup
2. `schedule_work` → `thhv_irqfd_inject` workqueue function
3. `themis_inject_interrupt(domain, vp_id, vector)` VMCALL
4. `do_inject_interrupt` in capavisor: validates child cap, gets `pid_phys`, calls
   `inject_via_pid(pid_phys, hhdm, vector, false)`
5. PIR bit set in Posted Interrupt Descriptor → delivered on next VMRESUME

---

## 5. Cloud-Hypervisor Themis Backend

The Themis backend (`cloud-hypervisor/hypervisor/src/themis/mod.rs`, ~1250 lines)
is enabled with `--features themis`.

### Key design choices
- Opens `/dev/thhv` (not `/dev/mshv`); detected via `Path::new("/dev/thhv").exists()`
- VP creation allocates META pages (3 × PAGE_SIZE) and COMM page (1 × PAGE_SIZE)
  via anonymous `mmap`; passes UAs to `THHV_CREATE_VP` ioctl
- `set_fpu()` and `set_lapic()` are no-ops — Themis manages FPU/LAPIC via VMCS/APICv
- `boot_msr_entries()` returns empty — Themis handles MSRs internally
- Exit reason decoding: `themic_intercept_message` in `thhv_run_vp.msg_buf`
- GSI = vector (simplified; no full MSI routing table yet — future P15i)

### vmm wiring
- `vmm/src/vm.rs`: `is_themis` detection, `init_themis()` (creates interrupt controller
  + devices, skips mshv-specific irqchip init)
- `vmm/src/seccomp_filters.rs`: Themis ioctl allowlist (magic 0xB8)
- Feature passthrough: `vmm/Cargo.toml` and `cloud-hypervisor/Cargo.toml`
  both expose `themis = ["hypervisor/themis"]`

---

## 6. Build & Deploy

### Current workflow (requires sudo for NBD mount)

```bash
# Build capavisor + boot ISO
cargo themis                        # or: bash themis/scripts/run-qemu.sh

# Build dom0 standalone (sanity check)
SEED=1 cargo dom0                   # first boot: provisions cloud user
cargo dom0                          # subsequent boots

# Build thhv.ko + test binaries + copy to guest disk
sudo COPY_TO_GUEST=/root bash thhv/build-guest.sh

# Build cloud-hypervisor with Themis backend
cd cloud-hypervisor
cargo build --features themis
```

### Scripts reference

| Script | Purpose | Sudo? |
|--------|---------|-------|
| `themis/scripts/build-iso.sh` | Build capavisor + Limine ISO | No |
| `themis/scripts/run-qemu.sh` | Boot Themis ISO + dom0 under QEMU | No |
| `themis/scripts/run-dom0.sh` | Boot dom0 standalone under QEMU | No |
| `themis/scripts/fetch-dom0.sh` | Download Ubuntu image + seed | No |
| `themis/scripts/mount-guest.sh` | NBD-mount dom0 QCOW2 | **Yes** |
| `themis/scripts/umount-guest.sh` | Unmount NBD | **Yes** |
| `themis/scripts/resize-disk.sh` | Grow dom0 QCOW2 | No |
| `thhv/build-guest.sh` | Build thhv.ko, copy to dom0 disk | **Yes** (NBD) |

### Environment knobs (run-qemu.sh / run-dom0.sh)

| Variable | Default | Description |
|----------|---------|-------------|
| `PROFILE` | `debug` | `release` for optimized builds |
| `QEMU_CPUS` | `4` (qemu) / `2` (dom0) | vCPU count |
| `QEMU_MEM` | `4G` | Guest RAM |
| `QEMU_ENABLE_KVM` | `1` | Use KVM acceleration |
| `QEMU_BIOS` | `0` | `1` = legacy BIOS instead of UEFI |
| `SEED` | `` | `1` = attach cloud-init seed (first boot) |
| `DOM0_VERSION` | `noble` | `noble` or `jammy` |
| `COPY_TO_GUEST` | `` | Set to guest user home (e.g. `/root`) to copy binaries |

### Dom0 login
- User: `cloud` / Password: `cloud123` (provisioned by cloud-init seed on first boot)
- SSH: `ssh -p 2222 cloud@localhost` (port forward configured in `run-dom0.sh`)

---

## 7. Planned: Automated Build & Deploy (Phase 16.5)

The planned automation eliminates all sudo from the build/deploy workflow using
a separate `bins.img` artifact disk (ext2, FUSE-mounted) and downloaded kernel headers.
See `todo.md` Phase 16.5 for the full plan.

### Target workflow (post Phase 16.5)

```bash
# One-time tool install (sudo once only)
sudo apt install e2fsprogs fuse2fs qemu-utils cloud-image-utils xorriso

# One-time project setup (all sudo-free after)
cargo fetch-dom0                              # download Ubuntu image + seed
bash themis/scripts/fetch-kheaders.sh        # download + extract kernel headers
bash themis/scripts/create-bins.sh           # create empty bins.img

# Build everything and pack artifacts
cargo build-bins                             # native
cargo build-bins-docker                      # via Docker (older kernel hosts)

# Boot
SEED=1 cargo dom0                            # first boot
cargo dom0                                   # subsequent boots
```

### Two build paths

| Path | When to use | Requires |
|------|-------------|---------|
| **Native** (`cargo build-bins`) | WSL / recent Linux host | Rust toolchain, build-essential, fuse2fs |
| **Docker** (`cargo build-bins-docker`) | Older kernel / CI | Docker only |

Both paths produce the same `themis/guest/bins.img`.  QEMU boot always runs natively.

---

## 8. Known Issues / Gotchas

- **Double kernel log lines in QEMU serial**: Linux guest has both `console=ttyS0`
  and `console=tty0`; both write to the serial port under `-serial mon:stdio`.
  Not a bug — expected behaviour.

- **Stale test binaries in guest**: `~/executables/` in the QCOW2 guest are old stubs
  compiled before the full implementation was written.  Refresh with
  `sudo COPY_TO_GUEST=/root bash thhv/build-guest.sh`.

- **Sync vs async switch mode**: `THHV_SCHED_SYNC` is the only implemented mode.
  `THHV_SCHED_ASYNC` (DomainComm async VP exit delivery) is deferred to P15-dc-m5.

- **GSI = vector (simplified)**: In `THHV_IRQFD`, the `gsi` field is treated directly
  as the interrupt vector.  A full MSI routing table (`THHV_SET_MSI_ROUTING`) is
  future work (P15i).

- **`eventfd_wq()` not used in thhv_irqfd.c**: This kernel function may not be
  exported in all kernel versions.  Instead, `wqh` is saved in the poll_table callback
  and stored in the entry.

- **thhv.ko build requires matching kernel headers**: Use `fetch-kheaders.sh` (Phase
  16.5d) or the NBD-mount fallback.  Building against wrong headers silently produces
  an incompatible module.

- **Device assignment requires IOMMU + VT-d**: P15i/P16e depend on capavisor having
  IOMMU SLPT per child domain (done, P4e/P8d) AND the thhv driver wiring
  `THHV_ASSIGN_DEVICE` (not yet done).

---

## 9. Todo Tracker

The authoritative task list is `todo.md` at the repo root.  Key open phases:

| Phase | Focus | Status |
|-------|-------|--------|
| 15-dc-m5 | Async VP exit via DomainComm | Deferred |
| 16f | Verify virtio backends with Themis | Pending P16h |
| 16h | End-to-end: boot Linux guest under cloud-hypervisor on Themis | Blocked on 16.5 |
| 16.5 | Automated build & deploy (bins.img, no-sudo, Docker) | **Next** |
| 16e | Device passthrough (`THHV_ASSIGN_DEVICE`) | Requires 16h first |
| 17 | Dom0 networking | Independent |
