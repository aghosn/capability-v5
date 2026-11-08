# Skill: Running and Testing Inside Capavisor + Dom0

## When to Use

Use this skill whenever you need to:
- Boot the full Themis stack (capavisor L0 + dom0 Linux L1) under QEMU
- Run commands, tests, or kernel modules inside dom0
- Observe the capavisor serial trace while simultaneously interacting with dom0
- Diagnose a hang or crash by inspecting the full trace after the fact

---

## Overview

### Architecture versus the development environment

Themis is designed as a bare-metal hypervisor, but **our development tests
boot it inside QEMU/KVM, not directly on the physical machine**.

Within the Themis architecture:

- **Capavisor (L0)** is the Rust `no_std` hypervisor. The capability engine
  validates operations before capavisor changes VMCS/EPT/IOMMU state.
- **Dom0 (L1)** is the first Linux domain, not a privileged exception to
  capability enforcement. Its Cloud Hypervisor (CHV) userspace VMM uses
  `/dev/thhv` and the `thhv.ko` driver to manage child domains.
- **Dom1 (L2)** is the child Linux guest being debugged. The parent explicitly
  schedules its VPs through synchronous SWITCH; capavisor enforces authority
  and preserves parent interrupt/preemption paths.

These L0/L1/L2 labels describe Themis's logical architecture, not absolute
hardware virtualization levels when an outer hypervisor is present.

The development stack on a native Linux host is:

```text
Physical machine
  Host Linux + KVM
    QEMU virtual machine booting the Themis ISO
      Capavisor
        Dom0 Linux + thhv.ko + Cloud Hypervisor
          Dom1 Linux
```

The previous machine added Hyper-V and WSL2 beneath QEMU:
`Hyper-V -> WSL2 Linux/KVM -> QEMU/Themis -> dom0 -> CHV/dom1`.
Moving to "Linux bare metal" means the **host Linux** runs natively; Themis
still runs under QEMU/KVM for these tests, and nested virtualization remains.
It does not mean installing Themis as the physical machine's boot hypervisor.

Build and run QEMU on the host. SSH to port 2222 reaches **dom0**, where the
driver and CHV run; the instrumented Linux checkout is for **dom1**, not the
host kernel or dom0. Kernel location/base/patch details are in
`skills/debugging-dom-boot.md`. Full axioms and component descriptions are
in `CONTEXT.md`; reproduction and log routing are in
`docs/dom1-debugging-handoff.md`.

### Terminal workflow

The workflow has two parallel tracks:

```
[terminal 1 / async shell]                [terminal 2 / ssh]
  cargo themis  →  /tmp/out.txt             ssh cloud@localhost -p 2222
  (capavisor + dom0 serial trace)           (dom0 userspace)
         │                                         │
         └──────── if hang/crash ──────────────────┘
                   stop owned QEMU session / specific PID
                   grep / tail /tmp/out.txt
```

---

## Step 0 — Rebuild Bins (after code changes)

After modifying thhv, cloud-hypervisor, or capavisor, repack the bins image
from the **repo root**:

```bash
cargo build-bins
```

This rebuilds and packs all binaries into `guest/bins.img` (mounted as
`/opt/bins/` in dom0).

---

## Step 1 — Build and Boot (with trace capture)

Boot the full Themis stack from **inside the `themis/` directory**:

```bash
cd themis/
cargo themis 2>&1 | tee /tmp/out.txt
```

`cargo themis` builds the ISO first, then launches QEMU. All capavisor
`serial_println!` and dom0 kernel messages go to stdout and are captured in
`/tmp/out.txt`.

### Profile and debug controls

Use an explicit profile for timing comparisons. `quantum-sched` was an
experimental approach and is no longer an available feature. Do not suppress
parent interrupt preemption to make a child run.

```bash
cd themis/
PROFILE=release cargo themis 2>&1 | tee /tmp/out.txt
```

`CAPAVISOR_FEATURES=verbose` enables compile-time high-frequency logs.
For runtime traces and guest DBG_PRINT, run
`sudo /opt/bins/tools/toggle-debug 1` inside dom0; use `0` to disable them.
These controls are independent. See `docs/dom1-debugging-handoff.md` for
CHV verbosity, driver dynamic debug, reproduction commands and known limitations.

**Wait for dom0 to finish booting** (watch `/tmp/out.txt` for the login prompt
or cloud-init completion), then SSH in from a separate terminal (Step 2).

---

## Step 2 — SSH Into Dom0

Once dom0 is ready, connect with key-based auth (no password needed):

```bash
ssh -o StrictHostKeyChecking=no -o BatchMode=yes -p 2222 cloud@localhost '<command>'
```

**Important quoting rule**: always use **single quotes** around the remote command,
or use **absolute paths**.  Double-quoted `~` expands on the *host*, not the guest:

```bash
# WRONG — ~ expands to /home/<your-host-user>
ssh ... "ls ~/foo"

# CORRECT
ssh ... 'ls ~/foo'
ssh ... 'ls /home/cloud/foo'
```

### Running a one-shot command

```bash
ssh -o StrictHostKeyChecking=no -o BatchMode=yes -p 2222 cloud@localhost \
    'sudo insmod /opt/bins/thhv/thhv.ko && dmesg | tail -5'
```

### Running a longer interactive session

```bash
ssh -o StrictHostKeyChecking=no -p 2222 cloud@localhost
```

### Copying a file into dom0

```bash
scp -o StrictHostKeyChecking=no -P 2222 ./myfile cloud@localhost:/home/cloud/
```

### Running cloud-hypervisor (dom1) inside dom0

From a terminal SSH'd into dom0:

```bash
# Request 2 vCPUs (not a claim that current multi-core boot is validated)
sudo CHV_CPUS=2 /opt/bins/cloud-hypervisor/run-dom1.sh --themis

# One-vCPU baseline
sudo CHV_CPUS=1 /opt/bins/cloud-hypervisor/run-dom1.sh --themis
```

`thhv.ko` is loaded automatically by `run-dom1.sh` if not already loaded.

---

## Step 3 — Watch the Trace in Real Time

From a separate shell (or the same one with `tail -f`):

```bash
tail -f /tmp/out.txt
```

Filter for specific subsystems:

```bash
# Capavisor boot phases
grep -E "Phase|EPT|VMCS|VMXON|dom0|caps" /tmp/out.txt

# Hypercall trace (requires verbose feature build)
grep "VMCALL\|hypercall\|hc=" /tmp/out.txt

# DBG_PRINT traces from guest instrumentation (runtime toggle must be on)
grep "\[DBG\]" /tmp/out.txt

# dom0 Linux kernel messages
grep -v "^\[" /tmp/out.txt | head -100
```

---

## Step 4 — Handling a Hang or Crash

If dom0 stops responding or the boot never completes:

### Kill QEMU

```bash
# Prefer Ctrl-C in the owned launcher terminal, or stop its tool session.
# If using a PID, first verify it belongs to this run:
ps -p "$THEMIS_PID" -o pid,args
kill "$THEMIS_PID"
```

### Inspect the trace

```bash
# Last 100 lines — usually shows the crash / hang point
tail -100 /tmp/out.txt

# Last capavisor message before silence
grep -v "^$" /tmp/out.txt | tail -20

# Check for panics
grep -i "panic\|PANIC\|FATAL\|triple fault\|exit 33" /tmp/out.txt

# Check for VMEXIT errors
grep "VMEXIT\|VM entry\|exit reason" /tmp/out.txt | tail -20

# Check which hypercalls were in flight
grep "VMCALL\|\[HC\]" /tmp/out.txt | tail -10
```

### Common failure signatures

| Symptom in trace | Likely cause |
|---|---|
| `[FATAL] VM entry failed: VmFailValid` + `VM_INSTRUCTION_ERROR=N` | VMCS misconfiguration; look up error N in Intel SDM Vol 3C §30.4 |
| `exit 33` (VMENTRY_INVALID_GUEST) with register dump | Guest state violates VMCS consistency checks |
| `!!! PANIC:` | Capavisor Rust panic — stack trace follows |
| Stops after `Phase 2c: EPT build` | EPT allocation failure — META pool exhausted |
| SSH never becomes available but trace shows `cloud-init complete` | sshd didn't start; check `grep sshd /tmp/out.txt` |
| Trace stops mid-boot, no panic | Triple fault or hard hang; check last RIP if available |

---

## Step 5 — Full Workflow Summary

```
# 1. After code changes — repack bins (repo root)
cargo build-bins

# 2. Boot the stack (inside themis/)
cd themis/
PROFILE=release cargo themis 2>&1 | tee /tmp/out.txt

# 3. In a separate terminal — SSH into dom0
ssh cloud@localhost -p 2222

# 4. Inside dom0 — run the one-vCPU baseline
sudo CHV_CPUS=1 /opt/bins/cloud-hypervisor/run-dom1.sh --themis

# 5. Watch traces (from host, after enabling runtime debug in dom0)
grep '\[DBG\]' /tmp/out.txt | tail -30
```

---

## Reference

| Item | Value |
|------|-------|
| SSH host | `localhost` |
| SSH port | `2222` |
| SSH user | `cloud` |
| Auth | Key-based (`~/.ssh/id_*`), no password needed |
| Trace file | `/tmp/out.txt` (by convention) |
| Bins in dom0 | `/opt/bins/` (mounted from `guest/bins.img`) |
| Boot command | `cargo themis` (inside `themis/`) |
| QEMU process name | `qemu-system-x86_64` |
| Stop QEMU | Ctrl-C / stop owned tool session / verified specific PID |
| Networking | SLIRP user-mode, no external access needed |
