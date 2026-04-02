# Skill: Running and Testing Inside Capavisor + Dom0

## When to Use

Use this skill whenever you need to:
- Boot the full Themis stack (capavisor L0 + dom0 Linux L1) under QEMU
- Run commands, tests, or kernel modules inside dom0
- Observe the capavisor serial trace while simultaneously interacting with dom0
- Diagnose a hang or crash by inspecting the full trace after the fact

---

## Overview

The workflow has two parallel tracks:

```
[terminal 1 / async shell]                [terminal 2 / ssh]
  cargo themis  →  /tmp/out.txt             ssh cloud@localhost -p 2222
  (capavisor + dom0 serial trace)           (dom0 userspace)
         │                                         │
         └──────── if hang/crash ──────────────────┘
                   pkill qemu-system-x86_64
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

### Enabling quantum-sched (required for multi-core dom1)

To boot dom1 with multiple CPUs, you **must** enable the `quantum-sched`
feature.  Without it, dom0's 250 Hz LAPIC timer preempts the child before
any instruction executes (~100 µs nested VMRESUME overhead).

```bash
cd themis/
CAPAVISOR_FEATURES=quantum-sched cargo themis 2>&1 | tee /tmp/out.txt
```

This defers parent-bound interrupts while a child VP runs, then delivers
them on the next child exit (MMIO/EPT).  The preemption timer caps each
child quantum at ~20 ms.

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
# Run dom1 with 2 vCPUs (requires quantum-sched, see Step 1)
sudo CHV_CPUS=2 /opt/bins/cloud-hypervisor/run-dom1.sh

# Run dom1 with 1 vCPU (for debugging without quantum-sched)
sudo CHV_CPUS=1 /opt/bins/cloud-hypervisor/run-dom1.sh
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

# DBG_PRINT traces from guest kernel instrumentation
grep "\[DBG\]" /tmp/out.txt

# dom0 Linux kernel messages
grep -v "^\[" /tmp/out.txt | head -100
```

---

## Step 4 — Handling a Hang or Crash

If dom0 stops responding or the boot never completes:

### Kill QEMU

```bash
pkill -f qemu-system-x86_64
# or, if you have the PID:
kill $THEMIS_PID
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
CAPAVISOR_FEATURES=quantum-sched cargo themis 2>&1 | tee /tmp/out.txt

# 3. In a separate terminal — SSH into dom0
ssh cloud@localhost -p 2222

# 4. Inside dom0 — run dom1 (2 vCPUs)
sudo CHV_CPUS=2 /opt/bins/cloud-hypervisor/run-dom1.sh

# 5. Watch traces (from host)
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
| Boot command | `cargo themis` (repo root) |
| QEMU process name | `qemu-system-x86_64` |
| Kill QEMU | `pkill -f qemu-system-x86_64` |
| Networking | SLIRP user-mode, no external access needed |
