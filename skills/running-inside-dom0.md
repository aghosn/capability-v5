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

## Step 1 — Build and Boot (with trace capture)

Boot the full Themis stack and redirect all serial output to a file:

```bash
cargo themis > /tmp/out.txt 2>&1 &
THEMIS_PID=$!
echo "Themis PID: $THEMIS_PID"
```

Or equivalently from the scripts directory:

```bash
bash themis/scripts/run-qemu.sh > /tmp/out.txt 2>&1 &
```

`cargo themis` builds the ISO first (`build-iso.sh`), then launches QEMU.
The serial console (`-serial mon:stdio`) is the only output — all capavisor
`serial_println!` and dom0 kernel messages go to `/tmp/out.txt`.

**Wait for dom0 to be ready** by polling the trace:

```bash
# Wait until dom0's SSH server is accepting connections (up to ~90s).
for i in $(seq 1 90); do
    ssh -o StrictHostKeyChecking=no -o BatchMode=yes \
        -o ConnectTimeout=2 -p 2222 cloud@localhost true 2>/dev/null && break
    sleep 1
done
echo "dom0 ready"
```

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

```bash
ssh -o StrictHostKeyChecking=no -o BatchMode=yes -p 2222 cloud@localhost '
    sudo insmod /opt/bins/thhv/thhv.ko
    /opt/bins/cloud-hypervisor/cloud-hypervisor \
        --kernel /opt/bins/nested/bzImage \
        --memory size=512M \
        --cpus boot=1 \
        --serial tty \
        --console off \
        2>&1
'
```

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

## Step 5 — Full Example Workflow (agent-ready)

```bash
#!/usr/bin/env bash
set -euo pipefail

REPO="$(git rev-parse --show-toplevel)"
OUT=/tmp/out.txt

# 1. Boot
cd "$REPO"
cargo themis > "$OUT" 2>&1 &
QEMU_PID=$!
echo "QEMU PID=$QEMU_PID, trace: $OUT"

# 2. Wait for dom0 SSH
echo "Waiting for dom0..."
SSH="ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=2 -p 2222 cloud@localhost"
for i in $(seq 1 90); do
    $SSH true 2>/dev/null && break
    if ! kill -0 $QEMU_PID 2>/dev/null; then
        echo "QEMU exited early — trace:"
        tail -30 "$OUT"
        exit 1
    fi
    sleep 1
done

# 3. Run test
echo "dom0 ready — running test"
$SSH 'sudo insmod /opt/bins/thhv/thhv.ko && echo "thhv loaded"'

# 4. Inspect result
$SSH 'dmesg | grep -i thhv | tail -10'

# 5. Shutdown cleanly (optional)
$SSH 'sudo poweroff' || true
wait $QEMU_PID || true
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
