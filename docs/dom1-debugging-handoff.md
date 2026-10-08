# Dom1 debugging handoff

Updated October 8, 2026. The goal is reliable dom1 Linux boot and networking
under Themis, while preserving capability enforcement and parent scheduling
authority. **The boot/liveness issue is unresolved.** This is a record of
observations and reproducible procedures, not a diagnosis to adopt.

## Review and transfer status

The parent repository and `cloud-hypervisor` submodule are both on
`debug/dom1-linux-handoff`. After compilation checks, the user authorized
local commits on October 8, 2026; no push was authorized or performed.
CHV commit: `80a60d29347d82573ab83c96b186667306e2234b`. The parent commit
containing this handoff records that gitlink. Transfer both repositories'
commit objects (for example using Git bundles); a parent bundle alone does
not carry the submodule's commit objects.

Base revisions before the handoff changes:

- Parent: `3593ea07936f51454bb19e704db5e20de31180ec`.
- Cloud Hypervisor: `ea45eca55d5faa43f09da78d46c3d155e589b36a`.

Read `CONTEXT.md`, the newest `todo.md` entry, and relevant `skills/` files.
Older notes contain obsolete paths and proposals. In particular,
`quantum-sched` is not an available feature; do not restore it as a prerequisite.
The authoritative blocked VP chain already exists in the engine
(`CoreContext.call_stack` and `Waiting::unlocks`).

### External Linux instrumentation

The guest Linux checkout is outside this repository, at
`/home/aghosn/Documents/Programs/linux` on the old host. Its branch is
`v6.19.14-themis`, base commit
`44df971c640f8618de24aa08a9019496353e1b47`. As verified on October 8,
18 files still have uncommitted changes: `special_insns.h`, APIC handling,
init/exec, cgroup/kernfs, percpu-rwsem, RCU, idle and timer paths. These were
not removed by the capavisor/VMM cleanup.

The current source has two separate gates: guest `themis_trace_enabled`
controls whether `themis_trace()` issues a VMCALL, while capavisor's runtime
gate controls serial output. `run_init_process()` in `init/main.c` calls
`themis_trace_set_enabled(true)` before `kernel_execve()`. That helper also
issues the debug-toggle VMCALL, enabling capavisor runtime logging.
Consequently, turning logging off before boot is not sufficient for a quiet
run of a kernel built from this source. Turning it off from dom0 afterward
suppresses printing, but does not clear the guest flag or remove its calls.
There is no documented guest runtime interface for clearing that flag.

Do not assume the packaged `guest/kernel/bzImage` exactly matches this working
tree. Kernel compilation and image packaging are separate steps; compare
hashes and explicitly select the kernel/modules when changing the baseline.
At the user's request, Linux is carried as
`themis/debug/linux-instrumentation.patch` in the parent repository, **not**
as a new Linux branch or commit. Application/build instructions and the base
revision are in `themis/debug/README.md`. Applying the patch to the exact base
in an isolated Git index was verified to reproduce all 18 changed files in
the source checkout. The original Linux worktree and branch were left intact.

The separate evidence bundle also includes `cleanup/linux.config` and
`cleanup/linux-base-revision.txt`, not a full Linux checkout. Preserve the
configuration with the patch when transferring to the next machine.

## What was cleaned and what remains

Removed temporary execution profiling (`execution-stats`, VP-TIME/SWITCH-COST),
timer/PIR/entry trace counters, unconditional diagnostic VMCS reads, CHV exit-rate
counters, and one-off cgroup/network init-script installers. Removed whole-file
and individual-hunk formatting churn only when old and new code normalized
identically through rustfmt. This eliminated the unrelated engine/ARM diffs.
Routine CHV exit/IO/MMIO/LAPIC tracing now uses its normal debug log level.
Errors and fatal diagnostics remain.

Retained functional changes, which still need normal review:

- External interrupt injection respects an occupied VM-entry event slot;
  PIR bits remain pending, and VPs without a PID have a VP-local pending bitmap.
  The cached deadline check runs after pending COMM register writes.
- Interrupted-event replay from `IDT_VECTORING_INFO`, including error code.
  This is not a claim that all event/exception arbitration is complete.
- Earlier CPUID/XSAVE restrictions matching the implemented x87/SSE/AVX state
  storage; EPT doorbell and exact xAPIC EOI handling; hardware-VID delivery path.
- Driver retry-loop `cond_resched()` instead of a forced sleep after every
  physical-interrupt return.
- Earlier guest image/module/network preparation and configurable console sinks.
  These matter to reproducing the actual workload, not just logging.

The cleanup intentionally did not redesign or silently remove these **provisional
timer behaviors**:

- Capavisor emulates child TSC deadlines using its existing VMX preemption timer
  and fixed vector `0xec`. The user wants a future timer design not founded on
  VMX preemption counters; no replacement has been selected.
- thhv's HLT timeout converts TSC delta using a hard-coded 3 GHz assumption and
  has a retained-tick fallback. **This assumption may be wrong on the new host.**
- CHV no longer owns the old TSC-deadline timerfd path. Its xAPIC timer-register
  shadow is not a complete timer implementation; reprogramming is a no-op.
- The existing exact EOI fast paths and software interrupt-delivery fallback
  are not proof of complete APIC priority/mask semantics.

Treat these as reviewable implementation limitations, not established causes
of the observed failure. Timer/driver behavior was preserved to avoid mixing
cleanup with another unvalidated functional experiment.

## Previous environment and observations

The old host was WSL2 (`6.6.87.2-microsoft-standard-WSL2`) under Microsoft
Hyper-V, exposing an i7-1185G7 / 3 GHz TSC. KVM reported `nested=Y`,
`enable_shadow_vmcs=N`, `enable_apicv=N`. The tested stack was:

```
Hyper-V -> WSL2 Linux/KVM -> QEMU/Themis -> dom0 Linux -> CHV/dom1 Linux
```

Moving to a native Linux host removes the Hyper-V/WSL layer; running Themis
under QEMU/KVM still uses nested VMX. Verify actual exposed features rather
than assuming shadow VMCS or APICv will become available.

QEMU used four CPUs and 4 GiB. Dom0 ran `6.8.0-142-generic`; its matching
config reported `CONFIG_HZ=1000`. Dom1 used the packaged `6.19.14+` kernel
and Ubuntu 24.04.4 userspace, one VP and 1 GiB.

Observed before cleanup:

- Direct-init networking worked in an earlier run. This did not establish
  that normal systemd boot or all timer paths worked.
- Normal boot varied: RCU/timer stalls and soft lockups in earlier runs;
  later runs progressed slowly through systemd startup without networking.
- The occupied-entry-slot bug was reproduced in host arbitration tests:
  a selected timer could be overwritten by a later PIR drain before entry.
  Two tests failed with the old eligibility logic; all five pass with the fix.
  These tests do not execute VMX instructions.
- With that fix, a 600-second run still timed out with no successful ping and
  zero tap packets. It reached `systemd-udev-trigger` startup, beyond an earlier
  stopping point around `lvm2-monitor`. One variable run does not establish an
  improvement or a causal relationship to either service.
- Dom0 SSH remained responsive. Physical interrupt forwarding and sampled
  timer-entry activity continued. No VM-entry assertion/fatal error was observed
  in that run. This does not prove timely delivery or guest handler completion.
- Dom0 switched from TSC to HPET around 333 seconds in both baseline and
  entry-fix runs. Timeout teardown produced `REVOKE_MEM ... failed (-2)` in
  both. Neither was isolated as the boot cause.

### Removed profiler's results

These are **instrumented, pre-cleanup** results, not a native-host baseline:

| Run | Entry-to-exit interval | Active VP handling | VP inactive | Same RIP at sampled physical exit |
|---|---:|---:|---:|---:|
| Dev, 120 s | 17.93% | 31.59% | 50.48% | 573 / 998 |
| Release, 120 s | 17.36% | 32.07% | 50.57% | 587 / 1033 |
| Release, timer snapshot disabled, 120 s | 17.27% | 14.14% | 68.60% | 684 / 1259 |

The timing bracket wrapped `ActiveVcpu::run`, including entry/exit support code,
VMCS reads, and replay bookkeeping. It included outer-host descheduling and
nested VMX overhead, not just guest execution. Inactive means between VP
deactivation and activation, not solely Linux scheduler wait. An unchanged
RIP is not an instruction-retirement measurement. HLT-associated inactive gaps
were small in those samples; physical exits accounted for most inactive time.

Further probes on the physical-interrupt return path measured approximately
2.32 us engine transition, 425.48 us COMM register copying, and 30.87 us VP
swap per return. A temporary vector-236 `read_set=NONE` override reduced the
copy cost to 0.51 us, but the guest still failed to complete boot in 120 seconds.
Visibility remained NotReport, write_set ALL, injectable true. The override
was a guest-only bind mount, then removed; no permanent policy change remains.

Thus release optimization and removing that snapshot were not sufficient
solutions in the tested environment. Missing VMCS shadowing is consistent
with expensive nested register access, but **the environment was not proven
to be the sole cause**. The next agent should form its own hypothesis from a
fresh baseline. Cleanup also removed work done solely for diagnostics, so
historical percentages should not be extrapolated to the cleaned build.

## Reproduction on the new Linux host

Use `docs/building.md` for dependencies and image setup. Transfer or rebuild
the guest kernels, matching modules, dom0 disk/seed, dom1 disk and bins image;
they are not all tracked by Git. Preserve local guest-kernel modifications
if transferring an instrumented kernel. Check `/opt/bins/version.txt` and
kernel/image hashes when comparing runs.

Record the host without changing global KVM settings:

```sh
uname -a
lscpu
cat /sys/module/kvm_intel/parameters/nested
cat /sys/module/kvm_intel/parameters/enable_shadow_vmcs
cat /sys/module/kvm_intel/parameters/enable_apicv
```

Build from the parent repository, then boot from `themis/`:

```sh
cargo build-bins
cd themis
PROFILE=release cargo themis > /tmp/themis-serial.log 2>&1
```

Leave that terminal running; use another terminal for SSH. Do not rebuild or
rewrite guest images while QEMU has them open. Explicitly use the same profile
for comparisons: `cargo themis` otherwise defaults to the dev build.

```sh
ssh -o BatchMode=yes -o StrictHostKeyChecking=no -p 2222 cloud@localhost
uname -r
cat /opt/bins/version.txt
sudo env CHV_CPUS=1 CHV_SERIAL=null \
  CHV_CONSOLE=file=/tmp/dom1-console.log \
  KERNEL_APPEND="loglevel=4 systemd.unit=multi-user.target systemd.default_timeout_start_sec=300s" \
  timeout 600 /opt/bins/cloud-hypervisor/run-dom1.sh --themis \
  > /tmp/dom1-launch.log 2>&1
```

A timeout exit status of 124 means the bounded run ended; it is not by itself
a guest crash. Shorter runs are useful when a specific failure is already
reproduced. The script appends several clocksource/service masks and disables
cloud-init; inspect its full generated command line. Account provisioning
may therefore be absent even if networking works.

In a separate dom0 SSH session:

```sh
sudo tail -50 /tmp/dom1-console.log
sudo tail -50 /tmp/chv-stderr.log
ip -s link show tap-dom1
ping -c 3 -W 1 192.168.100.2
```

**Log ownership and routing matter:**

- Outer `/tmp/themis-serial.log`: capavisor + dom0, not dom1's normal console.
- Dom0 `/tmp/dom1-console.log`: actual dom1 virtio console, root-owned.
- Dom0 `/tmp/chv-stderr.log` and `/tmp/chv-stdout.log`: actual CHV output;
  `run-dom1.sh` redirects these internally. The launcher log is not CHV stderr.
- `CHV_SERIAL=null` intentionally discards early UART output. For a separate
  early-boot investigation use `CHV_SERIAL=file=/tmp/dom1-uart.log`, recording
  that difference from the historical workload.

Copy all relevant logs off dom0 before stopping QEMU. Use Ctrl-C in the owned
launcher terminal, or terminate its specific PID, not a name-wide kill.

## Debug controls after cleanup

### Capavisor runtime debug

`serial_rtdbg!` is off at boot. Existing local helper, run as root **inside dom0**:

```sh
sudo /opt/bins/tools/toggle-debug 1
sudo /opt/bins/tools/toggle-debug 0
```

Expect `[RTDBG] runtime debug ENABLED/DISABLED` in outer serial and status zero
from the helper. This controls runtime routing traces and `THEMIS_DBG_PRINT`
output. It does not enable compile-time verbose logs or suppress fatal output.
The current helper prints argument zero after either call; trust the serial
state-change message, not that printed argument.
The existing helper uses a raw diagnostic VMCALL; it is a legacy debugging
exception, not a pattern for adding userspace hypercalls (normal ABI uses thhv).

`THEMIS_DBG_PRINT` now uses this runtime gate for all trace codes, rather than
the previous hard-coded subset and timer tracing trigger. Guest instrumentation
still incurs its VMCALL while printing is disabled if its guest-side flag is
enabled. The current external kernel source also turns the capavisor gate
back on at init launch; see the external instrumentation section above.

### Capavisor compile-time verbose

```sh
PROFILE=release CAPAVISOR_FEATURES=verbose cargo themis > /tmp/themis-verbose.log 2>&1
```

Unset `CAPAVISOR_FEATURES` and rebuild/reboot to turn it off. `serial_debug!`
is gated by that feature; disabled logging no longer evaluates its arguments
(including diagnostic VMREADs). `serial_println!` remains unconditional.
The temporary `execution-stats` feature has been removed.

### Driver and VMM

thhv keeps rate-limited HLT `pr_debug` sites. On a guest kernel with dynamic
debug enabled and debugfs mounted, use:

```sh
echo 'module thhv +p' | sudo tee /sys/kernel/debug/dynamic_debug/control
sudo dmesg -w
# Disable in another shell:
echo 'module thhv -p' | sudo tee /sys/kernel/debug/dynamic_debug/control
```

If the control file is absent, check the guest kernel's dynamic-debug/debugfs
configuration rather than assuming the command succeeded.

CHV's normal levels are: no `-v` = warn, `-v` = info, `-vv` = debug, `-vvv` =
trace. The launcher already passes one `-v`; adding `CHV_EXTRA_ARGS=-v` enables
debug. Omit the extra argument on the next launch to return to info. Some
older startup/error `eprintln!` sites remain unconditional.
`SYSTEMD_DEBUG=1` adds guest systemd debug logging; omit it for normal runs.

Use short, explicit debug windows: logging itself can materially alter
timing. Record which controls were enabled. For kernel trace codes and
`themis_trace()`, see `skills/debugging-dom-boot.md`.

## Working constraints and evidence

Preserve engine validation before hardware changes, the existing VP chain,
parent-controlled SWITCH and physical interrupt preemption. Do not silently
drop/defer parent interrupts, add a parallel scheduler, or claim a timing
workaround establishes correctness. These constraints do not predetermine
which implementation is faulty.

The old machine's evidence is under session
`7c80019f-c715-4b45-82b2-f92b0aa18941/files/`: `entry-event-fix/`, `vp-time/`,
`intr-snapshot-policy.json`, and pre-cleanup parent/CHV patches. These paths
are not part of Git. Copy the evidence bundle separately if raw logs are
needed; the observations above are intended to stand alone.

Portable evidence bundle on the old host:
`/tmp/themis-dom1-evidence-2026-10-08.tar.gz`. It includes the historical
logs/pre-cleanup patches and cleanup build/smoke logs, current working-tree
patches, the new interrupt helper, external Linux patch/configuration and
this handoff. It is not a full guest image or guest Linux source backup.

Cleanup validation passed: five VMX host tests, engine tests, full binary
build/package, release capavisor with/without verbose, shell syntax and
diff checks. Packaging emitted a permission-preservation warning from sed
under fuse2fs while editing guest fstab, but returned zero.
The cleaned release booted dom0, SSH and both debug-toggle states worked.
A 45-second dom1 smoke run reached the Ubuntu welcome banner before timeout;
CHV shut down normally. No full boot/networking success or native-Linux-host
comparison is claimed. Logs were preserved and QEMU stopped.

On the user's subsequent pre-commit request, compilation was repeated:
full release `cargo build-bins`, dev and verbose-release capavisor, release
`capa-cli`, and external Linux `make -j4 bzImage modules` all passed. VMX and
engine tests passed again. Warnings remain, including unused Rust items,
thhv's compiler-version mismatch, two WireGuard stack-frame warnings, and
the packaging permission warning above; there were no build failures.
Logs are included as `cleanup/themis-precommit-*.log`.

The freshly built Linux image (#28) was deliberately not installed over the
packaged baseline. Their SHA256 prefixes are `76a4d6d4e7050ce6` (rebuilt) and
`f60d0ee662c62920` (packaged); full hashes are in
`cleanup/kernel-sha256.txt`. A hash difference can reflect build metadata
and does not by itself prove a source change. This kernel compilation check
is not a new boot test of that image.
