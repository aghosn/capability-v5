## Themis — Implementation Status & Plan

> **Archives**: Previous todo content archived to:
> - [`docs/archive/todos/archived_todo_09_03_2026.md`](docs/archive/todos/archived_todo_09_03_2026.md) — phases 0–15, BUG-1–15, dom0 bringup
> - [`docs/archive/session-notes/27_03_2026.md`](docs/archive/session-notes/27_03_2026.md) — full history through dom1 multi-core debugging
> - [`docs/archive/session-notes/07_04_2026.md`](docs/archive/session-notes/07_04_2026.md) — differential testing, VITAL cascade fix, TPM, code review

## Current Status

- **2026-10-08 — Linux patch and authorized local handoff commits**:
  User chose a portable patch, not a Linux branch/commit. Added
  `themis/debug/linux-instrumentation.patch` (all 18 tracked Linux changes)
  and `themis/debug/README.md` (base revision, application/build instructions,
  guest-only scope and trace-toggle caveats). An isolated Git index at Linux
  base `44df971c640f8618de24aa08a9019496353e1b47` accepted the patch and
  reproduced the source worktree exactly; original Linux files/index/branch
  were not changed. Source whitespace check passed.
  CHV committed as `80a60d29347d82573ab83c96b186667306e2234b` on
  `debug/dom1-linux-handoff`; the parent commit containing this entry pins
  that gitlink and includes the cleanup, regression tests and handoff.
  Only documentation and patch export changed after successful compilation.
  No push authorized or performed; no commit to either default branch.
  Updated `docs/dom1-debugging-handoff.md` and `todo.md` with transfer status.
  Dom1 boot remains unresolved; next work is a baseline on the native host.

- **2026-10-08 — explicit pre-commit compilation check (DONE)**:
  User asked whether Linux was instrumented and to verify compilation before
  committing. Confirmed 18 dirty files in external `../linux`, branch
  `v6.19.14-themis`, base `44df971c640f8618de24aa08a9019496353e1b47`.
  The source enables guest tracing and capavisor runtime debug at init launch;
  corrected handoff/trace skill to distinguish the two gates. Saved Linux
  patch/config/base revision in the migration evidence. Did not modify Linux.
  Fresh full release build/package (capavisor, CHV, engine, thhv plus its test
  binaries, 11 eunomia workloads, C tools), dev and verbose-release capavisor,
  CLI release build, five VMX tests and engine tests passed. Instrumented Linux
  `make -j4 bzImage modules` also passed: bzImage #28 and modules built.
  Shell syntax and parent/CHV whitespace checks passed. Nonfatal warnings:
  compiler unused items, thhv compiler-version mismatch, WireGuard stack-frame
  sizes, and existing fuse2fs/sed permission preservation during packaging.
  Rebuilt Linux was not installed over the existing packaged baseline:
  packaged kernel SHA256 starts `f60d0ee662c62920`, rebuilt `76a4d6d4e7050ce6`.
  Differing binary hashes alone do not prove a source-code difference.
  Build logs, Linux patch/config/revision and full kernel hashes are saved
  in the updated migration evidence bundle. No source fixes were needed.
  At this checkpoint nothing had been committed or pushed; see the later
  authorization and patch/commit entry above.
  Files modified: `docs/dom1-debugging-handoff.md`,
  `skills/debugging-dom-boot.md`, `todo.md` (instrumentation/build details).

- **2026-10-08 — cleanup and Linux-host handoff (DONE; review pending)**:
  Review branches created in parent and CHV: `debug/dom1-linux-handoff`.
  User explicitly forbids commits/pushes without full review, validation and
  approval. Nothing committed or pushed; transferring the branch alone is
  insufficient because work is uncommitted.
  - Removed execution-stats feature/counters, injected-entry and timer/PIR
    tracing, CHV rate counters and one-off cgroup/network init installers.
    Kept functional event preservation and earlier boot/CPUID/APIC changes.
    Kept provisional HLT/timer semantics unchanged; limitations called out.
  - Restored rustfmt-only files/hunks after proving normalized equivalence.
    Engine and ARM diffs were formatting-only; no engine behavior changed.
  - Fixed disabled `serial_debug!` argument evaluation; DBG_PRINT now uses
    the existing runtime toggle, without hard-coded trace-code selection.
    CHV routine exit/IO/MMIO/LAPIC traces use the standard debug log level.
  - Added `docs/dom1-debugging-handoff.md`: neutral observations, timing
    caveats, prior environment, reproduction and debug-toggle procedures.
    Pre-cleanup snapshots saved outside repo in session files.
  Files changed by cleanup (relative to the pre-cleanup working tree):
  - `themis/capavisor/src/main.rs`, `src/hypercall/mod.rs` — gate debug work
    and unify DBG_PRINT with the existing runtime switch.
  - `themis/capavisor/src/arch/x86_64/`: `hypercall/switch.rs`, `pid.rs`,
    `msr_emulator.rs`, `vcpu_switch.rs`, `hypercall/doorbell.rs`,
    `vmexit/apic.rs`, `x86_platform.rs` — remove experimental timing/logging.
    Retain functional paths; several files now match HEAD exactly.
  - `themis/capavisor/Cargo.toml`, `themis/crates/vmx/Cargo.toml`,
    `themis/crates/vmx/src/lib.rs`, `vcpu.rs` — remove profiling feature/hooks;
    deleted `execution_stats.rs`. Keep new `interrupts.rs` and five regressions.
  - `thhv/src/thhv_vp.c`, `thhv/src/thhv_irqfd.c` — remove unconditional
    diagnostic counters (irqfd now matches HEAD); retain dynamic-debug sites.
  - `cloud-hypervisor/hypervisor/src/themis/vcpu.rs` — remove rate probes,
    use debug-level logs; preserve functional CPUID/APIC/timer code.
  - `themis/scripts/run-dom1.sh`, `themis/scripts/update-bins.sh` — remove
    one-off cgroup/network init installers, clean retired files from images.
  - `skills/running-inside-dom0.md`, `skills/debugging-dom-boot.md` — correct
    removed scheduling-feature advice, debug controls, paths and log ownership.
  - `docs/dom1-debugging-handoff.md` (new), `todo.md` — portable handoff/status.
  - Formatting-only restoration: 92 whole files plus 65 hunks in mixed files;
    exact lists in evidence bundle. Restored generated `tools/toggle-debug`
    binary to HEAD after packaging; its source was unchanged.

  Validation: five VMX host tests, engine `cargo test`, full `cargo build-bins`,
  release capavisor with and without `verbose`, shell syntax, new helper
  rustfmt check, parent/submodule `git diff --check` all passed. Packaging
  emitted a fuse2fs/sed permission-preservation warning while rewriting
  guest fstab; command returned zero. No native-host run was possible.
  Cleaned release booted dom0; SSH responded and serial confirmed runtime
  debug ENABLED then DISABLED. The helper's printed argument is misleading
  (both calls printed zero); actual serial state transitions were verified.
  A bounded 45-second dom1 smoke launch reached the Ubuntu welcome banner;
  timeout returned 124 and CHV shut down normally. This is not a successful
  full systemd/networking boot and does not resolve the original problem.
  Owned QEMU stopped; logs preserved. Evidence archive:
  `/tmp/themis-dom1-evidence-2026-10-08.tar.gz` (copy separately from Git).
  Next step: user review of the uncommitted parent and CHV diffs, then transfer
  to the native Linux host and establish a fresh baseline using the handoff.
  No further timer/scheduler design is approved.

- **2026-10-08 — focused execution experiment (DONE; boot root cause UNRESOLVED)**:
  User explicitly redirected work away from broad information gathering.
  Narrow question: is time lost outside dom1, or in repeated entries ending
  in immediate physical preemption? Only measure entry/exit and VP
  activation/deactivation intervals, exit reasons, and sampled unchanged RIP
  on physical exits. Opt-in `execution-stats`; bounded aggregate snapshots.
  No thhv/timer changes. Used short runs of the same workload, then followed
  the dominant measured path rather than extending the profiler.
  Raw TSC residence includes nested-VMX overhead/outer-host descheduling;
  it must not be presented as retired guest instructions or pure CPU time.
  The entry/exit bracket wraps `ActiveVcpu::run`, including its VMCS result
  reads/replay bookkeeping, so actual guest execution is less than this
  interval. Inactive covers deactivation-to-reactivation, not just Linux
  scheduler wait. The measurements partition elapsed time, not CPU usage.

  Results (cumulative final snapshots; 3 GHz TSC confirmed by dom0 boot):
  - Default dev, 120s timeout: entry/exit 17.93%, active handling 31.59%,
    inactive 50.48%; 573/998 sampled physical exits had unchanged RIP.
  - Release, 120s timeout: 17.36% / 32.07% / 50.57%; 587/1033 unchanged.
    Debug optimization is NOT the explanation. HLT-associated gaps were
    negligible; most inactive time followed physical interrupts.
  - Added probes only around the measured physical return path. Release
    90s run: engine transition 2.32us, COMM snapshot 425.48us, VP swap
    30.87us per return. Register publication, not engine validation or
    raw VMCLEAR/VMPTRLD, dominated that measured part.
  - Causal policy experiment, fresh boot, same release binary: override
    vector 236 read_set to NONE, preserve NotReport/write_set/injectable.
    Used a guest-only bind mount; repository/image policy was not edited.
    Snapshot cost fell to 0.51us, but dom1 still only reached its Ubuntu
    welcome banner at 120s, no network at the sampled check. Time split:
    17.27% / 14.14% / 68.60%, 684/1259 unchanged physical RIP.
    This rules out snapshot removal as a sufficient fix. Original policy
    was restored and verified; owned VMM/QEMU processes stopped.

  Verified environment constraint:
  - The actual host kernel is `6.6.87.2-microsoft-standard-WSL2`, lscpu
    reports Microsoft hypervisor; KVM `nested=Y`, `enable_shadow_vmcs=N`,
    `enable_apicv=N`; exposed VMX flags lack VMCS shadowing.
  - Dom0 is `6.8.0-142-generic`; its matching /boot/config identifies
    CONFIG_HZ=1000 (do not reuse the stale 250Hz assumption).
  - Intel SDM Vol. 3C, VMCS types/shadowing: VMREAD/VMWRITE in VMX non-root
    cause exits when VMCS shadowing is off. This provides a concrete reason
    the numerous register accesses are expensive in this environment.
    It does NOT prove the environment is the sole cause of dom1's stall.
  - No parent interrupts were suppressed/delayed, no timer backend or
    scheduling ABI was changed. No host KVM/Hyper-V settings were changed.
  Next decisive control: same image/workload on native Linux/KVM with
  shadow VMCS available, or bare-metal Themis. That control is not available
  in this session. Do not label the bug fixed or redesign scheduling solely
  from these nested-host timings.

  Evidence: host `/tmp/themis-{time,time-release,switch-cost,no-snapshot}-*.log`,
  persistent copies under this session's `files/vp-time/`. Experiment-only
  JSON is `files/intr-snapshot-policy.json`. IMPORTANT: run-dom1.sh redirects
  CHV itself to `/tmp/chv-{stdout,stderr}.log`; the previously captured
  launcher stdout was not its actual exit-rate log. Actual stderr preserved
  for switch-cost and no-snapshot runs.
  Validation: 7 VMX host tests with execution-stats pass; cargo build-bins
  passes; feature-enabled default and release boots compile and run.
  Files modified for this experiment:
  - `themis/crates/vmx/src/execution_stats.rs` (new), `lib.rs`, `Cargo.toml`:
    opt-in time partition counters and host tests.
  - `themis/crates/vmx/src/vcpu.rs`: counters travel with VP; lifecycle hooks.
  - `themis/capavisor/Cargo.toml`: execution-stats feature forwarding.
  - `themis/capavisor/src/arch/x86_64/x86_platform.rs`: entry/exit timing,
    sampled physical-exit RIP and bounded aggregate output.
  - `themis/capavisor/src/arch/x86_64/hypercall/switch.rs`, `vcpu_switch.rs`:
    three-stage physical-return and raw swap measurements.
  - `todo.md`: results, limitations and this handoff. No commit.

- **2026-10-08 — entry-event preservation fix (DONE; dom1 liveness UNRESOLVED)**:
  User approved reproducing/fixing the occupied VM-entry slot bug before any
  timer redesign. Timer source, parent interrupt routing and retry timing
  remain unchanged.
  - Extracted the IF/shadow arbitration into a host-testable VMX helper.
    Two regressions failed with the old check: overdue timer overwritten by
    a later PIR drain, and new timer injection replacing event replay.
    Added the occupied-slot guard and all five host tests now pass.
  - Wired the guard into both local delivery and PIR drain; pending PIR bits
    are restored when entry is occupied. Added a per-VP software bitmap for
    VPs without a PID so the new deferral does not silently drop their events.
    This bitmap moves with Active/InactiveVcpu, not with a physical core.
    Raw external injection asserts its precondition; the generic x86
    interrupt method now uses the shared delivery helper as well.
  - Moved SWITCH's expiry check after dirty COMM registers are applied, so
    IF/shadow eligibility uses the guest state actually being entered.
  - `cargo test -p vmx --target x86_64-unknown-linux-gnu --lib --quiet`
    passes (5 tests); `cargo build-bins` and changed-file formatting pass.
    These host tests cover arbitration, not actual VM-entry execution.
  - Full stack booted with the same default dev profile, 4 CPUs and 4G as
    `/tmp/out.txt`'s baseline. Dom0 SSH remained responsive. Ran the same 600-second
    dom1 run with CHV_CPUS=1, null serial, file console and
    `loglevel=4 systemd.unit=multi-user.target systemd.default_timeout_start_sec=300s`.
    **Timed out (124), zero tap RX/TX packets, no successful ping.** Dom1
    slowly progressed through lvm2-monitor and module startup; final console
    shows systemd-udev-trigger still running (6min 47s). The previous run
    stopped earlier around lvm2-monitor, but one variable boot is insufficient
    to attribute that difference to this change.
  - No assertion/panic or VM-entry failure was observed. Sampled dom1 timer
    entries continued through timer#70000, including exits in the timer
    handler's EOI path. This is not proof of timely timer delivery, and
    fixing the demonstrated overwrite does NOT explain or solve the
    remaining boot failure.
  - Dom0 switched TSC -> HPET around uptime 333s; the prior baseline did the
    same. Timeout teardown emitted thhv REVOKE_MEM failures (-2), also present
    in the baseline. Neither is newly attributed to the entry guard.
    CHV's captured log had no THEMIS-RATE samples; no exit-rate conclusion.
  - Logs saved on the host:
    `/tmp/themis-entry-fix-{serial,dom1-run,poll,dom1-console,dom1-chv,final-state}.log`
    and `/tmp/themis-entry-fix-build.log`; persistent copies in this session's
    `files/entry-event-fix/` directory. Initial console reads needed sudo;
    the complete root-owned console was subsequently copied successfully.
    CHV exited at the timeout, dom0 storage was synced, and the owned QEMU
    stack/monitor processes were stopped. No running experiment or commit.
  - Next investigation must isolate the remaining delay with evidence;
    do not assume ancestor timers or substitute a VMX-counter redesign.
  Files changed in this fix:
  - `themis/crates/vmx/src/interrupts.rs` (new), `lib.rs` - shared arbitration,
    pending bitmap and host regressions.
  - `themis/crates/vmx/src/vcpu.rs` - persistent no-PID pending state.
  - `themis/capavisor/src/arch/x86_64/vcpu_ext.rs`, `pid.rs`,
    `hypercall/switch.rs`, `x86_platform.rs` - guard and queue wiring.
  - `docs/architecture/interrupt-virtualization.md` - entry-slot invariant.
  - `todo.md` - this handoff. No timer backend or engine changes.

- **2026-10-08 — timer-source constraint (USER CONFIRMED)**:
  Do not rely on the VMX preemption timer as the backing source for guest
  timers. The previous proposal to multiplex ancestor guest deadlines onto
  that counter is withdrawn. Guest timers need persistent per-VP state,
  absolute-time expiry accounting, and a wakeup source independent of which
  VP is executing; expiry/pending state must remain distinct from delivery
  and from the parent's decision to schedule an off-core child.
  Selecting that source must respect existing hardware ownership: dom0
  currently has native timer access, so capavisor cannot simply repurpose the
  physical LAPIC timer without addressing its capability/policy contract.
  No replacement backend has been selected or implemented. The entry-event
  overwrite investigation below remains relevant regardless of timer source.
  Files modified for this clarification: `todo.md` only.

- **2026-10-08 — scheduling-plan reevaluation (REVIEW COMPLETE; prototype PAUSED)**:
  User challenged repeated speculative proposals and asked for a code/design
  reevaluation before implementation. No functional changes or new boot runs.
  The previous ancestor-timer prototype is NOT justified as the next dom1 fix.

  Verified existing mechanisms:
  - `capa-engine/src/switch.rs::CoreContext.call_stack` already records the
    live Running/Locked chain. `deliver_interrupt_vp` uses it to lazy-unwind;
    `switch_domain_forward` reconstructs it on resume. Off-core frozen segments
    already use `VpRunState::Waiting::unlocks`, including cross-core resume.
    There is no missing chain representation or need for a second scheduler.
  - Physical handler selection uses `find_interrupt_handler`/visibility;
    virtual injection uses `injectable`. `deliver_interrupt_vp` also snapshots
    Report semantics into Waiting states, so it is not merely a target-neutral
    swap helper. Any reuse must preserve register filters, blocked/unlocks,
    reporting and revoke synchronization, not just select a domain and swap.
  - `thhv/src/thhv_vp.c:159-186` already handles ERR_RETRY, doorbell draining,
    signals and rescheduling inside RUN_VP. Returning to the parent kernel is
    not returning to CHV. Local MSHV confirms the same important separation,
    but does not prove Hyper-V's internal interrupt/timer design.
  - The observed boot is dom0 -> dom1, with dom1 the leaf. Root MSR policy is
    Native (`domain.rs:636`, `boot/vmcs.rs:50`), while the child TSC deadline
    is emulated. The saved trace has continuing physical 0xec INTR_FWD events
    (#282000 through #284000). There is no observed intermediate virtual
    parent timer whose neglect explains this run. Ancestor deadline scanning
    would not eliminate those required physical lazy-unwinds.

  Concrete local delivery hazard found by tracing SWITCH (static finding,
  NOT yet demonstrated as the cause of the stalled boot):
  1. `hypercall/switch.rs:136` checks an overdue child deadline before PIR drain.
  2. `msr_emulator.rs:180` clears the deadline; `pid.rs:196` may put the timer
     directly into VMENTRY_INTERRUPTION_INFO_FIELD when IF/shadows permit.
  3. Later in the SAME SWITCH, `drain_pir_inject_lowest` can remove a different
     pending vector from PIR and overwrite that field (`switch.rs:355`).
     `guest_can_accept_external` checks only IF/STI/MOV-SS, not an occupied
     entry-event slot (`vcpu_ext.rs:119`). The overwritten direct timer was
     neither retained in PIR nor left armed. No guest entry separates writes.
  4. `vmx::ActiveVcpu::run` also preserves interrupted event delivery using
     IDT_VECTORING_INFO; this saved event must not be overwritten by new
     injection either. Changes must cover all writers, not only timer expiry.

  Other constraints on the earlier overly simple timer plan:
  - Deadline checks currently run at WRMSR/SWITCH/timer-exit points, not every
    guest entry. The VMX preemption counter runs in VMX non-root, unlike an
    absolute TSC deadline (checked against Intel SDM section on VMX-preemption
    timer). Any timer service must account for time spent handling exits.
  - Timer expiry, pending state, and eligibility for delivery are separate.
    Parent/leaf masking, LVT vector/mode/mask, an occupied entry-event slot,
    and off-core Waiting/Available state cannot be replaced by "minimum
    deadline then unconditional unwind".
  - Current CHV xAPIC LVT shadow is not consulted by the capavisor's fixed-0xec
    deadline injector; MMIO timer reprogramming is a no-op. These remain
    incomplete timer semantics, not a proven explanation of this particular
    boot stall. Hardware support does not excuse an incoherent fallback.

  Verification: existing `cargo test --quiet --test unit_switch
  --test integration_interrupt` passed (39 + 4 tests). This verifies existing
  engine scenarios, not VMX delivery or the new static hazard.
  Next recommended discriminator: reproduce overdue deadline + another pending
  vector + IF=1 on SWITCH, and check that neither event is lost before entry.
  Then make a narrowly tested pending-event/entry-slot correction and compare
  the same dom1 workload, without suppressing parent interrupts or tuning
  sleeps. Track actual guest handler/RCU/network progress, not sampled CHV
  counts alone. Recursive ancestor-timer support is a separate test/work item:
  B arms its timer and SWITCHes to C spinning; B's handler must regain control,
  with existing chain semantics and policy preserved. No new ABI is proposed.
  Files modified in this reevaluation: `todo.md` only.

- **2026-10-08 — interrupt/timer design clarification (PROPOSAL, not implemented)**:
  Reviewed `CONTEXT.md`, the interrupt design document, and the current
  capavisor/CHV injection and LAPIC paths. Documentation is not proof of
  implementation: the interrupt document says a plain vIRR write suffices,
  whereas `pid.rs::queue_virtual_interrupt_vid` explicitly updates RVI.
  Recommended boundary: engine owns authority, policy and lifetime;
  capavisor's architecture layer owns each virtual VP's local interrupt/timer
  state, with hardware acceleration and a semantically equivalent software
  backend; CHV owns virtual peripheral models and capability-authorized
  configuration/injection; thhv transports requests and scheduling wakeups,
  not invented guest timer ticks. Keep physical lazy-unwind/EOI separate.
  Backend selection must not bypass vector policy, expose META, or change
  guest-visible timer semantics. Off-CPU timer wakeups and revoke/callback
  synchronization need an explicit contract; no scheduling guarantee against
  a parent that refuses to run its child is implied.
  Scheduling clarification after examining Linux MSHV (supersedes the
  proposed SWITCH budget/deadline ABI): local
  `../linux/drivers/hv/mshv_root_main.c:419-590` dispatches with
  `time_slice = 0`, checks Linux guest-entry work between dispatches, waits on
  blocked VPs, and redispatches ready/non-intercept returns inside the ioctl.
  `../linux/kernel/entry/virt.c:5-25` handles rescheduling via `schedule()`
  and signals via `-EINTR`. Returning to the parent kernel for scheduling is
  not the same as returning an intercept to the userspace VMM.
  Themis already has that basic split in thhv's ERR_RETRY/cond_resched loop.
  Recommendation: retain event-driven synchronous delegation rather than add
  mandatory nested budgets. Each domain's own timer and reschedule events must
  remain effective while its VP is waiting inside SWITCH to a descendant.
  An eligible event addressed to a waiting ancestor must reactivate it through
  an engine-mediated chain transition; do not route that virtual event as a
  bare physical vector or let the leaf's IF prevent ancestor preemption.
  Parent masking rules still apply to delivery into the parent itself.
  Existing TSC-deadline checks operate on the active VP or the newly switched
  target, not waiting ancestors. This is a concrete gap to investigate for
  recursive scheduling, not proof of the current dom1 boot failure.
  Hardware acceleration of the leaf's LAPIC does not replace the need to
  track/wake waiting ancestors. MSHV source demonstrates its root-dispatch
  contract, not Hyper-V's internal implementation or arbitrary Themis nesting.
  Physical lazy-unwind remains required under A3; its kernel returns cannot
  simply be suppressed. No source-code changes were made in this comparison.
  This is a design recommendation awaiting agreement, not a proven boot fix.
  Current fallback code selects the lowest pending vector ("device-first"),
  and the deadline source does not consult CHV's LVT shadow. These warrant
  transition-level investigation, not further timing tweaks.
  Corrected earlier inference: missing sampled CHV rate lines do not establish
  that VM exits ceased; runtime `INTR_FWD` counters continued advancing.
  Files modified in this clarification: `todo.md` only.

- **2026-10-02 — dom1 doorbell/network and systemd split (IN PROGRESS)**:
  Goal: get dom1 to a usable login/SSH without confusing image/systemd delays
  with capavisor interrupt/device bugs.

  What was tried:
  - Checkpoint saved after the CPUID/XSAVE fix and capavisor EOI fast path:
    targeted rebuilds passed for `themis/capavisor` and CHV `hypervisor`
    (`--features themis,kvm`). The running QEMU/Themis stack was stopped
    cleanly before resuming timer/PIR debugging. `tools/toggle-debug` remains
    a generated binary side effect of `cargo build-bins` and should be
    reverted before a clean final diff if its source is unchanged.
  - Implemented and validated the EPT-violation doorbell fast path for
    registered IOEVENTFD GPAs. Virtio notify MMIO spam disappeared and virtio
    device activation moved much earlier.
  - Added a capavisor exact LAPIC EOI EPT-violation fast path for the common
    Linux xAPIC store (`89 04 25 <disp32>`) using an explicit 7-byte RIP
    advance. This avoids the parent/CHV round-trip for the hot EOI path and
    drops CHV `lapic_eoi` counters to zero. Do not use VMX
    `VMEXIT_INSTRUCTION_LEN` for this path; observed values were still wrong.
  - Tried adding VAPIC ISR clearing to that capavisor EOI path. A correct
    xAPIC-register stride (`0x100,0x110,...`) caused early PID1 segfaults, so
    the EPT-violation fallback fast path is intentionally RIP-only for now.
    The APIC-access handler keeps the fixed ISR stride for the APICv path.
  - Made dom1 image setup deterministic: `fetch-dom1.sh` and `update-bins.sh`
    now install `/etc/netplan/99-dom1.yaml` directly, disable stale
    `LABEL=BOOT`/`LABEL=UEFI` fstab entries, and default the launcher to
    `fstab=no` plus masks for stale console/multipath/snapd waits.
  - Verified `guest/dom1.raw` contains netplan for MAC `12:34:56:78:90:ab`
    and static `192.168.100.2/24`, and fstab BOOT/UEFI entries are commented.
  - Normal systemd boot with file-backed console now gets past the old
    `/boot`/`/boot/efi` waits and reaches much later systemd/module/udev work,
    but still times out before ping/SSH in 420s.
  - Added `/themis-net-test.sh` to dom1 during `update-bins.sh` packaging and
    booted it with `init=/themis-net-test.sh`, `CHV_SERIAL=null`, and a
    file-backed virtio console. It reached `THEMIS_NET_TEST_START`, brought up
    `eth0`, assigned `192.168.100.2/24`, and successfully pinged dom0
    `192.168.100.1`. Tap counters advanced (`RX 10/TX 5` packets in the first
    successful sample).
  - A systemd boot with overly broad masks including
    `systemd-udev-trigger.service` is invalid: PID1 prints
    `Failed to start up manager` and freezes. Do not use that mask set as
    evidence.
  - A narrower systemd boot with only `multipathd.socket` additionally masked
    does not fail immediately, but still times out before ping. It progresses
    through udev/tmpfiles/sysusers/resolved work, activates virtio-net around
    CHV time ~62s, then remains extremely slow and reports a guest soft lockup
    around 376s while CHV has forwarded ~40k LAPIC EOI writes.
  - Added low-volume CHV exit/LAPIC counters. The result is now unambiguous:
    after virtio activation, generic MMIO and IO exits mostly flatten while
    LAPIC EOI EPT violations keep climbing almost one-for-one with total EPT
    exits. Baseline example: by 392s CHV saw 55k exits, 44.7k EPT exits,
    44.0k LAPIC EOI writes, only 703 generic MMIO exits, and no HLT exits.
  - Tried a CHV-side EOI shortcut that trusted VMCS `instruction_length`.
    It regressed badly because EPT-violation instruction length is unreliable
    here: first EOI samples had `vmx_len=0` or `3`, while iced-x86 decoded the
    real instruction length as 7 bytes
    (`89 04 25 b0 d0 5f ff`, `Mov_rm32_r32`). Advancing by the VMX length
    jumps into the middle of the instruction stream.
  - Added a safer CHV LAPIC EOI fast path in
    `cloud-hypervisor/hypervisor/src/themis/vcpu.rs`: exact-match the common
    7-byte Linux xAPIC EOI store and advance RIP by 7; otherwise fall back to
    iced-x86 decode and advance by the decoded length. This preserves CHV's
    LAPIC software state update and avoids the previous bad VMX-length
    shortcut.
  - Exact EOI fast-path validation gets farther than the old baseline in some
    runs (`systemd-resolved` and `systemd-timesyncd` can start, cloud-init
    local stage begins), but still does not reach ping/SSH before 420s. The
    guest reports the older timer/RCU failure again:
    `rcu_preempt kthread timer wakeup didn't happen for 62247 jiffies` and
    `Possible timer handling issue on cpu=0 timer-softirq=1895`, plus later
    soft lockups. Tap counters remain zero.
  - Found and fixed a separate correctness bug that explained random dom1
    userspace crashes (`udevadm`/`ip` returning `-11`, transient PID1
    segfaults): CHV pushed host CPUID leaves as `Emulate` policy, bypassing
    capavisor's local CPUID mask. Dom1 could see host AVX-512/large XSAVE
    state while capavisor only saves/restores x87+SSE+AVX (`XCR0=0x7`,
    1024-byte XSAVE area). Fixed by masking pushed Themis CPUID leaves in
    `cloud-hypervisor/hypervisor/src/themis/vm_state.rs` and enforcing the
    same `0x7` XCR0 mask in capavisor `handle_xsetbv`. Reproduction that
    previously logged `ip` exit `-11` no longer shows SIGSEGV after the fix.
  - Removed an unbounded CHV hot-path diagnostic from
    `set_gsi_routing()`. The old `gsi_routing` print emitted the full MSI
    routing table repeatedly during device setup and made the systemd boot
    measurements much worse. After removing it, a 360s run progressed much
    farther: cloud-init/network stages ran, `ssh.socket` was reached, and the
    guest produced tap traffic instead of stalling around early device setup.
  - Tightened the pushed CPUID/XSAVE mask beyond the first AVX-512-only fix.
    CHV now hides MPX, PKU/OSPKE, AMX, AVX-512 BF16, clears leaf `0xD.1`
    feature bits, and zeros all `0xD` subleaves above AVX (`index >= 3`).
    This matches the capavisor's actual XSAVE support (`XCR0=0x7`) and avoids
    advertising any xstate component capavisor cannot save/restore.
  - Added direct systemd-networkd static configuration to dom1 image setup
    (`/etc/systemd/network/10-dom1-eth0.network`) and made `run-dom1.sh`
    default to `cloud-init=disabled`. This avoids cloud-init/netplan as a
    boot confounder now that the image already contains deterministic network
    configuration. One 360s validation with cloud-init disabled reached
    `multi-user.target` and login prompt services; live polling after a later
    rebuild showed tap carrier but no ping yet because that run stalled much
    earlier in systemd (`lvm2-monitor`/tmpfiles), confirming remaining
    progress variance is still timer/liveness related rather than basic
    virtio-net plumbing.
  - Verified the host `guest/dom1.raw` root partition directly with
    `fuse2fs -o ro,norecovery,offset=1074790400`: the direct networkd file
    and netplan file are present, but cloud-init has not completed first-boot
    provisioning (`/var/lib/cloud` only has the seed tree) and `/etc/passwd`
    has no `cloud` user yet. Therefore a never-initialized image would break
    password SSH login even after networking works, but it does **not**
    explain no ping or tap RX/TX=0; direct init already proves manual IP setup
    can ping without cloud-init.
  - Found that the apparent `systemd-udevd.service` failure was a timeout
    symptom, not a udev crash: with the default 90s start timeout, udevd
    repeatedly failed/restarted before networkd could configure the link.
    Re-running with
    `KERNEL_APPEND="loglevel=4 systemd.unit=multi-user.target systemd.default_timeout_start_sec=300s"`
    let `systemd-udevd.service` start and moved the boot through
    `systemd-networkd.service`, `network.target`, `network-online.target`,
    `ssh.socket`, `basic.target`, and into `systemd-logind`. The run still
    timed out at 900s, dominated by RCU/timer stalls and very slow units such
    as `ldconfig.service`.
  - The 900s long-timeout run still had tap RX/TX counters stuck at zero and
    no ping/TCP/22 despite networkd reaching `network-online.target`. That
    means systemd believes the network stack is configured, but the guest is
    not transmitting on the virtio-net tap. Next network-specific discriminator
    should be a small systemd one-shot service that runs the already-working
    manual `/themis-net-test.sh` path after udev/networkd/device activation,
    or an init/debug shell that queries `ip addr`/`networkctl` inside the
    guest. Do not treat SSH login failure as authoritative until a `cloud`
    user is provisioned independently of cloud-init.
  - Runtime-gated capavisor tracing during the stalled long-timeout run shows
    the dom1 local timer bit pending in PIR (`pir[3]=0x100000000000`,
    vector `0xec`) while `guest_can_accept_external()` is false. Sampled
    blocked RIPs include `native_irq_return_iret`, `setup_APIC_eilvt`, and
    workqueue tracing paths; `PRIMARY_PROCBASED_EXEC_CONTROLS` already had
    interrupt-window exiting set, but no `DBG-INTR-WINDOW` samples fired in
    the trace window. At the same time the log is flooded with parent-bound
    physical `vec=236` (`0xec`) `INTR_FWD ... vis=NotReport`, and many
    `DBG-ENTRY-RESULT` samples show an injected dom1 timer immediately
    leaving via `EXIT_REASON_EXTERNAL_INTERRUPT` at
    `asm_sysvec_apic_timer_interrupt` or via EPT at the LAPIC/APIC path. This
    strengthens the current lead that dom0 physical timer lazy-unwinds are
    repeatedly preempting dom1 while dom1's own timer handler/PIR delivery is
    trying to make progress.
  - Stop point for 2026-10-02: no QEMU/CHV/dom1 shell sessions or processes
    were left running. The last active investigation was reading
    `ActiveVcpu::run()` and interrupt-forwarding paths to test whether a
    pending dom1 timer injection is being clobbered or starved by repeated
    parent physical `0xec` lazy-unwinds. No new code was written after this
    trace analysis; only this handoff note was added.

  Current hypothesis: virtio-net, IOEVENTFD doorbells, IRQFD injection, tap
  plumbing, and basic userspace memory/FPU state are now separated from the
  remaining failure. The direct init test can ping, `cloud-init=disabled`
  can reach multi-user in a good run, and the CPUID/XSAVE exposure has been
  narrowed to exactly what capavisor saves. Normal Ubuntu is still extremely
  slow and variable because timer/liveness remains unhealthy: increasing
  systemd unit timeouts lets services that previously "failed" progress, but
  Linux repeatedly reports RCU timer wakeups not happening and soft lockups.
  Runtime PIR/TSC traces show timer vector `0xec` being produced and pending
  while IF is closed; when injected, it often exits immediately via EPT
  violation at the APIC/EOI path (`rip=0xffffffff81305cf2`) or via a
  physical external timer preemption while RIP is at
  `asm_sysvec_apic_timer_interrupt`. The current strongest lead is the
  interaction between dom1's local timer injection and dom0's physical
  `0xec` timer interrupts forcing full lazy-unwind/context-switches at high
  frequency. Since this nested host exposes
  `APICv: partial/none` and capavisor logs
  `VIRTUALIZE_APIC_ACCESSES not supported`, continue focusing on local
  timer/APIC delivery semantics, physical dom0 timer preemption while dom1 is
  running, and xAPIC EPT fallback overhead; do not treat network plumbing as
  the primary blocker anymore.

  Last known state / trace:
  ```
  Direct init:
    THEMIS_NET_TEST_START
    THEMIS_NET_TEST_DEV eth0
    THEMIS_NET_TEST_PING_OK eth0

  Narrow systemd:
    baseline counter run:
      55k exits at 392s, 44.7k EPT, 44.0k LAPIC EOI,
      703 generic MMIO, 0 HLT, no ping.
    exact EOI fast-path run:
      55k exits at 403s, 38.3k EPT, 37.5k LAPIC EOI,
      703 generic MMIO, 0 HLT.
      systemd-resolved/timesyncd can start, cloud-init-local begins,
      but RCU reports "timer wakeup didn't happen" and no ping before timeout.
    capavisor exact EOI fast-path run:
      CHV lapic_eoi=0, ept exits fall to hundreds/low thousands by early
      systemd, virtio activates around 36s, but normal boot still times out.
    CPUID/XSAVE mask fix run:
      userspace SIGSEGV/-11 symptom disappears; normal 420s boot still reports
      soft lockups and times out around early cloud-init/systemd work.
    after CHV gsi_routing log removal:
      360s boot with cloud-init enabled reached cloud-init/network stage and
      ssh.socket; netplan still once reported exit -11 before the tighter
      CPUID mask.
    after tighter CPUID mask + cloud-init=disabled:
      one 360s run reached multi-user.target and getty; later live run had tap
      carrier but no IP/ping and stalled earlier in systemd, showing remaining
      nondeterministic timer/progress variance.
    image inspection:
      direct networkd/netplan config exists; cloud user does not yet exist
      because cloud-init has not completed first boot.
    long systemd timeout run:
      systemd-udevd starts when start timeout is raised to 300s.
      reaches network.target/network-online.target/ssh.socket/basic.target,
      but RCU reports repeated "timer wakeup didn't happen" stalls, tap RX/TX
      stays 0, and ping/tcp22 fail until the 900s timeout.
    runtime trace around the stall:
      [DBG-PIR-DRAIN timer_blocked] ... can_accept=false ...
        pir=[0x0,0x0,0x0,0x100000000000]
      [INTR_FWD] vec=236 vis=NotReport
      [DBG-ENTRY-RESULT] entry_before=0x800000ec exit=1
        vmexit_intr=0x800000ec rip=0xffffffff81000e30
    no ping before timeout
  ```

  Next step: keep the CPUID/XSAVE fix, then focus on physical-parent-timer vs
  dom1-local-timer interaction. Audit whether every parent-bound physical
  `0xec` must force immediate lazy-unwind while a child timer interrupt is
  already being injected/handled, or whether a bounded deferral/quantum model
  is needed for the nested dev environment. In parallel, add a deterministic
  non-cloud-init `cloud` user and/or a one-shot manual network service only as
  observability aids; they are not the root liveness fix. Do not trust VMX
  `instruction_length` for EPT-violation EOI; use decoded/exact instruction
  length only.

  Validation: `cargo build-bins` passed after the image-config/net-test updates;
  `bash -n` passes for `themis/scripts/run-dom1.sh`,
  `themis/scripts/fetch-dom1.sh`, and `themis/scripts/update-bins.sh`.
  `cargo build-bins` also passed after CHV exit/LAPIC counters, the exact EOI
  fast path, the CPUID/XSAVE mask fix, removal of the CHV `gsi_routing` hot
  log, the tighter CPUID/xstate mask, and the direct systemd-networkd dom1
  config. Systemd validation runs with
  `CHV_CPUS=1`, `CHV_SERIAL=null`,
  `CHV_CONSOLE=file=/tmp/dom1-console.log`,
  `KERNEL_APPEND="loglevel=4 systemd.unit=multi-user.target"`, and 420s
  timeout still end with `timeout` exit 124.

  Files modified this session:
  - `themis/capavisor/src/arch/x86_64/hypercall/switch.rs` — retained the
    successful EPT doorbell fast path and added the exact RIP-only capavisor
    LAPIC EOI fast path.
  - `themis/capavisor/src/arch/x86_64/vmexit/mod.rs` — clamps guest XCR0 to
    the xstate components capavisor actually saves/restores (`0x7`).
  - `themis/capavisor/src/arch/x86_64/vmexit/apic.rs` — fixed APIC-access ISR
    stride for the APICv path (`0x100,0x110,...`), not used by the current
    nested xAPIC EPT fallback.
  - `themis/scripts/fetch-dom1.sh` — install direct netplan/fstab cleanup and
    add default masks for stale dom1 boot units when regenerating dom1.
  - `themis/scripts/run-dom1.sh` — default dom1 cmdline now uses `fstab=no` and
    `cloud-init=disabled`, and masks stale multipath/socket/serial-getty/snapd waits.
  - `themis/scripts/update-bins.sh` — inject nested modules, deterministic
    netplan/systemd-networkd/fstab cleanup, and `/themis-net-test.sh` into
    `guest/dom1.raw` before packing.
  - `cloud-hypervisor/hypervisor/src/themis/vcpu.rs` — added aggregate
    Themis-exit/LAPIC counters and the exact/decode-safe LAPIC EOI fast path;
    confirmed VMX `instruction_length` is invalid for these EPT-violation EOI
    writes.
  - `cloud-hypervisor/hypervisor/src/themis/vm_state.rs` — masks CPUID
    entries pushed as Themis `Emulate` policy so dom1 cannot see xstate beyond
    capavisor's x87+SSE+AVX save/restore support; now zeros all unsupported
    xstate subleaves and hides MPX/PKU/AMX/AVX-512-family feature bits.
  - `cloud-hypervisor/hypervisor/src/themis/vm_impl.rs` — removed the
    unbounded `gsi_routing` debug print from the MSI routing hot path.
  - `themis/scripts/fetch-dom1.sh` — installs the same direct
    systemd-networkd static eth0 config when regenerating `dom1.raw`.
  - `todo.md` — recorded the doorbell/network/systemd split and next direction.

- **2026-09-28 — dom1 systemd/cgroup2 boot hang (IN PROGRESS)**:
  Goal: get dom1 to a usable login/SSH so dom1 can later spawn dom2 and test
  non-dom0 child creation.

  What was tried:
  - Normal dom1 boot reaches `/sbin/init`, then stops during early systemd
    setup before networking/SSH.
  - `INIT_SHELL=1` reaches `/bin/sh`, proving kernel boot, rootfs mount, and
    basic userspace execution work.
  - `CHV_CPUS=1` still stops at the same point, so this is not obviously an
    SMP/IPI-only issue.
  - `systemd.unit=emergency.target systemd.log_level=debug
    systemd.log_target=console` was verified in CHV's cmdline and also stops
    before an emergency shell.

  Current hypothesis: this is not a systemd target/dependency problem. The
  failure is timing-sensitive around early cgroup/kernfs/systemd setup, not a
  deterministic cgroup2 mount failure. A manual cgroup2 mount previously stopped
  after `THEMIS_BEFORE_CGROUP_MOUNT`; after adding `themis_trace()` probes and
  re-enabling capavisor `THEMIS_DBG_PRINT` serial output, the same mount completes
  (`THEMIS_AFTER_CGROUP_MOUNT rc=0`). With the same DBG timing perturbation,
  emergency-target systemd also gets past the old cgroup2 line and reaches
  `Welcome to Ubuntu 24.04.4 LTS!`, loopback setup, and "Unified cgroup hierarchy
  is located at /sys/fs/cgroup", then stops later before ping/SSH. This points to
  a scheduling/interrupt/timer race or missing progress event that serial/VMCALL
  debug timing masks.

  Last known live state:
  ```
  CHV command includes:
    --cpus boot=1,max_phys_bits=40
    --serial file=/tmp/dom1-serial.log
    --console file=/tmp/dom1-console.log
    systemd.unit=emergency.target systemd.log_level=debug systemd.log_target=console

  dom1 last console lines:
    No filesystem is currently mounted on /sys/fs/cgroup.
    Mounting cgroup2 to /sys/fs/cgroup of type cgroup2 with options nsdelegate,memory_recursiveprot.
    Mounting cgroup2 (cgroup2) on /sys/fs/cgroup (MS_NOSUID|MS_NODEV|MS_NOEXEC "nsdelegate,memory_recursiveprot")...

  dom0 state from last pull:
    tap-dom1 UP at 192.168.100.1/24
    ping 192.168.100.2 loses 100%
    CHV was still alive as pid 1101
    /tmp/dom1-console.log, /tmp/dom1-serial.log, /tmp/chv-stderr.log stopped moving
  ```

  Next step: instrument Linux `kernel/time/sleep_timeout.c` and timer-wheel
  expiry (`process_timeout()` / `schedule_timeout()`) for the RCU GP kthread.
  The latest discriminator shows cgroup mount blocks because normal
  `synchronize_rcu()` starts a GP and the `rcu_preempt` GP kthread enters the
  timed wait inside `rcu_gp_fqs_loop()`, but that timeout never returns even
  though scheduler ticks continue in the guest. Confirm whether the
  `schedule_timeout()` callback fires and, if not, why the timer wheel does not
  expire it under Themis.

  Latest trace results:
  - New strongest root-cause lead: cgroup mount blocks in
    `synchronize_rcu_normal()` at `wait_for_completion(&rs.completion)`.
    The normal RCU request is added (`0x2b1`), `start_poll_synchronize_rcu()`
    runs (`0x29d`), and the waiter sleeps (`0x29e`) but never reaches `0x29f`.
  - The RCU GP kthread does wake and initialize that request: it reaches
    `rcu_gp_init()` (`0x2b2`/`0x2b4`), rolls the request into a wait segment
    (`0x2b0`), and enters `rcu_gp_fqs_loop()` (`0x2bc`/`0x2d0`/`0x2d1`).
    The stuck GP does not reach `0x2d2`/`0x2d3`/`0x2bd`, so it is sleeping in
    the timed `swait_event_idle_timeout_exclusive()` wait, not stuck in cgroup
    code, GP init, or cleanup.
  - Scheduler ticks continue while the GP is stuck (`0x2ce` thousands of
    times), but RCU core does not provide the needed normal QS for the stuck GP
    (`0x2d5`/`0x2ca` do not lead to `0x2cd`/`0x2c7` for that final GP). The
    current lead is timer-wheel/schedule-timeout progress for the RCU GP
    kthread, not total LAPIC timer loss.
  - `rcupdate.rcu_expedited=1` confirms expedited RCU can complete GP work
    (`0x271`→`0x277`) and lets systemd reach `Welcome to Ubuntu 24.04.4 LTS!`
    and emergency target, but it is only a discriminator, not a final fix.
  - `idle=poll` does **not** fix the non-expedited stall. It still stops at the
    same normal RCU GP-kthread timed wait (`0x2d1` without `0x2d2` for the
    final GP), so preventing guest idle/HLT is insufficient.
  - End-of-day stop point (2026-09-28): stopped the remaining local
    `themis-rcu` shell task. Dom0 SSH on host port 2222 refused connections at
    shutdown time, so no remote CHV/dom1 process could be inspected or killed
    from the host in this session. Resume by booting dom0, then continue with
    Linux `schedule_timeout()` / timer-wheel probes for the RCU GP kthread.
  - Manual cgroup init with DBG_PRINT enabled completes:
    `THEMIS_AFTER_CGROUP_MOUNT rc=0`, `/proc/mounts` shows
    `cgroup2 /sys/fs/cgroup cgroup2 rw,relatime,nsdelegate,memory_recursiveprot`.
  - Cgroup/kernfs trace sequence for dom1 includes complete ranges:
    `0x22c 0x22d 0x229 0x22a 0x230..0x23e 0x22b 0x22e 0x22f`.
  - Emergency-target systemd with DBG_PRINT enabled also passes the former stop
    point and logs `Found cgroup2...`, `Welcome to Ubuntu 24.04.4 LTS!`,
    loopback setup, and `Unified cgroup hierarchy is located at /sys/fs/cgroup`,
    but still does not ping or reach SSH.
  - A first `themis_trace()` helper variant caused a false kernel oops because
    its inline asm did not declare VMCALL clobbers; fixed in the Linux tree.
  - `quantum-sched` is not available in the current capavisor; it was removed
    on 2026-08-04. The `skills/running-inside-dom0.md` note saying to enable it
    is stale.
  - CHV LAPIC fallback EOI was patched to clear the highest software ISR bit,
    but `[LAPIC-EOI]` never fires because CHV's `lapic_regs` ISR remains zero.
    Guest EOI writes (`offset=0xb0`) are frequent, but capavisor injects
    interrupts through VM-entry/PIR and does not mirror those deliveries into
    CHV's LAPIC ISR shadow.
  - Stronger root-cause lead: a run without HLT polling reached `/sbin/init`,
    then stopped after `thhv: DBG_RUN HLT vp=0 pending=0 halted=0`. Since the
    capavisor TSC-deadline emulator has no wake source while the VP thread is
    sleeping in thhv, this can lose LAPIC-timer progress after guest idle.
  - Temporary diagnostic in `thhv/src/thhv_vp.c`: changed the HLT wait to
    `wait_event_interruptible_timeout(..., msecs_to_jiffies(1))`. This confirms
    the hang is timer/progress related: the guest no longer silently parks at
    `/sbin/init`, but advances into device activation/workqueue activity.
  - Latest HLT-timeout run is still not usable: CHV spins high CPU, dom1 does
    not ping, and the guest logs workqueue hog warnings after `/sbin/init`.
    Hot exits alternate between LAPIC EOI (`native_apic_mem_eoi`, MMIO
    `offset=0xb0`) and virtio MMIO (`iowrite16`), with many forwarded physical
    `0xec` dom0-timer interrupts. This likely combines the real halted-timer
    wake bug with heavy temporary serial instrumentation overhead.
  - 2026-09-30 update: the missing `[DBG] dom=1` traces were caused by a stale
    nested bzImage in `bins.img`, not capavisor VMCALL dispatch. Rebuilding
    `../linux/arch/x86/boot/bzImage` and repacking/copying it to
    `/opt/bins/nested/bzImage` restored guest tracepoints.
  - Focused timer-wheel probes narrowed the old cgroup hang: the cgroup2 mount
    reaches `0x22e`, enters `synchronize_rcu_normal()`, queues a normal RCU
    request (`0x2b1`), the waiter sleeps (`0x29e`), and with the thhv 1ms HLT
    diagnostic the GP kthread reaches `0x2ba 0x2b2 0x2b4 0x2b0 0x2b5 0x2bc
    0x2d0 0x2d1`, then arms a `schedule_timeout()` (`0x2d6 0x2d7 0x2d8
    0x2e7`). The exact timer callback still never fires: no `0x2fd`, no
    `0x2fe`, no `0x2da/0x2db`, and no `0x2f0/0x2f4` timer softirq activity
    after that final `0x2e7`.
  - `nohz=off highres=off` did **not** fix the final timeout edge. The run
    still stopped after the final `0x2d6/0x2d8/0x2e7`, so the issue is not just
    highres/nohz one-shot mode failing to program the clockevent.
  - Strongest current lead (2026-09-30): LAPIC timer vector `0xec` accumulates
    in the child PID/PIR (`pir[3]=0x100000000000`) and remains pending across
    many drains. There are repeated `DBG-PIR-DRAIN ... can_accept=true ...
    pir=[...,0x100000000000]` samples (23 sampled accept-true cases in the
    latest aggregate), but later drains still see the same pending bit. This
    suggests the next root-cause audit should focus on capavisor PIR drain /
    VM-entry interrupt injection semantics: whether `VMENTRY_INTERRUPTION_INFO`
    is being overwritten, cleared too early, rejected by VM-entry/interrupt
    state, or whether the injected vector is not reaching Linux despite
    `guest_can_accept_external()`.
  - 2026-09-30 later update: the "no `0x311`" observation was again a stale
    nested-kernel packaging issue. `guest/kernel/bzImage` was old, while
    `../linux/arch/x86/boot/bzImage` and `vmlinux` contained the probe. Repacking
    with `NESTED_KERNEL=../linux/arch/x86/boot/bzImage` restored `[DBG] dom=1`.
  - With the corrected kernel, dom1 reaches `/sbin/init` and prints
    `[DBG] dom=1 val=0x311`, then stalls/loops in normal Linux idle:
    HLT RIP `0xffffffff821db84a` resolves to `pv_native_safe_halt` (`sti; hlt`),
    not MCE. The steady trace is `0x300 -> 0x303 -> 0x302`, meaning idle loop,
    cpuidle unavailable, `default_idle_call(stop_tick=false)`.
  - The old RCU GP timeout edge did **not** reproduce in the corrected run:
    normal GP traces reached `0x2d2/0x2d3/0x2bd` and later cleanup markers
    `0x2b6/0x2b7/0x2b8`. Timer vector injection also reaches Linux's timer
    entry: `DBG-PIR-INJECT vec=0xec entry_intr=0x800000ec` followed by
    `DBG-ENTRY-RESULT ... exit=1 vmexit_intr=0x800000ec rip=0xffffffff81000e30`
    (`asm_sysvec_apic_timer_interrupt`). `IDT_VECTORING_INFO` was `0`.
  - Current post-init stall evidence: after `0x311`, sampled APIC timer handler
    probes `0x312/0x313` do not appear. HLT forwarding samples show
    `deadline=0`, mostly empty PIR, and no CHV/systemd serial output after
    `Run /sbin/init as init process`. The temporary thhv 1ms HLT timeout is
    still the only thing preventing an indefinite wait when no IRQ/deadline is
    visible to thhv.
  - Added thhv IRQFD diagnostics and reran. IRQFD registration/injection does
    occur during boot (`DBG_IRQFD assign` for timer and virtio vectors;
    successful sampled injections for vectors 33/35/37/38), but dom1 still
    stops after `0x311`. So the remaining gap is not "irqfds never registered"
    and not simply "no device interrupts ever inject"; it is specifically after
    execing `/sbin/init` / before visible systemd progress.
  - Added Linux exec-transition probes for next run:
    `0x314` begin_new_exec, `0x315` end of begin_new_exec,
    `0x316` setup_new_exec, `0x317` finalize_exec, `0x318` x86 start_thread,
    `0x319` `kernel_execve()` returned with error. The kernel (`#27`) built and
    was packed into `bins.img`, but the user needed to stop the machine before
    the run reached the collection point; no `0x314`-`0x319` result has been
    captured yet.
  - 2026-10-01 resume: reran the packed exec-probe kernel. The exec-transition
    probes fired in order: `0x311 0x314 0x315 0x316 0x317 0x318 0x319`.
    Despite `0x319`, dom1 serial/console proves PID 1 entered systemd and ran
    early userspace, so the `0x319` placement is not a useful failure
    discriminator as currently inserted. The visible stop point returned to the
    known cgroup2 mount:
    `Mounting cgroup2 ... nsdelegate,memory_recursiveprot`.
  - The latest cgroup/RCU trace is now sharper. The earlier RCU timeout can
    complete in some cycles (`0x2f0/0x2f4/0x2fd/0x2fe/0x2da/0x2db/0x2d9/0x2dc/0x2dd`),
    but the final cgroup path reaches
    `0x23f 0x240 0x241 0x248 0x249 0x251 0x252 0x258 0x259 0x25a 0x25b
    0x2d0 0x2d1 0x2d6 0x2d7 0x2d8 0x2e7 0x2ff`, then stalls. That means the
    final RCU GP-kthread timeout is queued as a new first timer (`0x2e7`), the
    idle task enters `do_idle()` with the timeout active (`0x2ff`), and then no
    timer-softirq/callback expiry is observed for that exact timer.
  - Important timer/HLT insight from this run: after the final `0x2e7`, Linux
    loops `0x300 -> 0x303 -> 0x302`, i.e. cpuidle unavailable and
    `default_idle_call(stop_tick=false)`. Since `stop_tick=false`, Linux
    retains the periodic tick and does not necessarily program a new
    `IA32_TSC_DEADLINE` immediately before `sti; hlt`. Capavisor then forwards
    HLT with `deadline=0`, so thhv has no principled wake deadline; the current
    1ms timeout is only a diagnostic busy retry, not a real timer model.
  - Tried a temporary thhv diagnostic that injected vector `0xec` on
    zero-deadline HLT timeout. It was reverted in-session: the patched run became
    much slower and failed to reach `/sbin/init` within the bounded window, so it
    is not useful evidence and is not in the current tree. `cargo build-bins`
    plus explicit `NESTED_KERNEL=../linux/arch/x86/boot/bzImage
    themis/scripts/update-bins.sh` passed after reverting.
  - 2026-10-01 retained-tick update: audited the child LAPIC/HLT path and
    implemented a candidate HLT contract for the retained periodic tick case.
    Capavisor forwards HLT with `guest_physical_address = vcpu.tsc_deadline()`,
    sets `HLT_EXIT_QUAL_PENDING_PIR` when PIR is non-empty, and sets
    `HLT_EXIT_QUAL_RETAINED_TICK` when the forwarded TSC deadline is zero.
    thhv interprets that retained-tick bit by parking the VP for a bounded
    `THHV_RETAINED_TICK_MS` interval (currently 4 ms) and injecting the local
    timer vector `0xec` only when that retained-tick wait times out. This
    replaces the earlier unconditional 1 ms diagnostic poll and avoids blind
    `0xec` injection for every zero-deadline HLT.
  - Validation with a clean nested kernel
    (`NESTED_KERNEL=themis/guest/kernel/bzImage`) changed the failure mode
    substantially: dom1 got past `/sbin/init`, passed the old cgroup2/normal-RCU
    stall class, and entered sustained systemd activity. Serial output showed
    `systemd-journald`, `systemd-modules-load`, `systemd-random-seed`,
    `systemd-udevd`, `systemd-networkd`, `systemd-resolved`, and
    `systemd-logind` activity. The run still timed out after 420 seconds before
    a confirmed final emergency/login/SSH target. Later output included
    `wait_rcu_exp_gp hogged CPU` and a `clocksource watchdog` report marking TSC
    unstable due to skew, so the retained-tick fix appears to address the
    original silent idle/RCU stall but is not yet a polished final boot fix.
  - Stopped the retained-tick validation boot (`themis-boot-retained`) before
    ending the experiment. Rebuilt and repacked after naming the HLT ABI bits:
    `cargo build-bins && NESTED_KERNEL=themis/guest/kernel/bzImage
    bash themis/scripts/update-bins.sh` passed. Existing warnings remain
    unrelated/pre-existing.
  - 2026-10-01 later update: downgraded hot capavisor/thhv/CHV diagnostics so
    normal validation is no longer dominated by `DBG-HLT-FWD`, `DBG_RUN HLT*`,
    `DBG_IRQFD`, `DBG-ENTRY-RESULT`, `[THEMIS-MSR]`, or `[LAPIC-TIMER]`
    progress logs. Build/repack passed after the cleanup.
  - TSC-watchdog discriminator: without `tsc=nowatchdog`, dom1 marks TSC
    unstable (`clocksource watchdog` reports ~38 ms skew against HPET) and
    switches to HPET, which makes the already slow nested path crawl. Adding
    `tsc=nowatchdog` keeps dom1 on TSC; one 420s run reached
    `emergency.target`, but later runs still reproduced very slow progress and
    the RCU GP timeout warning. So the watchdog/HPET fallback is a real
    secondary slowdown but not the complete root cause.
  - Added low-volume thhv counters. Results so far: the retained zero-deadline
    HLT path fires only once in the long runs (`retained HLT count=1`,
    `retained tick inject count=1`). A nonzero-deadline HLT was also observed
    with the forwarded deadline already in the past
    (`deadline < now`), which exposed an artificial extra host-jiffy sleep in
    thhv before capavisor could re-check and inject the overdue TSC deadline.
    Patched thhv so already-expired forwarded deadlines use `timeout = 0` and
    immediately retry `SWITCH`. Build/repack passed, but later runs were still
    very slow and did not reliably reach emergency, so this is only a partial
    correctness/performance fix.
  - Normal boot with CHV serial/console disabled and a 600s timeout still did
    not ping `192.168.100.2`. thhv counters in that run showed only one
    nonzero-deadline HLT (`deadline HLT count=1`) and no accumulated retained
    tick activity, suggesting the remaining issue is not continuous
    zero-deadline HLT parking. The next lead is either a later TSC-deadline
    re-arm/fire accounting problem, a device/block progress issue, or an
    interaction with the guest's LAPIC timer state that the current coarse thhv
    retained-tick shim does not model.
  - 2026-10-01 later: found and removed a stale CHV-local LAPIC timer source.
    The Themis backend still had a `timerfd`/irqfd bridge for vector `0xec`
    driven by `IA32_TSC_DEADLINE` and LAPIC MMIO timer writes. That duplicated
    capavisor's TSC-deadline ownership. CHV now leaves `IA32_TSC_DEADLINE` and
    LAPIC timer programming to capavisor.
  - Domain-tagged timer logs showed the repeated module-RIP direct `0xec`
    deliveries are `dom=0` physical dom0 timer delivery, not dom1. Dom1 timer
    delivery is mostly PIR-queued when IF is closed and injected when IF opens;
    `0xec` VM-entry injection reaches Linux's APIC timer entry.
  - Dom1 later reached early userspace far enough to report
    `systemd[1]: Failed to find module 'autofs4'`. The nested modules were
    present in `bins.img` but not installed into `dom1.raw`. A first attempt to
    mount/copy modules from inside dom0 immediately before CHV launch perturbed
    dom0 memory and caused `THHV_SET_GUEST_MEMORY` to fail with `EINVAL` after
    translating 1 GiB of guest RAM into many HPA segments. That launch-time
    mutation was removed.
  - `update-bins.sh` now pre-populates `guest/dom1.raw` with
    `/lib/modules/$KVER` on the host before packing it into `bins.img`, using a
    rootless `sfdisk` + partition extract + `fuse2fs` flow. `run-dom1.sh` only
    reports the packaged module version and no longer mutates the disk from
    dom0. `create-bins.sh` now defaults to a 6 GiB sparse image because the
    self-contained dom1 disk plus modules no longer fits reliably in 4 GiB.
  - Validation after module prepopulation: `THHV_SET_GUEST_MEMORY` succeeds
    again (example clean run: 1 GiB translated into 5 HPA segments; later stock
    run into 27 segments). `autofs4.ko` and `modules.dep` are present in the
    host `dom1.raw` rootfs. The old module-missing failure is no longer the
    current blocker.
  - Instrumented Linux kernel (`../../linux/arch/x86/boot/bzImage`) is now a
    major performance confound: with serial disabled it still failed to reach
    `init/main.c` markers in a 600s bound and only cycled through early
    RCU/percpu-rwsem markers (`0x251`–`0x25f`, `0x2d0`–`0x2d5`). A stock nested
    kernel (`guest/kernel/bzImage`) is substantially faster: in a 300s bound it
    reached PCI/virtio enumeration, activated RNG and block devices, registered
    multiple irqfds, and activated virtio-net around CHV time ~168s. It still
    did not ping before the timeout.
  - Current strongest lead is no longer a single lost local timer interrupt.
    Boot progress is dominated by slow forwarded I/O/MMIO and device activation
    under Themis. Hot resolved RIPs include `pci_conf1_read/write`,
    `clockevents_program_event`, `sysvec_apic_timer_interrupt`, and
    `irqentry_exit`; tap carrier appears while CHV is alive, but RX/TX counters
    remain zero before timeout. Next run should add low-volume exit-rate/timing
    counters around IO_INSTRUCTION, EPT/MMIO, irqfd injection, and TSC
    arm/fire, then determine whether the remaining delay is expected
    virtualization overhead or a specific stalled device/interrupt path.
  - 2026-10-01 instrumentation toggle update: capavisor already had
    `THEMIS_TOGGLE_DEBUG` (`0x1d`) and `tools/toggle-debug`; the hot temporary
    capavisor timer/PIR/injection diagnostics are now gated behind
    `serial_rtdbg!` so they stay silent until the runtime toggle is enabled.
    The instrumented Linux `themis_trace()` helper now checks a global
    `themis_trace_enabled` flag before issuing VMCALLs, and `run_init_process()`
    enables both guest tracing and capavisor runtime debug immediately before
    the `/sbin/init` marker (`0x311`). This should eliminate the worst early
    boot slowdown while preserving detailed traces around the current
    post-init/systemd/device-progress failure window.

  Current hypothesis: vector `0xec` VM-entry injection is not the active lost
  interrupt; it reaches Linux's timer entry. PID 1 does enter systemd. The
  retained-periodic-tick / HLT handoff was a real bug and the candidate ABI
  prevents indefinite zero-deadline HLT parking, but the latest counters show it
  is not the whole remaining problem: retained HLT happens only once in the
  long clean-kernel runs. The remaining failure is a later progress/timing
  issue after `/sbin/init`, possibly in TSC-deadline re-arm/fire accounting,
  block/device progress, or LAPIC timer state modeling. `tsc=nowatchdog` avoids
  a misleading HPET fallback slowdown but is not the root fix.

  2026-10-08 update (hypothesis, not established root cause): the child
  LAPIC/timer state-sharing contract is incomplete. CHV conditionally
  keeps nested children in xAPIC mode when capavisor does not advertise
  `FEATURE_X2APIC_VIRT` (current nested-KVM run), shadows xAPIC LAPIC
  LVT/timer writes, and now has `reprogram_lapic_mmio_timer()` as a no-op
  after the stale CHV timer source was removed. At the same time dom1 policy
  traps/emulates `IA32_TSC_DEADLINE` (`0x6e0`) in capavisor, so capavisor is
  the component that fires vector `0xec`; however capavisor's
  `deliver_timer_vector()` only gates on `injectable` plus IF/STI
  interruptibility and does not model the guest-visible LAPIC state that should
  gate a local timer interrupt (SVR enable, LVT timer mask/vector/mode, TPR/PPR,
  ISR/in-service/EOI, IRR/RVI). The observed 600s validation after replacing
  thhv's retry `usleep_range(50, 100)` with `cond_resched()` improved early
  progress (`THEMIS-RATE` 5k exits in ~24.8s vs ~125s before; 10k exits in
  ~104.8s vs ~246s before) but then stopped making visible boot progress:
  no sampled CHV exit counter beyond 10k,
  console stuck at `lvm2-monitor` with an incomplete line beginning
  `[92.582564] w`, no tap RX/TX, and timeout exit 124. The last CHV-visible
  LAPIC writes were timer/APIC state changes
  (`LVT_TIMER` programmed then masked, other LVTs masked, ESR written, SVR
  written), while capavisor's last dom1 entry sample was a preemption-timer exit
  at `asm_sysvec_apic_timer_interrupt`. A runtime-debug sample while stuck
  showed continuing physical timer lazy-unwinds. Missing sampled child-entry
  logs do not distinguish a halted VP, a guest loop, or repeated switching.
  Neither the precise stopping instruction nor the causal role of the LAPIC
  writes has been established; they could be consequences of an earlier fault.

  Architectural implication: choose one owner for the child LAPIC timer
  contract. Either (A) capavisor owns the full virtual LAPIC/clockevent model
  for children (handle xAPIC MMIO timer writes and x2APIC timer MSRs, maintain
  guest-visible LVT/SVR/TPR/ISR/IRR/RVI state, respect masks/in-service before
  injecting `0xec`, and make HLT/deadline wakeups derive from that state), or
  (B) CHV remains the device-model owner and `IA32_TSC_DEADLINE`/LAPIC timer
  programming should be trap-forwarded to CHV, with CHV using the Themis
  interrupt-injection path as the sole source of timer vectors. The current
  split is not inherently invalid: components may cooperate through a coherent,
  capability-checked state-sharing contract. The observed implementation lacks
  that coherence for the timer/LVT path. The recommendation in Current Status
  is to keep virtual VP-local state in capavisor's architecture layer, not to
  move general peripheral emulation into capavisor.

  Last known trace snippets:
  ```
  Final cgroup/RCU timeout edge:
    0x29e 0x2ba 0x2b2 0x2b4 0x2ad 0x2b0 0x2b5 0x2bc
    0x2d0 0x2d1 0x2d6 0x2d7 0x2d8 0x2e7
    then no 0x2f0/0x2f4/0x2fd/0x2fe/0x2da/0x2db

  Repeated capavisor samples:
    [DBG-PIR-DRAIN] ... can_accept=true ... pir=[0x0,0x0,0x0,0x100000000000]
    [DBG-INTR-WINDOW] ... rflags=0x246 ...
    [DBG-HLT-FWD] ... deadline=0x0 pir=[0x0,0x0,0x0,0x0]
  ```

  Next step: agree on the interrupt/timer state contract before implementation,
  then identify a failing transition with bounded state capture (VP run state,
  RIP, deadline, pending/in-service state, LVT, entry-event slot and wakeup
  state). Do not infer the cause from sampled counter silence or restore a
  second independent timer source. Keep `tsc=nowatchdog` for now to avoid the HPET fallback
  confounder, and avoid the heavily instrumented Linux kernel unless a targeted
  trace is needed because its `themis_trace()` exits dominate early boot.

  Validation: `bash -n themis/scripts/run-dom1.sh` passed. `cargo build-bins`
  completed and repacked `guest/bins.img` with the updated launcher and temporary
  capavisor DBG_PRINT output. The instrumented Linux bzImage was built from
  `../linux` and packed with `NESTED_KERNEL=... update-bins.sh`. As usual,
  `tools/toggle-debug` was rebuilt as a generated binary side effect.
  A later `cargo build-bins` also passed after the temporary thhv HLT-timeout
  diagnostic and CHV LAPIC EOI patch, followed by explicit
  `NESTED_KERNEL=../linux/arch/x86/boot/bzImage update-bins.sh`.
  Latest validation builds also passed after log gating, `tsc=nowatchdog`, thhv
  HLT counters, and the overdue-deadline immediate-retry fix:
  `cargo build-bins && NESTED_KERNEL=themis/guest/kernel/bzImage
  bash themis/scripts/update-bins.sh`.
  The toggleable instrumentation update was validated with
  `make -C /home/aghosn/Documents/Programs/linux -j$(nproc) bzImage` and
  `cd /home/aghosn/Documents/Programs/capability-v5 && cargo build-bins`; both
  completed successfully. The resulting instrumented nested kernel was packed
  with `NESTED_KERNEL=../linux/arch/x86/boot/bzImage bash
  themis/scripts/update-bins.sh`, and `guest/bins.img` was refreshed. Remaining
  build warnings are pre-existing.

  Files modified in the latest debugging segment:
  - `themis/capavisor/src/arch/x86_64/hypercall/switch.rs` — temporary PIR
    drain, interrupt-window, and HLT-forward diagnostics; logs pending PIR,
    `can_accept`, RFLAGS, interruptibility, entry-interrupt info, primary
    controls, RIP, and HLT forwarded deadline. Candidate fix still present:
    HLT forwards now carry the child TSC deadline plus named
    `HLT_EXIT_QUAL_PENDING_PIR` / `HLT_EXIT_QUAL_RETAINED_TICK` bits. Hot
    diagnostics are now runtime-toggle gated via `serial_rtdbg!`.
  - `thhv/src/thhv_vp.c` — temporary HLT run-loop diagnostics and the active
    retained-tick HLT path. If capavisor marks retained tick, thhv waits
    `THHV_RETAINED_TICK_MS` and injects `THHV_LOCAL_TIMER_VECTOR` (`0xec`) on
    timeout; high-frequency `DBG_RUN HLT*` logs are now `pr_debug_ratelimited`.
    Low-volume counters log retained/deadline HLT counts and deadline timeouts.
    Already-expired forwarded deadlines now retry immediately instead of
    sleeping for one host jiffy.
  - `thhv/src/thhv_irqfd.c` — temporary low-volume IRQFD assignment and sampled
    successful-injection diagnostics (`DBG_IRQFD`).
  - `cloud-hypervisor/hypervisor/src/themis/vm_impl.rs`,
    `cloud-hypervisor/hypervisor/src/themis/vcpu.rs`, and
    `cloud-hypervisor/hypervisor/src/themis/consts.rs` — stale CHV-local
    timerfd/irqfd LAPIC timer source for vector `0xec` removed/disabled so
    capavisor remains the sole TSC-deadline owner.
  - `themis/capavisor/src/arch/x86_64/hypercall/doorbell.rs` and
    `themis/capavisor/src/arch/x86_64/pid.rs` — temporary low-volume source and
    domain tags for vector `0xec`, used to prove module-RIP direct timer logs
    were dom0 (`dom=0`) rather than dom1. These diagnostics are now
    runtime-toggle gated.
  - `../linux/arch/x86/include/asm/special_insns.h` — added
    `themis_trace_enabled`, `themis_trace_set_enabled()`, and
    `themis_toggle_capavisor_debug()` helpers so guest trace VMCALLs can stay
    off during early boot and enable capavisor runtime debug at the same time.
  - `../linux/init/main.c` — defines `themis_trace_enabled` and enables guest +
    capavisor tracing immediately before the `/sbin/init` marker (`0x311`).
  - `themis/capavisor/src/arch/x86_64/msr_emulator.rs`,
    `themis/capavisor/src/hypercall/mod.rs`, and
    `themis/capavisor/src/arch/x86_64/x86_platform.rs` — temporary targeted
    TSC-arm/fire and VM-entry-result diagnostics used to prove `0xec` reaches
    Linux's timer entry. Hot logs were downgraded, except low-volume
    TSC-arm/fire counters were re-enabled for the next rebooted validation.
  - `themis/crates/vmx/src/vcpu.rs` — IDT-vectoring preservation hardening after
    VM exit; useful but not yet proven to be the root cause of this hang.
  - `../linux/kernel/time/sleep_timeout.c` — temporary RCU GP-kthread
    `schedule_timeout()`/`process_timeout()` probes and globals tracking the
    exact RCU timeout timer address.
  - `../linux/kernel/time/timer.c` — temporary timer-wheel/softirq probes
    (`0x2f0`–`0x2fe`) to determine whether the exact RCU timer expires.
  - `../linux/kernel/time/tick-sched.c` and `../linux/kernel/sched/idle.c` —
    temporary idle/nohz/tick-stop probes (`0x2ff`–`0x310`) added for the next
    discriminator.
  - `../linux/init/main.c` and `../linux/arch/x86/kernel/apic/apic.c` —
    temporary post-init marker and sampled APIC timer interrupt entry/exit
    probes (`0x311`–`0x313`).
  - `../linux/fs/exec.c`, `../linux/arch/x86/kernel/process_64.c`, and
    `../linux/init/main.c` — temporary exec-transition probes (`0x314`–`0x319`)
    to distinguish failed exec from entering userspace and blocking.
  - `skills/debugging-dom-boot.md` — trace registry updated through `0x319`;
    next free range is `0x31A`.
  - `themis/scripts/run-dom1.sh` — added `tsc=nowatchdog` to the default dom1
    cmdline to avoid false TSC-vs-HPET watchdog fallback while debugging the
    real timer path.
  - `themis/scripts/update-bins.sh` — installs nested kernel modules into
    `guest/dom1.raw` before packing, using rootless partition extraction and
    `fuse2fs`; this replaces unsafe dom0 launch-time disk mutation.
  - `themis/scripts/create-bins.sh` — default sparse bins image size raised
    from 4 GiB to 6 GiB.
  - `cloud-hypervisor/hypervisor/src/themis/vm_impl.rs`,
    `cloud-hypervisor/hypervisor/src/themis/vcpu.rs`, and
    `cloud-hypervisor/hypervisor/src/themis/consts.rs` — stale CHV-local
    timerfd/irqfd LAPIC timer source for vector `0xec` removed/disabled so
    capavisor remains the sole TSC-deadline owner.

- **2026-09-28 — dom1 debug console plumbing** ✅ DONE. Updated
  `themis/scripts/run-dom1.sh` so dom1 serial/virtio-console sinks are
  configurable via `CHV_SERIAL` and `CHV_CONSOLE` (default `tty`), enabling
  file-backed boot debugging without duplicate `--serial`/`--console`
  arguments; added `KERNEL_APPEND` for systemd target/cmdline experiments
  and validation for common `file/tmp/...` typo. Example:
  `CHV_SERIAL=file=/tmp/dom1-serial.log
  CHV_CONSOLE=file=/tmp/dom1-console.log sudo /opt/bins/cloud-hypervisor/run-dom1.sh --themis`.

  Files modified this session:
  - `themis/scripts/run-dom1.sh` — added `CHV_SERIAL`/`CHV_CONSOLE` and `KERNEL_APPEND` env knobs, typo validation, and prints selected sinks at launch.
  - `themis/scripts/run-dom1.sh` — added `CGROUP_TEST_INIT=1` mode to inject and boot a one-shot cgroup2 mount test init.
  - `themis/capavisor/src/hypercall/mod.rs` — temporarily re-enabled `THEMIS_DBG_PRINT` serial output so guest `themis_trace()` probes are visible.
  - `skills/debugging-dom-boot.md` — registered trace codes `0x229`–`0x23E`.
  - `../linux/arch/x86/include/asm/special_insns.h` — added/fixed `themis_trace()` helper with VMCALL clobbers.
  - `../linux/kernel/cgroup/cgroup.c` — temporary cgroup mount `themis_trace()` probes.
  - `../linux/fs/kernfs/mount.c` — temporary kernfs mount `themis_trace()` probes.
  - `../linux/kernel/locking/percpu-rwsem.c` — temporary `percpu_down_write()` probes.
  - `../linux/kernel/rcu/sync.c` — temporary `rcu_sync_enter()` probes.
  - `../linux/kernel/rcu/tree_exp.h` — temporary expedited-RCU GP selection, wait, and wake probes.
  - `../linux/kernel/rcu/tree.c` — temporary normal RCU GP request, GP kthread, scheduler-tick, RCU-core, and QS-report probes.
  - `../linux/kernel/rcu/update.c` — temporary old callback-wait path probes.
  - `cloud-hypervisor/hypervisor/src/themis/consts.rs` — temporary CHV LAPIC EOI diagnostic support (`APIC_REG_ISR_BASE`).
  - `cloud-hypervisor/hypervisor/src/themis/vcpu.rs` — temporary CHV LAPIC fallback EOI ISR-clear attempt; observed not to clear because CHV ISR stays zero.
  - `themis/capavisor/src/monitor.rs` — temporary external-interrupt/preemption-timer logging.
  - `themis/capavisor/src/arch/x86_64/{pid.rs,msr_emulator.rs,vmexit/apic.rs}` — temporary interrupt/timer/APIC diagnostics.
  - `themis/capavisor/src/arch/x86_64/hypercall/{switch.rs,doorbell.rs}` — temporary switch/PIR/irq-injection diagnostics.
  - `thhv/src/{thhv_vp.c,thhv_irqfd.c,thhv_part.c}` — temporary run-loop/HLT/irqfd/ioctl diagnostics; `thhv_vp.c` currently includes the HLT timeout diagnostic.
  - `todo.md` — recorded this script/debugging change.
  - `tools/toggle-debug` — generated rebuild side effect from `cargo build-bins`; revert before finalizing diffs if unchanged source is desired.

- **2026-09-07 — Closed A9 audit finding: capavisor's hypercall handlers
  resolving capability handles (`Weak::upgrade()`) outside the capa-engine's
  `execute()` op-lock. Fixed self/handle attestation mediation and, while
  auditing, discovered and removed a fully duplicated legacy text-report
  attestation code path.**

  1. **Mediated attestation**: `themis/capavisor/src/hypercall/attest.rs`'s
     `do_attest_self` previously called `build_structured_attestation`
     directly, unsynchronized. Added `Capability::attest_self_structured`
     and `Capability::attest_structured` (by-handle, with channel-target
     resolution) to `capa-engine/src/domain_api.rs` — both require
     sealed + `MonitorAPI::ATTEST` and run fully inside `execute()`.
     `do_attest_self` now calls `attest_self_structured`.

  2. **Removed duplicated attestation logic**: discovered the engine's old
     text-report path (`attest_domain`/`AttestationReport`/
     `attest_with_context`/`AttestContext`/`DomainSnapshot` in
     `capa-engine/src/attest.rs`, plus `Capability::attest_self`/`attest` in
     `domain_api.rs`) had **zero real callers** — `capa-cli` bypassed it
     entirely and called `attest_domain` directly with its own duplicated
     permission check. Per the user: keep only the binary/structured format
     in the engine (single source of truth, TCB-minimal) and move
     human-readable text formatting into `capa-cli`. Deleted ~630 lines of
     duplicated recursive text-walking logic from the engine; added
     `format_structured_attestation` to `capa-cli/src/rust_backend.rs` to
     format `StructuredAttestation` for humans outside the TCB. Updated all
     engine tests (`unit/attest.rs`, `unit/channel.rs`,
     `integration/{end_to_end,meta,vital_revoke}.rs`) and capavisor's
     boot-time dom0 attestation dump (`main.rs`) to use
     `build_structured_attestation` and check structured fields directly.
     Note: `build_structured_attestation` is flat (no child-subtree
     recursion) unlike the deleted `attest_domain`, and
     `StructuredAttestation` doesn't carry the `cores` bitmap — accepted as
     out of scope since capa-cli/tutorials don't need either.

  3. **Fixed unrelated pre-existing tutorial bug found during verification**:
     `capa-cli/tutos/05-basic-interrupts.txt` was failing because
     `new_restricted` domains (used by every `create-domain`) default their
     blanket interrupt visibility to `NotReport` (introduced earlier in this
     branch's interrupt-semantics redesign as the safe baseline), but the
     tutorial only set a per-vector `REPORT` override on `parent` (vector 55)
     without loosening `parent`'s own blanket default — so `child`'s blanket
     `REPORT` default request violated interrupt-visibility monotonicity
     against `parent`'s still-`NotReport` default. Fixed by adding
     `set-default-interrupt-policy parent REPORT` before `seal parent`.

  Verified: capa-engine `cargo test` + `cargo loom` (all pass, 20 loom
  suites); capavisor/capa-cli `--release` builds clean; all 15 capa-cli
  tutorial integration tests pass. Committed as `ce76bcab8` (attestation
  refactor) and `37c685b39` (tutorial fix).

  This closes out the whole A9 audit begun earlier in the branch: `do_seal`/
  `do_revoke_domain` (via platform callbacks under the engine lock,
  `3e728219f`), `do_add_vp`/`do_switch` (Pattern 1, shared fate,
  `19b5f0dcf`/`c005cffef`), `do_assign_device`/doorbell/`do_inject_interrupt`/
  DomainComm GROW (Pattern 2, promoted to genuine mediated
  `Capability::<Domain>::*` ops, `7a726aa3f`), and now attestation
  (`ce76bcab8`, this entry) are all fixed. No known remaining sites resolve
  capability handles outside `execute()`.

  **Longer-term idea floated but not started**: re-inventory whether
  `PlatformDomain`'s separate mutex can be eliminated in favor of relying on
  `Capability<Domain>`'s own per-object `.read()`/`.write()` for all
  domain-scoped mutual exclusion, removing the need for extra mutexes —
  deferred until the user revisits it.

- **2026-08-05 — Timer emulation fully fixed and verified on hardware; both
  `eunomia-timer` policy-suite scenarios (`deliver`, `suppress`) now pass at
  the harness level. Superseding all prior "attempted fix"/"reverted"/
  "unresolved" timer entries below — those are now historical.**

  Three issues found and fixed this session, in the order the user asked for:

  1. **Root cause of the original hang**: `eunomia/policies/timer/deliver.json`
     set vector `0xEC` (236, LAPIC/TSC-deadline timer) `visibility: "Deliver"`.
     `visibility` governs only real-hardware-interrupt ambient routing (see
     `VectorPolicy` doc in `capa-engine/src/domain.rs`) — completely orthogonal
     to `injectable` (software/emulator-driven injection). `Deliver` let real
     ambient timer interrupts leak into the domain regardless of whether
     `arm()` ever ran (confirmed via a diagnostic build with `arm()` made
     dead code — it hung identically). Fixed: `deliver.json` vector 236
     `visibility` → `"NotReport"` (kept `injectable: true`), matching the
     already-correct `suppress.json` (`NotReport` + `injectable: false`).
     `msr_emulator.rs::deliver_timer_vector` also had the `injectable` gate
     genuinely missing (not just misconfigured) — added via new
     `timer_vector_injectable(core_id)` helper, fails open to `true`.

  2. **Per-core (not per-VCPU) `TSC_DEADLINE` state**: was a
     `static [AtomicU64; MAX_CORES]` in `msr_emulator.rs`, indexed by physical
     core — stale/wrong across VP migration between cores. Moved to a
     `tsc_deadline: u64` field directly on `InactiveVcpu`/`ActiveVcpu`
     (`themis/crates/vmx/src/vcpu.rs`), threaded through `activate()`/
     `deactivate()` so it travels with the VP, not the core.

  3. **`reset_timer()` clobbering bug** (found while investigating why not to
     just rely on the raw VMX-preemption-timer field): `maybe_inject_tsc_deadline`'s
     early-refire branch correctly reprogrammed the VMCS preemption-timer via
     `program_preemption_timer`, but returned `false` — `monitor.rs`'s
     `handle_preemption_timer` calls `reset_timer()` (generic housekeeping)
     whenever the emulator returns `false`, immediately clobbering the just-set
     reprogram. Fixed by returning `true` (honoring the documented "if
     consumed, don't re-arm" contract). Software absolute-deadline tracking via
     `rdtsc()` remains necessary alongside the VMCS field — the hardware
     countdown only decrements in VMX non-root operation, freezing on *every*
     VM exit (not just cross-domain switch), so it alone systematically
     under-counts real wall-clock elapsed time vs. what Linux's TSC-deadline
     clockevent expects.

  4. **Test-harness scenario-awareness gap**: `run-eunomia.sh --policy-suite`
     boots the same ELF once per policy JSON and tallies pass/fail solely from
     the guest's own hardcoded expectation — `test_timer_fires` always expected
     a fire, so `suppress.json` (which correctly, by design, suppresses the
     timer) reported harness-level FAIL despite the fix working correctly.
     Fixed with a zero-new-ABI signal: RDMSR of `IA32_TSC_DEADLINE` under an
     `Emulate` MSR policy always returns the policy's static JSON `"value"`
     (never touched by the WRMSR-only handler registry) — repurposed as an
     expected-outcome flag. Added `rdmsr()`/`expected_fire()` helpers to
     `eunomia/src/timer.rs`; `deliver.json` value `0` = expect fire,
     `suppress.json` value `1` = expect suppression;
     `eunomia/workloads/timer/src/main.rs::test_timer_fires` now branches its
     pass/fail logic on this at startup.

  All debug `[TIMER-DBG]`/`[SWITCH-DBG]` serial prints added during
  investigation were removed from `msr_emulator.rs` and
  `hypercall/switch.rs`. Verified: capa-engine tests pass, `cargo build-bins`
  clean, **hardware-confirmed**: `deliver` scenario passes (timer fires),
  `suppress` scenario passes (timer correctly does not fire, harness reports
  PASS via the new scenario-aware logic).

  **Still open**: user's original item (3) — "not convinced the initial
  LVT_TIMER MMIO write performs according to what we want"
  (`eunomia/src/timer.rs::init()`'s write to the vapic-shadow LVT_TIMER
  register) — raised but not yet resolved to the user's satisfaction. See
  `lvt-timer-policy-gap` in the audit backlog below.

- **2026-08-04 (cont'd) — Working item 2 (`interrupt_inject` re-enable) surfaced
  two regressions, both fixed, plus a new UNRESOLVED hang under active
  investigation:**

  1. **`GET_REG EPERM` regression (all VM boots broken)** — FIXED.
     `VectorPolicy::default_not_report()` (`capa-engine/src/domain.rs`) had
     `read_set: NONE, write_set: NONE`, but these bitmaps are dual-purpose:
     they also gate general GET_REG/SET_REG for fresh/never-run VPs via
     `register_access_check`'s `VECTOR_AVAILABLE` fallback. Changed to
     `read_set: ALL, write_set: ALL` (visibility stays `NotReport`). Verified:
     300+ capa-engine tests pass, `cargo build-bins` clean.

  2. **Spurious LAPIC timer interrupt regression (recurrence)** — FIXED.
     Root cause: CHV's builtin userspace policy configs
     (`cloud-hypervisor/hypervisor/src/themis/defaults/{standard,confidential}.json`)
     hardcoded `interrupts.default.visibility: "Report"`, which
     `policy_walker.rs::walk_interrupts()` unconditionally projects into a
     `DEFAULT_INTR_VISIBILITY` op that **overwrites** the domain's default at
     creation time — silently undoing the capa-engine-level fix for every VM
     using the builtin profiles (dom1, eunomia). Fixed across every layer:
     capa-engine default, CHV's serde fallback (`config.rs::default_visibility()`),
     CHV's builtin JSON profiles, and the eunomia timer-test fixture JSONs
     (`eunomia/policies/timer/{suppress,deliver}.json` — these had
     `injectable: true`/`visibility: Report` contradicting their own
     documented intent; also genuinely fixed, not dismissed).
     **Renamed** CHV config's `Visibility::Suppress` → `Visibility::NotReport`
     everywhere (was confusingly named — nothing is ever dropped; it only
     means "don't raw re-inject on resume", the interrupt is still handled by
     whichever ancestor has `Deliver`).
     **Also**: dom1 previously had NO dedicated `--themis-config` file (relied
     silently on CHV's compiled-in builtin profile) — per repeated user
     request, added `themis/policies/dom1-{standard,confidential}.json` +
     wired into `run-dom1.sh` (always passes `--themis-config`) and
     `update-bins.sh` (packages `themis/policies/` → `/opt/bins/dom1/policies/`).
     Verified: 27 `hypervisor --features themis` tests pass, capa-engine
     tests pass, `cargo build-bins` clean, user confirmed both regressions
     resolved on hardware.

  3. **`wrmsr` policy-suite scenario `04-mixed-default-trap` hangs
     (`chv exit=124`) — UNRESOLVED, actively under investigation.** Scenarios
     1-3 of 4 pass; this scenario passed on 2026-07-20 (see below), so this is
     a genuine regression, not a pre-existing/untested combo — do NOT dismiss.
     `.chv` debug log shows normal boot/policy-push/partition-seal, then a
     stream of serial-port (UART, ports 0x3f8-0x3fd) `THEMIS-EXIT`/`THEMIS-IO`
     trace lines that abruptly stop mid-print of the second MSR test line's
     hex value — consistent with a vCPU hang/livelock during/around test case
     2 (`KERNEL_GS_BASE`, `Emulate` action), not an explicit crash or EPERM.
     Traced logic in `domain_api.rs`/`monitor.rs`: `interrupt_inject` should
     only fire on `Report`-visibility vectors with no callee, and the wrmsr
     scenario JSONs have no `interrupts` overrides (inherit the now-fixed
     `NotReport` default) — so it *shouldn't* be involved, but not yet proven.
     MSR `Emulate`/`Native`/`Trap` actions are a separate policy axis
     (`MsrPolicy`/`interposition.rs`) untouched by this session's changes.
     No local repro possible (no sudo/hardware access in this sandbox); all
     testing is done by the user pasting back logs.
     **Instrumentation added (built + packaged, awaiting next test run)**:
     `serial_println!` added in
     `themis/capavisor/src/arch/x86_64/hypercall/switch.rs`'s
     `if let Some(vector) = switch_ctx.interrupt_inject` block, logging
     vector/target-domain/target-vp whenever raw re-injection fires. Next
     step: user re-runs `sudo ./run-eunomia.sh --themis --policy-suite wrmsr`
     and checks for `[SWITCH-DBG] raw-inject ...` lines around the hang to
     confirm/rule out `interrupt_inject` as the cause. **Session paused here
     for the day — resume with this next.**

     **2026-08-05 update**: re-ran `--policy-suite wrmsr` 6 times total (1
     fresh + 5 back-to-back) on hardware — **4/4 scenarios passed every time**,
     including `04-mixed-default-trap`. No repeat of the `chv exit=124` hang.
     Conclusion: the single prior hang looks transient/environmental (e.g.
     stale `thhv.ko`/device state from a prior run) rather than a deterministic
     regression introduced by this session's changes — nothing in the diff
     between the hang and now besides the added (harmless, log-only)
     `[SWITCH-DBG]` debug print in `switch.rs`. Not yet confirmed whether
     `interrupt_inject` actually fires during a passing run (debug line not
     yet inspected in a `.chv` log) — low priority now given stability, but
     worth a quick check before removing the instrumentation. Moving on to
     testing the other eunomia workloads/policy suites before considering
     this fully closed and cleaning up the debug print.

  All changes this segment remain **uncommitted** (user's explicit workflow:
  "do not commit when you're done, let me review the changes and run tests").
  Modified/added: `capa-engine/src/domain.rs`, `domain_api.rs`,
  `tests/unit/switch.rs`; `cloud-hypervisor/hypervisor/src/themis/{config.rs,
  policy_walker.rs,defaults/{standard,confidential}.json}`;
  `eunomia/policies/timer/{suppress,deliver}.json`;
  `themis/policies/dom1-{standard,confidential}.json` (new);
  `themis/scripts/{run-dom1.sh,update-bins.sh}`; `docs/chv-themis-config.md`;
  `themis/capavisor/src/arch/x86_64/hypercall/switch.rs` (debug instrumentation).

- **2026-08-04 — LAPIC-timer policy bypass: root-caused, attempted fix caused a
  live hang, reverted to baseline. Fixed properly 2026-08-05.**

  **Fixed 2026-08-05** — `themis/capavisor/src/arch/x86_64/msr_emulator.rs`'s
  `deliver_timer_vector` (IA32_TSC_DEADLINE / vector `0xEC` emulation) now
  gates injection on the running domain's `VectorPolicy::injectable` bit for
  the vector (via new `vector_injectable()` helper, using the same
  `platform.get_core_cap(core_id)` lookup pattern as `doorbell.rs`'s
  `do_inject_interrupt` and `switch.rs`'s `current_core_child_cap`) — **not**
  `visibility`, since `injectable` is documented in `capa-engine/src/domain.rs`
  as exactly the axis for "a parent/emulated-device acting as the sole,
  software-controlled source of a vector regardless of real hardware timing",
  which is precisely this case. Fails open (`true`) if the current
  core/domain can't be resolved (matches every policy default and avoids a
  new failure mode during early boot). No VP-swap/full-context-switch
  reintroduced — this is a cheap, local policy read, avoiding the livelock
  from the first (reverted) attempt that routed through
  `forward_interrupt_to_handler`.

  **Fixture correction**: `eunomia/policies/timer/suppress.json`'s vector-236
  override previously set `injectable: true` (only `visibility: NotReport`
  differed from `deliver.json`) — that tested the wrong axis. Since
  `visibility` defaults to `NotReport` for *every* vector under
  `DomainPolicy::new_restricted` (the item-2 fix), gating the timer on
  `visibility` instead of `injectable` would break the LAPIC timer for every
  default-policy domain (dom1, all eunomia workloads with no explicit
  vector-236 override), not just this fixture. Corrected `suppress.json` to
  `injectable: false` so it actually exercises the "never fires" path via
  the same axis the emulator gates on. Updated `config.rs`'s
  `eunomia_timer_interrupt_policies_parse` test accordingly (per-file
  expected `injectable`, not a blanket `true`).

  Verified: `cargo build --release -p
  capavisor` clean, `cargo build-bins` packages cleanly, capa-engine tests
  pass (5 unit tests unaffected — no capa-engine changes needed for this
  fix), `hypervisor --features themis` 72 tests pass (incl. updated
  `eunomia_timer_interrupt_policies_parse`). **Still needs
  live hardware re-validation** with `eunomia/policies/timer/deliver.json`
  (expect fire) and `suppress.json` (expect no fire, no hang) — not yet
  tested on hardware as of this edit.

  **Confirmed bug (original, now fixed)**: `msr_emulator.rs`'s
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
