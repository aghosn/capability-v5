## Themis — Implementation Status & Plan

> **Archives**: Previous todo content archived to:
> - [`docs/archive/todos/archived_todo_09_03_2026.md`](docs/archive/todos/archived_todo_09_03_2026.md) — phases 0–15, BUG-1–15, dom0 bringup
> - [`docs/archive/session-notes/27_03_2026.md`](docs/archive/session-notes/27_03_2026.md) — full history through dom1 multi-core debugging
> - [`docs/archive/session-notes/07_04_2026.md`](docs/archive/session-notes/07_04_2026.md) — differential testing, VITAL cascade fix, TPM, code review

## Current Status

- **Reviewed changes approved for commit (2026-11-27):** Linux generated
  header follow-up committed as 71857b809a4c on top of 31ae7d6b8619;
  Linux worktree verified clean. Parent commit includes shared ABI
  generation/consumers/tests/build checks, Linux integration documentation
  and this tracker. Existing untracked _2025/ and testing-posted.md are
  excluded. Validation results below unchanged; no push or new live boot.
  Next work remains the recorded NMI/interface-unification/dom2 candidates;
  none is implicitly started by these commits.

- **Completing shared C ABI constants (DONE, 2026-11-27):**
  User requested fixing remaining duplicates and rechecking all consumers.
  Expanded Rust exporter for thhv's mirrored hypercall, policy, error,
  CPUID, register-selector, exit-reason, COMM and attestation-size values.
  Replaced remaining literal flag/VP-discovery/intercept-offset uses and
  test-local driver mirrors. Preserved driver-only UAPI/local limits and
  explicitly marked obsolete feature-bit names as legacy compatibility.
  Fixed stale test_intr_loop metadata budgets/ioctl structure by consuming
  the current thhv header; no production ABI values changed.
  Repository-wide pass also migrated tools/toggle-debug.c's private opcode.
  Coverage audit PASS: all 28 opcodes, 25 public policy constants, 10 error
  codes and 71 VP selectors exported; 295 generated definitions with no
  duplicate consumer macros. All 167 snapshotted pre-existing driver ABI
  numeric values unchanged; both generated copies identical and current.
  Validation PASS: 19 ABI unit tests + 2 doc tests; all ten userspace C
  test binaries compile without warnings; C/Rust layout executable
  (including signed-envelope size); utility compiles with -Werror;
  exporter rustfmt, shell syntax and both repositories' diff checks.
  Full cargo build-bins PASS, including thhv.ko against 6.8.0-136 headers;
  retains previously seen monitor/workload/compiler-version warnings.
  Linux bzImage #24 PASS with no compiler warnings/errors.
  No new live boot or /dev/thhv-dependent test execution.
  Packaged bins.img and tracked tools/toggle-debug restored and cmp-verified;
  bins hash remains 09e6f00d...f21bb17. Temporary backup/binary cleanup done.
  User subsequently approved committing all reviewed changes. Linux
  generated-header follow-up is 71857b809a4c; parent changes are included
  with this tracker update. Nothing pushed.
  Files modified in this follow-up:
  - themis/crates/themis-abi/examples/export_c_header.rs and
    thhv/inc/themis_abi.h, ../linux/include/linux/themis_abi.h:
    expanded Rust-owned definitions and regenerated copies.
  - themis/crates/themis-abi/src/domcomm.rs: alias duplicate CPUID leaf
    to canonical cpuid definition (plus earlier test/layout cleanup).
  - thhv/inc/thhv.h: consume generated constants, retain HC aliases and
    driver-only definitions; name attestation field lengths.
  - thhv/src/{thhv_doorbell_irq.c,thhv_translate.c,thhv_vp.c,
    thhv_internal.h}: use shared discovery/flag/COMM constants.
  - thhv/test/{test_attestation.c,test_child_hlt.c,test_coco_attacker.c,
    test_debug_revoke_all.c,test_intr_loop.c,thhv_test.c,test_abi_layout.c}:
    remove private ABI copies/literals and validate signed-envelope size.
  - tools/toggle-debug.c: use generated hypercall opcode.
  - docs/building.md and todo.md: document coverage and validation.

- **Linux review committed (2026-11-27):** All thirty reviewed Linux paths
  committed in ../linux as 31ae7d6b8619
  (x86/themis: consolidate PV platform and device I/O support).
  Staged diff --check passed; post-commit Linux worktree is clean.
  Prior final-source kernel #23 build and full build-bins passed; no
  additional build or boot performed for this commit. Nothing pushed.
  Returned to capability-v5 ABI/source/build/test/documentation review,
  starting with themis/crates/themis-abi/src/pv/descriptor.rs; parent
  changes remain uncommitted. NMI support remains a separate follow-up.

- [ ] **Post-commit: capability-mediated NMI support (PENDING):** User
  explicitly requested this follow-up after the reviewed commit.
  Agree the injection/authority contract before implementation across
  Linux, CHV, thhv and the monitor. Deliver real NMIs, not fixed vector 2;
  handle pending/NMI-blocked state and NMI-window injection. Current
  x2APIC PV IPI service accepts fixed delivery only; native fallback
  does not supply missing NMI semantics. Also address NMI-context use
  of the shared transport (currently rejected), including console/debug
  output. Test cross-CPU backtraces, blocked/repeated delivery and teardown,
  explicitly exercising x2APIC. Previous boot tests did not cover this.
  No NMI implementation included in the current commit scope.

- **Linux PV readability cleanup (DONE; pv.c STAGED):** User requested replacing
  hardcoded protocol indices and values in ../linux/arch/x86/coco/themis/pv.c.
  Implemented named descriptor, DomainComm/attestation and request/completion
  fields, sizes, services and operations, preserving wire format and behavior.
  User approved bringing forward shared C-header generation: Rust owns the
  definitions, thhv and Linux consume checked-in auto-generated copies.
  Ordinary Linux builds need neither Rust nor the parent checkout; parent
  kernel/driver build helpers check freshness. Rust descriptor/record code
  uses the same exported layout constants; attestation offsets/sizes are
  derived from Rust repr(C) types. Existing thhv constant duplicates removed.
  Validation PASS: 19 ABI tests + 2 doc tests; C/Rust layout and wide-mask
  checks; all userspace test binaries compile; matching header copies;
  stale-header rejection; shell syntax, focused rustfmt and diff checks.
  Final-source kernel bzImage #23 and full build-bins PASS, including
  thhv.ko against the pinned 6.8.0-136 headers. Kernel has no compiler
  warnings/errors; production build retains existing monitor/workload and
  kernel compiler-version warnings. No new boots for this wire-preserving
  cleanup; previous live evidence remains recorded below.
  PV checkpatch: zero errors, four existing volatile I/O-pointer warnings.
  pv.c approved and staged at user request; staged diff --check passes.
  Other cleanup edits remain unstaged; earlier staging preserved.
  Packaged bins.img and toggle-debug restored and cmp-verified; bins hash
  remains 09e6f00d...f21bb17. Temporary backups/stale-header probe removed.
  Parent index empty; previous twelve staged Linux files unchanged, with
  the hcall header's new generated-include migration deliberately unstaged.
  Next file presented: ../linux/include/linux/themis_abi.h. Generated
  constants/offsets match the driver copy and preserve integer widths;
  marked auto-generated with regeneration/check commands. Linux builds
  independently of Rust. Header approved and staged at user request;
  staged diff --check passes. Next: the unstaged follow-up in
  arch/x86/include/asm/themis_hcall.h, replacing three local opcode
  definitions with the generated header include; wrappers unchanged.
  Follow-up approved and staged; staged diff --check passes.
  Next file presented: arch/x86/include/asm/io.h. Routes scalar/string
  PIO and selected ioremap-backed MMIO through PV when enabled; standard,
  relaxed and raw MMIO accessors share the hook. Native paths and
  disabled-config stubs remain; decompressor shared accessors unchanged.
  Tradeoff: runtime checks in common kernel accessors when support is
  compiled in; arbitrary assembly/direct pointer accesses are not covered.
  io.h approved and staged; staged diff --check passes.
  Next file: arch/x86/kernel/io_delay.c. Replaces raw OUT assembly for
  delay ports 0x80/0xed with outb(0, port), reusing common PV/native
  routing and avoiding unspecified AL contents. No recursion: ordinary
  outb does not invoke slow_down_io. Existing udelay/none choices remain.
  io_delay.c approved and staged; staged diff --check passes.
  Next file: arch/x86/pci/mmconfig_64.c. Adds selected PV ECAM reads/
  writes because mmio_config_* uses dedicated assembly, bypassing normal
  readl/writel hooks. Native path preserved; both PV returns release the
  existing RCU read lock. mmconfig_64.c approved and staged; staged
  diff --check passes. Next file: arch/x86/include/asm/x86_init.h.
  Extends existing x86_apic_ops read callback with write, EOI and sync
  callbacks. Checked native defaults, wrappers and PV installation;
  declarations are generic, not Themis-specific. Header approved and
  staged; staged diff --check passes.
  Next file: arch/x86/kernel/x86_init.c. Initializes the three new
  IOAPIC callbacks to native implementations, preserving the normal
  path unless a platform explicitly overrides them. Approved and staged;
  staged diff --check passes.
  Next file: arch/x86/include/asm/io_apic.h. Declares the native write,
  EOI and sync functions; supplies NULL aliases when IOAPIC support is
  disabled, following the existing read/restore pattern. Approved and
  staged; staged diff --check passes.
  Next file: arch/x86/kernel/apic/io_apic.c. Retains hardware access in
  native_* functions and routes write/EOI/sync wrappers through callbacks.
  Existing IOAPIC locking and register ordering remain. Dedicated hooks
  cover fixed-mapped IOAPIC accesses, not ordinary ioremap device mappings.
  Approved and staged; staged diff --check passes.
  Next file: arch/x86/include/asm/apic.h. Routes x2APIC ICR writes
  through the PV IPI service when enabled, otherwise retaining WRMSR.
  Explicitly resurfaced the deferred NMI mismatch: Linux NMI requests
  use this path but CHV accepts fixed delivery only, so they fail.
  Approved and staged; staged diff --check passes. NMI follow-up added
  above at user request; no NMI design change.
  Next file: arch/x86/kernel/apic/apic.c. Adds one TSC-deadline helper
  used for both arming and shutdown. PV routes through the shared
  transport; other configurations retain native WRMSR. Existing deadline
  calculation and fence stay in place. Approved and staged; staged
  diff --check passes.
  Next file: arch/x86/kernel/pci-dma.c. Selects the already-reserved PV
  shared DMA pool, marks SWIOTLB enabled and skips ordinary pool/IOMMU
  discovery only when PV initialization succeeds. Other guests retain
  the old path. Approved and staged; staged diff --check passes.
  Next file: include/linux/swiotlb.h. Declares reserved-pool initialization
  and restricted-default-pool detection; exposes existing pool allocation
  helpers under SWIOTLB rather than only DMA_RESTRICTED_POOL. Adds a NULL
  guard to the per-device for_alloc check and disabled-config false stub.
  Checked implementations/users; header approved and staged; staged
  diff --check passes.
  Next file: kernel/dma/swiotlb.c. Initializes the default allocator from
  an already-reserved region, validates bounds/alignment, forces bouncing
  and enables allocations from that pool. Disables dynamic growth so DMA
  stays within the reserved region. Existing alloc/free implementations
  become available without DMA_RESTRICTED_POOL; its device-tree setup
  remains conditional. Reviewed setup/allocator context; approved and
  staged; staged diff --check passes.
  Next file: kernel/dma/direct.c. Skips per-allocation decrypt/re-encrypt
  operations for devices allocating from SWIOTLB pools, whose shared
  memory state is managed at pool level. Ordinary allocations retain
  existing transitions. Checked allocation/free context; approved and
  staged; staged diff --check passes.
  Next file: kernel/dma/pool.c. Skips ordinary atomic DMA pool creation
  when the default SWIOTLB pool is restricted; direct DMA already routes
  nonblocking allocations for those devices through SWIOTLB instead.
  Other systems retain existing initialization. Approved and staged;
  staged diff --check passes.
  Next file: drivers/virtio/virtio_pci_common.h. Removes the extra
  Themis-only notify mapping field used by the retired GPA-doorbell
  workaround. Checked its paired removal in virtio_pci_modern.c; normal
  vq->priv mapping/cleanup is restored there. Header approved and staged;
  staged diff --check passes.
  Next file: drivers/virtio/virtio_pci_modern.c. Removes the retired
  Themis GPA-doorbell callbacks and special mapping/cleanup. Restores
  ordinary virtio notification writes, now handled by common MMIO PV
  routing when active. Notification-data feature selection remains.
  Checked queue setup/teardown; approved and staged. All thirty changed
  Linux paths are now staged, no unstaged/untracked Linux changes;
  staged diff --check passes. No commit.
  Parent ABI cleanup review begins with
  themis/crates/themis-abi/src/pv/descriptor.rs: names existing wire
  offsets/sizes, uses them in encode/decode, and exposes constants for
  C-header generation. Known service mask derived from enum bits.
  Layout, protocol version and validation behavior unchanged. Unstaged.
  Follow-up consistency audit at user request: production descriptor
  encode/decode, request/completion paths, Linux consumers and migrated
  thhv definitions use the shared constants; generated-copy freshness
  check passes. Migration is not exhaustive in tests: pv.rs still uses
  numeric word indices in three corruption tests; descriptor.rs retains
  numeric offsets in malformed-input tests; domcomm.rs builds raw numeric
  test fixtures; thhv/test/test_attestation.c still duplicates attestation
  flag definitions. Fixed at user request: PV tests use named indices
  and descriptor offsets; DomainComm fixtures derive sizes/offsets from
  Rust structs and explicitly name synchronous doorbell kind. C attestation
  test includes the generated header for flags/entry sizes and asserts
  its report-header size matches the generated ABI.
  Validation PASS: 19 ABI unit tests + 2 doc tests, userspace test builds,
  C/Rust layout executable, both generated-header freshness checks and
  diff --check. rustfmt reports only the same four pre-existing descriptor
  formatting differences confirmed against HEAD; left unrelated lines
  untouched. Linux stays clean. Four test-bearing files modified for this
  follow-up: src/{pv.rs,pv/descriptor.rs,domcomm.rs} in themis-abi and
  thhv/test/test_attestation.c. No staging/commit of parent changes.
  Broader thhv audit found further omissions (now fixed; see top entry): retired
  notification flag remains numeric in thhv/src/thhv_translate.c:638
  and thhv/test/test_attestation.c:397; VP discovery still hardcodes the
  PV CPUID leaf/subleaf/version in thhv/src/thhv_doorbell_irq.c:178-180.
  These already have generated constants. Previous consistency claim
  was too broad. Separately, thhv.h still maintains other hypercall,
  policy-kind, error and CPUID values locally; exporter currently only
  covers the selected subset, not the entire ABI.
  No commit.
  Files modified/created:
  - themis/crates/themis-abi/src/{pv.rs,pv/descriptor.rs,domcomm.rs}:
    authoritative named layout/constants, unchanged protocol behavior.
  - themis/crates/themis-abi/examples/export_c_header.rs and
    themis/scripts/generate-abi-header.sh: reproducible exporter/checker.
  - thhv/inc/{themis_abi.h,thhv.h}: generated definitions and consumer.
  - thhv/{Makefile,test/test_abi_layout.c}: freshness/dependency and
    cross-language layout checks.
  - ../linux/{include/linux/themis_abi.h,arch/x86/coco/themis/pv.c,
    arch/x86/include/asm/themis_hcall.h}: generated copy and named consumers.
  - themis/scripts/build-kernel.sh: check both copies before parent build.
  - docs/building.md and todo.md: regeneration instructions and handoff.

- **Post-commit candidate: unify guest hypercall interfaces (PENDING):**
  User wants one shared implementation rather than parallel Rust/C
  interfaces. Reconcile themis/crates/libthemis/src/{lib,ffi}.rs with the
  current ABI and use a common interface from built-in Linux support and
  thhv where practical. thhv/Makefile still builds the Rust archive,
  but thhv/Kbuild does not link it; the FFI attestation wrapper exposes
  the old interface while current C wrappers use chunked reports.
  Current Linux wrappers accepted temporarily. Shared constants/header
  generation brought forward into the PV cleanup above; wrapper/FFI
  implementation unification is still pending. Consider that or dom2
  boot as the next work after the reviewed commit; neither started.

- **Linux file-by-file review (2026-11-27, IN PROGRESS):** User requested
  an interactive review led by the agent. Order: configuration/platform
  setup, I/O, interrupts, DMA, then documentation. First file examined:
  ../linux/arch/x86/Kconfig. Added SWIOTLB selection is needed for the
  reserved shared DMA pool in non-confidential PV mode too; updated help
  replaces the retired address-matched notification description. No
  functional issue found in this file's diff. Kconfig staged at user
  request; staged diff --check passes and no other Linux file is staged.
  Next file examined: ../linux/arch/x86/coco/themis/platform.c, including
  build/registration wiring and ACPI mapping/init ordering. Consolidates
  early detection/channel setup, normal hypervisor callbacks, APIC timer
  configuration publication and ACPI SystemMemory handling. RAM-aware
  mapping preserves private RAM; no new functional issue found in this
  read-through. platform.c staged at user request; staged diff --check
  passes. Only Kconfig and the new platform.c are staged; old platform
  file deletion and build/registration wiring await their review.
  Next file examined: ../linux/arch/x86/kernel/setup.c. Moves the single
  platform bootstrap after early mapping/static-call initialization and
  before early console parsing; removes the later bootstrap and separate
  CoCo call now owned by platform.c. Checked initialization dependencies;
  DMA reservation remains in the normal hypervisor callback. No issue
  found in this diff. User agreed to retain initialization here rather
  than split detection into head64.c; setup.c staged at user request.
  Staged diff --check passes; staged files are Kconfig, platform.c and
  setup.c. Next file: arch/x86/coco/Makefile, adding the Themis backend
  under CONFIG_THEMIS_GUEST (not limited to confidential guests).
  No functional issue found; coco/Makefile staged at user request.
  Staged diff --check passes. Next file: coco/themis/Makefile, building
  platform.o and pv.o into the selected backend. No issue found; this
  new Makefile staged at user request; staged diff --check passes.
  Next file: arch/x86/kernel/cpu/Makefile, removing the old
  themis_platform.o build entry now replaced by coco/themis/platform.o.
  No issue found; CPU Makefile staged at user request; staged diff
  --check passes. Next file: deletion of
  arch/x86/kernel/cpu/themis_platform.c. Its detection, feature state
  and exported query helpers are preserved in the reviewed new
  coco/themis/platform.c. No functionality lost; deletion remains
  staged at user request; staged diff --check passes.
  Next file: arch/x86/include/asm/hypervisor.h. Appends the internal
  X86_HYPER_THEMIS enum value and declares x86_hyper_themis, matching
  the existing hypervisor registration pattern. No issue found;
  header staged at user request; staged diff --check passes.
  Next file: arch/x86/kernel/cpu/hypervisor.c. Adds x86_hyper_themis
  to the detection table under CONFIG_THEMIS_GUEST, following existing
  entries. No issue found; hypervisor.c staged at user request and
  staged diff --check passes.
  Next file: arch/x86/include/asm/themis_platform.h. Corrects CPUID
  signature ECX bytes, updates feature bits to match themis-abi, and
  declares backend operations with disabled-config stubs where needed.
  Checked guarded PIO/IPI/deadline consumers. Existing signature comment
  incorrectly said NUL padding; corrected to two spaces at user request
  to match the actual ABI. Header staged at user request; staged diff
  --check passes.
  Next file: arch/x86/include/asm/themis_hcall.h. Replaces retired
  address-matched notification with held-capability NOTIFY, adds return
  to caller via SWITCH(0), and unsigned self-attestation chunk requests.
  Checked opcodes, argument/result registers and scratch clobbers against
  the ABI, thhv and monitor attestation handler. No functional issue
  found in this diff; hypercall header staged at user request with
  interface unification deferred as recorded above. Staged diff --check
  passes. Next file: arch/x86/include/asm/fixmap.h. Reserves 256 permanent
  virtual mapping slots for per-VP shared control pages under
  CONFIG_THEMIS_GUEST; descriptor parser caps VP count at 256. No issue
  found in this diff; fixmap.h staged following user clarification that
  their "ok" approved staging. Staged diff --check passes.
  Explained how the per-VP mappings back synchronous requests.
  Next file: arch/x86/coco/themis/pv.c. Read the full implementation:
  descriptor validation, held-doorbell discovery, ordered per-VP request/
  completion exchange, device/interrupt adapters and reserved shared DMA.
  Compared record layout, ordering and platform opcodes with themis-abi.
  Protocol mirroring belongs in the deferred interface-unification work;
  single IOAPIC and missing NMI support remain documented limitations.
  pv.c remains unstaged pending user review.
  Files modified for this correction:
  ../linux/arch/x86/include/asm/themis_platform.h (signature comment only);
  todo.md (review progress).
  Present the next file automatically after each staging approval.
  No kernel source edits or commits.
  Files modified: todo.md (review progress only).

- **Linux backend cleanup (DONE; UNSTAGED):** Consolidated boot support in
  ../linux/arch/x86/coco/themis/{platform,pv}.c. One early setup entry
  establishes the shared channel before early-console I/O; normal x86
  hypervisor registration handles later DMA reservation and APIC write
  override. Central x86 MMIO accessors replace branded virtio/MSI wrappers,
  preserving local RAM/firmware access. Registered ACPI SystemMemory
  handling replaces ACPICA/interpreter and OS-specific branches. thhv
  remains loadable; no capability, CHV or monitor source changes.
  The new AML runtime probe initially caught a handler regression:
  acpi_os_read/write_memory can ioremap private RAM through the shared
  window (failed #20 confidential probe at canonical GPA 0x120cf000).
  Fixed with RAM-aware acpi_os_map_iomem/unmap_iomem, acpi_os_read_iomem
  and normal write accessors. The same probe now passes confidentially;
  this was not established to be the previously recorded RAM-mapping bug.
  Final validation PASS: matching kernel bzImage #21; backend checkpatch;
  parent/Linux diff --check; three fresh-monitor cycles with existing dom0
  (four CPUs) and confidential, non-confidential PV, and legacy dom1 (two
  CPUs each), all with seccomp enabled. SSH, disk R/W, networking, IRQ/HLT,
  repeated Sync child teardown, signed attestation, COMM growth/reload and
  parent post-child cleanup pass (standard aliased guest skips exclusive
  growth). Both PV modes pass reserved shared DMA checks. Session-only
  probes pass RAM 8/16/32/64-bit and relaxed accessors, PCI MMIO, AML
  RAM/device fields, and accessors compiled with Themis disabled. Matching
  module imports checked; no kernel/monitor BUG, CPU WARNING, Oops/panic or
  VMM ERROR signatures in final logs. No dom2 or full NMI support claimed;
  NMI injection/API design remains explicitly separate by user choice.
  Owned VMs/helpers stopped; isolated dom0/bins/OVMF disks removed. Original
  bins.img unchanged, SHA256 09e6f00d...f21bb17. Nothing staged/committed.
  Logs: /tmp/linux-backend-cleanup-{build-final,probe-link,final-live-boots}.log
  and /tmp/linux-backend-cleanup-final-{confidential,pv,standard}-live-*.
  Reusable session probes/runners: session files/thhv-live/backend-probe/
  and kernel-cleanup-boots.py. Next: review the cleaned Linux diff; NMI
  work needs an agreed capability-mediated injection API, not native
  fallback or silently substituting fixed interrupts.
  Files modified: ../linux/arch/x86/{coco/themis/,coco/Makefile,
  include/asm/{io,apic,hypervisor,themis_platform}.h,kernel/{setup,io_delay}.c,
  kernel/cpu/{Makefile,hypervisor.c,themis_platform.c,themis_pv.c},
  pci/mmconfig_64.c} (backend relocation, callbacks and central accessors);
  drivers/acpi/{osl.c,acpica/exregion.c}, drivers/pci/msi/{msi.c,msi.h},
  drivers/virtio/{virtio_pci_common.c,virtio_pci_modern.c} and
  include/linux/virtio_pci_modern.h (restore generic accessors/interpreter;
  preserve old virtio workaround deletion); include/linux/themis_io.h
  removed (no branded wrappers needed).
  docs/chv-themis-config.md (integration boundary/limitations);
  todo.md (scope/results).

- **Linux integration review (DONE; kernel read-only):** Read all 29 tracked
  modified files and the new themis_pv.c/themis_io.h; followed early setup,
  device I/O, interrupt and shared-DMA paths. Confirmed correctness issue:
  arch/x86/include/asm/apic.h:234 routes every x2APIC ICR write through PV,
  including NMI backtraces (arch/x86/kernel/apic/hw_nmi.c:34 and local.h:38),
  but CHV hypervisor/src/themis/pv.rs:391 accepts only fixed interrupts.
  The rejected completion panics in themis_pv.c:319. This alternate x2APIC
  path was not exercised by the previous successful boots.
  Recommendation: consolidate support in a built-in Themis backend, reuse
  x86_init.hyper, x86_platform.guest, CPU/APIC and PCI operations where
  suitable, and minimize branded checks in generic virtio/MSI/ACPICA code.
  Ordinary built-in driver init still follows the earliest platform work;
  automatically loading thhv.ko cannot replace early hooks. TDX/SEV are
  useful precedents, but their #VE/#VC I/O handlers require corresponding
  CPU exception delivery, not merely registering a generic callback.
  Current IOAPIC support also explicitly assumes one controller at
  0xfec00000; preserve/document that machine contract or generalize it.
  DMA review found no additional confirmed defect in the reserved-pool
  lifecycle or atomic coherent-allocation path. Earlier matching-kernel
  build and standard/confidential boots remain the runtime evidence;
  no new build/boot during this read-only review. Linux HEAD/index and
  tracked diff SHA256 68990de8...e20 unchanged; nothing staged.
  Next: agree the cleanup scope before modifying Linux; dom2 deferred.
  Files modified: todo.md (review findings and architectural handoff only).

- **Parent review checkpoint (DONE):** Included this final handoff with the
  reviewed engine, CLI, capavisor, driver, ABI, policies, workloads and docs,
  plus CHV pinned at ef73ea57b. Validation results are recorded below.
  Next: review the existing ../linux modifications, specifically what can
  move into thhv instead of intrusive Linux hooks. Linux changes remain
  uncommitted and untouched by this parent checkpoint. Dom2 stays deferred.
  Files modified: todo.md (final checkpoint/next-review handoff).

- **Parent CHV pointer staging (DONE):** Staged cloud-hypervisor at
  ef73ea57bb45c38fa752cc4023eeb0790b5cd09a. Verified the index matches CHV
  HEAD, staged diff --check passes, and unrelated staging is unchanged.
  No parent commit or push. Files modified: todo.md (unstaged handoff).

- **CHV staging and commit (DONE):** Committed all 27 reviewed CHV files as
  ef73ea57b (`themis: add capability-based PV device and CPU services`).
  Includes the PV transport/device-memory/AP firmware work, review fixes,
  seccomp integration, diagnostic cleanup and strict Clippy fixes. Existing
  test/build/boot results are recorded below; commit-time diff --check PASS.
  CHV worktree clean. Parent staging unchanged (eda83fcc...8cf992c); its
  updated CHV submodule pointer is deliberately unstaged. No parent commit
  or push. Files modified: todo.md (this unstaged commit handoff).

- **CHV strict Clippy cleanup (DONE; UNSTAGED):** Fixed all 33
  diagnostics in the Themis backend and its tests. Mechanical fixes complete,
  no lint suppressions or JSON schema changes. Strict Clippy with
  `-p hypervisor --features themis,kvm --all-targets -- -D warnings` and all
  73 backend tests PASS. Uppercase ALL/NONE JSON parsing/serialization is
  preserved and checked in the existing interrupt-policy regression.
  Fix-only delta reviewed against a snapshot of the dirty worktree.
  Full release build-bins PASS. Original bins.img and toggle-debug restored
  and cmp-verified; bins SHA256 remains 09e6f00d...f21bb17. Temporary source
  snapshots/artifact backups removed. No additional boots for this
  behavior-preserving lint cleanup; the earlier final standard/confidential
  boot results remain recorded below. Existing staging preserved
  (eda83fcc...8cf992c), CHV index empty; no commits.
  Logs: /tmp/chv-clippy-cleanup-{before,fix,final,tests,build}.log;
  fix-only delta: /tmp/chv-clippy-cleanup-final.patch.
  Files modified: CHV hypervisor/src/themis/{abi,config,emulator,
  hypervisor_impl,mod,policy_walker,pv,vcpu,vm_impl}.rs (derived defaults,
  internal enum naming with explicit serde casing, redundant conversions/
  closures, range checks, formatting and test assertions); todo.md (handoff).

- **ABI/docs follow-up staging (DONE):** Staged the reviewed timer ABI and
  configuration documentation updates in themis/crates/themis-abi/ and docs/.
  Verified no unstaged changes remain in either path, staged diff --check
  passes, and unrelated staging/HEAD are unchanged. CHV index remains empty.
  No commit. Files modified: todo.md (this unstaged staging handoff).

- **CHV review fixes (DONE; new edits UNSTAGED):** Addressed the four
  review findings: guest-configured deadline timer delivery and real TSC
  frequency discovery/calibration; CPUID-identity IPI routing; actual
  cores/shared-RAM/Native+Trap CPUID policy application; removal/gating of
  temporary diagnostic chatter. New timer worker is stopped/joined on
  teardown. All 73 focused CHV regressions and isolated VMM/vCPU seccomp
  filter tests pass. Seccomp now derives ioctl values from the actual backend
  ABI, allows the current launch/doorbell/injection operations, and permits
  timer rearming on vCPU threads. Strict Clippy initially found backend lint
  debt, resolved by the subsequent mechanical cleanup recorded above.
  Coordinated timer ABI change retires PV opcode 9, adds deadline operation
  10 (requires previously published timer settings) and LVT update 11.
  Matching guest kernel build completed successfully in ../linux. User
  approved that checkout change; thhv itself is unchanged in this task.
  For the later Linux review, explicitly reconsider which
  existing Linux integration hooks can live in thhv instead of the kernel.
  New Linux edits: arch/x86/kernel/cpu/themis_pv.c (publish timer settings),
  arch/x86/include/asm/themis_platform.h (declaration), and
  arch/x86/include/asm/apic.h (publish timer LVT changes).
  First live dom0 checks passed, but standard dom1 exposed an incorrect new
  SIPI pre-check: GET_VP_STATE reads monitor activity, not thhv's software
  wait-for-SIPI. Removed the pre-check; thhv already rejects duplicate startup
  batches. No driver change needed. Removed leftover ARCH-DBG
  startup output and gated ivshmem doorbell notifications at debug level.
  Confidential boot exposed invalid virtual timer register readback.
  Simplified PV deadline handling to use its explicitly published LVT state
  rather than overwrite it from native APIC readback. Nonzero deadlines
  still fail without prior configuration; no fallback.
  Final validation PASS: 73 backend tests, isolated seccomp regression,
  19 ABI unit tests + 2 doc tests, private AP firmware / IOAPIC direct-EOI /
  shared-MMIO VMM tests, full release build-bins, matching guest kernel,
  backend formatting and root/CHV/Linux diff --check.
  Both fresh final monitor cycles PASS with seccomp enabled: dom0 on four
  CPUs, standard and confidential dom1 on two CPUs. Dom0: eventfd, repeated
  Sync child teardown, IRQ/HLT, COMM growth, attestation and driver reload.
  Each Linux dom1: authenticated SSH, disk R/W, network, signed attestation,
  driver unload/reload and clean VMM shutdown; parent post-child teardown,
  attestation and reload also pass. Confidential additionally passes shared
  DMA reservation, three-page RX/TX growth and oversized-growth rejection.
  Standard growth skipped because its RAM is aliased, not exclusive.
  No timer/service errors or kernel/monitor BUG, CPU WARNING, Oops or panic
  signatures in final logs; ordinary image/tap configuration warnings remain.
  No TPM quote, dom2, live custom-topology/policy or direct physical page
  accounting coverage claimed. Monitor-local timer emulation and inherited
  MSI destination routing are outside these CHV legacy-IPI/timer fixes.
  Owned VMs/helpers stopped; temporary disks and verified backup removed.
  Original bins.img restored and cmp/SHA256 verified (09e6f00d...f21bb17);
  generated toggle-debug executable diff removed. No temporary production
  debug instrumentation remains from this task; useful errors are retained.
  Logs: /tmp/chv-fixes-{tests,abi-tests,seccomp-tests,platform-tests,
  build-bins-final,kernel-build,live-boots}.log and
  /tmp/chv-fixes-{standard,confidential}-live-*.
  Files modified for these fixes:
  - CHV hypervisor/src/themis/{config,hypervisor_impl,policy_walker,vm_state}.rs
    and defaults/confidential.json: apply configured cores, CPUID and shared RAM.
  - CHV hypervisor/src/themis/{timer,vcpu,vm_impl,pv,consts}.rs: owned timer
    worker, actual frequency/vector/mask, APIC-identity IPI and targeted SIPI.
  - CHV hypervisor/src/themis/{abi,mod}.rs and vmm/src/seccomp_filters.rs:
    reuse current ABI ioctl constants and test actual restrictive filters.
  - CHV hypervisor/src/themis/emulator.rs, arch/src/x86_64/regs.rs and
    vmm/src/device_manager.rs: remove/gate temporary diagnostic output.
  - themis/crates/themis-abi/src/pv.rs and docs/chv-themis-config.md:
    coordinated timer operations and implemented configuration semantics.
  - The three Linux files listed above: publish guest timer state.
  - todo.md: progress/results and later Linux/driver placement review reminder.
  Root staging preserved (3bd2aed4...59b44a); CHV index empty. No commits.

- **CHV change review (DONE; source unchanged, UNSTAGED):** Reviewed the
  tracked changes and four new modules; no confirmed new functional
  regression or hardcoded domain handle found. Not yet clean enough to
  call principled: inherited timer code fixes the interrupt vector to
  Linux's 0xEC (hypervisor/src/themis/vm_impl.rs:122) and guesses a 19.2 MHz
  crystal or 3 GHz TSC (vcpu.rs:52-104); the new PV timer route reuses this.
  Legacy fixed IPIs still equate APIC IDs with VP indices (vcpu.rs:1369),
  unlike the new PV resolver; nonidentity CPU topology can misroute/drop
  interrupts. Inherited config gaps remain: CPUID Native/Trap overrides
  are skipped (policy_walker.rs:619), cores_mask is always !0
  (hypervisor_impl.rs:96), and general.shared_regions has no consumer.
  These are existing limitations, not regressions attributed to this diff.
  Unconditional THEMIS-DBG/THEMIS-EXIT/MMIO-DBG and LAPIC trace output
  remains in vm_state.rs, vm_impl.rs and vcpu.rs; remove or gate diagnostic
  chatter without removing real error reporting before staging.
  Validation PASS: 65 Themis hypervisor tests, private AP firmware test,
  IOAPIC direct-EOI test, shared-MMIO VMM integration test (68 total),
  and CHV diff --check. Earlier standard/confidential dom1 boots used this
  CHV source; custom topology/policy behavior was not runtime-tested.
  Root staged diff remains unchanged (3bd2aed4...59b44a); CHV index empty.
  No CHV source edits, staging or commits. Files modified: todo.md only
  (this unstaged review handoff). Test logs: /tmp/chv-final-review-*.log.

- **thhv staging (DONE):** Staged all reviewed thhv/ changes, including
  the META allocation cleanup fix and new doorbell/RX sources and tests.
  Verified no unstaged/untracked thhv changes remain, staged diff --check
  passes, and staging outside thhv/ is unchanged. No commit.
  Files modified: todo.md (this unstaged staging handoff).

- **thhv META fix live checks + review (DONE):** Both fresh-monitor boot
  cycles PASS: dom0 + shipped standard dom1, and dom0 + shipped confidential
  dom1. Guest-side SHA256 verifies the current fixed modules were tested.
  Dom0 (6.8.0-136, four CPUs): eventfd, four Sync child creation/teardown
  cycles, HLT, two eight-round IRQ tests, three-page RX/TX growth, oversized
  rejection, signed attestation and driver reload. After each Linux child
  exits, another Sync child teardown plus attestation and driver reload PASS
  (ten Sync child teardown checks total across both monitor boots).
  Both Linux dom1 profiles (6.19.14+, two CPUs): SSH, disk R/W, network,
  signed attestation, driver unload/reload and clean VMM shutdown PASS.
  Confidential additionally passes declared shared DMA reservation and
  three-page RX/TX growth/oversized rejection; standard growth deliberately
  skipped because its RAM is aliased, not exclusive. No TPM-quote coverage.
  Parent/child kernel and monitor logs show no BUG, CPU WARNING, page-ref,
  Oops or panic signatures. No direct physical page-accounting measurement.
  thhv inspection is complete for this change set; dom2 remains explicitly
  deferred and was not created. Matching dom1 module uses the built kernel's
  vmlinux.symvers via KBUILD_EXTRA_SYMBOLS; import CRCs verified.
  All owned VMs/helpers stopped; isolated bins copy, dom0 overlay and OVMF
  variables removed. Original bins.img SHA256 remains 09e6f00d...f21bb17;
  existing staging unchanged (c763c11e...b496ce0). No new driver source edits,
  debug code, staging or commits in this validation step.
  Logs: /tmp/thhv-meta-fix-live-boots.log and
  /tmp/thhv-meta-fix-{standard,confidential}-live-*.
  Files modified: todo.md (results/review handoff). Updated only session-local
  boot/guest runners and matching driver artifacts outside Git.

- **thhv META allocation cleanup (DONE; UNSTAGED):** Replaced per-page EPT
  META bookkeeping with allocation head/order tracking. Both DomainComm
  provisioning and SET_GUEST_MEMORY use the same helper, which records
  ownership before sending META. Whole blocks, including rounded-up unused
  pages, are freed exactly once after successful domain revocation. Failed
  SEND retains backing until teardown rather than risking a premature free.
  Removed the post-SEND tracking-array allocation failure/leak path.
  Validation PASS: normal and CONFIG_THHV_TEST driver builds, userspace test
  build, full release cargo build-bins, diff --check. Session-only regression
  harness exercises the actual helper/cleanup code with strict allocator
  stubs: mixed orders, non-power-of-two counts, repeated cleanup, failed
  SEND, all three allocation failures, and preservation of earlier batches.
  Wrong-order free and late-tracking negative controls both fail as expected.
  No new VM boots; actual guest allocator reuse is not claimed.
  Original bins.img restored after packaging writers exited, cmp/SHA256
  verified (09e6f00d...f21bb17), temporary backup removed. Existing staging
  unchanged; no commit or production debug code.
  Files modified: thhv/src/thhv_internal.h (allocation records/list and helper
  declaration), thhv/src/thhv_part_mem.c (shared allocation/SEND ownership
  helper and guest-memory caller), thhv/src/thhv_part.c (DomainComm caller,
  allocation-list initialization and whole-block teardown), todo.md (handoff).

- **thhv change review (DONE; driver unchanged):** Reviewed tracked changes
  and new doorbell/RX sources and tests. No additional confirmed regression
  or dom0-only execution dependency found. One inherited cleanup defect
  remains: EPT META batches use unsplit higher-order alloc_pages without
  __GFP_COMP (thhv_part.c:434, thhv_part_mem.c:234), but teardown assumes
  compound metadata and otherwise frees individual pages (thhv_part.c:65-71).
  Retain/free each allocation head and order once, or allocate independent
  pages; the current mismatch can leak backing or trip page-ref checks.
  DomainComm buffer teardown itself frees the correct order. This finding
  is static, not runtime-reproduced or established as the deferred dom2
  fault's cause. CONFIG_THHV_TEST driver and userspace test build PASS
  against guest 6.8.0-136 headers; thhv diff --check PASS.
  No driver source edits or staging; only this handoff note is new.

- **Staging update (DONE):** User requested staging capa-engine/,
  themis/crates/themis-abi/ and docs/. Staged all changes in those paths,
  including the COMM revocation fix and ABI/documentation follow-ups.
  Verified no unstaged changes remain there and other staged content is
  unchanged. No commit. This todo.md handoff update remains unstaged.

- **COMM revocation fix + dom0/dom1 boots (DONE; new edits UNSTAGED):**
  Implemented domain-level SEND(COMM) bindings and moved UncommRegion to
  revoke_subtree entry, before descendant cleanup as well as local zeroing
  and access restoration. SEND permits regions with descendants; a third
  mediated regression exposed this edge after the initial leaf-only fix.
  All three new regressions and the extended VP cleanup test failed before
  their respective fixes. Final validation PASS: 382 default tests,
  472 address_translation tests, all 60 Loom cases, CLI release build,
  release build-bins and ISO, git diff --check. Engine fmt --check still
  reports pre-existing formatting differences beginning at attest.rs:96;
  no formatting sweep performed.
  Repeated both boot cycles on the final descendant-safe monitor:
  dom0 PASS on four CPUs, including two eight-round IRQ runs, independent
  three-page RX/TX growth, oversized rejection, signed attestation and reload.
  Shipped standard dom1 PASS: Linux 6.19.14+, two online CPUs, authenticated
  SSH, disk R/W, network, signed attestation and driver unload/reload.
  Standard growth skipped because aliased RAM is not exclusive.
  Shipped confidential dom1 PASS: the same guest checks plus declared PV
  DMA reservation, three-page RX/TX growth and oversized-growth rejection.
  No relaxed test policy used. Fresh monitor for each profile; both guests,
  VMMs and outer VMs shut down cleanly. No dom2 created or investigated.
  No TPM attached; no TPM-quote coverage claimed. Individual COMM cleanup
  classification/order is regression-tested through applied engine updates;
  direct live page-content zeroing/reuse was not separately measured.
  Parent dmesg still logs redundant segment REVOKE(-ENOENT) after whole-domain
  revocation has already removed those caps; no driver cleanup changes here.
  Logs: /tmp/comm-fix-{standard,confidential}-final-* and
  /tmp/comm-fix-{engine-*,cli-build,final-build-bins,final-iso-build}.log.
  Original bins.img restored separately after packaging writers exited,
  cmp/SHA256 verified against the backup (09e6f00d...f21bb17).
  Owned temporary disks removed; no owned VMs/helpers remain.
  Existing index preserved (cached diff SHA256 a9ae6ded...f1f2dbbe);
  no staging or commits. No new production debug logging.
  Files modified: capa-engine/src/domain_api.rs (SEND COMM binding),
  capa-engine/src/capability.rs (invalidate before all covered reclamation),
  capa-engine/tests/integration/comm.rs (three regressions + VP ordering),
  todo.md (handoff). Session-only boot probes/scripts remain outside Git.

- **Debug-artifact inventory (REVIEW ONLY; no cleanup performed):**
  Added unconditional pre-seal CPUID table logging remains in the dirty
  cloud-hypervisor submodule, hypervisor/src/themis/vm_state.rs:604-610.
  thhv/src/thhv_domcomm.c grow[1] through grow[6] progress prints also remain,
  but predate this change stack (present in HEAD); they are not new test edits.
  One-off live probes, test policy and matching modules remain in session
  files/thhv-live; logs are in /tmp. None are in the Git diff.
  Temporary VM disk copies were deleted and no owned VMs/helpers remain.
  Existing untracked _2025/dom1-1vcpu-boot-proof.log and testing-posted.md
  were not created or modified by this live validation; left untouched.
  Doorbell test sources are intended regression tests, not temporary probes.
  Files modified for this inventory: todo.md only.

- **Capavisor arbitrary-domain fixes (STAGED; COMM reclamation gaps found):**
  User requested staging the six files: arch/x86_64/{boot/capa.rs,
  vmexit/cpuid.rs}, hypercall/{domcomm,vp}.rs, platform/{domain,mod}.rs.
  Staged only those paths; no commit. This tracker remains unstaged.
  Follow-up reclamation review: integration_comm passes 24 tests in each
  default/address_translation configuration, but these check emitted cleanup
  updates and bindings, not live page zeroing/reuse or complete teardown.
  Confirmed gaps to fix after review:
  - SEND with COMM emits CommRegion(vp_id=UINT32_MAX), but does not populate
    comm_binding. revoke_subtree defaults an absent binding to VP 0, so
    individual revocation can miss pending/active DomainComm cleanup.
    Sources: capa-engine/src/domain_api.rs:860-925 and
    capa-engine/src/capability.rs:565-573; capavisor platform/mod.rs:839-862.
  - revoke_subtree queues ZeroMemory and parent ChangeRights before
    UncommRegion. UpdateBatch preserves insertion order and execute applies
    it in order; channel invalidation is therefore not guaranteed to precede
    zeroing/restoring access. Sources: capa-engine/src/capability.rs:493-573,
    src/update.rs:355-359 and src/platform.rs:740-747.
  Successful self-COMM growth allocations intentionally survive driver unload
  for domain lifetime; there is no per-region Linux allocator reclamation
  hook for successful growth revocation. Failed cleanup revoke retains pages
  rather than freeing possibly live backing.
  Scope clarification: the confirmed binding/order findings concern revoking
  an individual COMM region while its domain remains alive, not proof of a
  full-domain destruction leak. Full domain revocation recursively revokes
  owned memory, removes the PlatformDomain (dropping all ring bookkeeping),
  and parent thhv frees initial DomainComm backing/unpins guest RAM.
  Self-growth pages inside a child's RAM return with that RAM on domain
  teardown; retaining them across module reload is intentional, not itself
  a domain-cleanup leak. Live allocator reuse/full nested teardown remains
  unverified because of the recorded RAM fault; its cause is not established.
  Logs: /tmp/thhv-comm-reclamation-{default,translated}.log.
  Files modified for this review: todo.md only (findings/staging handoff).

- **Engine self-COMM fixes (STAGED):** User requested staging, not committing,
  capa-engine/src/domain_api.rs and capa-engine/tests/integration/comm.rs.
  Other staging updates are recorded above; existing staged review work
  is preserved. No commit created. This tracker update remains unstaged.

- **thhv live dom0/dom1 validation (DONE; nested-child failure remains):**
  User requested both-domain runtime tests after the arbitrary-domain fixes.
  Isolated writable bins copy + dom0 qcow2 overlay; originals untouched by VMs.
  Dom0 PASS: 8 IRQ rounds on four CPUs, eventfd --grow, pending-close,
  Sync child discovery/notify/resume, signed Ed25519 attestation, unload/reload
  and repeat IRQ/eventfd. No TPM attached, so no TPM-quote coverage claimed.
  Standard Linux dom1 (6.19.14+, two CPUs) boots and loads thhv successfully;
  fresh signed 17 KiB attestation verifies nonidentity/scattered HPA mappings.
  Its shipped NotReport interrupt policy correctly rejects self-doorbells;
  aliased standard RAM correctly rejects SEND META for a nested child.
  Session-only private-RAM/PV test policy grants Deliver on vector 37;
  shipped policies are unchanged. Private dom1 PASS: 8 IRQ rounds on two
  CPUs, eventfd --grow (including generic child create/transfer/destroy),
  independent three-page RX and TX growth, oversized growth rejection,
  signed attestation, pending-close, unload/reload and repeat IRQ/attestation.
  Debug mmap PASS on nonidentity memory: HPA 0x13916f000 resolves to caller
  GPA 0x1eb6f000 and reads the expected bytes; MAP_PRIVATE returns EINVAL,
  unknown HPA returns ENXIO. Growth allocations also have nonidentity and
  scattered HPAs. Deliberately reordered CPU/VP IDs were not exercised.
  NOT a complete dom1 pass: after generic child teardown, Linux faults
  clearing RAM at GPA 0x13650000; separate Sync-child attempt reproduces at
  GPA 0x913c000. RIP 0xffffffff821e5767 resolves to clear_page_erms,
  sibling Linux arch/x86/lib/clear_page_64.S:52, EPT qualification 0x182.
  CHV treats the RAM fault as undeclared confidential MMIO and stops.
  Exact failure phase/root cause remains unconfirmed; do not claim dom2
  execution/Sync success. Independent checks above passed before this test.
  Hypothesis: investigate nested META/COMM backing lifetime and translated
  parent mappings across provisioning/revocation; do not relax protection.
  Repeated private launch after earlier child teardown also failed SEND
  META(-EINVAL); fresh monitor state launches private Linux successfully.
  Newer kernel removed asm/cpuid.h; use asm/processor.h on both kernels.
  Dom1 module build requires modules_prepare and the existing vmlinux.symvers
  via KBUILD_EXTRA_SYMBOLS (no forced loading or suppressed symbol errors).
  Standard packaging PASS after this portability fix; restored original
  bins.img separately after all fuse writers exited, cmp/SHA verified.
  First legacy boot hit CHV debug-stderr EAGAIN on SSH's terminal; redirect
  stderr to a guest file. Retry boots cleanly and shuts down cleanly.
  Wait for actual VMM exit after guest poweroff before reusing its TAP.
  Logs: /tmp/thhv-live-{dom0-*,dom1-*,monitor*.log,build-bins.log};
  key evidence dom1-{private-tests,isolated-tests,isolated-dmesg,sync,
  sync-failure-stderr}.log and dom0-final-tests.log. Dom0 IRQ and signed
  attestation still pass after the nested failure. All owned VMs stopped.
  Next: agree a focused investigation of the reproducible nested RAM fault.
  Session files/thhv-live contains matching modules, test-only policy,
  independent growth/debug-mmap probes and launch scripts.
  Files modified for this validation: thhv/src/{thhv_main,thhv_domcomm,
  thhv_doorbell_irq}.c (portable CPUID include); todo.md (runtime handoff).

- **thhv arbitrary-domain fixes (IMPLEMENTED; live results above):**
  REGISTER_COMM accepts SELF_CAPABILITY + UINT32_MAX for domain-level backing,
  separate from per-VP COMM, with aligned RW memory and normal SET checks.
  Removed the boot-only self-domain capability. New mediated with_domain_comm
  validates ownership/binding and holds the operation lock through adoption.
  CPUID DomainComm discovery advertises per-page GPA lookup and synchronous
  growth; domains without a channel no longer receive dom0's locator.
  Child provisioning translates/sends each page and sizes EPT META using the
  actual child addresses. Growth prepares mappings/arrays before NOTIFY,
  preserves unread bytes when capacity changes, and returns completion in
  registers rather than through the resized RX ring. Successful backing
  persists across driver reloads; partial multi-page progress is retained and
  errors are reported. Revoking active backing disables the channel before
  clearing/freeing memory. Failed revocation retains potentially live backing.
  Linux CPU-to-native-VP identity is discovered on each online CPU; Async
  doorbells and the IRQ probe use that mapping. Debug HPA listing translates
  Linux PFNs; MAP_SHARED debug mmap translates each HPA back to a known GPA.
  Fixed partial ring-map cleanup and partition-creation error teardown.
  Validation PASS: engine cargo test (379), address_translation suite (469),
  all 60 Loom models, themis-abi (19 unit + 2 doc), CLI release build,
  test-enabled driver/userspace-test build, capavisor release check, final
  BINS_TARGETS=capavisor,thhv cargo build-bins and git diff --check.
  Regressions cover child self-registration, multiple self regions alongside
  VP COMM, nonidentity GPAs, readonly rejection, lock-held callbacks, revoke
  before lock acquisition and wrapped unread bytes/u32 cursor rollover.
  Full-workspace cargo fmt --check remains nonclean on pre-existing formatting
  (first engine difference attest.rs:96; first themis difference aarch64/boot.rs).
  Rewritten hypercall/domcomm.rs is rustfmt-formatted; no formatting sweep.
  Added test_doorbell_eventfd --grow to interleave
  Async notifications, RX/TX growth and fresh attestation on a test-enabled
  module; regular test invocation is unchanged. Live checks now cover this,
  test_doorbell_irq and nonidentity debug mmap in both-domain validation
  above; reordered CPU/VP identities and dom1-to-dom2 isolation remain untested.
  Both packaging runs preserved/restored the complete bins.img. The final
  same-shell restore raced packaging teardown; after confirming no remaining
  image writers, repeated restoration separately and verified cmp/SHA256:
  09e6f00d9e2b289581ce67fd82eb0ac3c2d11adad29fdeab28f93d6b1f21bb17.
  Logs: /tmp/thhv-domain-reuse-{engine-default,engine-tests,abi-tests,loom,
  cli-build,build,final-build,final-check,engine-fmt,themis-fmt}.log.
  Files modified: capa-engine/src/domain_api.rs and tests/integration/comm.rs
  (mediated self COMM and regressions); themis/capavisor/src/arch/x86_64/
  {boot/capa.rs,vmexit/cpuid.rs} (generic boot/discovery); hypercall/{domcomm,vp}.rs
  (synchronous growth and registration decoding); platform/{domain,mod}.rs
  (scattered backing, growth and revocation); themis-abi/src/{lib,domcomm}.rs
  (discovery/completion ABI and tested resize helper); thhv/src/{thhv_domcomm,
  thhv_hvcall,thhv_internal,thhv_translate,thhv_part,thhv_part_mem,thhv_main,
  thhv_doorbell,thhv_doorbell_irq}.{c,h} as applicable (driver fixes);
  thhv/inc/thhv.h (CPU-index contract), thhv/test/test_doorbell_eventfd.c
  (optional growth test), thhv/README.md and docs/domain-comm.md (contracts/
  live procedure), todo.md (handoff). All fixes remain unstaged; original
  index hash unchanged: f3c06f78830304fb97f2dcd414a9351fcafcf34ad3d21b86355f6ac7b3adcbcc.
  No commit created.

- **thhv grouped review / arbitrary-domain reuse (REVIEW DONE; fixes pending):**
  Module detection, self-attestation, current domain ID, memory-handle discovery
  and normal GPA-to-HPA translation are domain-neutral. No driver source edits
  or staging in this review. Confirmed remaining assumptions:
  - Ring growth requires an attested self-domain handle
    (thhv_translate.c:657, thhv_domcomm.c:341); only root boot provisions one
    (themis/capavisor/src/arch/x86_64/boot/capa.rs:173). Normal child creation
    does not, and REGISTER_COMM does not resolve the SELF sentinel.
  - Child DomainComm provisioning and ring growth translate only the first
    page of a multi-page allocation, then assume contiguous HPAs
    (thhv_part.c:475, thhv_domcomm.c:362). Linux-contiguous GPAs do not
    guarantee contiguous host backing in dom1.
  - Async doorbells validate a Linux CPU index and pass it unchanged as a
    capability VP index (thhv_doorbell.c:48, thhv_doorbell_irq.c:183).
    Equality is assumed, not established; native CPUID 0x40000005/subleaf 1
    exposes the actual current VP identity.
  - Debug HPA listing actually reports Linux PFNs, and debug mmap uses its
    HPA argument directly as a guest PFN (thhv_part_mem.c:613,
    thhv_main.c:545). These debug interfaces assume identity mapping.
  Also reconfirmed ring-growth lifecycle issue: fallible krealloc/memremap
  occurs after successful monitor ACK; error cleanup revokes/frees growth
  pages, and partial mapping returns success (thhv_domcomm.c:452-503).
  Next step: agree fixes before changing source or staging the driver.
  Validation: source/diff review only; no new build or dom1 execution.
  File modified: todo.md only, to preserve review findings; left unstaged.

- **Themis policies walkthrough (DONE):** User accepted and staged
  themis/policies/{dom1-standard,dom1-pv,dom1-confidential}.json: explicit
  legacy/PV transports, parent-shared PV resources (4 KiB control per VP,
  24 MiB I/O), control/platform services and confidential protection/CPUID
  settings preserved explicitly under whole-section inheritance.
  Cached whitespace check PASS. No commit created.
  This tracker update remains unstaged.

- **Follow-up staging:** User requested staging remaining Eunomia workload
  and documentation changes. eunomia/workloads/revoke/src/main.rs comment
  cleanup is staged; all workload changes are staged without build artifacts.
  Include docs/architecture/child-domcomm.md terminology cleanup and the
  accumulated todo.md updates. Leave testing-posted.md and _2025/ untouched.
  No commit requested or created.

- **themis-abi walkthrough:** User accepted and staged
  themis/crates/themis-abi/src/lib.rs, including the legacy revoke-alias
  removal: unified ownership opcodes, capability-doorbell ABI, YIELD exit,
  scoped policy selectors/ranges and PV discovery definitions. Cached
  whitespace check PASS. User also accepted and staged domcomm.rs: v1 ring
  protocol/helpers, port/value doorbell events and attested doorbell lookup.
  User accepted and staged new pv.rs (request/completion protocol) and
  pv/descriptor.rs (resource discovery/layout validation); cached whitespace
  check PASS. User accepted and staged regs.rs, which only changes the instruction_bytes
  comment to explain the field is reserved for wire compatibility and the
  monitor never exports code bytes. All themis-abi files are now staged.
  User also accepted and staged libthemis/src/{lib,ffi}.rs cleanup follow-ups
  (remove compatibility helpers and expose unified FFI revoke).
  Cached whitespace check PASS. All themis/crates changes now staged;
  driver and related documentation cleanup follow-ups remain unstaged.
  No commit created; this tracker update remains unstaged.

- **Legacy hypercall-name cleanup (DONE):** Removed Rust/C legacy revoke
  opcode aliases (including both HC/OP header spellings), send_chan/
  accept_chan helpers and revoke_mem/revoke_domain hypercall wrappers.
  Migrated libthemis FFI to themis_revoke(parent, sub), thhv memory cleanup
  calls to themis_revoke(parent, sub), domain cleanup to
  themis_revoke(handle, 0), and parent-channel provisioning to themis_send.
  Numeric hypercall ABI and engine/CLI high-level APIs are unchanged.
  Source scan finds no removed names in the guest libraries, thhv, Eunomia
  or CHV. Rebuilt FFI/module symbol tables confirm unified revoke/send/accept.
  Validation PASS: themis-abi host tests (18 unit + 2 doc), no_std FFI release
  staticlib build, BINS_TARGETS=capavisor,thhv,eunomia cargo build-bins
  component builds (capavisor, thhv/module test binaries, all 13 workloads),
  final BINS_TARGETS=thhv cargo build-bins after the last header alias
  removal, and git diff --check. Formatting remains nonclean on existing
  differences starting in themis-abi/src/domcomm.rs:129; no formatting sweep.
  No live boot. Preserved/restored the complete bins.img around both
  packaging runs; cmp and SHA256 verify the original image:
  09e6f00d9e2b289581ce67fd82eb0ac3c2d11adad29fdeab28f93d6b1f21bb17.
  Both exact temporary image backups removed.
  Logs: /tmp/themis-legacy-cleanup-{build,final-build,fmt}.log.
  Files modified: themis/crates/libthemis/src/{lib,ffi}.rs (remove aliases/
  unified FFI); themis/crates/themis-abi/src/lib.rs and thhv/inc/thhv.h
  (remove opcode aliases); thhv/src/{thhv_hvcall.c,thhv_internal.h}
  (remove compatibility wrappers/declarations);
  thhv/src/{thhv_part,thhv_part_mem,thhv_main,thhv_shmem,thhv_vp,thhv_domcomm}.c
  (migrate callers and related diagnostics); eunomia/workloads/revoke/src/main.rs
  and docs/architecture/child-domcomm.md (update related terminology);
  todo.md (status). Follow-up edits remain unstaged; approved index preserved.
  No commit created.

- **libthemis walkthrough / SEND_CHAN caller audit:** Checked Rust, C/FFI,
  CLI, engine, Lean and cloud-hypervisor references after noticing the guest
  send_chan helper's changed meaning. No Rust callers of libthemis::send_chan.
  thhv/src/thhv_part.c:363 uses its separate C themis_send_chan wrapper to
  transfer a freshly created self-channel to a child; the wrapper delegates
  to generic SEND with the correct argument order. Engine/CLI/Lean send_channel
  operations already mean channel-capability transfer. No wrong-semantics
  caller found and no source fix needed. User accepted and staged
  themis/crates/libthemis/src/lib.rs; cached whitespace check PASS.
  No commit created; todo.md audit note remains unstaged.

- **Eunomia walkthrough (DONE):** User accepted and staged
  eunomia/src/domcomm.rs: shared ring-capacity calculation, invalid-ring
  checks, wrapping cursors and corrected acquire/release fence placement.
  User also accepted and staged eunomia/src/ivshmem.rs: legacy device
  doorbells use an MMIO write rather than the removed GPA-based hypercall.
  User accepted and staged eunomia/workloads/hypercall/src/main.rs, removing
  checks for the obsolete SEND_CHAN/ACCEPT_CHAN opcodes.
  User reviewed and staged eunomia/policies/pv/standard.json: standard-profile
  inheritance, parent-shared control/I/O regions and a synchronous control
  service channel. User clarified staging only, not committing.
  User accepted and staged eunomia/workloads/pv/{Cargo.toml,Cargo.lock,build.rs,
  src/main.rs}: descriptor/attested-doorbell validation and eight VP-0 control
  round trips per channel, alternating NOTIFY and voluntary return.
  All Eunomia changes staged; no target/ build artifacts included.
  Cached whitespace check PASS. No commit created.
  This review-status update to todo.md remains unstaged.

- **Documentation staging:** User requested staging all pending documentation
  without a walkthrough: CONTEXT.md, changed docs/ Markdown files,
  skills/{debugging-dom-boot,running-inside-dom0}.md, themis/README.md,
  thhv/README.md and todo.md. No source changes included in this action.
  Leave testing-posted.md and _2025/ untouched. No commit requested.

- [x] **CLI typed ACCEPT fix (DONE):** Both typed CLI ACCEPT methods now
  check the existing pending-transfer view before calling unified engine
  ACCEPT. Commands run serially through the backend. Wrong-type requests
  return an explicit error without consuming the offer; channel handle
  resolution uses checked lookup rather than indexing. Two regressions
  reproduced the previous failures and now verify the offer remains pending
  and can subsequently be accepted by the correct method. Tests set up and
  transfer capabilities through backend operations, with no direct state
  mutation. Files: capa-cli/src/rust_backend.rs (checks/tests), todo.md (status).
  Validation PASS: cargo test --manifest-path capa-cli/Cargo.toml (2 unit
  regressions and 16 tutorial tests), cargo build --manifest-path
  capa-cli/Cargo.toml --release, and scoped git diff --check. Two existing
  dead-code warnings remain. Formatting check remains nonclean on existing
  differences starting in capa-cli/build.rs; no formatting sweep performed.
  Log: /tmp/themis-cli-typed-accept-fmt.log. Resolves the typed-acceptance
  finding; nine other independent findings remain open. User accepted the
  fix; capa-cli/src/{backend,rust_backend}.rs staged, including the reviewed
  backend API additions. Cached whitespace check PASS; prior index preserved.
  No engine changes or commit. User accepted and staged commands/capability.rs,
  commands/mod.rs, parser.rs, completer.rs, main.rs and session.rs: raw-handle
  command dispatch, API flags, help and replay/export behavior. Both doorbell
  examples and tests/tutorial_tests.rs also accepted and staged. Cached
  whitespace check PASS. User also accepted and staged capa-cli/src/platform.rs:
  notification recording, pending-interrupt display and a 128-message
  per-recipient queue cap. All CLI changes are now staged. User explicitly
  clarified staging only, no commit. Simulator has no consumption path, so queues
  remain full after reaching the cap until reset. User informed of this
  limitation and unsupported Rust-test export for raw capability commands.
  todo.md also remains unstaged.

- [x] **Monitor policy/exit race fix (DONE):** User approved keeping
  policy lookup and action under one engine operation lock. Add a scoped
  VP-exit context with lock-free internal policy/runtime/return helpers;
  validate the saved domain+VP binding after lock acquisition, skipping an
  exit whose VP was replaced during revoke polling. Integrate monitor CPUID,
  MSR and ordinary exit handling without nested mediated operations.
  Add focused regressions for replacement VPs and lock-held delivery.
  Preserve the user's staged review stack; fix staged after user review.
  Implemented with_vp_exit and scoped VpExit helpers; monitor keeps policy
  handling under the lock. Interrupt routing uses the same protection,
  retrying physical interrupts against the replacement VP rather than
  discarding them. Five regressions pass: revoked source, same-domain VP
  replacement, policy/runtime write/return lock lifetime, interrupt handoff
  lock lifetime and callback error release.
  Rechecked tests against the user's mediated-API rule: all child setup,
  policy changes, switches and revocation use domain_api operations. New
  test hook only schedules real operations before shared-lock acquisition;
  no direct child/tree/policy/VP mutation. Existing root boot setup remains.
  Validation PASS: cargo test (377 tests), address_translation (467 tests),
  all five cargo loom suites (60 tests), no_std address-translation check,
  CLI release and BINS_TARGETS=capavisor cargo build-bins. git diff --check
  PASS. cargo fmt --check still finds pre-existing stack differences starting
  in src/attest.rs; only new blocks formatted. Logs:
  /tmp/themis-monitor-lock-{targeted,default,translation,loom,nostd,cli,capavisor,fmt}.log.
  Full bins.img restored and compared byte-for-byte after packaging; SHA256
  remains 09e6f00d9e2b289581ce67fd82eb0ac3c2d11adad29fdeab28f93d6b1f21bb17.
  Temporary image backup removed. No VM boot for this fix.
  This resolves the stale-policy-after-revoke finding; the other ten findings
  remain open. User requested a focused diff at completion.
  Files modified: capa-engine/src/domain_api.rs (scoped exit handling/shared
  policy helpers); tests/common/mod.rs (one-shot acquisition hook);
  tests/unit/switch.rs (five mediated regressions);
  themis/capavisor/src/monitor.rs (locked policy/action dispatch);
  arch/x86_64/hypercall/switch.rs (locked interrupt routing with retry);
  todo.md (status). All five source/test files staged at the user's request;
  prior index preserved, cached whitespace check PASS. No commit created.
  todo.md remains unstaged.

- **Next capavisor walkthrough:** arch/x86_64/vmexit/{mod,cpuid}.rs.
  Local EPT violations now log and inject #GP at both user and kernel
  privilege, removing the old kernel-mode instruction skip. CPUID advertises
  capability doorbells and extends the maximum Themis leaf to LEAF_PV; its
  identity subleaf returns current VP index and PV ABI version. Both files
  accepted and staged at user request; cached diff whitespace check PASS.
  Current walkthrough: monitor.rs routes exit/CPUID/MSR decisions through
  mediated engine APIs for effective per-VP policy, uses engine FeatureAction,
  and surfaces lookup/runtime-MSR errors by logging and halting. Emulated MSR
  writes update per-VP runtime values rather than attested configuration.
  Stale-policy-after-revoke finding prompted the completed fix above.
  monitor.rs accepted and staged with the race fix. Remaining architecture
  glue in arch/aarch64/mod.rs, arch/x86_64/{mod,x86_platform}.rs and
  arch_traits/types.rs accepted and staged at the user's request: handoff
  exports/ARM stub, interrupt destination refresh and pending-vector delivery
  before guest entry, and notification queue-full mapping to ERR_BUSY.
  Cached whitespace check PASS. Capavisor walkthrough complete; no commit
  created. todo.md remains unstaged.

- **Switch-handler review position:** Now walking
  arch/x86_64/hypercall/switch.rs. First item: hardware Call/Return/Interrupt
  handoffs run through the engine-owned callback while VP reservations and
  operation locking remain held, rather than after engine return. Source
  state is saved before it becomes claimable elsewhere. Handler registers
  its active Vcpu for the callback. Remaining items: zero-handle yield,
  effective VP policy masks and removal of guest instruction-byte copying
  on forwarded MMIO exits. File unstaged; this is not whole-file acceptance.
  Lock-lifetime clarification: execute's shared operation guard spans the
  hardware callback and final state publication. Individual capability-domain
  guards and platform-domain mutexes are short-lived, not held throughout.
  Running/Locked VP states reserve ownership across the callback; revoke and
  exclusive policy updates cannot interleave. This is not a domain-wide
  exclusive lock or exclusion of all concurrent shared engine operations.
  User accepted the hardware-handoff/locking item after this clarification.
  User subsequently explicitly requested staging switch.rs; it is staged,
  cached diff whitespace check PASS. Handoff/locking item accepted; yield,
  policy masks and instruction-byte removal have not yet been walked through.
  No commit created.

  Next switch.rs item explained: SWITCH handle zero follows the engine
  return path with synthetic THEMIS_EXIT_YIELD. The yielding VP gets SUCCESS
  and advances past VMCALL before saving; its caller resumes with YIELD as
  the switch exit reason. Synthetic exit metadata is zero rather than stale
  hardware exit fields; missing return caller yields an ordinary error.
  User accepted yield handling. File already staged at user request.
  Policy masks and instruction-byte
  removal still await walkthrough.
  Explained remaining switch.rs items: engine supplies effective per-VP
  exit/interrupt read masks to callbacks instead of capavisor reading domain
  defaults; permitted registers alone are copied to COMM. Removed guest
  instruction fetch/copy from MMIO forwarding. Verified CHV themis/vcpu.rs
  fetches instructions through emulator context for nonconfidential guests
  and explicitly rejects legacy confidential MMIO, which requires PV services.
  User accepted the remaining items after confirming that the capavisor
  instruction-reading block was deleted (page-walking helpers themselves
  were not removed). switch.rs walkthrough is complete; file already staged.

- [x] **Attestation continuation/locking fix (2026-11-26, DONE):**
  User approved an engine-mediated callback holding the shared operation
  lock through signing, cache access and queue publication. Generate a
  report only for the initial request; continuations must validate sealed,
  ATTEST permission and revocation without rebuilding the inventory.
  Implemented Capability::with_self_attestation: caller checks, optional
  snapshot and delivery all run inside execute(). The handler's platform
  mutex protects signing, cache access and RX publication within that engine
  lock. Continuations request no snapshot and do not walk the inventory.
  Focused tests cover lock lifetime/error release, skipped inventory and
  unsealed/unauthorized/revoked callers on initial and continuation requests.
  Validation PASS: targeted attestation/switch/channel tests, cargo test
  (372 tests), cargo test --features address_translation (462 tests), all
  five cargo loom suites (60 tests), no_std address-translation check,
  CLI release build and BINS_TARGETS=capavisor cargo build-bins.
  git diff --check PASS. Logs: /tmp/themis-attest-lock-*.log.
  cargo fmt --check still reports existing stack-wide differences, beginning
  in src/attest.rs; no unrelated formatting sweep.
  Modified files: capa-engine/src/domain_api.rs (mediated callback),
  capa-engine/tests/{common/mod.rs,unit/attest.rs} (regressions),
  themis/capavisor/src/hypercall/attest.rs (locked cached delivery), and this
  tracker. Full bins.img backed up and compared before packaging, restored
  afterward and compared byte-for-byte; original image SHA256 remains
  09e6f00d9e2b289581ce67fd82eb0ac3c2d11adad29fdeab28f93d6b1f21bb17.
  Temporary backup removed. No live VM boot for this fix.
  User approved staging: hypercall/attest.rs and its engine/test follow-up
  (domain_api.rs, tests/common/mod.rs and tests/unit/attest.rs) are staged.
  Cached diff whitespace check PASS; no commit created.

- [ ] **Joint capavisor source review (2026-11-26, IN PROGRESS):**
  Started after the user accepted the engine test review. Mapped the current
  capavisor diff and began with hypercall/mod.rs dispatch and
  hypercall/doorbell.rs creation decoding. The caller comes from the current
  core's capability binding; CREATE_DOORBELL delegates validation and
  mutation to Capability::create_doorbell. Walkthrough now covers NOTIFY
  dispatch and platform::commit_doorbell: publish RX event first; Sync saves
  the successful reply/advanced source RIP before engine-owned interrupt
  handoff, Async posts through inject_via_pid and returns normally. Queue
  reservation failure returns before publication, reply advancement or
  interrupt unwind. Now walking through apply_policy_change: engine-provided
  effective per-VP MSR/exit snapshots populate private MSR/I/O bitmaps.
  Confirmed snapshots are emitted on ADD_VP, relevant SET/reset and SEAL;
  removal of the old capavisor seal helper does not remove seal projection.
  User accepted the policy-projection walkthrough. Current item:
  snapshot_comm_regs and registers::merge_register_writes preserve pending
  pre-seal initialization when later runtime writes are forbidden or empty;
  permitted new writes replace only matching registers. Invalid COMM mapping
  now returns an explicit error. Next mod.rs item: handoff_vp callback.
  User accepted the COMM merge/error-handling item. Final mod.rs item now
  reviewed: handoff_vp delegates the engine-selected Call/Return/Interrupt
  to the architecture backend using the monitor's registered active VP.
  Return/interrupt handoff saves/releases hardware before the engine makes
  the source VP available to another core. User accepted the final item;
  platform/mod.rs and its new registers.rs helper are staged.
  Reviewed platform/domain.rs. Diff overview covers removal of legacy
  address-matched doorbell state/vector setter, cached attestation payload,
  checked ring capacity/address arithmetic, and prepare/commit RX writes
  replacing padding/recursive enqueue with checked two-page copying.
  Clarified first/second split one <=4096-byte message across backing pages;
  larger attestations use successive <=4080-byte payload chunks from the
  cached report. User accepted; platform/domain.rs is staged.
  Current file: hypercall/attest.rs. Reviewed offset-zero cache creation,
  signed tail/request consumed only at offset zero, cached continuations
  and one <=4080-byte payload per call (queue-full publishes no chunk).
  Cache is one per domain; overlapping retrievals must be serialized.
  User requested removing redundant continuation reports and keeping delivery
  under engine locking. Implemented the approved mediated callback above;
  continuations validate the caller without generating another report.
  Attestation fix validated and explained; user requested the next item.
  User subsequently approved staging hypercall/attest.rs and its engine/test
  follow-up; all four files are now staged.
  User accepted hypercall/capa.rs; the file is staged. Changes unify SEND/ACCEPT/REJECT
  across capability kinds and REVOKE across tree/domain revocation; policy
  decoding adds optional VP scope, checked key widths, emulation ranges and
  explicit INHERIT resets. Cached diff whitespace check PASS; no source edits.
  User accepted hypercall/mod.rs dispatch; the file is staged. New NOTIFY uses the engine;
  Sync handoff returns without touching the newly active VP, Async/error
  paths use normal reply writeback. Unified REVOKE/transfer dispatch removes
  legacy opcodes. ENUMERATE now returns the smallest pending ID >= start,
  with an explicit found flag. Cached diff whitespace check PASS; no source edits.
  Current walkthrough: arch/x86_64/hypercall/{doorbell,mod}.rs. Removes the
  old GPA-matched, parent-only doorbell enqueue/forwarding path and its
  architecture hook; engine NOTIFY plus platform::commit_doorbell replace it.
  write_reply becomes crate-visible for the platform callback's Sync reply.
  Explicit INJECT_INTERRUPT body is unchanged. User accepted both files;
  both are staged, cached diff whitespace check PASS.
  Current walkthrough: arch/x86_64/hypercall/vp.rs. Every VP receives private
  MSR and I/O bitmaps (seven META pages total), rather than sharing the first
  VP's bitmaps. I/O starts fully trapped until engine policy projection;
  removes hardcoded serial-port exceptions and old APIC-access-page argument.
  User accepted; file is staged. Cached diff whitespace check PASS.
  Current walkthrough: arch/x86_64/vcpu_ext.rs plus comment-only changes in
  arch/x86_64/vcpu_switch.rs and platform/vcpu_slot.rs. External interrupt
  readiness now rejects an already occupied VM-entry event slot, preventing
  overwrite of a pending event. Comments align handoff reservations with
  engine state ordering and remove the obsolete dom0-has-no-PID assumption.
  User accepted all three files; they are staged, cached diff whitespace
  check PASS. The larger hypercall/switch.rs diff is still to be walked
  separately. No commit created.
  Current walkthrough: arch/x86_64/vmcs/mod.rs. Child VMCS setup no longer
  accepts the unused APIC-access-page address; it passes zero to the shared
  controls helper and drops the diagnostic field. Child controls already
  disable xAPIC-access virtualization; this does not remove VAPIC or PID.
  User accepted after clarification; file is staged, cached diff whitespace
  check PASS. Related arch_state and boot changes are not yet
  accepted; review those separately.
  Current walkthrough: arch/x86_64/boot/{domain,vmcs,launch}.rs. Allocates a
  private META PID page for each dom0 VP and wires its address into both AP
  and BSP Vcpu construction instead of zero. These descriptors serve as
  software pending-interrupt queues; this does not enable hardware posted
  interrupts. User approved all three files; they are staged.
  Cached diff whitespace check PASS; no commit created.
  User agreed to retain software interrupt delivery for this commit and
  defer hardware posting to a separate evaluation. Removing WSL does not
  remove nesting when Themis still runs under QEMU/KVM; hardware posting
  would need migration, stopped-VP, revocation and queue-consumer validation.
  Current walkthrough: arch/x86_64/{arch_state,apic}.rs. Stores MSR/I/O
  bitmap addresses per VP, removes the APIC-address mapping exception so
  engine-approved mappings use the normal path, and centralizes monitor
  wakeups in send_monitor_ipi. Existing engine cross-core wake stays INIT;
  the old fixed-vector notification helper becomes INIT-based too, matching
  software PID delivery. User accepted after clarifying that [u64; 3] stores
  three bitmap addresses per VP, not three VPs. Both files are staged;
  cached diff whitespace check PASS. No commit created.
  Current walkthrough: arch/x86_64/pid.rs. NDST destination-core accesses
  become atomic release/acquire; remote injection uses the shared INIT
  wakeup and does not suppress it based on ON, avoiding a missed wake when
  software drain snapshots PIR then clears ON. Local destination skips the
  IPI. Documentation now describes software queueing, including dom0 PIDs.
  User accepted; file is staged. Cached diff whitespace check PASS.
  The remaining capavisor files are not yet jointly reviewed.
  User accepted hypercall/doorbell.rs and requested adding it to the commit;
  that file is staged. Review prompted the attestation production fix above;
  its new changes are now staged with user approval. No commit created.

- [x] **Joint capability-engine test review (2026-11-26, DONE):**
  User accepted the test review as complete after the mediated-API audit
  below. No further test walkthrough is pending. This does not clear the
  remaining source reviews or eleven open findings. Only todo.md changed
  for this acceptance note; no staging or commit.

- [x] **Mediated test audit (2026-11-26, DONE):**
  Reviewed changed engine tests and their fixtures against the domain_api
  rule. Replaced forged receiver handles with CREATE or transferred channels,
  direct VP insertion with CARVE + ADD_VP, post-seal policy writes with
  CREATE policies or pre-seal SET, and direct attestation builders with
  mediated ATTEST. Pending-transfer tests now use actual SEND freezes and
  REVOKE operations. Real sender revocation cancels the offer, so a later
  ACCEPT returns NotFound; the concurrent test also covers ACCEPT winning
  first, in which case the already-transferred memory survives sender revoke.
  Common bootstrap grants memory only to the initial root and retains the
  backing tree. Descendants receive memory through SEND. Ordinary test
  operations do not mutate capability trees; read-only assertions remain.
  Two new corruption-based negative handoff cases were replaced with
  reachable wrong-core and mismatched platform-binding cases, not equivalent
  coverage of manually corrupted ancestry.

  Scope: changed feature tests and supporting fixtures, not a rewrite of
  every historical internal test. Older raw primitive/tree tests remain,
  including legacy cases in unit/{channel,switch}.rs and
  concurrency/{loom_concurrency,loom_vp_switch}.rs. Do not claim the entire
  historical suite follows the mediated-API rule.

  Validation PASS: cargo test, cargo test --features address_translation,
  all five cargo loom suites, no_std address-translation check and CLI
  release build (two existing dead-code warnings). git diff --check PASS.
  cargo fmt --check is not clean across the existing stack (starts in
  src/attest.rs); no unrelated formatting sweep was made. Formatted the
  rewritten send_pending tests.
  Logs: /tmp/themis-api-test-audit-{default,translation,loom,nostd,cli,fmt}.log.
  No production changes for this audit, staging or commit. User index
  preserved. No VM, mount or background process left running.
  Joint test review accepted as complete by the user; the rest of the stack
  and eleven open review findings are not cleared.

  Files modified:
  - capa-engine/tests/common/mod.rs — root boot grant and mediated memory/VP helpers.
  - capa-engine/tests/unit/set_get.rs — mediated VP fixtures and nested memory delegation.
  - capa-engine/tests/unit/switch.rs — pre-seal policies, real child chains,
    mediated attestation and reachable handoff failure setups.
  - capa-engine/tests/concurrency/loom_vp_switch.rs — mediated VP provisioning
    and real SWITCH setup for the return/claim race.
  - capa-engine/tests/concurrency/loom_concurrency.rs — real receiver authority
    and sender revocation in changed memory models; exclusive revoke guard.
  - capa-engine/tests/integration/send_pending.rs — real pending-transfer lifecycle fixtures.
  - capa-engine/tests/integration/revoke.rs — CREATE receiver children instead of forged handles.
  - todo.md — audit scope, validation and review handoff.

- **Historical review pause (2026-11-25, superseded by completion above):**
  User requested stopping here. Continue the joint capability-engine test
  review, not implementation or boot bring-up. Source walkthrough is done;
  transfer race tests were explained and accepted. Publication-test review
  exposed the invalid CLEAN marker and led to the attribute fix below.
  Next: briefly review the corrected `check_endpoint_publication` in
  `tests/concurrency/loom_concurrency.rs` and the new
  `endpoint_send_rejects_memory_attributes_without_mutation` in
  `tests/unit/channel.rs`, plus the small SEND validation guard.
  Then guide changed tests in `tests/concurrency/loom_vp_switch.rs`,
  `tests/unit/{set_get,switch}.rs`, `tests/integration/{revoke,send_pending}.rs`
  and `tests/common/mod.rs`. Do not describe the entire stack as reviewed.
  Staging is user-controlled: engine source files are staged, but
  `src/domain_api.rs` also has an unstaged attribute-validation change;
  test changes and this handoff remain unstaged. Do not overwrite the index.
  No commits, VMs, mounts or background checks were started/left running
  during this review segment. Latest validation and logs are below.
  Attribute-validation logs:
  `/tmp/themis-endpoint-attrs-{tests,loom}-1317f85d.log`.
  Independent reviews are complete, but eleven other findings remain open:
  stale policy lookup after revoke; wrapped RX-growth rollback; interrupt
  injection before pending register updates; Linux NMI panic; Linux AML
  write-width narrowing; CLI typed acceptance; and CHV seccomp, implicit PV
  resources, MSI-X widths, address reservation and vhost-user backing.
  These have not been fixed or cleared by the successful boot tests.

- [x] **Endpoint attribute validation (2026-11-25, DONE):**
  Joint test review identified that memory attributes have no endpoint
  semantics. Channel/doorbell SEND now rejects non-NONE attributes with
  InvalidValue before mutation. Removed CLEAN as a synthetic publication-test
  marker; publication tests check owner references and pending-receiver state.
  Added rejection tests for every memory flag and a combination, sealed and
  unsealed receivers, generic SEND and typed channel SEND; rejection leaves
  ownership, handles and pending state unchanged.
  Validation PASS: default and address-translation engine tests, all five
  loom suites, no_std address-translation check and CLI release build
  (two existing dead-code warnings). No commit. Files:
  `capa-engine/src/domain_api.rs`, `capa-engine/tests/unit/channel.rs`,
  `capa-engine/tests/concurrency/loom_concurrency.rs`, `todo.md`.

- **Joint source review (2026-11-25):** `capa-engine/src/` walkthrough
  completed with the user, including the endpoint transfer fixes below.
  This does not mark engine test changes or the remaining CLI, monitor,
  driver, CHV and Linux stack as jointly reviewed. No additional staging
  or commit was requested.

- [x] **Endpoint transfer race fixes (2026-11-25, DONE):**
  User-approved review fixes: SEND revalidates operand handle identities
  under ordered sender/receiver domain write locks before consuming or
  freezing the endpoint. SEND/ACCEPT/REJECT publish endpoint metadata and
  table changes under those same locks, with the endpoint lock taken last.
  NOTIFY snapshots immutable endpoint fields without retaining the endpoint
  read lock across domain-lock acquisition. Typed channel SEND also checks
  the endpoint type inside the transaction.
  Reproduced both bugs before fixing: two concurrent doorbell SENDs both
  succeeded, and a pending offer exposed stale attributes. Eight new loom
  regressions cover channel/doorbell double-SEND, mixed receivers, handle
  reuse and immediate/pending metadata publication with accept/reject.
  Validation PASS: `cargo test`, `cargo test --features address_translation`,
  all five `cargo loom` suites, final `loom_concurrency` (38 tests),
  `cargo check --no-default-features --features address_translation`,
  and `cd capa-cli && cargo build --release` (two existing dead-code warnings).
  Files: `capa-engine/src/domain_api.rs` (atomic transfer transactions),
  `capa-engine/src/doorbell.rs` (NOTIFY lock ordering),
  `capa-engine/tests/concurrency/loom_concurrency.rs` (race regressions),
  `todo.md` (handoff). Fixes remain unstaged for joint review; previously
  staged files are unchanged in the index. No commit.

- [x] **Confidential Linux shared-DMA boot VERIFIED:** kernel #16, matched
  monitor/driver/CHV and explicit 24 MiB IO policy pass two-CPU confidential
  Linux boot, authenticated SSH, disk write/sync/read/remove, zero-loss ping
  and clean shutdown. Guest confirms the fixed 24 MiB SWIOTLB pool.
  Production NONE masks remain unchanged; live CHV mappings retain private
  RAM/AP firmware as CARVE and only the declared IO/control/ACPI aliases.
  CHV virtio memory view excludes private/control/descriptor memory (unit
  tested for same-backing identity/lifetime, late publication and bounds).
  No SWIOTLB exhaustion in the successful confidential run.
  Non-confidential PV and explicit legacy each pass the same two-CPU,
  authenticated SSH, storage, zero-loss network and clean-shutdown checks.
  Final validation: ABI 18 tests + 2 doctests, 65 backend tests, real-bus
  regression, supported VMM check, arch/VMM Clippy --no-deps, Linux DMA patch
  checkpatch (0 errors/warnings), matched release build and all three live
  modes PASS. Existing baseline unnecessary-unsafe/build warning remains;
  whole-file guest PV checkpatch also reports three pre-existing barrier
  comment warnings, not errors.
  Owned dom0 has shut down cleanly; no QEMU or image mount remains.
  Existing nonfatal SVR MSR warning remains open. Next work is optional
  warning cleanup and remaining isolation/attestation/concurrency evidence,
  not confidential rootfs/SSH boot bring-up.
  Latest verified actual disk (supersedes ALL earlier backups below):
  `/tmp/themis-shared-dma-24m-verified-1317f85d.raw`, SHA256
  `196093187455c61aafe824f6b42d7be3ae5fb063b411690211137269a4bff5f9`.
  Packaged disk matches. Kernel #16 SHA256
  `97892a795a2817240430043f7b8365b332c984b765749363eb9cbc46440f6ff1`;
  packaged CHV SHA256
  `5cfe7dbf7e2eeeef6e1f3b12d77fe36596b1ac1e79aba3896f2e849cd2440a60`.
  Never mount/repack live images. build-bins overwrites dom1.raw from its
  stale source: back up the CURRENT actual disk before packaging, restore
  the newest verified disk afterward, and hash-check.
  Logs: `/tmp/themis-shared-dma-24m-{confidential,pv,legacy}-{live,check,stderr}-1317f85d.log`,
  package `/tmp/themis-shared-dma-24m-package-1317f85d.log`,
  kernel `/tmp/themis-shared-dma-24m-kernel-1317f85d.log`.
  Additional budget files: `themis/crates/themis-abi/src/pv.rs`,
  `themis/policies/dom1-{pv,confidential}.json` (explicit 24 MiB IO,
  32 MiB total validation cap); `docs/{chv-themis-config.md,
  architecture/inter-domain-notification.md}` (transport/DMA contract).

- **Shared DMA bring-up history (DONE; final results above):** kernel build #12 and matched
  private-mailbox package PASS. Two-CPU PV and explicit legacy each pass
  authenticated SSH, storage write/sync/read/remove, zero-loss ping and clean
  shutdown. PV retains x2APIC and uses the new shared IPI/deadline calls.
  Strict confidential Linux now retains x2APIC and brings both CPUs online
  with production NONE masks and private AP firmware (live mapping log shows
  `0xe8000..0xed000 CARVE`, no mirror). It then fails during ACPI initialization
  at high shared MMIO `0x20fffffee000` (clean address `0xfffffee000`).
  One-CPU comparison hits the same failure: this is an ACPI hotplug device
  field, not AP entry. Both PV/confidential log a nonfatal WRMSR `0x80f=0xff`
  warning while Linux temporarily disables the LAPIC; investigate the APICv
  software-enable restriction, do not mask it silently.
  Added targeted guest shared-MMIO hooks for ACPI device OperationRegions,
  ACPI register I/O, PCI ECAM, virtio config/notification/ISR and PCI MSI-X.
  No global readl interception. AML RAM, persistent memory, ACPI/NVS and
  legacy firmware ranges stay local; CHV rejects non-device transactions.
  Kernel #13 is live-tested: confidential Linux passes ACPI/PCI discovery
  and reaches virtio, which refuses devices without VIRTIO_F_ACCESS_PLATFORM.
  Rootfs mount therefore still FAILS; no confidential SSH success claimed.
  Two-CPU PV and legacy both pass authenticated SSH, storage, network and
  clean shutdown with the new MMIO hooks.
  Added strict shared-device MMIO methods in CHV
  `hypervisor/src/{vm.rs,themis/pv.rs}` and `vmm/src/vm.rs`: missing device
  bus ranges return errors, while legacy hole behavior remains unchanged.
  The real-bus regression, all 64 backend tests, arch/VMM Clippy --no-deps
  and matched release package pass. Strict package live tests also pass:
  PV completes two-CPU SSH/storage/network/clean shutdown; confidential
  reaches the same virtio ACCESS_PLATFORM rejection without MMIO errors.
  Current owned dom0 is cleanly stopped.
  Kernel #15 built, installed/hash-verified and LIVE-TESTED: confidential
  Linux detects virtio-blk, reads /dev/vda1 and mounts the ext4 rootfs.
  Boot then stalls on the declared 1 MiB SWIOTLB pool: 423/512 slots remain
  occupied, leaving too little room for a 262144-byte disk request.
  No private fallback occurred. No confidential SSH success claimed.
  Exact owned child VMM PID 1137 was terminated after preserving logs.
  Owned dom0 then shut down cleanly for repackaging.
  User approved a larger arena ("Do 24MiB no? or 12"); selected 24 MiB.
  PV/confidential JSON now explicitly requests 0x1800000 bytes.
  ABI and Linux bound each IO arena at 24 MiB and total backing at 32 MiB,
  including control pages; no automatic growth or private fallback.
  ABI host-target 18 tests + 2 doctests, 65 backend tests and arch/VMM
  Clippy --no-deps pass. Kernel/package builds running in
  `shared-dma-24m-{kernel,package}`.
  Next: restore current disk and final kernel, hash-check, then retry
  confidential SSH/storage/network and PV/legacy regressions.
  Shared DMA implementation IN PROGRESS (user approved): reuse fixed restricted SWIOTLB
  for both coherent and streaming DMA; register/reserve only the IO arena
  for page   metadata, keep an explicitly declared budget and no private fallback.
  Give CHV virtio devices a shared-IO-only memory view using the exact same
  owned backing as the capability alias (not private/control/descriptor
  memory). This avoids the existing AccessPlatform translation helpers'
  unwrap-on-error path. CHV now owns Arc-backed shared mappings and exposes
  only declared IO ranges to virtio; selected PV advertises ACCESS_PLATFORM.
  All 65 backend tests and supported VMM check pass, including same-backing
  identity/lifetime and private/control/descriptor/bounds rejection.
  Guest changes reserve/register descriptor-discovered IO as E820 RAM,
  initialize fixed SWIOTLB for coherent and streaming DMA, keep freed DMA
  pages shared, and skip unused private atomic pools. Kernel build running
  in `shared-dma-kernel`, `/tmp/themis-shared-dma-kernel-1317f85d.log`.
  Matched DMA binary package passed; CHV is installed/hash-verified
  (`b5b4f96f98f37d0487c95cd9166d4b3dd7aac522d2f171ed3a1682001383c73b`).
  Kernel #15 is now installed and live-proven through confidential rootfs
  mount; the 1 MiB pool exhaustion above blocks further boot progress.
  Package log `/tmp/themis-shared-dma-package-1317f85d.log`.
  Kernel final build `/tmp/themis-shared-dma-kernel-final-1317f85d.log`;
  live logs `/tmp/themis-shared-dma-confidential-{live,check,stderr}-1317f85d.log`.
  Additional files: CHV `hypervisor/src/{vm.rs,themis/{pv,vm_state,
  hypervisor_impl,vm_impl}.rs}`, `vmm/src/{vm,device_manager}.rs`
  (shared-only owned virtio backing and feature selection);
  sibling Linux `arch/x86/{Kconfig,include/asm/themis_platform.h,
  kernel/{cpu/themis_pv.c,setup.c,pci-dma.c}}`,
  `include/linux/swiotlb.h`, `kernel/dma/{swiotlb,direct,pool}.c`
  (early arena reservation, fixed allocator and coherent lifetime).
  Files: sibling Linux `include/linux/{themis_io,virtio_pci_modern}.h`,
  `arch/x86/{kernel/cpu/themis_pv.c,pci/mmconfig_64.c}`,
  `drivers/{acpi/{osl.c,acpica/exregion.c},pci/msi/{msi.c,msi.h},
  virtio/{virtio_pci_common.c,virtio_pci_modern.c}}`
  (targeted shared-MMIO client and selected-PV adapters).
  Latest clean actual disk backup:
  Last clean-shutdown backup:
  `/tmp/themis-strict-mmio-verified-1317f85d.raw`, SHA256
  `0edbef9651acbf12708e2a189fc356ac37729496da0a1f997b903c99df9a5e71`.
  Newer CURRENT disk preserved after the 1 MiB attempt:
  `/tmp/themis-shared-dma-1m-attempt-1317f85d.raw` (requires possible journal
  recovery; restore this latest disk after the 24 MiB package).
  This supersedes older backups; preserve current disk before any future
  package and restore the newest verified copy afterward.
  Logs: `/tmp/themis-pv-cpu-private-{boot,linux-live,linux-check,legacy-live,
  legacy-check,confidential-live,confidential-check,confidential-one-live,
  confidential-one-check,package}-1317f85d.log`;
  kernel log `/tmp/themis-pv-device-mmio-kernel-1317f85d.log`;
  kernel #13 live results `/tmp/themis-pv-device-mmio-{confidential,pv,legacy}-{live,check}-1317f85d.log`;
  strict package `/tmp/themis-mmio-strict-package-1317f85d.log`;
  strict live `/tmp/themis-mmio-strict-{pv,confidential}-{live,check}-1317f85d.log`.
  The latest clean PV disk was backed up before the DMA package and
  restored afterward with matching hash. Preserve its CURRENT contents
  before another package. The latest confidential attempt mounted it RW
  before stalling; its forced VMM termination means journal recovery may
  be needed. Preserve that CURRENT disk rather than overwriting it.

- **Shared CPU requests and confidential x2APIC (IN PROGRESS):**
  Strict confidential runs with/without decompressor earlyprintk both stop at
  LAPIC GPA `0xfee000f0`. Without earlyprintk, native early UART exits disappear.
  Linux initially enables x2APIC but disables it because Themis never supplied
  `x86_init.hyper.x2apic_available`. Added that existing callback, gated on
  selected PV mode and advertised hardware x2APIC virtualization.
  Selected-PV fixed IPI and TSC-deadline writes now publish explicit shared
  operands (Platform opcodes 8/9); CHV binds requests to the caller VP and
  reuses interrupt injection/timerfd. No confidential register masks changed.
  IPI targets resolve configured APIC IDs, logical clusters and shorthands.
  Also corrected the old EBDA sharing window: AP firmware/mailbox/tables
  at `0xe8000..0xed000` must be CARVE, with no parent alias or vTOM mirror.
  The new regression checks these mappings and neighboring shared ACPI pages.
  New backend validation/routing/privacy regressions pass: 64 Themis tests, supported
  VMM check, arch/VMM Clippy `--no-deps`, ABI 18 tests + 2 doctests.
  Kernel #12 and #13 builds completed; these CPU changes are packaged and
  live-tested. Both confidential CPUs come online, and PV/legacy full Linux
  regressions pass. Owned dom0 has shut down cleanly.
  Next: continue virtio shared DMA after the strict MMIO live check above;
  do not mistake backend support for shared DMA completion.
  Files: ABI `themis/crates/themis-abi/src/pv.rs` (CPU opcodes);
  CHV `hypervisor/src/themis/{pv,vcpu,vm_state}.rs` (validated caller-bound
  dispatch, topology-aware fixed IPIs, reusable fallible timer/injection,
  private AP firmware exclusion and regression);
  sibling Linux `arch/x86/include/asm/{apic,themis_platform}.h`,
  `arch/x86/kernel/cpu/{themis_platform,themis_pv}.c`,
  `arch/x86/kernel/apic/apic.c` (availability hook and selected-PV CPU calls).
  Hardware without x2APIC virtualization still needs a LAPIC MMIO fallback.
  Current clean disk backed up before packaging:
  `/tmp/themis-mailbox-pv-legacy-verified-1317f85d.raw`, SHA256
  `6264d1e08c577fccd6c68be38c904458b03ea7929a6cb572da29e0117fd38f59`.
  This supersedes older disk backups; restore this one after packaging.

- [x] **Guest-owned AP entry implementation DONE:** user selected the
  existing Linux TDX-style ACPI MADT mailbox instead of a new capavisor
  startup operation. CHV now provides a small guest waiting stub, a private
  mailbox and private identity page tables in existing reserved EBDA memory
  (`0xe8000..0xecfff`) before sealing. PV secondary VPs have a pre-seal
  64-bit entry context; Linux's existing `acpi_wakeup_cpu` publishes each
  APIC ID and trampoline address. CHV only schedules the VPs; no post-seal
  register permissions or engine interfaces changed. Legacy SIPI unchanged.
  Version-0 MADT wakeup disables CPU offlining, matching the Linux contract.
  ACPI table placement checks for overlap with the reserved firmware area.
  Unit identity-map/mailbox/boundary test, all 61 CHV tests, supported
  `themis,kvm,ivshmem` VMM check and matched full package pass.
  Clippy with `--no-deps` passes for the changed arch/VMM crates. Including
  dependency linting is blocked by 47 existing backend lint errors.
  First live two-CPU PV run selected `acpi_wakeup_cpu` and entered Linux's
  AP trampoline, then triple-faulted immediately after its CR3 load at
  `0x9a14e`. Firmware context omitted EFER.NXE while Linux page tables use
  NX bits. Corrected pre-seal EFER to LME|LMA|NXE; rebuilt/repackaged,
  restored the verified disk (`af656459...a802`). Corrected live two-CPU PV
  Linux now PASSES: MADT selects `acpi_wakeup_cpu`, both CPUs come online,
  authenticated SSH, disk write/sync/read/remove, ping (zero loss) and clean
  shutdown. CHV log has no legacy SIPI handler or wait-for-SIPI messages.
  Explicit legacy two-CPU Linux also passes SSH, disk write/sync/read/remove,
  zero-loss ping and clean shutdown. Strict confidential comparisons and
  the current next steps are recorded above.
  Files: CHV `arch/src/{lib.rs,x86_64/{layout.rs,mod.rs,mp_wakeup.rs}}`
  (private firmware, identity mapping, initial context and focused test);
  `hypervisor/src/{vm.rs,themis/vm_impl.rs}` (PV mailbox-mode selection,
  no legacy wait-for-SIPI for PV); `vmm/src/{acpi,cpu,vm}.rs` (MADT
  advertisement, placement bound, pre-seal firmware/AP setup);
  `docs/chv-themis-config.md` (mailbox boot contract); `todo.md`.
  Logs: `/tmp/themis-guest-ap-mailbox-{package,nxe-package,boot,linux-live,
  clippy,clippy-nodeps}-1317f85d.log`, corrected live log
  `/tmp/themis-guest-ap-mailbox-nxe-linux-live-1317f85d.log`.
  First owned QEMU exited; corrected owned dom0 shut down cleanly after
  the regressions and confidential comparisons.

- **Confidential dom1 device work RESUMED (IN PROGRESS):** user confirmed
  standard dom1 boots and explicitly requested continuing the original
  confidential goal. Latest process check finds no QEMU or child VMM;
  recheck before any disk operation. Do not manage user-owned VMs.
  Implement the approved early shared-request PIO bootstrap first, then
  LAPIC and virtio/shared DMA. Confidential device operations must use
  shared requests and capability doorbells, never private register decoding.
  thhv already routes recipient ports to eventfds; CHV dispatches service
  IDs and reuses device backends/event matching. No device callbacks belong
  in thhv. Linux forces SWIOTLB for confidential guests, but allocating DMA
  rings, coherent memory and bounce buffers from declared shared backing
  is still missing; forcing SWIOTLB alone is not sufficient.
  Next: validate caller-bound IPI/deadline shared requests, then virtio
  and shared DMA. Retain NONE register masks. Confidential-safe secondary
  VP entry now uses the guest-owned mailbox described above; legacy CHV
  SIPI handling remains only for the legacy transport.
  VPs already exist before sealing; CHV still schedules them with SWITCH.
  The issue is their entry state, not creating or scheduling VPs. Do not
  assume a new engine operation is necessary or bypass the masks.

  [x] Linux CoCo secondary-entry investigation DONE. The local Linux TDX
  path already uses the user-proposed firmware parking/mailbox pattern:
  `arch/x86/kernel/acpi/madt_wakeup.c:129-183` writes APIC ID and the 64-bit
  trampoline address, publishes a wake command and waits for acknowledgment
  from guest firmware. The callback is installed at line 246; Linux chooses
  `trampoline_start64` in `arch/x86/kernel/smpboot.c:1000-1006`.
  This mailbox is firmware/OS communication, not a device request to CHV.
  SNP instead constructs a protected VMSA containing CS/RIP and initial
  registers in `arch/x86/coco/sev/core.c:1029-1153`, then requests AP activation.
  SEV-ES hotplug also resumes guest-side code through an AP halt loop and
  `soft_restart_cpu` (`core.c:1400-1445`); this is not its initial boot path.
  The existing MADT mailbox and 64-bit trampoline are now reused with a
  pre-seal guest-owned waiting stub, private mailbox/backing and valid
  initial page tables; implementation and live results are recorded above.

  Implemented and validated: Platform PIO 4/5 and MMIO 6/7 use
  bounded explicit operands and device backends, with shared writes reusing
  CHV ioeventfd matching. Linux early bootstrap no longer allocates through
  memblock; scalar/string/delay PIO and IOAPIC use the selected transport.
  User requested JSON-selectable legacy/PV for non-confidential dom1:
  `general.device_transport = "legacy" | "pv"` now binds descriptor header
  flag 1. Standard defaults legacy; confidential defaults PV and rejects
  explicit legacy. PV needs declared Control+Platform backing. Guest MMIO
  client hooks and shared DMA are NOT completed by the backend operations.
  Two-CPU non-confidential Linux passed authenticated SSH, disk
  write/sync/read/remove, ping and clean shutdown with both explicit legacy
  and PV policies. PV guest reports `shared PIO=1`; this is not yet a full
  PV MMIO/DMA boot. Strict confidential Linux initializes CoCo, the shared
  channel, early console and PV IOAPIC, then stops at LAPIC GPA
  `0xfee000f0`: legacy private-instruction emulation is correctly refused.
  CHV exit status 0 on this failure is NOT a successful guest boot.
  Some native UART exits still occur before the main-kernel PV bootstrap,
  probably in decompressor early serial code; identify/remove these rather
  than exposing private registers or trusting cached values.

  Validation: CHV 61 Themis tests pass (including runtime confidentiality
  overriding a legacy JSON selection before any partition ioctl); ABI
  18 tests + 2 doctests pass; guest kernel `6.19.14+` build #11 and the final
  matched `cargo build-bins` pass. The last added change is test-only.
  Latest verified disk backup:
  `/tmp/themis-device-transport-verified-1317f85d.raw`, SHA256
  `af656459623805d5615f5d6080692765c8d3055a7bc0f495bf4112b3fac6a802`.
  This supersedes the confidential-pio-user-disk backup and was restored
  into bins.img after packaging with matching hash. Owned dom0 PID 123497
  shut down cleanly; subsequent process check finds no QEMU/child VMM.
  Never mount/repack live images; build-bins still overwrites dom1.raw from
  the stale source image, so preserve/restore the newest disk afterward.
  Logs: `/tmp/themis-{confidential-pio,device-transport-final}-package-1317f85d.log`,
  `/tmp/themis-confidential-pio-{smoke,live}-1317f85d.log`,
  `/tmp/themis-nonconf-{pv,legacy}-linux-{live,check}-1317f85d.log`.
  Files: CHV `hypervisor/src/themis/{config,pv,vcpu,hypervisor_impl}.rs`
  (selection, validated dispatch, worker-event reuse, effective runtime
  confidentiality validation and its no-hardware regression);
  ABI `src/pv{,/descriptor}.rs`
  (opcodes, transport flag); Linux `arch/x86/{Kconfig,include/asm/{io,
  themis_platform}.h,kernel/{setup,io_delay,cpu/themis_pv}.c}` (early client
  and selected I/O hooks); `themis/policies/dom1-{standard,pv,confidential}.json`,
  `docs/chv-themis-config.md`, `todo.md` (explicit selection and status).

- [x] **Generic doorbell migration: reviewed, rebuilt and live VERIFIED.**
  This milestone is for the generic primitive and **standard/non-confidential**
  Linux integration, not confidential-device completion.
  Final reviewed stack passes all four-CPU IRQ probes, public Async/eventfd
  subscription/revoke, generic ownership/reclaim, real child Sync
  discovery/accept/notify/resume, corrected interruptible HLT regression,
  signed/unsigned attestation and ten close/unload/reload cycles (640 posts).
  Signed verification also passes with a live doorbell present (tree and held
  inventory), not just an empty doorbell array. PV one-VP, two-created-VP/
  BSP-only and relaunch runs each complete eight requests.
  Standard Linux `6.19.14+` passes authenticated SSH, two online CPUs,
  disk write/sync/read/remove, three pings with zero loss and clean shutdown.
  Reviewed standard-mode CoCo simulation passes five tests; host eventfd
  counts total five ivshmem notifications (coalescing is valid).
  Both review findings are fixed: one effective interrupt resolver keeps
  injection authority at domain scope despite VP snapshots; frozen transfer
  handles are excluded from held-doorbell attestation. Two new regressions
  pass in both plain and translated suites (826 test executions total).
  All five Loom suites pass (52 tests), CLI 16 tutorials/release pass,
  ABI 17 tests + 2 doctests and CHV 54 tests pass. Full reviewed package build
  passed; no source changes after that except documentation.

  **Still open:** confidential Linux scalar/string port I/O bootstrap,
  confidential LAPIC/virtio/shared-DMA services, actual concurrent guest-VP
  requests and Lean-model parity. Default confidential CoCo fails before
  guest tests at private-memory emulation (`invalid guest memory range:
  Bounds`); do not mistake standard-mode CoCo simulation for isolation proof.
  No production register masks or private-memory protections were weakened.
  The original HLT stall was a stale test expectation, not a notification
  regression; driver parks HLT by design and the corrected test verifies it.

  Latest clean tested Linux disk backup:
  `/tmp/themis-doorbell-reviewed-latest-1317f85d.raw` (3758096384 bytes),
  SHA256 `f78a107af5aab6128ac8188f48d40a4fad7de967b027806d98b29353820b6a77`.
  This supersedes `/tmp/themis-doorbell-latest-1317f85d.raw`.
  Dom0 and all session child VMMs are now cleanly stopped; no temporary
  bins mount or owned test TAP remains. Latest monitor/driver/VMM/kernel/
  workloads are packaged and ready for the next `cd themis && cargo themis`.
  `bins.img` already contains the tested updated disk; future build-bins
  overwrites it from stale `themis/guest/dom1.raw`, so restore this newest
  backup after packaging and verify its hash. Never mount/repack live disks.
  Logs: `/tmp/themis-doorbell-reviewed-{package,boot,live,held-attest,
  coco-live,coco-stderr}-1317f85d.log`,
  `/tmp/themis-doorbell-final-linux-{live,check}-1317f85d.log`,
  `/tmp/themis-doorbell-review-fixes-{engine,loom}-1317f85d.log`.
  Session helpers in `files/final-linux-regression.py` and
  `files/attest-held-doorbell.c` document the exact last integration checks.
  Modified file inventory/reasons are recorded in the migration entries below;
  final review-fix files: `capa-engine/src/{domain,domain_api,doorbell,attest}.rs`,
  `tests/unit/switch.rs`; `thhv/test/test_child_hlt.c` (real HLT contract).
  Next: resume the existing confidential-PIO task using only explicitly
  shared request buffers and the new capability doorbells; do not restore
  address-matched monitor notifications or expose private registers/memory.

- **Final doorbell ABI live regression (IN PROGRESS)**:
  Update: both independent-review fixes pass plain/translated engine,
  all five Loom suites, and CLI 16 tutorials/release. Standard-mode CoCo
  workload passes all five tests; CHV records all five ordinary ivshmem MMIO
  notifications. Confidential mode is still blocked before the guest tests.
  Logs: `/tmp/themis-doorbell-standard-coco-{live,guest}-1317f85d.log`,
  `/tmp/themis-doorbell-review-fixes-{engine,loom}-1317f85d.log`.
  Dom0 stopped cleanly; reviewed package rebuild is running.

  Review found two bugs, now fixed with regression tests: doorbell checks
  now share the effective interrupt resolver (VP visibility, domain injection
  authority), and frozen transfer handles are omitted from held-doorbell
  attestation. Plain/translated engine tests and CLI 16 tutorials/release pass;
  final Loom rerun is running. Files: `capa-engine/src/{domain,domain_api,
  doorbell,attest}.rs`, `tests/unit/switch.rs`.
  The HLT stall was a stale test: thhv deliberately parks HLT rather than
  returning it to userspace. `thhv/test/test_child_hlt.c` now interrupts the
  wait with SIGALRM and checks the actual COMM HLT record; live PASS.
  Linux final ABI reached a two-CPU login prompt. Two test-harness issues
  prevented completing SSH: nonblocking-terminal diagnostic printing
  (fixed by stderr file), then TCP-open preceding a real SSH banner (probe
  now checks the banner). No Linux/device policy weakened.
  Default confidential CoCo workload exits before guest tests with
  `invalid guest memory range: Bounds`, consistent with the known confidential
  emulation blocker; it does not validate ivshmem. Separate standard-mode
  ivshmem regression is running. Next: package the review fixes together,
  reboot, rerun live regressions and complete Linux SSH/storage/network/shutdown.

  Rebuilt four-CPU dom0 is responsive. All 16 targeted IRQ probes pass;
  public Async/eventfd subscription/revoke and generic ownership/reclaim
  pass on all CPUs. Real child ENUMERATE/ACCEPT/Sync NOTIFY/resume passes.
  Final-format unsigned and signed reports pass, including Ed25519
  verification (flags 5, header count at 36, envelope after all arrays).
  Ten immediate-owner-close/unload/reload cycles pass (640 posted events).
  PV one-created-VP, two-created-VP/BSP-only and relaunch runs each pass
  all eight requests with attested doorbell discovery.
  Separate old `test_child_hlt` stalled in RUN_VP while dom0 stayed
  responsive; its exact owned PID was terminated. Independent reviewer
  is checking whether its setup is stale; do not report this test as passed.
  Final two-CPU Linux SSH/disk/network/shutdown check is running.
  Logs: `/tmp/themis-doorbell-final-{boot,driver-live,attest-unload,pv-live,
  linux-live,linux-check}-1317f85d.log`.
  Live dom0 shell: `doorbell-final-boot`; never mount its disks while running.

- **Linux/device migration VERIFIED; final combined rebuild IN PROGRESS**:
  Update: full matched `cargo build-bins` passed after removing the remaining
  old synthetic exit, global vector setter and unused address-table constants.
  CLI 16 tutorials/release, engine plain/translated/all five Loom suites,
  shared ABI 17 tests + 2 doctests and CHV 54 tests pass. CPUID bit 1 is
  reserved (retired interface); new bit 3 advertises capability doorbells.
  Latest disk restored into bins and SHA256 verified. New four-CPU stack
  is booting for final live regression. Independent review is running.
  Additional files: capavisor `platform/domain.rs`,
  `arch/x86_64/{hypercall/switch,vmexit/cpuid}.rs`; shared ABI `src/pv.rs`;
  CHV `hypervisor/src/themis/policy_walker.rs` (retired exit/feature cleanup);
  `CONTEXT.md`, `docs/{domain-comm,capability-engine/semantics,
  architecture/{attestation,inter-domain-notification,confidential-vm,
  mshv-themis,interrupt-virtualization}}.md`, `thhv/README.md`,
  `skills/debugging-dom-boot.md` (current ABI/semantics, historical labels).

  Two-CPU standard Linux booted with the migrated PV client and ordinary
  MMIO/PIO event matching in CHV, not the capability engine. Authenticated SSH,
  disk write/sync/read/remove, ping and clean shutdown passed. PV initialization
  now follows `memblock_set_current_limit`, fixing the early allocation panic.
  CHV's 54 Themis tests pass, including three event-matching regressions.
  Removed the old engine notification module, monitor matching handlers,
  driver IOEVENTFD implementation and obsolete tests. Attestation now has
  `nr_doorbells` at header offset 36, flag 4 and 40-byte doorbell entries directly
  after PA maps; no transitional trailing count. Monitor, driver/userspace tests,
  Linux kernel and CHV build against this final format. CLI validation exposed
  one leftover display loop over the removed inventory; removed, revalidation
  pending. Engine translated tests pass; Loom is still running.
  **Running dom0 still uses the previous transitional ABI**: rebuild/reboot
  monitor, driver and guests together, never deploy only one new consumer.
  No child VMM is intentionally running. Latest clean disk backup:
  `/tmp/themis-doorbell-latest-1317f85d.raw`, SHA256
  `61a4a3d452e3b674ff76a4f9894e2922dede2bff2f3a379699f6fdcbca81072b`.
  Next: finish obsolete-code/docs cleanup, pass remaining checks, stop dom0,
  package (restore this backup after build-bins), boot and repeat live checks.
  Concurrent guest-VP requests, strict confidential I/O/device services and
  Lean-model parity remain unverified/unimplemented.
  Files: Linux sibling `arch/x86/{include/asm/themis_hcall.h,kernel/cpu/themis_pv.c,
  kernel/setup.c}`, `drivers/virtio/virtio_pci_{common.h,modern.c}` (client/native
  virtio); CHV `hypervisor/src/themis/{ioevent,vm_impl,vm_state,vcpu,emulator,
  hypervisor_impl,mod,abi,consts}.rs` (userspace event matching);
  `capa-engine/src/{lib,domain,platform,attest}.rs`, deleted `notification.rs`,
  tests `common/mod.rs`, `unit/switch.rs`, `concurrency/loom_vp_switch.rs`
  (remove bindings/final serialization); `capa-cli/src/rust_backend.rs`
  (remove old display); `themis/crates/{themis-abi/src/{domcomm,lib}.rs,
  libthemis/src/lib.rs}`, capavisor `hypercall/{mod,doorbell}.rs`,
  `arch/x86_64/hypercall/{mod,doorbell}.rs`, `platform/mod.rs`
  (final ABI/remove handlers); `thhv/{Kbuild,inc/thhv.h}`,
  `src/{thhv_rx,thhv_domcomm,thhv_part,thhv_vp,thhv_hvcall}.c`,
  `src/thhv_internal.h`, deleted `src/thhv_ioeventfd.c`,
  `test/{test_attestation,test_child_hlt}.c` (RX/removal/readers);
  `eunomia/src/ivshmem.rs` (ordinary MMIO notification); `todo.md`.
  Logs: `/tmp/themis-doorbell-native-linux-{live,check}-1317f85d.log`,
  `/tmp/themis-doorbell-{chv,linux,cli,loom}-final-*1317f85d.log`.

- **Capability-based PV round trip VERIFIED; remaining migration IN PROGRESS**:
  CHV creates one Sync endpoint for each configured shared-memory request queue,
  subscribes its eventfd and transfers the invocation capability to the child.
  Descriptor ABI 2 carries recipient/port identity (request protocol stays at 1).
  Eunomia resolves that identity to its own handle through self-attestation,
  rather than guessing handles or ringing a fake GPA. Driver RUN_VP now drains
  RX and returns EAGAIN to userspace after interrupt unwind, so CHV can service
  the request before resuming the child; the monitor's unwind is unchanged.
  Live Sync discovery/accept/notify/resume passes. Standard PV launches with
  one and two created VPs and a subsequent relaunch each complete all eight
  requests with one passing guest test and no failures. The two-VP workload
  still runs requests only on the BSP; this is not concurrent guest coverage.
  Shared ABI tests (17 plus 2 doctests), all 51 Themis VMM tests, guest and
  CHV release builds and driver build passed before these live runs.
  Files: `themis/crates/themis-abi/src/{domcomm,pv/descriptor}.rs`
  (checked attestation lookup and descriptor authority), `eunomia/workloads/pv/src/main.rs`
  (discovery/notify), CHV `hypervisor/src/themis/{abi,pv,config/pv,vm_state}.rs`
  (endpoint provisioning and descriptor publication), `thhv/inc/thhv.h`
  (recipient output), `thhv/src/{thhv_doorbell,thhv_vp}.c` (identity/return boundary),
  `thhv/test/test_doorbell_sync.c` (EAGAIN-aware regression), `todo.md`.
  Linux sibling `arch/x86/{include/asm/themis_hcall.h,kernel/cpu/themis_pv.c}`
  is being migrated to ABI 2/attested handles, with correct SWITCH opcode and
  no notify-failure/yield fallback; kernel build is running.
  Logs: `/tmp/themis-doorbell-pv-{live,repeat}-1317f85d.log`,
  `/tmp/themis-doorbell-linux-build-1317f85d.log`.
  Next: validate Linux client and strict PV policy; move ordinary device
  matching to CHV, retire the old engine/monitor mechanism, finish attestation
  consumers/model parity and package/regress. Strict confidential Linux port
  I/O remains a separate unsolved blocker. Current dom0 is responsive with
  copied latest driver/CHV/guest; do not repack/mount its live disks.

- [x] **Retired scheduling-feature cleanup: DONE.** Removed stale multi-core
  boot requirements and commands from `skills/running-inside-dom0.md` and
  `themis/README.md`. Removed the retired implementation recipe from
  `docs/architecture/interrupt-virtualization.md`, corrected the old cleanup
  inventory and marked old findings below as historical/removed. No code,
  Cargo feature or script gate remains for the retired scheduler; normal
  `cargo themis` boots the current four-CPU stack. Archived notes retain
  history, not active instructions. Files: the four documentation/skill
  files above and `todo.md`. Validation: repository reference search and
  inspection of the current capavisor feature list.

- **Driver eventfd/ownership integration VERIFIED; PV migration pending**:
  All five Loom suites passed after the generic ownership changes, including
  notify/revoke concurrency. The receive path now has public device ioctls
  for creating driver-vector endpoints, subscribing an eventfd, notifying and
  generic revocation; partition SEND_CAP uses the shared SEND VMCALL.
  Endpoint lifetime belongs to the creating device fd, not the subscription.
  RX and synchronous reply handling dispatch event type 8 by recipient port.
  Unload forces monitor entry on every online CPU in process context before
  releasing IRQs, after endpoint-owner fds have closed/revoked authority.
  Revoke failure is logged and pins the module instead of freeing a live
  vector. Public-API tests pass on all four CPUs: notification/eventfd delivery,
  subscription detach/reattach, attestation interleaving, stale-handle and
  invalid Sync rejection, generic child transfer and recipient-side reclaim.
  Ten unload/reload cycles after 640 notifications and immediate owner close
  passed. The rebuilt monitor also passes the 16 all-CPU IRQ probes.
  `test_doorbell_sync` passes live: a protected-mode child discovers a pending
  offer via ENUMERATE, ACCEPTs it, NOTIFYs its blocked parent, resumes after
  the successful VMCALL, and exits to the parent; exactly one eventfd signal.
  Separate SEND_CHAN/ACCEPT_CHAN/REVOKE_DOMAIN monitor opcodes/handlers were
  retired; typed C/Rust compatibility wrappers use shared SEND/ACCEPT/REVOKE.
  Guest SEND now supplies the no-GPA-hint sentinel explicitly.
  CHV now validates/emits `policies.api.allow`, including CREATE_DOORBELL and
  NOTIFY, immediately before seal; unknown names fail. All 51 Themis VMM
  tests, shared ABI tests, guest-wrapper check and VMM release build pass.
  Full monitor/driver/workload package rebuild passed before the Sync test
  was added; that test was compiled separately with -Wall -Wextra -Werror.
  CHV's latest binary and the Sync test still need final packaging.
  The current VM uses the rebuilt monitor and packaged driver; bins.img's
  dom1 disk was restored from the verified backup after packaging.
  Files: `thhv/src/thhv_doorbell.c` (endpoint/subscription lifetime and dispatch),
  `src/{thhv_main,thhv_part,thhv_domcomm,thhv_ioeventfd,thhv_doorbell_irq}.c`,
  `src/thhv_internal.h`, `inc/thhv.h`, `Kbuild` (public ABI, RX and cleanup);
  `thhv/test/test_doorbell_eventfd.c` (public API regression),
  `thhv/test/test_doorbell_sync.c` (real child Sync/resume regression);
  `themis/{capavisor/src/hypercall/{mod,capa}.rs,crates/themis-abi/src/lib.rs,
  crates/libthemis/src/lib.rs}`, `eunomia/workloads/hypercall/src/main.rs`
  (shared ownership ABI); CHV `hypervisor/src/themis/{policy_walker,vm_state}.rs`
  and `docs/chv-themis-config.md` (actual API permission application); `todo.md`.
  Logs: `/tmp/themis-doorbell-eventfd-1317f85d.log`,
  `/tmp/themis-doorbell-{chv-tests,chv-build,public-boot}-1317f85d.log`.
  Next: migrate PV/VMM consumers and ordinary device matching, remove the old
  monitor matching path, finalize attestation/other consumers, then package
  and rerun standard dom1. Do not mount/repack disks while the current VM runs.

- **Driver-only common-vector delivery VERIFIED on stock dom0**:
  No dom0 kernel modification is needed for the tested receive path.
  thhv uses an IRQ domain layered on the exported x86 vector domain,
  allocates normal CPU-pinned IRQs until a common vector is held on all
  online CPUs, and releases unused allocations. No private vector table,
  IDT writes or hidden symbol lookup. Its software-injection IRQ chip does
  not EOI a nonexistent physical LAPIC ISR entry. Deferred work drains RX.
  CPU hotplug is disabled while these fixed registrations are held and
  re-enabled on driver cleanup.
  Live stock Ubuntu `6.8.0-136-generic`: vector 38 registered on all four
  CPUs; four Async notify/revoke rounds per CPU all pass (16 probes).
  `/proc/interrupts` independently shows four deliveries on each target CPU.
  Source CPUs may migrate; targeted remote delivery uses the INIT/PIR path.
  Full capavisor/thhv package build passed with CONFIG_THHV_TEST; latest
  dom1 disk restored and SHA256 verified after packaging.
  Translated engine tests, all 16 CLI tutorials and CLI release build pass.
  All five Loom suites passed. The session VM is currently running for further
  integration; do not mount/repack its bins or guest disks while it runs.
  Logs: `/tmp/themis-doorbell-{build,boot,live-irq,driver}-1317f85d.log`.
  Next: finish capability ownership ABI consolidation and eventfd/PV/VMM
  migration, then exercise Sync and value/subscription/revoke behavior live.
  New/modified files this increment: `thhv/src/thhv_doorbell_irq.c`,
  `src/{thhv_main,thhv_hvcall,thhv_internal}.{c,h}`, `inc/thhv.h`, `Kbuild`
  (normal per-CPU allocation, deferred IRQ handling and monitor wrappers);
  `thhv/test/test_doorbell_irq.c` (real all-CPU notification probe);
  `todo.md` (verified result).

- **Doorbell implementation handoff (IN PROGRESS)**:
  Engine and CLI stages are implemented; monitor/driver/VMM migration and
  live validation are not complete. The user approved implementation.
  Older pause/review notes below are historical, not the current next step.
  Doorbells are immutable recipient-tree children, transferred like channels;
  reclaim destroys them. Sync selects the recipient in the live caller chain
  and shares interrupt unwind; Async stores its target VP. Both require
  Deliver and injectable. Ownership VMCALLs must be shared, with type dispatch
  inside the engine.

  Completed: shared handle allocation/ownership dispatch, doorbell lifecycle,
  policy/attestation inventory, prepared interrupt unwind and failure-atomic
  notification commit. CLI simulates queues/interrupts and has two passing
  executable examples. Plain and translated engine suites passed before
  the last focused additions; all 54 switch tests and all 16 CLI tutorials
  passed afterward. All five Loom suites passed, including notify/revoke.
  CLI release built before the final minor CLI edits; rerun at completion.

  Current hardware findings: initial-domain VPs have PID address zero;
  hardware posted interrupts are intentionally disabled. Existing remote
  `inject_via_pid` sends a fixed F2 IPI assuming hardware PI, whereas the
  existing cross-core monitor wake-up uses INIT and works independently of
  pin controls (`arch/x86_64/arch_state.rs::send_ipi`). INIT handling currently
  polls cross-core work but does not drain PIR. Reuse this wake-up and existing
  software drain rather than enabling hardware PI. Sync also needs to finish
  the source NOTIFY VMCALL before saving it in the shared interrupt handoff.
  Monitor integration has now started (details below); no live boots yet.
  Next: finish the interrupt-delivery plumbing, then migrate the shared ABI,
  driver/VMM/PV consumers and remove the superseded matching mechanism.

  Files changed for the engine/CLI stage:
  - `capa-engine/src/{doorbell,domain,domain_api,capability,platform,attest,lib}.rs`
    — endpoint object, common ownership, policy and shared interrupt transaction.
  - `capa-engine/tests/common/mod.rs`, `tests/unit/switch.rs`,
    `tests/concurrency/{loom_concurrency,loom_vp_switch}.rs`,
    `tests/integration/{revoke,send_pending}.rs` — semantic/race regressions
    and removal of manually colliding fixture handles.
  - `capa-cli/src/{backend,rust_backend,platform,parser,session,main,completer}.rs`,
    `src/commands/{mod,capability}.rs` — commands, replay and simulated delivery.
  - `capa-cli/examples/{doorbells,doorbell-lifecycle}.txt`,
    `tests/tutorial_tests.rs` — executable semantics examples.
  - `todo.md` — current progress and integration handoff.
  Attestation encoding is transitional while the old matching path remains;
  do not call the end-to-end migration complete.

- **Doorbell monitor/IRQ continuation (IN PROGRESS)**:
  Initial VPs now have software PID queues allocated from META. The shared
  INIT wake primitive replaces the remote fixed F2 IPI; NDST uses atomics.
  Every monitor entry refreshes NDST and drains PIR, preserving any already
  prepared VM-entry event. Monitor CREATE_DOORBELL/NOTIFY and a separate
  16-byte port/value DomainComm event are wired. Sync completes its source
  VMCALL before invoking the shared interrupt handoff; Async posts via PID.
  Queue and target backing are checked before publication.
  Engine pending-offer enumeration is type-independent (inclusive start ID;
  IDs include zero). Generic revoke accepts subhandle zero only for the old
  direct child-domain destruction semantics; held endpoints still require
  recipient-tree parent/subhandle revocation.
  Plain engine tests pass, including the new discovery/revoke regression;
  capavisor release `cargo check` passes. Full package rebuild, driver
  wrappers/ioctls, API consolidation/removal of old handlers, translated/
  Loom reruns and live verification remain pending. New monitor ABI numbers
  0x24/0x25 and event type 8 are not yet used by runtime consumers.

  Linux receive-path decision is NOT settled. Normal x86 IRQ allocation
  binds a vector on one CPU (`x86_vector_alloc_irqs` sets single-target;
  `chip_data_update` populates one CPU's vector table). Sync's fixed vector
  must work on whichever recipient VP resumes. User challenged the proposal
  to patch dom0: investigate registration entirely in thhv first.
  `request_percpu_irq` is exported but expects an already-backed per-CPU
  IRQ; it does not reserve/map the vector on all CPUs. Pinned Ubuntu
  6.8.0-136 exports x86_vector_domain/irqd_cfg, but not vector_irq,
  lock_vector_lock, alloc_intr_gate or x86_platform_ipi_callback.
  No dom0 kernel patch, per-VP-vector change or Sync restriction is approved.
  No Linux source changed. Next: resolve this specific driver-only vector
  registration question before choosing any new kernel integration.

  Additional files modified:
  - `capa-engine/src/domain_api.rs`, `tests/unit/switch.rs` — generic
    discovery and direct-domain revoke dispatch/regression.
  - `themis/capavisor/src/arch/x86_64/boot/{domain,vmcs,launch}.rs`,
    `platform/vcpu_slot.rs` — initial-VP software PID backing.
  - `themis/capavisor/src/arch/x86_64/{apic,arch_state,pid,x86_platform,vcpu_ext}.rs`
    — shared wake-up, concurrent destination reads and pending delivery.
  - `themis/capavisor/src/{platform/mod,hypercall/mod,hypercall/doorbell}.rs`,
    `arch/x86_64/hypercall/mod.rs` — validated queue/interrupt transaction,
    source completion and new monitor dispatch.
  - `themis/crates/themis-abi/src/{lib,domcomm}.rs` — new opcodes/event payload.

- [ ] **Generic doorbells (IMPLEMENTATION IN PROGRESS)**: User approved the
  reviewed plan and its corrections. Start with shared engine ownership
  operations and doorbells, then CLI examples before monitor integration.
  Existing separate memory/domain handle allocators permit collisions;
  shared operations require unambiguous allocation and engine-side lookup.
  Reuse interrupt-unwind preparation/commit for Sync transaction atomicity.
  Historical design discussion follows; approval supersedes its pause notes.
  User clarified that
  doorbells must be immutable channel-like children of the recipient's domain
  capability, transferable and reclaimable. No reconfiguration API. Both
  Sync and Async must notify a defined VP/vector, with effective Deliver
  policy; Sync additionally returns the donated CPU. User requested the full
  API/MonitorAPI design before implementation. User rejected further
  unsolicited features and complexity, not continued planning. The
  overextended draft was withdrawn and removed. User explicitly requested
  that detailed planning resume, covering APIs, objects and tree effects.
  Implementation remains paused for review. No proposed API names,
  permission bits or scheduling details are approved yet. Base the discussion
  strictly on the user's requirements and existing channel mechanisms:
  immutable doorbell, create for self/unsealed child, transfer, reclaim,
  destroy, notify ID/value, recipient interrupt VP/vector, Sync/Async,
  capability-tree placement, interrupt/MonitorAPI checks and attestation.
  Findings: CHV's `policies.api.allow` is parsed but not applied;
  monitor ENUMERATE is stubbed; initial-domain VP slots may lack PID backing;
  thhv has no actual notification IRQ receive path. Include these integration
  gaps, not just new type definitions. Abandoned partial engine/CLI rewrite
  was manually undone without touching prior uncommitted changes. Restored
  baseline engine compiles and all four notification tests pass with
  `cargo test --manifest-path capa-engine/Cargo.toml notification`.
  No new runtime implementation, disk packaging or live boot in this planning
  increment. Next: deliver the minimal channel-based API plan for user
  validation; no implementation until approval. The proposal uses the same
  recipient-tree/holder distinction and move/pending mechanics as channels,
  immutable vector and kind (`Sync` or `Async { vp_id }`), revocation and
  ID/value notification. Sync has no stored VP; its target is a blocked
  caller VP in the active call chain, not a separately configured VP.
  Reclaim means revocation: destroy the doorbell, never transfer ownership
  back. There is no separate ownership-return operation. Clearly label
  proposed MonitorAPI gates. Use one creation API with an optional child
  capability handle (absent means self). Only creation and notify need
  doorbell-specific VMCALL operations; send/accept/reject/revoke must use
  shared capability ownership entry points, not new doorbell-specific ones.
  Current ABI does have SEND_CHAN/ACCEPT_CHAN and separate memory/domain
  revoke operations; generalize the shared paths rather than copy that split.
  User clarified the layer boundary: the monitor exposes one shared entry
  point per ownership operation. The capability layer resolves handles,
  checks capability types and dispatches to specialized semantics. Do not
  require the caller or monitor to select a capability type.
  User additionally requires adapting `capa-cli` and adding examples after
  the engine implementation. Use the CLI to exercise/inspect the semantics
  before full monitor boot: tree placement, transfer, pending acceptance,
  reclaim, destruction, permission/policy denials and Sync/Async effects.
  The simulated platform must expose real queued events and pending interrupt/
  VP-state effects, not print success without modeling delivery. CLI examples
  and regression tests are an explicit stage before monitor integration.
  Plan prepared for review in the conversation: proposed API names and
  MonitorAPI bits, channel-style transfer, recipient-tree revocation,
  queue/interrupt delivery and CLI-first validation. User confirmed requiring
  both Deliver and injectable. User confirmed the Sync contract is checked
  in the engine using the active call chain: e.g. dom1_vp0 -> dom2_vp2
  identifies blocked dom1_vp0 for a Sync doorbell targeting dom1. A recipient
  outside that call chain is a semantic error; reject without queue,
  interrupt or scheduling changes. Validate the selected VP's blocked state
  and effective vector policy before publication; there is no configured
  Sync VP to match. For Async, the target VP is stored only in Async(vp).
  User confirmed Sync must also reach recipients farther up the chain and
  reuse the existing interrupt-unwind logic/code, not implement a parallel
  state machine. `deliver_interrupt_vp` already validates Locked edges,
  changes the target to Running and the leaf/intermediate VPs to Waiting,
  and preserves resumption links. Share that implementation while allowing
  explicit doorbell-recipient selection: ordinary interrupt delivery stops
  at the first Deliver handler, which is not sufficient to select a specific
  doorbell recipient. Retain all-or-nothing queue/interrupt/unwind validation.
  Verified channel placement/transfer/revocation code, existing VMCALL
  dispatch and the documented interrupt-policy distinction. No runtime edits or tests
  in this planning step. File modified: `todo.md` (correct reclaim semantics
  and record the review plan). Next: resolve the marked choices with the user.
  Confidential PIO remains deferred.
  Files retained this increment: `CONTEXT.md` (small-primitives design rule)
  and `todo.md` (this handoff). Completed notification records below describe
  the superseded matching contract, not the requested replacement.

- [x] **Notification documentation: DONE.** Documented `NotificationMatch`,
  `NotificationBinding`, `NotificationState` and transient `Notification`;
  source-domain storage, recipient-scoped IDs, lifecycle/permissions and
  mutable subscriptions; attestation counts, wire offsets and signature
  coverage. Also documented one-snapshot chunk retrieval and marked older
  protocol/wrapper sketches as historical. Files: `docs/capability-engine/semantics.md`,
  `docs/domain-comm.md`, `docs/architecture/attestation.md`,
  `docs/architecture/inter-domain-notification.md`, `CONTEXT.md` (current
  doorbell flow), `todo.md` (this completion record). Documentation only;
  no runtime changes or build required.

- [x] **Notification authority remediation: DONE for the synchronous notification contract.**
  User approved revising the sequence and continuing: finish capability-owned
  notification authority/transactions before extending Linux PIO services.
  User additionally requires doorbells to be part of capa and domain
  attestation. Store bindings in the domain capability's engine-owned state;
  configuration requires SET, direct child ownership and an unsealed child.
  Engine selects recipient and non-reused recipient-global ID; removal is
  exclusive and may reduce authority after seal. Validate the complete return
  chain before queue reservation, then perform an infallible handoff/commit.
  Attestation must serialize this same inventory, not CHV's service metadata.
  Driver eventfd subscriptions remain mutable and separate from authority.
  Implemented this model, exact post-seal lookup, exclusive removal and
  prepared/infallible return through the existing hardware handoff callback.
  Removed the platform-owned binding table. Queue reservation validates both
  backing pointers and all capacity before writing, including page/ring
  crossing; publish once, release producer lock, then commit hardware return.
  DomainComm is now 1.0 (intentional major incompatibility): power-of-two
  logical capacity makes u32 cursor rollover preserve offsets. Rust/C and
  Eunomia consumers agree. Binding entries are part of the engine-derived
  attestation base and therefore the existing signature, not CHV metadata.
  Driver RX consumers share one lock; global recipient IDs route messages
  independently of the VM thread draining. Subscription teardown, duplicate
  rejection and exact eventfd matching are serialized separately.
  Independent review caught driver lock/registry errors and a compatibility
  issue; fixed and follow-up reviews found no significant issues.
  Validation already passed: full plain/translated engine tests, all five
  Loom suites (including notification delivery/removal race), ABI 15+2,
  release CLI, full release stack/package. Live post-seal unsubscribe/
  resubscribe, duplicate/wrong-eventfd checks and rejection of new post-seal
  authority pass. One- and two-created-VP PV suites pass, verifying actual
  child attestation bindings and eight alternating ring/yield requests.
  Still BSP-only execution: no live concurrent AP claim is made.
  The new guest attestation check exposed a pre-existing report transport
  failure: enqueueing every chunk at once exhausted the child's RX ring.
  Fixed with one engine-derived cached report per domain, one chunk per
  existing offset call and a driver retrieval loop. Signed continuations
  retain identical bytes and consume the nonce request only once.
  Live Ed25519 verification passes, including a 4263-byte multi-chunk report
  with verified TPM RSA signature while a standard child is running.
  A 64-byte signed-report buffer returns ENOSPC with the full size, drains
  all chunks, and is followed by a successful complete signed/TPM report.
  Additional simultaneous-child probe: one child passes its inventory and
  requests; the other fails before execution with deferred SET_GUEST_MEMORY
  EEXIST. Cross-child live coverage is blocked by backing setup, not counted
  as a notification pass; exact backing ownership remains pending.
  The old HLT test had stale copied ioctl/layout/META constants; it now
  includes the real UAPI and provides `--notifications-only` for lifecycle
  testing. Its default HLT-running mode timed out; that pre-existing behavior
  is not repaired or counted as a pass. Raw kernel-only VMCALL helpers are
  now guarded so userspace can include the UAPI.
  Final standard two-CPU Linux regression passes authenticated SSH, root
  disk, gateway ping and clean shutdown (launcher exit 0). Parent shutdown
  also completes cleanly (boot helper exit 0); no session VM or FUSE mount
  remains. Final packaged CHV, driver, lifecycle test, PV workload and strict
  confidential profile match their current source/build artifacts.
  Newest post-validation disk: `/tmp/themis-notify-final-1317f85d.raw`,
  size 3758096384,
  SHA256 `976879bdf93a28938363861dec7f47af51123ea90049a1e765571d33958284ba`.
  The packaged disk is already this version. Restore this backup after
  future repacks; it supersedes the older cr-final backup below.
  Next: confidential PIO, keeping production NONE register masks. Cross-child
  live concurrency must be retried after backing-ownership remediation.
  Full confidential boot/effective-policy/artifact evidence remains pending.
  Logs: `/tmp/themis-notify-{engine,loom,cli,build-chunks,acceptance,lifecycle,attest-active-child,short-report,cross-child,boot-final}-1317f85d.log`;
  standard regression logs use `/tmp/themis-notify-standard-*`.
  Files modified/created in this notification increment:
  - `capa-engine/src/notification.rs` (new), `domain.rs`, `lib.rs` —
    authoritative binding inventory, domain-mediated lifecycle and delivery.
  - `capa-engine/src/domain_api.rs`, `platform.rs`, `error.rs` — prepared
    return, queue transaction callback and explicit queue-full error.
  - `capa-engine/src/attest.rs`, `capa-cli/src/rust_backend.rs` — wire inventory,
    text display and error conversion.
  - `capa-engine/tests/common/mod.rs`, `tests/unit/switch.rs`,
    `tests/concurrency/loom_vp_switch.rs` — permission, match/budget, inventory,
    queue-full/invalid-return atomicity, cross-child IDs and removal race.
  - `themis/crates/themis-abi/src/domcomm.rs` — protocol 1.0, notification wire
    entries and checked, wrapping RX-write planning/tests.
  - `themis/capavisor/src/platform/{domain,mod}.rs` — remove binding authority,
    all-or-nothing physical queue writes, report snapshot transport.
  - `themis/capavisor/src/hypercall/{doorbell,mod,attest}.rs`,
    `arch/x86_64/hypercall/doorbell.rs`, `arch_traits/types.rs` — thin mediated
    registration/ring glue, raw input checks, errors and report chunking.
  - `thhv/inc/thhv.h`, `src/thhv_internal.h`, `src/thhv_ioeventfd.c`,
    `src/thhv_part.c` — matched ABI, global subscription lifecycle/dispatch.
  - `thhv/src/{thhv_domcomm,thhv_main,thhv_translate}.c` — serialized RX,
    interleaved dispatch, bounded report retrieval and bootstrap parsing.
  - `thhv/test/{test_attestation,test_child_hlt}.c` — verifier offsets,
    real-UAPI post-seal subscription regressions.
  - `eunomia/src/domcomm.rs`, `eunomia/workloads/pv/src/main.rs` — matching
    ring semantics and guest-side attested-binding/round-trip regression.
  - `docs/architecture/inter-domain-notification.md`, `todo.md` — current
    implementation, results and remaining acceptance limits.

- **Confidential port-I/O investigation (IN PROGRESS; after notification validation)**:
  Traced existing Linux PV client and boot order without changing runtime code.
  `themis_pv_init()` currently runs after `init_mem_mapping()`, but early
  console setup in `parse_early_param()` runs earlier. Serial and early PCI
  use standard scalar port-I/O helpers; string I/O and raw I/O-delay assembly
  are additional paths that must not bypass a confidential/PV transport.
  Proposed next increment: bounded port/width/value requests in the existing
  Platform service, existing CHV PIO backends, earlier validated bootstrap,
  and confidential/PV-only Linux PIO hooks with strict completion checks.
  Keep native guests unchanged, production register masks NONE, and device
  payloads outside capavisor.   The user approved the revised sequence; then add
  focused malformed/width/backend-failure tests, build, independently review
  and retry strict confidential boot plus standard/PV regressions.
  PV LAPIC and virtio/shared-DMA remain subsequent work; no new boot success
  is claimed. No images, processes or runtime source changed in this
  investigation. File modified: `todo.md` (findings and next step).
  User requested clarification before approving: exact components, reused
  mechanisms and capability-policy compliance. Important qualification:
  Platform service opcodes describe voluntary shared messages to an untrusted
  virtual-device provider, not new hardware authority; the CHV service list
  is not itself engine-enforced policy. Existing doorbell identity/authority and enqueue/return atomicity were
  monitor-owned at investigation time (now remediated above). The proposed PIO extension must not be presented as
  completing that boundary; include the engine-owned notification work as a
  prerequisite to claiming full capability-policy compliance.

- [x] **2026-11-25 — Confidential CR_ACCESS local policy: DONE; port-I/O blocker confirmed.**
  User independently confirmed standard dom1 SSH works; boot seemed slow,
  performance investigation explicitly deferred. User then shut down both
  dom1 and dom0 and approved explicit capavisor-local CR_ACCESS handling
  with NONE parent register masks. Verified images unused and ports free.
  Preserved the user's latest disk before any packaging:
  `/tmp/themis-cr-before-1317f85d.raw`, size 3758096384,
  SHA256 `8075be6a282fb354880eace18d8c6f2613c2e1c32cfa685b78dedef3298bcd46`.
  This supersedes yesterday's cpuid-final disk for restore after repack.
  The existing generic monitor queries the running VP's engine exit policy
  before calling the local CR handler; no monitor override is needed.
  Added explicit CR_ACCESS local override with NONE read/write masks.
  Regression proves the actual profile emits exactly that trap/mask stream,
  retaining default parent-trap and NONE masks: fails before JSON fix,
  passes after. All CHV Themis tests pass (49); full release stack/package
  passes. Restored user's newest disk after packaging and verified its hash.
  Existing local CR handler was read; no hardware/engine code changed.
  Its incomplete CLTS/LMSW/CR8 cases remain pre-existing limitations, not
  newly validated support.
  Live strict retry clears CR_ACCESS and reaches IO_INSTRUCTION (30):
  serial/PCI accesses cannot be emulated correctly under NONE masks.
  CHV sees filtered/stale COMM RAX rather than the guest operand, and its
  staged RAX replies are not authorized to update the guest. The 90-second
  run times out, then CHV exits cleanly and dom0 remains responsive.
  Do not treat successful bulk-register staging as proof of application.
  A disposable diagnostic copied the production profile and explicitly
  authorized only RAX reads/writes on IO_INSTRUCTION through normal capa
  policy. It was passed as a separate /tmp profile, never installed over
  production. This restores real Linux console, detects Themis CoCo/vTOM,
  establishes the two-VP PV channel and passes I/O APIC discovery. It stops
  at the expected missing PV LAPIC guard: GPA 0xfee000f0, with no legacy
  private-memory decoder. Diagnostic CHV shuts down cleanly (launcher 0).
  This is diagnostic evidence only, NOT full NONE-mask confidential boot.
  A production fix must not blindly grant whole-RAX access: OUT byte/word
  operands do not authorize disclosure of unrelated upper RAX bits, nor do
  IN byte/word replies authorize replacing the whole register.
  Next: agree a capability-mediated operand-only I/O/PV path (and reject
  ineffective unauthorized parent emulation explicitly), then PV LAPIC/
  virtio/shared-DMA work. Notification/backing/evidence remediation remains.
  Live PV suite passes (1/1). Standard profile was not changed; user verified
  its SSH immediately before this work. Parent test VM shut down cleanly
  (boot helper exit 0); no session VM or temporary FUSE mount remains.
  Production policy SHA256:
  `fe72fd12b85058a0102e3c52969afd9ea79f51ba2686801b0c5c114e800d9935`.
  Packaged policy/CHV verified byte-for-byte against source/build.
  Newest backup `/tmp/themis-cr-final-1317f85d.raw`, size 3758096384,
  SHA256 `8075be6a282fb354880eace18d8c6f2613c2e1c32cfa685b78dedef3298bcd46`.
  The packaged disk has the same hash; restore this backup after any repack.
  Logs: `/tmp/themis-cr-{profile-red,chv,build,boot,pv}-1317f85d.log`,
  `/tmp/themis-cr-confidential-{launch,stdout,stderr,dom0-dmesg}-1317f85d.log`,
  `/tmp/themis-cr-io-diagnostic-{launch,stdout,stderr}-1317f85d.log`.
  Session-only diagnostic harness:
  `.copilot/session-state/1317f85d-e7cf-4b17-9ef4-c48bd8f124be/files/cr-io-diagnostic.py`
  under the user's home; remote diagnostic JSON removed.
  Files modified: `themis/policies/dom1-confidential.json` (local
  CR_ACCESS with NONE masks), CHV `hypervisor/src/themis/policy_walker.rs`
  (resolved-profile policy stream regression),
  `docs/architecture/inter-domain-notification.md`, `todo.md` (handoff/results).

- [x] **2026-11-24 — Generic CPUID emulated ranges: DONE, validated.**
  User approved exposing existing engine range support rather than widening
  confidential register masks. `ProcFeatureEmulateRange` now supports CPUID
  and MSR through normal child-capability/SET/pre-seal checks and domain/VP
  scope. Exact-range replacement is allowed; overlaps, partial updates,
  invalid words/endpoints and second-word-before-first are rejected without
  mutation. Full-width wire endpoints use new range policy kinds 22/23;
  selector bit 16 selects the result word independently of the VP selector.
  CHV translates explicit non-indexed CPUID entries to all-ECX ranges and
  indexed entries to exact answers plus zero gap/tail ranges. Configured
  points retain precedence without overlapping inherited rules; duplicate,
  mixed-index and unsupported-flag tables are rejected. The native producer
  now supplies correct index flags and only one non-indexed entry. Existing
  indexed coverage 0..3 remains, except sparse XSAVE is collected through
  architectural component index 63. Runtime fallback uses the same flags
  and rejects an absent CPUID table instead of silently querying the host.
  The parsed CPUID default was previously omitted; the walker now emits
  its explicit configured Native/Trap action as well.
  Validation: full plain/translated engine tests and release CLI
  pass; focused engine 65, ABI 14+2 and CHV Themis 48 pass. Independent
  reviewer found no significant issues and independently passed engine
  translated set_get 65, ABI 14+2 and CHV 48. Complete Loom and full release
  bins build/package pass; final CHV repack includes two lint-only fallback
  fixes and the preserved handoff disk was restored/verified before boot.
  Engine Clippy passes with existing warnings; CHV Clippy still has 49
  pre-existing errors (none in the new CPUID/range code).
  Strict confidential launch now gets past CPUID: both VPs submit 140
  entries (112 indexed), seal succeeds, and the first forwarded exit is
  CR_ACCESS (28), not CPUID. CHV correctly fails its register read with
  EPERM under actual NONE exit masks and shuts down cleanly (launcher 0).
  This is NOT a successful confidential boot or the PV LAPIC boundary.
  Local handling of CR_ACCESS already exists in capavisor; the profile
  currently requests parent trapping by default without allowing the
  register accesses that CHV's CR handler needs. Do not widen masks as a
  workaround; the next policy decision is explicit local handling.
  Live PV suite passes (1/1). Standard two-CPU Linux passes authenticated
  SSH, CPU-count/root-disk checks, gateway ping and clean shutdown (launcher
  0). Parent also shuts down cleanly (boot helper exit 0). No production
  register masks changed. Final packaged CHV and strict policy match
  source/build byte-for-byte; no test VM or temporary FUSE mount remains.
  Newest post-validation disk backup: `/tmp/themis-cpuid-final-1317f85d.raw`,
  size 3758096384,
  SHA256 `c3fe51e8f550b48fd1ffa0a4ee0669b8eb51710b4b077d9b8d8e8206ed416d01`.
  This supersedes the older handoff backup below. The packaged image
  already contains this newest disk; restore it after any future repack.
  Logs: `/tmp/themis-cpuid-{engine-plain,engine-translated,cli,loom,build,build-final,chv-final,clippy-final,engine-clippy}-1317f85d.log`,
  `/tmp/themis-cpuid-{boot,pv}-1317f85d.log`,
  `/tmp/themis-cpuid-confidential-{launch,stdout,stderr,dom0-dmesg}-1317f85d.log`,
  `/tmp/themis-cpuid-standard-{launch,ssh,stdout,stderr,dom0-dmesg}-1317f85d.log`.
  Next: engine-owned notification transactions remain unfinished. Before a
  further strict confidential Linux retry, explicitly resolve CR_ACCESS
  local-vs-parent policy without granting parent register access; subsequent
  PV LAPIC/virtio work remains. Full confidential Linux is NOT validated.
  Files modified this increment:
  - `capa-engine/src/{domain,domain_api,update}.rs` — mediated exact-range
    configuration, strict validation and full-width CPUID range delta.
  - `capa-engine/tests/unit/set_get.rs` — arbitrary ECX, distinct VPs,
    indexed/zero answers, full-width endpoints, unchanged-on-error and MSRs.
  - `themis/crates/themis-abi/src/lib.rs` — range selectors and validation.
  - `themis/capavisor/src/hypercall/capa.rs`, `platform/mod.rs` — thin range
    decoding and existing live-engine CPUID dispatch projection.
  - CHV `hypervisor/src/themis/{policy_walker,hypervisor_impl,vcpu}.rs` —
    range translation, explicit index metadata, configured default and
    policy-only fallback.
  - `docs/architecture/inter-domain-notification.md`, `todo.md` — progress
    and capability-boundary notes.

- **2026-11-24 — Actual confidential exit masks corrected; CPUID blocker exposed.**
  IMPORTANT correction to the earlier confidential validation: the built-in
  confidential profile has NONE exit masks, but the explicit dom1 profile
  replaces the entire `policies` section and omitted `exits`, which therefore
  deserialized to ALL. Prior live launch logs really show ALL exit masks;
  NONE interrupt masks did not prove NONE exit masks. Fixed the explicit
  `themis/policies/dom1-confidential.json` to declare NONE exit read/write
  masks. Existing inheritance semantics are unchanged.
  Added a regression to `cloud-hypervisor/hypervisor/src/themis/config.rs`
  (`dom1_policy_files_parse`) comparing the resolved default exit action with
  its base profile. It fails before the JSON fix (ALL vs NONE), passes after;
  full CHV Themis tests pass (45). Independent config review found no
  significant issues and independently passed all 15 config tests.
  Live retry confirms the actual resolved ExitAction has NONE masks.
  It does NOT reach Linux console or the previous PV LAPIC guard: the first
  forwarded CPUID (reason 10) cannot complete; bounded 90-second run times
  out, then CHV exits cleanly and the parent remains responsive. Displayed
  COMM RIP `0x100000` is not a fresh RIP disclosure under NONE masks.
  Do not widen default masks or claim confidential launch validation passes.
  Cause now confirmed with a disposable diagnostic profile: both VPs submit
  85 CPUID entries (2 flagged), but the first forwarded request is leaf 0,
  ECX `0xc35380`; later examples are leaf 1 with ECX `0x6c65746e` and
  `0x1a0`. Non-indexed leaves ignore ECX, but `walk_vp_cpuid` installed
  exact (leaf, subleaf) entries, so these ordinary requests miss the
  pre-seal answer and fall through to Trap. CHV's old fallback ignored ECX
  for non-indexed leaves and supplied zero for absent indexed subleaves.
  The diagnostic profile explicitly allowed only CPUID argument reads
  (RAX/RCX) and result writes (RAX/RBX/RCX/RDX), under existing capability
  policy; no monitor/private-memory bypass. Production NONE profile was
  restored and its SHA256 verified.
  Next: expose generic emulated-range support through the mediated policy
  interface so non-indexed CPUID leaf answers cover all ECX values, while
  preserving indexed leaves/termination and per-VP tables. Honor explicit
  CPUID index flags and correct their producer rather than infer semantics
  from equal sample values or silently run host CPUID.
  Also do not silently accept parent emulation writes that NONE masks
  intentionally discard. Keep any fix engine-/policy-mediated.
  Logs: `/tmp/themis-handoff-confidential-{launch,stdout,stderr,dom0-dmesg}-1317f85d.log`;
  regression proof `/tmp/themis-handoff-profile-red-1317f85d.log`;
  passing tests `/tmp/themis-handoff-chv-1317f85d.log`.
  Diagnostic logs:
  `/tmp/themis-handoff-cpuid-diagnostic-{launch,stdout,stderr}-1317f85d.log`.
  Files: `themis/policies/dom1-confidential.json` — explicit private exit
  masks; CHV `hypervisor/src/themis/config.rs` — resolved-profile regression.
  CHV `hypervisor/src/themis/{vcpu,vm_state}.rs` adds first-exit sanitized
  CPUID fields and pre-seal table counts for complete diagnostics; reads no
  new source registers. Trace release build passed, binary deployed and
  production policy restored. Parent test VM was shut down cleanly.
  Final release bins rebuild/package and CHV Themis tests (45) pass.
  Packaged CHV binary and production policy match source/build byte-for-byte.
  No session QEMU/CHV/swtpm remains. Latest post-validation guest disk:
  `/tmp/themis-handoff-final-1317f85d.raw`, size 3758096384,
  SHA256 `e153b12c09e6e3ca299d91d99d4f850fe5f13d4952525a1ff4459a51d88118f4`.
  This supersedes the older freeze-final backup for subsequent packaging.
  It has been restored into the final bins image and verified; no temporary
  FUSE mount remains. Final build/test logs:
  `/tmp/themis-handoff-build-final-1317f85d.log`,
  `/tmp/themis-handoff-chv-final-1317f85d.log`.

- **2026-11-24 — Engine-owned VP hardware handoff implemented and reviewed.**
  `Platform::handoff_vp` is a generic, engine-invoked hardware callback for
  calls, ordinary/exit returns and interrupt unwinds. The shared operation
  lock covers validation, hardware completion and scheduling publication.
  Returns keep the source Running and its destination Locked until the
  source hardware is saved/released; interrupt unwinds likewise publish no
  Waiting VP before that callback completes. No Returning state or global
  exclusive-return lock. Callbacks receive explicit resolved endpoints,
  exit/vector metadata and engine-selected disclosure masks; platform
  helpers perform no nested engine operations or authority decisions.
  Return checks include actual core binding and the complete Locked caller
  chain. Interrupt delivery validates its owning core, binding and every
  exact callee link before changing any state; malformed chains no longer
  partially unwind. Pending core updates drain before validation, with
  errors propagated. Forward hardware completion also runs inside the
  operation; collapsed resumes use their actual resolved leaf. Local
  Deliver interrupts do not swap a VP. The monitor refreshes its current
  mutable active-VP pointer immediately before entering handoff operations.
  Validation: full engine suites with/without address_translation, all five
  Loom suites, CLI release and full release bins build/package pass.
  Independent implementation review found no significant issues and ran
  45 switching tests in each engine mode plus six VP Loom tests. Live PV
  suite passes (1/1). Two-CPU standard Linux passes authenticated SSH,
  root-disk checks, gateway ping and clean shutdown (launcher exit 0).
  Actual confidential NONE-exit-mask launch is blocked at CPUID as above;
  it does not reach the previously observed missing-PV-LAPIC guard.
  Notification bindings/atomic queue delivery, backing and evidence are
  NOT fixed by this foundation; next implement the engine-owned notification
  transaction using this handoff, then driver subscription/RX fixes.
  Logs: `/tmp/themis-handoff-{engine-plain,engine-translated,loom,cli,build,pv}-1317f85d.log`,
  `/tmp/themis-handoff-boot-1317f85d.log`,
  `/tmp/themis-handoff-standard-{launch,ssh,stdout,stderr,dom0-dmesg}-1317f85d.log`.
  The packaged disk was restored from the latest preserved freeze-final
  snapshot (SHA256 verified); session-owned `handoff-live` exited cleanly.
  The newer post-validation handoff disk above was restored after the final
  package rebuild.
  Files modified:
  - `capa-engine/src/{platform,lib}.rs` — typed generic handoff callback/export.
  - `capa-engine/src/domain_api.rs` — validated save/handoff/commit ordering,
    current binding/Locked-chain checks and prevalidation core-update drain.
  - `capa-engine/tests/common/mod.rs`, `tests/unit/switch.rs`,
    `tests/concurrency/loom_vp_switch.rs` — real-thread paused-save races,
    invalid-chain/binding/no-swap/resolved-target checks and Loom save window.
  - `themis/capavisor/src/platform/mod.rs`, `arch/x86_64/{mod.rs,hypercall/switch.rs,vcpu_switch.rs}`
    — callback projection, explicit endpoint mechanics and pointer boundary.
  - `themis/capavisor/src/arch/aarch64/mod.rs` — explicit unsupported VP
    lifecycle callback, matching that backend's existing lifecycle status.
  - `docs/architecture/inter-domain-notification.md`, `todo.md` — current
    foundation, validation and remaining transaction boundary.

- **2026-11-24 — Confidential startup-state regression fixed and live-tested.**
  Full rebuilt stack passes PV requests and standard two-CPU Linux: root disk,
  SSH, gateway ping and clean shutdown. The first confidential retry instead
  triple-faults before Linux starts: VP 4, RIP `0x508`, zero GPRs/CR3,
  CR0 `0x31`. The parent later reports an RCU stall; the outer boot helper
  has exited. This is a regression, not the expected missing-PV-LAPIC stop.
  Driver register initialization is staged in parent-writable COMM memory;
  its first actual snapshot occurs at SWITCH, after seal. The new NONE
  runtime write mask therefore discards initial register setup.
  Fixed: the engine captures every VP's initial COMM register values before
  publishing Sealed under the exclusive operation lock. Private pending
  snapshots merge only subsequently authorized writes; empty/NONE captures
  cannot discard initialization, and rejected writes cannot replace it.
  Failed capture leaves the domain Unsealed; reseal cannot recapture state.
  No first-entry post-seal ALL exception or broader runtime masks.
  Full engine address_translation suite, complete Loom suites, CLI release,
  full release bins build/package and three production merge-helper tests
  pass. Independent reviewer found no significant issues and independently
  passed 62 engine access tests plus the three merge tests.
  Earlier retry with NONE interrupt masks (but, as corrected above, ALL
  exit masks) starts Linux, negotiates PV and reaches the
  expected explicit missing-PV-LAPIC stop at `0xfee000f0`; no private decoder
  or parent fault. Dom0 remains responsive. This is not a full confidential
  boot. Final PV suite also passes after the freeze fix. Final standard
  two-CPU Linux reaches clean poweroff. The SSH harness timed out during
  the session/logout, losing its stdout; recovered guest auth.log confirms
  its `set -e` validation script reached `sudo poweroff` after CPU-count,
  root-disk/readability and gateway-ping assertions. Console reaches
  `reboot: Power down`; CHV exits 0. Do not confuse the harness timeout
  with an early guest boot failure.
  Next: engine-owned notification authorization/delivery.
  Boot log: `/tmp/themis-remediation-boot-1317f85d.log`;
  confidential launch: `/tmp/themis-remediation-confidential-1317f85d.log`.
  Standard logs: `/tmp/themis-remediation-standard-{stdout,stderr}-1317f85d.log`.
  New logs: `/tmp/themis-remediation-freeze-{boot,confidential}-1317f85d.log`,
  `/tmp/themis-remediation-freeze-confidential-{stdout,stderr}-1317f85d.log`.
  Parent and standard helpers exited; parent was shut down cleanly.
  Final standard logs:
  `/tmp/themis-remediation-freeze-standard-{stdout,stderr,auth}-1317f85d.log`.
  Newest packaged disk after final clean shutdown is preserved as
  `/tmp/themis-remediation-freeze-final-1317f85d.raw`,
  SHA256 `2c9a91a0e41ccd3597018970c14cdbb2a52aef5e5a70b527879980ef5d7a4d1e`.
  Preserve that newer disk before future packaging, not this earlier snapshot:
  `/tmp/themis-remediation-poststandard-1317f85d.raw`,
  SHA256 `f2916028bfced029dd5e32ab0d7069bba3870c57d410610e4f897835f7edf27e`.
  The earlier `/tmp/themis-remediation-dom1-preserved-1317f85d.raw` is older.
  Files: engine `src/{domain_api,platform}.rs`, `tests/common/mod.rs`,
  `tests/unit/set_get.rs`; capavisor `platform/mod.rs` and new
  `platform/registers.rs` (merge plus directly runnable host regression tests).

- **2026-11-24 — Notification transaction follow-up design review (transaction still pending).**
  Existing reviewer found a cross-core handoff gap: marking a returning VP
  Available before its hardware slot is released lets another core claim it.
  Holding a shared operation lock through hardware completion blocks revoke
  but not another SWITCH. User corrected the proposed extra state/lock:
  keep the source Running and its parent Locked until hardware ownership
  is released, then publish the scheduling transition. Extend Platform with
  engine-invoked save/handoff callbacks as needed; capa owns validation and
  ordering, and hardware work must not trail a completed engine operation.
  No new Returning state is needed merely to compensate for early publication.
  Drain core updates before
  preparing/validating return state, not while holding a destination queue lock.
  A successful enqueue must invoke the prepared infallible commit exactly once;
  failure invokes it zero times. Complete hardware handoff under the operation
  lock after releasing the queue producer lock.
  Also found: current RX enqueue can publish padding then fail on the actual
  message; replace it with prevalidated cross-page writes and one publication,
  using u32 wrapping cursor arithmetic. Driver RX consumers need common
  serialization/dispatch, not just a subscription-table lock.
  Allocate non-reused binding IDs in the recipient namespace and route all
  child notifications through a global driver subscription index. Subscription
  identity includes eventfd/namespace/match data; detach must not remove fixed
  sealed authority. A separate exact binding lookup permits reattachment
  without post-seal creation. Deferred CHV ioeventfds are flushed before seal;
  genuinely new runtime tuples must be predeclared or rejected.
  RING supplies only key/value: reject ambiguous binding rules rather than
  arbitrarily choosing by access size or PIO/MMIO namespace. Validate raw
  arguments before narrowing; canonicalize ignored wildcard fields.
  Engine-private notify-vector state may represent mutable consumer state,
  not new sealed cross-domain authority; the shared header is only a mirror.
  No notification runtime files were changed during this follow-up review.

- **2026-11-24 — Scoped VP policy and first hardware boundaries implemented/reviewed.**
  User approved section 0.9 and confirmed that VP index is a parameter to the
  same CPUID policy kind, not separate CPUID_VP0/VP1 kinds. Initial engine work
  adds category-scoped VP overrides and CPU-local emulated MSR values while
  keeping initial policy immutable. Every VP retains its own CHV CPUID table,
  with common discovery policy inherited and JSON overrides taking precedence.
  The existing SET_POLICY selector now carries optional VP index without
  reducing capability-handle width. Each VP has independent I/O/MSR bitmaps
  (7 META pages/VP); removed the COM1-only I/O whitelist. The engine publishes
  complete effective hardware snapshots at VP creation, policy changes and
  seal, serialized through projection. Monitor CPUID/MSR/exit/interrupt queries
  use the actual running VP; failed engine MSR writes are no longer ignored.
  Added generic default exit/interrupt register masks and default injection
  permission, strict selector/value/index validation, and separate pre-seal
  register setup from post-seal access. Confidential profiles now request NONE
  default masks rather than ALL. Engine address_translation suite, complete
  Loom suites, CLI release build, capavisor release build, ABI 13+2 tests
  and CHV 45 Themis tests pass. Full release build/package passed, including
  driver tests. Reviewer `f388fd06-0c36-4d49-ba8a-e018e45a4857` independently
  reviewed policy/boundary changes and ran engine set_get (60), walker (14),
  selector (1), VP MSR Loom (1), and instruction-fetch (3) tests.
  Standard live Linux and PV tests pass; the setup/runtime-mask regression
  above is fixed and confidential Linux reaches the expected PV LAPIC guard.
  Removed private instruction export from capavisor; CHV fetches only through
  its own guest-memory access and handles instruction page boundaries.
  Removed LAPIC rights suppression and dummy APIC allocation/pin/carve/send;
  normal capa EPT/IOMMU projection now applies at that GPA too. Local EPT
  denial injects #GP(0) at every CPL without skipping the access.
  User further clarified that sharing is derived from capabilities and their
  ownership for now: no separate sharing-provenance field/model is required.
  Scope the report extension to actually missing policy, VP, notification and
  measurement facts, not redundant sharing authority or metadata.
  Files: `capa-engine/src/{domain,domain_api,interposition,lib,update}.rs`,
  engine `tests/unit/set_get.rs`, `tests/concurrency/loom_vp_switch.rs`;
  ABI `lib.rs`; capavisor `hypercall/capa.rs`, `monitor.rs`,
  `arch/x86_64/{arch_state.rs,hypercall/{vp,switch}.rs}`, `platform/mod.rs`;
  `thhv/inc/thhv.h`; CHV `themis/{consts,policy_walker,vcpu,vm_state}.rs` and
  confidential default JSON; `themis/policies/dom1-confidential.json`;
  capavisor `arch/x86_64/vmcs/mod.rs`, `vmexit/mod.rs`; ABI `regs.rs`;
  CHV `themis/{emulator,hypervisor_impl}.rs`; driver
  `src/{thhv_internal.h,thhv_part.c,thhv_part_mem.c}`;
  architecture document and this tracker. Remaining work:
  engine notifications, live denied-access/LAPIC projection
  probes, backing ownership/lifetime, declared firmware and real post-seal
  evidence. The larger remediation is not complete.

- **2026-11-24 — Boundary remediation design reviewed and approved.**
  Proposed fixes are recorded in section 0.9 of
  `docs/architecture/inter-domain-notification.md`; independent design reviewer
  `150e4da5-2966-444e-8f1e-85f2d38ecc14` completed the proposal review. No runtime
  remediation code had been changed at that point. User clarified that shared-memory peers
  are selected by sending aliases, with all authority governed by existing
  capa operations and ownership. Removed the proposed separate allowed-peer
  constraints; do not reintroduce peer lists or another sharing-policy layer.
  Track actual backing derivation and alias ownership/rights, rather than
  claiming permanent pair-only access or exclusivity from carving an Alias.
  Incorporated category-scoped VP overrides, pre-seal policy configuration,
  VP-local MSR runtime values, and notification validation/producer-lock/
  infallible-commit ordering. Removal uses the exclusive operation lock;
  queued entries may drain afterward without binding-ID reuse. Preserve legacy
  triggers through the same engine path. Proposed local EPT denial is #GP(0)
  at every CPL, not a forced parent report or skipped instruction. Preserve
  A4: no new IOMMU mirroring exceptions. Full measurement/report extensions
  remain the explicit final attestation milestone, not an inferred success.
  Next: implement and test the approved
  engine/VP-policy and monitor-boundary changes.
  Files modified: architecture document (proposed remediation and corrected
  sharing model); `todo.md` (design status and user clarification).

- **2026-11-24 — Capability/monitor boundary review completed; gaps remain open.**
  Read-only implementation review requested by user, including whether the
  monitor makes decisions that should belong to capa. No runtime source was
  changed during this review; this handoff note is the only repository edit.
  The capability engine remains unchanged. Seventeen existing focused engine
  integration tests pass with `address_translation`: alias/carve sends,
  sender retention/removal, explicit GPA placement, overlap/revoke behavior
  and the exclusive/shared CVM example. These do not replace live negative
  descriptor-write/parent-read tests, which remain open.
  New PV backing is fresh anonymous userspace memory, registered through
  `THHV_SET_GUEST_MEMORY`. Per physical segment, existing thhv code resolves
  the parent memory handle, calls ALIAS(RW), then SEND_AT to the child.
  Confidential vTOM mirrors use another ALIAS/SEND_AT of the same backing.
  The separate descriptor uses CARVE(R) then SEND_AT. Domain-mediated engine
  APIs own execute/apply-update; no new direct EPT mapping path was added.
  mmap's MAP_SHARED flag itself is not capability sharing.
  Reusable additions are the record/descriptor protocol, notification result
  handling, reason-tagged CPU return and current-VP discovery. Device semantics
  stay in CHV/Linux. V1 deliberately supports only parent/RW/sync channels.
  Confirmed inherited monitor issues, not introduced by the PV diff:
  - Child I/O bitmaps are initialized to allow every port except COM1 in
    `themis/capavisor/src/arch/x86_64/hypercall/vp.rs:157-189`.
    VMCS USE_IO_BITMAPS is enabled in `vmcs/controls.rs:74`, while
    `platform/mod.rs:554` does not project ExitPolicy changes. Nontrapped
    ports bypass capa's I/O trap decision. No live port-access probe was run.
  - Legacy EPT forwarding reads private page tables/code and copies up to
    16 instruction bytes into the parent intercept message, independently
    of register read masks (`hypercall/switch.rs:471-495`, x86 directory).
    CHV's new fail-closed guard is downstream and does not prevent this export.
  - Doorbell registration resolves a child through
    `Capability::platform_action_on_child`, but bindings live only in
    PlatformDomain; the engine does not own their policy/inventory or enforce
    a seal boundary for registration (`hypercall/doorbell.rs:39-65`).
    Ring delivery directly looks up caller/parent PlatformDomains and enqueues
    before the engine return operation (`arch/x86_64/hypercall/doorbell.rs:45-107`).
    The PV work reused this non-mediated path; fixing reply/queue-full behavior
    did not make its authorization/revocation boundary compliant with A9.
  - `arch/x86_64/arch_state.rs:264` silently discards a one-page LAPIC rights
    update before checking rights, including a requested unmap. Engine and
    hardware state can diverge; stale-mapping reachability was not live-tested.
    `arch/x86_64/vmexit/mod.rs:221-241` skips a denied CPL0 EPT access instead
    of reporting a failure. Both are inherited platform-selected semantics.
  Positive checks: SWITCH(0)/doorbell CPU returns call the existing engine
  switch_return_with_exit; the new VP-identity CPUID answer is reached only
  through the engine-configured Native policy. Synthetic return RAX=SUCCESS
  is an ABI reply after engine validation, not a parent register-write bypass.
  Stateful MSR emulation was checked: it already uses the mediated engine API.
  Separate declaration/evidence gaps: Linux allocation does not prove backing
  is exclusive to a parent/child pair, and ALIAS does not prohibit further
  delegation by an authorized holder. Sharing provenance/topology must be
  established through capa and existing post-seal attestation, not trusted JSON.
  Existing CHV firmware sharing is also still implicit (`vm_state.rs:93-98`,
  RWX aliases for 0xA0000..0x100000), and the confidential profile grants ALL
  registers on ordinary exits. Those operations are capability-authorized but
  too broad/undeclared for the intended confidentiality claim.
  Next: resolve the engine-owned notification policy and hardware-policy
  projection/export gaps before expanding device support. Do not patch around
  missing mediated APIs or add a new launch-finalization operation.

- **2026-11-24 — Linux PV I/O APIC slice validated; PV LAPIC is next.**
  Added semantic I/O APIC read/write/EOI/sync dispatch in CHV, serialized
  across VP threads, with exact register/value bounds and no private-memory
  reads or instruction decoding. Shared control/I/O regions now also receive
  RW/NX vTOM aliases for confidential guests; the descriptor remains a separate
  R-only private mapping. Added native CPUID PV subleaf 1 for the actual
  current VP index: architectural CPUID APIC IDs are domain-wide policy values
  and cannot safely select a request slot.
  Linux sibling worktree now has a built-in early PV client, strict descriptor
  parsing, permanent per-VP fixmaps, correlated synchronous completion checks,
  corrected hypercall output operands, and native-default I/O APIC callbacks.
  Corrected the existing Linux Themis base-signature ECX constant from
  `0x61436973` ("siCa") to ABI `0x61437369` ("isCa"). This activates existing
  virtio fast notifications, whose ignored errors were also fixed: at most
  four ring attempts, yield only between busy failures, and explicit failure
  propagation without MMIO fallback. Direct virtio transport, shared-only
  DMA, PV LAPIC and real attestation remain unimplemented.
  ABI 12 unit + 2 doc tests and strict ABI Clippy pass (use explicit hosted target
  `--target x86_64-unknown-linux-gnu`; bare-metal default cannot run tests).
  CHV 41 Themis tests pass, including concurrent platform requests, forbidden
  service/argument rejection, backend errors and vTOM mapping rights.
  Independent reviewer `399ee23e-cea9-497f-8691-0d5b0c63ad70` found two
  integration bugs: the identity subleaf needed an explicit Native policy,
  and the bus aperture stopped before the EOI register. Both are fixed.
  Independent follow-up passes 41 Themis tests and the new real-device/bus
  EOI regression. Independent mocked notification tests pass 7/7 cases.
  Linux checkpatch reports zero errors/warnings for tracked and new code.
  Full Linux kernel, release capavisor/CHV, full bins rebuild and packaging
  pass. Final standard live regression on the final CHV build passes kernel
  `6.19.14+`, Themis detection (`features=0x7`), two CPUs, `/dev/vda1` ext4,
  network/password SSH and clean shutdown with CHV exit 0. The configured
  Eunomia PV policy suite also passes. First standard
  attempt entered emergency mode after BOOT fsck failure; stopped-image
  read-only check found no structural errors and unchanged retries passed.
  Do not silently classify that intermittent userspace failure as resolved.
  Confidential channel negotiation and I/O APIC initialization are live-tested.
  An exploratory run reached two CPUs, then crashed CHV while the legacy
  emulator read private page tables (GVA `0xffffc90000025000`, CR3 `0x2c3c001`,
  table GPA `0x2c3cc90`). That progress still depended on legacy LAPIC
  instruction decoding and is NOT final confidential acceptance.
  Final CHV now rejects confidential EPT/MMIO exits before either LAPIC or
  generic instruction decoding. The final confidential run detects Themis,
  negotiates channel 0/two VP slots and initializes the I/O APIC, then fails
  closed at LAPIC GPA `0xfee000f0`. It reports the missing PV service and
  tears down the VMM without a private page-table walk or parent kernel #GP.
  CHV exit 0 here is orderly teardown, NOT successful guest boot.
  Independent review of this guard and the 41-test regression passes.
  Next: implement semantic per-VP LAPIC requests and narrow Linux callbacks;
  then remaining platform/discovery paths and direct virtio/shared-DMA work.
  Do not weaken the no-decoder guard just to recover the exploratory SMP
  result. Actual concurrent guest-VP requests, permission-denial tests,
  private-instruction-export prevention in capavisor and full confidential
  disk/network/SSH/shutdown acceptance remain open. Attestation remains
  configure -> seal -> existing attest API; no capability-engine change or
  new launch-finalization operation was introduced.
  CHV Clippy retains exactly 50 existing errors and no new PV-module errors.
  Full-workspace `cargo fmt --all -- --check` is also not clean: widespread
  formatting drift includes untouched capability-engine files. No unrelated
  files were reformatted; the new PV module/final guard have no formatter diff.
  Both final QEMU/TPM processes have exited; no guest owns the image.
  Persisted packaged kernel SHA-256:
  `c523d0920975b539bfaad22a329a333135f2f60aa9955419e54c9f74fb5d66d1`.
  Packaged disk after final clean standard shutdown:
  `b0af1eb6cad92ebbec2446ffcc1b7c3512471dd7fa81c7fe352744544ac5c35e`.
  Source `themis/guest/dom1.raw` is untouched. Preserve newer packaged disk
  writes rather than blindly restoring the older snapshots below.
  Pre-final-build validated backup:
  `/tmp/themis-pv-linux-standard-validated-1317f85d.raw`.
  Final logs: `/tmp/themis-pv-linux-{standard,confidential}-guard-{stdout,stderr}-1317f85d.log`,
  `/tmp/themis-pv-linux-final-{boot,package}-1317f85d.log`.
  All changes remain uncommitted; nothing pushed.
  Files: ABI `src/{lib.rs,pv.rs}` (VP identity and platform opcodes);
  capavisor `vmexit/cpuid.rs` (current VP); CHV `themis/{pv,vcpu,vm_state}.rs`
  (dispatch/mappings/fail-closed exit), `devices/src/ioapic.rs` (explicit EOI/bus regression),
  `arch/src/x86_64/layout.rs` (EOI aperture), confidential JSON profile
  (explicit control/platform channel), architecture contract (wire details);
  Linux `arch/x86/kernel/cpu/{Makefile,themis_pv.c}`, `kernel/setup.c`,
  `kernel/apic/io_apic.c`, `kernel/x86_init.c` and
  `include/asm/{fixmap,io_apic,themis_hcall,themis_platform,x86_init}.h`,
  plus `drivers/virtio/virtio_pci_modern.c` (notification error handling).

- **2026-11-24 — Direct PV implementation authorized (IN PROGRESS).**
  User requested: flesh out contract, subagent design review, implementation
  and tests, then independent subagent implementation review and testing.
  Concrete first-milestone contract is section 0.8 of
  `docs/architecture/inter-domain-notification.md`. Independent design review
  completed with seven required fixes, now captured in section 0.8.
  Implemented the atomic shared protocol and descriptor codecs, strict JSON
  layout resolver, separate R-only descriptor and RW aliases, exact registered
  doorbells, per-VP CHV servicing, reason-tagged voluntary return, successful
  child hypercall replies and memory-aware VMCALL assembly.
  ABI: 12 unit tests + 2 doc tests pass; CHV: 36 Themis tests pass.
  New `pv` Eunomia workload builds using
  `cd eunomia/workloads/pv && cargo build --release`.
  Initial build from the repository root missed Eunomia's Cargo rustflags;
  no source workaround was needed.
  [x] First executable channel gate: full release capavisor/thhv/CHV/Eunomia
  build and packaging pass. Live PV suite passes eight successive alternating
  doorbell/yield requests, teardown/relaunch, and two-created-VP launch.
  That workload only runs requests on the BSP: actual concurrent guest-VP
  requests remain unverified. Hosted two-VP slot dispatch is tested.
  Existing Eunomia smoke passes 6/6. Standard Linux regression confirms
  kernel `6.19.14+`, two online CPUs, `/dev/vda1`, network and password SSH,
  followed by clean shutdown and CHV exit 0. The image does not accept the
  host SSH key; initial BatchMode failure was authentication, not boot failure.
  Independent implementation reviewer `1ae2e3ea-1224-4935-942b-5b37fc7301e3`
  reran ABI/CHV tests and the guest build. Its sole doorbell-budget finding
  is fixed: shared ABI limit 128, checked combined PV/device registration
  preflight, threshold/overflow regression. Follow-up review found no remaining
  first-gate bugs. CHV Clippy still has the same 50 existing errors; new-module
  errors were fixed. Existing unnecessary-unsafe warning remains.
  First executable target: JSON-declared capability-backed control/I/O regions,
  early descriptor discovery and a small-guest request/reply round trip.
  This uses the final protocol. Linux platform/virtio and applied-state
  attestation remain required subsequent milestones, not implicit successes.
  Preserve existing profile/test/debug edits and the newer packaged standard
  dom1 disk when building. Only manage this session's exact QEMU/TPM processes.
  Changes this session: `themis-abi/src/{lib.rs,domcomm.rs,pv.rs,pv/descriptor.rs}` (wire
  contract); `libthemis/src/lib.rs` (memory synchronization/doorbell wrapper);
  CHV `themis/{config.rs,config/pv.rs,pv.rs,mod.rs,hypervisor_impl.rs,vm_state.rs,
  vcpu.rs,policy_walker.rs}` (resources, lifecycle, discovery, dispatch and
  protected synthetic return policies); capavisor `hypercall/{switch,doorbell}.rs`
  and `vmexit/mod.rs` (yield/doorbell/discovery), `platform/domain.rs` (shared
  doorbell budget); `thhv/inc/thhv.h` (yield code);
  `eunomia/workloads/pv/{Cargo.toml,Cargo.lock,build.rs,src/main.rs}` and
  `eunomia/policies/pv/standard.json` (real guest acceptance);
  architecture document and `todo.md` (contract/status).
  Both owned QEMU/TPM processes have exited cleanly; no guest owns an image.
  Packaged standard disk restored after each build; final verified SHA-256
  `ebaca581117729107699130687999f7869cdcd0195998966a8c48a5e749c4224`.
  Source `themis/guest/dom1.raw` remains untouched. No new commits or pushes.
  Attestation direction clarified by user: seal, then attest the sealed
  domain through the existing API. No separate launch-finalization operation;
  no capability-engine code was changed during that rejected design detour.
  Missing real measurements and applied-state evidence belong in the existing
  post-seal attestation path; measurement ordering still requires correction.
  Next: continue Linux early-platform/virtio/shared-DMA work and post-seal
  attestation. Negative parent/descriptor-access and real concurrent
  guest-VP acceptance are still open; do not mark whole integration complete.
  Private-instruction export on legacy EPT forwarding is still unresolved;
  do not claim confidential Linux or attestation is working.

- **2026-11-24 — Direct, attestable PV interface: planning complete; ABI awaits review.**
  Historical planning handoff; implementation authorization is recorded above.
  Latest user direction supersedes the earlier "explicit MMIO now, broader
  transport later" staging below. Plan the final parent-child shared-memory
  interface now, including declarative CHV resources and attestable deployment
  state. This is planning approval, not approval of a concrete runtime ABI.
  Full proposal: `docs/architecture/inter-domain-notification.md`, section 0.

  Reuse exclusively held parent backing -> ALIAS -> SEND_AT to child before
  seal; no new memory-sharing primitive. Proposed `comm.regions` and
  `comm.channels` describe named RW/NX buffers, per-VP control slots, shared
  I/O arena and parent-service binding. Resolve placement and device inventory
  before seal. Keep an immutable private bootstrap descriptor separate from
  mutable shared messages; discover it before PCI/I/O APIC initialization.

  Control protocol: bounded request/reply per VP, explicit operation/sequence/
  status, checked shared offsets, release/acquire ordering, local snapshots of
  untrusted messages, no private pointers, instruction decoding or register
  payload. Current RING_DOORBELL already notifies AND returns to parent;
  do not follow it with an unconditional second SWITCH(0). Plain SWITCH(0)
  also needs thhv intercept/result integration and a non-bootstrap register
  policy. Existing raw VMCALL `nomem` annotation needs attention if reused
  across a shared-memory publication boundary.

  Proposed guest/device path: built-in Themis early platform backend plus
  `virtio-themis`, keeping virtio-net/blk and CHV workers. Cover I/O APIC
  read/write/EOI AND its dummy sync read, LAPIC callbacks, platform discovery,
  and constrained DMA; sharing only control pages cannot support virtio.
  No x2APIC mode change, generic readl rewrite or per-net/block-driver edits.

  **Attestation gaps are explicit prerequisites, not already solved.**
  Existing signed reports omit full policy, content hashes and required
  sharing/binding evidence. `Platform::measure_region` defaults to zeros and
  capavisor has no override. HASH-on-send currently measures before the
  resulting mapping updates are applied; establish stable handoff ordering,
  not merely a SHA-256 implementation. JSON is expected configuration, not
  trusted evidence. Keep current unsigned/bootstrap report compatibility.

  Proposed milestones: contract -> declarative launch -> small-guest round
  trip (one/two VP) -> early Linux platform + virtio block/network -> full
  confidential acceptance. Measurement/reporting can proceed alongside the
  channel, but both must pass before claiming attestable deployment.
  Include stale replies, malformed offsets, lost notifications, concurrency,
  revocation, denied private access/code export, manifest/evidence mismatch,
  two-CPU SSH/shutdown and standard-guest regression checks. Batch boot
  instrumentation. Old register-only/scalar-MMIO implementation tasks are
  superseded, not implemented.

  Planning added this status and the architecture proposal only; no VM,
  runtime changes, image repacking, builds, commits or pushes in this step.
  `git diff --check` passes. Existing uncommitted changes remain:
  `themis/policies/dom1-confidential.json` (profile fix),
  CHV `hypervisor/src/themis/config.rs` (profile regression),
  CHV `hypervisor/src/themis/emulator.rs` (private-walk diagnostic),
  and prior investigation notes here. Unrelated untracked files preserved.

- **2026-11-24 — Confidential Linux dom1 bring-up (IN PROGRESS).**
  **Transport staging below is historical; the direct-PV plan above is current.**
  User approved confidential boot/isolation testing first, then remaining
  userspace crashes, then x2APIC integration. Keep APIC behavior unchanged.

  **Preflight fix: DONE.** Explicit profile sections replace their base sections:
  the timer customization lost the confidential CPUID leaf, and named general
  settings lost `confidential: true`. Restored both in the explicit profile;
  config merge semantics, timer routing and APIC behavior are unchanged.
  Extended the existing profile regression; it failed before the fix and all
  **15 config tests pass** afterward. Release CHV build and
  `PROFILE=release BINS_TARGETS=chv cargo build-bins` pass.

  **Confirmed first boot blocker: parent MMIO emulation reads private page tables.**
  Two fresh-stack confidential boots detect `Themis CoCo`, VTOM bit **45**, and
  reach `ACPI: PM-Timer IO Port: 0x608`, then CHV receives a protection fault.
  A debug log immediately before the page-table read proves the failing path:
  `vcpu.rs::handle_mmio_exit` -> `emulator.rs::translate_gva` ->
  `vm_ops.guest_mem_read`. Latest trace:
  ```
  GVA 0xffffffffff5fc000 CR3 0x2c3c000 page-table read GPA 0x2c3cff8
  [VMEXIT] EPT_VIOLATION CPL=3 gpa=0x10723cff8 ... -> inject #GP(0)
  ```
  The parent must NOT read those private page tables. This denial is expected
  enforcement, not a reason to grant access, and is not a full isolation test.
  The original stripped ELF's fault is an eight-byte source read at ELF
  `0x2f68da` (account for executable-segment virtual address `0x145000` when
  resolving the dmesg mapping, rather than subtracting its start alone).

  **User direction (2026-11-24 13:33 UTC): explicit MMIO now, broader PV interface later.**
  User accepted the explicit-MMIO direction for now. Later, implement a more
  MSHV-like paravirtual interface: dom1 publishes requests in memory explicitly
  shared with dom0, then rings a dom1-to-dom0 doorbell. The shared buffer carries
  request/reply data; the doorbell is only a notification, not the payload.
  This should support more than MMIO without exporting private guest memory.
  It is distinct from DomainComm (domain-to-capavisor) and VpCommPage
  (parent-to-capavisor register transfer); do not silently repurpose either as
  guest-to-parent shared memory. Memory sharing and notification authority must
  remain capability-mediated and work recursively, not special-case dom0.
  The future transport is deferred, not approved for implementation now.

  **Next step: resolve transport staging before changing code.**
  The preceding report offered two different guest integration scopes:
  current platform with bounded Linux hooks, or a Themis-specific transport/
  platform redesign. User explicitly confirmed `minimal-hooks`, then asked
  whether doing the larger effort immediately would make more sense.
  No MMIO implementation changes have started. Separate the transport choice
  from the guest platform redesign: shared request/reply memory + doorbell can
  be the initial MMIO transport while retaining bounded Linux hooks.
  Recommendation under discussion: implement that narrow slice of the eventual
  transport now, not a throwaway register-only ABI or a full PV device/platform
  rewrite. It must work before I/O APIC setup, with explicit capability-mediated
  sharing, synchronous completion, and one independently owned request per VP
  as an initial design candidate. User correctly pointed out that private
  parent-child sharing already exists in the capability model. Reuse an
  exclusively held parent backing region, ALIAS the request-buffer range and
  SEND_AT that alias to the child before sealing. The parent retains access;
  starting from exclusive backing avoids inherited ancestor aliases. No new
  sharing primitive or permission model is required for this setup.
  Verified `Capability::alias` / `send_at` in `domain_api.rs:238,364`,
  existing thhv wrappers in `thhv_hvcall.c:34-66`, and the carve -> alias ->
  send pattern in `tests/integration/translation.rs:184-205`.
  Remaining bootstrap work is wiring allocation, the child's GPA/discovery
  and early guest mapping to those existing operations, not designing memory
  sharing anew. Ordinary parent-child shared buffers are not COMM pages.
  Keep the full Themis device transport/platform redesign deferred unless the
  user selects it. Exact ABI, permissions and completion rules still need a
  concrete implementation plan; the transport revision is not yet approved.
  Earlier, user selected "Discuss the design first".
  **Address-only proposal is insufficient and withdrawn as a confidential-MMIO
  solution.** It removes the parent page-table walk but still requires CHV to
  decode guest instructions. Current `hypercall/switch.rs:439-466` reads guest
  instruction bytes and forwards them; CHV `vcpu.rs:1014` decodes them. This is
  inconsistent with the no-private-code-export direction documented in
  `docs/architecture/confidential-vm.md` section 12. Do not solve this by passing
  more address metadata, reading private code for the parent, or loosening
  capabilities. Next: agree a guest-mediated explicit MMIO request contract
  (operation, GPA, width, write value; read result returned to guest).
  An exception-based guest handler still decodes inside the trusted guest;
  eliminating decoding entirely requires explicit guest MMIO accessor hooks.
  Explicit MMIO is now accepted in principle; no runtime/ABI change has been
  implemented yet.
  Design review follow-up: guest-mediated MMIO is the normal confidential-guest
  pattern, not necessarily a replacement device protocol. Verified that CHV's
  existing MSHV backend handles GHCB `SVM_EXITCODE_MMIO_READ/WRITE` directly
  (`hypervisor/src/mshv/mod.rs:1096-1144`), separately from its ordinary emulator.
  Hyper-V can also put exception handling/device emulation in a trusted
  guest-side paravisor; this is not functionality confined to the MSHV host
  module. A native Themis equivalent needs built-in guest architecture/platform
  support and a checked monitor/driver/CHV request path, not changes to every
  device driver. Our Linux `traps.c:1642` #VE entry is currently TDX-specific,
  so exception delivery/early-boot integration must be designed, not assumed
  available. Existing Themis doorbell hypercalls cover virtio notifications
  only. The exception-decoding alternative is not the selected direction.
  **Follow-up investigation (2026-11-24): DONE; explicit-MMIO direction accepted.**
  User requested inspiration from Linux MSHV/Hyper-V, ideally keeping Linux
  changes inside Themis support; CHV changes are acceptable.

  Findings and exact scope:
  - Existing notify path is real but write-only: Linux
    `drivers/virtio/virtio_pci_modern.c:710-725` invokes RING_DOORBELL;
    capavisor `arch/x86_64/hypercall/doorbell.rs:34-107` matches a registered
    child GPA/value, enqueues DoorbellNotify and returns execution to parent;
    `thhv_ioeventfd.c:154-199` converts the notification to an eventfd signal;
    CHV `themis/vcpu.rs:605` ignores the synthetic exit. There is no generic
    MMIO read, returned data, or request/completion protocol.
  - Existing fast-path gaps to address before reusing it for general I/O:
    ring call carries no width and sends `size=0`; enqueue failure is ignored
    (enqueue returns zero on full ring); Linux notify callbacks discard
    hypercall status and return true. Reads cannot use this fire-and-forget
    eventfd path. Some source comments describe an old EPT fast path rather
    than the actual explicit-hypercall, synchronous-return path.
  - Inspected upstream Linux MSHV at indexed commit
    `8d7fe9885c62fc9a95bf55d9db244d9672a8aadc` as the local guest kernel
    lacks those host-driver files. `drivers/hv/mshv_root_main.c:668-691`
    forwards unhandled intercept messages to userspace;
    `mshv_eventfd.c:584-699` separately implements write-notification
    doorbells/ioeventfd. It does NOT turn arbitrary guest MMIO into
    explicit operations inside the host driver.
    Our ordinary x86 CHV MSHV intercept path still uses an instruction
    emulator (`mshv/mod.rs:707-735`); do not confuse it with the confidential
    GHCB path or assume the MSHV host driver eliminates decoding.
  - Actual Linux Hyper-V no-decode precedent is guest-side
    `drivers/pci/controller/pci-hyperv.c:1097-1159`: MMIO_READ/WRITE requests
    carry GPA, size and data through a per-CPU hypercall buffer.
    Its `use_calls` branches replace this driver's own PCI configuration
    accesses, not every kernel readl/writel. CHV's confidential MSHV path
    separately dispatches GHCB MMIO_READ/WRITE to its device bus
    (`hypervisor/src/mshv/mod.rs:1096-1144` in our checkout).
    Hyper-V paravisor configurations additionally rely on trusted guest-side
    exception handling/emulation; that is not host-driver-only support.
  - **First failing guest access is I/O APIC, not virtio.** Read-only GDB
    against the built Linux vmlinux gives FIX_IO_APIC_BASE_0=515 and
    its fixed address `0xffffffffff5fc000`, exactly the captured GVA.
    `arch/x86/kernel/apic/io_apic.c:271-287` writes the index register
    before reading data. This happens before the normal device-driver path.
    No running private guest memory was read to establish this.
  - A host thhv change cannot intercept guest-native MOVs. Guest x86
    `arch/x86/include/asm/io.h:47-112` emits inline MMIO instructions with
    no generic runtime callback. Additional bypasses include native LAPIC
    writes (`asm/apic.h:97-104`) and PCI MMCONFIG accessors
    (`asm/pci_x86.h:203+`, `arch/x86/pci/mmconfig_64.c:28-84`).
    Existing I/O APIC hook covers reads only (`x86_init.h:335-338`), not
    its static write/EOI paths. Thus a single driver or one readl hook
    cannot transparently cover the current platform.
  - Checked INDIRECT_IOMEM as prior art: logical I/O callbacks exist, but
    x86 does not wire `asm-generic/logic_io.h` into its native accessor
    family. Enabling the option alone is not a driver-only solution.
    Existing PCI and virtio operation tables can support Themis-owned
    transports, but a new virtio transport would solve device accesses
    only, not the early platform MMIO above.
  - Driver-first alternative is a different virtual platform, not a transparent
    MMIO interceptor: a Themis virtio transport can implement existing
    `virtio_config_ops`, keeping virtio-net/blk unchanged. Existing APIC
    callback/driver installation APIs (`asm/apic.h:275-384`) are useful
    platform precedents; Hyper-V uses them in `arch/x86/hyperv/hv_apic.c`.
    Hyper-V's callbacks still fall back to native MMIO for other registers,
    so copying them as-is does not solve Themis confidentiality.
    A new Themis APIC backend and no-IOAPIC/platform design could potentially
    remove the problematic native accesses without generic accessor edits,
    but IRQ delivery, SMP, timers, discovery and legacy devices must all be
    specified and tested. ACPI supports skipping I/O APIC probing with
    `noapic` (`acpi/boot.c:1198-1205`); this alone is not a full boot fix.
    Do not rule out driver-local support on a redesigned platform, and do
    not present that larger redesign as already validated or approved.

  Investigation recommendation (accepted in principle; scope/ABI to confirm):
  - Keep substantive guest logic in built-in Themis platform/driver support,
    reached through the existing early `themis_platform_init()` call.
    Accept a bounded set of generic hooks where no usable hook exists:
    scalar MMIO, native LAPIC paths and PCI configuration need explicit
    coverage or an agreed platform replacement. No per-net/block-driver edits.
    Strictly unmodified guest + current platform + no decoding cannot all
    be provided by the current interfaces. Do not promise otherwise.
    Alternative for a hard "no existing Linux-file modifications" goal:
    Themis-owned virtio transport + explicit PV platform, with more CHV/
    platform work. This is a separate choice, not an implicit APIC/ABI change.
  - Define a synchronous scalar request/reply path (read/write, GPA, width,
    write value; completion status/read value), initially 1/2/4/8 bytes.
    Reuse mediated parent/child switching and COMM transport machinery;
    parent access limited to deliberate request/reply state. ExitPolicy
    already indexes u32 synthetic exits and has per-exit register read/write
    masks (`capa-engine/src/domain.rs:362-385`).
  - Decide call/range authorization through sanctioned engine interfaces,
    completion ownership, per-VP in-flight state, ordering, error handling,
    revocation/cancellation and multi-VP behavior before coding. Existing
    `platform_action_on_child` is documented as an escape hatch, not an
    established generic device-permission model.
  - CHV dispatches typed operations directly to the existing device bus,
    never its instruction emulator or guest_mem_read/write. Require defined
    errors for unsupported/unregistered accesses; existing VmOps currently
    logs missing bus ranges and returns success. Keep doorbells as a
    narrowly defined notification optimization, not the read/reply mechanism.
  - Test a tiny sealed scalar-MMIO guest first, then early I/O APIC setup,
    LAPIC/PCI/MSI-X/virtio configuration, then guest-authorized DMA sharing
    and full confidential Linux boot. Include denied operations, no private
    code/register leakage, ordering, overflow, concurrent VPs, revoke during
    a pending read, and standard-guest behavior.
  Investigation changed `todo.md` only; no runtime or Linux changes, no VM
  started and no capability permissions changed. Prior config tests/build
  results above still describe the unchanged runtime tree.
  Guest-initiated DMA share-back also appears absent in Linux/CHV; that is a
  possible later blocker, not the cause of this early fault. Full boot, two-CPU
  operation, shared I/O, SSH and private-memory isolation remain unverified.

  **Other observed failure, kept separate:** retrying in the first still-running
  dom0 failed the large `THHV_SET_GUEST_MEMORY` with EINVAL before Linux ran.
  Another VP then drained no pending regions, sealed, and CHV exited zero.
  A zero launcher status is therefore not a boot-success test. Cleanup also
  logs `REVOKE_MEM ... failed (-2)`. Root causes not established or changed.
  Restarted the stack once to capture the original MMIO fault cleanly.

  **Evidence / validation:** initial logs `/tmp/themis-confidential-{host,stdout,
  stderr,dom0-dmesg}-20261124.log`; confirmed diagnostic logs
  `/tmp/themis-confidential-clean-{stdout,stderr,dmesg}-20261124.log` and
  `/tmp/themis-confidential-diagnostic-host-20261124.log`.
  Retry evidence is in `/tmp/themis-confidential-diagnostic-stderr-20261124.log`
  and `/tmp/themis-confidential-retry-full-dmesg-20261124.log`.
  Tested diagnostic CHV SHA256:
  `890dd1de01089f1f968e33e8d045a0ecf08564de174af713c3bb083c8effd5a0`.
  Package Clippy reports 50 findings in existing code; rustfmt reports existing
  formatting differences outside the added lines. Neither check is globally
  clean; no unrelated lint/format cleanup performed. Existing unnecessary-unsafe
  warning in `vm_state.rs:588` remains.

  **Images / runtime handoff:** owned QEMU/dom0 and TPM services shut down cleanly.
  Latest user-tested standard disk restored to packaged `bins.img` from
  `/tmp/themis-dom1-standard-before-confidential-1317f85d.raw`, verified SHA256
  `ebaca581117729107699130687999f7869cdcd0195998966a8c48a5e749c4224`.
  Host source `themis/guest/dom1.raw` is untouched (SHA256 starts `e39d9c23`).
  IMPORTANT: build-bins always overwrites the packaged disk from that source,
  even for CHV-only targets; preserve the newer standard backup when repacking.
  Current changes uncommitted; no push performed for this work.

  Files modified:
  - `themis/policies/dom1-confidential.json` — restore confidential discovery.
  - CHV `hypervisor/src/themis/config.rs` — profile-resolution regression.
  - CHV `hypervisor/src/themis/emulator.rs` — debug-level read-address diagnostic.
  - `todo.md` — results, blocker, preserved baseline and next design decision.

- [x] **2026-11-24 — x2APIC/capability-model investigation: DONE;
  implementation requires design confirmation.**
  Saved the verified FAT/networking work as `5763f23`; CHV remains at
  `4d7278799`, with no uncommitted submodule changes and nothing pushed.
  No runtime, kernel, capability-engine, driver, or policy changes made.

  **Actual mode / why Linux falls back:**
  - Saved child VMCS controls are `secondary=0x001013ba`: x2APIC virtualization,
    APIC-register virtualization and VID enabled; APIC-access virtualization off.
    Linux nevertheless reports `x2apic disabled` and uses physical-flat xAPIC.
    APICBASE Emulate writes are consumed without changing the advertised mode
    (`msr_emulator.rs:116-129`), so this is a mixed implementation, not a fully
    consistent virtual xAPIC/x2APIC mode transition.
  - Exact guest-kernel cause: `../linux/arch/x86/kernel/apic/apic.c:1827-1865`
    requires either guest interrupt remapping or the hypervisor's
    `x2apic_available()` hook. The latter defaults false in `x86_init.c:117`.
    `../linux/arch/x86/kernel/cpu/themis_platform.c:37-55` detects Themis but
    does not install this hook; Themis is also absent from `hypervisor.c`'s
    platform list. A native Themis hook, gated on actual support, is preferable
    to pretending to be KVM or exposing a physical IOMMU to the child.

  **Existing capability contracts that fit x2APIC:**
  - Domain `MsrPolicy` selects Trap/Emulate/EmulateConst/Native; initial/seal-time
    bitmap population and policy-update projection preserve those intercepts
    (`msr_bitmap.rs:121-162`, `platform/mod.rs:515-540`). Hardware virtualization
    is the mechanism for a private VAPIC, not independent authority.
  - Fixed guest IPIs forwarded by CHV use THHV_INJECT_INTERRUPT, resolving the
    caller's child capability under the engine lock and checking the target
    vector's `injectable` flag before `inject_via_pid`
    (`vcpu.rs:1355-1397`, `hypercall/doorbell.rs:116-188`).
    INIT/SIPI register setup uses the existing checked SET path, not physical IPIs.
  - `visibility` remains ambient hardware routing only; `injectable` gates
    explicit parent/emulator delivery, not ambient delivery. A guest-local
    hardware self-IPI is an MSR-authorized VP-local operation, not a reason to
    grant ambient Deliver or allow the parent to bypass `injectable`.
    Keep EOI-exit bitmaps zero, META private, and cross-core delivery through PID.

  **Gaps to fix before enabling Linux x2APIC:**
  - CHV unconditionally adds broad Native x2APIC MSR ranges after the configured
    baseline (`vm_state.rs:270-299`). This still goes through engine SET_POLICY,
    but implicitly grants accesses even for a Trap-default profile and can
    conflict with explicit overrides. Resolve the intended grants explicitly;
    do not broaden configured restrictions just because hardware supports them.
  - Intel SDM Vol. 3C section 30.5 does NOT virtualize arbitrary x2APIC writes:
    with the currently enabled controls, TPR (0x808), EOI (0x80B), and self-IPI
    (0x83F) have the relevant hardware write virtualization. Other untrapped
    writes, including SVR/LVT, retain physical-MSR behavior (guest #GP while
    the physical LAPIC is xAPIC). Existing Native ranges therefore are not a
    complete virtual LAPIC. Trap/emulate the remaining registers before merely
    enabling the Linux hook; existing generic parent MSR scratch storage alone
    is not a complete LAPIC model.
  - ICR destination is currently truncated to 8 bits on the x2APIC path
    (`vcpu.rs:636-648`, `vmexit/classify.rs:166-177`). Do not silently alias a
    32-bit destination to another VP; preserve/validate it. Shared IPI decoding
    also ignores logical addressing, and SIPI currently targets all non-self
    VPs. Either implement the supported routing semantics or reject unsupported
    cases explicitly; current two-CPU success does not validate larger guests.

  **Proposed direction (not implemented):** keep the existing capability model.
  First make the per-register MSR grants and emulation consistent, with no
  physical-LAPIC pass-through; retain checked parent routing for cross-VP IPIs.
  Then add the feature-gated native Themis Linux hook and consistent mode state.
  Test denied injection, Trap/Emulate/Native behavior, destination validation,
  SMP startup/IPIs, timer/idle wakeups, SSH and the no-hardware-support fallback.
  Confirm this approach with the user before changing capability semantics or
  implementing the nontrivial cross-component changes.
  Existing model tests passed: unit_interposition **34/34** and
  integration_interrupt **4/4**; these do not validate live x2APIC operation.
  Test log: `/tmp/themis-x2apic-model-tests-20261124.log`.
  Files modified for this investigation: `todo.md` only.

- [x] **2026-11-24 — Early static networking and SSH for dom1: DONE.**
  User approved `192.168.100.2/24`, gateway `192.168.100.1`, matched by NIC MAC
  `12:34:56:78:90:ab`. The old late static netplan conflicted with cloud-init's
  earlier DHCP definition. A single NoCloud `network-config` now supplies the
  address before network startup; no manual address assignment or DHCP server.
  Existing instances also need cloud-init's `updates.network.when: [boot]`
  available early in `/etc/cloud/cloud.cfg.d/99-themis-network-updates.cfg`.
  Putting this setting in user-data was too late for the initial migration;
  that approach was replaced, not retained as a second configuration source.
  Provisioning refreshes when its source/config changes, removes the old
  `99-dom1.yaml` and cached datasource object, and preserves instance identity,
  accounts, SSH host keys, and per-instance semaphore state. Existing-image
  migration verified those files unchanged. GRUB mask appending is idempotent.

  **Verified twice across a clean guest restart:** authenticated SSH from
  dom0 and from the host through dom0; hostname `dom1`, kernel `6.19.14+`,
  two online CPUs, automatic `/dev/vda15 vfat /boot/efi`, static `.2/24`,
  default route via `.1`, and selected network file
  `/run/systemd/network/10-netplan-dom1.network`. Both guests powered off
  cleanly. The test waits for an SSH banner: ping can work before SSH is ready.
  No temporary EFI mask, fstab change, capability/monitor/driver/policy change,
  instance reset, host-key regeneration, or live network workaround.

  Access while dom1 is running:
  - From dom0: `ssh cloud@192.168.100.2`
  - From host: `ssh -J cloud@localhost:2222 cloud@192.168.100.2`

  Validation: repeat provisioning fixture preserves existing state and checks
  seed/policy/cache cleanup; repeated GRUB editing does not duplicate masks.
  Cloud-init rendered the YAML correctly; `bash -n`, `git diff --check`,
  `PROFILE=release BINS_TARGETS=tools cargo build-bins`, and
  `cd themis && cargo fetch-dom1` passed. The latter skips the migrated image.
  Shut down owned dom0/QEMU and TPM. Saved the final tested active disk back to
  `themis/guest/dom1.raw` before packaging, then verified the packaged disk
  SHA-256 matches `e39d9c23cb65a307993d0c81c52e1eb92b438a384ebdfd7275ebd2e972ee1555`.
  Packaged kernel still matches the FAT-enabled hash below. This ordering
  matters: `update-bins.sh` always replaces the packaged dom1 disk from source.
  Pre-migration source/active image backups remain in
  `/tmp/themis-dom1-{source-pre-network,pre-network}-1317f85d.raw`.
  SSH logs: `/tmp/themis-dom1-network-{DOM0_SSH,HOST_SSH}-20261124.log`.
  Build log: `/tmp/themis-dom1-network-build-bins-20261124.log`;
  host trace: `/tmp/themis-dom1-network-host-20261124.log`.
  The earlier intermittent userspace crashes/boot failures remain unresolved;
  these successful boots do not establish general stability.

  Files included in the guest-fix commit:
  - New `themis/configs/dom1-network.yaml` — single early static network input.
  - `themis/scripts/fetch-dom1.sh` — seed network input, early refresh policy,
    non-destructive existing-image migration, repeatable provisioning.
  - `themis/configs/themis-coco-x86_64-minimal.config` — tested FAT/VFAT support.
  - `todo.md` — results and handoff. User confirmed SSH works and requested
    committing these fixes. Nothing pushed.

- [x] **2026-11-24 — SSH follow-up: FAT support DONE.**
  Committed prior verified fixes as superproject `5ef647a` and CHV `4d7278799`;
  nothing pushed. User approved adding FAT support after discussing the
  image's required EFI mount versus direct-kernel boot. Added built-in FAT,
  VFAT, and ISO-8859-1 support to
  `themis/configs/themis-coco-x86_64-minimal.config`, retaining kernel defaults
  for FAT codepage (437) and character set. `cargo build-kernel` passed.
  Packaged only the new kernel, verifying the dom1 disk SHA-256 was unchanged:
  `8adbaa0a8e8f9ec02a721d85048f61806d6751f015682cc84288a55d072bd756`.
  Built and deployed kernel SHA-256:
  `3a5997ea900d40d03b05a305cda2a6157320cdf3808f9e3145fc9da1390869c3`.
  The normal, unmasked launcher booted two CPUs and reached interactive login;
  `boot.mount` and `boot-efi.mount` were both automatically active, with
  `/dev/vda15 vfat /boot/efi`. No manual mounts were required on that boot.
  Clean guest-initiated poweroff completed. Logs:
  `/tmp/themis-dom1-fat-{host,launch,verification}-20261124.log`,
  `/tmp/themis-dom1-fat-kernel-build-20261124.log`.
  An earlier attempt failed at the ext4 `/boot` mount and never attempted EFI;
  root cause remains unknown alongside the already-documented userspace crashes.
  Do not describe the broader guest as stable merely because FAT passed.
  No fstab, mount-policy, monitor, capability, or network changes made.
  Network diagnosis confirmed: NoCloud seed has no `network-config`, so
  cloud-init generated DHCP `ens3` in `50-cloud-init.yaml`, while our later
  static `eth0` definition in `99-dom1.yaml` matches the same MAC.
  Networkd chose the former. Next: confirm the networking fix with the user,
  then provide one early static configuration and verify authenticated SSH.
  Files changed for FAT: minimal kernel config above and `todo.md`; included in
  the guest-fix commit.

- [x] **2026-11-24 — Original Linux dom1 timer stall and CPU-startup bugs:
  DONE; broader userspace validation remains open.** Fresh build passed.
  Smoke **6/6**, idle-timer **1/1**, internal timer policies **2/2**, WRMSR
  policies **4/4**, CHV policy unit tests **15/15**. Actual Linux reports
  `smp: Brought up 1 node, 2 CPUs`; interactive dom1 login confirms kernel
  `6.19.14+`, two online CPUs (`0-1`), working shell commands, and clean
  guest-initiated poweroff. No PKRU warning or original timer freeze reproduced.
  No capability-engine/model/ABI changes; timer ownership change was approved.

  **Fix review (all rebuilt and exercised):**
  - Architecture-specific Emulate APICBASE reads derive BSP from the engine's
    current VP binding; EmulateConst still returns the exact policy value.
  - Linux standard/confidential policy selects parent-owned TSC-deadline Trap;
    uses existing timerfd/irqfd/capability-checked injection. Future clock
    redesign is deferred; original internal-emulation tests remain intact.
  - Completing emulated instructions clears only STI/MOV-SS shadowing.
  - Child LAPIC MMIO stays unmapped because child VMCS does not enable
    APIC-access virtualization; existing parent emulation handles startup IPIs.
  - Hardware VAPIC holds the unshifted x2APIC ID; parent software xAPIC ID
    representation is unchanged. This corrects the observed CPU1 identity halt.
  - Native CPUID hides PKU consistently with its already-hidden PKRU state;
    new smoke regression checks this cross-leaf feature/state contract.

  **Remaining boot/userspace issues (IN PROGRESS; not fixed by a workaround):**
  - Default Linux command reaches systemd emergency mode: image fstab requires
    `LABEL=UEFI /boot/efi vfat`, but the minimal kernel has no FAT support.
    For one diagnostic boot only, added `systemd.mask=boot-efi.mount` on the
    command line; no source, fstab, kernel config, or persistent mask changed.
    This boot reached login and completed cloud-init. Default unattended boot
    is therefore NOT yet established.
  - Console `cat /etc/netplan/99-dom1.yaml` segfaulted once. Read-only inspection
    of the stopped disk also found an earlier `ip` segfault. Root cause unknown;
    do not call userspace fully stable or assume this is just image setup.
    Journal: `cat[831]`, fault VA `0x72e1ec3df0a0`, RIP `0x7e46f7a384d5`
    (libc offset `0x384d5`, `mov (%rsi),%edx` while loading locale data).
    Its crash report contains only an incomplete gzip header for CoreDump;
    no usable saved register image was recovered. Earlier `ip[376]`:
    RIP `0x758d10791000` in libmnl, error `0x14`, CPU1.
  - No IPv4 on ens3, despite correct static netplan content and completed
    cloud-init. Networkd selected `10-netplan-ens3.network`; the new
    `99-dom1.yaml` matched by MAC was not selected. SSH is NOT verified.
    `multipathd` also fails because this kernel lacks device-mapper support.
  - Next: review the completed fixes with the user, then decide follow-up scope.
    Diagnose the userspace crashes before claiming stability; separately choose
    proper minimal-kernel/image handling of EFI and inspect netplan precedence.
    Do not silently enable CPU features, change capability policy, or commit
    temporary diagnostic boot arguments.
  - Actual child logs were collected separately from dom0. Cleanly powered off
    dom1 through its own shell, then dom0; owned QEMU and TPM exited successfully.
    Removed temporary extracted binary/core copies after crash inspection.
    Host evidence:
    `/tmp/themis-dom1-cpu-state-{host,serial,chv,launch}-20261124.log`,
    `/tmp/themis-dom1-cpu-state-build-20261124.log`,
    `/tmp/themis-cpu-state-{tests,config-tests}-20261124.log`,
    `/tmp/themis-dom1-userspace-{console,verification,launch,serial,chv}-20261124.log`,
    `/tmp/themis-dom1-{image-diagnostics,crash-evidence}-20261124.log`.

  Files changed this session (source uncommitted for review):
  - Capavisor `src/{monitor.rs,arch_traits/traits.rs,arch_traits/types.rs}`,
    `src/arch/x86_64/{x86_platform,msr_emulator}.rs` — policy-gated per-VP
    APICBASE read hook and BSP synthesis.
  - Capavisor `src/arch/x86_64/{vcpu_ext,arch_state}.rs` — instruction
    completion and LAPIC MMIO projection; `hypercall/vp.rs` — x2APIC ID;
    `vmexit/cpuid.rs` — PKU/XSAVE consistency.
  - `themis/policies/dom1-{standard,confidential}.json` — approved parent timer.
  - `eunomia/workloads/smoke/src/main.rs` — BSP and feature/state regressions.
  - New `eunomia/workloads/timer-idle/{Cargo.toml,Cargo.lock,build.rs,src/main.rs}`
    and `eunomia/policies/timer-idle/parent.json` — repeated idle/wakeup regression.
  - CHV `hypervisor/src/themis/{vm_state,config}.rs` — corrected BSP explanation
    and resolved timer-policy test. Driver and switch diagnostics removed;
    those sources restored. `todo.md` — results and debugging handoff.
    Ignored binaries/ISO/disks refreshed; unrelated untracked files untouched.

- **2026-11-24 — Linux dom1 boot stall reproduced (IN PROGRESS).**
  Freshly built `6.19.14+` CoCo-capable kernel was packaged, hash-verified inside
  `bins.img` and again inside dom0, then booted through the Themis backend with
  the script defaults (2 vCPUs, 1G, standard policy, no initramfs).

  Actual child serial (`/tmp/chv-stdout.log` in dom0) proves Linux reached
  virtio device activation, mounted `/dev/vda1` as ext4, and launched
  `/sbin/init`. It then stopped at:
  ```
  [    5.239864] Run /sbin/init as init process
  [    5.442258] systemd[1]: Failed to find module 'autofs4'
  ```
  Serial stayed at 50,313 bytes across checks more than 90 seconds apart.
  Dom1 ping/SSH did not respond; dom0 SSH remained healthy. CHV's vCPU threads
  remained inside `thhv_run_vp`; no capavisor panic/VM-entry failure observed.
  The missing autofs4 warning is the last visible message, NOT a proven cause.

  **Separate confirmed CPU-startup bug:** despite CHV configuring 2 vCPUs, Linux
  deliberately brings only 1 CPU online. Its log says the BSP is not marked in
  APICBASE, assumes a crash kernel, and rejects the other CPU.
  `cloud-hypervisor/hypervisor/src/themis/vm_state.rs:275-299` installs a
  domain-wide emulated IA32_APIC_BASE value without BSP bit 8, claiming Linux
  derives BSP solely from MADT. That claim is false for this kernel:
  `../linux/arch/x86/kernel/cpu/topology.c:126-179` explicitly reads the bit and
  limits CPU count when absent. Correctness requires a per-vCPU BSP indication,
  not setting the domain-wide bit for every VP. This explains the missing AP,
  but is NOT yet established as the cause of the later systemd stall.

  Hardware APICv/x2APIC capabilities are exposed, but hardware posted interrupts
  are still deliberately disabled by `vmcs/controls.rs`; both child VMCS setups
  report software PIR-drain fallback. Linux also attempts to disable x2APIC
  later in boot (`IRQ remapping doesn't support X2APIC mode`).

  At 10:43 UTC, user requested both fixes and approved this implementation plan:
  policy-gated architecture RDMSR hook supplies the per-VP BSP bit, preserving
  literal EmulateConst values; batch timer arm/fire, HLT, and driver wakeup
  diagnostics before the next boot. No capability-engine/model changes.
  Implementation/testing IN PROGRESS; distinguish CPU enumeration from the
  systemd stall. Test stack was shut down cleanly before editing.
  Logs preserved on host:
  - `/tmp/themis-linux-dom1-host-20261124.log` — capavisor + dom0/build trace.
  - `/tmp/themis-linux-dom1-serial-20261124.log` — actual child Linux console.
  - `/tmp/themis-linux-dom1-chv-20261124.log` — CHV stderr/exit diagnostics.
  - `/tmp/themis-linux-dom1-console-20261124.log` — launcher/SSH output only.
  Files modified for this investigation:
  - `monitor.rs`, `arch_traits/{traits,types}.rs`,
    `arch/x86_64/{x86_platform,msr_emulator}.rs` under capavisor — policy-gated
    per-VP APICBASE read emulation; temporary bounded timer diagnostics.
  - Capavisor `arch/x86_64/hypercall/switch.rs`, `thhv/src/thhv_vp.c` — temporary
    HLT/deadline/wakeup diagnostics.
  - CHV `hypervisor/src/themis/vm_state.rs` — correct the BSP-policy explanation.
  - `eunomia/workloads/smoke/src/main.rs` — regression test for BSP reporting.
  - `todo.md` — debugging handoff; ignored bins/ISO — build/deployment artifacts.

  **BSP implementation and first diagnostic boot results:**
  - Full `PROFILE=release cargo build-bins-docker` passed, followed by native
    release ISO build/boot. Smoke including the new BSP assertion passed **5/5**;
    timer policy suite **2/2**, WRMSR policy suite **4/4**.
  - Linux no longer prints the APICBASE/crash-kernel fallback. It now reaches
    `smp: Bringing up secondary CPUs`, then stops earlier at its first HLT.
    Actual two-CPU startup remains UNVERIFIED.
  - Stall mechanism observed: 14 timer arms/fires, then arm #15 followed by:
    ```
    [TIMER-DIAG] hlt #1 vp=0 deadline=0x150891323c now=0x15087e054e timer=59368 lvt=0x10000 flags=0x246
    thhv: HLT wait vp=0 rip=0xffffffff821da85a flags=0x246 pending=0
    ```
    No following timer fire or driver wake across repeated checks; child serial
    remained 20,437 bytes. Capavisor's VMX timer only runs while that VP executes
    in guest mode; thhv instead waits indefinitely for an external injection.
    Existing Eunomia timer test busy-spins and therefore misses this HLT bug.
  - BSP fix preserves engine-selected Emulate/EmulateConst semantics; only
    Emulate APICBASE reads derive BSP from the engine's current VP identity.
    No engine, policy, or ABI modifications made.
  - User chose **parent-owned timer emulation**. Updated Linux dom1's standard
    and confidential policy files to select Trap for IA32_TSC_DEADLINE, using
    existing CHV timerfd → irqfd → capability-checked injection/driver wakeup.
    No capability-engine/model or ABI changes. A future paravirtual clock is
    explicitly deferred. Temporary diagnostics remain for the next experiment.
  - Added `eunomia/workloads/timer-idle/{Cargo.toml,build.rs,src/main.rs}` and
    `eunomia/policies/timer-idle/parent.json`: three arm/HLT/wakeup cycles, with
    existing suite timeout catching a stranded timer. Preserved original
    capavisor-emulation delivery/suppression tests.
    CHV `hypervisor/src/themis/config.rs` checks resolved Linux policies select
    the parent timer. Next: rebuild, verify idle regression and Linux SMP boot.
  - Saved logs: `/tmp/themis-dom1-fix-build-20261124.log`,
    `/tmp/themis-dom1-diag-{host,serial,chv,launch,regressions}-20261124.log`,
    `/tmp/themis-dom1-bsp-smoke-20261124.log`.
    Requested clean dom0 poweroff after collecting results.

  **Parent-timer follow-up (IN PROGRESS):**
  - CHV policy unit tests passed **15/15**. Linux now runs past the original
    freeze into systemd, but CPU1 times out and userspace hits an existing
    XSAVE/PKRU warning (`get_xsave_addr_user`, cloud-init generator). Neither
    successful SMP nor responsive Linux userspace is established.
  - New idle regression initially failed: policy fixtures only support one
    `extends` level (corrected the fixture), then `sti; hlt; cli` lost the timer.
    `ActiveVcpuExt::next_rip` advanced a trapped instruction without consuming
    STI/MOV-SS shadowing. Added shadow clearing to architectural instruction
    completion, preserving all other interruptibility bits. Regression untested.
  - CPU1 startup root cause: child VMCS never enables VIRTUALIZE_APIC_ACCESSES,
    but `arch_state::change_rights` mapped the fake LAPIC MMIO page whenever
    that assist was merely supported. Linux disables x2APIC and silently writes
    its startup IPIs into RAM. Keep child xAPIC MMIO unmapped so the existing
    EPT-fault/CHV LAPIC emulator handles these accesses. No engine/API changes.
  - Removed temporary timer/HLT/driver diagnostics after preserving evidence.
    Additional changed files: capavisor `arch/x86_64/{arch_state,vcpu_ext}.rs`
    for LAPIC projection and instruction completion. Driver and switch source
    are restored to their pre-investigation contents.
  - Next: fresh full build, idle regression, smoke/timer/WRMSR, Linux 2-VP boot.
    Logs: `/tmp/themis-dom1-parent-{host,serial,chv,launch}-20261124.log`,
    `/tmp/themis-parent-config-tests-20261124.log`,
    `/tmp/themis-timer-idle-parent-20261124.log`. Test stack shut down cleanly.

  **Clean validation and newly exposed CPU-state bugs:**
  - Full build passed; parent-owned timer-idle regression **1/1** (three
    arm/`sti; hlt; cli`/wakeup cycles), smoke **5/5**, original timer policies
    **2/2**, WRMSR policies **4/4**. Temporary diagnostics are absent.
  - LAPIC mapping correction makes INIT/SIPI reach CHV; both SIPIs report
    successful VP-state setup. CPU1 still fails to report alive.
    Read its state through pidfd_getfd + existing THHV_GET_VP_STATE (no direct
    hypercalls): RIP `0xffffffff812aa04f`, CR3 `0x2a3c000`, CR4 `0x20b0`.
    Exact kernel symbols resolve this to `common_startup_64`, head_64.S:309:
    halt because the APIC ID was not found. The child VAPIC page held VP ID in
    xAPIC bits [31:24], but hardware x2APIC reads consume the full ID.
    Changed `arch/x86_64/hypercall/vp.rs` to initialize the unshifted ID;
    parent xAPIC emulation retains its own correctly shifted ID.
  - Linux reaches systemd and then repeats soft-lockup reports while building a
    signal frame in cloud-init's generator. CPUID advertises PKU but leaf 0xD
    hides PKRU state. Added PKU masking alongside the existing XSAVE masks in
    `arch/x86_64/vmexit/cpuid.rs`; added a smoke regression checking this
    cross-leaf feature/state contract. These two new corrections are UNTESTED.
  - User requested concise bug-fix summaries for contract/design review; given
    for BSP, timer ownership, idle shadowing, LAPIC mapping, and pending fixes.
    No capability-engine/model/ABI changes or permission bypasses.
  - Next: fresh build and repeat exact regressions plus Linux two-CPU/userspace
    verification. Current test VM shut down. Logs:
    `/tmp/themis-dom1-idle-fix-{host,serial,chv,launch}-20261124.log`,
    `/tmp/themis-idle-fix-tests-20261124.log`.

- [x] **2026-11-24 — Fresh rebuild and interrupt-test baseline on asmodai:
  DONE.** Themis/dom0 boots, the rebuilt driver loads, Eunomia smoke passes
  **4/4**, timer policies **2/2**, and WRMSR policies **4/4**, including the
  formerly intermittent `04-mixed-default-trap` scenario.

  Host: Intel i5-1345U, Linux 6.8.0-149-generic, writable `/dev/kvm`,
  `kvm_intel` nested=Y and enable_apicv=Y. Unlike the old WSL environment,
  capavisor reports `VMX: yes  x2APIC: yes  APICv: full  VT-d: yes`;
  CHV confirms `FEATURE_X2APIC_VIRT=true` and `x2apic_virt=true` during actual
  child boot. Tests used the default feature set, with no interrupt workaround.
  These tests do not establish that every posted-interrupt path is correct.

  Build/setup corrections:
  - Full `PROFILE=release cargo build-bins-docker` rebuild/repack succeeded
    (capavisor, CHV, engine, thhv/tests, all 11 Eunomia workloads, utilities).
    The container's stale apt index initially lacked pinned Noble headers;
    fetched them after `apt-get update` in a temporary Noble build container,
    then resumed the normal alias. No image/toolchain/source changes needed.
  - Built the release ISO via `scripts/build-iso.sh` inside the same build image.
    Verified packaged thhv, CHV, smoke, and timer hashes against build outputs
    before the first boot.
  - Disk still booted `6.8.0-124-generic`, whereas the current source pin and
    rebuilt thhv target `6.8.0-136-generic`; initial insmod failed with
    `module_layout` CRC mismatch. Installed Noble image/modules/modules-extra
    for **6.8.0-136** inside dom0 and rebooted. Driver now loads successfully.
  - Existing CHV checkout was `898fbf41d`, one commit behind the superproject's
    recorded `ea45eca55`; timer JSONs failed parsing `NotReport`. With explicit
    user approval, aligned the clean submodule to `ea45eca55`, then rebuilt and
    repackaged CHV with `PROFILE=release BINS_TARGETS=chv cargo build-bins-docker`.
    Repeated smoke/timer/WRMSR against that aligned binary: all passed.

  Boot configuration matches `run-qemu.sh`: KVM, host VMX, 4 CPUs/4G,
  q35 split irqchip, Intel vIOMMU interrupt remapping, UEFI, TPM CRB.
  QEMU was invoked directly against the fresh ISO to avoid rebuilding it with
  the different host nightly. SSH works with existing key authentication.
  Test VMs are shut down after use; boot normally with `cd themis && cargo themis`
  (use `PROFILE=release` to match this baseline).

  Logs: `/tmp/themis-build-20261124.log`, `/tmp/themis-iso-20261124.log`,
  `/tmp/themis-dom0-kernel-20261124.log`, `/tmp/themis-chv-rebuild-20261124.log`,
  `/tmp/themis-aligned-20261124.log`, `/tmp/themis-aligned-tests-20261124.log`.

  Next interrupt work: revisit the still-open LVT_TIMER MMIO policy question
  documented below. The original Linux dom1 interrupt hang has NOT been tested
  by the Eunomia baseline. Full Linux dom1 remains the next boot/debug target.
  At 10:21 UTC, verified the user's new `../linux` checkout: clean worktree on
  `v6.19.14-themis` at `44df971c640f`, with `config THEMIS_COCO` present.
  At 10:34 UTC, the user's `cargo build-kernel` completed: kernel **6.19.14+**,
  `CONFIG_THEMIS_COCO=y`, installed as `themis/guest/kernel/bzImage` (12 MiB).
  Verified byte-identical to `../linux/arch/x86/boot/bzImage`; SHA-256:
  `f8926f330433e318e4b785ea95c1711452dfd2881d711fb36b211a66ef7b23d1`.
  At 10:36 UTC, with dom0 shut down, packaged the new kernel into `bins.img`;
  verified `/nested/bzImage` has the same SHA-256 as the build output.
  Linux dom1 boot/debug is IN PROGRESS; the first attempt reproduced a stall
  after starting systemd. See the newer debugging handoff above.

  Files modified this session:
  - `todo.md` — verified machine/build/boot/test state and exact setup corrections.
  - Guest disk/build artifacts (ignored) — rebuilt binaries/ISO/bins and installed
    matching dom0 kernel. No implementation source edits or commits.
  CHV submodule now matches the parent; untracked `_2025/` and `testing-posted.md`
  were left untouched.

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
  the now-removed interrupt-deferral shim was NOT enabled during the hang
  (verified via build fingerprints), so the hang was inherent to reusing the full-swap path at
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
  1. **Interrupt-deferral shim: REMOVED.** Its per-core deferred-vector
     state, helpers, handlers and Cargo feature no longer exist. This
     historical audit finding is resolved, not a feature to enable.
  2. **`SwitchContext::interrupt_inject` discarded** (`hypercall/switch.rs`
     ~L242: `let _ = switch_ctx.interrupt_inject;`) — a real, tested capa-engine
     field (lazy-unwind re-injection into the true leaf on `SWITCH`-return),
     disabled by a 2026-07-30 stop-gap that says it's safe to re-enable now
     that `policy_walker` wires `InterruptVisibility` correctly. Likely the
     *correct* mechanism to route timer (and other) delivery through instead
     of the removed deferral hack.
  3. **Duplicated interrupt-injection mechanisms**: `vcpu_ext.rs`
     `inject_external_vector`, `pid.rs` `inject_via_pid`, and
     `hypercall/switch.rs` `drain_pir_inject_lowest` all implement "deliver a
     vector to a VP" independently; the `guest_can_accept_external() ? direct
     : pid-inject` idiom is copy-pasted in `msr_emulator.rs`,
     `forward_interrupt_to_handler`, and `doorbell.rs`.
  4. **Overlapping policy axes (historical finding)**: `InterruptVisibility`,
     `injectable` and `guest_can_accept_external()` interacted with the
     now-removed defer flag. The current model is documented in
     `docs/architecture/interrupt-virtualization.md`.
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
| **Interrupt Virtualization** | `docs/architecture/interrupt-virtualization.md` | Single source of truth: goals, HW background, routing model, gap analysis, historical nested-virt scheduling findings, Directvisor reference, 3 delivery bugs |
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
