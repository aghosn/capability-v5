# Inter-Domain Notification — Design Document

> **Goal**: Define a general-purpose mechanism for one domain to notify
> another that it needs attention (e.g., "I sent you a capability",
> "check your event queue").  The mechanism must work under both
> sync-switch (current) and core-gapped (future) scheduling models.

---

## 0. Direct Paravirtual Interface Plan (2026-11-24)

**Current implementation update: capability doorbells supersede the
address-matching recipes below.** Each configured PV request queue gets a
Sync endpoint owned initially by the parent and transferred to the child
through generic SEND/ACCEPT. Descriptor ABI 2 names recipient/port, not a
fake GPA or guessed handle. The guest resolves its held handle through
self-attestation and calls NOTIFY(handle, value), with no failure-to-yield
fallback. Sync reuses interrupt unwind to the blocked recipient VP.
Driver event 8 carries port/value; eventfd subscriptions do not own authority.
Ordinary MMIO/PIO matching now lives in CHV userspace. REGISTER_DOORBELL,
RING_DOORBELL, driver IOEVENTFD, event 7 and synthetic doorbell exits are
removed. Older sections below retain design history, not instructions to
restore these paths. See [current engine semantics](../capability-engine/semantics.md#doorbell-capabilities)
and [wire format](../domain-comm.md#domcomm_msg_attest--binary-attestation-report).

**Status: design reviewed; first executable channel working (2026-11-24).**
The user selected planning the direct solution rather than a temporary
MMIO/register-transfer interface. Existing standard guests must continue to
work. This section supersedes the older PCI-first bootstrap and EPT-doorbell
assumptions below for the new confidential/PV deployment profile; the older
sections remain as historical context for existing ivshmem support.

### 0.1 Goal and trust boundary

Build a Themis-native parent-child service interface:

```
declarative deployment configuration
  -> capability-backed regions + notification bindings before seal
  -> early guest discovery of an immutable deployment descriptor
  -> private parent-child shared request/reply memory
  -> doorbell / CPU return
  -> parent service implementation (initially CHV)
```

The capavisor enforces capability authority and scheduling; it does not parse
virtio or device-service payloads. Parent userspace uses thhv for all monitor
operations. Nothing depends on the parent's domain ID being zero.

The parent is an untrusted I/O provider. It sees only deliberately shared
buffers and policy-permitted metadata, not private page tables, instructions,
or a general register dump. No instruction decoding is needed on either side.
Attestation proves deployment identity, resources and permissions, not that
the provider will answer honestly or continue scheduling the guest.

### 0.2 Reuse what exists

- Memory: derive the buffer from exclusively held parent backing, ALIAS it,
  then SEND_AT the alias to the unsealed child. Retain the parent mapping.
  Existing `Capability::alias`/`send_at` and thhv wrappers are sufficient;
  no new shared-memory capability type is proposed.
- Authority transfer: existing domain/channel capabilities remain the
  authority for transferring resources. A transport "channel" below is a
  memory/notification binding, not a replacement for GET_CHAN/SEND_CHAN.
- Signaling: reuse REGISTER_DOORBELL/RING_DOORBELL and existing eventfds.
  The current RING_DOORBELL implementation already returns execution to
  the parent. Do not ring it and then unconditionally SWITCH-return again.
- Scheduling: retain synchronous parent-child CPU donation. SWITCH with
  target handle zero already expresses voluntary return in the engine.
- Discovery: reuse the Themis CPUID discovery mechanism and early
  `themis_platform_init()`, not PCI enumeration for the bootstrap channel.
- Services: reuse CHV's device implementations and Linux's virtio drivers,
  not Hyper-V's wire ABI or a new network/block protocol.

DomainComm remains domain-to-capavisor; VpCommPage remains parent-to-capavisor
register transfer. Neither is the parent-child data plane. Existing ivshmem
can continue using the same capability primitives, but the bootstrap channel
must not depend on first booting a PCI device.

### 0.3 Declarative resources

Extend the existing `comm` configuration, preserving `comm.ivshmem`.
Illustrative new fields, not accepted by today's parser:

```json
{
  "comm": {
    "regions": [
      {
        "id": "pv-control",
        "kind": "alias",
        "peer": "parent",
        "gpa": "auto",
        "size_per_vp": "0x1000",
        "rights": "RW"
      },
      {
        "id": "pv-io",
        "kind": "alias",
        "peer": "parent",
        "gpa": "auto",
        "size": "0x100000",
        "rights": "RW"
      }
    ],
    "channels": [
      {
        "id": "parent-services",
        "protocol": "themis-pv/1",
        "region": "pv-control",
        "io_region": "pv-io",
        "notification": "doorbell",
        "scheduling": "sync",
        "services": ["platform", "virtio"]
      }
    ]
  }
}
```

Keep stock CHV configuration as the source for disks, NICs, kernel, initrd
and command line. The resolved descriptor binds those device IDs to services;
do not duplicate their backend configuration in this section.

`auto` is placement, not an unspecified policy: resolve all addresses,
region sizes and device bindings before seal, record the resolved deployment,
and validate it against the declaration. Reject overlaps, overflow, ambiguous
IDs, executable shared buffers, unsupported protocol versions, and missing
or incompatible bindings before handing away private RAM. Reject conflicts
introduced by CLI/config merging rather than silently overriding them.

One logical region may span several physical capabilities; neither the JSON
nor the protocol assumes physically contiguous backing. Validate exact GPA
coverage and rights over all segments and vTOM aliases.

Current code distinction: `general.shared_regions` is parsed, but runtime
confidential splitting still uses `ThemisVmState::SHARED_REGIONS`;
`comm.ivshmem` is actually reconciled into device configuration. Do not mistake
either for an already implemented generic resource manifest.

### 0.4 Stable control protocol and CPU handoff

Start with one fixed request/reply slot per VP, not a general message broker.
Specify version, channel/session generation, sequence, service/device ID,
operation, bounded payload length, completion status and result. Payload
references are checked offsets within named shared regions, never private
guest pointers or an arbitrary physical-memory service.

```
guest publishes request with release ordering
  -> RING_DOORBELL (current sync implementation also returns to parent)
  -> thhv returns notification to CHV
  -> CHV snapshots and validates request, dispatches the named service
  -> CHV publishes correlated completion with release ordering
  -> parent SWITCHes back to child
  -> guest acquires, copies and validates reply against private request state
```

Define compiler barriers and hypercall clobbers as well as CPU memory
ordering. In particular, do not blindly reuse `raw_vmcall`'s current `nomem`
annotation for a shared-memory synchronization boundary. Prevent migration
or interrupt reentry from reusing a VP's occupied slot.

Shared sequence/state is authoritative; a doorbell is only a wakeup hint.
Handle queue-full, duplicate/stale completion, reset, invalid lengths,
unsupported operations, and revoke during an outstanding request explicitly.
Do not silently drop notifications or fabricate successful reads.
Quiesce workers and revoke mappings before unpinning/reusing backing.

For an explicit SWITCH(0) return, define thhv-visible success/return metadata
and pending-work handling. Today's `do_switch` does not build the intercept
message that `thhv_run_vp` normally expects. Also distinguish voluntary
return from cold VP initialization for register permissions:
`last_exit_reason=None` currently selects VECTOR_AVAILABLE policy.
Use existing mediated return/exit-policy mechanisms; do not make yielding
grant the parent bootstrap-level register access.

Notification-only operations can later batch requests, and independent-core
delivery can be added later. Neither is required for synchronous v1.

### 0.5 Attestable deployment, not trusted JSON

The JSON is the verifier's expected declaration, not evidence supplied by a
trusted CHV. The verifier must compare it with signed, engine-derived facts.
Names and paths do not grant authority or prove who can map a region.

Use the existing launch sequence: configure, seal, then attest the sealed
domain through the existing API. Extend its evidence and measurement
implementation; do not introduce a separate launch-finalization operation.

Before calling a deployment attestable, provide versioned evidence for:

- Applied monitor-enforced domain policy, including API permissions,
  exit/interrupt register masks and CPUID/MSR interception controls, not
  just the requested JSON. CHV-owned CPUID answers remain provider claims,
  not monitor-enforced facts; this plan does not move CPUID ownership.
- Actual memory mappings, rights, attributes, derivation/sharing information
  and endpoint relationships needed to check the declared private/shared
  boundary. Correlate both endpoints' backing, not merely equal GPAs.
- Measurements of immutable boot artifacts and the resolved bootstrap
  descriptor. Hash neither live request queues nor changing I/O buffers.
- A defined launch boundary after initial VP register setup and before first
  entry, binding required entry state, image placement and boot inputs.
  Sealing alone is not proof of the initial execution state.
- Explicit identity/version binding for the descriptor, protocol and service
  inventory. CPUID is a discovery hint checked against that evidence.

Use an exclusively transferred, guest-read-only descriptor, separate from
mutable shared memory. Make a versioned report extension without breaking
the existing DomainComm PA-map/bootstrap format.

Actual gaps found while planning:

- `StructuredAttestation` currently carries cap/address-map entries, VP count
  and API flags, but not full policy, memory content hashes or the sharing
  relationships required above. The existing signature covers its full
  serialized base; signing is not the missing part.
- HASH-on-send calls `Platform::measure_region`; its default is zero and
  `ThemisPlatform` currently has no override. Implement real measurement and
  reject unsupported measurement rather than accepting a zero placeholder.
- Establish correct handoff ordering before relying on content hashes.
  The current send helper measures while preparing the engine operation,
  before its returned mapping updates are applied. A trustworthy measurement
  must not race a sender VP that still has write access.

Keep report construction within sanctioned engine interfaces and its
snapshot/update discipline. Any missing reporting or binding interface is
an explicit design item, not an excuse to inspect trees from CHV or ad-hoc
capavisor code. Do not assume seal freezes all memory-sharing state:
policy mutation is rejected after seal, while permitted memory operations
and revocation can still change resources. Define report snapshot/lifetime
semantics and the guest's allowed dynamic-sharing envelope.

This work does not by itself establish integrity of an untrusted disk or
truthfulness of device responses. Workload identity must include its trusted
boot chain and any in-guest verification of subsequently loaded code.

### 0.6 Linux and device integration

Proposed direct device path: a built-in Themis service client plus a
`virtio-themis` transport implementing `virtio_config_ops`, paired with a CHV
transport using `VirtioDevice`/`ActivationContext`. Keep virtio-net/blk and
the backend workers; translate feature/config/status/queue setup directly,
not through simulated PCI BAR loads/stores.
Keep control requests bounded and data I/O asynchronous through virtqueues.
Queue completions use explicitly declared, policy-authorized interrupts;
cross-core delivery continues through `inject_via_pid`, not a new bypass.

Give that transport an explicit DMA/shared-buffer policy. Use the declared
I/O arena for coherent rings/descriptors and bounce streaming private
buffers as required. CHV workers receive a memory view restricted to those
shared ranges; private guest RAM is not a fallback. Merely sharing the
control page cannot make virtio data I/O work.

Early platform support is a separate required slice: the reproduced first
failure is I/O APIC access before virtio probing. Keep the current APIC mode,
timer and interrupt capability semantics for this work. Use Themis-owned
LAPIC callbacks and a narrow I/O APIC backend with semantic register/EOI
operations over the same channel, rather than a global readl/writel
interceptor. Existing I/O APIC reads have a hook; writes, EOI and the dummy
sync read need explicit coverage. Add only the missing hooks needed to
reach built-in Themis support, preserving native behavior elsewhere.

The PV device profile must not advertise PCI/ECAM paths that then require
private instruction emulation. Specify its PCI/ACPI inventory and any
remaining platform accesses explicitly. Removing legacy platform devices
entirely is not a prerequisite for the control channel; a broader no-IOAPIC
platform can be a later choice.

Unexpected EPT faults must not export private instruction bytes or silently
fall back to the current emulator. Register masks alone do not control the
unconditional instruction-byte copy in `forward_child_exit`. Remove that
unauthorized export as part of the confidential profile's acceptance work,
while preserving legitimate standard-guest behavior.

### 0.7 Milestones and acceptance

1. **Contract**: agree schema, resolved descriptor, wire ownership, handoff
   permissions, required evidence and guest platform inventory. No runtime
   code until that boundary is agreed.
2. **Declarative launch**: create declared buffers via existing capabilities,
   publish early discovery/descriptor, configure notification and policy,
   validate and seal. Include fragmented backing and launch-failure cleanup.
3. **One real round trip**: small Eunomia/libthemis guest, one VP then two,
   executes correlated requests over the final channel with no register
   payload. Test both notification and voluntary return semantics.
4. **Evidence**: implement the missing measurement/reporting contract and a
   verifier that rejects a declaration/actual-state mismatch. Channel plumbing
   may be developed alongside this, but does not count as an attestable
   deployment until it passes.
5. **Linux integration**: early I/O APIC/LAPIC support, Themis virtio transport,
   constrained DMA, block then network. No per-net/block-driver edits planned.
6. **Acceptance**: two-CPU confidential Linux, disk, authenticated SSH, clean
   shutdown/relaunch, denied private access, and unchanged standard guest.

Focused checks must cover stale/duplicate replies, invalid service/offset,
overflow and missing notification, reply mutation, concurrent VPs, revoke
during a read, unintended register/code disclosure, mismatched declared
sharing/policy/measurement, and parent access after private-memory teardown.
Batch instrumentation and boot assertions rather than iterating one log
statement per reboot.

Source anchors: `capa-engine/src/domain_api.rs:238,364,1477,1880,3005,3887`;
`capa-engine/src/attest.rs:34-82`; `capa-engine/src/platform.rs:483`;
`themis/capavisor/src/hypercall/attest.rs:49-185`;
`themis/capavisor/src/arch/x86_64/hypercall/switch.rs:55-210,365-477`;
`themis/capavisor/src/arch/x86_64/hypercall/doorbell.rs:34-107`;
`cloud-hypervisor/hypervisor/src/themis/config.rs:316-349,749-791`;
`cloud-hypervisor/hypervisor/src/themis/vm_state.rs:95-191`;
`cloud-hypervisor/vmm/src/config.rs:2862-2932`;
`cloud-hypervisor/virtio-devices/src/device.rs:56-108`;
`themis/crates/libthemis/src/lib.rs:32-73`;
`eunomia/workloads/coco/src/main.rs`;
guest Linux `include/linux/virtio_config.h:34-135` and
`arch/x86/kernel/apic/io_apic.c:245-285,390-400`.

### 0.8 Implementation contract and review gate

The user authorized fleshing out this contract, subagent design review,
implementation/testing, then independent subagent implementation review and
testing. Implement in the milestone order above, preserving a working
standard profile between milestones. Do not equate transport completion
with confidential Linux boot or verified deployment attestation.

**Launch configuration.** Keep the example's field names. V1 supports only
parent-peer ALIAS regions with RW (never executable), `themis-pv/1`, doorbell
notification and synchronous scheduling. Require exactly one of `size` and
`size_per_vp`; control regions require `size_per_vp: 4096`, while I/O regions
require fixed `size`. This keeps configuration validation independent of the
eventual VP count. Control regions use one page per created VP.
Region/channel IDs are unique, nonempty ASCII identifiers of at most 31 bytes.
Bound descriptors to 16 regions and 8 channels. Each channel references
distinct control and I/O regions, with exclusive control-slot ownership.
Reject missing, multiply owned or unused regions, unknown service names,
and any unsupported mode rather than accepting an unapplied option.

Resolve `auto` by page-aligned first fit at or above 8 GiB, considering every
pending guest-memory mapping, previously resolved region and descriptor.
All ranges must fit below the vTOM bit (and the guest physical-address limit),
be nonempty/page-aligned and have checked ends. Explicit addresses use the
same checks. Prevalidate the complete layout before the first destructive
memory handoff. Allocate independent parent userspace backing, zero it,
and register through THHV_SET_GUEST_MEMORY with ALIAS and RW rights.
Keep backing alive until domain teardown; never dereference handed-off
private descriptor memory afterward.
For the first executable gate, bound each I/O arena to 1 MiB and total PV
backing to 8 MiB (at most 2048 physical page segments). Retain the normal
driver segment preflight and META provisioning. Larger arenas require an
explicit resource-budget change, not an unchecked allocation. thhv performs
the ALIAS/SEND_AT operations internally for independent userspace backing.
The shared-DMA integration explicitly raises those ceilings to 24 MiB per
I/O arena and 32 MiB total backing; the PV/confidential Linux policies request
24 MiB after the original 1 MiB pool exhausted during rootfs boot.

**Discovery.** Reserve CPUID leaf `0x40000005`, subleaf zero:
EAX/EBX are descriptor GPA low/high, ECX is its byte size (4096), EDX is
protocol version (1). Absent channels return zeros. Reject conflicting
user/runtime overrides rather than silently replacing them. The discovery
leaf is a locator, not evidence. The descriptor is a separate CARVE,
read-only in the child, containing magic/version/length, fresh 128-bit launch
generation, VP count, region IDs/ranges/rights and channel bindings.
Use fixed little-endian records, zero reserved fields and bounded counts;
guest parsing must not cast unvalidated bytes into a trusted reference.
Signed binding to measured state belongs to milestone 4.
Subleaf 1 is Native, with EAX = the calling VP's actual index, EBX/ECX = 0,
EDX = protocol version 1. Install that exact Native policy even when the
domain's default is Trap: excluding the locator leaf from broad Native
ranges also excludes its other subleaves. A guest must not infer its slot
from domain-wide emulated CPUID APIC IDs or Linux logical CPU numbering.
Each channel also records an unmapped doorbell-key page and an exact
doorbell value. VP n uses `doorbell_base + n * 8`, registered as an 8-byte
datamatch doorbell through THHV_IOEVENTFD before seal (not ANY_VALUE).
Prevalidate the combined PV and legacy-device registrations against the
shared ABI's 128-doorbell per-domain budget before registering any PV key.
Reserve these keys against all mappings; they do not themselves map memory.
Validate descriptor/control pages before mapping them in Eunomia's explicit
above-4-GiB page-table path; do not map the whole I/O arena for a control test.
The first small-guest test uses normal GPAs; the confidential Linux gate
additionally requires consistent vTOM aliases for declared shared buffers.

**One control page per channel/VP.** Page offsets 0 and 128 hold separate
128-byte request and completion records. Each record starts with an aligned
64-bit publication sequence followed by 15 aligned 64-bit words. Both sides
access shared words atomically; there are no ordinary Rust references to
concurrently attacker-writable payloads.

Payload words encode generation[2], `(channel, VP)`, `(service, opcode)`,
device ID plus request-reserved/completion-status, six argument/result
words and four zero reserved words. IDs/opcodes/status occupy explicit
32-bit halves, not compiler-dependent enums or pointers.
Sequence starts at one, increases without wrapping, and is private state
at both endpoints. Publish payload then sequence with release ordering;
acquire sequence, copy to private storage, recheck sequence, validate, use
only that snapshot. Match completion to the outstanding sequence/session/
service/device/operation. Never overwrite an occupied request slot.

V1 control service includes negotiation/liveness. Platform and virtio use
separate service IDs. Unsupported operations complete with an explicit
unsupported status; malformed identities, bounds or framing fail the
channel, never return fabricated read data. Data references are validated
offset/length pairs into the channel's declared I/O arena.

**Early platform service.** Service 1, device 0 identifies the single
I/O APIC at `0xfec00000`. Opcodes 0/1/2/3 are register read, register write,
direct EOI and synchronization. Argument 0 is the register selector or EOI
vector; argument 1 is the 32-bit write value; all other arguments are zero.
Reads permit selectors 0--2 and 0x10--0x3f. Writes permit selector 0 and
0x10--0x3f. EOI vectors fit eight bits; synchronization takes no arguments.
Reads return one 32-bit value; other results are zero. CHV serializes each
selector/data transaction across VPs and uses the existing device bus,
never private-memory access or instruction decoding. Its registered
I/O APIC aperture includes the 32-bit EOI register at offset 0x40.
The Linux backend validates/copies the descriptor, maps only the selected
channel's per-VP control pages using permanent fixmaps and the appropriate
vTOM aliases, and installs narrow read/write/EOI/sync callbacks. Native
callbacks remain unchanged without a declared platform channel. Missing,
invalid or failed synchronous completions are fatal, not an MMIO fallback.
Virtio service and LAPIC integration are not implemented by this slice.

**Synchronous servicing.** Before resuming a VP, CHV checks its declared
slots for outstanding work, including after non-doorbell exits; eventfd
delivery is not the source of truth. Dispatch only a local request copy and
publish a correlated completion. Repeated notifications do not re-execute a
completed operation.

Successful RING_DOORBELL returns SUCCESS to the guest on resumption and
returns the CPU exactly once. Queue-full is reported, not dropped silently.
A caller may fall back to voluntary SWITCH(0) only when ringing failed.
Voluntary return gets a distinct synthetic exit, a valid intercept message,
and normal engine return validation; an invalid/root return must report an
error, not panic. Both PV synthetic exits have empty parent read/write
register masks, separate from cold-boot initialization. No payload resides
in the intercept message. Preserve existing legacy doorbell handling.
After a successful return, an absent completion is an explicit no-completion
error, never success or an unbounded spin. Server slot scans run on the
owning VP thread immediately before each RUN_VP, independent of eventfds.
Quiesce all service users before domain-fd close and keep shared mappings
alive through that close. The descriptor's post-send exclusion and child
read-only EPT rights require negative guest/parent access tests; teardown
must clean private contents before any permitted parent reuse.

**First executable acceptance boundary.** A small Eunomia guest discovers
the descriptor and completes correlated requests through CHV and thhv using
real ALIAS/SEND_AT mappings, including successive requests and voluntary
return. Hosted tests cover malformed descriptors/requests, sequence and
generation mismatch, overflow/overlap, duplicate notifications, unavailable
completion and independent VP slots. Build ABI/libthemis, CHV, driver and
capavisor; run the small guest before claiming the channel works.

**Later gates remain mandatory.** Linux needs early platform/APIC coverage,
device discovery, virtio setup plus shared DMA and authorized completion
interrupts. Attestable deployment additionally needs real measurements,
correct measurement-handoff ordering and applied-state evidence through the
existing post-seal attestation API, not just protocol metadata.

Design review completed with conditional approval: B1--B7 cover doorbell
return status, reason-tagged voluntary return, compiler ordering, registered
doorbell discovery, explicit R/RW mapping rights, bounded high-GPA
allocation/teardown/vTOM treatment, and completion/liveness checks. They are
mandatory implementation/acceptance items above, not deferred suggestions.

**Executed first-gate checks (2026-11-24).** ABI unit/doc tests and CHV
configuration/policy/mmap-backed two-VP slot tests pass. Full release
capavisor/driver/CHV/Eunomia build and image packaging pass. A live Eunomia
guest completes eight successive requests, alternating doorbell and
voluntary return, and teardown/relaunch passes. A two-created-VP launch also
passes, but this workload exercises only the bootstrap CPU; actual concurrent
guest-VP requests remain unverified. Standard Linux regression confirms
kernel `6.19.14+`, two online CPUs, root disk, network/SSH and clean shutdown.
Independent implementation review reran host tests and the guest build;
its doorbell-budget finding is addressed by launch prevalidation.
Descriptor/parent permission-denial tests, confidential Linux, constrained
DMA/virtio, private-instruction-export prevention and real attestation remain
open gates, not inferred successes. Existing CHV Clippy baseline remains
failing with 50 pre-existing findings; new-module findings were fixed.

**Executed Linux I/O APIC slice (2026-11-24).** The built-in Linux client and
CHV semantic platform dispatcher negotiate the declared channel and
initialize the I/O APIC in a confidential guest. Native VP identity,
confidential shared aliases and the full I/O APIC EOI bus aperture are
implemented. Independent review/tests pass: 41 CHV tests, one real I/O APIC
bus/EOI test and seven mocked notification cases. ABI has 12 unit plus two
doc tests and passes strict Clippy; Linux checkpatch is clean. Full kernel,
release stack and packaged-image builds pass. Standard Linux on the final
build passes two CPUs, disk, network/password SSH and clean shutdown.

An exploratory confidential run reached two CPUs and a later private
page-table fault, but still used legacy LAPIC instruction decoding. That is
not confidential acceptance. Final CHV rejects confidential EPT/MMIO
exits before either legacy decoder. Its final live run initializes the
channel and I/O APIC, then explicitly stops at LAPIC GPA `0xfee000f0`,
without reading private page tables or crashing the parent. Orderly CHV
exit does not mean the guest booted successfully. The next platform slice
must provide semantic per-VP LAPIC access; do not bypass the guard.
Capavisor private-instruction export, direct virtio/shared DMA, actual
concurrent guest-VP requests, negative-access tests and existing-API
post-seal attestation remain open. The Linux base-signature correction also
enabled existing virtio fast notifications; these now retry bounded busy
failures and report errors rather than silently dropping queue kicks.

### 0.9 Capability-boundary remediation proposal (2026-11-24)

**Status: approved; scoped VP policy, initial hardware-boundary fixes and
engine-owned VP hardware handoff implemented and independently reviewed/tested.
Notification transactions, backing and post-seal evidence remain in progress.**
The audit above exposed inherited engine/platform boundary problems. Fix those
boundaries before adding more Linux device services. This proposal supersedes
the first-gate shortcuts where explicitly stated, not the existing
configure -> seal -> attest sequence.

**Policy scope.** Introduce a typed domain-default/VP policy target in the
engine, with explicitly inheriting VP overrides. CPU identity/CPUID, MSR
interposition, exit routing/register disclosure and CPU-local interrupt
visibility/register access are execution policy. Memory/device ownership,
monitor API authority and the domain's physical-core envelope remain domain
authority. VP overrides cannot enlarge that envelope or grant resources.
Keep interrupt ownership/injection authority separate from delivery visibility.
Validate scope, VP existence, caller rights and seal status inside the engine.
Domain-default updates must not overwrite explicit VP overrides; an absent VP
override must continue inheriting subsequent domain-default updates.
An override replaces an explicitly selected execution-policy category, not
unrelated categories. Policy configuration remains pre-seal only. Create the
VP before configuring its overrides; clearing an override restores inheritance.

Mutable emulated MSR values are VP runtime state, not edits to sealed policy.
Keep initial values in policy/evidence and resolve reads/writes against the
actual running VP. CHV must submit every VP's CPUID table, including topology
and APIC identity, rather than copying the first table into a domain-wide
answer. The existing Native current-VP discovery leaf remains an explicitly
authorized discovery primitive, not a substitute for correct CPUID topology.
Use scoped engine updates and per-VP hardware interception state where policies
can differ. Extend the ABI/driver with a typed scoped operation, preserving
existing domain-default calls and full-width capability handles.

**Physical I/O.** Remove the COM1-only interception workaround. Derive each
VP's hardware I/O interception from its effective engine policy at creation,
policy update and seal. A forwarded access must actually trap; unsupported
native device access must be rejected explicitly rather than quietly enabled.
Do not introduce a replacement port whitelist in monitor code. Keep EOI-exit
bitmaps zero.

**Exit disclosure and denied accesses.** Remove the monitor's unconditional
private instruction/page-table read and instruction-byte export. Standard CHV
may fetch instructions only through its own capability-backed memory view
and policy-authorized register reads. Confidential CHV retains the no-decoder
guard and semantic shared requests. Mandatory exit metadata and register masks
must come from the effective VP policy; synthetic returns grant no general
register access. A locally handled denied EPT access must produce an explicit
architectural failure, without advancing RIP or fabricating a completed load,
regardless of guest CPL.
Use #GP(0) for a locally denied EPT access at every CPL, preserving the existing
recoverable user-mode denial semantics. Do not unconditionally forward faults
to the parent when the engine policy selected local handling: that would add
disclosure outside the configured exit policy.

**Notifications.** Move binding identity, match rules, endpoint authority,
budget and inventory into the engine. Registration requires authorized child
access and an unsealed child; seal freezes new bindings and retargeting.
Revocation/removal may reduce authority afterward without reusing identities.
Keep mutable Linux eventfd subscriptions separate from the sealed authorization.
Both explicit rings and any retained legacy trigger must use engine-owned
authorization, not a platform lookup that merely happens under an engine lock.

For synchronous delivery, validate the running source VP, binding, destination
and return-chain state before any externally visible notification. Delivery
and the single CPU return form one mediated transaction. Queue-full or invalid
return must leave both the queue and VP scheduling state unchanged. Keep queue
reservation/commit and update ordering explicit; no fallible post-enqueue
validation, no nested execute(), and no callback that independently decides
authority. Serialize removal/revoke with delivery and test those races.
Removal takes the existing exclusive operation lock; rings use the shared
operation lock and the destination queue's producer lock. Split return handling
into validation and an infallible commit, with the validated source/return
state protected until commit. Check queue capacity under the producer lock
after validation. A full queue returns ERR_BUSY without committing a return or
publishing an entry. Previously queued notifications may drain after removal;
never reuse binding IDs, and let unsubscribed consumers ignore stale entries.
Keep existing legacy notification triggers only by routing them through this
same engine-owned authorization, not by maintaining a second implementation.

Follow-up implementation review found that a shared operation lock alone
cannot protect the hardware handoff: a source VP marked Available can be
claimed on another core before its hardware slot is released. Keep the source
Running and its parent Locked until the hardware handoff releases ownership,
then publish the scheduling transition. The engine should invoke Platform
save/handoff callbacks as needed to own this ordering; do not introduce a
Returning state or globally serialize returns merely to compensate for early
publication. Capability validation still precedes every hardware change.

The handoff foundation is implemented via `Platform::handoff_vp`: the engine
selects call/return/interrupt work, explicit endpoints and disclosure masks,
then invokes hardware completion under its shared operation lock. Ordinary
returns preserve Running/Locked through hardware completion; interrupt
unwinds preserve the complete active chain until then. Forward calls reserve
the target Running and source Locked, and complete hardware before releasing
the operation lock. The callback never resumes a guest or re-enters engine
operations. Return preparation validates the current binding and the complete
Locked caller chain; interrupt preparation validates its owning core and each
callee link before any mutation. Local Deliver does not swap hardware.
Paused-callback real-thread tests and Loom exercise competing claims during
the save window. The notification transaction now reuses this prepared-return
path, as described below.

Validation correction: dom1's explicit confidential profile replaces the
whole `policies` section, so omitting `exits` had restored ALL masks despite
the built-in confidential profile's NONE defaults. The explicit profile now
declares NONE, with a failing-before/passing-after resolved-profile test.
The actual NONE-mask live run stops at its first forwarded CPUID, before
Linux console or the earlier PV LAPIC guard. A disposable, explicitly
CPUID-authorized diagnostic confirms the first request is leaf 0 with
nonzero ECX: the submitted table uses exact subleaf matching even for
non-indexed leaves. Generic emulated ranges/index semantics are required;
broadening production register masks or silently using host CPUID is not a
substitute. Standard two-CPU Linux and the live PV suite pass the handoff.

The approved CPUID follow-up exposes generic exact emulated ranges through
the normal domain-mediated policy setter (CPUID and MSR, with optional VP
scope). Wire selectors preserve full-width endpoints and result words;
word selection is independent of VP selection. Non-indexed CHV entries
cover all ECX values; indexed entries retain explicit answers and zero
gap/tail ranges. Configured points take precedence through non-overlapping
splits, not implicit widening. Native table production supplies explicit
index flags; unknown or ambiguous metadata is rejected. CHV also emits the
configured CPUID default instead of silently retaining Trap. No confidential
register masks or capability rights are broadened. Independent review, full
plain/translated engine and Loom suites, ABI/CHV tests, release CLI and full
release stack/package pass. Live PV and two-CPU standard Linux
(SSH/root/network/clean shutdown) pass. Actual NONE-mask confidential Linux
now gets past CPUID and fails at a later CR_ACCESS exit: CHV's register read
is denied with EPERM as required. The profile defaults to parent trapping;
an explicit local-vs-parent CR policy remains to be resolved, not a broader
register mask. This is not a full confidential boot or proof of reaching
the PV LAPIC guard. The parent test VM was shut down cleanly.

On 2026-11-25, dom1's confidential profile explicitly selects local
CR_ACCESS handling through the existing engine exit policy, retaining NONE
read/write masks and the default parent-trap policy. A failing-before/
passing-after policy-stream regression, all 49 CHV Themis tests and full
release stack/package pass. The strict live run clears CR_ACCESS and reaches
port I/O, but cannot exchange its operands/replies with CHV under NONE
masks. A separate disposable diagnostic authorized only I/O-exit RAX through
capa; Linux then initializes the two-VP PV channel and reaches the known
missing-PV-LAPIC guard at 0xfee000f0. Production masks were not widened.
This diagnostic is not a production solution: byte/word OUT must not expose
unrelated upper RAX bits, and byte/word IN must not authorize whole-register
replacement. An operand-only capability-mediated I/O/PV path and explicit
failure for ineffective unauthorized emulation remain to be designed.
Live PV still passes; parent was shut down cleanly and disk preserved.

Prepare the return only after
draining pending core updates, then perform no hardware/platform-lock work
inside the queue's infallible state-commit callback. Complete hardware handoff
under the operation lock after releasing the queue producer lock.

Prevalidate all ring write extents and capacity, including page/ring wraps,
before any publication; the former padding recursion did not preserve the
unchanged-on-full guarantee. Cursor occupancy/advancement uses u32 wrapping
arithmetic. All driver RX consumers must share a serialization/dispatch
protocol. Recipient-global non-reused binding IDs let that dispatcher route
notifications from any child independently of which VP drained the queue.
Linux eventfd subscriptions are mutable and detached separately from fixed
bindings; use an exact existing-binding lookup for sealed reattachment.
Match subscription identity precisely and ignore unsubscribed stale IDs.
Since explicit RING supplies only key/value, do not accept ambiguously
overlapping rules distinguished only by access size or PIO/MMIO namespace.
Canonicalize ignored wildcard fields and validate raw arguments before casts.

**Notification implementation (2026-11-25).** Bindings now live in the source
domain's engine-owned state. SET plus direct child ownership authorizes
pre-seal registration; GET permits exact lookup after seal. Removal takes
the exclusive operation lock and IDs are allocated monotonically per
recipient, not per child. Attestation snapshots that same inventory into a
flagged extension: the 40-byte header's former reserved word is the count,
and 40-byte binding entries follow the PA map, before the signed envelope.
The existing signature therefore covers IDs, recipient and match rules.
No independent peer/provenance model or new attestation operation is added.
The [engine reference](../capability-engine/semantics.md#notification-bindings-doorbells)
documents the concrete types, storage and lifecycle; the
[DomainComm reference](../domain-comm.md#domcomm_msg_attest--binary-attestation-report)
documents the notification entry offsets and signed layout.

`notify_return` validates the binding and complete caller chain, then asks
the platform to publish the entry and invoke the infallible prepared return.
The platform prevalidates capacity and both backing pointers before writing,
publishes the head once, drops the recipient producer lock, then commits the
hardware return under the engine lock. No monitor-owned binding table remains.
DomainComm 1.0 uses power-of-two logical capacity to preserve u32 rollover
offsets; RX messages may cross pages. Older driver/monitor major versions
are intentionally incompatible. Driver RX consumers share one lock and
dispatch interleaved notifications; global subscription routing uses the
recipient-global IDs, with exact eventfd lifecycle checks.

Live validation also exposed the old all-chunks attestation enqueue exhausting
the child's RX ring. Offset zero now retains one engine-derived report
snapshot; each call publishes only one chunk, and subsequent offsets read
the same bytes, including any signed/TPM tail. The driver consumes the whole
report even for a short user buffer and does not consume another signing
request for continuations. This is report-transport state, not capability
authority or a new launch-finalization state.

Plain/translated engine tests, all five Loom suites, ABI tests, release CLI
and full stack builds pass. Independent implementation review found driver
locking/registry and version-compatibility issues; those were corrected and
follow-up review found no significant issues. Live subscription lifecycle
and authority-freeze checks pass; one- and two-created-VP PV launches verify
their actual attested bindings and eight alternating ring/yield requests.
These guest requests still execute only on the BSP, not concurrently on APs.
Live Ed25519 verification passes, including a multi-chunk report with a valid
TPM RSA signature while standard Linux is running. This does not complete
effective-policy/artifact evidence, negative-access acceptance or confidential
Linux device support. Short-buffer signed retrieval drains all chunks and
the next full signed report verifies. A simultaneous-child live probe is
not accepted as a notification result: one child completes, but the other
fails before execution at deferred SET_GUEST_MEMORY with EEXIST. Exact backing
ownership/setup remains a prerequisite to that coverage.
The final standard two-CPU Linux regression passes authenticated SSH, root
disk and gateway checks, and clean shutdown. The parent test VM is shut down
and its newest child disk preserved.

**Faithful mappings.** Eliminate the LAPIC ChangeRights special case, including
its ignored unmaps. Child VMCSes do not use the legacy APIC-access-page
allocation; remove that obsolete driver/CHV provisioning rather than pretending
it is a normal memory transfer. Accepted ordinary mappings and unmaps must be
materialized exactly in EPT and mirrored IOMMU tables. If an architectural
reservation is actually required, reject conflicting mappings before the
engine commits instead of silently overriding a successful operation.

**Shared backing and declarations.** Introduce explicit driver backing
ownership, separate from an individual GPA mapping: pin once, derive an
owned backing capability, then create the declared RW/NX aliases from
that exact capability. Reuse it for low/vTOM mappings instead of rediscovering
a broad parent handle and carving twice. A dedicated carve may group backing
ownership and revocation, but carving an Alias inherits its Aliased status;
it does not establish exclusive provenance. A requested private handoff must
verify that existing derivation facts actually establish exclusivity, and fail
otherwise. Do not prohibit ordinary alias transfers. Track partial failure,
mapping refs, revoke and pin lifetime; revoke before unpin/reuse.

Shared-memory peers are selected by sending them aliases. Existing capability
operations and ownership are the complete authority model; do not introduce
peer lists, allowed-peer constraints or a second sharing-policy mechanism.
A backing capability establishes the derivation boundary, and ALIAS/SEND_AT
establishes each recipient's access. Derive sharing from the capabilities and
their ownership; no separate sharing-provenance field or model is required
for this work. Further authorized delegation remains governed
by the same capability operations, not a promise of permanent pair-only access.

Replace the implicit firmware exception with declared, validated shared ranges
and exact rights; do not silently add RWX aliases. Confidential ordinary exits
and interrupt states default to empty parent register masks. Configure only
the explicit register access needed for initial setup and any supported
semantic exits, and verify isolation after first entry/return.
The engine freezes pending VP initialization at seal, before publishing the
sealed state. Later COMM captures merge only runtime-authorized writes into
that private snapshot; neither empty masks nor forbidden shared-memory
changes can discard or replace frozen setup. First entry has no post-seal
initialization privilege exception.

**Evidence and completion.** Extend the existing post-seal report, preserving
its bootstrap PA-map format, with versioned effective domain/VP policy,
notification inventory. Sharing is derived from capability state and ownership,
not a separate provenance extension. Distinguish
fixed authorization from mutable runtime state and snapshot facts. Real
immutable-artifact hashes require withdrawing all CPU/DMA writers before
measurement and publishing the transfer only afterward; unsupported
measurement must fail rather than report a zero hash. Do not claim attestable
deployment until this measurement/evidence gate passes.

Implement and validate in dependency order: scoped execution policy/state;
hardware projection/disclosure/fault correctness; engine notifications;
backing ownership and explicit CHV declarations; post-seal
evidence. Each stage needs focused negative tests and preserved standard-guest
behavior. Run engine tests with/without address_translation, relevant Loom
races, capa-cli release build, full bins build, independent implementation
review/testing, then batched live standard/PV/confidential negative-access
checks. A confidential stop at the still-unimplemented PV LAPIC service is
not full guest boot, and fixing these boundaries does not implement virtio.

Independent design review: `150e4da5-2966-444e-8f1e-85f2d38ecc14`.
The reviewer evaluated the proposal and supplied findings, not a second source
audit. Incorporated concrete policy lifetime/resolution and notification lock/
commit rules. The user's correction rejects both allowed-peer policies and
delegation-right stripping. Prefer uniform #GP denial over the reviewer's
suggested unconditional parent fault report, which would bypass configured
disclosure and cannot cover a caller without a parent. Do not introduce the
suggested IOMMU MSI-window skip: A4 requires faithful EPT/IOMMU projection;
removing unused dummy LAPIC provisioning does not authorize an exception.
Full measurement ordering and versioned evidence remain the explicit final
attestation milestone; no stage before that may claim attestable deployment.

---

## 1. Problem Statement

Today, when a child domain sends a capability to its parent (via
`CHANNEL_SEND`), there is no way for the child to signal "hey, I sent
you something — come look."  The parent only discovers pending
capabilities when it happens to poll, or when the child exits for an
unrelated reason (I/O, CPUID, etc.) and the parent checks.

More generally, inter-domain communication needs a **signaling
mechanism** (doorbell) separate from the **data plane** (shared memory
ring / pending capability queue).  This separation is a well-established
pattern (Hyper-V SynIC, virtio notification, ioeventfd).

### Requirements

1. **Decoupled from exit path**: notification is an explicit action by
   the sender, not a side-effect of a VMEXIT.
2. **Works same-core (sync-switch)**: child triggers notification →
   parent sees it when it resumes on the same core.
3. **Works cross-core (core-gapped)**: child triggers notification →
   IPI kicks parent on its core.
4. **Batched**: multiple messages can be enqueued before a single
   doorbell ring.
5. **Discoverable**: child learns notification parameters (doorbell
   GPA, shared region GPA) through a synthetic CPUID leaf.
6. **Dual trigger**: the child can ring the doorbell via either an
   MMIO write (EPT fault) or a VMCALL — both land in the same
   capavisor handler.

---

## 2. Existing Infrastructure

### 2.1 IOEVENTFD Doorbell (guest → VMM, already implemented)

The existing ioeventfd mechanism provides guest→VMM notification for
virtio devices:

```
Guest writes to doorbell GPA
  → EPT violation in capavisor
  → handle_ept_doorbell matches GPA
  → writes DoorbellNotify to parent DomainComm RX ring
  → advances child RIP, resumes child immediately
  → thhv drains DomainComm RX ring after switch returns
  → eventfd_signal wakes VMM worker thread
```

This works but is **device-specific** (registered per-GPA by the VMM)
and uses **EPT violations** as the trap mechanism.  It is not suitable
for general inter-domain signaling because:
- Requires a registered GPA per doorbell (VMM provisioning)
- Tied to the DomainComm RX ring (dom0-specific structure)
- Not accessible to child domains that don't have a VMM

However, the EPT-fault-on-known-GPA pattern is exactly right for the
general doorbell.  We generalize it.

### 2.2 DomainComm RX/TX Rings

Each domain has a DomainComm region (header + RX + TX pages).  The
capavisor writes messages to the RX ring (attestation reports, doorbell
notifications).  This is the capavisor-managed data plane — it carries
structured messages but has no built-in signaling and requires
capavisor involvement on every message.

### 2.3 Core-Gapping Shared Notification Area (designed, not yet built)

The core-gapping design doc (§5) describes a shared notification area
for forwarded events: event info written to a shared page, IPI sent as
doorbell.  This is conceptually the same pattern we need here.

### 2.4 Interrupt Injection (IRQFD path)

The existing `INJECT_INTERRUPT` hypercall + Posted Interrupt Descriptor
path lets dom0 inject interrupts into a child.  The reverse direction
(child → parent notification) is what we need to add.

---

## 3. Design

### 3.1 Two Planes, Two Triggers

The design cleanly separates **data plane** from **signaling plane**,
and provides two interchangeable **trigger mechanisms** that both
converge into a single capavisor handler.

```
                    ┌─────────────────────────────┐
                    │      DATA PLANE              │
                    │  Private shared memory        │
                    │  (parent ↔ child, direct)     │
                    │  No capavisor involvement     │
                    └──────────────┬──────────────┘
                                   │ child writes message(s)
                                   ▼
    ┌──────────────────────────────────────────────────────┐
    │              SIGNALING PLANE                         │
    │                                                      │
    │   Trigger A: MMIO write         Trigger B: VMCALL    │
    │   Child stores to doorbell GPA  Child calls          │
    │   → EPT violation               VMCALL_NOTIFY_PARENT│
    │           │                              │           │
    │           └──────────┬───────────────────┘           │
    │                      ▼                               │
    │            handle_doorbell(domain, reason)            │
    │                      │                               │
    │            ┌─────────┴──────────┐                    │
    │            ▼                    ▼                    │
    │       sync-switch          core-gapped               │
    │       return to parent     IPI to parent core        │
    └──────────────────────────────────────────────────────┘
```

### 3.2 Shared Region (Data Plane)

The data plane is a **capability-backed ivshmem device** (see §4).
Each `--ivshmem` flag creates an ivshmem PCI device whose BAR2 is
the shared memory region.  Both parent and child access it directly —
**no capavisor involvement** on the data path.

- The child writes structured messages (e.g., "I sent capability X on
  channel Y") directly to BAR2.
- The parent reads them directly via its own mapping of the same
  backing pages.
- The capavisor is only involved for the doorbell signal (BAR0 / VMCALL).
- Linux guests discover BAR2 via PCI enumeration (zero changes).
- Eunomia maps BAR2 explicitly at boot (see §4.6).

The shared region layout (producer/consumer indices, message ring) is
defined in `themis-abi` so both sides agree on the format.

### 3.3 Doorbell Triggers (Signaling Plane)

The child can ring the doorbell via two interchangeable mechanisms.
Both cause a VMEXIT that lands in the same capavisor handler:
`handle_doorbell(domain_id, reason)`.

#### Trigger A: MMIO Write (EPT Fault)

The doorbell GPA is an **intentionally unmapped page** in the child's
EPT.  Any write to it causes an EPT violation.  The capavisor's EPT
violation handler checks the faulting GPA against the domain's
registered doorbell GPA:

```
EPT fault on GPA X:
  1. Is X == domain.doorbell_gpa?  → handle_doorbell(domain, reason)
  2. Is X a registered ioeventfd?  → handle_ept_doorbell() (existing)
  3. Otherwise                     → forward as normal EPT violation
```

The reason code can be encoded in the write value (the data the child
was trying to store), or in a register (RAX/RDI at fault time).

**Pros**: simple from child's perspective — a plain memory store.
No special instruction needed, works from any context (kernel, user).

#### Trigger B: VMCALL

A new hypercall `VMCALL_NOTIFY_PARENT`:

```
Input:
  RAX = VMCALL_NOTIFY_PARENT (hypercall number)
  RDI = reason code

Output:
  RAX = 0 (success) or error code
```

**Pros**: explicit, carries a clean reason code in registers, no
EPT plumbing needed.  Useful for paravirtualized guests that already
use VMCALL for other Themis hypercalls.

#### Shared Handler

Both triggers converge in:

```rust
fn handle_doorbell(domain_id: DomainId, reason: u32) {
    // 1. Look up parent domain
    // 2. Decide action based on scheduling mode:
    match scheduling_mode {
        Sync => {
            // Return to parent with exit_reason = DOORBELL
            // Parent sees reason code in intercept message
            switch_return_to_parent(domain_id, EXIT_REASON_DOORBELL, reason);
        }
        CoreGapped => {
            // Write event to shared notification area
            // Send IPI to parent's core
            write_notification(parent_core, domain_id, reason);
            send_ipi(parent_core, doorbell_vector);
            // Resume child immediately
        }
    }
}
```

### 3.4 Discovery

**Linux guests**: Standard PCI enumeration discovers ivshmem devices
automatically (vendor `0x1AF4`, device `0x1110`).  BAR0 = doorbell
registers, BAR2 = shared data region.  No synthetic CPUID leaf needed.

**Eunomia**: Doesn't do PCI enumeration.  Discovers ivshmem BAR GPAs
via CPUID leaf `0x40000004` (extending the existing Themis convention:
`0x40000000` = signature, `0x40000001` = version, `0x40000002` =
DomainComm, `0x40000003` = limits):

```
CPUID leaf 0x40000004, subleaf N  (N = ivshmem device index)

EAX = BAR0 GPA (32-bit MMIO)   — doorbell registers
EBX = number of ivshmem devices (same in every subleaf)
ECX = BAR2 GPA (low 32 bits)   — shared data region
EDX = BAR2 GPA (high 32 bits)
```

CHV pushes these as Emulate CPUID overrides via SET_POLICY (same
mechanism as CoCo detection leaf `0x40000100`).  The capavisor
serves the pushed values on CPUID exit — no new capavisor code
needed for this leaf.

BAR2 GPAs (shared data regions) are also discoverable via the
attestation report — each ivshmem memory cap appears with its GPA.
Eunomia calls `ATTEST_SELF`, parses the report, and maps accordingly
(see §4.6).

### 3.5 Sync-Switch Integration

In sync-switch mode, ringing the doorbell causes an **eager return**
to the parent — the doorbell IS the exit reason.

```
Child rings doorbell (MMIO write or VMCALL)
  → VMEXIT to capavisor
  → handle_doorbell: switch_return_to_parent(EXIT_REASON_DOORBELL)
  → Parent resumes from SWITCH
  → Parent sees exit_reason = DOORBELL in intercept message
  → Parent reads shared region for message details
  → Parent processes notification (e.g., accepts pending capability)
  → Parent re-SWITCHes to child
```

This is simple and correct.  The cost is one context switch per
notification, which is acceptable for the current sync model.

**Future optimization (deferred delivery)**: the capavisor could
instead set a flag and resume the child, letting the parent discover
the notification on its next drain cycle.  This avoids the context
switch but requires a polling or timer mechanism.

### 3.6 Core-Gapped Integration

In core-gapped mode, the doorbell becomes an IPI:

1. Capavisor on child's core calls `handle_doorbell`.
2. Writes event metadata to the shared notification area (already
   described in `core-gapping.md` §5).
3. Sends IPI to parent's core.
4. Resumes child immediately (VMRESUME) — no context switch.
5. Parent's ISR fires, reads shared notification area, wakes handler.

This reuses the same infrastructure planned for core-gapping's
`Forward` policy.

---

## 4. Capability-Backed ivshmem (`--ivshmem` Extension)

The doorbell's data plane requires a shared memory region between
parent and child.  Rather than building a one-off mechanism, we extend
CHV's existing **`--ivshmem`** flag to support capability-backed shared
memory with a rendezvous protocol.  Each `--ivshmem` instance creates
a standard ivshmem PCI device, so guests discover shared regions
automatically via PCI enumeration — zero guest kernel changes for
Linux VMs (Eunomia needs explicit page table mapping at boot).

This primitive serves multiple use cases beyond the doorbell:
- **Dom0 ↔ dom1 communication** (doorbell ring, event queues)
- **Extra shared memory with a confidential child** (bounce buffers)
- **CVM ↔ CVM private channels** (no dom0 access)
- **Multiple ivshmem devices per VM** (one per `--ivshmem` flag)

### 4.1 CLI Interface

We extend the existing `--ivshmem` flag with optional `mode` and
`count` parameters.  Multiple `--ivshmem` flags are allowed — each
creates a separate ivshmem PCI device on the guest's PCI bus.

```
# Vanilla (existing, unchanged):
--ivshmem path=/tmp/file,size=1M

# Capability-backed (new):
--ivshmem path=/tmp/doorbell,size=4K,mode=alias,count=1
--ivshmem path=/tmp/vm-shared,size=2M,mode=plug
```

| Parameter | Description |
|-----------|-------------|
| `path`    | Filesystem path identifying the region (rendezvous key) |
| `size`    | Region size (must be power of 2, ivshmem spec requirement) |
| `mode`    | `alias`, `carve`, or `plug` (default: vanilla file-backed) |
| `count`   | (creator only) How many additional domains may plug in |

**Modes**:

- **`alias`** (creator): thhv allocates backing pages, creates a memory
  cap, aliases it (creator **keeps** access), then holds `count` extra
  aliases for future pluggers.  Used when dom0 needs to see the shared
  region (doorbell, bounce buffers).

- **`carve`** (creator): same allocation, but thhv carves the region
  out (creator **loses** access).  The carved cap is sent to the
  creator's child domain.  thhv holds `count` aliases of the carved
  cap for future pluggers.  Used for CVM↔CVM private channels where
  dom0 must not see the data.

- **`plug`** (subsequent VMs): thhv looks up the path in its
  rendezvous table, finds the pre-created aliases, sends one to the
  plugging VM's domain.  Decrements the available count.  Fails if
  count is exhausted.

- **(no mode)**: vanilla file-backed ivshmem (existing behavior,
  unchanged).

### 4.2 Multiple ivshmem Devices

CHV currently supports a single ivshmem device (`ivshmem_device:
Option<...>`, hardcoded name `"__ivshmem"`).  We extend this to
support multiple instances:

- `ivshmem_device: Option<...>` → `ivshmem_devices: Vec<...>`
- Each device gets a unique PCI BDF (bus/device/function) and name
  (`__ivshmem_0`, `__ivshmem_1`, ...).
- The guest distinguishes devices by PCI slot or by reading the
  ivshmem peer ID register (BAR0 offset 0x04).

### 4.3 GPA Placement

ivshmem BAR2 (the shared memory region) is placed in **PCI MMIO
address space**, not in the guest's RAM region:

```
GPA layout (x86-64):
  0x0000_0000 .. 0xC000_0000   RAM (up to 3GB below the MMIO hole)
  0xC000_0000 .. 0xFFFF_FFFF   PCI MMIO hole (32-bit BARs)
  0x1_0000_0000 ..             RAM continues (above 4GB)
                               64-bit BARs also allocated here
```

BAR assignment is handled automatically by CHV's PCI allocator — no
manual GPA needed in the `--ivshmem` flag.  The guest discovers the
BAR address through standard PCI configuration space reads.

This means `--memory size=2G` + `--ivshmem ...,size=1G` gives the
guest 2GB RAM + 1GB ivshmem at a PCI BAR address — they don't
overlap.

### 4.4 Capability Flow

```
Creator (alias mode, count=2):
  1. CHV mmaps backing pages → gets UA (user address)
  2. CHV passes UA + size + path + mode to thhv via ioctl
  3. thhv pins pages, finds parent cap covering HPA, carves a sub-cap
  4. thhv aliases sub-cap → alias_0 (sent to creator's domain)
  5. thhv aliases sub-cap → alias_1 (held for plugger 1)
  6. thhv aliases sub-cap → alias_2 (held for plugger 2)
  7. thhv registers (path → { backing_cap, [alias_1, alias_2] })

Creator (carve mode, count=2):
  1. CHV mmaps backing pages → gets UA
  2. CHV passes UA + size + path + mode to thhv via ioctl
  3. thhv pins pages, finds parent cap covering HPA, carves a sub-cap
  4. thhv creates count aliases of sub-cap BEFORE sending carve
  5. thhv carves sub-cap → carved_0 (sent to creator's domain)
     (creator no longer has access to the backing pages)
  6. thhv registers (path → { carved_0, [alias_1, alias_2] })

Plugger:
  1. CHV passes path to thhv via ioctl
  2. thhv looks up path → retrieves next available alias
  3. thhv sends alias to plugger's domain (maps into EPT)
  4. CHV presents as ivshmem PCI device (BAR2 at the mapped GPA)
  5. Decrements remaining count
```

### 4.5 Lifetime and Revocation

The creator's domain holds the **root cap** for the shared region
(either the alias or the carve).  Revocation cascades naturally through
the capability engine's CDT:

- If the creator's domain is revoked → all aliases (including those
  held by pluggers) are automatically revoked.  The ivshmem PCI device
  in plugger VMs effectively disappears (BAR2 unmapped from EPT).
- If a single plugger's domain is revoked → only that plugger's alias
  is revoked.  Other pluggers and the creator are unaffected.

This gives clean lifetime semantics with no manual cleanup.

### 4.6 Guest Discovery

**Linux VMs**: Standard PCI enumeration discovers each ivshmem device
automatically.  The guest uses `uio_pci_generic` or a custom ivshmem
driver (vendor `0x1AF4`, device `0x1110`) to map BAR2 and access the
shared region.  No guest kernel changes needed.

**Eunomia**: Eunomia is a bare-metal workload without PCI enumeration.
It needs to explicitly map the ivshmem BAR2 GPA in its page tables at
boot.  Two approaches:

- **CPUID discovery**: the capavisor reports ivshmem BAR GPAs via a
  synthetic CPUID leaf (`0x40000004`), pushed by CHV as Emulate
  overrides via SET_POLICY.  Eunomia reads CPUID at boot, maps the
  reported GPA range into its page tables.
- **Attestation report**: the ivshmem region appears in the domain's
  attestation report as a memory capability with its GPA.  Eunomia
  calls `ATTEST_SELF`, parses the report, and maps accordingly.

Either way, Eunomia needs a small boot-time routine to identity-map
the BAR2 GPA range (it's in PCI MMIO space, not in the e820 RAM
region, so it won't be covered by Eunomia's default RAM mapping).

### 4.7 Doorbell via ivshmem BAR0

The ivshmem spec defines an optional **doorbell register** in BAR0
(register 3, offset 0x0C).  Writing to it signals the peer.  We wire
this to the capavisor's doorbell handler:

1. BAR0 is MMIO-trapped (handled by CHV device emulation / capavisor).
2. Guest writes to BAR0 doorbell register → MMIO exit.
3. Capavisor recognizes it as an ivshmem doorbell for this domain →
   `handle_doorbell()`.

This gives us doorbell signaling that's 100% compatible with the
ivshmem spec.  No custom GPA or synthetic mechanism needed — the
guest just uses the standard ivshmem doorbell register.

For **Phase 1** (simplest path), we can alternatively use a dedicated
unmapped GPA as the doorbell (CPUID-discoverable), and wire the
ivshmem BAR0 doorbell later for full spec compliance.

### 4.8 thhv Rendezvous Table

thhv maintains a **rendezvous table** mapping paths to shared memory
state:

```c
struct thhv_shmem_entry {
    char path[256];           /* rendezvous key */
    u64  backing_hpa;         /* HPA of backing pages */
    u64  size;                /* region size */
    int  mode;                /* CARVE or ALIAS */
    int  total_count;         /* original count */
    int  remaining;           /* aliases still available */
    u64  held_cap_handles[];  /* pre-created alias handles */
};

/* Global rendezvous table (protected by mutex) */
static struct thhv_shmem_entry shmem_table[MAX_SHMEM_ENTRIES];
```

When a new VM starts with `--ivshmem ...,mode=plug`, thhv looks up
the path, pops the next alias handle, and sends it to the new domain.

### 4.9 Use Cases

**1. Parent ↔ child doorbell** (dom0 ↔ dom1 notification):
```bash
# dom1 launch:
cloud-hypervisor ... \
  --ivshmem path=/tmp/dom1-doorbell,size=4K,mode=alias,count=1
```
Dom0 keeps access (alias mode).  Dom1 discovers a PCI ivshmem device,
writes messages to BAR2, rings doorbell via BAR0.  Capavisor returns
to dom0 (sync) or IPIs dom0's core (async).

**2. CVM ↔ CVM private channel** (confidential inter-VM):
```bash
# CVM-A (creator):
cloud-hypervisor ... --confidential \
  --ivshmem path=/tmp/cvm-channel,size=2M,mode=carve,count=1

# CVM-B (plugger, started later):
cloud-hypervisor ... --confidential \
  --ivshmem path=/tmp/cvm-channel,size=2M,mode=plug
```
Dom0 loses access (carve mode).  CVM-A and CVM-B share 2M of memory
that dom0 cannot read.  Both see an ivshmem PCI device.

**3. Shared bounce buffer** (dom0 ↔ confidential child):
```bash
# dom1 launch (confidential with shared DMA region):
cloud-hypervisor ... --confidential \
  --ivshmem path=/tmp/dom1-dma,size=16M,mode=alias,count=1
```
Dom0 keeps access (alias mode) for DMA.  Dom1 uses it as a bounce
buffer for device I/O.  Replaces the swiotlb share-back mechanism.

---

## 5. Implementation Plan

### Phase 0: Multi-ivshmem + capability-backed mode ✅ DONE

Committed across several PRs.  Key implementation notes:

- `THHV_REGISTER_SHMEM` was folded into `THHV_SET_GUEST_MEMORY` to
  eliminate a double-send issue.  The `thhv_set_guest_memory` struct
  was extended with `shmem_mode`, `shmem_count`, `shmem_path[256]`.
- Shmem mode values: NONE=0 (default), ALIAS=1, CARVE=2, PLUG=3.
- Rendezvous aliases are created BEFORE the per-segment map loop
  (critical for carve ordering — carve removes dom0 access).
- Plug mode skips the per-segment map loop entirely and pops from
  the rendezvous table.
- CHV's `annotate_shmem()` annotates pending memory entries by GPA
  match, then the unified `ensure_initialized()` flush handles both
  normal and shmem memory slots in one path.

### Phase 1: Doorbell infrastructure (ivshmem BAR0 + CPUID)

**Key insight**: the doorbell pipeline is **already fully implemented**
via the existing IOEVENTFD mechanism.  The full chain exists:

```
Guest writes to doorbell GPA
  → EPT violation in capavisor
  → handle_ept_doorbell() matches GPA (fast-path)
  → writes DoorbellNotify to parent DomainComm RX ring
  → advances child RIP, resumes child immediately
  → thhv drains DomainComm → eventfd_signal()
  → CHV worker thread wakes up
```

What's **actually needed** is to wire ivshmem BAR0 to this existing
pipeline, add CPUID discovery for Eunomia, and handle the eventfd
signal on the CHV side.

| # | Task | Where | Notes |
|---|------|-------|-------|
| 1 | Register IOEVENTFD for ivshmem BAR0 doorbell offset (GPA+0xC) | CHV `device_manager.rs` | Creates eventfd, calls `register_ioevent(fd, Mmio(bar0+0xC))`. Same pattern as virtio notification BARs. |
| 2 | Push CPUID leaf `0x40000004` as Emulate override | CHV `themis/mod.rs` | Per ivshmem device: subleaf N = (BAR0 GPA, count, BAR2 GPA lo/hi). Pushed during `ensure_initialized()`. |
| 3 | Bump `CPUID_THEMIS_MAX` to `0x40000004` | capavisor `vmexit.rs` | One-line change. The catch-all `(CPUID_THEMIS_BASE..=CPUID_HV_RANGE_END)` already returns zeros for unknown leaves, and the Emulate override takes precedence anyway. |
| 4 | Handle doorbell eventfd in CHV | CHV worker/event loop | Minimal: log + wake parent thread to check pending work. |
| 5 | Update IvshmemDevice BAR0 write handler | CHV `ivshmem.rs` | Remove "unexpected write" warning for offset 0xC (handled via IOEVENTFD, not BusDevice). |
| 6 | Eunomia: map ivshmem BARs at boot | `eunomia` | Read CPUID `0x40000004`, identity-map BAR0 and BAR2 GPA ranges. |

### Phase 1.5: Kernel-bypass doorbell (optimization, deferred)

For performance-critical paths, the doorbell can be handled entirely
in the **kernel (thhv)** without going through CHV userspace:

```
Guest writes to doorbell GPA
  → EPT violation → capavisor handle_ept_doorbell()
  → writes DoorbellNotify to DomainComm
  → thhv drains DomainComm in-kernel
  → thhv directly performs the action (e.g., signals a peer domain,
    writes to a shared page) WITHOUT signaling CHV via eventfd
```

This avoids the userspace round-trip (eventfd → epoll wake → CHV
handler → ioctl back to thhv).  Useful for inter-domain doorbell
forwarding where thhv can directly ring the target domain's doorbell
via the capavisor, or for coalesced notification delivery.

### Phase 2: VMCALL trigger + deferred delivery

| # | Task | Where |
|---|------|-------|
| 7 | Add `VMCALL_NOTIFY_PARENT` constant | `themis-abi` |
| 8 | Hypercall dispatch → `handle_doorbell` | `capavisor/hypercall.rs` |
| 9 | Capavisor: set flag + resume child (no switch) | `capavisor/hypercall.rs` |
| 10 | Parent discovers notification on next drain | `thhv/thhv_vp.c` |

### Phase 3: Core-gapped doorbell

| # | Task | Where |
|---|------|-------|
| 11 | Replace eager return with IPI to parent core | `capavisor/hypercall.rs` |
| 12 | thhv doorbell ISR (reuse core-gapping infra) | `thhv` |

---

## 6. Open Questions

1. **Doorbell GPA provisioning**: The ivshmem BAR0 address is assigned
   by CHV's PCI allocator.  CHV registers an IOEVENTFD at BAR0+0xC
   (doorbell register offset) which triggers the capavisor's existing
   `handle_ept_doorbell()` fast-path via `REGISTER_DOORBELL`.

2. **Reason code encoding for MMIO trigger**: When the child writes
   to the BAR0 doorbell register, the ivshmem spec uses the write
   value as a (dest_peer, vector) pair.  We can use this directly —
   the write value encodes the reason code.  For VMCALL trigger, the
   reason is in RDI.

3. **Multiple doorbells per domain**: Each `--ivshmem` instance creates
   a separate PCI device with its own BAR0 doorbell.  A domain with
   multiple ivshmem devices has multiple independent doorbells.  The
   capavisor identifies which doorbell was rung by matching the
   faulting GPA.

4. **Rate limiting / coalescing**: Not needed for Phase 1 (eager return
   already serializes).  Relevant for core-gapped mode where IPIs
   should be coalesced.

5. **Notification scope**: child→sibling notification could work via
   ivshmem devices shared between siblings (carve mode, count=1).
   Each sibling gets a PCI device with shared BAR2 + doorbell BAR0.
   Defer to future design.

6. **Carve mode alias ordering**: When mode is `carve`, thhv must
   create `count` aliases BEFORE carving the sub-cap away to the child
   domain (otherwise it loses access and can't alias).  ✅ Implemented:
   rendezvous aliases are created before the per-segment loop in
   `thhv_set_guest_memory()`.

7. **Eunomia BAR mapping**: Eunomia doesn't do PCI enumeration.  It
   discovers ivshmem BAR GPAs via CPUID leaf `0x40000004` (pushed by
   CHV as Emulate overrides).  Eunomia must identity-map both BAR0
   (doorbell MMIO, 256B) and BAR2 (shared data region) in its page
   tables at boot.  BAR2 is in PCI MMIO space (above 0xC0000000 for
   32-bit, or above 4GB for 64-bit), not in e820 RAM.

8. **Kernel-bypass doorbell** (future optimization): For inter-domain
   doorbell forwarding, thhv can handle `DOORBELL_NOTIFY` messages
   directly in-kernel without signaling CHV via eventfd.  thhv would
   look up the target domain's doorbell GPA and ring it via the
   capavisor, avoiding the userspace round-trip entirely.  This is
   orthogonal to the basic IOEVENTFD pipeline and can be added
   incrementally.

---

## 7. Relationship to Other Designs

- **Core-gapping** (`core-gapping.md`): Phase 3 reuses the same shared
  notification area + IPI doorbell.  The `Forward` policy variant
  described there is a superset of what the doorbell needs.

- **IOEVENTFD** (`CONTEXT.md` §5): The existing doorbell mechanism for
  virtio devices.  The general doorbell generalizes this pattern —
  instead of per-device GPA registration by the VMM, each domain gets
  a single doorbell GPA checked by the capavisor on EPT fault.

- **`THEMIS_REGISTER_DOORBELL`** (existing hypercall 0x15): Already
  exists for ioeventfd registration.  The IOEVENTFD pipeline
  (`register_ioevent` → thhv `ioeventfd_assign` → capavisor
  `REGISTER_DOORBELL`) is the mechanism used for both virtio and
  ivshmem doorbells.  No new hypercall needed.

- **Child DomainComm** (`child-domcomm.md`): DomainComm is the
  capavisor-managed data plane (RX/TX rings).  The private shared
  region is a separate, direct parent↔child data channel that
  bypasses the capavisor on the data path.

- **Channels** (capability engine): Channels are the data plane for
  inter-domain capability transfer.  The doorbell is the signaling
  plane that says "I used the channel, come look."

- **Interrupt virtualization** (`interrupt-virtualization.md`): The
  `Report` policy causes switch-returns with interrupt vectors as exit
  reasons.  The doorbell is similar but triggered explicitly by the
  child, not by a hardware interrupt.  Both converge when the child
  uses the VMCALL trigger — the capavisor treats it like a synthetic
  exit reason.

- **ivshmem** (`cloud-hypervisor/docs/ivshmem.md`): CHV already has
  ivshmem support for inter-VM shared memory.  We extend `--ivshmem`
  with `mode` and `count` parameters to integrate with the capability
  model — regions are tracked by thhv with proper capability semantics
  (revocation cascades through CDT) rather than being raw file-backed
  mappings.  Multiple `--ivshmem` flags per VM are supported.

---

## 8. Summary

```
┌─────────────────────────────────────────────────────────────┐
│                    DOORBELL DESIGN                          │
│                                                             │
│  Data Plane:   Capability-backed ivshmem (BAR2)             │
│                Direct parent↔child access, no capavisor     │
│                Presented as standard ivshmem PCI device     │
│                                                             │
│  Signal Plane: Doorbell (child → capavisor → parent)        │
│                Two triggers: ivshmem BAR0 write OR VMCALL   │
│                Both → handle_doorbell() in capavisor        │
│                                                             │
│  Sync mode:    Eager return (doorbell = exit reason)        │
│  Async mode:   IPI to parent core (child resumes)           │
│                                                             │
│  Provisioning: --ivshmem path=...,size=...,mode=...,count=  │
│                alias = creator keeps access                 │
│                carve = creator loses access (CVM privacy)   │
│                plug  = subsequent VMs join via rendezvous   │
│                                                             │
│  Guest:        Linux: auto PCI discovery (zero changes)     │
│                Eunomia: explicit BAR2 mapping at boot       │
│                                                             │
│  Lifetime:     Tied to creator cap, CDT revocation cascades │
└─────────────────────────────────────────────────────────────┘
```
