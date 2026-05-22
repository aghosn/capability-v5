# Inter-Domain Notification — Design Document

> **Goal**: Define a general-purpose mechanism for one domain to notify
> another that it needs attention (e.g., "I sent you a capability",
> "check your event queue").  The mechanism must work under both
> sync-switch (current) and core-gapped (future) scheduling models.

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
via CPUID leaf `0x40000003` (extending the existing Themis convention:
`0x40000000` = signature, `0x40000001` = version, `0x40000002` =
DomainComm):

```
EAX = feature flags
      bit 0: MMIO doorbell available (ivshmem BAR0)
      bit 1: VMCALL doorbell available
      bits 2-31: reserved

EBX = BAR0 GPA (low 32 bits)   — doorbell registers
ECX = BAR0 GPA (high 32 bits)
EDX = number of ivshmem devices
```

BAR2 GPAs (shared data regions) are discoverable via the attestation
report — each ivshmem memory cap appears with its GPA.  Eunomia calls
`ATTEST_SELF`, parses the report, and maps accordingly (see §4.6).

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
  synthetic CPUID leaf (e.g., `0x40000003`).  Eunomia reads CPUID at
  boot, maps the reported GPA range into its page tables.
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

### Phase 0: Multi-ivshmem + capability-backed mode

| # | Task | Where |
|---|------|-------|
| 1 | Extend `IvshmemConfig` with `mode`, `count` fields | `cloud-hypervisor/vm_config.rs` |
| 2 | Support multiple `--ivshmem` flags (Vec, unique names) | `cloud-hypervisor/device_manager.rs` |
| 3 | CHV: pass ivshmem UA + metadata to thhv via new ioctl | `cloud-hypervisor`, `thhv` |
| 4 | thhv: rendezvous table (`thhv_shmem_entry`) | `thhv/thhv_shmem.c` (new) |
| 5 | thhv: alias/carve + hold aliases at setup | `thhv/thhv_part.c` |
| 6 | thhv: plug lookup + send alias at child creation | `thhv/thhv_part.c` |
| 7 | thhv: new ioctl `THHV_REGISTER_SHMEM` | `thhv/thhv_ioctl.c` |

### Phase 1: Doorbell infrastructure + MMIO trigger (sync-switch)

| # | Task | Where |
|---|------|-------|
| 8 | Add `EXIT_REASON_DOORBELL` constant | `themis-abi` |
| 9 | Add `NotifyReason` enum (CapabilitySent, Generic) | `themis-abi` |
| 10 | Add shared region message layout structs | `themis-abi` |
| 11 | `PlatformDomain`: store `doorbell_gpa` (BAR0 addr) | `capavisor/platform.rs` |
| 12 | EPT violation handler: check doorbell GPA | `capavisor/vmexit.rs` |
| 13 | `handle_doorbell`: eager return to parent | `capavisor/hypercall.rs` |
| 14 | thhv: register doorbell GPA with capavisor | `thhv/thhv_part.c` |
| 15 | thhv: recognize DOORBELL exit reason | `thhv/thhv_vp.c` |
| 16 | CHV: handle doorbell (check pending caps) | `cloud-hypervisor` |
| 17 | Eunomia: map ivshmem BAR2 GPA in page tables at boot | `eunomia` |

### Phase 2: VMCALL trigger

| # | Task | Where |
|---|------|-------|
| 18 | Add `VMCALL_NOTIFY_PARENT` constant | `themis-abi` |
| 19 | Hypercall dispatch → `handle_doorbell` | `capavisor/hypercall.rs` |

### Phase 3: Deferred delivery (optimization)

| # | Task | Where |
|---|------|-------|
| 20 | Capavisor: set flag + resume child (no switch) | `capavisor/hypercall.rs` |
| 21 | Parent discovers notification on next drain | `thhv/thhv_vp.c` |

### Phase 4: Core-gapped doorbell

| # | Task | Where |
|---|------|-------|
| 22 | Replace eager return with IPI to parent core | `capavisor/hypercall.rs` |
| 23 | thhv doorbell ISR (reuse core-gapping infra) | `thhv` |

---

## 6. Open Questions

1. **Doorbell GPA provisioning**: The ivshmem BAR0 address is assigned
   by CHV's PCI allocator.  thhv registers this address with the
   capavisor via `THEMIS_REGISTER_DOORBELL` (already exists) so the
   capavisor can match EPT violations against it.

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
   domain (otherwise it loses access and can't alias).  Order:
   carve sub-cap → alias × count → send carve to child.

7. **Eunomia BAR mapping**: Eunomia doesn't do PCI enumeration.  It
   needs either (a) CPUID `0x40000003` reporting BAR2 GPA, or
   (b) attestation report listing the ivshmem memory cap.  Either
   way, Eunomia must identity-map the BAR2 GPA in its page tables
   at boot (it's in PCI MMIO space above 0xC0000000, not in e820 RAM).

---

## 7. Relationship to Other Designs

- **Core-gapping** (`core-gapping.md`): Phase 4 reuses the same shared
  notification area + IPI doorbell.  The `Forward` policy variant
  described there is a superset of what the doorbell needs.

- **IOEVENTFD** (`CONTEXT.md` §5): The existing doorbell mechanism for
  virtio devices.  The general doorbell generalizes this pattern —
  instead of per-device GPA registration by the VMM, each domain gets
  a single doorbell GPA checked by the capavisor on EPT fault.

- **`THEMIS_REGISTER_DOORBELL`** (existing hypercall 0x10): Already
  exists for ioeventfd registration.  Could be extended or reused to
  register the general doorbell GPA for a child domain.

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
