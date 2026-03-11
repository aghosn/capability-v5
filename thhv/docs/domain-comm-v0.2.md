# Domain Communication Region — Design v0.2

## 1. Problem

The capavisor and a domain need a bidirectional communication channel for data
that doesn't fit in register-based hypercall arguments:

- **Attestation report** — binary structured report containing capability handles,
  GPA→HPA memory mappings, domain policies.  The domain needs this to bootstrap
  all subsequent capability operations.
- **Async VP exit notifications** — in async scheduling mode, child VP exits are
  delivered as messages rather than synchronous VMCALL returns.
- **Interrupt routing updates** — changes to interrupt policies, posted interrupt
  descriptors.
- **Domain→capavisor requests** — attestation requests, capability queries, bulk
  register state transfers, ring growth requests.

Register-based hypercalls are limited to ~5 arguments and ~3 return values.
A shared-memory message region removes this bottleneck.

## 2. Overview

The **DomainComm** is a multi-page shared memory region between a domain and
the capavisor.  It is:

- **Per-domain**, not per-VP (distinct from VpCommPage / ThemIC per-VP pages)
- **Bidirectional**: RX ring (capavisor→domain) + TX ring (domain→capavisor)
- **Pure message ring** — no fixed data fields; all data (including attestation,
  PA maps) is delivered as messages on the rings
- **Growable** — the domain can add pages to the rings dynamically after bootstrap
- **Recursive** — the same mechanism applies to all domains (dom0, children,
  grandchildren) using the same API; see §12

### Design Principles

1. **Capability engine stays clean**: The capability engine has no notion of
   COMM page subtypes.  `REGISTER_COMM` just marks a capability as COMM and
   returns an `UpdateBatch`.  The capavisor **platform layer** interprets the
   binding to determine whether a COMM page is VP-level or domain-level.

2. **PA map derived from attestation**: The GPA→HPA translation map is part of
   the binary attestation report delivered as a message on the RX ring.
   There is no fixed PA map region in the DomainComm header.  The driver must
   parse attestation to learn its capabilities, handles, and memory mappings.

3. **Minimal bootstrap, grow on demand**: The capavisor pre-allocates a small
   initial region (enough for the attestation message).  The driver grows the
   rings after bootstrap when it can perform CARVE operations.

## 3. Bootstrap & Discovery (dom0)

Dom0 has a chicken-and-egg problem: to CARVE pages for the ring, the driver
needs GPA→HPA translation; to get the PA map, the driver reads attestation from
the ring; to read the ring, DomainComm must exist.

**Solution**: The capavisor pre-allocates and pre-populates dom0's DomainComm
**before dom0 boots**.

### Pre-allocation

1. **Capavisor** allocates N pages (e.g., 4) for dom0's DomainComm region
2. Pages are mapped into dom0's GPA space but marked as **e820 type 2
   (reserved)** — Linux sees them, does not allocate from them
3. Capavisor writes the header (page 0) and pre-populates the RX ring with
   binary attestation data (capability handles, PA map entries, policies)

### Discovery via CPUID

The DomainComm region GPA is communicated via a CPUID leaf:

```
CPUID leaf 0x40000002  (DomainComm Discovery):
  EAX = base GPA, low 32 bits
  EBX = base GPA, high 32 bits
  ECX = region size in pages
  EDX = flags (reserved, 0)
```

### Driver Init Sequence

```
1. Read CPUID 0x40000002 → (gpa, nr_pages)
2. memremap(gpa, nr_pages * PAGE_SIZE, MEMREMAP_WB) → va
3. Validate header magic/version
4. Read ring metadata from page 0
5. Dequeue DOMCOMM_MSG_ATTEST message from RX ring
6. Parse binary attestation:
   a. Capability handles (root memory cap, domain caps)
   b. GPA→HPA translation entries → populate thhv_translate.c rb-tree
   c. Domain policies, VP count, API flags
7. Driver is now bootstrapped — can perform CARVE/SEND/etc.
```

## 4. Registration (REGISTER_COMM)

The capability engine's `REGISTER_COMM` remains unchanged.  The VMCALL
signature is:

```
VMCALL_REGISTER_COMM(mem_cap_handle, child_domain_handle, vp_id)
```

The capability engine:
- Validates the memory cap (must be Carve, Exclusive, owned by caller)
- Marks the capability with the COMM attribute
- Stores a CommBinding (target_domain_id, vp_id)
- Returns an UpdateBatch with a CommRegion update to the platform

**The platform layer** interprets the CommRegion update:

| Condition | Platform interpretation |
|-----------|----------------------|
| `target_domain_id == domain_id` | Domain-level comm (DomainComm ring) |
| `target_domain_id != domain_id` | VP-level comm (VpCommPage / ThemIC) |

For domain-level comm, the domain passes **its own domain handle** as
`child_domain_handle` and `vp_id = 0`.  The engine validates normally
(the domain has a handle to itself in its own capability table — this is the
self-referencing domain capability).  The platform sees `target == owner` and
treats it as a DomainComm registration.

**Note**: For dom0, the initial DomainComm is pre-allocated by the capavisor
(§3).  REGISTER_COMM is used for growth (§9) and for child domain DomainComm
setup.

## 5. Layout — Page 0 (Header)

Page 0 contains only ring metadata.  All data (including attestation and PA
maps) is delivered as messages on the rings.

```
DomainComm Page 0 (4096 bytes):

Offset   Size    Field                  Producer    Description
──────   ────    ─────                  ────────    ───────────
0x000    4       magic                  capavisor   0x444F4D43 ("DOMC")
0x004    2       version_major          capavisor   Layout version (0)
0x006    2       version_minor          capavisor   Layout version (2)
0x008    4       total_pages            capavisor   Pages in initial region
0x00C    4       flags                  both        Status/feature flags

─── RX Ring Metadata (capavisor → domain) ──────────────────────────────
0x010    4       rx_head                capavisor   Producer index
0x014    4       rx_tail                domain      Consumer index
0x018    4       rx_page_offset         capavisor   First page of RX ring (1-based)
0x01C    4       rx_page_count          capavisor   Number of pages backing RX ring
0x020    4       rx_capacity            capavisor   Total ring size in bytes

─── TX Ring Metadata (domain → capavisor) ──────────────────────────────
0x030    4       tx_head                domain      Producer index
0x034    4       tx_tail                capavisor   Consumer index
0x038    4       tx_page_offset         capavisor   First page of TX ring (1-based)
0x03C    4       tx_page_count          capavisor   Number of pages backing TX ring
0x040    4       tx_capacity            capavisor   Total ring size in bytes

─── Notification ───────────────────────────────────────────────────────
0x050    4       notify_vector          domain      IDT vector for RX notifications
0x054    4       notify_flags           both        Notification control flags

0x100  3840      reserved
```

Head and tail are **logical byte offsets** into the ring.  The ring logic
translates offsets to page-local addresses via:
`page_index = offset / PAGE_SIZE`, `page_offset = offset % PAGE_SIZE`.
Messages never cross page boundaries (see §6).  Capacity is derived:
`rx_capacity = rx_page_count * PAGE_SIZE`, same for TX.

## 6. Layout — Pages 1+ (Message Rings)

Pages after page 0 are divided between the RX and TX rings based on the
metadata in the header.

```
Page 1 .. Page (1+rx_page_count-1):   RX ring (capavisor → domain)
Page (1+rx_page_count) .. Page M:     TX ring (domain → capavisor)
```

Each ring is a **byte-oriented circular buffer** of variable-length messages.

### Page-Level Fragmentation

Ring backing pages may not be contiguous in HPA or GPA space (e.g., after
ring growth via multiple GROW messages, or when the domain cannot allocate
contiguous physical pages).

**Invariant: messages never cross page boundaries.**

When a message does not fit in the remaining space of the current page, the
producer writes a **padding message** (`type=0`, `total_size=remaining_bytes`)
to fill the rest of the page, and starts the real message at offset 0 of the
next page.  This means:

- **Max message payload** = `PAGE_SIZE - 16` bytes (one 16-byte header + payload
  within a single 4096-byte page = 4080 bytes of payload)
- Both sides can map and access each page **independently** — no need for a
  contiguous virtual mapping across the entire ring
- The capavisor accesses each page via `HHDM_BASE + page_hpa`, even when pages
  are scattered in physical memory
- The driver uses `memremap()` per page (or `vmap()` for an array of pages),
  maintaining an internal page table for ring access
- Head and tail are **logical byte offsets** into the ring.  The ring logic
  translates `offset → (page_index, page_offset)` using:
  `page_index = offset / PAGE_SIZE`, `page_offset = offset % PAGE_SIZE`

### Intra-Page Fragmentation

Because the ring is strict FIFO with in-order processing (SPSC), **intra-page
fragmentation is inherently low**:

- Messages are packed sequentially within each page with no gaps
- Once the consumer advances tail past a message, that space is reclaimed when
  head wraps around — no "holes" form because processing is strictly in-order
- The only wasted space is **page-boundary padding**: at most
  `(max_message_size - 1)` bytes per page transition
- In practice, most messages are small (attestation entries ~40B, VP exit
  notifications ~272B) relative to page size (4096B), so padding waste is
  typically < 7% per page boundary crossing
- No compaction or defragmentation is ever needed

### Message Layout (Variable-Length)

Each message has a fixed 16-byte header followed by variable-length payload:

```
Offset   Size    Field
0x00     4       message_type    DOMCOMM_MSG_*  (0 = padding/skip)
0x04     4       total_size      Total message size incl. header (aligned to 8)
0x08     8       sequence        Monotonic counter
0x10     ...     payload         (total_size - 16 bytes)
```

- `total_size` is always 8-byte aligned.  The next message starts at
  `current_offset + total_size`.
- A message with `total_size > PAGE_SIZE - current_page_offset` triggers
  page-boundary padding (see above).

### Enqueue (producer)

```
1. Check space: (capacity - (head - tail)) >= msg_total_size
   If not enough: return -ENOSPC (domain can request growth)
2. page_offset = head % PAGE_SIZE
   If (page_offset + msg_total_size > PAGE_SIZE):
     Write padding msg (type=0, total_size=PAGE_SIZE - page_offset)
     Advance head to next page boundary
3. Write payload at ring[head]  (within current page)
4. Write header (message_type, total_size, sequence++)
5. wmb()
6. Update head += total_size
7. (Optional) Send IPI / doorbell to consumer
```

### Dequeue (consumer)

```
1. if (tail == head) → empty, return
2. rmb()
3. page_offset = tail % PAGE_SIZE
4. Read header at ring[tail]
5. If type == 0 (padding): tail += total_size, goto 1  (skip to next page)
6. Read payload (guaranteed within same page)
7. tail += total_size
```

Single-producer single-consumer (SPSC) — no locking needed, just memory
barriers.  The capavisor is the sole producer for RX; the domain is the sole
producer for TX.

## 7. Message Types

```c
/* ── Capavisor → Domain (RX ring) ──────────────────────────── */
#define DOMCOMM_MSG_NONE            0x0000  /* padding / skip */
#define DOMCOMM_MSG_ATTEST          0x0001  /* Binary attestation report */
#define DOMCOMM_MSG_VP_EXIT         0x0002  /* Async VP exit notification */
#define DOMCOMM_MSG_IRQ_NOTIFY      0x0003  /* Interrupt delivery event */
#define DOMCOMM_MSG_DOMAIN_EVENT    0x0004  /* Child domain state change */
#define DOMCOMM_MSG_ERROR           0x0005  /* Error / backpressure signal */
#define DOMCOMM_MSG_GROW_ACK        0x0006  /* Acknowledge ring growth */

/* ── Domain → Capavisor (TX ring) ──────────────────────────── */
#define DOMCOMM_MSG_ATTEST_REQ      0x0100  /* Request (self-)attestation */
#define DOMCOMM_MSG_ACK             0x0101  /* Acknowledge RX message */
#define DOMCOMM_MSG_BULK_REG_SET    0x0102  /* Bulk register write */
#define DOMCOMM_MSG_GROW_RX         0x0103  /* Request RX ring growth */
#define DOMCOMM_MSG_GROW_TX         0x0104  /* Request TX ring growth */
#define DOMCOMM_MSG_ENUM_CAP        0x0105  /* Enumerate single capability */
```

### DOMCOMM_MSG_ATTEST — Binary Attestation Report

Delivered to RX ring at bootstrap (dom0: pre-populated) or in response to
ATTEST_REQ.  Large reports are split across multiple messages with sequence
numbers for reassembly.

```
Attestation payload (binary, variable-length):

Offset   Size    Field
0x00     8       domain_id
0x08     4       flags           (sealed, etc.)
0x0C     4       num_vps
0x10     4       api_flags       (MonitorAPI bitmask)
0x14     4       nr_mem_caps     Number of memory capability entries
0x18     4       nr_dom_caps     Number of domain capability entries
0x1C     4       nr_pa_entries   Number of PA map (GPA→HPA) entries
0x20     ...     mem_caps[]      Array of mem_cap_entry
                 dom_caps[]      Array of dom_cap_entry
                 pa_map[]        Array of pa_map_entry

Each mem_cap_entry (40 bytes):
  +0x00  u64  handle         Local handle in caller's table
  +0x08  u64  gpa_start      Guest Physical Address start
  +0x10  u64  size           Range size in bytes
  +0x18  u32  rights         Access rights bitmask
  +0x1C  u32  attributes     Capability attributes (COMM, META, etc.)
  +0x20  u64  hpa_start      Host Physical Address start

Each dom_cap_entry (16 bytes):
  +0x00  u64  handle         Local handle in caller's table
  +0x08  u64  domain_id      Target domain ID

Each pa_map_entry (24 bytes):
  +0x00  u64  gpa_start      Guest Physical Address start
  +0x08  u64  hpa_start      Host Physical Address start
  +0x10  u64  size           Range size in bytes
```

The driver parses this to populate the GPA→HPA translation tree AND learn
its capability handles for subsequent VMCALL operations.

### DOMCOMM_MSG_ENUM_CAP — Single Capability Enumeration

For enumerating a specific capability by handle (request/response pair):

```
TX (request):
  +0x00  u64  handle         Handle to enumerate

RX (response via DOMCOMM_MSG_ATTEST with single entry):
  Attestation message with nr_mem_caps=1 or nr_dom_caps=1
```

## 8. Boot Sequence

### dom0 (pre-allocated by capavisor)

```
1. Capavisor creates dom0:
   a. Allocates N pages for DomainComm (e.g., 4 pages)
   b. Marks region as e820 type 2 (reserved)
   c. Sets CPUID leaf 0x40000002 with GPA and page count
   d. Writes header to page 0 (magic, version, ring metadata)
   e. Pre-populates RX ring with DOMCOMM_MSG_ATTEST (binary attestation)
2. dom0 boots, Linux kernel starts
3. thhv driver init:
   a. CPUID 0x40000002 → (gpa, nr_pages)
   b. memremap(gpa, nr_pages * PAGE_SIZE, MEMREMAP_WB)
   c. Validate header, read ring metadata
   d. Dequeue DOMCOMM_MSG_ATTEST from RX ring
   e. Parse attestation → PA map + capability handles
   f. Driver is bootstrapped
```

### Child domain (set up by parent via capability operations)

```
1. Parent creates child domain (CREATE_DOMAIN)
2. Parent allocates pages for child's DomainComm
3. Parent CARVEs memory → REGISTER_COMM (self-ref → platform sees domain-level)
4. Actually TBD: see §12 (Recursive Design)
```

## 9. Ring Growth

After bootstrap, the driver can grow the rings dynamically:

```
1. Driver allocates new page(s) via alloc_pages()
2. Driver translates GPA→HPA (now possible — PA map is loaded)
3. Driver CARVEs a new memory capability for the pages
4. Driver sends DOMCOMM_MSG_GROW_RX or DOMCOMM_MSG_GROW_TX on TX ring:
   Payload:
     +0x00  u64  cap_handle    Handle of CARVEd capability
     +0x08  u64  nr_pages      Number of new pages
5. Capavisor maps new pages, extends the ring:
   a. Updates rx_capacity or tx_capacity in page 0 header
   b. Sends DOMCOMM_MSG_GROW_ACK on RX ring
6. Driver reads ACK, updates its local ring state
```

### Non-Contiguous Backing Pages

If the domain cannot allocate physically contiguous pages, it sends **multiple
GROW messages**, one per contiguous HPA segment.  The capavisor assembles them
into the logical ring by maintaining a page table of ring segments internally.

The ring remains logically contiguous from the producer/consumer perspective —
the capavisor handles scatter-gather mapping.  However, the driver side uses
`memremap()` per segment and maintains an iovec-like structure for ring access.

## 10. Async VP Exit Delivery

When a child VP exits in async mode:

```
1. Capavisor handles VMEXIT
2. Writes exit info to parent domain's RX ring as DOMCOMM_MSG_VP_EXIT
   payload:
     +0x00  u32  vp_id
     +0x04  u32  reserved
     +0x08  ...  themic_intercept_message (256 bytes)
3. Sends IPI to parent core (notify_vector, reused from ThemIC)
4. Driver IPI handler:
   a. Dequeues message from RX ring
   b. Looks up VP by vp_id
   c. Copies intercept data to VP's exit_msg buffer
   d. atomic_set(&vp->exit_pending, 1)
   e. wake_up(&vp->exit_wq)
5. Userspace thread (blocked in THHV_RUN_VP async) wakes, reads exit info
```

## 11. Backpressure & Error Handling

When the ring is full (producer cannot enqueue):

- **RX ring full** (capavisor cannot write): Capavisor sends an
  `DOMCOMM_MSG_ERROR` with error code indicating ring full.  The domain should
  grow the ring.  The capavisor does **not** block — it drops the message and
  signals the error.
- **TX ring full** (domain cannot write): Domain receives `-ENOSPC` from the
  enqueue function.  It should grow the ring or drain pending responses.

Rings are designed to be **growable dynamically** (§9) so backpressure is
transient.

## 12. Recursive Design

The DomainComm mechanism is designed to be **recursive** — the same API works
for dom0, children, and grandchildren:

- Every domain can have a DomainComm ring with the capavisor
- The same REGISTER_COMM (self-ref), message types, ring protocol, and growth
  mechanism apply uniformly
- For dom0: the capavisor pre-allocates the initial region (§3)
- For child domains: the parent sets up the initial region as part of domain
  creation.  The exact mechanism (pre-allocation vs post-boot setup) is TBD
  but will use the same structures and message formats
- A child domain's DomainComm ring is between that child and the capavisor
  (not between the child and its parent — the capavisor is always one endpoint)

This ensures the mechanism is designed once and reused at every level of the
domain hierarchy.

## 13. Relationship to Other Pages

| Page Type | Scope | Purpose | Registration |
|-----------|-------|---------|-------------|
| DomainComm | Per-domain | Attestation, async events, requests, growth | REGISTER_COMM (self-ref) |
| VpCommPage | Per-child-VP | Register state fast-path (dirty mask + values) | REGISTER_COMM (child, vp_id) |
| ThemIC Message Page | Per-child-VP | Sync intercept msgs, doorbells | REGISTER_COMM (child, vp_id) |
| ThemIC Event Flags | Per-child-VP | Pending-bit bitmap for ThemIC channels | REGISTER_COMM (child, vp_id) |
| META pages | Per-child-VP | Capavisor internal (VMCS, VAPIC, EPT) | SEND with META attr |

Note: The capability engine treats all COMM registrations uniformly.  The
platform layer distinguishes DomainComm (self-ref: target == owner) from
VP-level pages (target != owner) based on the CommBinding.

## 14. Resolved Design Decisions

- **Page count**: Configurable.  Asymmetric (more RX than TX).  Growable.
- **PA map delivery**: Via binary attestation message, not fixed header fields.
- **Large messages**: Variable-length with size in header.  Large payloads
  (e.g., attestation reports) may be split across multiple messages with
  sequence numbers.  Compressed formats (e.g., base64) may be used.
- **Backpressure**: Error signal + dynamic ring growth (§11).
- **Non-contiguous pages**: Supported via scatter-gather (§9).
- **Notification vector**: Reuse ThemIC vector.
- **Variable-length messages**: Size in the message header.  Byte-oriented
  ring with 8-byte alignment.
- **Capability engine**: Unchanged.  Platform layer interprets COMM subtypes.

## 15. Open Questions

- **Child domain bootstrap**: How does a parent set up DomainComm for a child?
  Pre-allocate before child boots (like dom0), or child requests after boot?
  The recursive design (§12) ensures the same structures, but the setup flow
  for non-dom0 domains needs design.
- **Attestation binary format versioning**: How to handle format evolution?
  Version field in the attestation payload, or rely on DomainComm version?
- **Ring page table**: The capavisor's internal representation of scatter-gather
  ring segments.  Flat array of HPAs?  Page table?  Needs capavisor-side design.
- **Self-referencing domain handle**: Need to verify that domains have a handle
  to themselves in their own capability table.  If not, add one during domain
  creation.

## 16. Implementation & Validation Plan

Implementation is incremental: each milestone is validated before moving to the
next.  Validation is driven from dom0 userspace via test utilities that talk to
the thhv driver through ioctls.

### Milestone 0 — Binary Attestation Format (prerequisite)

**What**: Define the binary attestation structures in both Rust (capavisor) and
C (driver/thhv.h).  This is a prerequisite for everything else.

- Define `domcomm_header`, `domcomm_msg_header`, `domcomm_attest_report`,
  `domcomm_mem_cap_entry`, `domcomm_dom_cap_entry`, `domcomm_pa_map_entry`
  in `thhv.h`
- Define corresponding Rust structs in `themis-abi` or capavisor platform code
- Define DomainComm message type constants

**Validation**: Compilation only — no runtime test.

### Milestone 1 — Capavisor DomainComm Pre-allocation

**What**: Capavisor allocates DomainComm pages for dom0 during domain creation,
marks them in e820, sets CPUID leaf, writes header + binary attestation to RX.

- Allocate 4 pages at a known GPA for dom0's DomainComm
- Mark in e820 as type 2 (reserved)
- Handle CPUID leaf 0x40000002 in vmexit handler
- Write DomainComm header to page 0
- Serialize dom0's attestation report (binary format) into the RX ring
- (Include PA map entries, capability handles, domain policies)

**Validation**: `cargo themis` boots dom0 normally — no regression.  The
reserved e820 region and CPUID leaf are present but ignored by the unmodified
kernel.

### Milestone 2 — Driver Discovery + Attestation Parsing

**What**: thhv driver discovers DomainComm at init, reads and parses the
binary attestation from the RX ring.

- Read CPUID 0x40000002 at module init
- `memremap()` the DomainComm region
- Validate header (magic, version)
- Initialize ring reader (page-aware dequeue logic)
- Dequeue `DOMCOMM_MSG_ATTEST` from RX ring
- Parse binary attestation → populate PA map rb-tree + store capability handles

**Validation**:
- Insert thhv.ko — `dmesg` shows discovered DomainComm GPA, page count,
  parsed PA map entries, capability handles
- **Userspace test tool** (`thhv-test-attest`): opens `/dev/thhv`, issues a new
  ioctl (`THHV_QUERY_PA_MAP` or `THHV_QUERY_ATTEST`) to read back parsed info,
  prints PA map entries and capability handles to stdout
- Verify PA map entries match expected dom0 memory layout

### Milestone 3 — Validate PA Map (CARVE with Real HPAs)

**What**: Validate the parsed PA map by attempting a real CARVE operation using
the handles and HPAs from attestation.

- Userspace allocates a page, calls `THHV_SET_GUEST_MEMORY` (or a test-only
  ioctl) to trigger the driver's pin → translate → CARVE path
- Driver uses PA map to translate GPA→HPA, uses root cap handle from
  attestation for CARVE

**Validation**: CARVE succeeds (capavisor returns success).  This proves the
PA map and capability handles are correct end-to-end.

### Milestone 4 — Ring Growth

**What**: Driver allocates new pages, CARVEs them, sends GROW_RX/TX message on
the TX ring.  Capavisor handles the growth request.

- Implement TX ring enqueue in driver (page-aware, variable-length)
- Implement `DOMCOMM_MSG_GROW_RX` / `DOMCOMM_MSG_GROW_TX` message handling in
  capavisor platform
- Platform layer: distinguish DomainComm from VP-comm via CommBinding (self-ref
  detection), needed for growth to route correctly
- Capavisor maps new pages, updates ring metadata, sends `DOMCOMM_MSG_GROW_ACK`

**Validation**:
- **Userspace test tool** (`thhv-test-grow`): triggers ring growth via ioctl,
  verifies ring capacity increased, sends/receives test messages to confirm the
  grown ring works
- Check `dmesg` for growth events

### Milestone 5 — Async VP Exit Delivery

**What**: Wire child VP exits through the DomainComm RX ring instead of (or in
addition to) the synchronous COMM page path.

- Capavisor writes `DOMCOMM_MSG_VP_EXIT` to parent's RX ring on child VMEXIT
- Driver RX handler dequeues, dispatches to VP waitqueue
- IPI notification via shared ThemIC vector

**Validation**:
- Create a child domain + VP, run it, trigger an exit (e.g., HLT or MMIO)
- Verify exit notification arrives via DomainComm RX ring
- Userspace receives the exit info through `THHV_RUN_VP` (async path)

### Milestone 6 — Single Capability Enumeration

**What**: `DOMCOMM_MSG_ENUM_CAP` request/response for querying individual
capabilities at runtime.

**Validation**: Userspace tool enumerates a known capability by handle, verifies
the response matches expected attributes.

### Test Utilities

All test tools are small C programs in `thhv/tests/` that open `/dev/thhv` and
exercise the driver via ioctls:

| Tool | Purpose | Milestone |
|------|---------|-----------|
| `thhv-test-attest` | Query parsed attestation/PA map from driver | M2 |
| `thhv-test-carve` | Trigger a CARVE to validate PA map correctness | M3 |
| `thhv-test-grow` | Trigger ring growth, send/receive test messages | M4 |
| `thhv-test-vpexit` | Create child VP, trigger exit, verify DomainComm delivery | M5 |

These tools run inside dom0 and are compiled against the same guest kernel
headers (via `build-guest.sh` or a separate Makefile).
