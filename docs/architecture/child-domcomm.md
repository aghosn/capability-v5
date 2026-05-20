# Child Domain DomainComm — Design & Implementation Plan

> **Goal**: Every child domain (dom1, Eunomia, etc.) gets a per-domain
> DomainComm region, set up transparently by thhv before seal.  This lets
> the child call `ATTEST_SELF`, discover its own capabilities, and
> participate in the full Themis protocol.

---

## Context

### What exists today

- **Dom0 DomainComm**: set up by the capavisor during boot
  (`bootstrap_init_domcomm`).  4 pages (header + RX + TX).  Discovered by
  dom0 via CPUID leaf `0x40000002`.

- **Per-child-VP COMM**: thhv carves a page per VP, calls `REGISTER_COMM`
  to bind it for the capavisor to read/write VP state.  This is a
  *different* thing — it's the `VpCommPage`, not the DomainComm ring.

- **Engine `register_comm`**: marks a capability as `COMM`, records a
  `CommBinding { target_domain_id, vp_id }`.  Pure bookkeeping — doesn't
  initialize any ring structures.

- **Capavisor `do_register_comm`**: calls the engine's `register_comm`.
  Does **not** call `init_domcomm` on the child's `PlatformDomain`.

### What's missing

1. **Capavisor**: when a COMM page is registered as *domain-level* (not VP),
   the capavisor must call `init_domcomm` on the child's `PlatformDomain`
   to write the header, set up ring metadata, and track the page HPAs.

2. **thhv**: must allocate pages, carve from parent cap, and call
   `REGISTER_COMM` with a flag/argument indicating "this is domain-level
   COMM" (not VP COMM).

3. **Child discovery**: the child needs to know the GPA of its DomainComm
   region so it can read the RX ring.  For dom0 this is CPUID
   `0x40000002`.  For children, the capavisor can provide the same leaf
   (it already handles CPUID natively for hypervisor leaves).

4. **Eunomia**: minimal DomainComm reader — parse the attestation report
   from the RX ring to discover capability handles.

---

## Design

### Step 1: DOMAIN_GLOBAL_COMM sentinel and sparse init_domcomm

**ABI** (`themis-abi/src/lib.rs`):
- `pub const DOMAIN_GLOBAL_COMM: u32 = u32::MAX;` — sentinel `vp_id`
  for `REGISTER_COMM` that marks pages as domain-level COMM.

**libthemis** (`libthemis/src/lib.rs`):
- `register_domcomm(cap, child_domain)` — convenience wrapper that calls
  `register_comm` with the sentinel.

**Engine** (`capa-engine/src/capability.rs`):
- `register_comm`: when `vp_id == u32::MAX`, skip VP index validation
  and allow multiple COMM bindings (one per DomainComm page).

**Capavisor** (`capavisor/src/platform.rs`):
- `PlatformDomain` gains `pending_domcomm_hpas: Vec<u64>`.
- `init_domcomm(&mut self, page_hpas: &[u64])` — takes a sparse HPA
  slice instead of `(base, count)`.  `page_hpas[0]` is header, rest
  split between RX and TX.
- `apply_update` for `CommRegion`: when `vp_id == DOMAIN_GLOBAL_COMM`,
  push HPAs to `pending_domcomm_hpas` on the child's PlatformDomain.
- `finalize_domcomm(domain_id)` — called at seal time, consumes the
  pending HPAs and calls `init_domcomm`.
- `do_seal` (hypercall.rs): after engine seal succeeds, calls
  `platform.finalize_domcomm(child_id)`.
- Per-domain CPUID `0x40000002`: looks up the calling domain's
  `PlatformDomain.domcomm` instead of global statics.  Falls back to
  dom0's global values during bootstrap.

### Step 2: thhv provisions DomainComm at domain creation

**thhv** (`thhv/src/thhv_part.c`):
- In `thhv_create_partition`, after domain creation and before seal:
  1. `alloc_pages(GFP_KERNEL, order)` — allocate `DOMCOMM_NR_PAGES` (4)
     contiguous pages.
  2. `page_to_phys()` → get HPA.
  3. `thhv_find_parent_handle(hpa, size)` → find parent cap.
  4. `themis_carve(parent, hpa, size, RWX)` → get carved handle.
  5. `thhv_cap_table_insert(carved_handle, ...)` — track locally.
  6. `themis_register_comm(carved_handle, child_domain, DOMCOMM_VP_SENTINEL)`
     — register as domain-level COMM.
  7. Store the GPA in `thhv_partition` for later reference.

This happens alongside the channel provisioning already in place (get_chan +
send_chan).

**Order in `thhv_create_partition` (before seal)**:
1. Create domain
2. Send memory regions (CARVE + SEND, already done by CHV)
3. Allocate + register DomainComm pages ← **NEW**
4. Get self-channel + send to child (already done)
5. Seal

### Step 3: Child discovers DomainComm GPA

**Option A — CPUID leaf** (preferred, matches dom0):
- The capavisor already handles CPUID leaf `0x40000002` natively for dom0
  (returns DomainComm GPA and page count).
- For child domains: the capavisor's CPUID handler should return the
  child's own DomainComm GPA (looked up from the child's `PlatformDomain`).
- This requires the CPUID handler to be per-domain, not global statics.
  Currently `DOMCOMM_GPA` / `DOMCOMM_PAGES` are global atomics set once
  for dom0.  Need to make them per-domain.

**Option B — Well-known GPA**:
- thhv places the DomainComm at a fixed GPA (e.g., `0xE000` like dom0).
- Simpler but fragile — assumes the GPA is not used by the guest.

**Recommendation**: Option A.  Change the CPUID handler to read from the
calling domain's `PlatformDomain.domcomm` instead of global statics.

### Step 4: Eunomia DomainComm reader

**Eunomia** (`eunomia/src/domcomm.rs` — new module):
- At boot: read CPUID `0x40000002` → get DomainComm GPA + page count.
- Map the region (it's already in the EPT, just need the virtual mapping).
- Parse the `domcomm::Header` struct (from `themis-abi`).
- Call `ATTEST_SELF` → capavisor writes attestation report to RX ring.
- Parse `domcomm::AttestReport` → extract `mem_cap_entry[]` with handles,
  GPAs, sizes, rights.
- Eunomia now knows its capability handles.

**Dependencies**: `themis-abi::domcomm` (already has Header, RingMeta,
AttestReport, etc.).

### Step 5: Eunomia CoCo workload

With capability discovery working, the CoCo workload can:

1. Boot under `--confidential` (CARVE mode).
2. Read CPUID → find DomainComm → call ATTEST_SELF → parse report.
3. Find its root memory capability handle.
4. `alias(root_handle, start, PAGE_SIZE, RW)` → create shared alias.
5. Find its channel handle (from the attestation report's dom_cap entries,
   or just use handle 0 if deterministic).
6. `send(alias_handle, channel_handle, 0)` → send alias to parent.
7. Parent (thhv/CHV) accepts the shared region.

**Test assertions**:
- ATTEST_SELF succeeds and returns a valid report.
- Memory cap entries list the expected regions.
- ALIAS + SEND succeed.
- (Future) dom0 can read the aliased page but not the private ones.

---

## Implementation Order

| # | Task | Where | Status |
|---|------|-------|--------|
| 1 | `DOMAIN_GLOBAL_COMM` sentinel constant | `themis-abi` | ✅ Done |
| 2 | `register_domcomm()` convenience wrapper | `libthemis` | ✅ Done |
| 3 | Engine: skip VP validation for sentinel | `capa-engine/capability.rs` | ✅ Done |
| 4 | `init_domcomm` takes sparse `&[u64]` | `capavisor/platform.rs` | ✅ Done |
| 5 | `apply_update` accumulates DOMAIN_GLOBAL_COMM pages | `capavisor/platform.rs` | ✅ Done |
| 6 | `finalize_domcomm` at seal time | `capavisor/platform.rs` + `hypercall.rs` | ✅ Done |
| 7 | Per-domain CPUID `0x40000002` | `capavisor/vmexit.rs` | ✅ Done |
| 8 | thhv provisions DomainComm pages at domain creation | `thhv/src/thhv_part.c` | Pending |
| 9 | Eunomia DomainComm reader module | `eunomia/src/domcomm.rs` | Pending |
| 10 | Eunomia CoCo workload | `eunomia/workloads/coco/` | Pending |
| 11 | CHV accept shared region back | `thhv`, CHV | Pending |

---

## Open Questions

- **Number of initial pages**: 4 (like dom0) or fewer?  For Eunomia, 2
  might suffice (header + RX).  TX not needed until the child sends
  messages to the capavisor.  Start with 4 for consistency.

- **init_domcomm contiguity**: Currently assumes contiguous.  Fine for
  initial allocation (`alloc_pages` with order).  Growth path already
  handles non-contiguous.  No change needed.

- **GPA placement**: When thhv sends the COMM pages to the child, what GPA
  do they land at?  The engine's `send` to an unsealed domain auto-maps at
  identity (GPA = HPA) unless `send_at` with a GPA hint is used.  thhv
  should use `send_at` to place the DomainComm at a well-known GPA (e.g.,
  `0xE000`) so the CPUID answer is predictable.  Actually — wait, the COMM
  pages are NOT sent to the child.  They stay owned by the parent (dom0).
  The capavisor accesses them via HHDM.  The child reads them at whatever
  GPA they're mapped in its EPT.  Since `register_comm` produces an
  `UpdateBatch`, the pages get mapped into the child's EPT at identity GPA
  by default.  The CPUID handler returns that GPA.

- **Channel handle discovery**: The attestation report includes dom_cap
  entries.  The channel sent by thhv should appear there.  Eunomia parses
  it to find the channel handle.
