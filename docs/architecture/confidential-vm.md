# Confidential VM Design — CC_VENDOR_THEMIS + VTOM

## 1. Goal

Run dom1 (and any child domain) in **confidential mode**: the VMM (cloud-hypervisor
in dom0) cannot read or write the guest's private memory. Only explicitly shared
regions (virtio rings, DMA bounce buffers) are accessible to dom0.

This is analogous to AMD SEV-SNP and Intel TDX, but enforced through Themis
capabilities and EPT isolation rather than hardware memory encryption.

### Non-goals (for now)

- Hardware memory encryption (no C-bit / encryption keys needed — Themis EPT
  isolation provides equivalent protection against a compromised dom0).
- Integrity hashing of guest pages (future work, can layer on top).
- Live migration of confidential VMs.

---

## 2. Threat Model

| Trusted | Untrusted |
|---------|-----------|
| Capavisor (L0) | Dom0 kernel + userspace (L1) |
| Hardware (CPU, memory controller) | Dom0 VMM (cloud-hypervisor) |
| Guest kernel (dom1) | Other domains |

The VMM (CHV) is an **untrusted intermediary**: it sets up the guest's memory
layout, devices, and boot parameters, but once the guest is sealed and running,
it should not be able to read or modify the guest's private state.

Today, CHV retains read/write access to all of dom1's memory through dom0's HHDM
(Higher Half Direct Map) even after capability SEND — the capability engine tracks
ownership correctly, but the EPT enforcement doesn't remove HPAs from dom0's
address space. This design closes that gap.

---

## 3. Architecture: VTOM Address-Space Split

### 3.1 Virtual Top of Memory (VTOM)

The guest physical address (GPA) space is split at a **VTOM boundary**:

```
dom1 GPA space (example: 1 GB RAM, VTOM at bit 39 = 0x80_0000_0000):

  [0x00_0000_0000 .. 0x3F_FFFF_FFFF]   →  PRIVATE memory
                                            - Kernel text/data, page tables, user processes
                                            - dom0 has NO access (HPAs removed from dom0 EPT)
                                            - Backed by CARVE + SEND (exclusive ownership)

  [0x80_0000_0000 .. 0xBF_FFFF_FFFF]   →  SHARED window (same HPAs, offset by VTOM)
                                            - virtio descriptor rings, DMA bounce buffers
                                            - dom0 retains read/write access (ALIAS)
                                            - Guest accesses via set_memory_decrypted()
```

The two windows map to the **same physical pages** (HPAs). The difference is access
control: private-window HPAs are removed from dom0's EPT, shared-window HPAs remain
in dom0's EPT.

### 3.2 Why VTOM (not per-page C-bit)

| Approach | Pros | Cons |
|----------|------|------|
| **VTOM (address-range split)** | Simple EPT setup, no per-page tracking, matches mshv/VBS model | Wastes GPA space (2× address range) |
| **C-bit (per-page encryption bit)** | Fine-grained, standard SEV model | Requires page-level tracking in capavisor, complex EPT management |
| **Hyper-V emulation** | Stock kernel, no patches | Must emulate synthetic MSRs, CPUID, VMBus — heavy |

VTOM is the right trade-off for Themis:
- EPT construction is straightforward (two ranges, same HPAs, different permissions)
- The GPA space "waste" is irrelevant (we control the EPT, not real hardware limits)
- Linux already has VTOM support via the CoCo framework (`cc_mkenc`/`cc_mkdec`)
- The mshv/VBS precedent means the code paths are well-tested in mainline

### 3.3 Capability flow: guest-initiated sharing

**Key insight**: In the capability model, dom0 cannot unilaterally retain access
to dom1's memory after SEND. The guest must **explicitly share back** the regions
it wants the VMM to access. This is the correct CoCo model — the guest decides
what's shared, not the hypervisor/VMM.

#### Boot-time protocol

```
Phase 1: Pre-boot (CHV writes into guest memory while dom0 still owns it)
──────────────────────────────────────────────────────────────────────────
  dom0: CARVE(root, guest_ram, size, RWX)
  dom0: [writes firmware, ACPI tables, kernel, initramfs into guest_ram]
  dom0: CREATE_CHANNEL(dom0, dom1) → dom0_endpoint, dom1_endpoint
  dom0: SEND(guest_ram, dom1)         ← dom0 loses ALL access
  dom0: SEAL(dom1)

Phase 2: Early guest boot (all in private memory, no I/O needed)
──────────────────────────────────────────────────────────────────────────
  dom1 kernel: early init, memory init, page tables
  dom1 kernel: detects CC_VENDOR_THEMIS via CPUID 0x4000_0100
  dom1 kernel: allocates swiotlb bounce buffer pool (e.g., 64 MB at 0x200_0000)

Phase 3: Share-back (two aliases: one for self VTOM mapping, one for parent)
──────────────────────────────────────────────────────────────────────────
  dom1: ALIAS(guest_ram, swiotlb_offset, swiotlb_size, RW) → alias_self
  dom1: ALIAS(guest_ram, swiotlb_offset, swiotlb_size, RW) → alias_parent
  dom1: MAP_SELF(alias_self, 0x80_0200_0000)  ← maps at GPA|VTOM in own EPT
  dom1: CHANNEL_SEND(dom1_endpoint, alias_parent) → dom0 receives it
  dom0/CHV: CHANNEL_RECV(dom0_endpoint) → alias_parent
  dom0/CHV: maps alias_parent into its address space

Phase 4: Normal operation
──────────────────────────────────────────────────────────────────────────
  dom1: set_memory_decrypted() flips VTOM bit → DMA goes to 0x80_0200_0000
  dom1: virtio uses DMA API → swiotlb bounces through shared window
  dom0: CHV reads/writes virtio rings and data via alias_parent only
  dom1: private memory (kernel, user pages) remains inaccessible to dom0
```

Every EPT mapping corresponds 1:1 with a capability. No implicit dual mappings.

#### Capability tree after share-back

```
dom1 owns:
  ├─ guest_ram [GPA 0x0 .. 0x3FFF_FFFF]              ← private, in dom1 EPT
  │    ├─ alias_self [GPA 0x80_0200_0000 .. +64MB]    ← VTOM view, in dom1 EPT
  │    └─ alias_parent [sent to dom0]                  ← same HPAs
  └─ dom1_endpoint (channel)

dom0 holds:
  ├─ dom0_endpoint (channel)                           ← revocation root
  └─ alias_parent (received via channel)               ← RW to bounce buffer
```

#### New hypercall: MAP_SELF

`MAP_SELF(cap_handle, gpa)` — requests the capavisor to map a capability the
calling domain owns at a specific GPA in that domain's own EPT.

This is needed because currently GPA assignment is done by the parent (CHV
calls `THHV_SET_GUEST_MEMORY` with a `guest_pfn`). For confidential mode, the
guest must control its own address space layout — the parent has no access to
do it.

Capavisor validation:
- The capability must be owned by the calling domain
- The GPA range must not overlap existing mappings (or we allow re-mapping)
- The capability's rights determine the EPT permissions
- A1 still holds: `execute() → apply_update()` validates before EPT changes

#### Child-to-parent transfer via channels

Channels are the mechanism for dom1 to send capabilities back to dom0:

1. **Pre-seal**: dom0 creates a channel and sends one endpoint to dom1
2. **Dom1 boot**: dom1 discovers the channel endpoint in its capability set
3. **Share-back**: dom1 creates alias_parent and sends it through the channel
4. **Dom0 receives**: CHV polls/accepts the capability from its endpoint

**Revocation**: dom0 holds dom0_endpoint. When dom0 revokes the channel (or
destroys dom1), all capabilities that flowed through the channel — including
alias_parent — are revoked. dom0_endpoint is the **revocation root** for all
shared memory. This gives dom0 clean teardown without needing to track individual
aliases.

**Open question**: Does the channel currently support revoking all capabilities
sent through it? If not, this needs to be added — the channel endpoint must
track capabilities that transited through it so that revoking the endpoint
cascades to them.

#### Bootstrapping sequence

The share-back happens during kernel init, **before** virtio devices are probed:

1. Kernel early init (memory, page tables, CoCo detection) — no I/O needed
2. swiotlb pool allocation — simple memory reservation, no device access
3. Themis-specific init: ALIAS + MAP_SELF + CHANNEL_SEND — all are VMCALLs
4. Dom0/CHV accepts the shared alias
5. Only now does virtio probe begin (bounce buffers are accessible to CHV)

If the share-back fails, the guest panics with a clear error.

### 3.4 VTOM address mapping

The VTOM bit controls routing in the guest's page tables. `set_memory_decrypted()`
flips the VTOM bit → accesses go to the VTOM-offset GPA → hits alias_self's EPT
mapping:

```
Guest virtual address → Guest page table (PTE with VTOM bit) → GPA

  Private access:  GPA = 0x0200_0000                → dom1 EPT (guest_ram cap)  → HPA
  Shared access:   GPA = 0x80_0200_0000 (VTOM set)  → dom1 EPT (alias_self cap) → same HPA
```

Each GPA range has its own capability backing:
- `0x0200_0000` mapped by `guest_ram` (the original SEND from dom0)
- `0x80_0200_0000` mapped by `alias_self` (dom1's MAP_SELF)
- Dom0 accesses the same HPAs via `alias_parent` (received through channel)

---

## 4. Linux Kernel Patch: CC_VENDOR_THEMIS

### 4.1 Overview

A **~50 line patch** to the stock Ubuntu kernel adds Themis as a CoCo vendor.
The same kernel binary boots as dom0 (no CoCo, `CC_VENDOR_NONE`) or dom1
(`CC_VENDOR_THEMIS`, triggered by CPUID).

### 4.2 Patch locations

**`arch/x86/include/asm/coco.h`** — add vendor enum:
```c
enum cc_vendor {
    CC_VENDOR_NONE,
    CC_VENDOR_AMD,
    CC_VENDOR_INTEL,
    CC_VENDOR_THEMIS,   // <-- new
};
```

**`arch/x86/coco/core.c`** — add platform detection and mask operations:
```c
static bool noinstr themis_cc_platform_has(enum cc_attr attr)
{
    switch (attr) {
    case CC_ATTR_GUEST_MEM_ENCRYPT:
    case CC_ATTR_MEM_ENCRYPT:
        return true;
    default:
        return false;
    }
}

// In cc_platform_has():
case CC_VENDOR_THEMIS:
    return themis_cc_platform_has(attr);

// In cc_mkenc() — "encrypt" = make private = clear VTOM bit:
case CC_VENDOR_THEMIS:
    return val & ~cc_mask;

// In cc_mkdec() — "decrypt" = make shared = set VTOM bit:
case CC_VENDOR_THEMIS:
    return val | cc_mask;
```

**`arch/x86/coco/core.c` or `arch/x86/coco/themis.c`** — detection at boot:
```c
void __init themis_cc_platform_init(void)
{
    u32 eax, ebx, ecx, edx;

    /* Check for Themis hypervisor CPUID leaf (0x4000_0100) */
    cpuid(0x40000100, &eax, &ebx, &ecx, &edx);
    if (ebx != THEMIS_CPUID_SIGNATURE)  /* e.g., "ThCA" */
        return;

    /*
     * Opt-in: capavisor only synthesizes this CPUID leaf for domains
     * created with confidential=true. No kernel cmdline needed — if the
     * leaf is present, the domain is confidential. But we could add
     * themis_confidential=0 as an escape hatch for debugging.
     */
    cc_vendor = CC_VENDOR_THEMIS;
    /* eax = VTOM bit position (e.g., 39), set by CHV at domain creation */
    cc_mask = 1ULL << eax;

    pr_info("Themis confidential mode: VTOM bit %u, mask %#llx\n",
            eax, cc_mask);
}
```

Called from `arch/x86/kernel/setup.c` early init, alongside existing
`sev_setup_arch()` / `tdx_early_init()`.

### 4.3 What this enables automatically

Once `CC_VENDOR_THEMIS` is set and `cc_mask` is configured:

| Subsystem | Behavior | How |
|-----------|----------|-----|
| **swiotlb** | Allocates bounce buffer pool at boot | `cc_platform_has(CC_ATTR_MEM_ENCRYPT)` → true |
| **DMA** | All DMA goes through bounce buffers | swiotlb intercepts `dma_map_*` calls |
| **virtio** | Uses DMA API (→ bounce buffers) | Standard virtio-pci DMA path |
| **set_memory_decrypted()** | Flips VTOM bit in PTE | `cc_mkdec()` called on page table entries |
| **set_memory_encrypted()** | Clears VTOM bit in PTE | `cc_mkenc()` called on page table entries |

No virtio driver changes needed. No special guest configuration.

### 4.4 Kernel config requirements

```
CONFIG_ARCH_HAS_CC_PLATFORM=y     # Already enabled in Ubuntu kernels
CONFIG_SWIOTLB=y                  # Already enabled
CONFIG_VIRTIO_BLK=y               # Already enabled (or =m)
CONFIG_VIRTIO_NET=y               # Already enabled (or =m)
# New:
CONFIG_THEMIS_GUEST=y             # Gates the CC_VENDOR_THEMIS code
```

### 4.5 Keeping up with stock kernels

The patch is **purely additive** — it adds a new enum value and new `case` branches.
It does not modify any existing AMD/Intel code paths. Rebase strategy:

1. Maintain the patch as a git branch on top of Ubuntu's kernel tree
2. When Ubuntu bumps the kernel (e.g., 6.8.0-107 → 6.8.0-108), rebase the branch
3. Conflicts are unlikely unless upstream restructures `coco/core.c` (rare)
4. Long-term: propose upstream inclusion (CoCo framework is designed for multiple vendors)

---

## 5. Capavisor Changes

### 5.1 CPUID synthesis for confidential domains

When creating a child domain marked as confidential, the capavisor must:

1. Intercept CPUID leaf `0x4000_0100` in the child's VMEXIT handler
2. Return:
   - `EAX` = VTOM bit position (e.g., 39)
   - `EBX` = Themis signature (e.g., `0x54684341` = "ThCA")
   - `ECX`, `EDX` = reserved (0)
3. For non-confidential domains (dom0): return all-zeros (no Themis CoCo)

### 5.2 EPT enforcement: remove private HPAs from dom0

**This is the critical security enforcement.** Currently, dom0's EPT maps all
physical memory via the HHDM. When a domain receives exclusive memory, the
corresponding HPAs must be **unmapped from dom0's EPT**.

When the capavisor processes `Update::ChangeRights` with `rights = 0` for dom0
(triggered by SEND of a CARVE'd region):

```rust
// Current behavior: unmap the GPA from dom0's EPT
// This only removes the specific GPA mapping, but the HPA is still
// reachable through dom0's HHDM at a different virtual address.

// NEW behavior for confidential mode:
// Also remove the HPA from dom0's HHDM EPT range.
// Track which HPAs are "exclusive" to child domains.
fn enforce_exclusive_hpa(dom0_ept: &mut Ept, hpa: u64, size: u64) {
    // Find and unmap all dom0 EPT entries that map this HPA
    // (both the original GPA mapping AND any HHDM alias)
    let hhdm_gpa = hpa; // In dom0, GPA = HPA for HHDM
    dom0_ept.unmap_range(hhdm_gpa, size);
}
```

This requires the capavisor to:
- Know which HPAs are now exclusive (capability engine already tracks this)
- Walk dom0's EPT and remove all mappings to those HPAs
- Re-map when the exclusive capability is revoked (parent regains access)

### 5.3 MAP_SELF implementation

New hypercall: dom1 requests mapping of an owned capability at a specific GPA.

```rust
fn do_map_self(domain: &Domain, cap_handle: Handle, gpa: u64) -> Result<()> {
    // Validate: cap_handle must be owned by calling domain
    // Validate: GPA range must not overlap existing mappings
    // execute() validates through capability engine
    // apply_update() creates the EPT mapping: gpa → cap's HPA
    let update = Update::MapSelf { domain_id, cap_handle, gpa };
    apply_update(domain, update);
}
```

This is the mechanism dom1 uses to create the VTOM-offset mapping for alias_self.

### 5.4 Shared-window: processing the channel transfer

When dom1 sends alias_parent through the channel, the capavisor processes it as
a standard channel send. When dom0/CHV accepts it, `apply_update()` maps the
alias's HPAs into dom0's EPT at the GPA CHV specifies.

Private HPAs (not aliased back) remain absent from dom0's EPT.

### 5.4 DomainPolicy extension

Add a `confidential: bool` field to `DomainPolicy` (or a new `ConfidentialConfig`):

```rust
pub struct ConfidentialConfig {
    pub vtom_bit: u8,       // e.g., 39
    pub enabled: bool,
}
```

This is set at `CREATE_DOMAIN` time and stored in the domain's metadata.

---

## 6. Responsibility Split: Who Does What

### Overview diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         BOOT-TIME SETUP                                 │
│                                                                         │
│  CHV (userspace)            thhv.ko (driver)           Capavisor (L0)   │
│  ─────────────────          ──────────────────          ────────────── │
│                                                                         │
│  1. mmap guest RAM ───────► allocate contiguous  ────► (physical pages  │
│     via /dev/thhv            phys memory (hugetlb       reserved)       │
│                              or CMA)                                    │
│                                                                         │
│  2. write firmware,                                                     │
│     kernel, initramfs                                                   │
│     into guest RAM                                                      │
│                                                                         │
│  3. SET_GUEST_MEMORY ─────► relay to capavisor ──────► CARVE from dom0  │
│     (flag = CARVE for                                   + SEND to dom1  │
│      private RAM,                                       (dom0 loses     │
│      flag = ALIAS for                                    EPT access     │
│      MMIO/shared)                                        for CARVEd)    │
│                                                                         │
│  4. CREATE_PARTITION ─────► auto-create channel ─────► channel cap in   │
│     (confidential=true)      parent↔child               dom1's cap set  │
│                              (CHV does NOT see                          │
│                               the channel)                              │
│                                                                         │
│  5. first vCPU run ──────► SEAL + run ───────────────► dom1 starts      │
│                                                                         │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│                    DOM1 EARLY BOOT (inside guest)                        │
│                                                                         │
│  Dom1 kernel / Eunomia                     Capavisor (L0)               │
│  ─────────────────────                     ──────────────               │
│                                                                         │
│  6. CPUID 0x4000_0100 ──── VMEXIT ────────► return VTOM bit + sig      │
│     → CC_VENDOR_THEMIS                      (only for confidential      │
│                                              domains)                   │
│                                                                         │
│  7. allocate swiotlb                                                    │
│     bounce buffer pool                                                  │
│     (e.g. 64 MB at                                                      │
│      GPA 0x200_0000)                                                    │
│                                                                         │
│  8. ALIAS(guest_ram, ──── VMCALL ─────────► create alias cap            │
│     swiotlb_off, size)                      (child of guest_ram)        │
│     → alias_self                                                        │
│                                                                         │
│  9. ALIAS(guest_ram, ──── VMCALL ─────────► create alias cap            │
│     swiotlb_off, size)                      (child of guest_ram)        │
│     → alias_parent                                                      │
│                                                                         │
│  10. MAP_SELF(alias_self, ─ VMCALL ───────► map alias_self at           │
│      GPA|VTOM)                               GPA|VTOM in dom1 EPT      │
│                                                                         │
│  11. CHANNEL_SEND( ─────── VMCALL ────────► transfer alias_parent       │
│      chan_endpoint,                          to parent (dom0)            │
│      alias_parent)                                                      │
│                                                                         │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│                    SHARE-BACK COMPLETION                                 │
│                                                                         │
│  Capavisor (L0)                            Dom0 EPT                     │
│  ──────────────                            ─────────                   │
│                                                                         │
│  12. receives channel  ──── ChangeRights ──► map alias_parent           │
│      send from dom1          for dom0        HPAs into dom0             │
│                                              EPT (bounce                │
│                                              buffer only)               │
│                                                                         │
│      CHV's original mmap pointers now work again — the EPT              │
│      entries are restored for the bounce buffer sub-region.             │
│      No new ioctl or mmap needed.                                       │
│                                                                         │
│      ⚠ AddressMap overlap: dom0's Blocked range (from                   │
│        original CARVE) must allow sub-region insertion.                  │
│        See §6.4.                                                        │
│                                                                         │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│                    STEADY STATE                                         │
│                                                                         │
│  Dom1 (guest)                              Dom0 / CHV                   │
│  ────────────                              ──────────                  │
│                                                                         │
│  Private access:                           Can ONLY access:             │
│    GPA 0x0..0x3FFF_FFFF                     - bounce buffer region     │
│    (kernel, page tables,                      (alias_parent)            │
│     user pages — invisible                  - MMIO via EPT violation    │
│     to dom0)                                  forwarding                │
│                                                                         │
│  Shared access (DMA):                                                   │
│    GPA 0x80_0200_0000                                                   │
│    (VTOM bit set →                                                      │
│     hits alias_self EPT                                                 │
│     → same HPAs as                                                      │
│     bounce buffer)                                                      │
│                                                                         │
└──────────────────────────────────────────────────────────────────────────┘
```

### 6.1 CHV (cloud-hypervisor) — memory classification only

CHV's job is simple: **decide CARVE vs ALIAS per memory region**.

| Region type | Flag | Effect |
|-------------|------|--------|
| Guest RAM (private) | `flags = 0` (CARVE) | Dom0 loses access after SEND |
| MMIO regions (PCI BARs, LAPIC page) | `flags = THHV_MEM_F_ALIAS` | Dom0 retains access for device emulation |
| Shared meta pages (VpCommPage, etc.) | `flags = THHV_MEM_F_ALIAS` | Dom0 needs ongoing access |

CHV does **NOT** handle:
- Channel creation (thhv.ko does this automatically)
- Accepting shared regions back from dom1 (thhv.ko + capavisor handle this)
- VTOM configuration (capavisor synthesizes CPUID, guest kernel reads it)

**Memory allocation**: CHV's `mmap` for guest RAM should go through `/dev/thhv`
(or a thhv-provided mechanism) so the driver can attempt contiguous physical
allocation (hugetlb, CMA, or similar). This enables efficient 2M/1G EPT mappings
and satisfies IOMMU requirements (axiom A4: IOVA = GPA).

### 6.2 thhv.ko — automatic channel creation

When CHV calls `THHV_CREATE_PARTITION` with `confidential=true`:

1. thhv.ko relays the creation to the capavisor
2. **thhv.ko automatically creates a parent↔child channel** via a hypercall to
   the capavisor: `CREATE_CHANNEL(dom0, dom1) → dom0_endpoint, dom1_endpoint`
3. The child's endpoint is placed in dom1's initial capability set (discoverable
   at boot via a well-known handle or CPUID sub-leaf)
4. The parent's endpoint is stored in thhv's per-partition state

CHV is **unaware** of the channel. This keeps the VMM simple and ensures the
channel exists regardless of VMM implementation.

When dom1 sends an alias back through the channel:
- The capavisor processes the transfer (ChangeRights for dom0)
- thhv.ko receives a notification (poll/eventfd on the parent endpoint)
- thhv.ko exposes the shared region to CHV via an ioctl or mmap

### 6.3 Share-back: how dom0 regains access to bounce buffers

After CARVE+SEND, CHV's original `mmap` pointers still exist in dom0's process
page tables, but the EPT entries for those HPAs are gone. When dom1 sends an
alias back via channel, the capavisor handles all EPT changes through capability
operations (`apply_update`). The question is how CHV's userspace pointers become
usable again.

**Chosen approach: accept at same GPA (= HPA, identity mapping)**

The alias is accepted at `GPA = HPA` (the original physical address). The
capavisor restores the EPT entry at the original GPA → CHV's existing process
PTEs (VA → GPA) are still valid → the original mmap pointer works immediately.
No userspace changes needed.

**Required engine change: `unblock_subrange()`**

Currently, `accept()` calls `overlaps()` which rejects any insertion that
touches a Blocked entry. We need a new operation that allows "plugging a hole"
with the same physical memory:

```rust
/// Unblock a sub-range within a Blocked entry, converting it to Mapped.
///
/// The alias's HPA must match the corresponding HPA within the Blocked range
/// (same physical memory that was carved out). Splits the Blocked entry into
/// up to 3 parts:
///
///   Blocked(before) | Mapped(alias) | Blocked(after)
///
/// # Validation
/// - The sub-range [gpa, gpa+size) must fall entirely within one Blocked entry
/// - alias_hpa == blocked_hpa + (gpa - blocked_gpa)  ← same physical memory
///
/// # Errors
/// - No Blocked entry contains the range
/// - HPA mismatch (different physical memory — reject)
pub fn unblock_subrange(
    &mut self,
    gpa: u64,
    size: u64,
    alias_hpa: u64,
    rights: Rights,
) -> Result<(), &'static str>
```

This is ~30-40 lines. The building blocks exist: `block()` / `unblock()` handle
full entries, `split()` already splits Mapped entries. This adds a
`split_blocked()` variant + HPA validation.

**Semantics**: you can only plug a hole with the same physical memory that was
carved out. This preserves the security invariant — you can't trick a domain
into mapping different HPAs at a GPA it expects.

**Alternative considered: accept at different GPA**

Would avoid the engine change but requires thhv.ko to patch CHV's process page
tables (`remap_pfn_range()` or new mmap). More kernel complexity, less clean.
Rejected in favour of Option A.

### 6.4 Inter-domain shared memory (future: ivshmem-like)

For sibling domains (dom1 ↔ dom2, both children of dom0), the plan is an
**ivshmem-equivalent** device backed by capabilities:

- Dom0 creates a shared memory region (ALIAS from its own memory, or dedicated
  allocation)
- Dom0 sends aliases to both dom1 and dom2 via their respective channels
- Each child MAP_SELFs the alias into its address space
- Doorbell interrupts via existing interrupt injection (inject_via_pid)

This reuses the same ALIAS + CHANNEL + MAP_SELF primitives. The ivshmem-like
device model in CHV provides the familiar PCI BAR interface that existing
drivers expect. **Implementation deferred** — CoCo share-back comes first.

---

## 7. Guest-Side: Share-Back Protocol

The guest (Linux with CC_VENDOR_THEMIS, or Eunomia) performs the share-back
during early boot, **before** any virtio device probe.

### 7.1 Steps (same for Linux and Eunomia, different implementations)

1. **Detect CoCo**: CPUID leaf `0x4000_0100` → read VTOM bit position + signature
2. **Enable swiotlb**: allocate bounce buffer pool (Linux: automatic when
   `cc_platform_has(CC_ATTR_MEM_ENCRYPT)` returns true; Eunomia: manual)
3. **Create alias_self**: `ALIAS(guest_ram_handle, swiotlb_offset, swiotlb_size)`
4. **Create alias_parent**: `ALIAS(guest_ram_handle, swiotlb_offset, swiotlb_size)`
5. **MAP_SELF(alias_self, GPA | VTOM)**: creates the VTOM-offset EPT mapping in
   dom1's own address space
6. **CHANNEL_SEND(endpoint, alias_parent)**: transfers alias_parent to dom0;
   dom0/thhv receives it and maps the bounce buffer HPAs into dom0's EPT
7. **Virtio probe begins**: DMA goes through swiotlb → VTOM-mapped bounce
   buffers → CHV can access via alias_parent

### 7.2 Channel discovery

Dom1 must find its channel endpoint handle at boot. Options:
- **Well-known handle** (e.g., handle 1 is always the parent channel) — simplest
- **CPUID sub-leaf** (e.g., CPUID 0x4000_0101 returns channel handle) — flexible

Decision: TBD (well-known handle preferred for simplicity).

### 7.3 Linux implementation

In `arch/x86/coco/themis.c` (or equivalent early init):

```c
void __init themis_coco_shareback(void)
{
    phys_addr_t swiotlb_base = swiotlb_get_base();
    size_t swiotlb_size = swiotlb_get_size();

    /* Create two aliases of the bounce buffer */
    u64 alias_self = themis_vmcall(THEMIS_ALIAS, guest_ram, swiotlb_base, swiotlb_size);
    u64 alias_parent = themis_vmcall(THEMIS_ALIAS, guest_ram, swiotlb_base, swiotlb_size);

    /* Map alias_self at VTOM-offset GPA in our own EPT */
    themis_vmcall(THEMIS_MAP_SELF, alias_self, swiotlb_base | cc_mask);

    /* Send alias_parent to dom0 via channel */
    themis_vmcall(THEMIS_CHANNEL_SEND, channel_endpoint, alias_parent);
}
```

### 7.4 Eunomia implementation

Eunomia CoCo workload (`eunomia/workloads/coco/`): minimal version of the above
using direct VMCALL wrappers. Tests: verify MAP_SELF creates the VTOM mapping,
verify CHANNEL_SEND delivers the alias to dom0.

---

## 8. Implementation Plan

### Phase A: Kernel patch + detection ✅ done

1. ✅ CC_VENDOR_THEMIS kernel patch in `../linux`
2. ✅ CoCo guest kernel config (245 modules)
3. [ ] CPUID leaf `0x4000_0100` interception in capavisor (for confidential children)
4. [ ] Boot dom1 with CoCo kernel → verify `cc_platform_has()` → swiotlb active

### Phase B: CHV memory classification + driver channel

1. ✅ MAP_SELF engine + hypercall wired
2. [ ] CHV: classify regions as CARVE (private RAM) vs ALIAS (MMIO/shared)
3. [ ] thhv.ko: direct guest RAM allocation via driver (contiguous phys memory)
4. [ ] thhv.ko: auto-create parent↔child channel on CREATE_PARTITION(confidential)
5. [ ] Capavisor: wire CHANNEL_SEND / CHANNEL_RECV hypercalls
6. [ ] thhv.ko: receive alias from channel, expose to CHV

### Phase C: Guest share-back + end-to-end

1. [ ] Eunomia CoCo workload: ALIAS + MAP_SELF + CHANNEL_SEND
2. [ ] Linux dom1 early init: `themis_coco_shareback()` in arch/x86/coco/
3. [ ] End-to-end: dom1 boots confidential, swiotlb active, virtio works
4. [ ] Test: dom0 cannot read dom1 private memory after SEND

### Phase D: Hardening + sibling sharing

1. [ ] Revoke: verify clean teardown (all private HPAs returned to dom0 EPT)
2. [ ] Multi-vCPU: verify shared window works with 2+ vCPU dom1
3. [ ] ivshmem-like device for dom1↔dom2 shared memory
4. [ ] Attestation: include VTOM config and shared region list

---

## 9. Resolved Design Decisions

1. **VTOM bit position**: Orthogonal to capavisor/Themis — the capavisor only sees
   capabilities, not GPA layout. VTOM is a Linux + CHV concern. The capavisor
   reports the VTOM bit via CPUID leaf `0x4000_0100`, and CHV must have a path
   to configure it at domain creation time (passed through thhv ioctl). Default
   bit 39 for testing; CHV can set a different value per domain.

2. **Shared region size**: Handled entirely by the guest kernel via capabilities.
   Linux default swiotlb is 64 MB; the guest can allocate more with `swiotlb=N`.
   The capability engine imposes no limit — dom1 can alias as much of its own
   memory as it wants. Start with 64 MB default for initial implementation.

3. **MMIO regions**: Handled via capabilities. MMIO regions (PCI BARs, IOAPIC) are
   already intercepted by the capavisor as EPT violations. They don't need to be
   in the VTOM shared window — they go through hypercall-based device emulation.

4. **Firmware tables (ACPI) — separate shared memory slot**:

   ACPI tables live at `0xA0000–0xA1FFF` (EBDA region). The CoCo kernel accesses
   them with the VTOM bit set (marking them as shared/host-provided data), which
   means the CPU generates accesses to `GPA | (1 << VTOM_BIT)` — e.g.,
   `0x40_000A12B3` with VTOM bit 38. If only the base range is mapped in the EPT,
   this causes an EPT violation that cannot be emulated (it's RAM, not MMIO).

   **Solution**: CHV registers the firmware/ACPI region as a **separate memory slot**
   and double-maps it: once at the base GPA (`0xA0000`) and once at the VTOM-offset
   GPA (`0x40_000A0000`). Both point to the same backing memory. This is safe because:

   - The EBDA/ACPI region (`0xA0000–0xFFFFF`) is in the e820 gap — Linux marks it
     as "nosave" memory and never reclaims or repurposes it.
   - The region is small and fixed (≈8 KB of ACPI tables, within a 384 KB window).
   - CHV already knows where it places the tables (`RSDP_POINTER = EBDA_START`).

   In `create_user_memory_region`, when CHV registers the ACPI/firmware region, it
   issues **two** THHV_SET_GUEST_MEMORY calls: one for the base GPA and one for the
   VTOM-aliased GPA. The capavisor sees both as valid ALIAS mappings.

   **Scope**: Only the firmware data region needs double-mapping. Guest RAM (kernel,
   user pages) remains single-mapped — the guest handles its own VTOM mappings for
   shared regions (bounce buffers) via the MAP_SELF share-back protocol.

   **Alternative considered**: Double-map ALL guest RAM at the VTOM alias. Rejected —
   this defeats the purpose of CoCo (the parent would retain access to the full
   VTOM-aliased range). Only firmware data that the guest *must* access as shared
   gets the double-mapping.

5. **Debug/fallback**: Use **opt-in** rather than opt-out. The kernel does NOT
   enable CoCo by default when detecting the CPUID leaf. Instead, boot with
   `themis_confidential=1` (or equivalent) to explicitly enable confidential mode.
   This makes non-confidential the safe default for debugging.

6. **Upstream potential**: Acknowledged. The CC vendor framework is designed for
   extensibility. A well-structured patch can be proposed upstream once the model
   is proven and stabilized.

7. **Share-back mechanism**: Resolved as **self-channel** (not GRANT_PARENT).
   `get_chan_self(caller)` creates a channel whose target is the calling domain
   itself. Dom0 creates a self-channel, sends it to the sealed CVM, CVM accepts
   and uses it to send aliases back. Implemented and validated in tutorial 16.
   See `capa-cli/tutos/16-confidential-vm-vtom.txt` for the full working example.

8. **Channel revocation**: Already works through CDT — no new engine work needed.
   The alias sent through the channel is a CDT child of `guest_ram`. Revoking the
   CVM cascades: CVM → guest_ram → shared_buf (alias) → hypervisor loses it.
   Hypervisor can also revoke just its received alias (surgical teardown).

9. **Multi-region sharing**: Works naturally. CVM sends multiple aliases through the
   channel. Each is a separate `send` + `accept-capability` pair. No protocol needed.

## 10. Remaining Open Questions

1. **MAP_SELF semantics**: ✅ **Resolved.** MAP_SELF allows a sealed domain to
   remap one of its own capabilities at a chosen GPA. No overlap with existing
   mappings (after removing old footprint). No re-mapping into blocked ranges.
   Implemented using the refcounted projection model — see
   `address_translation.md` §13 for full design.  Per-right reference counts
   ensure removing one capability's contribution does not affect siblings/parent.

2. **Channel discovery at boot**: Dom1 needs to find its channel endpoint during
   early kernel init. How does dom1 know the handle? Options: (a) fixed well-known
   handle, (b) capavisor provides it via a CPUID sub-leaf, (c) dom1 enumerates
   its capability set. Decision: likely a well-known default handle.

---

## 11. References

- **Tutorial 16** (working CLI demo): [`capa-cli/tutos/16-confidential-vm-vtom.txt`](../../../../capa-cli/tutos/16-confidential-vm-vtom.txt)
- Linux CoCo framework: `arch/x86/coco/core.c`, `include/linux/cc_platform.h`
- VTOM in Hyper-V: [LKML patch series](https://lkml.org/lkml/2022/10/20/1008)
- mshv-themis driver design: [`docs/architecture/mshv-themis.md`](mshv-themis.md)
- Themis capability model: [`CONTEXT.md`](../../../../CONTEXT.md)
- Current CHV memory setup: `cloud-hypervisor/hypervisor/src/themis/mod.rs` (lines 438-475)
- swiotlb bounce buffer: `kernel/dma/swiotlb.c`
- virtio CoCo hardening: [LWN article](https://lwn.net/Articles/865216/)

---

## 12. Virtio notify via `THEMIS_RING_DOORBELL` (guest patch)

### Why

The pre-CoCo virtio kick path was `iowrite16(vq->index, notify_bar)`. That
triggers an `EPT_VIOLATION` which the capavisor used to resolve by reading
guest instruction bytes via a page walk (so the parent's iced-x86 could
decode), then forwarding to CHV userspace for ioeventfd dispatch.

That is wrong for two reasons:

1. **Capavisor must never decode guest instructions.** It is a hard
   invariant — for a confidential domain the capavisor cannot read guest
   code, and for any domain it is the parent's job (with information
   provided by the capavisor straight from the VMCS exit fields) to do
   any decoding. Tracked separately by `parent-side-mmio-emulation`.
2. **Latency.** Each kick = two VMCS swaps + iced-x86 dispatch. Slow
   enough that systemd generators time out (SIGALRM) during boot.

The Themis-native answer mirrors SEV-SNP's GHCB: the guest itself packages
the request and issues a hypercall, the host gets a fully resolved
notification with no decode required.

### Mechanism

The optimization is **decoupled from CoCo**: it is gated on a CPUID
feature bit so that non-confidential Themis guests benefit too (no
parent-side decode round-trip). Capavisor advertises capabilities via a
paravirt CPUID feature leaf, mirroring the KVM/Hyper-V layout:

| Leaf         | Always? | Content                                                     |
|--------------|---------|-------------------------------------------------------------|
| `0x40000000` | yes     | EAX = max leaf, EBX:ECX:EDX = `"ThemisCapa  "` (LE bytes)   |
| `0x40000001` | yes     | EAX = feature bitmap (see below)                            |
| `0x40000002` | yes     | DomainComm GPA + page count                                 |
| `0x40000003` | yes     | Capacity limits                                             |
| `0x40000004` | when ivshmem | Per-device subleaves                                   |
| `0x40000100` | confidential only | EAX = VTOM bit; EBX:ECX:EDX = `"ThemisCoCo  "`     |

Feature bits in EAX of `0x40000001` (see `themis_abi::cpuid::feature_bits`):

- bit 0 — `FEATURE_SYNC_SWITCH`
- bit 1 — `FEATURE_DOORBELL_HYPERCALL` — guest may use `THEMIS_RING_DOORBELL`
  in place of MMIO writes to virtio notify BARs

The guest reads `0x40000000` early in `setup_arch()`
(`themis_platform_init()` in `arch/x86/kernel/cpu/themis_platform.c`),
caches the bitmap, and the virtio modern transport flips its
`vp_notify` callback only when bit 1 is set. CoCo detection
(`0x40000100`) runs separately in `themis_coco_init()` and sets
`cc_vendor`. Memory-confidentiality and the doorbell path are now
orthogonal.

When the doorbell bit is set the guest's `vp_notify` swaps the MMIO
write for a `THEMIS_RING_DOORBELL` (opcode `0x23`) VMCALL carrying the
notify GPA and the queue index (or notification-data word for the
`VIRTIO_F_NOTIFICATION_DATA` path). Path:

```
guest THEMIS_RING_DOORBELL
   → capavisor matches GPA against the child PD's doorbell list
   → enqueues DoorbellNotify on the parent's DomainComm RX ring
   → forward_child_exit(THEMIS_EXIT_DOORBELL)
   → thhv drains the ring and signals the matching eventfd
   → CHV virtio backend runs the queue
```

No instruction decode anywhere; the GPA comes from the guest, equivalent
to how SEV-SNP packages MMIO requests inside the GHCB.

### Why the GPAs agree by construction

Doorbells are registered today through:

```
CHV register_ioevent  →  thhv THHV_IOEVENTFD  →  REGISTER_DOORBELL hypercall
                       →  capavisor pushes DoorbellEntry into the child PD
```

Both CHV and the guest compute the notify GPA the same way:

```
notify_gpa = notify_bar_base + queue_notify_off * notify_off_multiplier
```

from the standard virtio_pci notify capability. In the guest that is the
existing `pa` out-parameter of `vp_modern_map_vq_notify(mdev, index,
&pa)`.

### Guest-side code (linux fork, branch `v6.19.14-themis`)

- **`arch/x86/include/asm/themis_hcall.h`** (new) — inline
  `themis_ring_doorbell(gpa, value)` wrapping `vmcall` with the System V
  convention (RAX = opcode `0x23`, RDI = GPA, RSI = value, RAX = return).
  Opcode mirrors `themis_abi::opcodes::THEMIS_RING_DOORBELL`.

- **`arch/x86/include/asm/themis_platform.h`** (new) — public API for
  Themis paravirt detection: `themis_platform_init()`,
  `themis_on_themis()`, `themis_feature_bits()`, `themis_has_feature()`.
  Stubs out to `false`/`0` when `CONFIG_THEMIS_GUEST=n`. Mirrors the ABI
  signature constants and feature bits.

- **`arch/x86/kernel/cpu/themis_platform.c`** (new, gated on
  `CONFIG_THEMIS_GUEST`) — reads CPUID `0x40000000` for the signature
  and `0x40000001` for the feature bitmap; called from `setup_arch()`
  before `themis_coco_init()`.

- **`arch/x86/Kconfig`** — new `CONFIG_THEMIS_GUEST` symbol (default y if
  Themis CoCo); `CONFIG_THEMIS_COCO` now `select`s it.

- **`drivers/virtio/virtio_pci_common.h`** — `struct virtio_pci_vq_info`
  gains an optional `themis_notify_iomem` field (gated on
  `CONFIG_THEMIS_GUEST`) used to remember the per-vq ioremap so
  `del_vq` can release it cleanly. We need the side-band field because
  `vq->priv` is re-purposed in Themis mode (see below).

- **`drivers/virtio/virtio_pci_modern.c`**:
  - Includes `<asm/themis_platform.h>` and `<asm/themis_hcall.h>` under
    `CONFIG_THEMIS_GUEST`.
  - `themis_is_active()` returns
    `themis_has_feature(THEMIS_FEATURE_DOORBELL_HYPERCALL)`.
  - New static `themis_vp_notify` / `themis_vp_notify_with_data` call
    `themis_ring_doorbell((u64)(unsigned long)vq->priv, vq->index_or_data)`.
  - `setup_vq` picks the themis variants when `themis_is_active()`. After
    the existing `vp_modern_map_vq_notify(..., NULL)` it re-resolves with
    `&pa`, drops the per-vq ioremap (if `mdev->notify_base == NULL`) and
    stores it in `info->themis_notify_iomem` for later cleanup, then
    overwrites `vq->priv` with the GPA cast to `void *`.
  - `del_vq` releases `info->themis_notify_iomem` instead of treating
    `vq->priv` as iomem in Themis mode.

The legacy virtio_pci path is unchanged — cloud-hypervisor only exposes
the modern transport.

### Why `vq->priv` overloading

`vp_notify(vq)` only has the `struct virtqueue *` to work from, so the
per-vq state (iomem ptr today, GPA in Themis) must be reachable from
there. The two cases are mutually exclusive (selected by the
`FEATURE_DOORBELL_HYPERCALL` bit at probe time), so re-purposing the
existing field keeps the patch small and avoids extra per-vq
storage. The dual semantics are confined to `virtio_pci_modern.c`;
nothing outside the module touches `vq->priv`.

### Status

| Component                                        | Status    |
|--------------------------------------------------|-----------|
| CPUID base + feature leaf (`0x40000000` / `0x40000001`) | done |
| Capavisor `do_ring_doorbell` (`0x23`)            | done      |
| CHV `register_ioevent` → `REGISTER_DOORBELL`     | done      |
| Guest virtio notify swap (this section)          | done      |
| Non-Themis-aware fallback rewrite (`parent-side-mmio-emulation`) | pending |

### CHV-side fallback (non-Themis-aware guests)

For Themis guests where `FEATURE_DOORBELL_HYPERCALL` is unused (e.g. an
unmodified upstream kernel), kicks still EPT-violate. That path is
documented as broken-by-design and tracked by the
`parent-side-mmio-emulation` todo: capavisor must hand the parent RIP /
GPA / qualification straight from the VMCS exit fields, and the parent
decodes itself (capavisor must never decode guest instructions).

