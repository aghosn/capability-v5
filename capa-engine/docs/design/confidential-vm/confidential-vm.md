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
  dom0: SEND(guest_ram, dom1)         ← dom0 loses ALL access
  dom0: SEAL(dom1)

Phase 2: Early guest boot (all in private memory, no I/O needed)
──────────────────────────────────────────────────────────────────────────
  dom1 kernel: early init, memory init, page tables
  dom1 kernel: detects CC_VENDOR_THEMIS via CPUID 0x4000_0100
  dom1 kernel: allocates swiotlb bounce buffer pool (e.g., 64 MB)

Phase 3: Share-back (guest grants VMM access to bounce buffer region)
──────────────────────────────────────────────────────────────────────────
  dom1 kernel: ALIAS(guest_ram, shared_region, swiotlb_size, RW)
  dom1 kernel: SEND_TO_PARENT(shared_alias)    ← via channel or new hypercall
  dom0/CHV:   receives alias → maps shared_region into its address space

Phase 4: Normal operation
──────────────────────────────────────────────────────────────────────────
  dom1: virtio uses DMA API → swiotlb bounces through shared_region
  dom0: CHV reads/writes virtio rings and data in shared_region only
  dom1: private memory (kernel, user pages) remains inaccessible to dom0
```

#### Capability tree after share-back

```
dom0 (root)
  └─ dom1 [sealed, confidential]
       ├─ guest_ram [0x0 .. 0x3FFF_FFFF]     ← private, dom0 has NO access
       │    └─ shared_alias [0x200_0000 .. 0x23FF_FFFF]  ← aliased back to dom0
       └─ ...
dom0 holds:
  └─ shared_alias (received from dom1 via channel)  ← RW access to bounce buffer
```

#### Child-to-parent capability transfer

The capability engine's `send` operation sends from parent to child. For the
reverse direction (dom1 sharing back to dom0), we have two options:

**Option A: Channel-based sharing** (works today)
1. Before sealing dom1, dom0 creates a channel between itself and dom1
2. Dom1 accepts the channel during boot
3. Dom1 sends the shared_alias through the channel to dom0
4. Dom0 receives and maps it

**Option B: New `GRANT_PARENT` hypercall** (cleaner, new capability operation)
1. New operation: `grant_parent(cap_handle, rights)` — creates an alias and
   sends it to the calling domain's parent
2. Simpler than channels for this specific use case
3. The parent receives the alias as a pending capability and accepts it

Option A requires no engine changes. Option B is more ergonomic but adds a new
operation to the capability engine. Both preserve the invariant that **the guest
controls what is shared**.

#### Bootstrapping consideration

The share-back happens during kernel init, **before** virtio devices are probed.
This works because:
- Kernel early init (memory, page tables, CoCo detection) needs no I/O
- swiotlb pool allocation is a simple memory reservation (no device access)
- The share-back hypercall is a VMCALL (no device I/O needed)
- Only after dom0 maps the shared region does virtio probe begin

If the share-back fails (dom0 doesn't accept, or channel not set up), the guest
falls back to non-confidential mode or panics with a clear error.

### 3.4 VTOM address mapping

Once the shared region is established, the guest kernel uses the VTOM bit to
direct I/O through it. The `set_memory_decrypted()` call flips the VTOM bit
in the page table entry, causing accesses to route through the shared-window
GPA range:

```
Guest virtual address → Guest page table (PTE with VTOM bit) → GPA

  Private access:  GPA = 0x0200_0000                → dom1 EPT → HPA (exclusive)
  Shared access:   GPA = 0x80_0200_0000 (VTOM set)  → dom1 EPT → same HPA (aliased)
```

The capavisor maps both GPA ranges in dom1's EPT to the same HPA. But only the
shared-window GPA's HPA is also present in dom0's EPT (via the alias dom1 sent back).

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

### 5.3 Shared-window EPT setup

When the capavisor processes dom1's ALIAS + SEND-to-parent (the share-back),
it maps the aliased region in dom1's EPT at the VTOM-offset GPA, and restores
the corresponding HPAs in dom0's EPT:

```rust
// Dom1 aliases a sub-region and sends it back to dom0:
// 1. dom1's EPT: map shared HPAs at VTOM-offset GPA too
map_range(dom1_ept, gpa | vtom, hpa, size, EPT_RW);  // shared view

// 2. dom0's EPT: restore access to shared HPAs (via alias received from dom1)
map_range(dom0_ept, alias_gpa, hpa, size, EPT_RW);   // dom0 can access again
```

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

## 6. Cloud-Hypervisor (CHV) Changes

### 6.1 Memory setup: send everything

In confidential mode, CHV sends **all** guest RAM as a single CARVE (not ALIAS).
Dom0 loses all access after SEND:

```rust
// All guest RAM: CARVE + SEND (dom0 loses access)
thhv_set_guest_memory(ThhvSetGuestMemory {
    guest_pfn: 0,
    size: ram_size,
    flags: 0,  // CARVE (not ALIAS)
    rights: THHV_MEM_R_READ | THHV_MEM_R_WRITE | THHV_MEM_R_EXEC,
    ..
});
```

### 6.2 Firmware/kernel loading (unchanged)

CHV writes firmware tables, kernel, and initramfs into guest memory **before**
SEND. This already works (the `ensure_initialized()` pattern defers SEND until
first vCPU run). No change needed.

### 6.3 Receiving the shared region

After dom1 boots and shares back its bounce buffer region (§3.3), CHV receives
the alias via the channel or grant mechanism. CHV then maps this region for
virtio device I/O:

```rust
// CHV receives shared_alias from dom1 (via channel accept or grant callback)
// Maps it for virtio ring/data access
let shared_region = accept_shared_from_guest(channel_fd)?;
// Now CHV can read/write virtio descriptors in this region only
```

### 6.4 Post-share device I/O

After receiving the shared alias, CHV can only access that specific region.
Virtio devices work because:
1. Guest kernel detects CoCo → enables swiotlb
2. Virtio DMA goes through bounce buffers in the shared window
3. CHV accesses virtio rings/data via the aliased region

For MMIO devices (serial, RTC), the capavisor intercepts EPT violations and
forwards them — no guest memory access needed.

---

## 7. thhv.ko Changes

Minimal — the driver already supports CARVE and ALIAS. Changes needed:

- A new flag `THHV_MEM_F_CONFIDENTIAL` or `THHV_CREATE_PARTITION` flag to signal
  confidential mode to the capavisor
- Pass-through of the VTOM bit in the partition creation ioctl
- **Channel or grant accept ioctl**: when dom1 shares back its bounce buffer
  region, CHV needs an ioctl to accept the incoming capability and map it:
  - Option A (channel): extend existing channel ioctls for memory cap transfer
  - Option B (grant): new `THHV_ACCEPT_GRANT` ioctl to accept pending caps

The driver does NOT need to understand confidential memory semantics — it just
relays flags to the capavisor and provides ioctls for CHV to accept shared regions.

---

## 8. Implementation Plan

### Phase A: Kernel patch + detection (minimal, testable independently)

1. Create the ~50 line kernel patch (CC_VENDOR_THEMIS)
2. Add CPUID leaf `0x4000_0100` interception in capavisor (return VTOM config)
3. Boot dom1 with the patched kernel → verify `cc_platform_has()` returns true
4. Verify swiotlb is activated (`dmesg | grep swiotlb`)
5. At this point virtio will break (bounce buffers allocated in private memory
   that dom0 can't access) — that's expected, confirms the detection works

### Phase B: Share-back protocol

1. Decide: channel-based (Option A) vs GRANT_PARENT hypercall (Option B)
2. If Option B: add `grant_parent` operation to capa-engine + tests
3. Implement kernel-side share-back: Themis-specific early init that allocates
   swiotlb pool, aliases it, and sends alias to parent
4. Implement CHV-side accept: receive alias, map shared region
5. Test: dom1 boots, shares back bounce buffer, CHV maps it

### Phase C: EPT enforcement + full confidential boot

1. Implement `enforce_exclusive_hpa()` in capavisor — remove HPAs from dom0 HHDM
   when memory is CARVE'd + SEND'd to a confidential domain
2. Implement re-map on revoke (parent regains access when domain is destroyed)
3. Boot dom1 → share-back → virtio works through shared bounce buffers
4. Test: dom0 cannot read dom1's kernel text, page tables, user data
5. Test: dom1 boots to systemd login with confidential memory

### Phase D: Hardening

1. Attestation: include VTOM configuration and shared region list in attestation
2. Capability engine: ensure VITAL/META semantics work with exclusive memory
3. Revoke: verify clean teardown (all private HPAs returned to dom0 EPT)
4. Multi-vCPU: verify shared window works with 2+ vCPU dom1
5. Malicious guest test: dom1 tries to alias more than it should — verify
   capability engine rejects (aliased region must be within owned range)

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

4. **Firmware tables**: ACPI tables are written by CHV before SEND and become private
   to dom1 after boot. If CHV needs ongoing read access to tables (e.g., for
   hotplug), dom1 can share them back as **read-only** aliases. The capability
   engine already supports `R` (read-only) rights on aliases.

5. **Debug/fallback**: Use **opt-in** rather than opt-out. The kernel does NOT
   enable CoCo by default when detecting the CPUID leaf. Instead, boot with
   `themis_confidential=1` (or equivalent) to explicitly enable confidential mode.
   This makes non-confidential the safe default for debugging.

6. **Upstream potential**: Acknowledged. The CC vendor framework is designed for
   extensibility. A well-structured patch can be proposed upstream once the model
   is proven and stabilized.

## 10. Remaining Open Questions

1. **Option A vs Option B for share-back**: Channel-based sharing (Option A, no
   engine changes) vs new `GRANT_PARENT` hypercall (Option B, new cap operation).
   See §3.3 for details. Decision needed before Phase B implementation.

2. **Opt-in mechanism details**: Is `themis_confidential=1` on the kernel cmdline
   sufficient, or should the CPUID detection itself be gated (e.g., capavisor only
   synthesizes the CPUID leaf if the domain was created with `confidential: true`)?
   If the latter, the kernel doesn't need a cmdline flag at all — detection is
   implicit.

3. **Multi-region sharing**: Can dom1 share back multiple disjoint regions (e.g.,
   swiotlb pool + a separate virtio-fs shared buffer)? The capability model
   supports this naturally (multiple ALIASes), but CHV needs a way to discover
   and map each one. Protocol design needed.

4. **VTOM and dom1's initial EPT**: When dom1 first boots, its EPT only has
   the private-window mappings (below VTOM). The shared-window mappings (above
   VTOM) get added when dom1 issues the ALIAS. But: who sets up the VTOM-offset
   EPT mapping — dom1 via hypercall, or does the capavisor infer it from the
   ALIAS operation? (The ALIAS target GPA tells the capavisor where to map.)

---

## 11. References

- Linux CoCo framework: `arch/x86/coco/core.c`, `include/linux/cc_platform.h`
- VTOM in Hyper-V: [LKML patch series](https://lkml.org/lkml/2022/10/20/1008)
- mshv-themis driver design: [`capa-engine/docs/design/mshv_themis/mshv_themis.md`](../mshv_themis/mshv_themis.md)
- Themis capability model: [`CONTEXT.md`](../../../../CONTEXT.md)
- Current CHV memory setup: `cloud-hypervisor/hypervisor/src/themis/mod.rs` (lines 438-475)
- swiotlb bounce buffer: `kernel/dma/swiotlb.c`
- virtio CoCo hardening: [LWN article](https://lwn.net/Articles/865216/)
