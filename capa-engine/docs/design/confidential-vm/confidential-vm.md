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

### 3.3 Memory mapping flow

```
                     CHV (dom0 userspace)
                            │
                    THHV_SET_GUEST_MEMORY
                            │
                     ┌──────┴──────┐
                     │             │
              Private region   Shared region
              (CARVE + SEND)   (ALIAS, retained)
                     │             │
                     ▼             ▼
              dom1 EPT:        dom1 EPT:
              GPA [0..VTOM)    GPA [VTOM..2×VTOM)
              → HPA page       → same HPA page
                     │
                     ▼
              dom0 EPT:
              HPA REMOVED      HPA RETAINED
              from HHDM        in HHDM
```

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

    /* eax = VTOM bit position (e.g., 39) */
    cc_vendor = CC_VENDOR_THEMIS;
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

For the shared region (above VTOM), the capavisor maps the same HPAs at the
VTOM-offset GPA in dom1's EPT:

```rust
// For each shared region:
// Map at both private GPA and shared GPA (VTOM offset)
map_range(dom1_ept, gpa,          hpa, size, EPT_RWX);  // private view
map_range(dom1_ept, gpa | vtom,   hpa, size, EPT_RWX);  // shared view

// dom0 retains access only to the shared HPAs
// (private HPAs are removed from dom0's EPT per §5.2)
```

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

### 6.1 Memory region split

Currently, CHV sends all guest RAM as a single ALIAS region. For confidential mode:

```rust
// Private region: bulk of guest RAM
thhv_set_guest_memory(ThhvSetGuestMemory {
    guest_pfn: 0,
    size: ram_size,
    flags: 0,  // CARVE (not ALIAS)
    rights: THHV_MEM_R_READ | THHV_MEM_R_WRITE | THHV_MEM_R_EXEC,
    ..
});

// Shared region: small bounce buffer area (e.g., 64 MB at VTOM offset)
thhv_set_guest_memory(ThhvSetGuestMemory {
    guest_pfn: vtom >> PAGE_SHIFT,
    size: shared_size,
    flags: THHV_MEM_F_ALIAS,  // ALIAS — dom0 retains access
    rights: THHV_MEM_R_READ | THHV_MEM_R_WRITE,
    ..
});
```

### 6.2 Firmware/kernel loading

CHV writes firmware tables, kernel, and initramfs into guest memory **before**
SEND. This already works (the `ensure_initialized()` pattern defers SEND until
first vCPU run). No change needed.

### 6.3 Post-SEND device I/O

After SEND, CHV can only access the shared region. Virtio devices work because:
1. Guest kernel detects CoCo → enables swiotlb
2. Virtio DMA goes through bounce buffers in the shared window
3. CHV accesses virtio rings/data at VTOM-offset GPAs (which are ALIAS'd)

For MMIO devices (serial, RTC), the capavisor intercepts EPT violations and
forwards them — no guest memory access needed.

---

## 7. thhv.ko Changes

Minimal — the driver already supports CARVE and ALIAS. May need:

- A new flag `THHV_MEM_F_CONFIDENTIAL` or `THHV_CREATE_PARTITION` flag to signal
  confidential mode to the capavisor
- Pass-through of the VTOM bit in the partition creation ioctl

---

## 8. Implementation Plan

### Phase A: Kernel patch + detection (minimal, testable independently)

1. Create the ~50 line kernel patch (CC_VENDOR_THEMIS)
2. Add CPUID leaf `0x4000_0100` interception in capavisor (return VTOM config)
3. Boot dom1 with the patched kernel → verify `cc_platform_has()` returns true
4. Verify swiotlb is activated (`dmesg | grep swiotlb`)
5. Verify virtio still works (may break if bounce buffers allocated but shared
   window doesn't exist yet — that's expected, confirms detection works)

### Phase B: EPT enforcement

1. Implement `enforce_exclusive_hpa()` in capavisor — remove HPAs from dom0 HHDM
2. Implement re-map on revoke (parent regains access)
3. Test: dom0 should fault when accessing dom1's private memory through HHDM
4. Test: dom1 should still function (private memory accessible through its own EPT)

### Phase C: Shared window + full confidential boot

1. CHV splits memory: CARVE for private, ALIAS for shared
2. Capavisor maps shared window at VTOM offset in dom1's EPT
3. Boot dom1 → swiotlb uses shared window → virtio works
4. Test: dom1 boots to systemd login with confidential memory
5. Verify: dom0 cannot read dom1's kernel text, page tables, user data

### Phase D: Hardening

1. Attestation: include VTOM configuration in domain attestation report
2. Capability engine: ensure VITAL/META semantics work with split memory
3. Revoke: verify clean teardown (private HPAs returned to dom0 EPT)
4. Multi-vCPU: verify shared window works with 2+ vCPU dom1

---

## 9. Open Questions

1. **VTOM bit position**: 39 (512 GB boundary) seems reasonable for QEMU testing.
   Real hardware may want a different value. Should this be configurable per-domain?

2. **Shared region size**: How much shared memory does dom1 need? swiotlb default
   is 64 MB. Configurable via kernel cmdline `swiotlb=N`.

3. **MMIO regions**: Device MMIO (PCI BARs, IOAPIC) should be in the shared window.
   Currently mapped at fixed GPAs. Need to ensure they fall above VTOM or are
   handled separately.

4. **Firmware tables**: ACPI tables are written by CHV before SEND. Once private,
   the guest can read them but CHV can't update them. This is fine for static
   tables but may affect hotplug.

5. **Debug/fallback**: Should there be a `themis_confidential=0` kernel cmdline to
   disable CoCo even when the CPUID leaf is present? Useful for debugging.

6. **Upstream potential**: The CC vendor framework is designed for extensibility.
   A well-structured patch could be proposed upstream once the model is proven.

---

## 10. References

- Linux CoCo framework: `arch/x86/coco/core.c`, `include/linux/cc_platform.h`
- VTOM in Hyper-V: [LKML patch series](https://lkml.org/lkml/2022/10/20/1008)
- mshv-themis driver design: [`capa-engine/docs/design/mshv_themis/mshv_themis.md`](../mshv_themis/mshv_themis.md)
- Themis capability model: [`CONTEXT.md`](../../../../CONTEXT.md)
- Current CHV memory setup: `cloud-hypervisor/hypervisor/src/themis/mod.rs` (lines 438-475)
- swiotlb bounce buffer: `kernel/dma/swiotlb.c`
- virtio CoCo hardening: [LWN article](https://lwn.net/Articles/865216/)
