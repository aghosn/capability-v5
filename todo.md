## Real platform implementation and integration

**Goal**

Implement Themis (the capavisor) as described in the paper.
Themis uses the capability engine to maintain a state machine for domains that run on top of it and that Themis isolates using virtualization extensions (e.g., Intel VT-x).
It starts the initial domain, dom0 that acts as the root on the machine, i.e., the first domain owning the initial memory capabilities.

The goal here is to start a new implementation from scratch.
We can draw inspiration from `../vmxvmm/` that used a previous implementation of capabilities located at `../vmxvmm/crates/capability-engine/`.
However, the implementation (and semantics) are different and we want a clean implementation.

Themis should run (and boot) on bare-metal.
If we can, it'd ideally enable to target different platform (e.g., Intel and AMD to begin with).


**Differences with the previous implementation**

Many differences exist between the previous impl and the new one we want:

* The new implementation should use the capability engine from this folder.
* The new impl. should enable alloc in Themis and use heap allocation for capabilities. It should receive a memory region to use as the heap at boot.
* The new implementation should use crates where possible rather than reimplement everything.

* The general idea is the same, but the implementation is radically different and from scratch.

The general parts we will have are:

firmware -- loads --> bootloader --loads --> capavisor (themis in memory) & linux image somewhere so we can virtualize it.

The bootloader is the equivalent of our first stage, and should reserve some continuous memory for Themis + some space for its heap (configurable), provide information to Themis about the memory layout and where to find the linux img loaded in memory.
Themis will then initialize the capability engine, creating the first domain dom0 for the linux image, allocate the memory that it does not use to dom0 via the root memory capability, isolated it with the platform (creating the correct mappings etc.).

We will use the capability META for EPTs (aka SLATs) maintained by Themis.
So this will be part of the initialization too.

The result should be that Themis runs in bare-metal root mode on all cores and Linux boots on all cores in non-root mode initially.

## Development setup

We will need a virtualized development setup (like in `../vmxvmm/`) to develop and test our implementation. Ideally this should have support for debugging, correctly map the different binaries in memory to be able to debug root Themis and non-root Linux dom0.

---

## Q1: Using existing crates — Resolved Decisions

### Bootloader

**Decision: Use the Limine bootloader protocol (`limine` crate, crates.io).**

The [Limine protocol](https://github.com/limine-bootloader/limine) is the modern standard for bare-metal Rust kernels/monitors:
- Fully `no_std` compatible; requests declared as `#[used] static` structs.
- Provides everything Themis needs: physical memory map (unifying E820/UEFI), HHDM offset,
  SMP (`MpRequest`: all AP LAPIC IDs + `goto_address` callback for AP wakeup), RSDP physical
  address (entry point to the ACPI table hierarchy), loaded modules (capavisor binary + Linux
  bzImage), framebuffer, kernel virtual/physical base.
- AP bootstrap is handled by Limine (no INIT-SIPI-SIPI in Themis).
- Replaces the patched `bootloader` crate used by `vmxvmm/capavisor/first-stage/`.

```rust
// capavisor/src/main.rs — Limine requests (all zero-cost statics)
// Current state: BASE_REVISION, MEMMAP, HHDM, RSDP, MP are declared.
// ModuleRequest will be added in Phase 0.5c when module discovery is implemented.
static BASE_REVISION:   BaseRevision       = BaseRevision::new();
static MEMMAP_REQUEST:  MemoryMapRequest   = MemoryMapRequest::new();
static HHDM_REQUEST:    HhdmRequest        = HhdmRequest::new();
static RSDP_REQUEST:    RsdpRequest        = RsdpRequest::new();
static MP_REQUEST:      MpRequest          = MpRequest::new();
```

### VT-x / VMX

**Decision: Use the `x86` crate (crates.io, v0.52) as the primary VMX foundation;
extract the EPT implementation from `asterinas/hyperenclave` (Apache-2.0) for the EPT
mapper; use `verified-nrkernel` (Verus-verified) for Themis's own host page tables.**

The `x86` crate is the correct primary choice on maturity, trust, and control grounds:

- **`x86`** (crates.io, v0.52, MIT/Apache-2.0, `no_std`): the de-facto standard for bare-metal
  x86-64 CPU programming in Rust. Provides:
  - `x86::bits64::vmx`: unsafe wrappers for every VMX instruction — `vmxon`, `vmxoff`,
    `vmptrld`, `vmptrst`, `vmclear`, `vmread`, `vmwrite`, `vmlaunch`, `vmresume`.
  - `x86::vmx::vmcs`: complete VMCS field encoding constants.
  - Control registers (`Cr0`, `Cr3`, `Cr4`), MSRs (`rdmsr`, `wrmsr`), EFER, GDT/IDT
    descriptors, CPUID, paging constants, segment registers, x87/SSE state.
  - Widely used: referenced by dozens of real kernels, hypervisors, and OS-dev projects.
    Battle-tested surface with stable semantics.
  - Gives Themis full control over VMCS structure — no framework assumptions imposed.
  - Covers AMD primitives too (MSR constants for `VM_CR`, `HSAVE_PA`, EFER SVM enable bit).

#### EPT Page-Table Mapper

**Decision: Extract and use the EPT implementation from `asterinas/hyperenclave` (Apache-2.0)
directly. Do not use `axaddrspace` — the asterinas EPT is the only existing formally verified
EPT implementation in Rust and its source is available under a permissive license.**

`asterinas/hyperenclave` ([github.com/asterinas/hyperenclave](https://github.com/asterinas/hyperenclave))
is a production TEE hypervisor (used by Ant Group / Alibaba Cloud) whose EPT layer has been
formally verified at ASPLOS'24 using a custom Rust MIR → Coq formalization. The EPT source
is Apache-2.0. The extraction plan:

1. Identify the EPT module within `asterinas/hyperenclave` (the `src/memory/ept.rs` or
   equivalent — structures for PML4/PDPT/PD/PT entries, walk, map, unmap, `INVEPT` wrappers,
   permission encoding, memory-type attributes).
2. Extract it into `crates/ept/` within the Themis workspace, stripping the TEE/enclave-specific
   policy (e.g. enclave memory ownership checks) but keeping the page-table data structures
   and algorithms intact.
3. Adapt the frame-allocation hook to Themis's `FrameAllocator`.
4. The formal verification artifacts (Coq proofs) are not imported — we inherit the design
   correctness from the verified implementation, and the proof methodology is documented for
   future re-verification against Themis's specific invariants.

**Why not `axaddrspace`**: `axaddrspace` is unverified and adds abstraction layers that would
need re-verification anyway. The asterinas EPT source is concrete, directly inspectable, and
already carries the strongest correctness argument available in the Rust ecosystem for EPT.

**Note**: The asterinas EPT covers x86-64 EPT only. AMD NPT reuses the same extracted crate
(identical 4-level structure; only the root pointer registration differs — VMCB `N_CR3` vs.
`VMCS.EPT_POINTER`). See AMD SVM section.

**Note on `vmxvmm/crates/mmu/` reuse**: no longer needed. **Only `crates/vtd/`** from vmxvmm
remains a candidate for adaptation (no published VT-d crate exists).

#### Monitor Host Page Tables

Themis itself runs in VMX root mode with its own CR3 page tables (standard 4-level
x86-64 paging, not EPT). These page tables may need **dynamic modification at runtime**:
- **META capability regions**: when a parent domain registers a META region as a VP state
  mirror (see Q2 EVMCS-META section), Themis needs to map that physical page into its
  own virtual address space so it can write VP state to it on VMEXIT.
- **Frame allocator bookkeeping**: as physical frames are carved and sent to domains, the
  Themis may need to update its own mappings (e.g., unmapping pages from its HHDM view once
  they are exclusively owned by a child domain for confidentiality).
- **Per-VP structures** (VMCS, VAPIC page, PI descriptor): allocated dynamically and must be
  accessible to Themis in root mode.

**Decision: Use `verified-nrkernel` as the basis for Themis's host page tables.**

[`verified-nrkernel`](https://github.com/matthias-brun/verified-nrkernel) (ETH Zurich / CMU,
SOSP'24 Distinguished Artifact Award) provides a **Verus-verified** 4-level x86-64 host
page-table implementation with proofs of:
- Mapping correctness: the software page-table state matches the hardware MMU model.
- Spatial isolation: no two distinct virtual regions map to overlapping physical frames.
- Functional correctness of `map_frame` and `unmap_frame` against a high-level specification.

The implementation structure (`spec_t/hardware.rs` hardware model, `spec_t/hlspec.rs`
high-level spec, `impl_u/l2_impl.rs` verified implementation) is designed to be adapted.
The adaptation for Themis:

1. Import `verified-nrkernel`'s verified page-table implementation as a subtree in
   `crates/capavisor-pt/` (it is not on crates.io — git subtree or vendored copy).
2. Extend the hardware model (`spec_t/hardware.rs`) to account for Themis-specific invariants:
   - META pages: a frame mapped META is accessible by Themis AND visible in a child
     domain's EPT but with restricted rights. The host PT proof must track which frames are
     META-mapped.
   - HHDM identity region: the bulk of physical memory is identity-mapped in Themis's
     host PT; the proof should establish that HHDM mappings are never reused for other purposes.
3. The Verus proofs remain runnable (`verus capavisor-pt/`) and serve as a regression check
   when the page-table code changes (e.g., adding a new META mapping pattern).
4. In the non-proof compilation path (`cfg(not(verus))`), the same Rust code compiles
   normally into the capavisor binary — Verus annotations are erased.

**Why dynamic host PT modification matters for META**: when dom0 allocates a META capability
and registers it as a VP state mirror, Themis must map that physical page into root-mode
accessible memory (so it can write VP registers to it on every VMEXIT). This requires calling
`map_frame` in Themis's host PT at domain-seal time, and `unmap_frame` at
`on_domain_revoked` time. A verified implementation ensures these dynamic modifications
cannot violate the isolation invariants between other capavisor-internal structures.

#### Formal Verification of EPT

No crate currently combines crates.io publication + `no_std` + formal verification + EPT.
The landscape as of early 2026:

| Project | Verification tool | EPT coverage | Status |
|---|---|---|---|
| [`asterinas/hyperenclave`](https://github.com/asterinas/hyperenclave) | Custom Rust MIR → Coq | ✅ EPT spatial isolation proofs (ASPLOS'24) | **Primary choice** — Apache-2.0; extract EPT module |
| [`verified-nrkernel`](https://github.com/matthias-brun/verified-nrkernel) | Verus (SMT) | ❌ Host paging only | **Primary choice for capavisor host PT** — SOSP'24 Distinguished Artifact |
| [`asterinas/vostd`](https://github.com/asterinas/vostd) | Verus | ❌ Host paging | Alternative Verus reference if nrkernel adaptation proves difficult |

**Alternative: `x86_vcpu`** (crates.io, v0.2.2, Apache-2.0, `no_std`, ArceOS ecosystem):
Provides a higher-level vCPU framework (VMXON region management via `VmxArchPerCpuState`,
full VMCS lifecycle, `VmxExitReason` dispatch, EPT `invept`, per-VP register save/restore).
Internally depends on `x86`. Worth considering if we want to reduce boilerplate in the VMX
path — but it imposes the `AxVCpuHal` HAL trait and is much newer (first release August 2025,
~260 dl/month, used by 2 crates), so trust and maturity are lower. **AMD SVM feature is
declared but not implemented.** If the ArceOS SVM implementation matures, revisiting
`x86_vcpu` as the primary framework for the AMD path becomes attractive.

**Note on vmxvmm crates reuse**: `vmxvmm/crates/vmx` and `vmxvmm/crates/mmu/` are no longer
candidates — the asterinas EPT extraction and `x86` crate cover both. Only `crates/vtd/`
(VT-d IOMMU) from vmxvmm remains a candidate for direct adaptation.


### AMD SVM

**Decision: Not deferred — provide a concrete plan.** No production-quality `no_std`
bare-metal AMD SVM crate exists on crates.io yet, but viable paths exist.

#### Ecosystem Status (as of early 2026)

| Source | AMD SVM coverage | Usability |
|--------|-----------------|-----------|
| `x86_vcpu` v0.2.2 `svm` feature | Declared in `Cargo.toml`, **not implemented** — no `src/svm/` module, no VMCB types | Placeholder only; track upstream progress |
| `x86` crate v0.52 | Some AMD MSR constants (`EFER`, `VM_CR`, `HSAVE_PA`), no VMCB types, no `vmrun`/`vmsave`/`vmload` | Low-level primitives only |
| `not-matthias/amd_hypervisor` (GitHub, no crates.io) | **Complete VMCB** (`control_area.rs`, `save_area.rs`), NPT (Nested Page Tables), MSR bitmap, VMRUN assembly, exit-reason handlers | Windows kernel driver — depends on `winapi`; needs substantial adaptation to `no_std` |
| `tandasat/Hypervisor-101-in-Rust` (GitHub, UEFI) | Both Intel VMX and AMD SVM; bare-metal UEFI environment; more portable | Educational reference; not a reusable library |

#### Implementation Plan for AMD SVM

The `Platform` trait isolates all hardware virtualization; AMD support lives entirely in
`src/arch/amd64/svm.rs`. The plan is:

1. **VMCB types from scratch, guided by `not-matthias/amd_hypervisor`**: Define `VmcbControlArea`
   and `VmcbSaveArea` as `#[repr(C)]` packed structs matching AMD APM (AMD64 Architecture
   Programmer's Manual Vol. 2, §15). Use `not-matthias/amd_hypervisor` as a field-by-field
   reference; strip all Windows-specific allocator and FFI. Estimated ~600 LoC for the structs.

2. **VMRUN / VMSAVE / VMLOAD assembly stubs**: Implement `vmrun`, `vmsave`, `vmload`, and `stgi`/
   `clgi` (global interrupt enable/disable) as inline `asm!` or a tiny `.s` file. Reference
   `tandasat/Hypervisor-101-in-Rust` for the register save/restore discipline around VMRUN.

3. **Nested Page Tables (NPT)**: AMD NPT has the same 4-level structure and permission
   encoding as Intel EPT. `crates/ept/` (the asterinas extraction) can be reused almost
   unchanged — the primary difference is pointing the VMCB `N_CR3` field at the NPT root
   instead of `VMCS.EPT_POINTER`. No new mapper crate is needed.

4. **MSR permission bitmap**: ~8 KB bitmap, one bit per MSR, two bitmaps (read + write).
   Structurally identical to the Intel MSR bitmap; same allocation/init pattern.

5. **Monitor `Platform` dispatch**: `src/arch/mod.rs` picks `VmxPlatform` vs `SvmPlatform` at
   runtime via CPUID (bit `ECX[31]` for Intel VMX, bit `ECX[2]` for AMD SVM). Both implement
   `ArchPlatform` with `vmcs_setup`, `vm_entry`, `vm_exit_reason`, `invlpga` (TLB shootdown
   for NPT), etc.

6. **Interrupt delivery**: AMD AVIC (Advanced Virtual Interrupt Controller) is analogous to
   Intel APICv. The AVIC backing page and AVIC logical table are the SVM equivalents of the
   VAPIC page. Add `CpuFeatures::avic` detection; fall back to VMEXIT-based delivery if absent.

7. **Track `x86_vcpu` upstream for potential future adoption**: Once the ArceOS team
   implements the `svm` feature in `x86_vcpu`, evaluate replacing the hand-rolled
   VMCB/VMRUN code. Given `x86_vcpu`'s current immaturity (sub-year old, few users),
   the hand-rolled path is preferred for now.

#### Crate Dependencies for AMD Path

```toml
# x86 crate (already primary for Intel) covers AMD MSR primitives too
x86 = { version = "0.52", default-features = false }
# For NPT: reuse crates/ept/ (same page-table format as EPT)
# VMCB: hand-rolled from AMD APM reference; no external crate
```

### Other Architectures (ARM, RISC-V)

The ArceOS hypervisor ecosystem publishes per-architecture vCPU crates that mirror the
`x86_vcpu` approach: each crate wraps the architecture's hardware virtualization extension
behind a common `VCpu` trait, covering VM entry/exit, register save/restore, and
trap/exception routing.

| Architecture | Crate | Virtualization extension |
|---|---|---|
| ARM64 / AArch64 | `arm_vcpu` (crates.io) | ARMv8 Hypervisor Extension (EL2 / VHE), GIC-v3 interrupt virtualization |
| RISC-V | `riscv_vcpu` (crates.io) | RISC-V H-extension (hypervisor mode), IMSIC/APLIC interrupt virtualization |
| AMD x86_64 | `svm` / future `amd_vcpu` | AMD-V SVM (VMRUN/VMEXIT), nested page tables (NPT) |

**Integration path**: because Themis's `Platform` trait cleanly separates
architecture-specific hardware operations from the capability engine, adding a new
architecture means:
1. Implementing a new `src/arch/<arch>/` module using the corresponding `*_vcpu` crate.
2. Mapping the crate's VM entry/exit interface to Themis's VMEXIT handler dispatch.
3. Adapting the second-level address translation (EPT equivalent) to the architecture's
   format (Stage-2 page tables on ARM, G-stage on RISC-V) — using the `mmu` crate adapter
   or a new mapper.
4. Providing IRQ routing via the architecture's interrupt controller (GIC on ARM,
   PLIC/IMSIC on RISC-V) instead of the x2APIC + I/O APIC.

The `vmxvmm` reference already has a working RISC-V port (`monitor/themis` RISC-V target +
`riscv_tyche`, `riscv_pmp`, `riscv_sbi`, `riscv_csrs` crates) that serves as a reference
for the RISC-V `Platform` implementation.

### APIC / x2APIC

**Decision: Use the `x2apic` crate (crates.io, v0.5, `no_std`).**

- Provides `LocalApic` / `LocalApicBuilder` with runtime xAPIC/x2APIC detection.
- IPI sending: `send_ipi()`, `send_init_ipi()`, `send_sipi()`, `send_nmi()`.
- Local APIC timer: `enable_timer()`, `set_timer_mode()`, `set_timer_initial()`.
- I/O APIC: `IoApic` with redirection table entry management.
- Used for: reading LAPIC IDs at boot, sending shootdown IPIs, programming I/O APIC for
  physical interrupt routing, LAPIC timer for watchdog/preemption.

### ACPI Parsing

**Decision: Use the `acpi` crate (crates.io, rust-osdev, v6.1, `no_std` + `alloc`).**

Provides everything Themis needs from firmware tables:
- `PlatformInfo` from MADT: processor topology, local APIC/x2APIC IDs per core.
- `PciConfigRegions` from MCFG: PCIe ECAM base addresses per segment/bus range.
- `find_table("DMAR")`: locate the raw Intel VT-d DMAR table bytes (no high-level parsing
  of DMAR structures in the public API — see IOMMU section).
- `find_table("IVRS")`: AMD I/O Virtualization Reporting Structure (future).
- AML interpreter for DSDT/SSDT (needed for runtime device method evaluation).

Limine's `RsdpRequest` gives the RSDP physical address; `acpi::AcpiTables::from_rsdp` is
called with a physical-memory mapper implementing `acpi::AcpiHandler`.

### PCI/PCIe Enumeration

**Decision: Use `pci_types` (crates.io, rust-osdev, `no_std`) with ECAM from `acpi`.**

- `pci_types` provides typed config-space headers (`PciHeader`, `EndpointHeader`,
  `PciBridgeHeader`), BAR decoding, `CommandRegister`/`StatusRegister`, and the
  `ConfigRegionAccess` trait.
- Themis implements `ConfigRegionAccess` using volatile MMIO over the ECAM window whose
  base address is obtained from `acpi::PciConfigRegions`.
- Themis walks bus 0..255 / device 0..31 / function 0..7 to build a
  `Vec<PciDevice { addr, vendor, device, class, bars, capabilities }>` device table.
- This table is built at boot and drives IOMMU configuration and device assignment.

### IOMMU (Intel VT-d)

**Decision: Adapt `../vmxvmm/crates/vtd/` into the new workspace. No suitable public crate exists.**

The `vtd` crate from vmxvmm provides:
- `Iommu` struct: MMIO register access macros (`ro_reg!`, `rw_reg!`) for VT-d registers
  (version, capability, extended capability, root table address, context command, fault status,
  global command/status).
- `RootEntry` / `ContextEntry` types for the two-level device-context table.
- `enable_translation()`, `update_root_table_addr()`, `iter_fault()`.

We adapt it to:
- Parse DMAR table from `acpi::find_table("DMAR")` to discover DRHD units and RMRR regions.
- Build per-domain DMA remapping page tables (same second-level format as EPT, reusing the
  EPT mapper crate when possible).
- Program each DRHD unit's context table so that device DMA respects domain boundaries.

AMD AMD-Vi (IVRS): deferred, same pattern.

### Global Heap Allocator

**Decision: Use `linked_list_allocator` (crates.io, `no_std`) as `#[global_allocator]`.**

Backed by a contiguous physical memory region carved from the Limine memory map at boot
(e.g. 64 MB). This region is excluded from `r0` (never exposed to any domain). With the
heap active, the capability engine's `Arc`, `BTreeMap`, `Vec` work out of the box.

---

## Q2: dom0 Driver, Cross-Core Interrupt Routing, and EVMCS-Inspired META Regions

### Background and Motivation

The original design assumed dom0 Linux would create child domains via **KVM** (QEMU/LKVM as
the VMM). This has structural problems: KVM tightly couples the hypervisor to the Linux
scheduler and memory management, QEMU/LKVM carry massive attack surface, and the TCB boundary
becomes unclear when dom0's kernel path to VMX hardware is not under Themis's control.

The alternative explored here is a **Themis-native** approach that draws inspiration from
MSHV/Hyper-V concepts without aiming for protocol compatibility. The goal is:
1. A thin Linux kernel driver (`themis-vmm.ko`) that exposes domain management to userspace
   in dom0 (and recursively to any domain that has child-creation capabilities).
2. An interrupt routing architecture that protects confidential-domain cores from spurious
   exits.
3. A SynIC-inspired inter-domain notification protocol.
4. An EVMCS-inspired META region mechanism for low-overhead VP state access.

### MSHV as Design Reference (not Compatibility Target)

The Linux `drivers/hv/mshv_root_main.c` and friends implement Linux as a **root partition**
sitting atop Microsoft's Type-1 hypervisor. The driver exposes `/dev/mshv` and provides:
- Partition (VM) create/destroy, memory region mapping, VP create/run/destroy.
- A per-VP `hv_message` intercept page (VP suspend reason delivered without a syscall).
- Fast-path interrupt injection via a per-VP **register page** mmap (zero hypercall if the
  partition has `HV_VP_DISPATCH_INTERRUPT_INJECTION_AVAILABLE`).
- irqfd/ioeventfd for device IRQ and I/O event delivery without poll loops.

**Important**: the existing mshv driver and cloud-hypervisor's mshv backend are *clients* of
an already-running Hyper-V — they do not implement a hypervisor. Themis must implement the
*hypervisor* side, then provide a driver to dom0 that looks structurally similar to mshv_root.

**cloud-hypervisor** (using its `mshv` feature, `mshv-ioctls`/`mshv-bindings` crates) is the
VMM of choice for dom0: smaller TCB than QEMU, Rust, confidential-VM support (SNP/IGVM via the
mshv backend), virtio, PCIe, VFIO, live migration. It could target `/dev/themis` with a thin
backend adaptation, or `/dev/mshv` if we implement a close-enough shim. This is a separate
decision from the driver design.

### Themis-VMM Driver Model

`themis-vmm.ko` is a thin Linux kernel module that:
1. Detects Themis at boot via CPUID hypervisor leaf (Themis sets a custom vendor string).
2. Exposes `/dev/themis` with an ioctl interface for domain/VP lifecycle and memory management.
3. Translates ioctl operations into Themis hypercalls (`VMCALL`).
4. Is recursive: any domain that holds child-creation capabilities (not only dom0) can load a
   driver instance and manage its own children. The driver model is uniform across the hierarchy.

| ioctl operation | Themis hypercall(s) | Notes |
|---|---|---|
| `THEMIS_CREATE_DOMAIN` | `VMCALL_CARVE` + `VMCALL_CREATE_DOMAIN` | Allocates domain handle |
| `THEMIS_MAP_MEMORY` | `VMCALL_CARVE` + `VMCALL_SEND` | GPA region → child domain |
| `THEMIS_INIT_DOMAIN` | `VMCALL_SEAL` | Finalizes domain; allocates VMCS/VAPIC |
| `THEMIS_DELETE_DOMAIN` | `VMCALL_REVOKE_DOMAIN` | Full subtree revoke |
| `THEMIS_CREATE_VP` | part of `VMCALL_SEAL` or separate `VMCALL_CREATE_VP` | Per-VP VMCS |
| `THEMIS_RUN_VP` | `VMCALL_SWITCH` | Blocks until intercept |
| `THEMIS_GET_VP_REGS` | `VMCALL_GET_REG` or META page read | See EVMCS-META section |
| `THEMIS_SET_VP_REGS` | `VMCALL_SET_REG` or META page write | See EVMCS-META section |
| `THEMIS_IRQFD` | kernel-side: eventfd → interrupt injection | Posted interrupt path |
| `THEMIS_IOEVENTFD` | kernel-side: MMIO/PIO write → eventfd | I/O notification path |

The VP intercept reason (exit cause, faulting GPA/RIP, etc.) is delivered via a per-VP
**intercept message page** that Themis writes before suspending the VP. The driver mmaps this
page to the THEMIS_RUN_VP caller's userspace buffer — same pattern as `hv_message` in mshv,
avoiding a copy through kernel ioctl return buffers.

### Cross-Core Interrupt Routing

#### Motivation

When a physical interrupt arrives on a core running a confidential domain, the naive response
is to VMEXIT and context-switch to dom0 on that same core so dom0 can decide how to handle it.
This is problematic:
- dom0's execution state would land on a core dedicated to a confidential domain — a policy
  violation in the stronger isolation model.
- The confidential core's TLB and cache state gets polluted by dom0's working set.
- If dom0 determines the interrupt should be re-delivered to the original domain, a full
  VMCS reload back to the domain is needed.

The alternative: **keep the confidential domain's core suspended inside Themis** while the
interrupt decision is offloaded cross-core to a dom0 core, then resume in-place.

#### Mechanism

```
[Core X — running confidential domain]
        │
        │  Physical interrupt arrives (EXTERNAL_INTERRUPT VMEXIT)
        │  OR interrupt is not deliverable to the current domain (policy)
        ▼
[Themis on core X — does NOT switch to dom0 locally]
        │
        1. Write interrupt info into per-VP META page (vector, source, IRQ state).
        2. Set PENDING_IRQ bit in VP META page header (atomic).
        3. Post a virtual interrupt to the dom0 VP on the dom0 core:
              set PIR[tyche_irq_notification_vector] in dom0 VP's PI descriptor,
              send NV IPI to dom0 core's LAPIC.
              → dom0's APICv hardware delivers the notification; no VMEXIT on dom0 core.
        4. Core X spins in Themis (a tight poll loop on PENDING_IRQ flag in VP META page).
           The confidential domain VP is suspended; dom0 never runs on core X.
        │
        ▼ (cross-core: dom0 core receives virtual interrupt, handles notification)
[Dom0 on dom0 core — Themis IRQ notification handler]
        │
        ├── Read interrupt info from VP META page of the suspended domain VP.
        │
        ├── IrqRouter::resolve(domain, vp, vector):
        │     Case A — interrupt belongs to the domain (e.g. assigned device):
        │         1. Write PIR[vector] bit in domain VP's PI descriptor (inside META page).
        │         2. Set RESUME_WITH_IRQ bit in VP META page header.
        │
        │     Case B — interrupt is for dom0 (device dom0 owns, timer, NMI, etc.):
        │         1. Dom0 handles the interrupt locally (its own interrupt handler runs).
        │         2. Set RESUME_NO_IRQ bit in VP META page header.
        │
        └── In both cases: the dom0 core updates the META page and returns to its own VM.
        │
        ▼ (core X polls detect the RESUME_* bit)
[Themis on core X — resumes]
        │
        ├── Case A: PI descriptor has PIR[vector] set → hardware delivers on VMRESUME,
        │          no extra work. Zero VMEXIT on VMRESUME if APICv priority allows.
        │
        └── Case B: VMRESUME domain VP with no pending interrupt; domain continues.
```

Key properties:
- **dom0 never executes on core X** — the confidential domain's core only ever runs Themis
  (the TCB) or the confidential domain itself.
- **Core X blocks in Themis** during the cross-core round-trip. This is a latency tradeoff
  (cross-core IPI + dom0 handler) acceptable for infrequent interrupt events on confidential
  cores. Frequent high-throughput interrupts (e.g., virtio queues) should be assigned to
  non-confidential domains.
- **dom0 core is not disturbed by a VMEXIT** — the posted interrupt NV IPI delivers into dom0's
  guest context directly via APICv, so the dom0 VP receives it as a virtual interrupt without
  any VMEXIT or Themis involvement on the dom0 side.
- **PI descriptor and resolution bits** all live in the per-VP META page, which the dom0 core
  can access as the parent domain's META capability. No additional shared-memory mechanism is
  needed beyond what the EVMCS-META design already provides.

#### When This Path Is Not Taken

Not every interrupt on a confidential core needs the cross-core path:
- If the interrupt policy for the domain is `DELIVER` (the domain handles all its interrupts
  itself — e.g., dom0, or a non-confidential driver domain), the conventional path applies:
  Themis injects via VIRR/PI and VMRESUMEs immediately on the same core.
- The cross-core path activates only when the policy is `DEFER_TO_PARENT` or
  `REPORT` and the domain is marked confidential. This is a per-VP capability attribute set
  at domain creation.
- NMIs always exit to Themis directly (cannot be posted); Themis handles them without dom0.

#### Physical LAPIC EOI and ISR State

This is a fundamental hardware constraint that must be handled correctly and is separate from
all virtual APIC management.

**How the physical LAPIC works on an EXTERNAL_INTERRUPT VMEXIT:**

When a physical interrupt is delivered to core X's LAPIC and causes a VMEXIT:
1. The LAPIC moves the bit from **IRR** (Interrupt Request Register) to **ISR** (In-Service
   Register) for that vector. The interrupt is now "in service" from the LAPIC's perspective.
2. The VMEXIT fires. The physical interrupt vector is recorded in `VM_EXIT_INTR_INFO`.
3. **No EOI has been written.** The LAPIC ISR bit remains set.
4. While ISR is set, the LAPIC will not deliver another physical interrupt at the same or
   lower priority level to this core. Higher-priority interrupts can still arrive.

**Themis must write physical EOI immediately on EXTERNAL_INTERRUPT VMEXIT, before parking:**

```rust
// In Themis's EXTERNAL_INTERRUPT VMEXIT handler on core X, first thing:
unsafe {
    // x2APIC: write 0 to EOI MSR (0x80B)
    x86::msr::wrmsr(x86::msr::IA32_X2APIC_EOI, 0);
    // xAPIC fallback: volatile write to LAPIC MMIO base + 0xB0
}
// NOW the physical LAPIC ISR is clear. Safe to park with CLI.
```

Writing physical EOI immediately:
- Clears the ISR bit → same/lower-priority physical interrupts can arrive again.
- For level-triggered interrupts: sends an EOI broadcast to the I/O APIC, de-asserting the
  IRQ line. Without this, the device continues to assert and the I/O APIC keeps requesting
  the interrupt — it will re-fire immediately on any other core it's routed to.
- This is completely independent of any virtual APIC (VAPIC page) state. The physical EOI
  must be written regardless of whether APICv is active.

**What happens to interrupts accumulating in IRR during the park:**

After writing physical EOI, Themis parks on core X with `CLI` (interrupts disabled in root
mode). New physical interrupts can still arrive and will be latched in the LAPIC **IRR**
(the LAPIC's IRR is not gated by `IF` — it accepts arrivals regardless). They will not be
delivered to the CPU while `IF=0`, but they are not lost.

On `VMRESUME`, the guest's `RFLAGS.IF` is restored from VMCS guest state. If the guest
has `IF=1` and `EXTERNAL_INTERRUPT` exiting is still active, any pending IRR bits will
cause an immediate new VMEXIT on the first instruction boundary. This is correct and
expected — each such VMEXIT goes through the same cross-core resolution path.

**Virtual EOI and the two-layer separation:**

With APICv virtual-interrupt delivery, there are two entirely separate EOI paths:

| Layer | What it acknowledges | Who writes it | When |
|---|---|---|---|
| **Physical LAPIC EOI** | Physical interrupt that caused VMEXIT (ISR bit, level-triggered line) | **Themis** in root mode | Immediately on EXTERNAL_INTERRUPT VMEXIT, before any other action |
| **Virtual APIC EOI** | Guest-visible interrupt in VAPIC ISR (the bit in the virtual ISR page) | **The domain guest** via LAPIC EOI write to VAPIC page | After the guest's interrupt handler finishes |

When the domain guest writes virtual EOI to the VAPIC page, APICv hardware:
1. Clears the highest-set bit in the VAPIC ISR.
2. If the vector has an EOI-exit bitmap entry: causes `EOI_INDUCED_VMEXIT` (so Themis can
   e.g. notify parent or count events).
3. For level-triggered virtual interrupts: sends an EOI broadcast to the I/O APIC.
4. **Does NOT write to the physical LAPIC EOI register again** — that was already done by
   Themis at VMEXIT time. The virtual EOI only affects the VAPIC page state.

For dom0 running with a virtualized APIC: same rules apply. Dom0's guest writes virtual EOI
→ APICv clears VAPIC ISR → EOI broadcast if level-triggered. The physical LAPIC EOI for any
interrupt that caused a dom0 EXTERNAL_INTERRUPT VMEXIT must also be written by Themis before
handing control to dom0. If dom0's interrupts are handled via posted interrupts (NV path,
never an EXTERNAL_INTERRUPT VMEXIT), the hardware writes EOI for the NV IPI automatically
as part of posted-interrupt processing — no Themis involvement needed.

**NV IPI physical EOI (posted interrupt notification vector):**

When Themis sends the NV IPI to the dom0 core to notify it of the pending interrupt from
core X, the dom0 core's LAPIC receives a physical interrupt (the NV IPI). APICv handles this
case automatically: the CPU recognizes the NV and processes the posted interrupt without a
VMEXIT, and writes physical EOI for the NV IPI as part of that hardware processing. Themis
does not need to handle this EOI explicitly.

#### Interaction with APICv / AVIC

For dom0 notification (step 3 above):
- `VMCS.POSTED_INTR_DESC_ADDR` for dom0 VP has a dedicated NV for Themis-to-dom0 notifications.
- `PIR[tyche_irq_notification_vector]` bit set + NV IPI → hardware delivers to dom0 VP.
- Dom0's virtual interrupt handler (in `themis-vmm.ko`) reads the queue and dispatches.

For domain re-delivery (case A above):
- `PIR[vector]` set in the domain VP's PI descriptor (inside the VP META page).
- On VMRESUME on core X: CPU merges `PIR` → `VIRR` atomically, delivers interrupt to domain.
- Zero additional VMEXIT if the interrupt priority exceeds current `TPR`.

Without APICv fallback: Themis on core X injects via `VM_ENTRY_INTR_INFO` directly; the
cross-core path still works but the dom0 notification uses a regular IPI causing a VMEXIT
on the dom0 core instead of the posted-interrupt path.

#### Parking on Core X with CLI

Themis can park on core X with **interrupts disabled** (`CLI`). This is viable because:
- Physical EOI was already written immediately on VMEXIT (see above), so the LAPIC ISR is clear.
- New physical interrupts that arrive during the park are latched in the LAPIC **IRR** (the
  IRR accepts arrivals regardless of `IF`), but they will not be delivered to the CPU. They are
  not lost — on the next `STI` or `VMRESUME` they will be dispatched.
- The physical LAPIC state for the original interrupt has already been fully acknowledged.

The park loop is therefore simple:

```rust
// Core X parked in Themis with CLI — no IDT handlers needed during park.
// Physical EOI already written. LAPIC IRR may accumulate; handled on VMRESUME.
loop {
    // Cross-core barriers: must participate even with CLI.
    // These are driven by polling shared atomic flags, not by IPI delivery.
    platform.poll_and_respond_cross_core();

    // Check for resume signal written by dom0 core.
    let status = vp_meta.status.load(Ordering::Acquire);
    if status & (RESUME_WITH_IRQ | RESUME_NO_IRQ) != 0 {
        break;
    }
    core::hint::spin_loop();
}
// VMRESUME: guest RFLAGS.IF restored from VMCS. Any IRR bits pending in the
// LAPIC will cause a new EXTERNAL_INTERRUPT VMEXIT on the first opportunity.
// Each such VMEXIT is handled normally through the same cross-core path.
```

**Cross-core barriers with CLI**: the `poll_and_respond_cross_core` loop uses shared
atomics (not IPI delivery) for the acknowledgment phase — core X checks a per-core flag
written by the initiating core, performs its local action (e.g. `INVEPT`), and increments
an acknowledgment counter. No interrupt delivery is needed; CLI does not break this.
The initiating core spins waiting for all ack counts; it does not deadlock as long as core
X keeps polling, which the park loop guarantees.

**NMI**: NMI (`#2`) is non-maskable and will fire regardless of `IF`. Themis's NMI IDT
handler must be installed and must write EOI (NMI EOI is handled separately via `IRET`
re-enabling the NMI window) and either panic or record a watchdog event. This is true in all
Themis root-mode contexts, not specific to the park path.

**Ordering guarantee**: dom0 core writes the interrupt decision to the META page with
`Release` semantics, then sends a resume IPI. Core X reads the META page with `Acquire`.
The resume IPI itself is not strictly needed since core X is spinning (not halted), but
it ensures timely wakeup if core X is ever extended to use `HLT` in the park loop.

### TychIC: Themis-Native Synthetic Interrupt Controller

Rather than emulating APIC hardware to every domain, Themis can expose a **TychIC** —
a lightweight, capability-aware synthetic interrupt model.

Each VP has two Themis-managed pages (both META regions, described below):
- **Intercept page**: written by Themis when a VP is suspended; carries exit reason, faulting
  address, register snapshot. Read by the parent driver without a hypercall.
- **Event flag page** (shared between parent and child): a 4 KB bitmap, one bit per
  "notification slot". Parent sets bits to signal events to the child; child reads/clears
  them. Used for virtio-style kick notifications, domain wakeup, and channel-based IPC.

**Doorbell mechanism**: a write by a domain to a Themis-reserved GPA range (intercepted as an
EPT violation) triggers a lightweight "doorbell" VMEXIT. Themis routes the doorbell to the
registered notification slot in the target domain's event flag page and posts an interrupt to
the target VP. This is the equivalent of Hyper-V's doorbell ports, enabling high-throughput
cross-domain signalling without a VMCALL from the signalling side.

**Interrupt channels**: a parent can register a `(child_vp, notification_slot, vector)` tuple
with Themis. When the child VM writes to the slot-associated GPA, Themis translates it to a
vector injection into the child VP — the parent never needs to be involved in the delivery
path. This enables clean device interrupt virtualization for driver domains without the parent
domain being on the hot path.

### EVMCS-Inspired META Regions for VP State

#### Background: Intel EVMCS

When dom0 runs cloud-hypervisor (or any nested hypervisor), dom0 issues `VMLAUNCH`/`VMRESUME`
for its child VMs. Normally, every `VMREAD`/`VMWRITE` issued by dom0 for its nested VMCS
causes a VMEXIT to Themis (because dom0 is non-root and VMCS accesses trap). Intel EVMCS
(Enhanced VMCS) solves this: Themis allocates a 4 KB **EVMCS page** (a shared memory page),
writes a pointer into `VMCS.VMCS_LINK_POINTER`, and both Themis and dom0 can access the nested
VMCS fields through this shared page — eliminating the VMREAD/VMWRITE exits entirely.

#### Themis Generalization: META VP-State Regions

The `META` capability type already captures the key semantic: a META region is given to a
child domain's EPT (for page-table backing memory), but the **parent retains access** to it —
it is never fully transferred. This same property can be exploited for VP state sharing.

**Proposed extension**: a parent domain can designate a `META` capability region (4 KB,
4 KB-aligned) as the **VP state mirror** for a specific child VP:

```
# In capability-engine terms (parent's cap table):
carve r0 → vp_state_meta   (4 KB, META flag)
register_vp_meta child_domain vp_id vp_state_meta
```

Themis then:
1. Maps `vp_state_meta` into the parent's address space at a known offset (parent retains
   read/write access — it is the parent's META region, the child never sees it).
2. Uses this page as a **mirror** of the VP's key register state: on every VMEXIT from the
   child VP, Themis writes `{RIP, RSP, RAX-R15, CR3, RFLAGS, exit_reason, exit_qual}` into
   the page before returning to the parent.
3. For the parent's `THEMIS_GET_VP_REGS` ioctl: read directly from the mapped page — **zero
   hypercall cost** when the VP is not running.
4. For the parent's `THEMIS_SET_VP_REGS` ioctl: write to the page; Themis picks up the values
   at next VMENTRY via a dirty flag in the page header — **zero hypercall cost** for the common
   case of setting registers between THEMIS_RUN_VP calls.
5. For EVMCS-style nested VMX: when cloud-hypervisor inside dom0 issues `VMREAD`/`VMWRITE`
   for a nested VMCS, Themis can consult/update the child VP's `vp_state_meta` page rather
   than intercepting each instruction individually — reducing nested VMX overhead.

**Page layout** (proposal):

```rust
#[repr(C)]
pub struct VpStateMeta {
    // Written by Themis on VMEXIT; read by parent without hypercall.
    rip: u64, rsp: u64, rflags: u64,
    rax: u64, rbx: u64, rcx: u64, rdx: u64,
    rsi: u64, rdi: u64, rbp: u64,
    r8: u64,  r9: u64,  r10: u64, r11: u64, r12: u64, r13: u64, r14: u64, r15: u64,
    cr0: u64, cr3: u64, cr4: u64, efer: u64,
    exit_reason: u32, exit_qualification: u64,
    // Written by parent; consumed by Themis at VMENTRY.
    dirty: AtomicU32,   // bits: DIRTY_GPR | DIRTY_CR | DIRTY_RIP | DIRTY_RSP
    _pad: [u8; ...],
    // Posted interrupt descriptor (64 B, 64 B-aligned) — placed in same 4 KB page
    // so parent can set PIR bits without a separate META region.
    pi_desc: PostedInterruptDescriptor,
}
```

**Security property**: the child domain never holds a capability to this page — it is purely
parent-accessible META. Themis enforces this: `register_vp_meta` checks that the
capability is indeed META and owned by the calling domain. Themis writes to the page only at
VMEXIT (when the child is suspended), so there is no data race.

**PI descriptor colocation**: placing the `PostedInterruptDescriptor` (64 B, required for
posted interrupts) inside the `VpStateMeta` page means a single META allocation covers both
VP state mirroring and posted interrupt delivery. The parent's `IrqRouter` writes directly to
`pi_desc.pir[vector]` and sends the NV IPI without any additional page allocation.

### Capability Model Integration

| New concept | Capability primitive | Notes |
|---|---|---|
| VP state mirror | `META` region + `register_vp_meta` op | Parent-only read/write; Themis writes on VMEXIT |
| Posted interrupt descriptor | Colocated in VP state META page | Service-core writes PIR; target core hardware-consumes |
| Event flag page | `META` region, shared between parent + child EPT | Parent sets bits; child reads/clears |
| Intercept message page | Themis-internal; mmapped via driver | VP exit info; no capability needed |
| Doorbell channel | `(child_domain, gpa_range, vp_id, slot)` registered via hypercall | EPT intercept → notification |

### Comparison with KVM-Based Approach

| Dimension | KVM + QEMU/LKVM | Themis-native driver + cloud-hypervisor |
|---|---|---|
| **TCB** | KVM in kernel + QEMU userspace (millions of LoC in trust boundary) | Themis (small) + thin kernel driver + cloud-hypervisor |
| **Interrupt model** | APICv, device IRQs can interrupt any core | Service-core routing; confidential cores never exit for device IRQs |
| **VP state access** | `KVM_GET_REGS` ioctl → kernel copy | META page read — zero hypercall when VP suspended |
| **Nested VMX** | KVM shadow-VMCS or EVMCS if KVM guest | EVMCS-META: parent's META page mirrors nested VMCS state |
| **Cross-domain IPC** | Shared memory + eventfd (no semantic model) | Doorbell + event flag pages + capability-tracked channels |
| **Confidential VM** | TDX/SEV via KVM (complex, large TCB) | Themis isolates memory via EPT/NPT; no KVM involvement |
| **Implementation effort** | Lower initially (existing tooling) | Higher (driver + protocol) but cleaner TCB story |

### Open Questions

1. **driver scope**: Should `themis-vmm.ko` aim for `/dev/mshv` wire compatibility so that
   cloud-hypervisor's existing mshv backend works with zero changes? Or provide `/dev/themis`
   with a Themis-specific ioctl set and contribute a `themis` hypervisor backend to
   cloud-hypervisor? Wire compatibility is operationally simpler but constrains the design
   (must match Hyper-V partition property IDs, VP register indices, etc.).

2. **service core assignment**: Is a single service core (e.g., core 0) always the IRQ
   dispatch core, or does each domain get its own service VP? The latter scales better but
   requires per-domain service VPs and more complex IrqRouter logic.

3. **META page write-back timing**: Themis writes the VP state mirror on every VMEXIT. For
   high-frequency VMEXITs (VMCALL hypercalls from dom0), this write adds overhead. Options:
   (a) write only on suspension events (not VMCALL returns), (b) use a generation counter so
   the parent knows when state is stale, (c) only write fields marked dirty by VMEXIT reason.

4. **EVMCS for nested VMX**: Does cloud-hypervisor's MSHV backend actually rely on EVMCS,
   or does it use `HvCallGetVpRegisters`/`HvCallSetVpRegisters` for nested state? This
   determines whether Themis needs EVMCS at all for cloud-hypervisor to work.

5. **TychIC vs raw APIC**: Does exposing TychIC to dom0 require a paravirtual driver in
   dom0's Linux kernel? Or can the doorbell/event-flag mechanism be invisible to Linux and
   only used by userspace VMMs like cloud-hypervisor?

---

## Monitor Design

### Workspace Structure

```
themis/
├── Cargo.toml                     — workspace
├── capavisor/                       — bare-metal capavisor binary
│   ├── Cargo.toml
│   ├── linker.ld                  — Limine-compatible linker script
│   └── src/
│       ├── main.rs                — _start (BSP) + ap_entry
│       ├── platform.rs            — TychePlatform: Platform trait impl
│       ├── memory.rs              — PhysicalInventory, FrameAllocator
│       ├── heap.rs                — global allocator init
│       ├── acpi.rs                — ACPI table parsing (AcpiHandler impl)
│       ├── devices.rs             — PCI enumeration, device table
│       ├── iommu.rs               — VT-d initialization + DMA remapping
│       ├── irq.rs                 — IrqRouter, IrqAssignment, vapic module
│       ├── hypercall.rs           — VMCALL dispatch → capability engine
│       └── arch/
│           ├── mod.rs             — Arch trait + dispatch
│           └── x86_64/
│               ├── mod.rs
│               ├── vmx.rs         — VMXON, VMCS setup, VMENTRY/VMEXIT loop
│               ├── ept.rs         — EPT map/unmap wrappers (crates/ept)
│               ├── vapic.rs       — virtual APIC page + posted interrupt setup
│               ├── apic.rs        — x2APIC IPIs, I/O APIC programming
│               ├── smp.rs         — AP wakeup via Limine SMP
│               └── context.rs     — VpRegister enum, VMCS field mappings
├── crates/
│   ├── ept/                       — extracted from asterinas/hyperenclave (Apache-2.0); verified EPT
│   ├── capavisor-pt/                — vendored from verified-nrkernel (Verus); capavisor host page tables
│   ├── vtd/                       — adapted from vmxvmm/crates/vtd/ (VT-d IOMMU)
│   └── themis-abi/                 — hypercall ABI (shared with guest libtyche)
└── capability-engine/             — path dep on 2026/ capability engine
```

External crate dependencies (all `no_std`):
- `x86` — VMX instructions, VMCS constants, control registers, MSRs
- `x2apic` — LAPIC/x2APIC, I/O APIC
- `acpi` — ACPI table parsing (MADT, MCFG, DMAR raw)
- `pci_types` — PCI config-space header types, BAR decoding
- `spin` — RwLock, Mutex (bare-metal)
- `limine` — bootloader protocol
- `linked_list_allocator` — global heap allocator

Vendored / extracted crates (not on crates.io):
- `crates/ept/` — extracted from `asterinas/hyperenclave` (Apache-2.0); verified EPT mapper
- `crates/capavisor-pt/` — vendored from `verified-nrkernel` (Verus); capavisor host page tables

The capability engine is compiled with `--no-default-features`,
`features = ["address_translation"]`, using the `spin` RwLock backend.

### Key Data Structures

#### `TychePlatform`

```rust
pub struct TychePlatform {
    // Bare-metal RW lock serialising capability tree mutations.
    op_lock: spin::RwLock<()>,
    // Spinlock serialising cross-core IPI+barrier sequences.
    update_lock: AtomicBool,
    // Per-domain hardware state.
    domains: spin::Mutex<BTreeMap<DomainId, DomainHw>>,
    // Core → running domain (fast path in VMEXIT handler).
    core_domains: [AtomicU64; MAX_CORES],
    // Domain → core (for IPI targeting).
    domain_cores: spin::Mutex<BTreeMap<DomainId, CoreId>>,
    // Domain → parent (fallback on revocation).
    domain_parents: spin::Mutex<BTreeMap<DomainId, Option<DomainId>>>,
    // Physical frame allocator (EPT frames, VMCS, VMXON, PI descriptors).
    frame_alloc: spin::Mutex<FrameAllocator>,
    // IRQ router (device vector → domain assignment + PI state).
    irq_router: spin::Mutex<IrqRouter>,
    // IOMMU manager.
    iommu: spin::Mutex<IommuManager>,
    // Switch manager from capability engine.
    switch_mgr: SwitchManager,
}

struct DomainHw {
    // EPT root physical address (EPTP bits [51:12]).
    ept_root: PhysAddr,
    // Per-VP hardware context.
    vps: BTreeMap<u64, VpHw>,
    // Devices assigned to this domain (BDFs).
    assigned_devices: Vec<PciAddress>,
}

struct VpHw {
    // VMCS physical address.
    vmcs_phys: PhysAddr,
    // Virtual APIC page (4 KB, 4 KB-aligned) — one per VP.
    vapic_phys: PhysAddr,
    // Posted interrupt descriptor (64 B, 64 B-aligned) — one per VP.
    pi_desc_phys: PhysAddr,
}
```

#### VP Register Mapping

`VProcessorState.registers` maps `VpRegister as u64` → `u64`. Themis commits these
to VMCS guest-state fields at VMLAUNCH and reads them back on every relevant VMEXIT.

```rust
#[repr(u64)]
pub enum VpRegister {
    // General-purpose registers saved/restored in VMEXIT handler stub
    Rax = 0x00, Rbx, Rcx, Rdx, Rsi, Rdi, Rbp,
    R8, R9, R10, R11, R12, R13, R14, R15 = 0x0E,
    // VMCS guest-state fields (committed at VMLAUNCH, read via VMREAD)
    Rip    = 0x20,
    Rsp    = 0x21,
    Rflags = 0x22,
    Cr0    = 0x23,
    Cr3    = 0x24,
    Cr4    = 0x25,
    Efer   = 0x26,
    // Segment selectors / bases
    Cs = 0x30, Ds, Es, Fs, Gs, Ss, Tr, Ldtr,
    FsBase = 0x38, GsBase = 0x39, KernelGsBase = 0x3A,
    // Sysenter MSRs
    SysenterCs = 0x40, SysenterEsp = 0x41, SysenterEip = 0x42,
    // APIC
    ApicBase = 0x50,
    // virtual APIC state (readable by parent via GET; written by Themis)
    Tpr = 0x60, Ppr = 0x61,
}
```

`VProcessorState.platform_data` stores the VMCS physical address (first 8 bytes) so the
Themis can VMPTRLD the correct VMCS without a map lookup.

#### META Memory for EPTs

```
# Per-domain init (in capability API terms; performed by Themis at dom0 creation
# and by dom0 hypercalls for child domains):
carve r0         → dom_ept_meta  (physical frames for EPT page tables)
create_domain    → dom
send dom_ept_meta dom META       # excluded from dom GPA; zeroed+vital on revoke
carve r0         → dom_mem
send dom_mem     dom             # dom's physical address space; mapped in EPT
seal dom
```

### Boot Flow (Revised)

```
[Firmware (UEFI/BIOS)]
  ↓ loads Limine bootloader
[Limine]
  ↓ loads capavisor ELF + Linux bzImage module
  ↓ provides: memory map, SMP, HHDM, RSDP, module addresses
  ↓ starts all APs via MpRequest (goto_address callback)
[BSP: _start]
  1. Assert Limine BaseRevision.
  2. Parse memory map → PhysicalInventory (usable ranges).
  3. Reserve heap (64 MB) → init linked_list_allocator.
  4. Init serial console (println!).
  5. CPUID: verify VMX, x2APIC, APICv (APIC-register virtualization,
     virtual-interrupt delivery, posted interrupts), VT-d support.
  6. Init x2APIC (x2apic crate); read LAPIC IDs from Limine SMP response.
  7. Parse ACPI from RSDP:
     a. MADT → core topology (LAPIC IDs, physical→logical core map).
     b. MCFG → PCIe ECAM base addresses.
     c. DMAR → VT-d DRHD units + RMRR regions.
  8. Enumerate PCI devices via pci_types over ECAM → build device table.
  9. Initialize VT-d IOMMUs (one per DRHD unit): set up root/context tables,
     enable translation in passthrough mode initially (all DMA permitted for dom0).
  10. Enable VT-x on BSP: allocate VMXON region, execute VMXON.
  11. Set up IDT: #GP, #PF, NMI, APIC-timer, IPI-shootdown, PI-notification vectors.
  12. Init capability engine:
      a. root domain (id=0, sealed, all cores, all API).
      b. r0 = all usable physical memory minus heap, minus capavisor binary.
  13. Wait for APs to complete VT-x init and signal ready.
  14. Create dom0:
      a. carve r0 → dom0_ept_meta (EPT frame pool, META send).
      b. carve r0 → dom0_mem (all remaining memory).
      c. create_domain root dom0 (all cores, all API).
      d. send dom0_ept_meta dom0 META.
      e. send dom0_mem dom0.
      f. Set dom0 VP[i] interrupt policy:
         - default: DELIVER (dom0 handles all interrupts initially).
         - NMI: DELIVER at root (Themis handles, not dom0).
      g. Set VP[i] registers: RIP, RSP, RSI (boot_params), CR3, EFER, RFLAGS.
      h. seal_domain dom0.
      i. Platform: for each VP allocate VMCS + VAPIC page + PI descriptor;
         set all VMCS fields; program I/O APIC for dom0 (all device IRQs → dom0).
  15. switch_domain(root, dom0, 0) → VMLAUNCH on BSP.

[APs: ap_entry (called by Limine)]
  1. Enable VT-x: VMXON.
  2. Signal ready; spin on mailbox.
  3. Mailbox: VMPTRLD(dom0 VP[i]) + VMLAUNCH.
```

---

## Device Enumeration and IOMMU

### Motivation

Themis enumerates all PCI/PCIe devices at boot so it can:
1. Create "driver domains" — child domains of dom0 with exclusive device access.
2. Program the IOMMU (VT-d) to restrict device DMA to the owning domain's physical memory.
3. Correctly route device IRQs to the assigned domain (I/O APIC / MSI-X programming).

### Device Table

```rust
pub struct PciDevice {
    addr:    PciAddress,          // bus:device.function
    vendor:  u16, device: u16,
    class:   u8, subclass: u8,
    bars:    [Option<Bar>; 6],    // decoded from pci_types::EndpointHeader
    msi_cap: Option<MsiCap>,      // MSI capability offset + config
    msix_cap: Option<MsixCap>,    // MSI-X table location + size
    irq_line: u8,                 // INTx line (legacy)
    owner:   Option<DomainId>,    // None = unassigned (dom0 by default)
}

pub static DEVICE_TABLE: spin::Mutex<Vec<PciDevice>> = ...;
```

Built at boot by walking bus 0..255 over the ECAM MMIO window.
RMRR regions from the DMAR table are noted: the physical ranges they describe must always
remain mapped for the relevant devices (e.g. USB EHCI) even when a device is reassigned.

### IOMMU Manager

```rust
pub struct IommuManager {
    // One Iommu instance per DRHD unit.
    units: Vec<IommuUnit>,
    // Per-domain DMA page tables (BTreeMap<DomainId, DmaPageTable>).
    domain_pts: BTreeMap<DomainId, DmaPageTable>,
}

struct IommuUnit {
    iommu: vtd::Iommu,
    // Root table: 256 entries (one per PCI bus) → context table pages.
    root_table: PhysAddr,
    // Context tables: per-bus, 256 entries (device/function) → domain PT.
    context_tables: BTreeMap<u8, PhysAddr>,
}
```

#### Integration with `apply_update`

The DMA page tables have the same format as EPTs (second-level address translation).
`apply_update` updates both EPT and IOMMU for any domain that has assigned devices:

```rust
fn apply_update(&self, update: &Update) {
    match update {
        Update::ChangeRights { domain, address, physical, size, rights, .. } => {
            let dh = self.domains.lock();
            let hw = dh.get(domain).unwrap();
            // 1. Update EPT.
            ept_op(hw.ept_root, address, physical, size, rights, &mut *self.frame_alloc.lock());
            // 2. If domain has assigned devices, update IOMMU DMA page tables too.
            if !hw.assigned_devices.is_empty() {
                let mut iommu = self.iommu.lock();
                iommu.update_domain_pt(*domain, *physical, *size, *rights);
            }
        }
        Update::ZeroMemory { start, size } => {
            unsafe { core::ptr::write_bytes(hpa_to_virt(*start), 0, *size as usize); }
        }
        Update::FlushTLB { domain } => {
            let dh = self.domains.lock();
            if let Some(hw) = dh.get(domain) {
                vmx::invept_single_context(hw.ept_root);
                // Also invalidate IOMMU TLB for this domain if it has devices.
                if !hw.assigned_devices.is_empty() {
                    self.iommu.lock().invalidate_domain(*domain);
                }
            }
        }
        Update::RevokeDomain { .. } => { /* handled by on_domain_revoked */ }
    }
}
```

#### `VMCALL_ASSIGN_DEVICE` hypercall

```
RAX = VMCALL_ASSIGN_DEVICE
RDI = PCI address (bus << 16 | dev << 8 | fn)
RSI = target domain handle (LocalHandle in caller's domain cap table)
```

Steps:
1. Verify caller is sealed, has appropriate API permission (e.g. a new `MANAGE_DEVICES` bit).
2. Look up device in `DEVICE_TABLE`; verify caller currently owns it.
3. Update device owner → target domain.
4. Reprogram IOMMU context entry for device BDF → target domain's DMA page table.
5. Reprogram I/O APIC / MSI-X for device IRQ → target domain VP.
6. Return success.

---

## Virtual APIC, Posted Interrupts, and IRQ Abstraction

### Motivation

Linux (the primary guest OS for dom0 and driver domains) relies heavily on the LAPIC:
- LAPIC timer for per-core scheduling and timekeeping.
- IPI delivery for SMP coordination (TLB shootdowns, task migration, etc.).
- Device interrupt delivery via I/O APIC → local APIC vector.
- EOI writes after every interrupt handler.

Without APIC virtualization, each of these operations causes a VMEXIT. Intel APICv
(APIC virtualization) enables hardware-assisted handling of nearly all APIC accesses.
Posted interrupts additionally allow physical device interrupts to be delivered to a
running guest VP **with zero VMEXITs**.

The IRQ abstraction layer bridges the capability engine's domain interrupt policy
(`VectorPolicy { visibility, read_set, write_set }`) with the hardware mechanisms
(virtual APIC page, posted-interrupt descriptor, I/O APIC/MSI-X routing).

### Intel APICv Feature Set

All features are controlled by VMCS execution control fields (checked via CPUID at boot):

| Feature | VMCS control | Effect |
|---------|-------------|--------|
| Virtualize APIC accesses | Secondary PROCBASED bit 0 | APIC MMIO page → VAPIC page (xAPIC mode) |
| APIC-register virtualization | Secondary PROCBASED bit 8 | Guest register reads from VAPIC page |
| Virtual-interrupt delivery (VID) | Secondary PROCBASED bit 9 | CPU delivers from VIRR at VMENTRY; EOI virtualized |
| Virtualize x2APIC mode | Secondary PROCBASED bit 4 | x2APIC MSR accesses → VAPIC page |
| Process posted interrupts | PIN-BASED bit 7 | Physical NV interrupt → PIR→VIRR without VMEXIT |

Detection at boot:

```rust
// Verify all APICv bits are available before enabling them.
// If any are missing (e.g. on older hardware), fall back to full-VMEXIT APIC emulation.
let has_vapic  = msr::read(IA32_VMX_PROCBASED_CTLS2) & SECONDARY_APIC_REG_VIRT != 0;
let has_vid    = msr::read(IA32_VMX_PROCBASED_CTLS2) & SECONDARY_VIRT_INTR_DELIVERY != 0;
let has_pi     = msr::read(IA32_VMX_PINBASED_CTLS)   & PIN_PROCESS_POSTED_INTRS != 0;
let apicv_mode = has_vapic && has_vid && has_pi;
```

### Per-VP Hardware State for APICv

Each VP (`VpHw`) carries:

```rust
struct VpHw {
    vmcs_phys:    PhysAddr,     // VMCS (4 KB, 4 KB-aligned)
    vapic_phys:   PhysAddr,     // Virtual APIC page (4 KB, 4 KB-aligned)
    pi_desc_phys: PhysAddr,     // Posted-interrupt descriptor (64 B, 64 B-aligned)
}

// Posted-interrupt descriptor layout (Intel SDM Vol 3C §29.6)
#[repr(C, align(64))]
struct PiDescriptor {
    pir:      [u64; 4],   // [255:0] posted-interrupt request bitmap (one bit per vector)
    on:       u64,        // bit 0 = SN (suppress notification); bit 1 = ON (outstanding notif)
    _reserved: [u64; 3],
}
```

VMCS fields set when APICv is enabled (per VP):

| VMCS field | Value |
|-----------|-------|
| `VIRTUAL_APIC_PAGE_ADDR` | `VpHw.vapic_phys` |
| `POSTED_INTR_DESC_ADDR` | `VpHw.pi_desc_phys` |
| `POSTED_INTR_NV` | per-domain notification vector (e.g. 0xF2) |
| `APIC_ACCESS_ADDR` | per-domain APIC access page (4 KB at APIC MMIO address) |
| Secondary PROCBASED controls | `VIRT_X2APIC | APIC_REG_VIRT | VIRT_INTR_DELIVERY` |
| Pin-based controls | `PROCESS_POSTED_INTERRUPTS` |
| EOI-exit bitmap | mask of vectors requiring VMEXIT on EOI (for REPORT-policy vectors) |

### IRQ Router

`IrqRouter` maps physical interrupt vectors to domain assignments and manages hardware
configuration for each assigned IRQ:

```rust
pub struct IrqRouter {
    // Physical vector → IRQ assignment.
    assignments: BTreeMap<u8, IrqAssignment>,
    // Notification vector used for posted-interrupt delivery (fixed per system).
    pi_notification_vector: u8,
}

pub struct IrqAssignment {
    vector:       u8,
    source:       IrqSource,         // Legacy INTx | MsiX { pci_addr, entry }
    domain:       DomainId,
    delivery:     IrqDeliveryMode,   // PostedInterrupt | VirtualInject | VmExit
}

pub enum IrqSource {
    IoapicLegacy { gsi: u8 },
    MsiX { pci_addr: PciAddress, table_entry: u16 },
}

pub enum IrqDeliveryMode {
    // Physical interrupt → PIR bit set; CPU delivers to running VP via PI mechanism.
    PostedInterrupt,
    // Physical interrupt → VMCS event injection (VIRR bit set manually; VMRESUME delivers).
    VirtualInject,
    // Physical interrupt → VMEXIT → Themis calls deliver_interrupt_vp → capability routing.
    VmExit,
}
```

#### IRQ Policy from Capability Engine

After `seal_domain_op` succeeds, the hypercall handler calls
`IrqRouter::configure_domain_policy(domain_id, &DomainPolicy)`:

```rust
fn configure_domain_policy(&mut self, domain: DomainId, policy: &DomainPolicy, hw: &DomainHw) {
    for (vector, vp) in policy.interrupts.iter() {
        match vp.visibility {
            InterruptVisibility::Deliver => {
                // This domain handles the vector. Configure hardware for optimal delivery.
                if self.pi_capable(vector) {
                    // Program I/O APIC / MSI-X to use the posted-interrupt notification
                    // vector targeting this domain's VP(s).
                    self.configure_posted_interrupt(vector, domain, hw);
                } else {
                    // Fall back to VMEXIT-based routing.
                    self.assign_vmexit(vector, domain);
                }
            }
            InterruptVisibility::Report => {
                // Domain is notified but not the final handler.
                // Must use VMEXIT path so Themis can call deliver_interrupt_vp.
                self.assign_vmexit(vector, domain);
                // Add vector to EOI-exit bitmap for this domain's VPs
                // so that EOI from this domain causes a VMEXIT (allowing Themis
                // to propagate the EOI upward through the REPORT chain).
                self.add_eoi_exit(vector, domain, hw);
            }
            InterruptVisibility::NotReport => {
                // Skip; parent or ancestor will handle it.
            }
        }
    }
}
```

#### Interrupt Delivery Path

```
Physical interrupt, vector V, fires on physical core C
              │
              ├─── (DELIVER domain running on C, posted interrupt configured)
              │         CPU sees PI notification vector
              │         CPU: PIR[V]=1 → VIRR[V]=1 → delivers to guest at VMENTRY
              │         Zero VMEXITs. ✓
              │
              └─── (otherwise: VMEXIT reason EXTERNAL_INTERRUPT)
                        │
                        ▼
              VMEXIT handler: IrqRouter::route(V, C, &platform)
                1. domain D = core_domains[C] (currently running domain)
                2. policy = D.interrupt_policy(V)
                   DELIVER:   handler = D
                   REPORT:    handler = walk CDT until DELIVER ancestor
                   NOTREPORT: handler = walk CDT until DELIVER ancestor (no notify)
                3. deliver_interrupt_vp(D_cap, handler_id, C, &platform)
                   → suspends VP call chain (Running→Interrupted, Locked→Suspended)
                   → handler VP: Available/Locked → Running
                4. inject V into handler VP's VIRR (VAPIC page bit set)
                5. VMRESUME into handler domain VP
```

#### Timer Virtualization

The LAPIC timer (configured by Linux in dom0) is handled via APICv:
- Linux writes to LAPIC timer registers (LVT Timer, Initial Count, Divide Config) →
  VAPIC page is updated; no VMEXIT unless the LVT Timer vector is in the EOI-exit bitmap.
- Timer fires → posted interrupt (if timer vector is DELIVER for dom0) or VMEXIT
  (if REPORT, e.g. for preemption monitoring by a parent domain).
- Default: timer is DELIVER for dom0 → posted interrupt → Linux timer handler runs
  at near-native speed.

#### EOI Virtualization and the REPORT Path

When a child domain has `REPORT` visibility for vector V:
- Vector V is added to that domain's **EOI-exit bitmap** in its VMCS.
- Guest EOI for vector V causes a VMEXIT (reason: `EOI_INDUCED`).
- Monitor: calls the capability engine's resume-after-interrupt sequence, which walks
  the REPORT chain and notifies the relevant parent domains.
- This is the only VMEXIT required in the REPORT path (interrupt delivery itself uses
  posted interrupts if the child has DELIVER for a sub-vector).

#### Interrupt Policy Hypercalls

Two new hypercalls (called before `VMCALL_SEAL` to configure the domain's interrupt policy):

```
VMCALL_SET_INTR_POLICY(domain_handle, vector, visibility)
VMCALL_SET_DEFAULT_INTR_POLICY(domain_handle, visibility)
```

These map to `DomainPolicy::set_interrupt_policy` already in the capability engine.
The platform-side hardware configuration happens at seal time (not at policy-set time),
so configuration is done atomically once the policy is frozen.

### Fallback: No APICv

On hardware without APICv (or when disabled for testing):
- `IrqDeliveryMode::VmExit` is used for all interrupts.
- Every APIC register access (TPR, EOI, ICR) causes a VMEXIT and is emulated by Themis.
- Functional but significantly slower; not recommended for production.

---

## VMEXIT Handler (Updated)

| VMEXIT Reason | Action |
|---------------|--------|
| `VMCALL` | Decode RAX (opcode), invoke capability engine via `execute()`, write back. |
| `EXTERNAL_INTERRUPT` | `IrqRouter::route(vector, core, &platform)` → deliver via CDT, inject into VIRR, VMRESUME. |
| `EOI_INDUCED` | EOI for a REPORT-visibility vector: notify parent chain via capability engine. |
| `APIC_ACCESS` | APIC MMIO access (xAPIC fallback): emulate register read/write against VAPIC page. |
| `EPT_VIOLATION` | Demand-page or inject #PF; future: driver domain MMIO passthrough. |
| `CPUID` | Emulate: expose virtualization leaf, hide VMX from guest, filter APICv bits. |
| `CR_ACCESS` | CR0/CR4 write: validate + forward; CR8 (TPR) → VAPIC page. |
| `XSETBV` | XCR0 write: filter. |
| `HLT` | Spin/C-state. |
| `PAUSE` | Yield. |
| `IO_INSTRUCTION` | Forward/emulate (dom0 has I/O BITMAP disabled initially). |
| `INIT` / `SIPI` | Should not occur in steady state. |

---

## Hypercall ABI

```
RAX = opcode
Arguments: RDI, RSI, RDX, RCX, R8, R9
Return:    RAX = error code (0 = success), RDI = first return value, RSI = second
```

| Opcode | CapavisorAPI | Capability engine call |
|--------|-----------|------------------------|
| `VMCALL_CARVE`               | `CARVE`   | `Capability::carve` |
| `VMCALL_ALIAS`               | `ALIAS`   | `Capability::alias` |
| `VMCALL_SEND`                | `SEND`    | `Capability::send` / `send_at` |
| `VMCALL_ACCEPT`              | `SEND`    | `Capability::accept` / `accept_at` |
| `VMCALL_REJECT`              | `SEND`    | `Capability::reject_memory` |
| `VMCALL_CREATE_DOMAIN`       | `CREATE`  | `Capability::create` |
| `VMCALL_SEAL`                | `SEAL`    | `Capability::seal` → then `IrqRouter::configure_domain_policy` |
| `VMCALL_REVOKE_MEM`          | `REVOKE`  | `Capability::revoke_memory_child` |
| `VMCALL_REVOKE_DOMAIN`       | `REVOKE`  | `Capability::revoke_domain` |
| `VMCALL_SWITCH`              | `SWITCH`  | `Capability::switch_domain` |
| `VMCALL_GET_CHAN`             | `GETCHAN` | `Capability::get_chan` |
| `VMCALL_ATTEST_SELF`         | `ATTEST`  | `Capability::attest_self` |
| `VMCALL_ATTEST`              | `ATTEST`  | `Capability::attest` |
| `VMCALL_GET_REG`             | `GET`     | `Capability::get_register` |
| `VMCALL_SET_REG`             | `SET`     | `Capability::set_register` |
| `VMCALL_SET_INTR_POLICY`     | `SET`     | `DomainPolicy::set_interrupt_policy` |
| `VMCALL_SET_DEF_INTR_POLICY` | `SET`     | `DomainPolicy::set_default_interrupt_policy` |
| `VMCALL_ASSIGN_DEVICE`       | (new)     | `IrqRouter` + `IommuManager` |
| `VMCALL_ENUMERATE`           | `ENUMERATE` | TBD |

---

## Implementation Phases

### Phase 0 — Workspace Setup ✅

- [x] **P0a**: Create `themis/` workspace; `capavisor/` member with `#![no_std]` +
  `#![no_main]` + `extern crate alloc`.
  - Added `capability-engine-v2` path dep: `features = ["address_translation"]`,
    `default-features = false`.
  - Added `x86`, `x2apic`, `acpi`, `pci_types`, `spin`, `limine`, `linked_list_allocator`.
  - Added `rust-toolchain.toml` pinned to nightly (required by `x2apic→x86_64/nightly`
    and `acpi 6.x/allocator_api`).
  - Serial console (COM1, 115200 baud, 8N1) implemented directly in `main.rs` with
    `serial_print!`/`serial_println!` macros.
  - `crates/themis-abi/`: hypercall ABI fully defined (24 opcodes, error codes,
    `VpRegister` enum with 39 registers, META page layout constants).
- [x] **P0b**: Linker script (`capavisor/linker.ld`) higher-half at `0xffffffff80000000`;
  `build.rs` emits absolute `-T` path; `.cargo/config.toml` sets `x86_64-unknown-none`
  target + soft-float rustflags (`-sse,-sse2`) + `relocation-model=static` (Limine
  rejects PIE ET_DYN without PT_DYNAMIC).
- [x] **P0c**: Stubs created for `crates/ept/`, `crates/capavisor-pt/` (each with
  detailed extraction plan in the source), and full port of `vmxvmm/crates/vtd/` →
  `crates/vtd/` (local `PhysAddr`/`VirtAddr`/`FrameAllocator` types, bitflags 2.x fixes).
- [x] **P0d**: QEMU dev environment: `scripts/build-iso.sh` (Limine ISO),
  `scripts/run-qemu.sh` (`cargo themis`, KVM+VMX, env knobs),
  `scripts/debug.sh` (`cargo debug`, QEMU `-s -S` + rust-gdb attach),
  `themis.gdbinit` (symbol load, `print-cr3` helper).
  `cargo check` passes cleanly on nightly.

### Phase 0.5 — dom0 Linux Image & Bootloader Integration

**Goal**: give Themis a real Linux kernel + rootfs to hand off as dom0, exercisable
under QEMU from day one.  The disk image is *not* booted directly — Themis loads it,
carves it into a domain, and schedules it across all cores before yielding to it.

> **Scope**: this phase uses a **stock minimal Linux image** (Ubuntu cloud image or
> equivalent) purely to exercise the kernel-loading and boot-params plumbing.  No
> Themis-specific drivers or paravirtualisation are expected to work at this stage.
> A dedicated later phase (see *Phase 14 — Custom dom0 Image*) covers building a
> purpose-built dom0 image with the `themis-vmm.ko` driver, stripped-down config, and
> any required device support compiled in.

#### Rationale

Limine supports a "modules" protocol: extra files (kernel, initrd, etc.) can be
declared in `limine.conf` and the bootloader will load them into memory before
jumping to Themis.  Themis reads the Limine module list, finds the Linux kernel
and initrd, and places them into the dom0 address range before first VMENTRY.

Using a stock cloud image for QEMU development avoids building a custom kernel; once
the loading path is exercised the same flow works with a bespoke hardened dom0 kernel.

#### Sub-tasks

- [x] **P0.5a** — dom0 disk image + standalone boot:
  - `scripts/fetch-dom0.sh` downloads the **standard Ubuntu Jammy cloud image**
    (`jammy-server-cloudimg-amd64.img`) from `cloud-images.ubuntu.com/jammy/current/`.
    *(Originally planned to use the CH-custom image from `ch-images.azureedge.net`,
    but that image was EFI-only with no BIOS GRUB modules, causing GRUB rescue errors
    when booted standalone. Switched to the standard Ubuntu image which boots under
    both BIOS and UEFI.)*
  - Cloud-init seed: uses `cloud-localds` to create an ISO9660 CIDATA seed
    (`guest/seed.img`). *(Originally planned FAT32 via `mkdosfs`/`mcopy`; `cloud-localds`
    is simpler and is the standard cloud-image-utils approach.)*
    Credentials: user `cloud` / password `cloud123`, passwordless sudo.
  - **No separate kernel download**: the kernel and initrd live inside the disk at
    `/boot/vmlinuz` and `/boot/initrd.img`. Limine loads them directly from the disk
    via `fslabel(cloudimg-rootfs)`.
  - `scripts/run-dom0.sh` (`cargo dom0`): standalone QEMU boot of the dom0 disk
    (no Themis, no Limine) using virtio-blk + `-nographic`. Used as a sanity check.
    First boot requires `SEED=1 cargo dom0` to provision cloud-init; subsequent boots
    need no seed (`.dom0-seeded` marker file tracks this).

- [x] **P0.5b** — Limine config & ISO build:
  - `scripts/build-iso.sh` packages the capavisor ELF into a Limine-bootable ISO.
    Limine v8.x uses `limine.conf` (not the old `.cfg`) with lowercase YAML-like
    syntax. The config declares dom0 modules loaded from the disk at runtime:
    ```
    /Themis Capavisor
        protocol: limine
        kernel_path: boot():/boot/capavisor
        module_path: fslabel(cloudimg-rootfs):/boot/vmlinuz
        module_cmdline: dom0-kernel
        module_path: fslabel(cloudimg-rootfs):/boot/initrd.img
        module_cmdline: dom0-initrd
    ```
    *(Originally planned to copy vmlinuz/initrd into the ISO tree. In practice, Limine
    reads them directly from the attached disk via `fslabel()`, so the ISO contains
    only the capavisor binary. The dom0 module lines are only added if the disk image
    is present, allowing capavisor-only ISO builds for testing.)*
  - **BIOS/IDE caveat**: Limine runs at BIOS level using INT 13h for disk access.
    virtio-blk is invisible at this stage (requires an OS driver). The disk must be
    attached to QEMU as `-drive ...,if=ide` so Limine can reach it.

- [x] **P0.5-tooling** — Limine setup, xtask, and cargo aliases:
  - `scripts/setup-limine.sh` (`cargo setup-limine`): clones Limine v8.7.0 (commit
    `aad3edd`) from the `v8.x-binary` branch into `tools/limine/` and builds only the
    CLI tool. Everything local — nothing installed system-wide. Auto-triggered by
    `build-iso.sh` if Limine is not found.
  - `xtask/` crate: thin dispatcher that maps `cargo <task>` to `scripts/<task>.sh`.
    *(Originally used `["!bash", "scripts/foo.sh"]` aliases in `.cargo/config.toml`,
    which is not valid Cargo syntax. Replaced with xtask pattern: aliases invoke
    `cargo run --manifest-path xtask/Cargo.toml -- <task>`, xtask `exec()`s the
    corresponding script so QEMU gets direct terminal access.)*
  - Aliases: `cargo iso`, `cargo themis` (was `cargo qemu`, renamed for clarity),
    `cargo debug`, `cargo fetch-dom0`, `cargo dom0`, `cargo setup-limine`.

- [x] **P0.5c** — Themis module-discovery stub:
  - Added `limine::request::ModuleRequest` to `capavisor/src/main.rs`.
  - In `_start`, after `BASE_REVISION` check, iterates `MODULE_REQUEST.get_response()`
    modules and logs each module's cmdline tag, path, base address, and size via serial.
  - Identifies `dom0-kernel` module by `module_cmdline` tag match.
  - `capavisor/src/guest/mod.rs` + `guest/modules.rs`: `ModuleInfo` struct with
    `from_limine_file()` constructor and `find_module(name)` lookup helper.
  - No heap allocation required (iterates Limine response in-place).

- [x] **P0.5d** — Linux kernel header parsing:
  - Parse the `linux_boot_params` / `boot_protocol` header at offset 0x1f1 inside
    the bzImage to extract:  `kernel_alignment`, `init_size`, `pref_address`,
    `payload_offset` (compressed payload start), `payload_length`.
  - Define `capavisor::guest::linux::BootHeader` mirroring the relevant fields
    (refs: Linux `arch/x86/include/uapi/asm/bootparam.h`, boot protocol §4).
  - This will be used in Phase 7 when setting up the dom0 address space and
    `struct boot_params` for the guest.

- [ ] **P0.5e** — *(Future)* Switch to virtio-blk for dom0 disk once Themis's virtio-blk
  backend is implemented (Phase 12+). At that point, the disk can be passed as
  `-drive ...,if=virtio` in QEMU and Limine access becomes irrelevant (Themis will load
  the kernel from memory, not Limine). Kernel command line root= will switch to
  `root=/dev/vda1`.

- [x] **P0.5f** — `.gdbinit` update:
  - Once P0.5c is working, extend `themis.gdbinit` with an `add-symbol-file` for the
    uncompressed Linux vmlinux at the address Themis places it in memory.
  - Add a `dmesg-hint` command that prints the GPA range of the dom0 kernel text
    section (read from the Themis domain descriptor).

#### Design notes

**Why bzImage, not ELF?**
Limine natively boots Limine-protocol kernels.  Linux is *not* a Limine kernel; we
load it ourselves.  A bzImage is the standard deliverable from `make bzImage`.  Themis
must decompress the payload (gzip/zstd depending on kernel config) and place the
decompressed image at the correct aligned address before VMENTRY.  For early
development, build Linux with `CONFIG_KERNEL_UNCOMPRESSED=y` to skip decompression.

**Address placement**
Linux boot protocol v2.12+ declares `pref_address` (preferred load address, typically
`0x1000000` = 16 MiB).  Themis should honour this during Phase 7; for Phase 0.5 we
only parse and print it.

**Boot params page**
The `struct boot_params` page (4 KiB, zero-filled, then populated by the loader) is
conventionally placed at `0x10000`.  Themis writes `hdr`, `e820_table`,
`ext_ramdisk_image`, `ext_ramdisk_size` into it, then sets `rsi = boot_params_gpa`
before the first VMENTRY into dom0.

**Limine terminal for early output**
Serial UART (COM1, 115200 baud) is already initialized in `_start` (Phase 0).
`serial_print!` / `serial_println!` macros are available for debug output during
module discovery and subsequent phases.

### Phase 1 — Boot, Memory, ACPI, PCI

The memory architecture follows a two-tier model:

- **Heap** (`linked_list_allocator`): internal bookkeeping, capability tables, data
  structures, message buffers.  Carved once at boot from the Limine memory map.
- **META-backed frames**: VMCS, VAPIC, EPT pages, `VpStateMeta`, PI descriptors.
  These are allocated by *carving META capabilities* through the capability engine.
  The parent (Themis for dom0, dom0 for its children) retains read/write access to
  META pages while the child owns them in the capability tree.

**dom0 bootstrap**: at boot, Themis plays the parent role for dom0.  It splits the
physical memory map into three pools:

1. **Themis heap** — internal allocator, never exposed to any domain.
2. **dom0-owned regions** — normal capabilities sent to dom0's cap table.
3. **dom0 META pool** — physical frames reserved for dom0's VMCS, EPT root, VAPIC,
   and `VpStateMeta` pages.  Reflected as META capabilities in dom0's cap table
   (dom0 "owns" them, Themis retains parent-side access).

When dom0 later creates children via `themis-vmm.ko`, it follows the same pattern:
carve META from its own pool, register it for the child VP.

- [x] **P1a**: Limine entry `_start`: parse memory map → `PhysicalInventory`; reserve heap
  (64 MB); init `linked_list_allocator::LockedHeap`.
  *(Note: serial console is already implemented — see Phase 0. `_start` currently
  boots, prints to serial, and halts. Phase 1 continues from the halt point.)*
- [x] **P1b**: Physical memory partitioning: split the physical memory map into
  `{themis_heap, dom0_owned, dom0_meta_pool}`.  The META pool size is computed from
  the number of dom0 VPs × per-VP hardware structures (VMCS 4 KiB + VAPIC 4 KiB +
  VpStateMeta 4 KiB + VMXON 4 KiB per core + EPT root pages).  Remaining memory
  goes to dom0-owned.

  **Capavisor page table safety invariant**: The capavisor's own CR3 page tables
  currently live in Limine `BOOTLOADER_RECLAIMABLE` memory, which is implicitly
  safe because `from_limine()` only partitions `USABLE` regions.  New PT pages
  created by `paging.rs::ensure_table()` come from the heap (also excluded).
  However, there is no explicit tracking of which frames are capavisor PT pages.
  When we replace the ad-hoc paging module with the verified host PT
  implementation (`verified-nrkernel`), we must explicitly account for these
  frames — especially if we ever reclaim `BOOTLOADER_RECLAIMABLE` memory.
- [x] **P1c**: SMP bootstrap via Limine `MpRequest`: per-AP `goto_address` entry point;
  global barrier until all APs complete Phase 2 init.
  *(Note: AP entry stub (`ap_entry`) already exists — it parks APs in a halt loop.
  Phase 1 replaces the halt with a proper mailbox/barrier.)*
- [x] **P1d**: ACPI parsing:
  - Implement `acpi::AcpiHandler` trait (physical → virtual address mapping using HHDM offset).
  - `AcpiTables::from_rsdp(handler, rsdp_phys)`.
  - Extract: MADT (LAPIC IDs, x2APIC entries), MCFG (PCIe ECAM bases), DMAR raw bytes.
- [x] **P1e**: PCI enumeration via `pci_types` over ECAM:
  - Implement `ConfigRegionAccess` using volatile MMIO over ECAM window.
  - Walk all buses/devices/functions; decode headers + BARs + capabilities (MSI/MSI-X).
  - Build `DEVICE_TABLE: Vec<PciDevice>`.

### Phase 2 — VT-x Foundation

**Architecture note**: Every domain (including dom0) owns a `Domain` struct with a
per-domain `MetaAllocator` — a bump allocator over its META pool.  All hardware VP
structures (VMXON, VMCS, VAPIC, EPT pages) are allocated via `domain.meta.alloc_frame()`.
dom0 is special only in that the capavisor bootstraps its META pool at boot (no parent).
Child domains will receive their META pool via capability operations from their parent.

- [x] **P2a**: CPUID checks: VMX, x2APIC, APICv (APIC-register virtualization,
  virtual-interrupt delivery, posted interrupts), VT-d. Record a global `CpuFeatures` struct.
- [x] **P2b**: VMXON on BSP (per-core VMXON region from dom0's `MetaAllocator`).
  AP VMXON deferred to Phase 7 (requires mailbox mechanism to wake parked APs).
  Introduced `Domain` struct (`domain.rs`) and `MetaAllocator` (`mem/meta_alloc.rs`).
- [ ] **P2c**: VMCS allocation + minimal setup using `x86::bits64::vmx`:
  - VMCS pages allocated from dom0 META pool (one per VP).
  - Host state: capavisor CS/SS/DS, CR0/CR3/CR4, EFER, RSP/RIP → `vmexit_handler`.
  - Guest state: from `VProcessorState.registers`.
  - Execution controls: intercept VMCALL, CPUID, CR accesses, I/O bitmap,
    `EXTERNAL_INTERRUPT` (all physical interrupts exit to Themis), `NMI_EXITING` (watchdog).
  - Secondary controls: `EOI_INDUCED` exiting enabled after Phase 5 APICv setup (EOI-exit
    bitmap controls which vectors cause a VMEXIT on EOI, used for REPORT-policy vectors).
  - Install NMI IDT handler in root mode: must be present at all times since NMI is
    non-maskable regardless of `CLI`; handler writes EOI (IRET re-enables NMI window) and
    records a watchdog event or panics.
- [ ] **P2d**: EPT setup: call `crates/ept` to allocate an EPT root per domain; EPT page
  frames come from the domain's META pool (parent retains access for map/unmap).
  Write EPTP into `VMCS.EPT_POINTER` (4-level, WB memory type).
- [ ] **P2e**: Minimal VMEXIT dispatch: VMCALL → stub, CPUID → emulate, HLT → spin,
  others → log + halt. VMRESUME after each handled exit.

### Phase 3 — Platform Trait Implementation

- [ ] **P3a**: `TychePlatform` with all `Platform` methods:
  - `acquire_shared_lock` / `acquire_exclusive_lock`: `spin::RwLock<()>`.
  - `apply_update`: EPT + IOMMU map/unmap/zero/flush as described above.
  - `register_domain`: allocate EPT root + IOMMU domain PT; insert into `domains` map.
  - `on_domain_revoked`: redirect cores, free EPT + IOMMU structures, release devices.
  - `set_core_domain` / `clear_core_domain` / `domain_core`.
  - `send_ipi` (x2APIC), `sync_barrier` (two AtomicUsize counters per barrier phase).
  - `try_acquire_update_lock` / `release_update_lock` / `poll_and_respond_cross_core`.
- [ ] **P3b**: IPI handler (IDT vector): set per-core `ipi_pending` flag;
  `poll_and_respond_cross_core` checks flag and participates in barrier.
- [ ] **P3c**: TLB shootdown: `INVEPT` (single-context) after each EPT update;
  `IOTLB` invalidation after each IOMMU update.

### Phase 4 — VT-d IOMMU Initialization

- [ ] **P4a**: Parse raw DMAR bytes: locate DRHD units (hardware units) + RMRR regions.
- [ ] **P4b**: For each DRHD unit: allocate root table + context tables from `FrameAllocator`;
  program root table address register; set passthrough mode (all DMA allowed) initially.
- [ ] **P4c**: Enable VT-d translation: `iommu.enable_translation()` on all units.
- [ ] **P4d**: RMRR handling: pre-map RMRR physical ranges as identity in the dom0 IOMMU domain
  PT (these regions must remain accessible to legacy devices regardless of domain assignment).
- [ ] **P4e**: `IommuManager::update_domain_pt(domain, hpa, size, rights)`:
  walk DMA PT (same format as EPT), set/clear entries, call IOTLB invalidation.
- [ ] **P4f**: `IommuManager::assign_device(pci_addr, domain)`:
  reprogram context entry for device BDF → domain's DMA page table.

### Phase 5 — APICv and Virtual APIC

- [ ] **P5a**: Per-VP allocation: VAPIC page (4 KB from `FrameAllocator`) and
  posted-interrupt descriptor (64 B, 64 B-aligned from `FrameAllocator`).
  Note: once Phase 10 (META VP-state regions) is implemented, the PI descriptor is
  colocated inside the `VpStateMeta` page, eliminating the separate allocation;
  `VpHw.pi_desc_phys` becomes an offset into the META page.
- [ ] **P5b**: APIC access page: one 4 KB page per domain at APIC MMIO address (0xFEE00000);
  used by `APIC_ACCESS_ADDR` VMCS field for xAPIC mode.
- [ ] **P5c**: VMCS secondary execution controls (when `CpuFeatures::apicv`):
  `VIRTUALIZE_X2APIC | APIC_REG_VIRT | VIRT_INTR_DELIVERY`.
  Pin-based controls: `PROCESS_POSTED_INTERRUPTS`.
  VMCS fields: `VIRTUAL_APIC_PAGE_ADDR`, `POSTED_INTR_DESC_ADDR`, `POSTED_INTR_NV`,
  `APIC_ACCESS_ADDR`, EOI-exit bitmap (zeroed initially).
- [ ] **P5d**: `vapic::inject_virtual_interrupt(vapic_page, vector)`:
  set bit in VIRR (offset 0x200 + vector/8 in VAPIC page); update RVI (requesting
  virtual interrupt = highest VIRR bit that exceeds PPR).
- [ ] **P5e**: `vapic::post_interrupt(pi_desc, vector)`:
  set `PIR[vector]` bit atomically; set `ON` (outstanding notification) bit;
  send posted-interrupt notification IPI (NV) to target LAPIC if domain VP is running.
- [ ] **P5f**: Fallback path: if `!CpuFeatures::apicv`, disable all APICv VMCS bits;
  emulate APIC register access via VMEXIT.

### Phase 6 — IRQ Router and Interrupt Policy

- [ ] **P6a**: `IrqRouter` initialization at boot: all vectors assigned to dom0 with
  `PostedInterrupt` delivery (APICv) or `VmExit` fallback.
- [ ] **P6b**: I/O APIC programming (`x2apic::IoApic`): set redirection table entries
  for all PCI legacy IRQs targeting dom0 initially.
- [ ] **P6c**: MSI-X programming: write MSI-X table entries for PCI devices targeting
  dom0's notification vector (LAPIC ID = dom0 VP[0] physical LAPIC).
- [ ] **P6d**: `IrqRouter::configure_domain_policy(domain, policy, hw)`:
  called by `VMCALL_SEAL` handler; programs EOI-exit bitmap and posted interrupt config.
- [ ] **P6e**: VMEXIT `EXTERNAL_INTERRUPT` handler:
  1. **Immediately** write physical LAPIC EOI: `wrmsr(IA32_X2APIC_EOI, 0)` (x2APIC) or
     MMIO write to LAPIC base + 0xB0 (xAPIC). This clears the physical ISR bit and
     de-asserts level-triggered IRQ lines. Must happen before any other action, and is
     independent of virtual APIC state (see Physical LAPIC EOI section in Q2).
  2. Read `VM_EXIT_INTR_INFO` to obtain the physical vector V.
  3. Look up `IrqRouter::route(V)` → (domain D, delivery mode).
  4. If delivery is `DELIVER` with `PostedInterrupt` or `VirtualInject`:
     call `deliver_interrupt_vp`; inject V into handler VP's VIRR (VAPIC page bit set);
     VMRESUME into handler domain VP on same core.
  5. If domain D is confidential and policy is `DEFER_TO_PARENT` or `REPORT`:
     **cross-core routing path** (see Q2 Cross-Core Interrupt Routing):
     a. Write interrupt info (vector, source, IRQ state) into VP META page.
     b. Set `PENDING_IRQ` bit in VP META page header atomically.
     c. Post virtual interrupt to dom0 VP's PI descriptor (`PIR[tyche_irq_notification_vector]`);
        send NV IPI to dom0 core's LAPIC → APICv delivers to dom0 with zero VMEXIT.
     d. Park core X with `CLI` — spin poll loop on RESUME_WITH_IRQ / RESUME_NO_IRQ bits
        in VP META page, calling `poll_and_respond_cross_core()` each iteration for barrier
        participation.
     e. On `RESUME_WITH_IRQ`: PI descriptor `PIR[V]` already set by dom0 core;
        hardware merges PIR → VIRR on VMRESUME; VMRESUME.
     f. On `RESUME_NO_IRQ`: VMRESUME with no pending interrupt (interrupt was for dom0).
- [ ] **P6f**: VMEXIT `EOI_INDUCED` handler: capability engine resume-after-interrupt
  for REPORT-visibility vectors; notify parent chain.
- [ ] **P6g**: Timer interrupt: LAPIC timer → DELIVER to dom0 by default; APICv posts
  it without VMEXIT. Monitor can intercept via EOI-exit bitmap if timer-based preemption
  of child domains is needed.
- [ ] **P6h**: NMI: always VMEXIT (cannot be posted); route to Themis for watchdog/panic.

### Phase 7 — Capability Engine Initialization + dom0 Boot

dom0 bootstrap: Themis acts as the parent and sets up the initial capability tree.

- [ ] **P7a**: `init_root()`: root domain (id=0, sealed, all cores) + r0 covering all
  physical memory from the Limine memory map.
- [ ] **P7b**: Partition r0 into three pools:
  1. `themis_heap` — already reserved in P1a, excluded from the capability tree.
  2. `dom0_meta_pool` — carve as META capabilities; sized for dom0's VMCS + VAPIC +
     VpStateMeta + EPT root pages + VMXON regions.  Reflected in dom0's cap table
     with META flag (dom0 owns them, Themis retains parent-side access).
  3. `dom0_mem` — remaining memory sent to dom0 as normal capabilities.
- [ ] **P7c**: Create dom0 domain; send `dom0_mem` (normal) + `dom0_meta_pool` (META).
- [ ] **P7d**: Set dom0 interrupt policy: all vectors DELIVER (dom0 is the default handler).
- [ ] **P7e**: Allocate dom0 hardware VP structures from the META pool:
  VMCS + VAPIC + PI descriptor + VpStateMeta per VP.  Write all VMCS fields.
  Call `IrqRouter::configure_domain_policy` for dom0.
- [ ] **P7f**: Parse Linux bzImage (using `BootHeader` from P0.5d); write `boot_params`
  into dom0_mem; set up initial identity-mapped page tables in EPT; set VP
  RIP/RSP/RSI/CR3.
- [ ] **P7g**: Seal dom0; `switch_domain(root, dom0, 0)` → VMLAUNCH on BSP; APs VMLAUNCH
  via mailbox.

### Phase 8 — Hypercall Dispatch + Hypercall ABI

- [ ] **P8a**: `crates/themis-abi/`: opcode constants, `VpRegister` enum, error codes.
  Shared between capavisor and `libtyche` guest library.
- [ ] **P8b**: `hypercall.rs`: decode RAX, call `execute(||...)`, encode result.
- [ ] **P8c**: Implement all CapavisorAPI hypercall handlers listed in the Hypercall ABI table,
  including: `VMCALL_CARVE`, `VMCALL_ALIAS`, `VMCALL_SEND`, `VMCALL_ACCEPT`, `VMCALL_REJECT`,
  `VMCALL_CREATE_DOMAIN`, `VMCALL_SEAL`, `VMCALL_REVOKE_MEM`, `VMCALL_REVOKE_DOMAIN`,
  `VMCALL_SWITCH`, `VMCALL_GET_CHAN`, `VMCALL_ATTEST_SELF`, `VMCALL_ATTEST`,
  `VMCALL_GET_REG`, `VMCALL_SET_REG`, `VMCALL_SET_INTR_POLICY`, `VMCALL_SET_DEF_INTR_POLICY`.
  Stubs for `VMCALL_REGISTER_VP_META` and `VMCALL_REGISTER_DOORBELL` (implemented in
  Phases 10–11).
- [ ] **P8d**: `VMCALL_ASSIGN_DEVICE`: validate caller, reprogram IOMMU + I/O APIC.
- [ ] **P8e**: `libtyche` guest library (`crates/libtyche/`): `no_std` VMCALL wrappers.
  Usable from Linux kernel module (`std`) via FFI or from a bare-metal child domain.

### Phase 9 — Multi-Domain Support

- [ ] **P9a**: dom0 `VMCALL_CREATE_DOMAIN` → Themis allocates EPT root + IOMMU PT.
- [ ] **P9b**: dom0 carves memory + sends to child → `apply_update` updates child EPT + IOMMU.
- [ ] **P9c**: dom0 seals child → Themis allocates child VMCS + VAPIC + PI descriptors;
  calls `IrqRouter::configure_domain_policy` for child.
  Allocate a META page per child VP (parent-owned, carve from parent r0) for VP state
  mirroring and PI colocation (Phase 10); register via `VMCALL_REGISTER_VP_META`.
- [ ] **P9d**: `VMCALL_SWITCH` → `switch_domain`, VMPTRLD child VMCS, VMRESUME.
- [ ] **P9e**: `VMCALL_REVOKE_DOMAIN` → capability engine subtree revoke; `on_domain_revoked`
  frees EPT + IOMMU + VMCS + VAPIC structures; reassigns devices to parent.
- [ ] **P9f**: Cross-domain interrupt delivery (REPORT): EOI-exit VMEXIT → capability engine
  `deliver_interrupt_vp` → VMCS switch to handler domain → VMRESUME.

### Phase 10 — META VP-State Regions

Implements the EVMCS-inspired `VpStateMeta` pages for zero-hypercall VP register access,
PI descriptor colocation, and the cross-core interrupt routing channel. Depends on Phase 9.

- [ ] **P10a**: Define `VpStateMeta` struct in `crates/themis-abi/` (shared layout between
  capavisor and driver/userspace). Fields: GPRs, RIP/RSP/RFLAGS, CR0/CR3/CR4/EFER,
  exit_reason, exit_qualification, `dirty` atomic bitmask (DIRTY_GPR | DIRTY_CR |
  DIRTY_RIP | DIRTY_RSP), interrupt routing fields (PENDING_IRQ, RESUME_WITH_IRQ,
  RESUME_NO_IRQ, vector, irq_source), `pi_desc: PostedInterruptDescriptor` (64 B,
  64 B-aligned, at a fixed offset within the 4 KB page).
- [ ] **P10b**: `VMCALL_REGISTER_VP_META(domain_handle, vp_id, meta_cap_handle)`:
  - Validate: caller is the parent domain of the target domain VP.
  - Validate: `meta_cap_handle` is a META capability (4 KB, 4 KB-aligned) owned by caller.
  - Map the META physical page into Themis's own root-mode address space via
    `crates/capavisor-pt` (the `verified-nrkernel` adapter): call `capavisor_pt::map_meta(phys)`.
  - Store `VirtAddr` of the mapped page in `VpHw.meta_virt` and physical address in
    `VpHw.meta_phys`.
  - Update `VpHw.pi_desc_phys` to point to the PI descriptor field within the META page
    (eliminating the separately-allocated PI descriptor once META is registered).
  - Update the VMCS `POSTED_INTR_DESC_ADDR` field to `meta_phys + offset_of!(pi_desc)`.
- [ ] **P10c**: On every VMEXIT from a VP that has a registered META page, Themis writes
  the VP mirror: copy `{RIP, RSP, RAX-R15, CR0, CR3, CR4, EFER, RFLAGS, exit_reason,
  exit_qualification}` from VMCS guest-state and saved GP registers into `VpStateMeta`
  fields. Use `Release` store ordering on the last field to ensure visibility.
  Optimization: only write on suspension events (not VMCALL returns) per open question P10g;
  add a `SUSPEND_EVENT` bit to distinguish at VMEXIT dispatch.
- [ ] **P10d**: On every VMENTRY for a VP with a registered META page, check `dirty` field:
  if any `DIRTY_*` bit is set, reload the corresponding VMCS guest-state fields from the
  META page (consume with `Acquire` load), then clear `dirty` atomically. This is the
  parent's zero-cost `THEMIS_SET_VP_REGS` path.
- [ ] **P10e**: Update the `THEMIS_GET_VP_REGS` ioctl path in the driver (Phase 12): if META
  page is mapped, read directly from the mmap'd META page — no hypercall. Document as the
  fast path; `VMCALL_GET_REG` remains available as a slow fallback.
- [ ] **P10f**: Update cross-core interrupt routing (P6e step 5) to use META page fields
  (`PENDING_IRQ`, `RESUME_WITH_IRQ`, `RESUME_NO_IRQ`, vector, irq_source) rather than
  any separate data structure.
- [ ] **P10g**: Resolve write-back timing open question: implement generation counter in
  META page header so the parent can detect stale state; benchmark overhead of writing
  on every VMEXIT vs. only on suspension events on a high-frequency VMCALL workload.

### Phase 11 — TychIC: Doorbell and Event Flag Pages

Implements the SynIC-inspired cross-domain notification protocol. Depends on Phase 10.

- [ ] **P11a**: Define event flag page layout in `crates/themis-abi/`: a 4 KB page where each
  bit corresponds to a notification slot (up to 4096 slots). Both parent and child have this
  page mapped (parent via META, child via a normal GPA mapping in its EPT).
- [ ] **P11b**: `VMCALL_REGISTER_EVENT_FLAGS(domain_handle, vp_id, meta_cap_handle)`:
  register an event flag page for a domain VP. Themis maps the physical page into root mode
  (via `capavisor-pt`) and also maps it into the child domain's EPT at a Themis-reserved GPA
  range. Parent holds META capability; child has read/clear access only.
- [ ] **P11c**: `VMCALL_REGISTER_DOORBELL(domain_handle, vp_id, gpa, slot, vector)`:
  register a doorbell — a write by the domain (or any domain that can reach that GPA) to
  `gpa` is intercepted as an EPT violation; Themis sets bit `slot` in the target VP's event
  flag page and injects `vector` into the target VP via PI descriptor. The writing domain
  gets no VMEXIT (EPT violation fires on the *writing* VP, which is a different domain if
  cross-domain signalling).
- [ ] **P11d**: In the EPT_VIOLATION VMEXIT handler: check if the faulting GPA matches any
  registered doorbell range. If yes: set event flag bit, post interrupt to target VP, and
  VMRESUME the writing VP — no userspace involvement needed for the delivery path.
- [ ] **P11e**: Interrupt channel registration: `VMCALL_REGISTER_INTR_CHANNEL(child, vp_id,
  slot, vector)` — when child writes to the slot-associated GPA, Themis injects `vector`
  directly into the child VP (or parent VP if the direction is inverted). Enables device
  interrupt virtualization for driver domains with parent domain off the hot path.
- [ ] **P11f**: TychIC vs raw APIC exposure: decide (per open question in Q2) whether the
  doorbell/event-flag mechanism is invisible to Linux in dom0 (only `themis-vmm.ko` and
  userspace VMMs use it) or whether a paravirtual driver is needed for dom0 Linux.

### Phase 12 — `themis-vmm.ko` Linux Kernel Driver

Thin Linux kernel module that exposes `/dev/themis` to userspace (dom0 and any domain with
child-creation capabilities). Depends on Phase 8 (hypercall ABI). Developed in a separate
`drivers/themis/` or standalone repo; loaded as a `.ko` into the Linux dom0.

- [ ] **P12a**: CPUID hypervisor leaf: have Themis return a custom vendor string (e.g.
  `"TycheVMMMMM"`) on leaf `0x40000000`. `themis-vmm.ko` probes this at `module_init` to
  detect the Themis hypervisor; refuses to load otherwise.
- [ ] **P12b**: Character device `/dev/themis`: `file_operations` with `open`, `release`,
  `unlocked_ioctl`, `mmap`. One file descriptor per managed domain (or a root FD for
  domain creation).
- [ ] **P12c**: Implement ioctl handlers (all translate to `VMCALL` via inline asm):
  - `THEMIS_CREATE_DOMAIN` → `VMCALL_CARVE` + `VMCALL_CREATE_DOMAIN`
  - `THEMIS_MAP_MEMORY` → `VMCALL_CARVE` + `VMCALL_SEND`
  - `THEMIS_SET_VP_REGS` → META page write if META registered; else `VMCALL_SET_REG`
  - `THEMIS_GET_VP_REGS` → META page read if META registered; else `VMCALL_GET_REG`
  - `THEMIS_INIT_DOMAIN` → `VMCALL_SET_INTR_POLICY` * N + `VMCALL_SEAL`
  - `THEMIS_DELETE_DOMAIN` → `VMCALL_REVOKE_DOMAIN`
  - `THEMIS_RUN_VP` → `VMCALL_SWITCH` (blocks in kernel until next intercept; intercept
    info written by Themis to the VP's intercept message page before suspending the VP)
  - `THEMIS_IRQFD` → kernel-side eventfd → interrupt injection via PI descriptor
  - `THEMIS_IOEVENTFD` → kernel-side MMIO/PIO write → eventfd signalling
- [ ] **P12d**: Intercept message page: for each VP, Themis writes exit reason + faulting
  address + exit qualification to the VP's `VpStateMeta` page (already defined in Phase 10).
  `THEMIS_RUN_VP` returns to userspace with a pointer to the mmap'd META page; the userspace
  VMM reads intercept info without a kernel copy.
- [ ] **P12e**: `mmap` implementation: allow userspace to map the VP META page
  (`VM_PFNMAP`, read-only for intercept info, read-write for register dirty flags).
  GPA memory regions can optionally be mmap'd for direct device emulation (phase 9+).
- [ ] **P12f**: `THEMIS_IRQFD`: `eventfd_ctx` + workqueue; on eventfd signal, write
  `PIR[vector]` in VP PI descriptor and send NV IPI to the VP's physical core if VP is
  running; else set VIRR bit for delivery on next VMENTRY.
- [ ] **P12g**: `THEMIS_IOEVENTFD`: install an EPT-violation or I/O-bitmap intercept for
  a specified GPA/port range; on match, signal the registered eventfd without going to
  userspace → enables zero-copy virtio kick paths.
- [ ] **P12h**: Driver recursion: any domain that has child-creation capabilities can load
  `themis-vmm.ko` inside its own Linux instance; the ioctl surface is identical. The driver
  uses the same `VMCALL` ABI regardless of depth in the domain tree.

### Phase 13 — AMD SVM Support

Parallel to the Intel VT-x path; gated behind `#[cfg(target_feature = "svm")]` or a runtime
CPU feature flag. Depends on Phase 2 (VT-x provides the pattern).

- [ ] **P13a**: CPUID check for AMD-V: `CPUID[0x80000001].ECX[bit 2]` (SVM available);
  `CPUID[0x8000000A]` for SVM version, NASID, AVIC support. Record in `CpuFeatures`.
- [ ] **P13b**: Hand-roll `Vmcb` struct from AMD APM Vol.2 §15 (control area + state save
  area, each 0x400 bytes). Use `not-matthias/amd_hypervisor` as a field-name reference
  (Windows KM, not directly usable, but authoritative field definitions). Mark all fields
  `#[repr(C)]`; verify sizes with `static_assert_eq!(size_of::<Vmcb>(), 0x1000)`.
- [ ] **P13c**: VMRUN / VMSAVE / VMLOAD wrappers as `unsafe fn` using inline `asm!`:
  ```rust
  unsafe fn vmrun(vmcb_phys: u64) { asm!("vmrun rax", in("rax") vmcb_phys, options(nostack)); }
  unsafe fn vmsave(vmcb_phys: u64) { asm!("vmsave rax", in("rax") vmcb_phys); }
  unsafe fn vmload(vmcb_phys: u64) { asm!("vmload rax", in("rax") vmcb_phys); }
  ```
  Enable SVM globally: `wrmsr(IA32_EFER, rdmsr(IA32_EFER) | EFER_SVME)`.
  Allocate per-core VMCB host save area (4 KB from META pool);
  `wrmsr(MSR_VM_HSAVE_PA, host_save_phys)`.
- [ ] **P13d**: VMCB control area setup: intercept VMCALL (`#VMEXIT_VMCALL`), CPUID,
  CR0/CR3/CR4 writes, physical interrupts (`V_INTR_MASKING=1`, `INTERCEPT_INTR=1`),
  NMI (`INTERCEPT_NMI`). Set `GUEST_ASID = domain_id + 1` (0 is invalid).
- [ ] **P13e**: Nested Page Tables (NPT): reuse `crates/ept/` (identical 4-level structure).
  Point `VMCB.N_CR3` at the NPT root instead of `VMCS.EPT_POINTER`.
  Enable: `VMCB.control.nested_paging = 1`.
- [ ] **P13f**: Physical interrupt on VMEXIT (`#VMEXIT_INTR`): same physical LAPIC EOI
  requirement as Intel path — write `wrmsr(IA32_X2APIC_EOI, 0)` immediately. VMEXIT info
  is in `VMCB.exit_info_1` (vector). Follow same cross-core routing logic as P6e.
- [ ] **P13g**: AVIC (AMD Virtual Interrupt Controller): equivalent of Intel APICv.
  Requires: `VMCB.control.virt_ext |= AVIC_ENABLE`; AVIC backing page (4 KB, analogous
  to VAPIC page); AVIC logical/physical tables. Use as AVIC physical table the same
  `VpStateMeta` page approach for PI descriptor colocation if feasible. Defer to post-P13f
  if AVIC is not available on dev hardware.
- [ ] **P13h**: `arch/x86_64/svm.rs`: implement `Arch` trait for SVM path, mirroring
  `arch/x86_64/vmx.rs` structure. Runtime dispatch in `arch/x86_64/mod.rs`:
  `if cpu_features.vmx { vmx::run() } else if cpu_features.svm { svm::run() }`.

### Phase 14 — Custom dom0 Image

**Goal**: replace the stock minimal Linux kernel used in Phase 0.5 with a
purpose-built dom0 image that has Themis-native drivers compiled in, a stripped
configuration, and the correct device support for bare-metal operation.

This is intentionally deferred until Phase 12 (`themis-vmm.ko`) is functional,
because the dom0 image needs to include that driver.

#### Sub-tasks

- [ ] **P14a** — Kernel configuration:
  - Start from `make defconfig` + `make kvm_guest.config` as a baseline.
  - Strip all unnecessary drivers, filesystems, and subsystems.
  - Enable only: virtio-blk, virtio-net, 9p/virtio-fs (for host filesystem sharing),
    serial console, x86 platform quirks required for bare metal.
  - Disable: KASLR, DEBUG_INFO_BTF (speeds up build), unnecessary crypto.
  - Keep: `CONFIG_KVM_GUEST=n` (we are not a KVM guest), `CONFIG_HYPERVISOR_GUEST=y`
    (for paravirt hooks Themis may eventually exploit).
  - Ship a committed `guest/dom0/kernel.config` in the repository.

- [ ] **P14b** — `themis-vmm.ko` integration:
  - The kernel config must be built with module support enabled.
  - After P14a kernel build, compile `themis-vmm.ko` against the kernel source tree
    (out-of-tree module build: `make -C <kernel_src> M=<driver_src>`).
  - Pack the module into the initrd via a `scripts/pack-dom0-initrd.sh` helper that
    uses `gen_init_cpio` or `dracut --no-compress`.

- [ ] **P14c** — Minimal rootfs:
  - Use **Alpine Linux mini rootfs** or **BusyBox static** for a small footprint.
  - The rootfs must auto-load `themis-vmm.ko` on boot (add to `/etc/modules` or
    an init script).
  - Provide a minimal init (`/sbin/init` or a custom PID-1 written in Rust) that:
    1. Loads `themis-vmm.ko`.
    2. Opens `/dev/themis` and performs the `THEMIS_REGISTER_CHILD_CREATE` hypercall
       to advertise dom0's child-creation capability to Themis.
    3. Spawns a getty on `ttyS0` for interactive debugging.

- [ ] **P14d** — Build script `scripts/build-dom0.sh`:
  - Fetches kernel source at pinned tag (e.g. `v6.8`).
  - Applies config from `guest/dom0/kernel.config`.
  - Builds `bzImage` + out-of-tree `themis-vmm.ko`.
  - Assembles initrd with rootfs + module.
  - Outputs `guest/dom0/vmlinuz` and `guest/dom0/initrd.img`, replacing the
    cloud-image-extracted versions from Phase 0.5a.

- [ ] **P14e** — Validation:
  - Boot under QEMU; verify serial console output shows kernel + driver messages.
  - Confirm `themis-vmm.ko` loads without errors (module params, `/proc/themis` or
    similar sysfs node visible).
  - Run a basic child-domain creation smoke test via the driver.

#### Design notes

**Kernel version policy**: pin to an LTS kernel (6.6 or 6.12) and update
intentionally.  The `themis-vmm.ko` driver will need to track the KVM/mshv API
surface it borrows from; a pinned kernel version prevents surprise breakage.

**No KVM inside dom0**: dom0 must not be allowed to load `kvm.ko` or `kvm-intel.ko`.
The kernel config should have `CONFIG_KVM=n` to prevent accidental use of the
in-kernel hypervisor from inside a Themis domain.

**Long-term**: the custom dom0 image is a candidate for reproducible builds
(Nix flake or BitBake/Yocto) so the exact kernel + rootfs can be reproduced from
source for audit purposes.  This is a post-MVP concern.



## Platform API / Unimplemented Features

- [ ] **#U1** `UpdateBatch::snapshots` — rollback not implemented. _Deferred — future work._
- [ ] **#U2** `CapavisorAPI::ENUMERATE` / `enumerate_pending` — semantics TBD. _Deferred._
- [ ] **#U3** Cache coloring — see `./2026/docs/design/address_translation.md`. _Phase 4–6 of address translation design._
