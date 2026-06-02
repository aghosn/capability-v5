# capavisor

The Themis hypervisor binary (`no_std`, `x86_64-unknown-none`).

This crate is the **L0 capability hypervisor** in the broader Themis
three-tier stack (L0 capavisor / L1 dom0 / L2 nested guest, see
[`../../CONTEXT.md`](../../CONTEXT.md)). The build/boot/qemu workflow lives
in [`../README.md`](../README.md). This file documents what's *inside*
`capavisor/src/`: how the code is layered, which types form each layer's
interface, and which file owns what.

---

## Internal layering

Within `capavisor`, the source is organised around four cooperating
layers plus an arch backend. Each layer talks to its neighbours through a
narrow set of types — not by reaching into private struct fields.

```
                      ┌────────────────────────────────────┐
   ABI (L1)           │ themis-abi crate                   │
                      │   opcodes::*, errors::*, VpRegister│  ← external surface for
                      │   (no_std, shared with dom0/thhv)  │     dom0 / nested guests
                      └──────────────┬─────────────────────┘
                                     │  HypercallArgs / HypercallResult
                                     ▼
                      ┌────────────────────────────────────┐
   Dispatch (L2)      │ src/hypercall/                     │
                      │   reads CoreContext → CapabilityRef│  ← arch-neutral routing
                      │   calls capa-engine execute()      │
                      │   ArchHypercall for raw-VP work    │
                      └──────────────┬─────────────────────┘
                                     │  Update batch + Platform trait
                                     ▼
                      ┌────────────────────────────────────┐
   Engine (L2a)       │ capa-engine crate                  │
                      │   Capability tree + execute()      │  ← validates first,
                      │   emits Update list                │     mutates after
                      └──────────────┬─────────────────────┘
                                     │  Platform::apply_update(&Update)
                                     ▼
                      ┌────────────────────────────────────┐
   Platform (L3)      │ src/platform/  (ThemisPlatform)    │
                      │   per-domain EPT/IOMMU + COMM      │  ← capability_engine::Platform
                      │   per-core CoreContext + VcpuSlot  │     trait impl
                      │   cross-core IPI barrier protocol  │
                      └──────────────┬─────────────────────┘
                                     │  ArchVpOps / ArchGuestPhysMap /
                                     │  ArchCoreSignaling / ArchIommu / ArchBoot
                                     ▼
                      ┌────────────────────────────────────┐
   Arch backend       │ src/arch/x86_64/   (and aarch64/)  │
                      │   VMCS, posted-IPIs, EPT, VT-d,    │  ← ISA-specific mechanism
                      │   APIC, ACPI, GDT, boot, IRQ DT    │
                      └────────────────────────────────────┘
```

### Interface types (where layers meet)

| Boundary | Types / traits | Where defined |
|---|---|---|
| ABI ↔ Dispatch | `themis_abi::opcodes::*`, `themis_abi::errors::*`, `VpRegister` | [`themis-abi`](../crates/themis-abi/) |
| Dispatch ↔ Arch | `HypercallArgs`, `HypercallResult`, `ExitInfo`, `SemanticExit`, `Vp<A>` | [`arch_traits/types.rs`](src/arch_traits/types.rs) |
| Dispatch / Monitor ↔ Arch | `ArchVpOps`, `ArchHypercall` | [`arch_traits/traits.rs`](src/arch_traits/traits.rs), [`hypercall/mod.rs`](src/hypercall/mod.rs) |
| Dispatch ↔ Engine | `capability_engine::execute()`, `OpLockGuard`, `CapabilityRef<Domain>`, `Update` batch | [`capa-engine`](../../capa-engine/) |
| Engine ↔ Platform | `capability_engine::Platform` trait (`apply_update`, `op_lock`, `notify_cores`, …) | [`capa-engine`](../../capa-engine/), impl in [`platform/mod.rs`](src/platform/mod.rs) |
| Platform ↔ Arch | `ArchVpOps`, `ArchGuestPhysMap`, `ArchCoreSignaling`, `ArchIommu`, `ArchBoot` | [`arch_traits/traits.rs`](src/arch_traits/traits.rs) |
| Platform ↔ Domain state | `ArchDomainState`, `ArchPlatformState` (per-arch concrete types) | [`arch/<isa>/arch_state.rs`](src/arch/x86_64/arch_state.rs) |

The key invariant (axiom **A1**): every hypercall flows
**Dispatch → `execute()` → `apply_update`**. The capability engine
validates the operation against the capability tree *before* the platform
touches any hardware. There is no path from ABI directly to arch code.

The key arch-neutrality invariant (axiom **A9**): the dispatch layer
talks to hardware only via `ArchVpOps` / `ArchHypercall`. Any new arch
backend reimplements those traits, and the dispatch and monitor loop
should compile unchanged.

---

## Source tree

```
src/
├── main.rs                # BSP entry, Limine boot, BSP→AP bring-up,
│                          # one-shot orchestration of arch::boot::*
├── monitor.rs             # Generic per-core run loop (ArchVpOps-driven)
│                          # SemanticExit dispatch → policy / hypercall / forward
│
├── util.rs                # Tiny crate-wide arch-neutral helpers (fmt_kib, …)
│
├── domain.rs              # Crate-level domain state glue (Tier 0 routing)
├── attestation.rs         # Measured-boot / quote assembly logic
├── comm.rs                # VpComm shared-page accessors (per-VP COMM page)
│
├── arch_traits/           # The arch ↔ everything-else interface
│   ├── traits.rs          #   ArchVpOps, ArchGuestPhysMap, ArchCoreSignaling,
│   │                      #   ArchIommu, ArchBoot
│   ├── types.rs           #   HypercallArgs/Result, SemanticExit, ExitInfo,
│   │                      #   Vp<A>, MapPermissions, PageSize, DeviceId
│   └── mod.rs
│
├── platform/              # L3 — capa_engine::Platform impl (ThemisPlatform)
│   ├── mod.rs             #   ThemisPlatform struct + Platform trait impl
│   ├── domain.rs          #   PlatformDomain, DoorbellEntry, DomainComm*
│   ├── vcpu_slot.rs       #   VcpuSlot (atomic VP take/return), CoreContext
│   ├── sync.rs            #   Two-phase Barrier, Shared/ExclusiveGuard
│   ├── maps.rs            #   CoreUpdate, DomainTable (Tier 2),
│   │                      #   RoutingMaps (Tier 3)
│   └── helpers.rs         #   map_range_typed, rights_to_ept_flags
│                          #   (x86-only EPT seam — see todo platform-arch-seams)
│
├── hypercall/             # L2 — arch-neutral dispatch
│   ├── mod.rs             #   VMCALL → opcode router, ArchHypercall trait
│   ├── capa.rs            #   create/seal/send/revoke (capability ops)
│   ├── vp.rs              #   add/remove VP, set/get VP register
│   ├── doorbell.rs        #   register/unregister/fire doorbell
│   ├── domcomm.rs         #   DomainComm ring enqueue/dequeue
│   └── attest.rs          #   measured-boot quote assembly
│
├── mem/                   # Physical memory + paging
│   ├── inventory.rs       #   E820/Limine memory map → PhysRegion list
│   ├── meta_alloc.rs      #   Per-domain META page allocator
│   ├── uncacheable.rs     #   MMIO range tracking (UC vs WB)
│   ├── paging.rs          #   x86 host page-table builder (HHDM, kernel map)
│   ├── paging_aarch64.rs  #   aarch64 equivalent
│   └── mod.rs
│
├── guest/                 # Image loading helpers (kernels, initrd, modules)
│   ├── linux.rs           #   bzImage / PVH / direct boot helpers
│   ├── modules.rs         #   Initrd / module concat
│   └── mod.rs
│
├── arch/                  # Arch backend(s)
│   ├── mod.rs             #   Cross-arch boot::* contract (doc-comment),
│   │                      #   ArchPlatformState / ArchDomainState selection
│   │
│   ├── x86_64/            # ── Intel VT-x / EPT backend ────────────────────
│   │   ├── mod.rs
│   │   ├── x86_platform.rs   # ArchPlatformState (per-platform x86 state)
│   │   ├── arch_state.rs     # ArchDomainState (per-domain x86 state)
│   │   │
│   │   ├── boot/             # Bring-up pipeline (Phases 1–7)
│   │   │   ├── mod.rs        #   PlatformInfo, VmxState, CapaState, LinuxState
│   │   │   ├── platform.rs   #   Phase 1: ACPI/CPUID/MTRR/PAT discovery
│   │   │   ├── vmx.rs        #   Phase 2a-b: VMX on, IA32_FEATURE_CONTROL
│   │   │   ├── themis.rs     #   ThemisPlatform construction
│   │   │   ├── capa.rs       #   Phase 2c: dom0 capability tree
│   │   │   ├── vmcs.rs       #   Phase 2d: dom0 VMCS init
│   │   │   ├── linux.rs      #   Phase 7f: Linux image staging
│   │   │   └── launch.rs     #   Phase 7g: VMLAUNCH
│   │   │
│   │   ├── vmcs/             # VMCS field encoding / setup
│   │   │   ├── mod.rs        #   Public API (cr0_required_bits, setup_*)
│   │   │   ├── controls.rs   #   Pin/Proc/Entry/Exit controls
│   │   │   ├── host.rs       #   Host-state area
│   │   │   └── guest.rs      #   Guest-state area
│   │   │
│   │   ├── vmexit/           # VMEXIT classification + handlers
│   │   │   ├── mod.rs        #   Top-level dispatch
│   │   │   ├── classify.rs   #   ExitReason → SemanticExit
│   │   │   ├── cpuid.rs      #   CPUID masking, Themis leaf, AVX-512 bitflags
│   │   │   ├── apic.rs       #   x2APIC virtualisation
│   │   │   ├── cr.rs         #   CR0/CR4 access traps
│   │   │   ├── msr.rs        #   MSR read/write virt
│   │   │   └── fatal.rs      #   Unrecoverable exits → panic
│   │   │
│   │   ├── hypercall/        # x86-specific ArchHypercall impl
│   │   │   ├── mod.rs
│   │   │   ├── doorbell.rs   #   Posted-IPI doorbell mechanics
│   │   │   ├── switch.rs     #   VP swap (VMPTRLD, GDT/TSS rebind)
│   │   │   └── vp.rs         #   VP register R/W via VMCS
│   │   │
│   │   ├── vmexit_decode.rs  # MOV decoder, IO qual decode, EPT qual decode
│   │   ├── vcpu_switch.rs    # VMCS swap dance
│   │   ├── vcpu_ext.rs       # ActiveVcpu helpers (next_instruction, …)
│   │   ├── reg_apply.rs      # VpRegister → VMCS field map
│   │   ├── msr_virt.rs       # MSR-virt bitmap construction
│   │   ├── page_walk.rs      # Guest-virtual → guest-physical walk
│   │   ├── apic.rs           # LAPIC MMIO helpers
│   │   ├── pid.rs            # Posted-Interrupt Descriptor management
│   │   ├── pci.rs            # ECAM / config-space helpers
│   │   ├── iommu_ir.rs       # VT-d IR (Interrupt Remapping) tables
│   │   ├── acpi.rs           # ACPI table walk (MADT, MCFG, DMAR)
│   │   ├── gdt.rs            # Per-core GDT/TSS
│   │   └── layout.rs         # Magic numbers (LAPIC base, MMIO sizes, …)
│   │
│   └── aarch64/           # ── ARM VHE / Stage-2 backend (skeleton) ─────────
│       ├── mod.rs
│       ├── aarch64_platform.rs / arch_state.rs
│       ├── boot.rs        # Bring-up
│       ├── boot_descriptor.rs
│       ├── el2_regs.rs    # System registers
│       ├── stage2.rs      # Stage-2 page tables (EPT analogue)
│       ├── mmu.rs         # EL2 MMU
│       ├── gicv3.rs       # GICv3 LR / virtual interface
│       ├── vectors.rs     # EL2 vector table
│       ├── fdt_patch.rs   # Device-tree patching
│       ├── serial.rs
│       └── vcpu.rs
```

---

## Dependencies

- **`capability_engine`** — the validate-then-mutate kernel. Out of tree at
  `../../capa-engine/`. We implement `Platform` for `ThemisPlatform`.
- **`themis-abi`** — the shared hypercall ABI. `no_std`, also consumed by
  the dom0 driver (`thhv`) and any guest userspace.
- **`ept`** — Extended Page Table mapper (workspace crate).
- **`vtd`** — Intel VT-d IOMMU driver (workspace crate).
- **`capavisor-pt`** — host page-table manager (workspace crate, stub).

---

## Adding a new arch backend

1. Create `src/arch/<isa>/` with a `mod.rs` and:
   - `<isa>_platform.rs` — defines `ArchPlatformState`.
   - `arch_state.rs` — defines `ArchDomainState`.
2. Implement `ArchVpOps`, `ArchGuestPhysMap`, `ArchCoreSignaling`,
   `ArchIommu`, `ArchBoot` for that backend (see
   [`arch_traits/traits.rs`](src/arch_traits/traits.rs)).
3. Implement the `arch::boot::*` contract (see the doc-comment in
   [`arch/mod.rs`](src/arch/mod.rs) — `platform()`, `init_themis()`,
   `capa()`, `linux()`, `launch()` are required; `vmx()` is x86-specific).
4. Implement `ArchHypercall` for that arch (see
   [`hypercall/mod.rs`](src/hypercall/mod.rs)).
5. Replace x86-only seams flagged by todo `platform-arch-seams`
   (`platform/helpers.rs` and a few spots in `platform/domain.rs` /
   `platform/mod.rs`).

If your backend's port re-uses any of `mem/paging.rs`, fold the
common parts out as part of the work; the current x86 / aarch64 split
keeps `mem/paging*.rs` per-arch.
