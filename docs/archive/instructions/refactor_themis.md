# Themis Capavisor — Refactor Design Document

> **Status**: DRAFT — Phase P7i (Post-boot cleanup)
> **Context**: dom0 boots to login with stock Ubuntu 5.15.0-171-generic kernel,
> single and multi-CPU. Time to clean the foundation before building on it.

---

## Table of Contents

1. [Design Guidelines](#1-design-guidelines)
2. [Threading Model & Stacks](#2-threading-model--stacks)
3. [VCPU Abstraction](#3-vcpu-abstraction)
4. [Domain Model](#4-domain-model)
5. [VMEXIT Handler Architecture](#5-vmexit-handler-architecture)
6. [Memory Allocation](#6-memory-allocation)
7. [Module Organisation](#7-module-organisation)
8. [Known Shortcuts to Harden](#8-known-shortcuts-to-harden)
9. [Notes](#9-notes)

---

## 1. Design Guidelines

### Principles

- **One struct, one concern**: A VCPU should be *one* type that owns all its
  state (VMCS phys, VAPIC phys, host stack, guest register cache). Today this
  is split across `VpHardware`, `Domain`, `PerCoreCell`, and raw VMCS fields.

- **Allocate once, reuse**: VP provisioning (VMXON, VMCS, VAPIC, host stack,
  MSR bitmap) should be a single function that returns a fully-initialised VP.
  Currently spread across `Domain::alloc_*`, `boot::vmcs()`, `vmcs::setup_vmcs_for_vp()`.

- **Distinguish boot-time from runtime**: Boot-time code (Limine handoff,
  memory carving, GDT/TSS setup) is inherently sequential and single-use.
  Runtime code (VMEXIT handling, domain creation, capability operations) must
  be reentrant and per-core. Keep them in separate modules.

- **Minimal global state**: Currently 6+ global `AtomicXxx` variables in
  `main.rs`. After boot, only `PLATFORM_PTR` should be needed; per-core state
  goes into a per-core struct indexed by APIC ID.

- **Debug-mode verification**: Add `#[cfg(debug_assertions)]` vmread-back
  checks after VMCS writes. Currently 100+ vmwrites with no verification —
  a single bad write causes silent VMRESUME failure.

### Coding conventions

- No `unsafe` blocks without a `// SAFETY:` comment.
- Prefer `expect("context")` over `unwrap()` in non-hot paths.
- Keep the VMEXIT handler zero-allocation (no heap in the exit path).
- `serial_println!` diagnostics guarded by a verbosity level or `cfg(debug)`.

### What NOT to change (yet)

- EPT structure and mapping logic — working, tested, used by capability engine.
- Capability tree / rights model — orthogonal to VP refactor.
- ACPI parsing — stable, self-contained.
- Limine boot protocol interface — external dependency.

---

## 2. Threading Model & Stacks

### Current state

```
BSP (_start)                          AP (ap_entry)
───────────                           ──────────────
Limine entry                          Limine entry (SMP trampoline)
  │                                     │
  ├─ platform()   memory carving        ├─ spin on AP_LAUNCH_READY (Acquire)
  ├─ init_themis() heap, GDT, ACPI      │
  ├─ vmx()        VMXON all cores       │
  ├─ capa()       capability tree       │
  ├─ vmcs()       VMCS for all VPs      │
  ├─ linux()      load kernel+initrd    │
  ├─ launch()     VMLAUNCH (BSP VP)     ├─ read VMXON_PHYS[id], PLATFORM_PTR
  │               ↓ never returns       ├─ VMXON
  └─ [guest]                            ├─ VMPTRLD
                                        ├─ VMLAUNCH (wait-for-SIPI)
                                        │   ↓ never returns
                                        └─ [guest, parked until SIPI]
```

**Synchronisation**: `AP_LAUNCH_READY` (AtomicBool, Release/Acquire) is the
single barrier between BSP setup and AP entry. BSP stores all per-AP data
(VMXON phys, VMCS phys) before the Release store. APs read after Acquire load.

**Per-core state access** (3 tiers):
| Tier | Lock | Scope | Example |
|------|------|-------|---------|
| 0 | None (atomic) | Per-core cell | `current_domain`, `current_vp` |
| 1 | `Mutex` | Per-domain | `PlatformDomain` (EPT, META, VPs) |
| 2 | `RwLock` | Global | `RoutingMaps`, `op_lock` |

### Stacks

| Stack | Size | Allocation | Lifetime |
|-------|------|------------|----------|
| BSP boot | ~64 KiB | Limine-provided | Until VMLAUNCH |
| AP boot | ~16 KiB | Limine SMP trampoline | Until VMLAUNCH |
| Host VMX (per-VP) | 16 KiB | Heap `Vec<Box<[u8]>>` | Domain lifetime |
| Guest kernel | N/A | Guest-managed | Guest lifetime |

The host VMX stack is the RSP loaded on every VMEXIT (`HOST_RSP` in VMCS).
The VMEXIT trampoline pushes 15 GPRs (~120 bytes), then calls `handle_vmexit`
which uses the remaining stack for Rust function calls.

**Pain point**: Host stacks are heap-allocated (`Vec<Box<[u8; 16384]>>`) and
stored in `VmcsState::host_stacks`. This scales poorly for multi-domain
(16 KiB × num_cores × num_domains). Consider META-pool allocation.

### Proposed changes

I don't like the fact that we allocate the capavisor stacks from the heap.
This is consuming heap resources for no good reason. How big is the stack provided to each core by limine and why this can't be used?
Also the model right now registers the handle_vmexit as the host RIP so that we jump there after an exit. I would like something that looks more like a function call for vmrun so that we can use it in a function that might have some context passed to it as arguments later on (useful to avoid globals). 
The ../../vmxvmm/ has a nicer abstraction for the vmentry that looks like a function call/return from the host.

---

## 3. VCPU Abstraction

### Current state — fragmented across 4 places

```
Domain (domain.rs)          PlatformDomain (platform.rs)
  vmxon_regions: Vec<u64>     vps: Vec<VpHardware>
  vmcs_regions:  Vec<u64>         └─ vmcs_phys: u64
  vapic_regions: Vec<u64>
  io_bitmap_a/b: u64         PerCoreCell (platform.rs)
  msr_bitmap:    u64            current_domain: AtomicU64
                                current_vp:     AtomicU32

                              VMCS (hardware)
                                HOST_RSP, HOST_RIP
                                all guest state fields
                                control fields
```

There is no single type that represents "a virtual processor with all its
state." Identity is implicit: `vp_index == core_index` for dom0, `VPID =
vp_index + 1`.

### Proposed: unified `Vcpu` struct

```rust
/// A virtual CPU — owns all hardware and software state for one VP.
pub struct Vcpu {
    /// VP index within its domain (0-based).
    pub vp_index: u32,
    /// VPID for TLB tagging (globally unique, 1-based).
    pub vpid: u16,
    /// Physical address of the 4 KiB VMCS page.
    pub vmcs_phys: u64,
    /// Physical address of the 4 KiB virtual-APIC page.
    pub vapic_phys: u64,
    /// Physical address of the host stack top (16 KiB, 16-byte aligned).
    pub host_stack_top: u64,
    /// Cached guest GPRs (saved/restored by trampoline on VMEXIT/VMRESUME).
    pub regs: GuestRegs,
    /// The physical core this VCPU is currently scheduled on (or None).
    pub pinned_core: Option<u32>,
}
```

**Provisioning** becomes a single function:
```rust
impl Vcpu {
    /// Allocate and initialise a VCPU for the given domain.
    pub fn provision(
        domain: &mut PlatformDomain,
        vp_index: u32,
        vpid: u16,
        eptp: u64,
    ) -> Result<Self, VcpuError> { ... }
}
```

### Open questions

- Should `GuestRegs` live in the `Vcpu` struct or on the host stack (current
  approach — pushed/popped by the trampoline)? Stack-based is faster (no
  pointer indirection) but couples the struct to the asm layout.

- Should `Vcpu` own the host stack memory, or should stacks come from a
  separate pool? Ownership simplifies drop semantics but means `Vcpu` is not
  `Send` if the stack is heap-pinned.

- VMCS-as-source-of-truth vs shadow copy: currently all guest state lives only
  in the VMCS (read via `vmread`). A shadow copy in `Vcpu` would enable
  inspection without `vmread` but adds consistency risk.

Answers:
- Stack based saving before jumping is alright, but the Domain structure in the platform should have the array for general purpose registers.
- No the host stack will be reused across vcpus and is not related to the vcpu. It should not be owned. 
- for now keep it in the vmcs, we'll do something about it later.


Other notes:

I want a clean ActiveVcpu/InactiveVcpu abstraction that encapsulates all of this.
I want the ActiveVcpu to correspond to the vmptrld state of the vmcs, while InactiveVcpu is when it's not the currently active one on the core.
I want the vmread and vmwrite to be methods on the ActiveVcpu. 
I also want somehow to consider how we could handle vcpu migration across cores by doing a !Send in rust for example, requiring the appropriate flush on the last core it ran on before being loaded into a new core.
I think starting with this is the top priority. You can also draw inspiration from ../../vmxvmm/crates/vmx/ BUT remember that this other project didn't have an allocator (the meta allocator) and was doing things via static globals. We do not need to do that here.

---

## 4. Domain Model

### Current state

```
ThemisPlatform
  └─ domain_table: DomainTable
       └─ BTreeMap<DomainId, Arc<Mutex<PlatformDomain>>>
            └─ PlatformDomain
                 ├─ ept: Option<EptMapper>
                 ├─ meta: MetaAllocator    (free-stack for phys pages)
                 ├─ vps: Vec<VpHardware>   (just vmcs_phys today)
                 ├─ parent: Option<DomainId>
                 └─ allocated: Vec<AllocatedRegion>
```

`Domain` (domain.rs) is a *separate* struct used only during boot to track
allocation of VMXON/VMCS/VAPIC/bitmap pages. It does not survive past boot.
`PlatformDomain` is the runtime representation.

### Proposed consolidation

After refactor, `Domain` (boot-only) disappears. `PlatformDomain` holds
`Vec<Vcpu>` instead of `Vec<VpHardware>`. Allocation tracking moves into
`Vcpu::provision()`.

```
PlatformDomain
  ├─ id: DomainId
  ├─ vcpus: Vec<Vcpu>          // replaces vps + Domain's parallel Vecs
  ├─ ept: EptMapper             // non-optional after init
  ├─ meta: MetaAllocator
  ├─ msr_bitmap_phys: u64
  ├─ io_bitmap_phys: (u64, u64)
  └─ parent: Option<DomainId>
```

### Open questions

- Lifetime of VMXON regions: currently one VMXON page per physical core, owned
  by dom0's `Domain` struct. Should VMXON be per-core global state (not
  per-domain)? On bare metal, VMXON is done once per core and never undone.

- Domain destruction: currently no `drop`/`destroy` path. Need to define what
  happens to a domain's META pages, EPT tables, and VCPUs when revoked.

Answer:
- VMXON: one per core, never changes whether dom0 is running or another domain.
These can be stored in the global structure but are still allocated at boot by reserving memory.

- We will refine that once we integrate the revoke domai: one per core, never changes whether dom0 is running or another domain.
These can be stored in the global structure but are still allocated at boot by reserving memory.

- We will refine that once we integrate the revoke domain. We will need to collect platform state in a thread safe way.

---

## 5. VMEXIT Handler Architecture

### Current state

`vmexit_trampoline` (naked asm):
```
VMEXIT → push 15 GPRs → call handle_vmexit(&mut GuestRegs) →
         pop 15 GPRs  → VMRESUME
```

`handle_vmexit` is a single 400-line function with a `match basic_reason`.
All exit reasons handled inline. Global atomics (`EXIT_COUNT`, `LAST_REASON`)
for diagnostics.

### Issues

1. **No per-VCPU context in handler**: The handler doesn't know which VCPU
   it's running on. It has to vmread VPID or check the core's `PerCoreCell`.

2. **Host state on stack only**: If we need to access `Vcpu` fields (e.g.,
   domain-specific policy), we'd need a pointer. Options:
   - Store `&mut Vcpu` pointer at a known offset on the host stack
   - Use a per-core global (indexed by APIC ID or core index)
   - Stash pointer in an unused VMCS field (HOST_IA32_SYSENTER_ESP, etc.)

3. **All exits in one function**: Makes it hard to test or extend individual
   handlers. Consider dispatching to per-reason functions.

### Proposed changes

For the above, see my previous comment about making vmrun a function call like abstraction. We will go into a function with the appropriate per-core state passed as a function call argument and handle things from there.

---

## 6. Memory Allocation

### Two pools

| Pool | Purpose | Allocator | Backing |
|------|---------|-----------|---------|
| META | VMXON, VMCS, VAPIC, EPT, MSR/IO bitmaps | `MetaAllocator` (free-stack) | Physical frames from Limine memory map |
| Heap | Rust data structures (`Vec`, `BTreeMap`, `Arc`) | `linked_list_allocator` | 64 MiB static BSS array |

### Concerns

- **Heap in VMEXIT path**: Currently the handler is heap-free, but it's not
  enforced. Any accidental `Vec::push` or `format!` in the hot path would
  allocate. Consider `#[deny(clippy::disallowed_methods)]` for heap-allocating
  functions in `vmexit.rs`.

- **META exhaustion**: No fallback if META runs out of frames. `alloc_frame()`
  returns `Option<u64>` but callers mostly `expect()`. Need graceful error
  propagation for child domain creation.

- **No deallocation path**: META frames are allocated but never freed (no
  domain teardown yet). The free-stack supports `push` but it's never called
  after boot.

Answers:

We will handle this after the first few items on the refactoring list.

---

## 7. Module Organisation

### Current layout (5,652 lines total)

```
capavisor/src/
├── main.rs          (302)   Entry points, global state, serial macros
├── boot.rs         (1238)   7-phase boot sequence (MONOLITH)
├── vmexit.rs        (723)   VMEXIT trampoline + handler
├── platform.rs      (624)   Platform trait, domain table, barriers
├── vmcs.rs          (426)   VMCS field setup
├── acpi.rs          (415)   ACPI/MADT/DMAR parsing
├── vmx.rs           (167)   VMX feature detection, enable
├── domain.rs        (141)   Domain struct (boot-only)
├── gdt.rs           (214)   GDT/TSS per-core setup
├── pci.rs           (178)   PCI enumeration
├── guest/
│   ├── linux.rs     (550)   bzImage loading, boot_params
│   └── modules.rs    (49)   Limine module parsing
└── mem/
    ├── inventory.rs (204)   Memory map → region list
    ├── uncacheable.rs(161)  UC range tracking
    ├── paging.rs    (120)   Kernel page tables
    └── meta_alloc.rs(113)   Free-stack frame allocator
```

### Proposed splits

- `boot.rs` (1238 lines) → split into `boot/phases.rs` + `boot/linux.rs`
  (or keep `guest/linux.rs` and slim `boot.rs`)
- `platform.rs` → `platform/mod.rs` + `platform/domain_table.rs` +
  `platform/routing.rs` + `platform/barriers.rs`
- `vmexit.rs` → `vmexit/trampoline.rs` + `vmexit/handlers.rs` +
  `vmexit/msr.rs` + `vmexit/cpuid.rs`
- `domain.rs` → merge into `platform/domain.rs` or into new `vcpu.rs`

### New modules to add

- `vcpu.rs` — unified VCPU struct + provisioning
- `inject.rs` — event injection helpers (`inject_gp`, `inject_ud`, etc.)

Answer:

A cleaner split would give us all the general vmx related code in one crate, including the vcpu abstractions I was talking about, and then we split the rest of the logic specific to the monitor into modules.

---

## 8. Known Shortcuts to Harden

### Must fix (affects correctness)

| ID | Issue | Where | Risk |
|----|-------|-------|------|
| S1 | **INVEPT missing** | platform.rs:484 | Stale TLB entries after EPT changes |
| S2 | **AP TSS hard-coded to core 0** | vmcs.rs:265 | Breaks if APs need per-core TSS |
| S3 | **No VMCS state verification** | vmcs.rs | Silent VMRESUME failure on bad field |
| S4 | **Nested VMX XCR0 workaround** | boot.rs:1193, main.rs:264 | Unnecessary on bare metal |

### Should fix (affects robustness)

| ID | Issue | Where | Risk |
|----|-------|-------|------|
| S5 | **VAPIC allocated but unused** | domain.rs:87 | Wasted META pages |
| S6 | **Domain routing race window** | platform.rs:562 | Stale core→domain map |
| S7 | **Host stack scaling** | boot.rs:938 | 16K × cores × domains |
| S8 | **No META deallocation** | meta_alloc.rs | Memory leak on domain destroy |

### Deferred (post-refactor)

| ID | Issue | Ticket |
|----|-------|--------|
| D1 | vAPIC for all domains | #U5 |
| D2 | XSAVES/XRSTORS support | #U6 |
| D3 | VT-d / IOMMU integration | P4 |

_[Your notes here]_

---

## 9. Notes

_[Space for your notes, design decisions, sketches, and open questions]_

---
