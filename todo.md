## Real platform implementation and integration

**Goal**

Implement the monitor (Tyche) as described in the paper.
The monitor uses the capability engine to maintain a state machine for domains that run on top of it and that the monitor isolates using virtualization extensions (e.g., Intel VT-x).
It starts the initial domain, dom0 that acts as the root on the machine, i.e., the first domain owning the initial memory capabilities.

The goal here is to start a new implementation from scratch.
We can draw inspiration from `../vmxvmm/` that used a previous implementation of capabilities located at `../vmxvmm/crates/capability-engine/`.
However, the implementation (and semantics) are different and we want a clean implementation.

The monitor should run (and boot) on bare-metal.
If we can, it'd ideally enable to target different platform (e.g., Intel and AMD to begin with).


**Differences with the previous implementation**

Many differences exist between the previous impl and the new one we want:

* The new implementation should use the capability engine from this folder.
* The new impl. should enable alloc in the monitor and use heap allocation for capabilities. It should receive a memory region to use as the heap at boot.
* The new implementation should use crates where possible rather than reimplement everything.

* The general idea is the same, but the implementation is radically different and from scratch.

The general parts we will have are:

firmware -- loads --> bootloader --loads --> monitor (tyche in memory) & linux image somewhere so we can virtualize it.

The bootloader is the equivalent of our first stage, and should reserve some continuous memory for the monitor + some space for its heap (configurable), provide information to the monitor about the memory layout and where to find the linux img loaded in memory.
The monitor will then initialize the capability engine, creating the first domain dom0 for the linux image, allocate the memory that it does not use to dom0 via the root memory capability, isolated it with the platform (creating the correct mappings etc.).

We will use the capability META for EPTs (aka SLATs) maintained by the monitor.
So this will be part of the initialization too.

The result should be that the monitor runs in bare-metal root mode on all cores and Linux boots on all cores in non-root mode initially.

## Development setup

We will need a virtualized development setup (like in `../vmxvmm/`) to develop and test our implementation. Ideally this should have support for debugging, correctly map the different binaries in memory to be able to debug root monitor and non-root Linux dom0.

---

## Q1: Using existing crates — Resolved Decisions

### Bootloader

**Decision: Use the Limine bootloader protocol (`limine` crate, crates.io).**

The [Limine protocol](https://github.com/limine-bootloader/limine) is the modern standard for bare-metal Rust kernels/monitors:
- Fully `no_std` compatible; requests declared as `#[used] static` structs.
- Provides everything the monitor needs: physical memory map (unifying E820/UEFI), HHDM offset,
  SMP (`MpRequest`: all AP LAPIC IDs + `goto_address` callback for AP wakeup), RSDP physical
  address (entry point to the ACPI table hierarchy), loaded modules (monitor binary + Linux
  bzImage), framebuffer, kernel virtual/physical base.
- AP bootstrap is handled by Limine (no INIT-SIPI-SIPI in the monitor).
- Replaces the patched `bootloader` crate used by `vmxvmm/monitor/first-stage/`.

```rust
// monitor/src/main.rs — Limine requests (all zero-cost statics)
static BASE_REVISION: BaseRevision       = BaseRevision::new();
static MEMMAP:        MemmapRequest      = MemmapRequest::new();
static MODULES:       ModuleRequest      = ModuleRequest::new();
static SMP:           MpRequest          = MpRequest::new();
static HHDM:          HhdmRequest        = HhdmRequest::new();
static RSDP:          RsdpRequest        = RsdpRequest::new();
static KADDR:         KernelAddressRequest = KernelAddressRequest::new();
```

### VT-x / VMX

**Decision: Use the `x86` crate (crates.io) for VMX instructions and VMCS field constants;
adapt `../vmxvmm/crates/mmu/` for the EPT page-table mapper.**

- **`x86`** (crates.io, v0.52, `no_std`): provides `x86::bits64::vmx` with unsafe wrappers for
  every VMX instruction (`vmxon`, `vmxoff`, `vmptrld`, `vmptrst`, `vmclear`, `vmread`, `vmwrite`,
  `vmlaunch`, `vmresume`) plus the full set of VMCS field encoding constants in `x86::vmx::vmcs`.
  Also covers control registers, MSRs, GDT/IDT, paging, CPUID — everything a bare-metal monitor
  needs from the x86 ISA.
- **EPT page-table mapper**: adapt `vmxvmm/crates/mmu/` (`EptMapper`, 4-level walk, frame
  allocation). No public crate provides a complete EPT mapper.
- No custom VMX crate needed: `x86` is the right public foundation.

### AMD SVM

**Decision: Defer.** The `Platform` trait abstraction isolates architecture-specific code;
AMD support is an additional `src/arch/amd64/` module added later.

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

**Integration path**: because the monitor's `Platform` trait cleanly separates
architecture-specific hardware operations from the capability engine, adding a new
architecture means:
1. Implementing a new `src/arch/<arch>/` module using the corresponding `*_vcpu` crate.
2. Mapping the crate's VM entry/exit interface to the monitor's VMEXIT handler dispatch.
3. Adapting the second-level address translation (EPT equivalent) to the architecture's
   format (Stage-2 page tables on ARM, G-stage on RISC-V) — using the `mmu` crate adapter
   or a new mapper.
4. Providing IRQ routing via the architecture's interrupt controller (GIC on ARM,
   PLIC/IMSIC on RISC-V) instead of the x2APIC + I/O APIC.

The `vmxvmm` reference already has a working RISC-V port (`monitor/tyche` RISC-V target +
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

Provides everything the monitor needs from firmware tables:
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
- The monitor implements `ConfigRegionAccess` using volatile MMIO over the ECAM window whose
  base address is obtained from `acpi::PciConfigRegions`.
- The monitor walks bus 0..255 / device 0..31 / function 0..7 to build a
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

## Monitor Design

### Workspace Structure

```
tyche-monitor/
├── Cargo.toml                     — workspace
├── monitor/                       — bare-metal monitor binary
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
│               ├── ept.rs         — EPT map/unmap wrappers (mmu crate)
│               ├── vapic.rs       — virtual APIC page + posted interrupt setup
│               ├── apic.rs        — x2APIC IPIs, I/O APIC programming
│               ├── smp.rs         — AP wakeup via Limine SMP
│               └── context.rs     — VpRegister enum, VMCS field mappings
├── crates/
│   ├── mmu/                       — adapted from vmxvmm/crates/mmu/ (EPT mapper)
│   ├── vtd/                       — adapted from vmxvmm/crates/vtd/ (VT-d IOMMU)
│   └── tyche-abi/                 — hypercall ABI (shared with guest libtyche)
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

`VProcessorState.registers` maps `VpRegister as u64` → `u64`. The monitor commits these
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
    // virtual APIC state (readable by parent via GET; written by monitor)
    Tpr = 0x60, Ppr = 0x61,
}
```

`VProcessorState.platform_data` stores the VMCS physical address (first 8 bytes) so the
monitor can VMPTRLD the correct VMCS without a map lookup.

#### META Memory for EPTs

```
# Per-domain init (in capability API terms; performed by monitor at dom0 creation
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
  ↓ loads monitor ELF + Linux bzImage module
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
      b. r0 = all usable physical memory minus heap, minus monitor binary.
  13. Wait for APs to complete VT-x init and signal ready.
  14. Create dom0:
      a. carve r0 → dom0_ept_meta (EPT frame pool, META send).
      b. carve r0 → dom0_mem (all remaining memory).
      c. create_domain root dom0 (all cores, all API).
      d. send dom0_ept_meta dom0 META.
      e. send dom0_mem dom0.
      f. Set dom0 VP[i] interrupt policy:
         - default: DELIVER (dom0 handles all interrupts initially).
         - NMI: DELIVER at root (monitor handles, not dom0).
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

The monitor enumerates all PCI/PCIe devices at boot so it can:
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
    // Physical interrupt → VMEXIT → monitor calls deliver_interrupt_vp → capability routing.
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
                // Must use VMEXIT path so the monitor can call deliver_interrupt_vp.
                self.assign_vmexit(vector, domain);
                // Add vector to EOI-exit bitmap for this domain's VPs
                // so that EOI from this domain causes a VMEXIT (allowing the monitor
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
- Every APIC register access (TPR, EOI, ICR) causes a VMEXIT and is emulated by the monitor.
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

| Opcode | MonitorAPI | Capability engine call |
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

### Phase 0 — Workspace Setup

- [ ] **P0a**: Create `tyche-monitor/` workspace; `monitor/` member with `#![no_std]` +
  `#![no_main]` + `extern crate alloc`.
  - Add `capability-engine-v2` path dep: `features = ["address_translation"]`,
    `default-features = false`.
  - Add `x86`, `x2apic`, `acpi`, `pci_types`, `spin`, `limine`, `linked_list_allocator`.
- [ ] **P0b**: Linker script + `.cargo/config.toml` for `x86_64-unknown-none` target.
- [ ] **P0c**: Port `vmxvmm/crates/mmu/` → `crates/mmu/` (EPT mapper, 4-level walk).
  Port `vmxvmm/crates/vtd/` → `crates/vtd/` (VT-d IOMMU register access).
  Remove `vmx` crate dependency (replace with `x86` crate). Verify `no_std` compilation.
- [ ] **P0d**: QEMU development environment:
  - `qemu-system-x86_64 -enable-kvm -cpu host,+vmx -m 8G -smp 4 -cdrom limine.iso -s -S`
  - GDB `.gdbinit`: load monitor ELF symbols + vmlinux symbols at correct addresses.

### Phase 1 — Boot, Memory, ACPI, PCI

- [ ] **P1a**: Limine entry `_start`: parse memory map → `PhysicalInventory`; reserve heap
  (64 MB); init `linked_list_allocator::LockedHeap`.
- [ ] **P1b**: Serial console (UART 16550) + `println!` macro.
- [ ] **P1c**: `FrameAllocator` over physical pages beyond heap (for EPT frames, VMCS, etc.).
- [ ] **P1d**: SMP bootstrap via Limine `MpRequest`: per-AP `goto_address` entry point;
  global barrier until all APs complete Phase 2 init.
- [ ] **P1e**: ACPI parsing:
  - Implement `acpi::AcpiHandler` trait (physical → virtual address mapping using HHDM offset).
  - `AcpiTables::from_rsdp(handler, rsdp_phys)`.
  - Extract: MADT (LAPIC IDs, x2APIC entries), MCFG (PCIe ECAM bases), DMAR raw bytes.
- [ ] **P1f**: PCI enumeration via `pci_types` over ECAM:
  - Implement `ConfigRegionAccess` using volatile MMIO over ECAM window.
  - Walk all buses/devices/functions; decode headers + BARs + capabilities (MSI/MSI-X).
  - Build `DEVICE_TABLE: Vec<PciDevice>`.

### Phase 2 — VT-x Foundation

- [ ] **P2a**: CPUID checks: VMX, x2APIC, APICv (APIC-register virtualization,
  virtual-interrupt delivery, posted interrupts), VT-d. Record a global `CpuFeatures` struct.
- [ ] **P2b**: VMXON on BSP and all APs (per-core VMXON region from `FrameAllocator`).
- [ ] **P2c**: VMCS allocation + minimal setup using `x86::bits64::vmx`:
  - Host state: monitor CS/SS/DS, CR0/CR3/CR4, EFER, RSP/RIP → `vmexit_handler`.
  - Guest state: from `VProcessorState.registers`.
  - Execution controls: intercept VMCALL, CPUID, CR accesses, I/O bitmap, EXTERNAL_INTERRUPT.
- [ ] **P2d**: EPT setup: allocate EPT root from `FrameAllocator`; `ept_map`/`ept_unmap`
  wrappers using `crates/mmu`. EPTP → VMCS `EPT_POINTER` (4-level, WB memory type).
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
- [ ] **P6e**: VMEXIT `EXTERNAL_INTERRUPT` handler: call `IrqRouter::route`, then
  `deliver_interrupt_vp`, then inject into handler VP's VIRR; VMRESUME.
- [ ] **P6f**: VMEXIT `EOI_INDUCED` handler: capability engine resume-after-interrupt
  for REPORT-visibility vectors; notify parent chain.
- [ ] **P6g**: Timer interrupt: LAPIC timer → DELIVER to dom0 by default; APICv posts
  it without VMEXIT. Monitor can intercept via EOI-exit bitmap if timer-based preemption
  of child domains is needed.
- [ ] **P6h**: NMI: always VMEXIT (cannot be posted); route to monitor for watchdog/panic.

### Phase 7 — Capability Engine Initialization + dom0 Boot

- [ ] **P7a**: `init_root()`: root domain (id=0, sealed, all cores) + r0.
- [ ] **P7b**: Carve dom0_ept_meta + dom0_mem; create dom0; send with META + normal attrs.
- [ ] **P7c**: Set dom0 interrupt policy: all vectors DELIVER (dom0 is the default handler).
- [ ] **P7d**: Set dom0 VP[i] registers from Linux bzImage boot params; seal dom0.
- [ ] **P7e**: Platform: allocate VMCS + VAPIC + PI descriptor per VP; write all VMCS fields;
  call `IrqRouter::configure_domain_policy` for dom0.
- [ ] **P7f**: Parse Linux bzImage; write `boot_params` into dom0_mem; set up initial
  identity-mapped page tables; set VP RIP/RSP/RSI/CR3.
- [ ] **P7g**: `switch_domain(root, dom0, 0)` → VMLAUNCH on BSP; APs VMLAUNCH via mailbox.

### Phase 8 — Hypercall Dispatch + Hypercall ABI

- [ ] **P8a**: `crates/tyche-abi/`: opcode constants, `VpRegister` enum, error codes.
  Shared between monitor and `libtyche` guest library.
- [ ] **P8b**: `hypercall.rs`: decode RAX, call `execute(||...)`, encode result.
- [ ] **P8c**: Implement all MonitorAPI hypercall handlers.
- [ ] **P8d**: `VMCALL_ASSIGN_DEVICE`: validate caller, reprogram IOMMU + I/O APIC.
- [ ] **P8e**: `libtyche` guest library (`crates/libtyche/`): `no_std` VMCALL wrappers.
  Usable from Linux kernel module (`std`) via FFI or from a bare-metal child domain.

### Phase 9 — Multi-Domain Support

- [ ] **P9a**: dom0 `VMCALL_CREATE_DOMAIN` → monitor allocates EPT root + IOMMU PT.
- [ ] **P9b**: dom0 carves memory + sends to child → `apply_update` updates child EPT + IOMMU.
- [ ] **P9c**: dom0 seals child → monitor allocates child VMCS + VAPIC + PI descriptors;
  calls `IrqRouter::configure_domain_policy` for child.
- [ ] **P9d**: `VMCALL_SWITCH` → `switch_domain`, VMPTRLD child VMCS, VMRESUME.
- [ ] **P9e**: `VMCALL_REVOKE_DOMAIN` → capability engine subtree revoke; `on_domain_revoked`
  frees EPT + IOMMU + VMCS + VAPIC structures; reassigns devices to parent.
- [ ] **P9f**: Cross-domain interrupt delivery (REPORT): EOI-exit VMEXIT → capability engine
  `deliver_interrupt_vp` → VMCS switch to handler domain → VMRESUME.

---

## Platform API / Unimplemented Features

- [ ] **#U1** `UpdateBatch::snapshots` — rollback not implemented. _Deferred — future work._
- [ ] **#U2** `MonitorAPI::ENUMERATE` / `enumerate_pending` — semantics TBD. _Deferred._
- [ ] **#U3** Cache coloring — see `./2026/docs/design/address_translation.md`. _Phase 4–6 of address translation design._
