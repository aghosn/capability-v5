# Themis Capavisor — Multi-Platform (ARM AArch64) Porting Design

**Status**: **M1 complete** (2026-04-15). Capavisor boots on QEMU aarch64 via Limine,
prints to PL011 UART, dumps memory map. Next: M2 (memory + platform discovery).
**Scope**: Extending the Themis capavisor to run on ARM AArch64 hardware (targeting
ARMv8.1-A+ with VHE — Virtualization Host Extensions — i.e., EL2 capable SoCs).

### Implementation Progress

| Milestone | Description | Status |
|-----------|-------------|--------|
| **M1** | Boot on QEMU aarch64, PL011 UART, memory map dump | ✅ Done (9823d73, d0fe7c4) |
| **M2** | Memory + ACPI/DTB discovery, MetaAllocator, GIC addresses | 🔜 Next |
| **M3** | EL2 + Stage-2 page tables, exception vectors, guest entry/exit | Planned |
| **M4** | GICv3 + IPI (GICD/GICR init, SGI, ICH_LR injection) | Planned |
| **M5** | Boot Linux dom0 on QEMU aarch64 | Planned |
| **M6** | SMMUv3 (stretch) | Planned |

### Files created/modified (M1)

| File | What |
|------|------|
| `capavisor/linker-aarch64.ld` | AArch64 ELF linker script (higher-half 0xffffffff80000000) |
| `capavisor/src/arch/aarch64/serial.rs` | PL011 UART driver (MMIO 0x0900_0000) |
| `capavisor/build.rs` | Arch-aware linker script selection |
| `capavisor/src/main.rs` | aarch64 `_start`: PL011, heap, Limine, memory dump, WFI |
| `scripts/aarch64-iso.sh` | Build aarch64 UEFI ISO with BOOTAA64.EFI |
| `scripts/aarch64-themis.sh` | Launch QEMU aarch64 (`cargo aarch64-themis`) |

### Key learnings (M1)

- Limine enters aarch64 kernels at **EL1** (not EL2)
- Limine base revision 0 required for PL011 access (identity maps first 4 GiB including device MMIO; revision 1+ only HHDM-maps memory-map regions)
- AAVMF firmware (`qemu-efi-aarch64` package) required for UEFI boot
- QEMU `virt` machine provides ~1 GiB usable RAM across ~45 memory regions

---

## 1. Feasibility Summary

**Short answer: Feasible, but substantial.**  The capability engine and hypercall
dispatch logic are already architecture-independent.  The entire virtualization
stack (VMX, APIC, VMCS, EPT, VT-d, GDT/TSS, MSR virtualization, guest Linux
boot protocol) must be replaced with ARM equivalents.  The best analogy: the
_policy_ layer is portable; the _mechanism_ layer is not.

Rough breakdown:
- ~30 % of the capavisor codebase is architecture-independent today.
- ~70 % is Intel/x86-64-specific and must be re-implemented for ARM.
- Zero new logic needs to be added to the capability engine (`capa-engine/` crate).

---

## 2. Architecture-Independent Code (keep as-is or minor changes)

| Component | Location | Notes |
|-----------|----------|-------|
| Capability engine | `capa-engine/src/` | Pure logic, no arch assumptions |
| Hypercall opcode table | `themis-abi/src/lib.rs` | Opcodes are arch-neutral integers |
| DomainComm ring buffer protocol | `themis-abi/src/domcomm.rs` | Pure data protocol |
| Memory inventory & partitioning | `capavisor/src/mem/inventory.rs`, `meta_alloc.rs` | Physical address math |
| MetaAllocator | `capavisor/src/mem/meta_alloc.rs` | Frame pool, no arch deps |
| ACPI parsing | `capavisor/src/acpi.rs` + `acpi` crate | ACPI is used on ARM too |
| PCI config-space enumeration | `capavisor/src/pci.rs` | PCIe is arch-neutral |
| Hypercall dispatch routing | `capavisor/src/hypercall.rs` | Calls capability engine; only reg-file names are arch-specific (see §4.4) |
| Domain lifecycle struct | `capavisor/src/domain.rs` | Tracks physical addresses; rename VMCS→VirtCtl |
| Platform barrier/IPI protocol | `capavisor/src/platform.rs` (barrier logic) | Logic is arch-neutral; IPI send mechanism is not |
| Limine boot requests | `capavisor/src/main.rs` (request statics) | Limine supports aarch64 |
| Heap allocator | `capavisor/src/main.rs` | `linked_list_allocator` is arch-neutral |
| EPT/Stage-2 mapper _walker_ | `crates/ept/src/walker.rs` | 4-level walk logic is reusable with new entry types |
| `capavisor-pt` stub | `crates/capavisor-pt/` | Still a stub; new implementation will be arch-specific anyway |

---

## 3. Architecture-Specific Code (must be ported or replaced)

### 3.1 Virtualization Control Structures

**x86**: Intel VT-x uses a **VMCS** (Virtual Machine Control Structure) — a 4 KB
region in memory that stores per-VP execution state, control bits, and exit
information.  It is loaded/unloaded with `VMPTRLD`/`VMCLEAR` and accessed
with `VMREAD`/`VMWRITE`.

**ARM (AArch64) — bare EL2 model**: Themis runs at EL2; guests (Linux) run at
EL1/EL0.  There is no VMCS.  Per-VP configuration is done via **EL2 system
registers**:

| Purpose | x86 VMCS field | ARM EL2 register |
|---------|---------------|-----------------|
| Enable hypervisor traps | Primary/secondary proc-based controls | `HCR_EL2` |
| Stage-2 page table root | EPT_POINTER | `VTTBR_EL2` |
| Stage-2 config (size, levels) | EPT_POINTER flags | `VTCR_EL2` |
| Guest entry address | VMCS guest RIP | `ELR_EL2` (set before ERET) |
| Guest saved CPSR | VMCS guest RFLAGS + CS | `SPSR_EL2` |
| Exception vector base | VMCS HOST_RIP (indirect) | `VBAR_EL2` |
| APIC virtualisation | APICv, VAPIC page | GIC List Registers (`ICH_LR<n>_EL2`) |

Per-VP state (X0–X30, SP_EL0, SP_EL1, ELR_EL1, SPSR_EL1, and all EL1 system
registers) has **no hardware save area** — the hypervisor saves/restores them in
software on every EL2 entry/exit (stored in an in-memory `VpState` struct,
analogous to `InactiveVcpu` today).

The `VMXON` region (per-core hardware root for VMX) has no ARM equivalent — EL2
is entered at boot via Limine (or firmware) and stays enabled.

Files affected:
- `crates/vmx/` → new `crates/el2/` (ARM EL2 setup, VP run loop)
- `capavisor/src/vmcs.rs` → `arch/aarch64/virt_ctrl.rs`
- `capavisor/src/vmexit.rs` → `arch/aarch64/exception.rs`

### 3.2 Guest Entry / Exit (VMLAUNCH/VMRESUME → ERET)

**x86**: `VMLAUNCH` / `VMRESUME` enter the guest; a VMEXIT trap returns to the
host RIP stored in `VMCS.HOST_RIP`.  `ActiveVcpu::run()` in `crates/vmx/src/vcpu.rs`
wraps this as a function call.

**ARM**: `ERET` instruction exits EL2 to EL1 (guest kernel) or EL0 (guest
userspace).  Return from guest is via an exception to EL2 (synchronous, IRQ, FIQ,
SError).  The EL2 exception vector table (VBAR_EL2) dispatches to handlers.

Exit reasons are encoded in `ESR_EL2.EC` (Exception Class) + `ESR_EL2.ISS`
(Instruction-Specific Syndrome).  Notable ARM equivalents to VMX exit reasons:

| x86 VMX Exit | ARM AArch64 equivalent |
|---|---|
| EPT Violation (48) | Stage-2 translation fault (EC=0x24 data / EC=0x20 instruction) |
| VMCALL (18) | HVC instruction (EC=0x16) |
| CPUID (10) | Trapped by `HCR_EL2.TID3` — SMC/system instruction trap |
| RDMSR/WRMSR (31/32) | System register traps (`HCR_EL2.TID*`, `HCR_EL2.TSW`, etc.) |
| External interrupt (1) | IRQ/FIQ routed to EL2 via `HCR_EL2.IMO`/`FMO` |
| CR access (28) | No direct equivalent; CR0/CR3/CR4 concepts don't exist |
| HLT (12) | WFI/WFE trap (`HCR_EL2.TWI`/`TWE`) |
| IO instruction (30) | No equivalent (ARM uses MMIO, not port I/O) |
| XSETBV (55) | No equivalent on ARM |

Files affected:
- `crates/vmx/src/vcpu.rs` → new `crates/el2/src/vcpu.rs`
- `capavisor/src/vmexit.rs` → `arch/aarch64/exception_handler.rs`

### 3.3 Guest Register File

**x86**: `VpGpRegs` in `themis-abi/src/regs.rs` covers RAX–R15, RSP, RIP,
RFLAGS, and x86 segment registers (`SegmentReg` with VMX access-rights encoding).
`VpSregs` covers CR0/CR3/CR4/EFER.

**ARM**: Completely different register set: X0–X30 (64-bit GPRs), SP_EL0,
SP_EL1, ELR_EL1, SPSR_EL1, and system registers (SCTLR_EL1, TTBR0_EL1,
TTBR1_EL1, MAIR_EL1, TCR_EL1, VBAR_EL1, etc.).  No segment registers.

The ABI register indices in `VpRegister` enum must be duplicated for ARM.
The `THEMIS_GET_REG`/`THEMIS_SET_REG` hypercall encoding will need arch-specific
register ID namespaces.

Files affected:
- `themis-abi/src/regs.rs` → split into `regs/x86_64.rs` and `regs/aarch64.rs`

### 3.4 Hypercall Instruction and Calling Convention

**x86**: Guests invoke hypercalls with `VMCALL`.  Register convention is
System V AMD64 (RAX = opcode, RDI/RSI/RDX/RCX/R8 = args, RAX/RDI/RSI/RDX out).

**ARM**: Guests invoke hypercalls with `HVC #0`.  The ARM EABI calling convention
uses X0–X7 for arguments/return values (X0 = opcode or first arg, X1–X7 = args).
The Linux KVM ABI uses W0 = function ID (SMCCC-style), X1–X5 = args.

The opcode numbers in `themis-abi::opcodes` can stay the same; only the
_transport_ (which register holds what) changes.  `hypercall.rs` reads from
`Reg::Rax`, `Reg::Rdi`, etc. — those references become `Reg::X0`, `Reg::X1`, etc.

Files affected:
- `crates/themis-abi/src/lib.rs` — add `arch` module with calling-convention
  adapter; opcodes stay shared
- `capavisor/src/hypercall.rs` — parametrize register reads by arch

### 3.5 Second-Level Page Tables (EPT → Stage-2)

**x86**: EPT (Extended Page Tables) uses a 4-level structure (PML4E/PDPTE/PDE/PTE)
where permission bits are at positions 0/1/2 (R/W/X) and memory type is encoded
in bits 3–5.

**ARM**: Stage-2 translation tables also use a 4-level structure (when using 4KB
granule on ARMv8.1+), but the entry format is different:
- Permissions are `AP[1:0]` (bits 7:6) + `XN`/`UXN` (bit 54/53)
- Memory type is encoded as MemAttr index into MAIR-like Stage-2 attribute register
  (`VTCR_EL2.SL0` configures start level)
- The root physical address is written to `VTTBR_EL2` instead of `VMCS.EPT_POINTER`

The `ept` crate's walker (`walker.rs`) and mapper skeleton (`mapper.rs`) could be
reused if entry flag types are made generic, but the flag definitions in `lib.rs`
and the mapper's memory-type encoding will differ.

Note: the `ept` crate already comments _"AMD Nested Page Tables have the identical
structure... this crate will be reused for NPT"_.  Stage-2 is similar enough that
a new `crates/stage2/` crate following the same API makes sense, or alternatively
a generic `crates/slpt/` that is parameterized by arch-specific entry types.

The IOMMU SLPT must also follow the Stage-2 format on ARM (ARM SMMU uses the same
table format as CPU Stage-2 translation).

Files affected:
- `crates/ept/` — stays for x86
- New `crates/stage2/` — ARM Stage-2 tables (or generalize `ept` with feature flags)

### 3.6 IOMMU (VT-d → ARM SMMU)

**x86**: Intel VT-d (DMAR ACPI table) provides:
- DMA remapping via per-domain SLPT (mirroring EPT, per A4)
- Interrupt remapping via IRTEs (Interrupt Remapping Table Entries)
- Posted interrupt delivery into VP PIDs

**ARM**: ARM SMMU v2/v3 (described in the IORT ACPI table or device tree) provides:
- DMA remapping via Stage-2 translation (same table format as CPU Stage-2!)
- MSI interrupt remapping via ITS (Interrupt Translation Service) + VPE tables
  (for GICv4 direct virtual LPI delivery — the ARM equivalent of posted interrupts)

The `vtd` crate (`crates/vtd/`) is entirely VT-d specific.  A new `crates/smmu/`
is needed.  However, the _logical interface_ (program domain SLPT, remap interrupt)
can be defined as a common trait, making `apply_update` in `platform.rs` arch-neutral.

The good news: the SLPT page tables on ARM are identical between CPU Stage-2 and SMMU
Stage-2, so the `crates/stage2/` mapper can be shared.

Files affected:
- `crates/vtd/` — stays for x86
- New `crates/smmu/` — ARM SMMU v2/v3 driver
- `capavisor/src/iommu_ir.rs` → split into `arch/x86_64/iommu_ir.rs` and
  `arch/aarch64/iommu_ir.rs`

### 3.7 Interrupt Controller (x2APIC/LAPIC → GIC)

**x86**: Local APIC (xAPIC or x2APIC) handles per-core interrupt delivery.
Posted Interrupt Descriptor (PID) enables hardware-accelerated virtual interrupt
injection without VMEXIT.  The `x2apic` crate manages this.

**ARM (AArch64)**: GIC (Generic Interrupt Controller) v3/v4:
- `GICD` — Distributor (global; enables/routes SPIs)
- `GICR` — Redistributor (per-CPU; handles PPIs/SGIs)
- `GICV`/`GICH` — Virtual interface (EL2 managed, allows direct virtual interrupt
  injection without exiting the guest, via List Registers in `ICH_LR<n>_EL2`)
- GICv4 — adds direct virtual LPI injection (equivalent to posted interrupts)

IPI delivery: ARM uses SGIs (Software Generated Interrupts) via `ICC_SGI1R_EL1`.
For posted interrupts: GICv4 VPE (Virtual PE Entry) tables serve as the ARM
equivalent of Intel's Posted Interrupt Descriptors.

Files affected:
- `capavisor/src/platform.rs` (IPI send, `send_ipi_to_core`) → must dispatch to
  LAPIC (x86) or GIC SGI (ARM)
- `capavisor/src/vmcs.rs` APICv/PID constants → new `arch/aarch64/gic.rs`
- `capavisor/src/iommu_ir.rs` posted-interrupt IRTE programming → ARM ITS VPE programming

### 3.8 CPU Feature Detection

**x86**: `crates/vmx/src/features.rs` uses `CPUID` and reads Intel VMX capability
MSRs (`IA32_VMX_BASIC`, `IA32_VMX_PROCBASED_CTLS`, etc.).

**ARM**: Feature detection uses system registers:
- `MIDR_EL1` — implementer/part number
- `ID_AA64MMFR0_EL1` — memory model features (Stage-2 page sizes, etc.)
- `ID_AA64PFR0_EL1` — processor feature register (GIC interface, SVE, etc.)
- `ID_AA64ISAR0_EL1` — ISA feature register
- Virtualization support via `HCR_EL2` availability (always present at EL2 on ARMv8)

Files affected:
- `crates/vmx/src/features.rs` → `crates/el2/src/features.rs`

### 3.9 SMP AP Startup (SIPI → PSCI)

**x86**: Application processors (APs) are started by sending an INIT + SIPI
(Startup IPI) sequence via the APIC ICR register.  In Themis the child VPs
start in real-mode (ACTIVITY_STATE=6 / wait-for-SIPI), and `EXIT_REASON_SIPI`
(exit code 4) in `vmexit.rs` handles this by setting CS and RIP to the SIPI
vector address.  The INIT signal (exit code 3) is also overloaded by Themis as
the cross-core IPI mechanism: when the BSP wants to preempt an AP's running VP,
it sends an INIT via x2APIC, which causes an `EXIT_REASON_INIT_SIGNAL` VMEXIT
on that AP, allowing the AP to poll its update queue.

**ARM**: There is no INIT/SIPI.  ARM SMP AP startup uses **PSCI** (Platform
State Coordination Interface, SMCCC-defined):
- `PSCI_CPU_ON` SMC call wakes a secondary CPU at a specified entry address.
- The calling convention uses HVC/SMC with W0 = function ID.
- Limine handles this transparently on ARM (MP response works the same way).

For the cross-core IPI mechanism, ARM uses **SGIs (Software-Generated
Interrupts)** via the GIC: `ICC_SGI1R_EL1` system register to send a targeted
SGI to any CPU MPIDR.  The ARM equivalent of polling on INIT_SIGNAL exit would
be trapping a specific SGI at EL2 and handling the cross-core update queue from
an IRQ exception handler.

Files affected:
- `capavisor/src/vmexit.rs` INIT_SIGNAL and SIPI handlers → `arch/aarch64/exception.rs`
- `capavisor/src/platform.rs` `send_ipi_to_core()` → dispatch via SGI on ARM

### 3.10 GDT / TSS / IDT Setup

**x86**: `capavisor/src/gdt.rs` sets up a minimal GDT (null + CS64 + DS64 + TSS
per core) required by VMX host-state checks, and loads TR.

**ARM**: No GDT/TSS/IDT — replaced by:
- `VBAR_EL2` — exception vector base address (64-entry table)
- Each exception level has its own stack pointer (SP_EL2)
- No task register or I/O permission bitmap concept

Files affected:
- `capavisor/src/gdt.rs` → arch-specific; no ARM equivalent; replaced by
  `arch/aarch64/exception_vectors.rs`

### 3.10 MSR Virtualization

**x86**: `capavisor/src/msr_virt.rs` traps RDMSR/WRMSR exits for performance
counter MSRs and x2APIC MSRs.  MSR bitmap in domain's VMCS controls which MSRs trap.

**ARM**: MSR-equivalent is system register access (MRS/MSR instructions at EL1).
Trapping is configured via `HCR_EL2` bits (e.g., `HCR_EL2.TID3` for ID registers,
`HCR_EL2.TIDCP` for cache maintenance, etc.).  There is no equivalent of the x86
MSR bitmap.  Trap handling is per-register-class via `ESR_EL2`.

Files affected:
- `capavisor/src/msr_virt.rs` → `arch/x86_64/msr_virt.rs`
- New `arch/aarch64/sysreg_virt.rs` for ARM system register trap handling

### 3.11 Serial Console

**x86**: COM1 UART at I/O port 0x3F8 (8250/16550 compatible), accessed with
`x86::io::outb`/`inb`.

**ARM**: No port I/O.  Common ARM UARTs:
- PL011 (ARM PrimeCell UART) — MMIO, found in most QEMU ARM virt machines and
  many SoCs.
- 16550-compatible MMIO variants also exist.

QEMU `virt` machine exposes a PL011 at 0x0900_0000 (MMIO).

Files affected:
- `capavisor/src/main.rs` (SerialPort) → `arch/x86_64/serial.rs` and
  `arch/aarch64/serial.rs` (PL011 MMIO)

### 3.12 Guest Boot Protocol

**x86**: `capavisor/src/guest/linux.rs` implements the x86 Linux boot protocol:
- Parses bzImage setup header (offset 0x1f1, magic `HdrS`)
- Builds `struct boot_params` (zero-page)
- Constructs e820 memory map
- Sets up initial VMCS guest state (protected mode, no paging, initial CS:IP)

**ARM (AArch64)**: The ARM64 Linux boot protocol is completely different:
- Image format: raw `Image` (no bzImage overhead) or `vmlinuz`
- Header: 64-byte ARM64 Image header at offset 0 (`MZ` magic + `ARM\x64` magic
  at offset 0x38, text offset, image size, flags)
- Boot parameters: Flattened Device Tree (FDT/DTB) blob passed in X0
- Entry state: X0 = FDT physical address, X1–X3 = 0, CPU in EL1 (or EL2 for KVM)
- Memory map: described in the DTB (`/memory` nodes), not e820

Files affected:
- `capavisor/src/guest/linux.rs` → `arch/x86_64/guest/linux.rs`
- New `arch/aarch64/guest/linux_arm64.rs`

### 3.13 Platform Boot Sequence (Limine)

**Positive**: Limine supports both x86-64 and aarch64.  The Limine protocol
requests used (HHDM, MemoryMap, MP, RSDP, Module) are the same on both arches.

**Differences**:
- `MpRequest` on ARM returns MPIDR affinity values instead of LAPIC IDs.
  `bsp_lapic_id` would become `bsp_mpidr` or similar.
- `RsdpRequest` still works on ARM platforms with ACPI firmware (most server ARM
  platforms do have ACPI).  On embedded/QEMU virt without ACPI, a DTB would be
  needed instead.
- `x86::controlregs::cr4_write()`, `xsetbv` inline ASM, and other x86 boot-time
  register writes in `main.rs` / `ap_entry()` must be conditioned or replaced.

---

## 4. Proposed Refactoring Architecture

### 4.1 Directory Layout After Refactoring

```
themis/
├── capavisor/src/
│   ├── arch/
│   │   ├── mod.rs               ← re-exports the active arch module
│   │   ├── x86_64/
│   │   │   ├── mod.rs
│   │   │   ├── serial.rs        ← COM1 UART
│   │   │   ├── gdt.rs           ← GDT/TSS setup
│   │   │   ├── vmcs.rs          ← VMCS field constants + setup
│   │   │   ├── vmexit.rs        ← VMX exit dispatch
│   │   │   ├── msr_virt.rs      ← MSR bitmap + RDMSR/WRMSR handler
│   │   │   ├── iommu_ir.rs      ← VT-d interrupt remapping
│   │   │   ├── apic.rs          ← x2APIC IPI
│   │   │   └── guest/
│   │   │       └── linux.rs     ← x86 boot protocol
│   │   └── aarch64/
│   │       ├── mod.rs
│   │       ├── serial.rs        ← PL011 UART
│   │       ├── exception_vectors.rs ← VBAR_EL2 table
│   │       ├── virt_ctrl.rs     ← EL2 system register setup
│   │       ├── exception.rs     ← EL2 exception dispatch (ESR_EL2)
│   │       ├── sysreg_virt.rs   ← System register trap handling
│   │       ├── iommu_ir.rs      ← ARM SMMU + ITS
│   │       ├── gic.rs           ← GICv3/v4 IPI + virtual LPI
│   │       └── guest/
│   │           └── linux_arm64.rs ← ARM64 boot protocol
│   ├── main.rs                  ← arch-neutral orchestrator
│   ├── boot.rs                  ← arch-neutral (calls arch:: for hw init)
│   ├── domain.rs                ← arch-neutral
│   ├── hypercall.rs             ← arch-neutral (uses arch::Regs trait)
│   ├── platform.rs              ← arch-neutral (calls arch:: for SLPT, IOMMU, IPI)
│   ├── mem/                     ← arch-neutral
│   ├── acpi.rs                  ← arch-neutral
│   └── pci.rs                   ← arch-neutral
├── crates/
│   ├── vmx/                     ← stays (x86 VT-x)
│   ├── el2/                     ← NEW: ARM EL2 vcpu (mirrors vmx/)
│   │   └── src/
│   │       ├── features.rs
│   │       └── vcpu.rs
│   ├── ept/                     ← stays (x86 EPT, also usable for AMD NPT)
│   ├── stage2/                  ← NEW: ARM Stage-2 translation tables
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── mapper.rs
│   │       └── walker.rs
│   ├── vtd/                     ← stays (Intel VT-d)
│   ├── smmu/                    ← NEW: ARM SMMU v2/v3 driver
│   ├── themis-abi/              ← split regs by arch; opcodes shared
│   ├── libthemis/               ← stays (client library)
│   └── capavisor-pt/            ← stays (stub; future will be arch-specific)
```

### 4.2 Key Trait Boundaries to Introduce

These traits would be defined in `capavisor/src/arch/mod.rs` (or a new
`crates/hal/` crate) and implemented per-arch:

```rust
/// Virtualization backend: manages VP lifecycle and exit handling.
pub trait VirtBackend {
    type Vcpu;          // ActiveVcpu on x86, EL2Vcpu on ARM
    type InactiveVcpu;

    fn enable_on_core(vmxon_or_el2_phys: u64) -> Result<(), HwError>;
    fn detect_features() -> ArchFeatures;
}

/// Second-level page table (EPT on x86, Stage-2 on ARM).
pub trait SecondLevelPt {
    fn map(&mut self, gpa: u64, hpa: u64, flags: SlptFlags) -> Result<()>;
    fn unmap(&mut self, gpa: u64) -> Result<()>;
    fn root_phys(&self) -> u64;
    fn flush_tlb(&self);
}

/// Interrupt controller abstractions.
pub trait InterruptController {
    fn send_ipi(target_cpu: usize, vector_or_sgi: u32);
    fn program_virtual_interrupt(vcpu: &Self::Vcpu, vector: u8);
}

/// IOMMU abstractions (VT-d on x86, SMMU on ARM).
pub trait Iommu {
    fn program_slpt(&mut self, domain_id: u64, root: u64);
    fn program_interrupt(&mut self, irte_idx: u8, target: IrteTarget);
    fn invalidate_iec(&mut self, irte_idx: u8);
}
```

`ThemisPlatform` in `platform.rs` would hold `Box<dyn SecondLevelPt>`,
`Box<dyn Iommu>`, etc., or use conditional compilation via `#[cfg(target_arch)]`.

### 4.3 `platform.rs` apply_update Changes

Today `apply_update` directly calls:
- `EptMapper::map()` / `EptMapper::unmap()` — would call `SecondLevelPt::map()`
- `vtd::...` IOMMU APIs — would call `Iommu::program_slpt()`
- `irte_program_posted/remapped` — would call `Iommu::program_interrupt()`
- `x2apic::send_ipi()` — would call `InterruptController::send_ipi()`

All of these become dispatch-through-trait calls, making `apply_update` itself
architecture-independent.

### 4.4 `hypercall.rs` Register Convention Changes

Currently hypercall arguments are read as:
```rust
let opcode = vcpu.get_reg(Reg::Rax);
let arg0   = vcpu.get_reg(Reg::Rdi);
```

On ARM these would be:
```rust
let opcode = vcpu.get_reg(Reg::X0);
let arg0   = vcpu.get_reg(Reg::X1);
```

Since `hypercall.rs` imports `Reg` from `crate::vcpu`, and `crate::vcpu` re-exports
from the arch-specific vcpu crate, the fix is just to change what `Reg::*` maps to
per arch.  The dispatch table itself (`match opcode { THEMIS_CREATE_DOMAIN => ... }`)
does not change.

---

## 5. Open Questions / Clarifications Needed

Before committing to this design, the following questions need answers:

1. **Target ARM hardware profile**: **Desktop/server-class** — targeting Neoverse N1/V2,
   Ampere Altra, AWS Graviton-class platforms.  This means: **GICv3/v4**, **ARM SMMU v3**,
   **ACPI** (MADT with GIC entries, IORT for SMMU), **VHE available** (ARMv8.1+).

2. **VHE vs. non-VHE**: **Decided: traditional bare EL2 (no VHE).**  Themis is the
   lowest-level software on the machine — nothing runs below it (no EL3 firmware staying
   resident, no TrustZone monitor that matters here).  It runs natively at EL2.  Guests
   (Linux dom0 and child VMs) run at EL1/EL0.  VHE is not used or needed: VHE exists to
   let a Type-1 hypervisor host OS run at EL2 directly, which is not Themis's model.

3. **Stage-2 EPT crate reuse**: **Decided: keep separate narrow crates** (`ept/`,
   `stage2/`, `npt/`) — cleanest per-arch, no abstraction overhead.

4. **Guest type on ARM**: **Decided: unmodified AArch64 Linux VM from day one.**
   Same goal as on x86 (dom0 = Ubuntu AArch64, child VMs = unmodified AArch64 Linux).
   The ARM64 boot protocol (Image + DTB) must be implemented at the same time as the
   EL2 VM entry path.

5. **ARM SMMU**: **In scope from day one** — required to maintain the A4 invariant
   (IOVA = GPA).  ARM SMMU v3 Stage-2 translation will mirror the CPU Stage-2 tables,
   exactly as VT-d SLPT mirrors EPT on x86.  QEMU `virt` supports SMMU v3 with
   `-machine virt,iommu=smmuv3`.

6. **Limine on ARM**: The Limine bootloader supports aarch64.  Have you verified
   that the build/ISO workflow (currently x86 UEFI + Limine) can be adapted for
   ARM?  QEMU `virt` boots via UEFI (EDK2) which Limine supports.

---

## 6. Effort Estimate (relative, not timed)

| Work Item | Relative Effort | Risk |
|-----------|----------------|------|
| Arch directory restructuring + trait definitions | Medium | Low |
| `crates/el2/` — ARM EL2 vcpu (replaces `vmx`) | **Large** | High |
| ARM exception vector table + dispatch | Medium | Medium |
| `crates/stage2/` — ARM Stage-2 page tables | Medium | Low (structure similar to EPT) |
| ARM boot sequence (EL2 init, MPIDR, PL011) | Medium | Low |
| `crates/smmu/` — ARM SMMU driver | **Large** | High |
| GICv3/v4 driver (replaces x2APIC) | **Large** | High |
| ARM64 guest Linux boot protocol | Medium | Medium |
| `themis-abi` register profile for AArch64 | Small | Low |
| `thhv.ko` kernel module (ARM Linux) | Medium | Medium |
| `cloud-hypervisor` Themis backend on ARM | Small | Low (mostly HVC vs VMCALL) |

---

## 7. What Does NOT Need to Change

- The entire `capa-engine/` capability engine workspace
- `themis-abi` opcode numbers and error codes
- DomainComm ring buffer format
- The `THEMIS_SWITCH` synchronous scheduling model
- Axioms A1–A11 — all remain valid on ARM
- The meta-pool / EPT-never-in-guest invariant (A5)
- Dom0 non-privilege invariant (A2)
- The IOVA=GPA invariant (A4) — ARM SMMU Stage-2 works identically

---

## 8. Recommended Next Steps

All design decisions are now resolved.  Suggested phased approach:

1. **Arch scaffolding (zero-risk refactoring)**: Move all existing x86 code into
   `arch/x86_64/` subdirectories without any functional change.  Verify x86 still
   builds and boots.  This is pure file reorganization.

2. **HAL trait definitions**: Define `SecondLevelPt`, `Iommu`, `InterruptController`,
   and `VirtBackend` traits (§4.2) and wire them into `platform.rs` for x86.  The
   x86 implementation becomes the first (and reference) impl.

3. **`crates/el2/`**: Implement ARM EL2 VP lifecycle (save/restore, ERET entry,
   exception vector table, `HCR_EL2` setup).  Start with QEMU `virt` only.

4. **ARM boot + serial**: PL011 UART, Limine aarch64 boot sequence, MPIDR-based
   SMP (replace LAPIC IDs), basic EL2 entry on QEMU.

5. **`crates/stage2/`**: ARM Stage-2 page table mapper (model on `ept/` walker).
   Wire into `ThemisPlatform` as the ARM `SecondLevelPt` impl.  Boot an AArch64
   Linux dom0.

6. **ARM64 guest boot protocol**: `arch/aarch64/guest/linux_arm64.rs` — parse ARM64
   Image header, build DTB, set `ELR_EL2`/`SPSR_EL2` for EL1 entry.

7. **GICv3/v4**: Replace x2APIC IPI and Posted Interrupt logic with GIC SGI delivery
   and List Register-based virtual interrupt injection.

8. **`crates/smmu/`**: ARM SMMU v3 driver, Stage-2 SLPT mirroring (same A4 invariant
   as VT-d).  IORT table parsing in `acpi.rs` to discover SMMU units.

9. **`thhv.ko` on ARM**: The kernel module uses `VMCALL` / x86 ioctls.  Port the
   hypercall transport to `HVC` on ARM.  The ioctl ABI (magic 0xB8, structs) is
   architecture-independent and can stay unchanged.

---

## 9. Build & Tooling Concerns (non-trivial)

Beyond the hypervisor code itself, a seamless cross-platform build/run story requires:

| Area | x86 today | ARM additional work |
|------|-----------|---------------------|
| Guest OS image | Ubuntu cloud image (amd64) via `fetch-dom0.sh` | Separate AArch64 image fetch; same cloud-init seeding |
| QEMU machine | `q35` + `OVMF` (x86 UEFI) | `virt` + EDK2 aarch64 firmware; `-cpu cortex-a72` or `host` |
| Limine ISO | x86_64 EFI ISO | aarch64 EFI ISO; same Limine tool, different target |
| Rust cross-compile | `x86_64-unknown-none` target | `aarch64-unknown-none` target; update `rust-toolchain.toml` |
| Docker build layer | x86 stable toolchain | Either native ARM runner, or `cross`/`cargo cross` with QEMU binfmt |
| `thhv.ko` kernel headers | x86 Ubuntu kernel headers | AArch64 Ubuntu kernel headers; same `fetch-kheaders.sh` approach |
| `run-qemu.sh` / `build-iso.sh` | Single-arch scripts | Needs `ARCH=` knob or separate script variants |

Architecture-specific selections (machine type, guest image URL, CPU target, firmware
path) should be driven by a single `ARCH=x86_64|aarch64` environment variable so all
scripts stay DRY.  This is probably the right time to consolidate `dom0-versions.conf`
into a more structured config file.
