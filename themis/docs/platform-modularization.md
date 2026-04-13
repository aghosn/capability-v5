# Capavisor Platform Modularization Design

**Status**: Phases A–C done. Phase E (policy fixes) done. Phase F (generic monitor loop) done. Phase A7 (full generification) next.
**Scope**: Restructure the capavisor into a platform-agnostic core and
pluggable architecture backends, enabling multi-ISA support (x86-64, AArch64,
future targets) without duplicating policy logic.

**Related**: [`arm-porting-design.md`](arm-porting-design.md) (feasibility study
for ARM AArch64 — the first target backend after x86).

---

## 1. Motivation

The capavisor currently works on x86-64 (Intel VT-x). Policy logic (domain
lifecycle, hypercall dispatch, capability-engine integration) and mechanism logic
(VMCS, EPT, APIC, VT-d, GDT) are interleaved in the same files. This makes it
impossible to add a second ISA without either duplicating policy code or doing a
risky big-bang rewrite.

**Goals**:
1. Clean separation: **shared core** (policy) vs **arch backend** (mechanism).
2. Minimize new lines of code — the refactor should mostly *move* existing code
   behind trait boundaries, not add layers.
3. Keep x86-64 working at every step — no "big merge that breaks boot".
4. Make adding ARM (or RISC-V, etc.) a matter of implementing a small set of
   focused traits, with zero changes to shared code.

**Non-goals**:
- Actually implementing the ARM backend (that is Phase D, separate work).
- Changing the capability engine — it is already fully platform-agnostic.
- Changing `themis-abi` opcodes — they are arch-neutral integers.

---

## 2. Current State Analysis

Based on per-file classification of `capavisor/src/`:

| Classification | Files | Approx LOC |
|---|---|---|
| **Generic** | `domain.rs`, `mem/meta_alloc.rs`, `mem/uncacheable.rs`, `mem/mod.rs` | ~430 |
| **Mixed** (generic + x86 interleaved) | `platform.rs`, `hypercall.rs`, `vmexit.rs`, `boot.rs`, `mem/inventory.rs`, `acpi.rs`, `pci.rs`, `attestation.rs`, `guest/` | ~8500 |
| **x86-only** | `vmcs.rs`, `gdt.rs`, `msr_virt.rs`, `iommu_ir.rs`, `mem/paging.rs` | ~1340 |
| **Entry** | `main.rs` | ~420 |

The "mixed" files are the main challenge. They contain both policy decisions
(e.g., "dispatch this opcode to `do_create_domain`") and mechanism code (e.g.,
"write VMCS field X"). The refactor extracts the mechanism into trait impls.

---

## 3. Design

### 3.1 Principles

1. **Semantic events, not hardware exits**. Shared code never sees VMX exit
   reason codes or ARM ESR_EL2 values. Arch code decodes raw hardware events
   into a `ArchExit` enum. This avoids a "bag of optional fields" generic
   exit type that mirrors one ISA.

2. **Focused sub-traits, not one monolith**. A single `HardwarePlatform` trait
   inevitably becomes shaped like the first ISA. Instead: one trait per concern,
   each small enough to implement independently.

3. **Opaque handles, concrete shared types**. Arch modules own their internal
   structures (VMCS, EPT tables, GIC state). Shared code uses concrete value
   types (`HypercallArgs`, `InterruptVector`, `PageSize`, `Permissions`) and
   opaque handles (`VpHandle`, `MapHandle`) only where it must store arch-owned
   resources.

4. **Preserve invariants by construction**. The trait API must make it hard to
   violate axioms A1 (execute→apply_update), A2 (no dom0 privilege), A5 (META
   never in guest map), A9 (all ops through capability engine). For instance,
   `ArchGuestPhysMap::map` is only called from `apply_update`, not from
   hypercall handlers directly.

5. **Minimize new code**. The traits are thin interfaces. Implementations wrap
   existing functions. The net LOC increase for the trait layer itself should be
   small (~200–300 lines of trait defs + type defs). Most "new" code is just
   existing code relocated behind `impl` blocks.

### 3.2 Arch-Backend Traits

```rust
// ── VP lifecycle and guest entry/exit ──────────────────────────────

pub trait ArchVpOps {
    type VpHandle;

    fn create_vp(&mut self, domain_id: u64, cpu: u32) -> Result<Self::VpHandle, CapaError>;
    fn destroy_vp(&mut self, vp: &mut Self::VpHandle);
    fn enter_guest(&mut self, vp: &mut Self::VpHandle) -> ArchExit;
    fn advance_ip(&mut self, vp: &mut Self::VpHandle, len: u32);

    fn get_hypercall_args(&self, vp: &Self::VpHandle) -> HypercallArgs;
    fn set_hypercall_result(&mut self, vp: &mut Self::VpHandle, result: HypercallResult);
    fn inject_interrupt(&mut self, vp: &mut Self::VpHandle, vector: u32) -> Result<(), CapaError>;
}

// ── Guest physical address space (EPT / Stage-2) ──────────────────

pub trait ArchGuestPhysMap {
    type MapHandle;

    fn create_map(&mut self) -> Result<Self::MapHandle, CapaError>;
    fn destroy_map(&mut self, map: &mut Self::MapHandle);
    fn map(&mut self, map: &mut Self::MapHandle,
                gpa: u64, hpa: u64, size: PageSize, perms: Permissions);
    fn unmap(&mut self, map: &mut Self::MapHandle, gpa: u64, size: PageSize);
    fn flush(&mut self, map: &Self::MapHandle);
}

// ── Cross-core signaling ──────────────────────────────────────────

pub trait ArchCoreSignaling {
    fn send_ipi(&self, target_core: u32);
    fn broadcast_flush(&self, domain_id: u64);
    fn logical_core_id(&self) -> u32;
    fn max_cores(&self) -> u32;
}

// ── Device isolation (IOMMU — optional) ───────────────────────────

pub trait ArchIommu {
    fn assign_device(&mut self, domain_id: u64, device: DeviceId) -> Result<(), CapaError>;
    fn release_device(&mut self, device: DeviceId);
    fn map_dma(&mut self, domain_id: u64, iova: u64, hpa: u64, perms: Permissions);
    fn unmap_dma(&mut self, domain_id: u64, iova: u64);
    fn flush_dma(&mut self, domain_id: u64);
}

// ── Boot (staged) ─────────────────────────────────────────────────

pub trait ArchBoot {
    type BootInfo;

    fn early_boot() -> Self::BootInfo;
    fn init_bsp(info: &Self::BootInfo);
    fn init_ap(cpu: u32, info: &Self::BootInfo);
    fn enable_virtualization();
}
```

### 3.3 Semantic Exit Events

Arch code decodes raw hardware exits and produces:

```rust
pub enum ArchExit {
    Hypercall,
    ExternalInterrupt { vector: u32 },
    TimerExpired,
    GuestMemoryFault { gpa: u64, write: bool },
    IoInstruction { port: u16, size: u8, write: bool, value: u32 },
    MmioAccess { gpa: u64, write: bool, len: u8, data: u64 },
    GuestFaultToForward(ExitInfo),
    StartupEvent { target_cpu: u32 },
    Halt,
    Shutdown,
    ArchSpecific(u64),  // escape hatch for debugging
}
```

The shared monitor loop in `core/hypercall.rs` pattern-matches on `ArchExit`.
Arch-specific exits that don't map to any shared semantic (e.g., x86 XSETBV,
ARM WFE trap) are handled entirely within arch code before reaching the shared
layer.

### 3.4 Target Module Structure

```
capavisor/src/
├── core/                       # Platform-agnostic
│   ├── mod.rs
│   ├── traits.rs               # Sub-trait definitions (§3.2)
│   ├── types.rs                # ArchExit, HypercallArgs, Permissions, PageSize, ...
│   ├── platform.rs             # ThemisPlatform<T> — capability engine bridge
│   ├── hypercall.rs            # Opcode dispatch, ABI error mapping
│   ├── domain.rs               # Domain metadata, lifecycle orchestration
│   ├── boot.rs                 # Generic boot orchestration
│   └── mem/
│       ├── meta_alloc.rs
│       ├── inventory.rs        # Generic partitioning logic
│       └── uncacheable.rs
├── arch/
│   ├── mod.rs                  # cfg!(target_arch) re-exports
│   └── x86_64/
│       ├── mod.rs
│       ├── platform_impl.rs    # impl ArchVpOps, ArchGuestPhysMap, ... for X86Platform
│       ├── vmcs.rs
│       ├── vmexit.rs           # Raw VMX exit → ArchExit
│       ├── gdt.rs
│       ├── msr_virt.rs
│       ├── apic.rs
│       ├── iommu.rs
│       ├── paging.rs
│       ├── firmware.rs         # ACPI, PCI (x86 I/O port access)
│       └── boot.rs             # VMXON, ACPI discovery, Linux bzImage, e820
├── main.rs
└── attestation.rs              # Split later if needed
```

Conditional compilation in `arch/mod.rs`:

```rust
#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::X86Platform as Platform;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::AArch64Platform as Platform;
```

Generic code imports `crate::arch::Platform`.

---

## 4. Migration Plan

The refactor is done in four phases. **x86 boots at every step.**

### Phase A: Introduce trait seams (no file moves)

The traits and types are defined. `X86Platform` implements each trait by
wrapping existing functions. `ThemisPlatform` becomes generic. Existing files
stay in their current locations — only new `mod` files and `impl` blocks are
added.

| Step | What | Verification |
|------|------|---|
| A1 | Define `core::traits`, `core::types` | Compiles |
| A2 | `impl ArchVpOps for X86Platform` (wrap vmcs.rs/vmexit.rs) | dom0+dom1 boot |
| A3 | `impl ArchGuestPhysMap for X86Platform` (wrap EPT) | dom0+dom1 boot |
| A4 | `impl ArchCoreSignaling for X86Platform` (wrap x2APIC IPI) | 2-vCPU dom1 boot |
| A5 | `impl ArchIommu for X86Platform` (wrap VT-d) | device passthrough |
| A6 | `impl ArchBoot for X86Platform` (wrap boot/main) | dom0 4-CPU boot |
| A7 | `ThemisPlatform<T>` generic over traits | full boot matrix |

### Phase B: Semantic exit translation

| Step | What | Verification |
|------|------|---|
| B1 | vmexit.rs produces `ArchExit` | dom0+dom1 boot |
| B2 | Merge dom0/child dispatch via ArchExit | full boot matrix |

### Phase C: File reorganization

| Step | What | Verification |
|------|------|---|
| C1 | Move generic code → `core/` | cargo build |
| C2 | Move x86 code → `arch/x86_64/` | cargo build |
| C3 | Move ACPI/PCI → `arch/x86_64/firmware.rs`, define shared output structs | cargo build |
| C4 | Fix all paths, final verification | full boot matrix |

### Phase D: ARM skeleton (future work)

Create `arch/aarch64/` with trait impls. See
[`arm-porting-design.md`](arm-porting-design.md) for the detailed ISA mapping.

---

## 5. Invariant Preservation

Every phase must verify these axioms are not violated:

| Axiom | How the trait design preserves it |
|---|---|
| **A1** execute→apply_update | `ArchGuestPhysMap::map` is only called from `apply_update`, never from hypercall handlers |
| **A2** dom0 not privileged | Traits take `domain_id`, not `is_dom0`. No special-case paths |
| **A3** EOI-exit zero | VMCS/VirtCtl setup stays in arch code, unchanged |
| **A5** META not in guest EPT | `ArchGuestPhysMap` receives only validated (gpa, hpa) from capability engine |
| **A9** All ops through engine | `core::hypercall` always calls `execute()` before any arch trait method |

---

## 6. Complexity Budget

The refactor should be **net-neutral or net-negative** in total LOC:

| New code | Est. lines | Justification |
|---|---|---|
| Trait definitions (`traits.rs`) | ~100 | 5 traits × ~20 lines |
| Shared types (`types.rs`) | ~80 | ArchExit enum, HypercallArgs, etc. |
| `X86Platform` impl wrappers | ~150 | Thin delegation to existing functions |
| `arch/mod.rs` + cfg gates | ~20 | Boilerplate |
| **Total new** | **~350** | |

Offsetting savings:
- Eliminating duplicated dom0/child vmexit dispatch (~200 lines)
- Removing ad-hoc x86 conditionals from generic paths
- Deduplicating argument extraction patterns across hypercalls

The trait layer is a **routing layer**, not a new abstraction with its own state.
Each trait method maps 1:1 to an existing function — it just moves the call site
behind a trait boundary.

---

## 7. What This Does NOT Change

- **`capa-engine/`**: Mostly untouched. Already platform-agnostic. (Exception:
  `register_access_check` fix in §8.)
- **`themis-abi/`**: Minor additions (unified SET_POLICY opcode, §8.2).
- **`crates/vmx/`, `crates/ept/`, `crates/vtd/`**: Stay as-is. They become
  dependencies of `arch/x86_64/`, not of `core/`.
- **`thhv/`**: Dom0 kernel module. x86-specific by nature. A different driver
  would be needed for ARM dom0. (Exception: unified THHV_SET_POLICY ioctl, §8.5.)
- **`cloud-hypervisor/`**: VMM. Separate concern. (Exception: update to new
  SET_POLICY ioctl, §8.5.)
- **`lean-exec/`**, **`capa-cli/`**: Model and CLI. Unaffected.

---

## 8. Policy Enforcement Fixes

### 8.1 Problem Statement

The capability engine defines two symmetric policy types that control register
visibility when a child domain exits to its parent:

- **ExitPolicy** (`u32` exit reason → `ExitAction { trap, read_set, write_set }`):
  for non-interrupt exits (CPUID, EPT violation, IO, MSR, etc.)
- **InterruptPolicy** (`u8` vector → `VectorPolicy { visibility, read_set, write_set }`):
  for interrupt-caused exits

Both define `read_set` (what the parent sees on the comm page when the child
exits) and `write_set` (what the parent can modify on the comm page before
resuming the child). The model is simple and symmetric:

1. Child exits → capavisor looks up the right policy entry → uses `read_set`
   to filter registers copied to the comm page.
2. Parent handles exit → writes to comm page → on resume, capavisor uses
   `write_set` from the **same policy entry** to filter what gets applied.

The difference between the two types:
- **Exits** go to the **direct parent** via `forward_child_exit`.
- **Interrupts** walk the **CDT upward** via `route_interrupt` to find the
  first domain with `Deliver` visibility. Intermediate domains with `Report`
  are notified.

#### Current bugs

1. **Forward path for interrupts**: `forward_interrupt_to_handler` does NOT
   copy registers to the comm page using `InterruptPolicy.read_set`. It does
   a raw context switch with no register filtering.

2. **Resume path always uses InterruptPolicy**: `register_access_check` in
   the engine always looks up `InterruptPolicy.get_policy(effective_vector)`
   for the write_set. For non-interrupt exits, `effective_vector` =
   `VECTOR_AVAILABLE` (0xFF), so it falls back to the default VectorPolicy
   instead of the ExitPolicy entry that actually caused the forward.

3. **Exit reason not stored securely**: The resume path needs to know which
   policy entry caused the exit. This must be stored in **capavisor-private
   VP metadata** (not the comm page, which is parent-writable and untrusted).

4. **THHV missing ioctls**: `THHV_SET_EXIT_POLICY` / `THHV_SET_DEF_EXIT_POLICY`
   ioctls are missing from `thhv_part.c`. The vmcall wrappers exist in
   `thhv_hvcall.c` but userspace (cloud-hypervisor) cannot reach them.

5. **No hypercall for reg bitmaps**: The engine supports `ExitReasonRegReadSet`,
   `ExitReasonRegWriteSet`, `VectorRegReadSet`, `VectorRegWriteSet` via
   `Capability::set_policy(PolicyIdentifier)`, but there are no capavisor
   hypercalls or THHV paths to set them.

### 8.2 Design: Unified SET_POLICY Hypercall

The engine already has a single generic dispatch:

```rust
Capability::set_policy(caller, child_handle, PolicyIdentifier, value) -> Result<()>
```

where `PolicyIdentifier` is an enum with variants for all policy fields (cores,
API, interrupt visibility, exit trap, reg bitmaps, etc.).

Rather than adding separate hypercalls for each bitmap variant, we introduce
**one unified hypercall** `THEMIS_SET_POLICY` that mirrors this interface:

```
THEMIS_SET_POLICY(child_handle, policy_tag, policy_key, value)
```

- `policy_tag`: discriminant of `PolicyIdentifier` (u8)
- `policy_key`: variant-specific parameter(s) packed into u64
  (e.g., vector + word_index, or exit_reason + word_index)
- `value`: the u64 value to set

This replaces (or subsumes) the existing per-type hypercalls:
- `THEMIS_SET_INTR_POLICY` → tag=VectorVisibility, key=vector
- `THEMIS_SET_DEF_INTR_POLICY` → tag=DefaultInterruptVisibility
- `THEMIS_SET_EXIT_POLICY` → tag=ExitReasonTrap, key=reason
- `THEMIS_SET_DEF_EXIT_POLICY` → tag=DefaultExitTrap

And naturally supports the new bitmap operations:
- tag=VectorRegReadSet, key=(vector, word_index)
- tag=VectorRegWriteSet, key=(vector, word_index)
- tag=ExitReasonRegReadSet, key=(reason, word_index)
- tag=ExitReasonRegWriteSet, key=(reason, word_index)

On the THHV side, one ioctl `THHV_SET_POLICY` with a struct encoding the
tag + key + value, replacing the current per-type ioctls.

### 8.3 Design: Correct read_set / write_set Enforcement

#### Storing the exit reason

When a child exits with a non-interrupt exit (forwarded via `forward_child_exit`),
the capavisor stores the exit reason in **VP metadata** owned by the capavisor
(the `PlatformDomain` / `VcpuSlot` structure — not the comm page). This is
tamper-proof since the parent never sees capavisor memory (A5).

For interrupt exits, the vector is already stored in `VpRunState::Interrupted { vector }`
inside the capability engine itself.

#### Forward path (child → parent)

- **Non-interrupt exits** (`forward_child_exit`): Already correct — uses
  `ExitPolicy.get_action(reason).read_set` to filter registers. ✓
- **Interrupt exits** (`forward_interrupt_to_handler`): Must be fixed to copy
  registers to the comm page using `InterruptPolicy.get_policy(vector).read_set`,
  similar to how `forward_child_exit` does it.

#### Resume path (parent → child)

`register_access_check` in the engine must be updated:

1. Determine whether the VP's last exit was an interrupt or a non-interrupt exit.
2. If interrupt: use `InterruptPolicy.get_policy(vector).write_set` (current
   behavior, already correct for this case).
3. If non-interrupt exit: use `ExitPolicy.get_action(saved_reason).write_set`.

The VP run state already distinguishes `Interrupted { vector }` from `Available`
(non-interrupt exit returns the VP to Available). The saved exit reason
(from capavisor VP metadata) must be made accessible to the engine's
`register_access_check`, either by:
- (a) Adding an `exit_reason` field to a VpRunState variant or a side field, or
- (b) Having the platform store it and the engine query it via a Platform
  trait method.

Option (a) is simpler and keeps the information in the engine where the access
check happens.

### 8.4 Implementation Plan

| Step | What | Files | Verification |
|------|------|-------|---|
| E1 | Store exit reason in VP metadata | `capa-engine/src/domain.rs`, `capability.rs`, capavisor `hypercall.rs` | `cargo test` |
| E2 | Fix `register_access_check` to branch on exit vs interrupt | `capa-engine/src/capability.rs` | `cargo test` |
| E3 | Fix `forward_interrupt_to_handler` to copy registers via read_set | capavisor `hypercall.rs` | build succeeds |
| E4 | Unified `THEMIS_SET_POLICY` hypercall | `themis-abi`, capavisor `hypercall.rs` | build succeeds |
| E5 | THHV: unified `THHV_SET_POLICY` ioctl + deprecate per-type ioctls | `thhv/inc/thhv.h`, `thhv/src/thhv_part.c`, `thhv/src/thhv_hvcall.c` | kernel module builds |
| E6 | Cloud-hypervisor: update callers to use new ioctl | `cloud-hypervisor/` | CHV builds |

---

## 9. Generic Monitor Loop Restructuring (Phase F)

### 9.1 Problem

The monitor loop (`monitor_loop` + `handle_vmexit` in `arch/x86_64/vmexit.rs`)
is ~530 lines of x86-specific code that **intermixes** three concerns:

1. **Raw exit decoding** — reading VMX exit reason, EXIT_QUALIFICATION, INTR_INFO
   fields → pure x86 mechanism.
2. **Policy lookup** — consulting ExitPolicy/InterruptPolicy to decide
   trap-vs-local → pure generic logic.
3. **Handling** — forwarding to parent (generic: engine switch + comm page copy)
   or local emulation (x86: CPUID, MSR, CR access, XSETBV, APIC).

Similarly, `hypercall.rs` (~2200 lines) mixes generic opcode dispatch with x86
VMCS manipulation (register read/write, VMCLEAR/VMPTRLD for context switches,
PIR injection, interrupt-window management).

This makes it impossible to reuse the dispatch logic for a different ISA.

### 9.2 Target Architecture

The agreed design is **approach A**: the generic loop owns the policy decision;
arch code only does raw decoding (before the loop) and local emulation (when
the loop delegates back).

```
┌─────────────────────────────────────────────────────────┐
│  Generic monitor loop (core/monitor.rs)                 │
│                                                         │
│  loop {                                                 │
│      exit = arch.enter_and_decode(vp)  ─────► arch code │
│                                                         │
│      match exit {                                       │
│          ArchHandled => continue,      // arch ate it   │
│          Hypercall   => generic_hypercall_dispatch(),    │
│          ExternalInterrupt { vector } =>                │
│              generic_interrupt_route(vector),            │
│          PolicyDriven { reason, .. } =>                 │
│              if policy.trap(reason):                    │
│                  generic_forward_to_parent(reason)      │
│              else:                                      │
│                  arch.handle_local(vp, exit)  ► arch    │
│          TimerExpired => generic_timer_handler(),        │
│          Shutdown     => halt(),                         │
│      }                                                  │
│  }                                                      │
└─────────────────────────────────────────────────────────┘
```

Key principle: **arch code fully decodes raw exits into semantic events**. The
generic loop never reads VMX-specific fields (EXIT_QUALIFICATION, INTR_INFO,
etc.). It only pattern-matches on `SemanticExit` variants.

### 9.3 Revised SemanticExit Enum

The current `ArchExit` enum needs refinement. In particular, exits that are
purely arch-internal (handled before reaching the generic loop) get a dedicated
variant so the loop can skip them. And EXCEPTION_NMI is split by the arch
decoder into NMI (→ interrupt routing) vs Exception (→ exit policy).

```rust
/// Produced by arch code after enter_and_decode().
pub enum SemanticExit {
    // ── Arch already handled — generic loop just continues ──
    ArchHandled,

    // ── Always generic dispatch (no policy lookup needed) ──
    Hypercall,
    ExternalInterrupt { vector: u32 },
    TimerExpired,

    // ── Policy-driven exits (generic loop consults ExitPolicy) ──
    PolicyDriven {
        reason: u32,              // raw exit reason (opaque to generic code
                                  // but passed through to ExitPolicy lookup
                                  // and forwarded to parent)
        info: ExitInfo,           // arch-decoded details for local handling
    },

    // ── Fatal — log and halt ──
    Shutdown { message: &'static str },
}

/// Arch-decoded exit details. Generic code does NOT inspect this —
/// it's passed through to arch.handle_local() if policy says trap=false.
/// Also carried to forward_to_parent for comm page population.
pub enum ExitInfo {
    Cpuid { leaf: u32, subleaf: u32 },
    Msr { number: u32, is_write: bool, value: u64 },
    CrAccess { cr: u8, is_write: bool, gpr_index: u8, value: u64 },
    IoInstruction { port: u16, size: u8, is_write: bool, value: u32 },
    EptViolation { gpa: u64, is_write: bool },
    Exception { vector: u8, error_code: Option<u32> },
    ApicIcr { icr_low: u32, icr_high: u32 },
    Sipi { vector_page: u8 },
    Halt,
    Other,  // fallback for unrecognized exit reasons
}
```

The arch decoder (x86: `classify_exit`) handles these **internally** and returns
`ArchHandled`:
- INIT_SIGNAL → cross-core notification (poll_and_respond)
- XSETBV → XCR0 write
- INTERRUPT_WINDOW → drain PIR
- EOI_INDUCED → A3 (currently no-op)
- EXCEPTION_NMI where type=NMI → returns `ExternalInterrupt { vector: 2 }`
  (NMI is routed like an interrupt)

The arch decoder returns `PolicyDriven` for everything else that's not
Hypercall, ExternalInterrupt, or fatal.

### 9.4 Arch Backend Entry Point

The `ArchVpOps` trait gets a refined entry method:

```rust
pub trait ArchVpOps {
    type VpHandle;

    /// Enter the guest, wait for an exit, decode it fully.
    /// Arch-internal exits (XSETBV, INIT, interrupt-window) are handled
    /// inside this call and return SemanticExit::ArchHandled.
    fn enter_and_decode(&mut self, vp: &mut Self::VpHandle,
                        platform: &ThemisPlatform) -> SemanticExit;

    /// Handle a local (non-trapped) exit. Called when ExitPolicy says
    /// trap=false for a PolicyDriven exit.
    fn handle_local(&mut self, vp: &mut Self::VpHandle,
                    info: &ExitInfo, platform: &ThemisPlatform);

    /// Advance the instruction pointer past the current instruction.
    fn advance_ip(&mut self, vp: &mut Self::VpHandle);

    // ... existing methods: get_hypercall_args, set_hypercall_result, etc.
}
```

On x86, `enter_and_decode` wraps: `vcpu.run()` → read basic_reason →
handle arch-internal exits (INIT, XSETBV, interrupt-window) internally →
if not internal, call `classify_exit()` to produce SemanticExit.

`handle_local` wraps the existing local handlers: `handle_cpuid_local`,
`handle_rdmsr_local`, `handle_wrmsr_local`, `handle_cr_access`,
`reinject_exception`, `next_instruction` for HLT/IO, etc.

### 9.5 Generic Monitor Loop (core/monitor.rs)

```rust
pub fn monitor_loop<A: ArchVpOps>(arch: &mut A, vp: &mut A::VpHandle,
                                   platform: &ThemisPlatform) -> ! {
    loop {
        let exit = arch.enter_and_decode(vp, platform);

        match exit {
            SemanticExit::ArchHandled => continue,

            SemanticExit::Shutdown { message } => {
                serial_println!("[FATAL] {}", message);
                halt_forever();
            }

            SemanticExit::Hypercall => {
                // Generic dispatch: read args, route opcode, write result.
                let args = arch.get_hypercall_args(vp);
                if let Some(result) = dispatch_hypercall(args, vp, arch, platform) {
                    arch.set_hypercall_result(vp, result);
                    arch.advance_ip(vp);
                }
                // None → SWITCH swapped the VP; no writeback.
            }

            SemanticExit::ExternalInterrupt { vector } => {
                // Generic: consult InterruptPolicy, route via engine.
                handle_interrupt(arch, vp, platform, vector);
            }

            SemanticExit::TimerExpired => {
                // Generic: check deferred vectors, reset timer.
                handle_timer(arch, vp, platform);
            }

            SemanticExit::PolicyDriven { reason, ref info } => {
                let trap = lookup_exit_policy(platform, reason);
                if trap {
                    // Generic: engine switch + comm page + VMCS swap.
                    forward_to_parent(arch, vp, platform, reason, info);
                } else {
                    // Arch-specific local emulation.
                    arch.handle_local(vp, info, platform);
                }
            }
        }
    }
}
```

The functions `dispatch_hypercall`, `handle_interrupt`, `forward_to_parent`
contain the **existing generic logic** currently in `hypercall.rs`:
- `dispatch_hypercall` → current `handle_vmcall` opcode match
- `handle_interrupt` → current `forward_interrupt_to_handler` (policy check +
  engine deliver_interrupt_vp + VMCS swap)
- `forward_to_parent` → current `forward_child_exit` (engine switch_return +
  comm page register copy + VMCS swap)

The VMCS swap parts of those functions (VMCLEAR/VMPTRLD, reading/writing VMCS
fields) get extracted into `ArchVpOps` methods:
- `deactivate_vp(vp) -> SavedVp` (VMCLEAR)
- `activate_vp(saved) -> VpHandle` (VMPTRLD)
- `read_reg(vp, VpRegister) -> u64`
- `write_reg(vp, VpRegister, u64)`

### 9.6 What Stays in Arch Code

These remain in `arch/x86_64/` and are NOT touched by the generic loop:

| Handler | Why arch-only |
|---------|---------------|
| `handle_xsetbv` | XCR0 is x86-specific (ARM uses CPACR_EL1) |
| `handle_cpuid_local` | CPUID is x86; ARM uses HVC-based feature query |
| `handle_rdmsr_local` / `handle_wrmsr_local` | MSRs are x86 |
| `handle_cr_access` | CR0/CR3/CR4 are x86; ARM uses SCTLR/TTBR/TCR |
| `reinject_exception` | VMENTRY_INTERRUPTION_INFO is VMX-specific |
| `handle_apic_access` / `handle_apic_write` | VAPIC / APIC-access page is x86 |
| SIPI setup (CS/RIP/CR0/activity) | Real-mode bootstrap is x86 only |
| `sync_ia32e_mode_guest` | IA-32e mode bit is x86 |
| Dump helpers (vmentry failure, triple fault, EPT misconfig) | VMX fields |

### 9.7 CPUID / APIC ICR Special Cases

Two exits need special handling in the policy-driven path:

**CPUID**: Certain leaves (Themis hypervisor leaves `0x40000000–0x40000003`,
TSC calibration `0x15`) are always handled locally regardless of policy.
Solution: the arch decoder checks the leaf and for those specific leaves
returns `ArchHandled` (handling them directly). For all other leaves, it
returns `PolicyDriven { reason: 10, info: Cpuid { leaf, subleaf } }`.

**APIC ICR write** (exit reasons 44/56): When a child writes ICR, the parent
needs to see it for SIPI handling. The arch decoder detects ICR writes
(checking the APIC offset in EXIT_QUALIFICATION) and returns
`PolicyDriven { reason: APIC_ACCESS, info: ApicIcr { icr_low, icr_high } }`.
Non-ICR APIC accesses return `ArchHandled` (handled locally by VAPIC
emulation).

### 9.8 Migration Strategy

The restructuring is done in 4 steps. **Builds and boots at every step.**

| Step | What | Verification |
|------|------|---|
| F1 | Create `SemanticExit` + `ExitInfo` types. Extend `ArchVpOps` with `enter_and_decode`, `handle_local`, VP save/restore, reg read/write methods. Implement for X86Platform (wrapping existing code). | `cargo build` passes |
| F2 | Create `core/monitor.rs` with generic `monitor_loop`. Port `forward_child_exit` and `forward_interrupt_to_handler` to be generic (using trait methods instead of direct VMCS access). Keep old `vmexit.rs::monitor_loop` as fallback. | `cargo build` passes |
| F3 | Wire new generic `monitor_loop` as the entry point. Remove old `handle_vmexit`. Move generic parts of `hypercall.rs` to `core/hypercall.rs`. | full boot test |
| F4 | Clean up: remove dead code, update module structure, verify all paths. | full boot matrix: dom0 4-CPU, dom1 1-CPU, dom1 2-CPU |

### 9.9 Lines-of-Code Impact

| Change | Lines |
|--------|-------|
| `SemanticExit` + `ExitInfo` types | ~80 new |
| `ArchVpOps` trait extensions | ~40 new |
| `X86Platform` impl (wrapping existing) | ~200 new (thin wrappers) |
| `core/monitor.rs` (generic loop) | ~150 new (extracted from vmexit.rs) |
| Removed from `vmexit.rs` | ~300 removed (handle_vmexit + duplicate dispatch) |
| Removed from `hypercall.rs` | ~100 removed (x86-specific parts move to arch) |
| **Net** | **~70 new lines** (mostly type definitions) |

The goal is net-neutral or slightly positive. The generic loop + types add
~470 lines but removing the interleaved dispatch saves ~400. The remaining
arch code in `vmexit.rs` shrinks to: `enter_and_decode` (classify), `handle_local`
(dispatch to existing handlers), and dump helpers.

### 9.10 Relationship to Other Phases

- **Phase E (policy fixes)**: E3 (interrupt register filtering) will be
  implemented as part of the generic `handle_interrupt` in F2. The generic
  path naturally handles both interrupt and exit register filtering symmetrically.
  E4-E6 (unified SET_POLICY) are independent and can proceed in parallel.
- **Phase A7** (ThemisPlatform generic over traits): F1-F4 provide the
  `ArchVpOps` methods that A7 needs. After Phase F, making ThemisPlatform
  fully generic is a natural next step.
- **Phase C** (file reorganization): Phase F creates the `core/monitor.rs`
  file and starts the core/arch split. Phase C completes it by moving
  remaining files.
- **Phase D** (ARM skeleton): After Phase F, adding ARM means implementing
  `run` (ESR_EL2 decode) and `handle_local` (SCTLR/TTBR/GIC).
  The generic loop, hypercall dispatch, and policy logic work unchanged.

---

## 10. Completion Summary (2026-04-13)

### Phases completed

| Phase | Description | Key commits |
|-------|-------------|-------------|
| A1-A6 | Trait seams + X86Platform impls | Earlier session |
| B1-B2 | ArchExit translation, unified dispatch | Earlier session |
| C1-C4 | File reorganization (arch/x86_64/) | Earlier session |
| E1-E2 | Store exit reason in VP metadata, fix register_access_check | 730756ce5, a41ca1328 |
| E3 | Fix forward_interrupt_to_handler register filtering | 45285a774 |
| E4 | Unified THEMIS_SET_POLICY hypercall (0x22) | fd1964d19 |
| E5-E6 | THHV ioctl + CHV support for unified SET_POLICY | 5e5acdbcf |
| F1 | SemanticExit types + ArchVpOps::run/handle_local | 4c028a175 |
| F2 | Generic monitor loop (monitor.rs) | 5f5f9d215 |
| F3 | Wire generic loop, remove old dispatch (-405 lines) | 111453574 |
| Cleanup | Remove old per-type policy paths (-245 lines) | 097f59d23 |

### Architecture after refactoring

```
main.rs::_start()              [generic boot orchestration]
  -> arch::boot::platform()     [arch: hardware discovery]
  -> arch::boot::init_themis()  [generic: create ThemisPlatform]
  -> arch::boot::vmx/capa/vmcs  [arch: VMX/EPT/VMCS setup]
  -> arch::boot::launch()       [arch: VMLAUNCH -> monitor_loop]

monitor::monitor_loop()        [GENERIC - the core run loop]
  -> ArchVpOps::run()           [arch: enter guest, decode exit -> SemanticExit]
  -> match SemanticExit          [generic: policy dispatch]
    -> Hypercall -> handle_vmcall [generic: capability engine]
    -> ExternalInterrupt         [generic: InterruptPolicy routing]
    -> PolicyDriven              [generic: ExitPolicy lookup -> forward or local]
    -> handle_local_exit()       [arch: CPUID, MSR, CR emulation]
```

### Key types

- **SemanticExit**: ArchHandled, Hypercall, ExternalInterrupt(vector),
  TimerExpired, PolicyDriven(reason, ExitInfo), Shutdown(reason)
- **ExitInfo**: Cpuid, Exception, EptViolation, IoInstruction, CrAccess,
  Msr, ApicIcr, Sipi, Halt, Other
- **ArchVpOps::run()**: enter guest, return SemanticExit
- **ArchVpOps::handle_local()**: arch-specific local exit handling

### Unified policy interface

One opcode (THEMIS_SET_POLICY / 0x22) covers all 10 PolicyIdentifier
variants: Cores, ApiMonitor, DefaultInterruptVisibility, VectorVisibility,
VectorRegReadSet, VectorRegWriteSet, DefaultExitTrap, ExitReasonTrap,
ExitReasonRegReadSet, ExitReasonRegWriteSet.

Full stack: CHV -> THHV ioctl -> vmcall -> capavisor -> Capability::set_policy().

### Remaining work

- **D** ✅ (2025-06-27): ARM skeleton created + trait boundary fixes:
  - `arch/aarch64/aarch64_platform.rs`: `Aarch64Platform` with all 5 trait impls (stubs)
  - `forward_interrupt`: u8→u32 (GIC IDs exceed 255)
  - `check_doorbell`: `(gpa, qualification)` → `&ExitInfo` (arch extracts fault info)
  - `EXTERNAL_INTERRUPT_EXIT_REASON` associated const on ArchVpOps
  - ExitInfo: added ARM variants (Stage2Fault, SystemRegTrap, Smc, Wfi)
  - `halt_forever()`: cfg-gated asm (cli;hlt vs wfi)
  - x86 deps cfg-gated in Cargo.toml
  - aarch64-unknown-none target installed; trait modules + skeleton compile

- **A7** (next): Full platform generification via cfg-gating.
  Strategy: cfg-gate x86 blocks in-place (not file moves) for minimal churn.
  Sub-steps:
  1. A7.1: cfg-gate domain.rs (all x86: VMCS, VAPIC, IO/MSR bitmaps)
  2. A7.2: cfg-gate guest/linux.rs (x86 bzImage loader)
  3. A7.3: cfg-gate platform.rs x86 parts (EptMapper, VcpuSlot, invept, VT-d)
  4. A7.4: cfg-gate hypercall.rs x86 parts (ActiveVcpu, VMCS fields, VT-d IRTE)
  5. A7.5: cfg-gate main.rs (serial I/O, boot body, AP entry)
  6. A7.6: cfg-gate attestation.rs (TPM MMIO)
  7. A7.7: Verify cross-compilation (aarch64 + x86)

- **ARM testbed**: QEMU virt machine with EL2 (`-machine virt,virtualization=on`)
