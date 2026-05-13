# Eunomia — Micro-Kernel Design Document

*Eunomia (Εὐνομία): goddess of lawful order, daughter of Themis.*

## 1. Purpose

Eunomia is a minimal, configurable micro-kernel written in Rust (`no_std`)
designed to run as a guest domain inside Themis.  It serves two roles:

1. **Test vehicle** — fast-booting (microseconds) guest for testing capavisor
   features (core-gapping, timer virtualization, interrupt forwarding, memory
   policies) without waiting for a full Linux boot.
2. **Minimal TCB runtime** — a small, auditable kernel for security-sensitive
   workloads (crypto enclaves, key stores, attestation agents) that benefit
   from running in a Themis confidential domain with a tiny trusted computing
   base.

Eunomia is **not** a general-purpose OS.  It targets a single address space,
cooperative (and optionally preemptive) multitasking, and tight integration
with the Themis capavisor via paravirtualized interfaces.

---

## 2. Design Principles

1. **Configurable core** — the kernel is structured around traits for its major
   subsystems (device I/O, scheduling, memory management).  Different
   implementations can be selected at compile time to customize behavior for
   testing, unikernel workloads, or future multi-process scenarios.

2. **Themis-native** — Eunomia knows it runs inside Themis.  It uses Themis
   hypercalls, understands the capability model, and can interact with the
   capavisor for memory management, inter-domain communication, and
   attestation.  No legacy BIOS/UEFI assumptions.

3. **Minimal footprint** — target < 5000 lines of Rust for the core kernel.
   No libc, no filesystem (initially), no network stack (initially).  Each
   feature is an optional crate that compiles in only when needed.

4. **PVH boot** — enters at 64-bit long mode via the PVH entry point
   (supported by cloud-hypervisor).  No real-mode bootstrap, no bzImage
   header, no decompression.  Identity-mapped memory provided by the VMM.

5. **Test-first** — the test harness is a first-class citizen, not an
   afterthought.  Tests are registered declaratively, run sequentially, and
   report results via serial.  The kernel can be built in "test mode" where
   it boots, runs all tests, and exits.

---

## 3. Related Work and Inspiration

| Project | Relevance to Eunomia |
|---------|---------------------|
| **Writing an OS in Rust** (phil-opp) | Tutorial-quality Rust OS: GDT, IDT, paging, heap, async. We adapt boot and interrupt setup patterns. |
| **Hermit** (hermit-os/kernel) | Rust unikernel for VMs. Single address space, library OS model. Validates the "Rust kernel in a VM" approach. Supports PVH boot on CHV. |
| **Redox** (redox-os/kernel) | Rust micro-kernel with trait-based subsystems, message-passing IPC. Inspiration for configurable kernel architecture. |
| **Theseus** (theseus-os) | Intralingual design — leverages Rust type system for resource management. Shows how to use Rust traits for OS modularity. |
| **Poplar** (pebble-os) | Capability-based Rust micro-kernel. Relevant for capability integration patterns. |
| **Embassy** (embassy-rs) | Embedded async framework with trait-based HALs for different hardware. Model for `Device` trait abstraction and compile-time configuration. |
| **rust-hypervisor-firmware** | Minimal firmware for CHV. Demonstrates PVH boot entry for Rust binaries on CHV. |

---

## 4. Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                    Applications                      │
│  (test harness, crypto enclave, key store, ...)      │
├───────────────── UserKernelInterface ────────────────┤
│                   Kernel Services                    │
│  ┌──────────┐  ┌───────────┐  ┌──────────────────┐  │
│  │Scheduler │  │  Memory   │  │    Device I/O    │  │
│  │ (trait)  │  │  Manager  │  │    (trait)       │  │
│  │          │  │  (trait)  │  │                  │  │
│  └────┬─────┘  └─────┬─────┘  └───────┬──────────┘  │
│       │              │                │              │
│  ┌────┴─────┐  ┌─────┴─────┐  ┌──────┴───────────┐  │
│  │coop_sched│  │bump_alloc │  │  serial_device   │  │
│  │preempt   │  │page_alloc │  │  virtio_console  │  │
│  │  ...     │  │  ...      │  │  themis_pv_timer │  │
│  └──────────┘  └───────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────┤
│                  Arch Layer (x86_64)                 │
│  boot.rs  gdt.rs  idt.rs  paging.rs  msr.rs         │
├───────────────── HypervisorInterface ───────────────┤
│               Themis Integration Layer               │
│  hypercall.rs  capability.rs  domcomm.rs             │
├─────────────────────────────────────────────────────┤
│                 Themis Capavisor (L0)                 │
└─────────────────────────────────────────────────────┘
```

### 4.1 Trait-Based Subsystems

The kernel core defines traits for each major subsystem.  Concrete
implementations are selected at compile time via Cargo features.

```rust
/// Scheduler trait — controls how tasks are dispatched.
pub trait Scheduler {
    /// Initialize the scheduler.
    fn init(&mut self);
    /// Add a task to the run queue.
    fn spawn(&mut self, task: Task);
    /// Select the next task to run.  Returns None if idle.
    fn schedule(&mut self) -> Option<Task>;
    /// Yield the current task.
    fn yield_now(&mut self);
}

/// Memory manager trait — controls memory allocation.
pub trait MemoryManager {
    /// Initialize with the memory map provided at boot.
    fn init(&mut self, memory_map: &[MemoryRegion]);
    /// Allocate a contiguous region of `size` bytes.
    fn allocate(&mut self, size: usize, align: usize) -> Option<*mut u8>;
    /// Free a previously allocated region.
    fn deallocate(&mut self, ptr: *mut u8, size: usize);
}

/// Device trait — abstraction for I/O devices.
pub trait Device {
    /// Device name for identification.
    fn name(&self) -> &str;
    /// Initialize the device.
    fn init(&mut self) -> Result<(), DeviceError>;
}

/// Console output device.
pub trait ConsoleDevice: Device {
    /// Write bytes to the console.
    fn write_bytes(&mut self, bytes: &[u8]);
}

/// Timer device — programs deadlines and handles ticks.
pub trait TimerDevice: Device {
    /// Arm a one-shot timer for `deadline` (TSC value or reference time).
    fn arm(&mut self, deadline: u64);
    /// Check if the timer has fired.
    fn pending(&self) -> bool;
    /// Acknowledge the timer interrupt.
    fn ack(&mut self);
}

/// User-to-kernel interface — defines how user-level code invokes kernel
/// services (syscalls, upcalls, signal delivery).
///
/// Implementations may range from a simple function-call ABI (single
/// address space unikernel) to a full SYSCALL/SYSRET trap-based
/// interface for a multi-process configuration.
pub trait UserKernelInterface {
    /// Handle a user request identified by `op` with up to 4 arguments.
    /// Returns a result value or an error code.
    fn handle_request(&mut self, op: u64, args: [u64; 4]) -> Result<u64, SyscallError>;
    /// Deliver an asynchronous event (signal/upcall) to user code.
    fn deliver_upcall(&mut self, event: UpcallEvent) -> Result<(), SyscallError>;
    /// Register a handler for a given upcall type.
    fn register_upcall_handler(&mut self, event_type: u64, handler: UpcallHandler);
}

/// Kernel-to-hypervisor / remote-domain interface — defines how the
/// kernel communicates with the hypervisor (capavisor) and with peer
/// or parent domains.
///
/// Implementations:
/// - `ThemisBackend`: VMCALL-based hypercalls + DomainComm shared pages.
/// - `StubBackend`: no-op (for unit testing outside a VM).
/// - Future: could target different hypervisors (e.g., KVM pvcalls).
pub trait HypervisorInterface {
    /// Issue a hypercall to the hypervisor.
    fn hypercall(&self, op: u64, args: [u64; 4]) -> Result<u64, HvError>;
    /// Send a message to a peer domain identified by `domain_id`.
    fn send(&self, domain_id: u64, buf: &[u8]) -> Result<usize, HvError>;
    /// Receive a message from any domain.  Returns (sender_id, bytes_read).
    fn recv(&self, buf: &mut [u8]) -> Result<(u64, usize), HvError>;
    /// Query hypervisor for a capability or configuration value.
    fn query(&self, key: u64) -> Result<u64, HvError>;
}
```

### 4.2 Compile-Time Configuration

Features in `Cargo.toml` select implementations:

```toml
[features]
default = ["sched-coop", "alloc-bump", "console-serial"]

# Scheduler implementations
sched-coop    = []   # Cooperative round-robin (default)
sched-preempt = []   # Preemptive with timer-based quantum

# Memory manager implementations
alloc-bump    = []   # Bump allocator (fast, no free)
alloc-page    = []   # Page-granularity allocator (supports free)

# Console implementations
console-serial = []  # 16550 UART on port 0x3F8
console-virtio = []  # Virtio-console (future)

# Timer implementations
timer-tsc     = []   # Native TSC-deadline (WRMSR 0x6E0)
timer-pv      = []   # Themis paravirtualized synthetic timer (future)

# Themis integration
themis-hypercall = [] # Enable Themis hypercall interface
themis-attest    = [] # Enable attestation support

# User-kernel interface implementations
uki-direct  = []  # Direct function calls (unikernel, single address space)
uki-syscall = []  # SYSCALL/SYSRET trap-based (multi-process, future)

# Hypervisor/domain interface implementations
hvi-themis  = []  # Themis VMCALL + DomainComm (production)
hvi-stub    = []  # No-op stub (unit testing outside a VM)
```

---

## 5. Boot Sequence

### 5.1 PVH Entry

CHV loads Eunomia as an ELF64 binary.  It looks for a PVH entry point
(`XEN_ELFNOTE_PHYS32_ENTRY` ELF note) and enters at 64-bit long mode
(CHV transitions from the 32-bit PVH entry to 64-bit before jumping):

1. **CHV**: loads ELF segments into guest memory at the ELF-specified
   physical addresses.
2. **CHV**: sets up initial page tables (identity map), GDT, and segment
   registers.
3. **CHV**: sets RIP to the PVH entry point.
4. **Eunomia `_start`**: receives `hvm_start_info` pointer in `%ebx` (or
   `%rdi` for 64-bit entry).

### 5.2 Early Boot (`_start` → `main`)

```
_start (assembly stub):
  1. Set up stack pointer (use a static 64 KiB stack)
  2. Save hvm_start_info pointer
  3. Call rust_main(hvm_start_info)

rust_main:
  1. Initialize serial console (port 0x3F8)
  2. Print boot banner: "Eunomia v0.1.0 booted"
  3. Parse hvm_start_info → memory map
  4. Initialize GDT (code64, data64, TSS)
  5. Initialize IDT (exception handlers + timer vector)
  6. Initialize memory manager (from memory map)
  7. Initialize scheduler
  8. Initialize timer device
  9. If test mode: run_tests() → exit via triple fault or VMCALL
  10. If app mode: run main application loop
```

### 5.3 hvm_start_info

The PVH boot protocol passes a `hvm_start_info` struct containing:
- `magic`: 0x336ec578
- `memmap_paddr`: physical address of E820-like memory map
- `memmap_entries`: number of entries
- `cmdline_paddr`: kernel command line (optional)

Eunomia parses this to discover usable memory regions.

---

## 6. Subsystem Details

### 6.1 Interrupt Handling (IDT)

Eunomia sets up a minimal IDT with handlers for:

| Vector | Handler | Purpose |
|--------|---------|---------|
| 0 | `#DE` | Divide error |
| 6 | `#UD` | Invalid opcode |
| 8 | `#DF` | Double fault (IST) |
| 13 | `#GP` | General protection |
| 14 | `#PF` | Page fault |
| 32+ | Timer | LAPIC timer / PV timer |
| 33+ | Device | Future: virtio interrupts |

Exception handlers print diagnostic info via serial and halt (or panic
with a test failure in test mode).

The timer interrupt handler is pluggable via the `TimerDevice` trait.

### 6.2 Memory Management

Initial implementation: **bump allocator** for simplicity.

- The memory map from `hvm_start_info` identifies usable regions.
- The bump allocator hands out memory from the first usable region.
- No `free()` in the bump allocator — sufficient for test mode and
  simple applications.
- Future: page-granularity allocator with free list, supporting the
  Rust `GlobalAlloc` trait for `alloc` crate integration.

### 6.3 Scheduling

Initial implementation: **cooperative round-robin**.

- Tasks are Rust closures or function pointers registered with the
  scheduler.
- `yield_now()` switches to the next task.
- No preemption initially — timer interrupts are used for testing,
  not for task preemption.
- Future: preemptive scheduler using timer interrupts for quantum
  enforcement.

### 6.4 Serial Console

16550 UART on I/O port 0x3F8 (COM1).  This is the primary output
channel.  CHV captures serial output via `--serial tty` or `--serial
file=/path`.

### 6.5 User-Kernel Interface

The `UserKernelInterface` trait (§4.1) defines the boundary between
application code and the kernel.  Two planned implementations:

- **Direct call** (`uki-direct`): In the default unikernel / single
  address space mode, applications call kernel services through normal
  Rust function calls via a global `KernelServices` struct.  No ring
  transition, no context switch — just a trait method invocation.  This
  is the initial implementation.

- **Syscall** (`uki-syscall`): For a future multi-process configuration,
  applications would use `SYSCALL`/`SYSRET` to trap into the kernel.
  The `handle_request` method would be invoked from the syscall handler
  in the IDT path.  Upcalls (signals/notifications) would be delivered
  by modifying the user-space return frame.

### 6.6 Hypervisor / Domain Interface

The `HypervisorInterface` trait (§4.1) abstracts all communication
below the kernel — toward the hypervisor and toward peer domains.

- **Themis backend** (`hvi-themis`): production implementation using
  `VMCALL` for hypercalls and DomainComm shared pages for inter-domain
  messaging (see §7 for details).

- **Stub backend** (`hvi-stub`): no-op implementation that returns
  errors or canned values.  Allows unit-testing kernel logic on the
  host without a hypervisor.

```rust
pub struct SerialConsole;

impl ConsoleDevice for SerialConsole {
    fn write_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            unsafe {
                // Wait for transmit buffer empty
                while (inb(0x3FD) & 0x20) == 0 {}
                outb(0x3F8, b);
            }
        }
    }
}
```

The `print!` and `println!` macros use this globally.

---

## 7. Themis Integration Layer

This is what distinguishes Eunomia from a generic toy OS: tight
integration with the Themis capavisor, abstracted behind the
`HypervisorInterface` trait (§4.1).

### 7.1 Hypercall Interface

The `ThemisBackend` implementation of `HypervisorInterface` issues
Themis hypercalls (VMCALL) to interact with the capavisor:

- **Attestation**: request attestation report from the capavisor.
- **Memory management**: request additional memory pages via capability
  engine operations.
- **Inter-domain communication**: send/receive messages via DomainComm.
- **Controlled exit**: signal completion to the parent domain.

```rust
/// Issue a Themis hypercall.
pub unsafe fn themis_hypercall(op: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let result: u64;
    core::arch::asm!(
        "vmcall",
        inlateout("rax") op => result,
        in("rbx") arg1,
        in("rcx") arg2,
        in("rdx") arg3,
    );
    result
}
```

### 7.2 DomainComm

Eunomia can communicate with its parent domain (dom0) via the DomainComm
shared memory ring.  This enables:

- Test result reporting (structured, not just serial text).
- Request/response protocols with dom0 services.
- Future: virtio-over-DomainComm transport.

### 7.3 Paravirtualized Devices

Instead of emulating full hardware devices, Eunomia can use Themis-specific
paravirtualized interfaces:

- **PV timer**: synthetic timer MSRs (§10 of core-gapping.md) —
  future enhancement, initially uses native TSC-deadline.
- **PV console**: DomainComm-based console output — future enhancement,
  initially uses serial.

---

## 8. Test Harness

The test harness is a core feature of Eunomia, not an add-on.

### 8.1 Test Registration

Tests are registered using a `#[eunomia_test]` attribute macro (or a
simpler inventory-based approach):

```rust
struct TestCase {
    name: &'static str,
    func: fn() -> Result<(), &'static str>,
}

// Static test registry (populated by linker section or manual array).
static TESTS: &[TestCase] = &[
    TestCase { name: "timer_tsc_deadline", func: test_timer_tsc_deadline },
    TestCase { name: "pio_serial_echo",    func: test_pio_serial_echo },
    TestCase { name: "exception_gp",       func: test_exception_gp },
    // ...
];
```

### 8.2 Test Runner

```rust
fn run_tests() -> ! {
    println!("=== Eunomia Test Suite ===");
    let mut passed = 0;
    let mut failed = 0;
    for test in TESTS {
        print!("  {} ... ", test.name);
        match (test.func)() {
            Ok(()) => { println!("PASS"); passed += 1; }
            Err(msg) => { println!("FAIL: {}", msg); failed += 1; }
        }
    }
    println!("=== {}/{} passed ===", passed, passed + failed);
    // Exit: use Themis hypercall or triple fault
    if failed == 0 {
        exit_success();
    } else {
        exit_failure();
    }
}
```

### 8.3 Exit Mechanism

In test mode, Eunomia needs to signal completion to the VMM.  Options:
- **I/O port exit code**: write to a special port (e.g., 0xF4, used by
  QEMU's `isa-debug-exit` device).  CHV can be configured to recognize this.
- **HLT**: execute HLT, which causes a VMEXIT.  Dom0/CHV reads the exit
  and checks serial output for results.
- **Themis hypercall**: `VMCALL_SHUTDOWN` or a custom exit hypercall.

### 8.4 Example Tests

**Timer test** (core-gapping relevant):
```rust
fn test_timer_tsc_deadline() -> Result<(), &'static str> {
    static TIMER_FIRED: AtomicBool = AtomicBool::new(false);

    // Register timer ISR.
    register_timer_handler(|| { TIMER_FIRED.store(true, Ordering::SeqCst); });

    // Program TSC-deadline 1ms in the future.
    let deadline = rdtsc() + tsc_frequency_hz() / 1000;
    unsafe { wrmsr(IA32_TSC_DEADLINE, deadline); }

    // Busy-wait (with timeout).
    let timeout = rdtsc() + tsc_frequency_hz(); // 1 second
    while !TIMER_FIRED.load(Ordering::SeqCst) {
        if rdtsc() > timeout {
            return Err("timer did not fire within 1 second");
        }
        core::hint::spin_loop();
    }
    Ok(())
}
```

**PIO test**:
```rust
fn test_pio_serial_echo() -> Result<(), &'static str> {
    // Write a known pattern to serial port.
    let pattern = b"EUNOMIA_PIO_TEST";
    for &b in pattern {
        unsafe { outb(0x3F8, b); }
    }
    // If we get here without a fault, PIO exits are working.
    Ok(())
}
```

---

## 9. Project Structure

```
eunomia/
├── Cargo.toml                # no_std, features for subsystem selection
├── build.rs                  # linker script path emission
├── linker.ld                 # flat binary, load at 0x100000
├── src/
│   ├── main.rs               # entry point, boot sequence, test runner
│   ├── lib.rs                # kernel API (for future app crates)
│   │
│   ├── arch/
│   │   └── x86_64/
│   │       ├── mod.rs
│   │       ├── boot.rs       # PVH entry, hvm_start_info parsing
│   │       ├── gdt.rs        # GDT + TSS setup
│   │       ├── idt.rs        # IDT setup, exception/interrupt handlers
│   │       ├── msr.rs        # MSR read/write helpers
│   │       └── paging.rs     # page table manipulation (future)
│   │
│   ├── traits/
│   │   ├── mod.rs
│   │   ├── scheduler.rs      # Scheduler trait
│   │   ├── memory.rs         # MemoryManager trait
│   │   ├── device.rs         # Device, ConsoleDevice, TimerDevice traits
│   │   ├── uki.rs            # UserKernelInterface trait
│   │   └── hvi.rs            # HypervisorInterface trait
│   │
│   ├── sched/
│   │   ├── mod.rs             # compile-time scheduler selection
│   │   ├── coop.rs            # cooperative round-robin
│   │   └── preempt.rs         # preemptive (future)
│   │
│   ├── mem/
│   │   ├── mod.rs             # compile-time allocator selection
│   │   ├── bump.rs            # bump allocator
│   │   └── page.rs            # page allocator (future)
│   │
│   ├── devices/
│   │   ├── mod.rs
│   │   ├── serial.rs          # 16550 UART (0x3F8)
│   │   ├── timer_tsc.rs       # TSC-deadline timer
│   │   └── timer_pv.rs        # Themis PV timer (future)
│   │
│   ├── themis/
│   │   ├── mod.rs
│   │   ├── hypercall.rs       # VMCALL interface
│   │   ├── hvi_themis.rs      # HypervisorInterface: Themis backend
│   │   ├── domcomm.rs         # DomainComm ring (future)
│   │   └── attest.rs          # attestation (future)
│   │
│   ├── uki/
│   │   ├── mod.rs             # compile-time UKI selection
│   │   ├── direct.rs          # direct-call (unikernel mode)
│   │   └── syscall.rs         # SYSCALL/SYSRET (future)
│   │
│   ├── hvi/
│   │   ├── mod.rs             # compile-time HVI selection
│   │   ├── stub.rs            # no-op stub (host testing)
│   │   └── themis.rs          # re-exports themis/hvi_themis.rs
│   │
│   └── tests/
│       ├── mod.rs             # test registry, runner
│       ├── timer.rs           # timer interrupt tests
│       ├── pio.rs             # PIO exit tests
│       ├── mmio.rs            # MMIO exit tests (future)
│       ├── exception.rs       # exception handler tests
│       └── core_gapping.rs    # core-gapping specific tests (future)
│
└── README.md
```

---

## 10. Implementation Phases

### Phase E1: Boot and Serial (Foundation)

**Goal**: Eunomia boots via PVH, prints to serial, and halts.

- PVH entry stub (assembly), stack setup
- Serial console driver (0x3F8)
- `print!` / `println!` macros
- Panic handler (print message, halt)
- Build as ELF64, loadable by CHV via `--kernel`

**Lines**: ~200
**Depends on**: nothing

### Phase E2: GDT + IDT + Exceptions

**Goal**: proper GDT with TSS, IDT with exception handlers.

- GDT: code64, data64, TSS (for IST double-fault stack)
- IDT: #DE, #UD, #DF (IST), #GP, #PF handlers
- Exception handlers print fault info and halt
- Test: trigger #UD (invalid opcode), verify handler runs

**Lines**: ~250
**Depends on**: E1

### Phase E3: Test Harness

**Goal**: declarative test registration, runner, exit mechanism.

- `TestCase` struct, static test array
- `run_tests()` function with pass/fail counting
- Exit via I/O port 0xF4 (isa-debug-exit) or HLT
- Serial output format parseable by test scripts
- Cargo feature `test-mode` to build in test mode

**Lines**: ~100
**Depends on**: E1

### Phase E4: Timer Interrupt

**Goal**: program TSC-deadline timer, handle interrupt in IDT.

- Timer vector (e.g., 0x20) in IDT
- `TimerDevice` trait implementation for TSC-deadline
- WRMSR 0x6E0 programming
- Timer ISR increments counter, EOIs LAPIC
- Test: arm timer, verify it fires

**Lines**: ~150
**Depends on**: E2

### Phase E5: Memory Manager

**Goal**: bump allocator from hvm_start_info memory map.

- Parse `hvm_start_info` memory map
- Bump allocator implementation
- Implement `GlobalAlloc` trait (enables `alloc` crate)
- Test: allocate and use a `Vec<u8>`

**Lines**: ~150
**Depends on**: E1 (memory map parsing), E3 (test harness)

### Phase E6: Cooperative Scheduler

**Goal**: simple task scheduler.

- `Task` type (function pointer + small stack)
- Cooperative round-robin scheduler
- `yield_now()` via context switch
- Test: two tasks alternating via yield

**Lines**: ~200
**Depends on**: E5 (for task stacks)

### Phase E7: Themis Integration

**Goal**: Themis hypercall interface, basic capability interaction.

- `themis_hypercall()` function
- Exit via Themis-specific hypercall
- DomainComm shared page discovery (from memory map)
- Test: issue a hypercall, verify response

**Lines**: ~100
**Depends on**: E1

### Future Phases

- **E8**: Core-gapping test suite (Forward policy, shared page events,
  doorbell IPI verification)
- **E9**: Virtio-console driver (richer I/O than serial)
- **E10**: Preemptive scheduler (timer-based quantum)
- **E11**: Page-granularity allocator with free
- **E12**: Multi-VP support (AP startup via SIPI)
- **E13**: Attestation client (request/verify attestation reports)
- **E14**: Application framework (crypto enclave, key store template)

---

## 11. Build Integration

### Workspace

Add to root `Cargo.toml` workspace members:
```toml
members = [
    # ...existing...
    "eunomia",
]
```

### Target

Eunomia uses `x86_64-unknown-none` (freestanding, no OS).  A custom
target JSON may be needed for specific linker settings:

```json
{
    "llvm-target": "x86_64-unknown-none",
    "data-layout": "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128",
    "arch": "x86_64",
    "os": "none",
    "features": "-mmx,-sse,-sse2,+soft-float",
    "linker": "rust-lld",
    "panic-strategy": "abort",
    "disable-redzone": true,
    "executables": true
}
```

Alternatively, use the built-in `x86_64-unknown-none` target with
`.cargo/config.toml` overrides.

### Build Command

```bash
cargo build -p eunomia --release --target x86_64-unknown-none
```

The output ELF is at `target/x86_64-unknown-none/release/eunomia`.

### Running

```bash
# Inside dom0, or with QEMU directly for testing:
KERNEL=/path/to/eunomia sudo ./run-dom1.sh
```

---

## 12. Relationship to Existing Components

| Component | Relationship |
|-----------|-------------|
| **Capavisor** | Eunomia runs as a guest under the capavisor.  It exercises capavisor features (timer, interrupt, memory) and can issue hypercalls. |
| **capa-engine** | Eunomia's capabilities are managed by the engine.  The Themis integration layer may query capability state. |
| **thhv.ko** | Dom0's driver manages Eunomia's domain lifecycle (create, seal, run, destroy). |
| **cloud-hypervisor** | Loads Eunomia as a PVH kernel, provides virtual devices.  Eunomia's serial output goes through CHV's `--serial` option. |
| **test_child_hlt** | Eunomia supersedes this minimal test.  `test_child_hlt` tests the thhv ioctl surface; Eunomia tests the full capavisor + guest interaction. |
| **themis-abi** | Eunomia should use `themis-abi` for hypercall opcode definitions and shared data structures. |

---

## 13. References

- **Writing an OS in Rust**: https://os.phil-opp.com/ — boot, GDT, IDT,
  paging, heap, async patterns
- **Hermit unikernel**: https://github.com/hermit-os/kernel — Rust unikernel
  for VMs, PVH boot, single address space model
- **Redox kernel**: https://github.com/redox-os/kernel — Rust micro-kernel
  with trait-based architecture
- **Theseus OS**: https://github.com/theseus-os/Theseus — intralingual
  design, Rust type system for OS modularity
- **Poplar**: https://github.com/pebble-os/pebble — capability-based Rust
  micro-kernel
- **Embassy**: https://github.com/embassy-rs/embassy — trait-based HAL
  design for embedded systems
- **rust-hypervisor-firmware**: CHV's firmware, demonstrates PVH boot in Rust
- **PVH boot protocol**: Xen PVH specification, `hvm_start_info` structure
- **Intel SDM Vol 3C**: GDT, IDT, paging, MSRs, TSC-deadline timer
- `docs/architecture/core-gapping.md` §10 — timer virtualization design
- `docs/architecture/interrupt-virtualization.md` — interrupt routing model
