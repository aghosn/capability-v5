#![no_std]
#![no_main]
// Enable heap-allocated types (Vec, Box, BTreeMap, …) via the global allocator
// declared below.  The allocator is backed by a static BSS array (`HEAP`) that
// is placed and mapped as part of the kernel binary — no runtime carving
// of physical memory is required.
extern crate alloc;

use core::fmt;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[cfg(not(feature = "direct-boot"))]
use limine::request::{
    ExecutableAddressRequest, ExecutableFileRequest, HhdmRequest, MemoryMapRequest, ModuleRequest,
    MpRequest, RsdpRequest,
};
#[cfg(not(feature = "direct-boot"))]
use limine::BaseRevision;
use linked_list_allocator::LockedHeap;

// Direct-boot uses a smaller heap during early bringup (MMU off, BSS zeroed by asm stub).
#[cfg(feature = "direct-boot")]
pub(crate) const HEAP_SIZE: usize = 4 * 1024 * 1024; // 4 MiB
#[cfg(not(feature = "direct-boot"))]
pub(crate) const HEAP_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

/// Aligned wrapper so the heap array sits on a 16-byte boundary in .bss.
#[repr(align(16))]
struct AlignedHeap(#[allow(dead_code)] [u8; HEAP_SIZE]);

/// Heap backing storage — placed in .bss by the linker, mapped by Limine.
/// Limine loads the capavisor ELF and handles physical placement and page
/// table setup for this array as part of the kernel binary.  The global
/// allocator is initialised from this array at the very start of _start()
/// before any heap-using boot code runs.
static mut HEAP: AlignedHeap = AlignedHeap([0; HEAP_SIZE]);

/// Runtime debug toggle — controlled via THEMIS_TOGGLE_DEBUG vmcall.
/// When true, `serial_rtdbg!` prints are emitted.
pub(crate) static RUNTIME_DEBUG: AtomicBool = AtomicBool::new(false);

/// Print only when RUNTIME_DEBUG is enabled.
#[macro_export]
macro_rules! serial_rtdbg {
    ($($arg:tt)*) => {
        if $crate::RUNTIME_DEBUG.load(core::sync::atomic::Ordering::Relaxed) {
            $crate::serial_println!($($arg)*);
        }
    };
}

mod arch;
mod arch_traits;

mod attestation;
mod comm;
#[cfg(target_arch = "x86_64")]
mod domain;
mod guest;
mod hypercall;
mod mem;
mod monitor;
mod platform;
mod util;
#[cfg(target_arch = "x86_64")]
mod vmx {
    pub use ::vmx::features::*;
}
#[cfg(target_arch = "x86_64")]
pub mod vcpu {
    pub use ::vmx::vcpu::*;
}

// ── Serial console (COM1, 0x3F8) ────────────────────────────────────────── //

pub struct SerialPort;

#[cfg(target_arch = "x86_64")]
impl SerialPort {
    /// Standard COM1 UART initialization (8N1, 115200 baud).
    fn init() {
        unsafe {
            x86::io::outb(0x3F8 + 1, 0x00); // Disable interrupts
            x86::io::outb(0x3F8 + 3, 0x80); // Enable DLAB (set baud rate divisor)
            x86::io::outb(0x3F8 + 0, 0x01); // 115200 baud (divisor = 1)
            x86::io::outb(0x3F8 + 1, 0x00);
            x86::io::outb(0x3F8 + 3, 0x03); // 8 bits, no parity, one stop bit
            x86::io::outb(0x3F8 + 2, 0xC7); // Enable FIFO, clear, 14-byte threshold
            x86::io::outb(0x3F8 + 4, 0x03); // RTS/DSR set
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
impl SerialPort {
    fn init() {
        // PL011 init deferred to _start (needs identity map to be set up).
    }

    /// Initialize PL011 UART using identity-mapped physical address.
    fn init_physical() {
        arch::aarch64::serial::init_physical();
    }
}

#[cfg(target_arch = "x86_64")]
impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            unsafe {
                while (x86::io::inb(0x3F8 + 5) & 0x20) == 0 {}
                x86::io::outb(0x3F8, b);
            }
        }
        Ok(())
    }
}

#[cfg(not(target_arch = "x86_64"))]
impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            arch::aarch64::serial::putc(b);
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => { let _ = core::fmt::write(&mut $crate::SerialPort, format_args!($($arg)*)); };
}

#[macro_export]
macro_rules! serial_println {
    ()            => { $crate::serial_print!("\n") };
    ($($arg:tt)*) => { $crate::serial_print!("{}\n", format_args!($($arg)*)) };
}

/// Like `serial_println!` but only emits output when the `verbose` feature is enabled.
/// Use this for high-frequency per-VMEXIT / SWITCH / CHILD_EXIT tracing.
#[macro_export]
macro_rules! serial_debug {
    ($($arg:tt)*) => {
        #[cfg(feature = "verbose")]
        $crate::serial_println!($($arg)*)
    };
}

// ── Limine protocol requests (not used with direct-boot) ─────────────────── //

#[cfg(not(feature = "direct-boot"))]
mod limine_requests {
    use super::*;

    // Use base revision 0 on aarch64 to get identity mapping of first 4 GiB
    // (needed for PL011 UART at 0x0900_0000 before we have our own page tables).
    // Revision 0 is the only one with unconditional 4 GiB identity map.
    // x86 uses revision 3 (default from BaseRevision::new()).
    #[cfg(target_arch = "x86_64")]
    #[used]
    pub static BASE_REVISION: BaseRevision = BaseRevision::new();
    #[cfg(not(target_arch = "x86_64"))]
    #[used]
    pub static BASE_REVISION: BaseRevision = BaseRevision::with_revision(0);
    #[used]
    pub static MEMMAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();
    #[used]
    pub static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();
    #[used]
    pub static RSDP_REQUEST: RsdpRequest = RsdpRequest::new();
    #[used]
    pub static MP_REQUEST: MpRequest = MpRequest::new();
    #[used]
    pub static MODULE_REQUEST: ModuleRequest = ModuleRequest::new();
    #[used]
    pub static KERNEL_ADDR_REQUEST: ExecutableAddressRequest = ExecutableAddressRequest::new();
    #[used]
    pub static KERNEL_FILE_REQUEST: ExecutableFileRequest = ExecutableFileRequest::new();
}

#[cfg(not(feature = "direct-boot"))]
use limine_requests::*;

// ── Global heap allocator ────────────────────────────────────────────────── //

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

// ── SMP barrier ─────────────────────────────────────────────────────────── //

/// Number of APs that have signalled readiness to the BSP.
pub(crate) static AP_READY_COUNT: AtomicU64 = AtomicU64::new(0);
/// Spinlock for serializing AP serial output.
pub(crate) static SERIAL_LOCK: AtomicBool = AtomicBool::new(false);

/// Physical and virtual base of the capavisor kernel binary.
/// Set once at the top of _start() from KernelAddressRequest.
/// Used by paging::ensure_table to correctly translate kernel-space heap
/// VA → PA (BSS heap is at kernel VA, not HHDM VA, so virt - hhdm is wrong).
pub(crate) static KERNEL_PHYS_BASE: AtomicU64 = AtomicU64::new(0);
pub(crate) static KERNEL_VIRT_BASE: AtomicU64 = AtomicU64::new(0);

// ── AP launch synchronization ────────────────────────────────────────────── //
//
// BSP populates PLATFORM_PTR (pointer to the live ThemisPlatform, which holds
// per-core VMXON addresses) with a Relaxed store, then sets AP_LAUNCH_READY
// with a Release store.  APs spin on AP_LAUNCH_READY (Acquire); the
// Release/Acquire edge makes PLATFORM_PTR visible.  APs take their
// InactiveVcpus from the PlatformDomain via take_vcpu().

pub(crate) static AP_LAUNCH_READY: AtomicBool = AtomicBool::new(false);

/// Pointer to the fully-initialized ThemisPlatform; set in _start() before
/// AP_LAUNCH_READY (Release).  APs load this after the Acquire on AP_LAUNCH_READY.
pub(crate) static PLATFORM_PTR: core::sync::atomic::AtomicPtr<platform::ThemisPlatform> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

// ── BSP entry point ──────────────────────────────────────────────────────── //

/// BSP entry point called by the Limine bootloader.
#[no_mangle]
#[cfg(target_arch = "x86_64")]
pub extern "C" fn _start() -> ! {
    // SAFETY: HEAP is only mutated here (once, BSP-only, before any AP runs).
    // We use addr_of_mut! to get a raw pointer without creating a Rust reference.
    unsafe {
        ALLOCATOR
            .lock()
            .init(core::ptr::addr_of_mut!(HEAP) as *mut u8, HEAP_SIZE);
    }

    // Store kernel phys/virt base so paging::ensure_table can correctly
    // translate kernel-space heap VAs to physical addresses.
    if let Some(r) = KERNEL_ADDR_REQUEST.get_response() {
        KERNEL_PHYS_BASE.store(r.physical_base(), Ordering::Relaxed);
        KERNEL_VIRT_BASE.store(r.virtual_base(), Ordering::Relaxed);
    }

    SerialPort::init();
    assert!(BASE_REVISION.is_supported(), "unsupported Limine revision");

    serial_println!();
    serial_println!("========================================");
    serial_println!("  Themis capavisor — Limine OK");
    serial_println!("========================================");
    serial_println!();

    // ── Attested boot: keygen + SHA-256 measurement ────────────────────────── //
    // Must happen before any domain exists.  The key pair is stored in a
    // static inside META (capavisor address space, never in any domain's EPT).
    // TPM probing is deferred to after ACPI parsing (need TPM2 table to
    // discover the device address portably).
    {
        // Get the raw ELF file bytes from Limine.  This is the pristine binary
        // as loaded from the boot medium — deterministic and excludes .bss.
        let elf_file = KERNEL_FILE_REQUEST
            .get_response()
            .expect("no ExecutableFileRequest response")
            .file();
        let elf_addr = elf_file.addr() as u64;
        let elf_size = elf_file.size();

        // Also get load addresses for logging.
        let (phys_base, virt_base) = if let Some(ka) = KERNEL_ADDR_REQUEST.get_response() {
            (ka.physical_base(), ka.virtual_base())
        } else {
            (0, 0)
        };

        serial_println!(
            "[attest] capavisor: phys={:#x} virt={:#x} elf_file={:#x} elf_size={:#x} ({} KiB)",
            phys_base,
            virt_base,
            elf_addr,
            elf_size,
            elf_size / 1024
        );
        attestation::init(elf_addr, elf_size);
    }

    // Unpack Limine responses.
    let hhdm_offset = HHDM_REQUEST
        .get_response()
        .expect("no HHDM response")
        .offset();
    let entries = MEMMAP_REQUEST
        .get_response()
        .expect("no memory map response")
        .entries();
    let rsdp_phys = RSDP_REQUEST
        .get_response()
        .expect("no RSDP response")
        .address() as u64;
    let mp = MP_REQUEST.get_response().expect("no MP response");
    let cpus = mp.cpus();
    let bsp_lapic_id = mp.bsp_lapic_id();

    // Log modules if present.
    if let Some(r) = MODULE_REQUEST.get_response() {
        serial_println!("Limine modules: {}", r.modules().len());
        for (i, m) in r.modules().iter().enumerate() {
            let info = guest::ModuleInfo::from_limine_file(m);
            serial_println!(
                "  [{}] {:?}  {:#x}  {} KiB",
                i,
                info.cmdline,
                info.base as usize,
                info.size / 1024
            );
        }
        serial_println!();
    }

    // ── Phase 1: Platform discovery ──────────────────────────────────────── //
    let platform = arch::boot::platform(entries, hhdm_offset, rsdp_phys, cpus, bsp_lapic_id);

    // ── TPM probe (after ACPI discovery) ─────────────────────────────────── //
    // The ACPI TPM2 table tells us if a TPM is present.  If so, map its MMIO
    // region (not in Limine's HHDM) and probe + extend PCR 11.
    if let Some(ref tpm_info) = platform.acpi.tpm {
        serial_println!(
            "[attest] ACPI TPM2 found (start_method={}, control_area={:#x})",
            tpm_info.start_method,
            tpm_info.control_area
        );
        attestation::try_tpm(tpm_info.start_method, tpm_info.control_area, hhdm_offset);
    } else {
        serial_println!("[attest] No ACPI TPM2 table — TPM not available");
    }

    // ── ThemisPlatform init: register dom0, hand it the full META pool ──────── //
    // Must happen before boot::vmx() so that VMXON pages can be allocated from
    // ThemisPlatform's MetaAllocator.
    let mut themis = arch::boot::init_themis(&platform);

    // ── Phase 2a–b: VMX feature detection + VMXON on BSP ─────────────────── //
    let mut vmx_state = arch::boot::vmx(&platform, &mut themis);

    // ── Phase 2c: Capability engine + EPT build ───────────────────────────── //
    // `themis` is consumed here; further access via `capa.platform`.
    let capa = arch::boot::capa(&platform, themis);

    // ── Phase 2c attestation: dump dom0 capability state ─────────────────── //
    {
        let report = capability_engine::attest::attest_domain(&capa.root_domain);
        serial_println!();
        serial_println!("=== dom0 attestation ===");
        serial_println!("{}", report.report);
        serial_println!("=== end attestation ===");
    }

    // ── Phase 2d: VMCS allocation + setup ────────────────────────────────── //
    // Vcpus are stored directly in the PlatformDomain (dom0).
    arch::boot::vmcs(&platform, &mut vmx_state, &capa);

    // ── Collect Limine modules for P7f ────────────────────────────────────── //
    let modules: alloc::vec::Vec<guest::ModuleInfo> = MODULE_REQUEST
        .get_response()
        .map(|r| {
            r.modules()
                .iter()
                .map(|m| guest::ModuleInfo::from_limine_file(m))
                .collect()
        })
        .unwrap_or_default();

    // ── Phase 7f: Linux kernel loading + boot_params ──────────────────────── //
    let linux = arch::boot::linux(&platform, &modules);

    // ── Phase 7g: VMLAUNCH ────────────────────────────────────────────────── //
    PLATFORM_PTR.store(&capa.platform as *const _ as *mut _, Ordering::Relaxed);

    // ── Initialise per-core scheduling state (CoreContext) ────────────────── //
    // Store dom0's CapabilityRef as the tree root anchor, then pre-populate
    // every core's CoreContext with (root_domain, vp=core_id).  This must
    // happen before AP_LAUNCH_READY so APs can read their CoreContext.
    capa.platform.set_dom0_cap(capa.root_domain.clone());
    let num_cores = cpus.len();
    for core_id in 0..num_cores {
        capa.platform
            .set_core_context(core_id, capa.root_domain.clone(), core_id as u32);
    }

    // Initialize dom0 VP run states to Running so that the capability engine's
    // find_vp_on_core() succeeds when dom0 calls SWITCH or SET_REGISTER.
    // Each dom0 VP maps 1:1 to a core (VP id == core id).
    {
        use capability_engine::VpRunState;
        let dom = capa.root_domain.read();
        for core_id in 0..num_cores {
            if let Some(vp) = dom.data.policy.vprocessor_states.get(core_id) {
                *vp.run_state.write() = VpRunState::Running {
                    core: core_id as capability_engine::CoreId,
                    caller: None,
                };
            }
        }
    }

    // ── Phase 7g: VMLAUNCH ────────────────────────────────────────────────── //
    // launch() returns a platform-agnostic Vp; the monitor loop runs here
    // (generic code), not inside arch::boot (fixes the layering).
    let mut vp = arch::boot::launch(&linux, &vmx_state, &capa.platform);
    monitor::monitor_loop(&mut vp);
}

// ── AArch64 Limine-based entry point (non-direct-boot) ──────────────────── //

#[no_mangle]
#[cfg(all(not(target_arch = "x86_64"), not(feature = "direct-boot")))]
pub extern "C" fn _start() -> ! {
    // Initialize PL011 UART first using identity-mapped physical address
    // (base revision 0 gives us identity map of first 4 GiB).
    SerialPort::init_physical();

    // Early heartbeat — confirms we reached _start.
    serial_println!("[early] _start reached");

    // SAFETY: HEAP is only mutated here (once, BSP-only, before any AP runs).
    unsafe {
        ALLOCATOR
            .lock()
            .init(core::ptr::addr_of_mut!(HEAP) as *mut u8, HEAP_SIZE);
    }

    serial_println!("[early] heap init done");

    assert!(BASE_REVISION.is_supported(), "unsupported Limine revision");

    serial_println!();
    serial_println!("========================================");
    serial_println!("  Themis capavisor — AArch64 / Limine OK");
    serial_println!("========================================");
    serial_println!();

    // ── Unpack Limine responses ──────────────────────────────────────────── //

    let hhdm_offset = HHDM_REQUEST
        .get_response()
        .expect("no HHDM response")
        .offset();
    serial_println!("HHDM offset: {:#x}", hhdm_offset);

    // Store kernel phys/virt base (needed by paging_aarch64 for virt→phys).
    if let Some(r) = KERNEL_ADDR_REQUEST.get_response() {
        KERNEL_PHYS_BASE.store(r.physical_base(), Ordering::Relaxed);
        KERNEL_VIRT_BASE.store(r.virtual_base(), Ordering::Relaxed);
        serial_println!(
            "Kernel: phys={:#x} virt={:#x}",
            r.physical_base(),
            r.virtual_base()
        );
    }

    let entries = MEMMAP_REQUEST
        .get_response()
        .expect("no memory map")
        .entries();

    let mp = MP_REQUEST.get_response().expect("no MP response");
    let cpus = mp.cpus();
    let bsp_mpidr = mp.bsp_mpidr();

    // ── Phase 1: Platform discovery ──────────────────────────────────────── //

    let info = arch::boot::platform(entries, hhdm_offset, cpus, bsp_mpidr);

    // ── Phase 2a: ThemisPlatform bootstrap ───────────────────────────────── //

    let _platform = arch::boot::init_themis(&info);

    // ── Allocator smoke test ─────────────────────────────────────────────── //

    let test_frame = _platform.alloc_meta_frame(0);
    serial_println!();
    serial_println!("META alloc smoke test: frame @ {:#x} ✓", test_frame);

    serial_println!();
    serial_println!("AArch64 M2 complete — platform initialized.");
    serial_println!("Next: M3 (EL2 + Stage-2), M4 (GICv3).");

    loop {
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}

// ── AArch64 direct-boot entry point (EL2, MMU off) ──────────────────────── //
//
// QEMU `-kernel` with `virtualization=on` enters at EL2 with:
//   X0 = FDT pointer, MMU off, caches enabled.
// The assembly stub zeroes BSS, sets up a stack, and calls _start_rust.

#[cfg(all(target_arch = "aarch64", feature = "direct-boot"))]
core::arch::global_asm!(
    r#"
    .section .text.entry, "ax"
    .global _start
    .type _start, @function
_start:
    // Save FDT pointer (X0) in a callee-saved register.
    mov     x19, x0

    // Zero BSS section.
    ldr     x1, =__bss_start
    ldr     x2, =__bss_end
1:
    cmp     x1, x2
    b.ge    2f
    stp     xzr, xzr, [x1], #16
    b       1b
2:
    // Set up initial stack (16-byte aligned, grows downward).
    ldr     x0, =__boot_stack_top
    mov     sp, x0

    // Pass FDT pointer as first argument to Rust.
    mov     x0, x19
    bl      _start_rust

    // Should not return — halt.
    b       .
    "#
);

/// Boot stack for direct-boot (allocated in BSS, zeroed by assembly stub).
#[cfg(all(target_arch = "aarch64", feature = "direct-boot"))]
#[repr(C, align(16))]
struct BootStack([u8; 64 * 1024]); // 64 KiB

#[cfg(all(target_arch = "aarch64", feature = "direct-boot"))]
#[no_mangle]
static mut BOOT_STACK: BootStack = BootStack([0; 64 * 1024]);

/// Symbol for the assembly stub to reference.
#[cfg(all(target_arch = "aarch64", feature = "direct-boot"))]
core::arch::global_asm!(
    r#"
    .global __boot_stack_top
    .set    __boot_stack_top, BOOT_STACK + 65536
    "#
);

/// Rust entry point for AArch64 direct-boot (called from assembly _start).
///
/// Runs at EL2 with MMU off, identity-mapped. `fdt_ptr` is the physical
/// address of the QEMU-provided FDT blob.
#[no_mangle]
#[cfg(all(target_arch = "aarch64", feature = "direct-boot"))]
pub extern "C" fn _start_rust(fdt_ptr: u64) -> ! {
    // PL011 is at 0x0900_0000 — accessible via identity mapping (MMU off).
    SerialPort::init_physical();

    serial_println!();
    serial_println!("========================================");
    serial_println!("  Themis capavisor — AArch64 direct-boot");
    serial_println!("========================================");
    serial_println!();

    // Read and display current exception level.
    let current_el: u64;
    unsafe {
        core::arch::asm!("mrs {}, CurrentEL", out(reg) current_el, options(nomem, nostack));
    }
    let el = (current_el >> 2) & 0x3;
    serial_println!("Running at EL{}", el);
    serial_println!("FDT pointer (X0): {:#x}", fdt_ptr);

    // QEMU places FDT at start of RAM (0x4000_0000) for `-kernel` boot.
    // If X0 is zero (trampoline clobber), scan known locations.
    let fdt_addr = if fdt_ptr != 0 {
        fdt_ptr
    } else {
        // QEMU virt places DTB at the start of RAM.
        const QEMU_RAM_BASE: u64 = 0x4000_0000;
        let magic = unsafe { *(QEMU_RAM_BASE as *const u32) };
        if magic == 0xd00d_feed_u32.to_be() {
            serial_println!("FDT found at RAM base ({:#x})", QEMU_RAM_BASE);
            QEMU_RAM_BASE
        } else {
            serial_println!("WARNING: no FDT found (magic at RAM base = {:#x})", magic);
            0
        }
    };

    // Initialize heap allocator.
    unsafe {
        ALLOCATOR
            .lock()
            .init(core::ptr::addr_of_mut!(HEAP) as *mut u8, HEAP_SIZE);
    }
    serial_println!("Heap initialized: {} KiB", HEAP_SIZE / 1024);

    // Parse FDT to discover hardware.
    let mut gicd_base: u64 = 0x0800_0000; // fallback (QEMU virt default)
    let mut gicr_base: u64 = 0x080A_0000;
    let mut fdt_ram_end: u64 = 0x8000_0000; // fallback: 1G
    let mut fdt_ram_base: u64 = 0x4000_0000; // fallback: QEMU virt default

    if fdt_addr != 0 {
        let fdt_slice = unsafe { core::slice::from_raw_parts(fdt_addr as *const u8, 0x10_0000) };
        match fdt::Fdt::new(fdt_slice) {
            Ok(fdt) => {
                serial_println!();
                serial_println!("FDT: model = {:?}", fdt.root().model());
                serial_println!("FDT: compatible = {:?}", fdt.root().compatible().first());

                // Memory regions
                let mem = fdt.memory();
                serial_println!("Memory regions:");
                for region in mem.regions() {
                    if let Some(size) = region.size {
                        let end = region.starting_address as u64 + size as u64;
                        serial_println!(
                            "  {:#x}..{:#x}  ({} MiB)",
                            region.starting_address as u64, end,
                            size / (1024 * 1024)
                        );
                        if end > fdt_ram_end {
                            fdt_ram_end = end;
                        }
                        let base = region.starting_address as u64;
                        if base < fdt_ram_base {
                            fdt_ram_base = base;
                        }
                    }
                }

                // CPUs
                let mut cpu_count = 0u32;
                for node in fdt.all_nodes() {
                    if node.name.starts_with("cpu@") {
                        cpu_count += 1;
                    }
                }
                serial_println!("CPUs: {}", cpu_count);

                // GIC — extract register addresses from FDT
                for node in fdt.all_nodes() {
                    if let Some(compat) = node.compatible() {
                        if compat.all().any(|c| c == "arm,gic-v3") {
                            serial_println!("GIC: {} ({})", node.name, compat.first());
                            // Parse "reg" property: GICD base+size, GICR base+size
                            if let Some(mut reg) = node.reg() {
                                if let Some(gicd_reg) = reg.next() {
                                    gicd_base = gicd_reg.starting_address as u64;
                                    serial_println!("  GICD: {:#x} (size {:#x})",
                                        gicd_base, gicd_reg.size.unwrap_or(0));
                                }
                                if let Some(gicr_reg) = reg.next() {
                                    gicr_base = gicr_reg.starting_address as u64;
                                    serial_println!("  GICR: {:#x} (size {:#x})",
                                        gicr_base, gicr_reg.size.unwrap_or(0));
                                }
                            }
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                serial_println!("FDT parse error: {:?}", e);
            }
        }
    }

    // ── Enable MMU at EL2 (identity-mapped) ────────────────────────────────── //

    unsafe { arch::aarch64::mmu::init_and_enable() };

    // ── Install exception vectors and configure EL2 sysregs ──────────────── //

    unsafe { arch::aarch64::vectors::install_vectors() };
    unsafe { arch::aarch64::el2_regs::configure_el2() };

    // ── Configure Stage-2 translation ───────────────────────────────────── //

    unsafe { arch::aarch64::stage2::configure_vtcr() };

    // ── Skip GIC init — let Linux guest own the physical GIC ─────────── //
    // (M4's gicv3::init_gicv3 is NOT called here so Linux can initialize
    //  GICD/GICR/ICC from scratch, which is the expected boot path.)

    // ── M5b: Boot Linux kernel ──────────────────────────────────────────── //

    serial_println!();
    serial_println!("=== M5b: Linux kernel boot ===");

    // Guest memory layout (identity-mapped via Stage-2):
    //   0x4000_0000..0x4010_0000  — QEMU FDT (hypervisor reads it, not mapped for guest)
    //   0x4010_0000..image_end    — Hypervisor code+BSS (NOT mapped in Stage-2)
    //   image_end+0x1000          — Boot descriptor blob (loaded by QEMU script)
    //   (kernel/initrd/fdt addresses come from boot descriptor — no hardcoded constants)
    //   0x0800_0000..0x0810_0000  — GIC (GICD + GICR, device memory)
    //   0x0900_0000..0x0900_1000  — PL011 UART (device memory)

    const GUEST_FDT_ALLOC: usize = 0x10_0000; // 1 MiB for FDT copy (QEMU pads to this)
    let guest_ram_end = fdt_ram_end;

    // __image_end is the 2M-aligned end of the capavisor image (BSS included).
    // The boot descriptor blob is loaded at the page right after it.
    extern "C" {
        static __image_end: u8;
    }
    let image_end = unsafe { &__image_end as *const u8 as u64 };
    let descriptor_addr = image_end + 0x1000; // 4K after image end

    // Guest RAM starts at the FDT-declared base (0x40000000 on QEMU virt).
    // We map the full range in Stage-2 even though the capavisor binary sits
    // at the low end — the capavisor runs at EL2 with its own Stage-1 tables,
    // so Stage-2 mappings only affect the guest (EL1). In the single-domain
    // dev model the guest is trusted; multi-domain will carve this properly.
    let guest_ram_start = fdt_ram_base;
    serial_println!("Hypervisor image ends at {:#x}", image_end);
    serial_println!("Boot descriptor expected at {:#x}", descriptor_addr);
    serial_println!("Guest RAM starts at {:#x}", guest_ram_start);

    // ── Parse boot descriptor to discover modules ────────────────────────── //
    use crate::guest::{find_module, ModuleInfo};

    let (modules, module_count) = unsafe {
        arch::aarch64::boot_descriptor::parse_descriptor::<8>(descriptor_addr as *const u8)
    }.unwrap_or_else(|e| {
        serial_println!("WARNING: {}", e);
        serial_println!("Hint: use 'cargo fetch-aarch64-kernel && cargo aarch64-direct'");
        serial_println!();
        serial_println!("AArch64 — no boot descriptor, halting.");
        loop { unsafe { core::arch::asm!("wfi", options(nomem, nostack)) }; }
    });

    serial_println!("Boot descriptor: {} module(s)", module_count);
    for i in 0..module_count {
        serial_println!("  [{}] {:?} at {:#x} ({} KiB)",
            i, modules[i].cmdline, modules[i].base as u64,
            modules[i].size / 1024);
    }

    let modules_slice = &modules[..module_count];

    // Locate kernel and optional initrd from the descriptor.
    let kernel_mod = find_module(modules_slice, "dom0-kernel")
        .expect("boot descriptor: 'dom0-kernel' module not found");
    let initrd_mod = find_module(modules_slice, "dom0-initrd");

    // Find the guest FDT address from the descriptor (or use a default after initrd/kernel).
    let guest_fdt_mod = find_module(modules_slice, "guest-fdt");
    let guest_fdt_addr = if let Some(fdt_mod) = guest_fdt_mod {
        fdt_mod.base as u64
    } else {
        // Place FDT copy 1M after the last module.
        let mut last_end = kernel_mod.base as u64 + kernel_mod.size;
        if let Some(initrd) = initrd_mod {
            let initrd_end = initrd.base as u64 + initrd.size;
            if initrd_end > last_end {
                last_end = initrd_end;
            }
        }
        // Align to 2M boundary and add 2M margin.
        ((last_end + 0x20_0000 - 1) & !0x1F_FFFF) + 0x20_0000
    };

    // Guest initial stack: 1M after FDT.
    let guest_stack_top = guest_fdt_addr + GUEST_FDT_ALLOC as u64;

    {
        use crate::arch_traits::types::{MapPermissions, PageSize};

        let mut map = arch::aarch64::stage2::Stage2Map::new();
        let rwx = MapPermissions { read: true, write: true, execute: true };

        // Map guest RAM using the largest block size possible.
        // Use 1G blocks where aligned, fall back to 2M for remainders.
        let mut addr = guest_ram_start;
        while addr < guest_ram_end {
            if addr % 0x4000_0000 == 0 && addr + 0x4000_0000 <= guest_ram_end {
                map.map(addr, addr, PageSize::Page1G, &rwx);
                addr += 0x4000_0000;
            } else {
                map.map(addr, addr, PageSize::Page2M, &rwx);
                addr += 0x20_0000;
            }
        }
        serial_println!(
            "Stage-2: mapped guest RAM {:#x}..{:#x} ({} MiB)",
            guest_ram_start, guest_ram_end,
            (guest_ram_end - guest_ram_start) / (1024 * 1024)
        );

        // Map device MMIO regions (identity-mapped, device memory).
        // 0x0800_0000..0x0A00_0000: GIC (GICD/GICR) + UART (PL011)
        addr = 0x0800_0000;
        while addr < 0x0A00_0000 {
            map.map_device(addr, addr, PageSize::Page2M);
            addr += 0x20_0000;
        }
        // 0x0A00_0000..0x0A20_0000: virtio-mmio, GPIO, RTC, etc.
        map.map_device(0x0A00_0000, 0x0A00_0000, PageSize::Page2M);

        // 0x1000_0000..0x4000_0000: PCIe MMIO low (768 MiB, 2M blocks)
        addr = 0x1000_0000;
        while addr < 0x4000_0000 {
            map.map_device(addr, addr, PageSize::Page2M);
            addr += 0x20_0000;
        }

        serial_println!("Stage-2: mapped device regions (GIC/UART/virtio/PCIe-low)");

        // PCIe ECAM: 0x40_1000_0000..0x40_2000_0000 (256 MiB, above 4 GiB).
        addr = 0x40_1000_0000;
        while addr < 0x40_2000_0000 {
            map.map_device(addr, addr, PageSize::Page2M);
            addr += 0x20_0000;
        }
        serial_println!("Stage-2: mapped PCIe ECAM 0x4010000000..0x4020000000 (device)");

        // PCIe high MMIO: 0x80_0000_0000..0x100_0000_0000 (512 GiB, 1G device blocks).
        addr = 0x80_0000_0000;
        while addr < 0x100_0000_0000 {
            map.map_device(addr, addr, PageSize::Page1G);
            addr += 0x4000_0000;
        }
        serial_println!("Stage-2: mapped PCIe high MMIO 0x8000000000..0x10000000000 (device)");

        // Load the Stage-2 map and flush TLB.
        unsafe { arch::aarch64::stage2::load_vttbr(&map, 1) };
        map.flush();
        serial_println!("VTTBR_EL2 loaded (VMID=1), TLB flushed");

        // Don't drop — guest will use this map.
        core::mem::forget(map);
    }

    // Copy QEMU's FDT to guest-visible memory.
    if fdt_addr != 0 {
        let fdt_total_size = unsafe {
            u32::from_be(*(fdt_addr as *const u32).add(1)) as usize
        };
        serial_println!("Copying FDT ({} bytes) from {:#x} to {:#x}",
            fdt_total_size, fdt_addr, guest_fdt_addr);
        unsafe {
            core::ptr::copy_nonoverlapping(
                fdt_addr as *const u8,
                guest_fdt_addr as *mut u8,
                fdt_total_size,
            );
        }

        // Patch FDT /chosen with initrd range if an initrd module was provided.
        if let Some(initrd) = initrd_mod {
            let initrd_start = initrd.base as u64;
            let initrd_end = initrd_start + initrd.size;
            serial_println!("Initrd: {:#x}..{:#x} ({} KiB)",
                initrd_start, initrd_end, initrd.size / 1024);

            let patch_result = arch::aarch64::fdt_patch::patch_chosen_initrd(
                guest_fdt_addr as *mut u8,
                GUEST_FDT_ALLOC,
                initrd_start,
                initrd_end,
            );
            match patch_result {
                Ok(()) => { serial_println!("FDT patched: /chosen with initrd range"); }
                Err(e) => { serial_println!("WARNING: FDT patch failed: {}", e); }
            }
        }
    }

    // Validate Linux ARM64 Image magic at the kernel module address.
    let kernel_addr = kernel_mod.base as u64;
    let image_magic = unsafe { *((kernel_addr + 0x38) as *const u32) };
    if image_magic != 0x644D_5241 { // "ARM\x64" in little-endian
        serial_println!(
            "ERROR: No ARM64 Image magic at {:#x} (got {:#x})",
            kernel_addr, image_magic
        );
        serial_println!("The dom0-kernel module does not appear to be a valid ARM64 Image.");
        loop { unsafe { core::arch::asm!("wfi", options(nomem, nostack)) }; }
    }

    let text_offset = unsafe { *((kernel_addr + 0x08) as *const u64) };
    let entry = kernel_addr + text_offset;
    serial_println!(
        "Linux Image at {:#x} (text_offset={:#x}, entry={:#x})",
        kernel_addr, text_offset, entry
    );

    // Configure HCR_EL2 for guest: VM=1, direct-assignment (no IMO/FMO/AMO).
    unsafe { arch::aarch64::el2_regs::configure_el2_for_guest() };

    serial_println!("Entering Linux at {:#x} (X0=FDT@{:#x}, SP={:#x})",
        entry, guest_fdt_addr, guest_stack_top);
    serial_println!();

    // ERET into Linux — does not return.
    unsafe {
        arch::aarch64::vcpu::enter_guest_initial(entry, guest_stack_top, guest_fdt_addr);
    }
}

// ── AP entry point ───────────────────────────────────────────────────────── //

/// Application processor entry point — called by Limine for each AP.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe extern "C" fn ap_entry(cpu: &limine::mp::Cpu) -> ! {
    while SERIAL_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    serial_println!("  AP {} (LAPIC {}) ready", cpu.id, cpu.lapic_id);
    SERIAL_LOCK.store(false, Ordering::Release);

    AP_READY_COUNT.fetch_add(1, Ordering::Release);

    // ── Spin until BSP sets AP_LAUNCH_READY ──────────────────────────────── //
    while !AP_LAUNCH_READY.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }

    let id = cpu.id as usize;

    // Take the InactiveVcpu from PlatformDomain (dom0, vp_id = id).
    let platform_ptr = PLATFORM_PTR.load(Ordering::Relaxed);
    assert!(!platform_ptr.is_null(), "AP{}: PLATFORM_PTR is null", id);
    let platform = unsafe { &*platform_ptr };

    let vmxon_phys = platform.vmxon_phys(id);

    // Enable VMX on this AP.
    crate::vmx::enable_vmx_on_core(vmxon_phys).expect("AP VMXON failed");

    // Set XCR0 to full feature set before VMLAUNCH.
    {
        let cr4 = x86::controlregs::cr4();
        x86::controlregs::cr4_write(cr4 | x86::controlregs::Cr4::CR4_ENABLE_OS_XSAVE);

        let cpuid_d = core::arch::x86_64::__cpuid_count(0xD, 0);
        let max_xcr0 = (((cpuid_d.edx as u64) << 32) | (cpuid_d.eax as u64)) | 1;
        core::arch::asm!(
            "xsetbv",
            in("ecx") 0u32,
            in("eax") max_xcr0 as u32,
            in("edx") (max_xcr0 >> 32) as u32,
            options(nomem, nostack),
        );
    }

    let inactive = platform
        .take_vcpu(0, id)
        .unwrap_or_else(|| panic!("AP{}: no InactiveVcpu in PlatformDomain", id));

    let active = inactive.activate().expect("AP activate failed");

    // Wrap in platform-agnostic Vp and enter the generic monitor loop.
    let arch = crate::arch::x86_64::x86_platform::X86Platform::new(platform as *const _);
    let mut vp = crate::arch_traits::types::Vp::new(arch, active);
    monitor::monitor_loop(&mut vp);
}

// ── Panic handler ────────────────────────────────────────────────────────── //

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("!!! PANIC: {}", info);
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("cli; hlt", options(nomem, nostack));
        }
        #[cfg(not(target_arch = "x86_64"))]
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack));
        }
    }
}
