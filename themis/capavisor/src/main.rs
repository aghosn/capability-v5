#![no_std]
#![no_main]
// Enable heap-allocated types (Vec, Box, BTreeMap, …) via the global allocator
// declared below.  The allocator is backed by a static BSS array (`HEAP`) that
// Limine places and maps as part of the kernel binary — no runtime carving
// of physical memory is required.
extern crate alloc;

use core::fmt;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use limine::request::{ExecutableAddressRequest, ExecutableFileRequest, HhdmRequest, MemoryMapRequest, ModuleRequest, MpRequest, RsdpRequest};
use limine::BaseRevision;
use linked_list_allocator::LockedHeap;

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

mod acpi;
mod attestation;
mod boot;
mod domain;
mod gdt;
mod guest;
mod hypercall;
mod iommu_ir;
mod mem;
mod msr_virt;
mod pci;
mod platform;
mod vmcs;
mod vmexit;
mod vmx {
    pub use ::vmx::features::*;
}
pub mod vcpu {
    pub use ::vmx::vcpu::*;
}

// ── Serial console (COM1, 0x3F8) ────────────────────────────────────────── //

pub struct SerialPort;

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

// ── Limine protocol requests ─────────────────────────────────────────────── //

#[used] static BASE_REVISION:       BaseRevision            = BaseRevision::new();
#[used] static MEMMAP_REQUEST:      MemoryMapRequest        = MemoryMapRequest::new();
#[used] static HHDM_REQUEST:        HhdmRequest             = HhdmRequest::new();
#[used] static RSDP_REQUEST:        RsdpRequest             = RsdpRequest::new();
#[used] static MP_REQUEST:          MpRequest               = MpRequest::new();
#[used] static MODULE_REQUEST:      ModuleRequest           = ModuleRequest::new();
#[used] static KERNEL_ADDR_REQUEST: ExecutableAddressRequest = ExecutableAddressRequest::new();
#[used] static KERNEL_FILE_REQUEST: ExecutableFileRequest    = ExecutableFileRequest::new();

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
pub extern "C" fn _start() -> ! {
    // SAFETY: HEAP is only mutated here (once, BSP-only, before any AP runs).
    // We use addr_of_mut! to get a raw pointer without creating a Rust reference.
    unsafe { ALLOCATOR.lock().init(core::ptr::addr_of_mut!(HEAP) as *mut u8, HEAP_SIZE); }

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
        let elf_file = KERNEL_FILE_REQUEST.get_response()
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

        serial_println!("[attest] capavisor: phys={:#x} virt={:#x} elf_file={:#x} elf_size={:#x} ({} KiB)",
            phys_base, virt_base, elf_addr, elf_size, elf_size / 1024);
        attestation::init(elf_addr, elf_size);
    }

    // Unpack Limine responses.
    let hhdm_offset = HHDM_REQUEST.get_response()
        .expect("no HHDM response").offset();
    let entries = MEMMAP_REQUEST.get_response()
        .expect("no memory map response").entries();
    let rsdp_phys = RSDP_REQUEST.get_response()
        .expect("no RSDP response").address() as u64;
    let mp = MP_REQUEST.get_response()
        .expect("no MP response");
    let cpus = mp.cpus();
    let bsp_lapic_id = mp.bsp_lapic_id();

    // Log modules if present.
    if let Some(r) = MODULE_REQUEST.get_response() {
        serial_println!("Limine modules: {}", r.modules().len());
        for (i, m) in r.modules().iter().enumerate() {
            let info = guest::ModuleInfo::from_limine_file(m);
            serial_println!("  [{}] {:?}  {:#x}  {} KiB",
                i, info.cmdline, info.base as usize, info.size / 1024);
        }
        serial_println!();
    }

    // ── Phase 1: Platform discovery ──────────────────────────────────────── //
    let platform = boot::platform(entries, hhdm_offset, rsdp_phys, cpus, bsp_lapic_id);

    // ── TPM probe (after ACPI discovery) ─────────────────────────────────── //
    // The ACPI TPM2 table tells us if a TPM is present.  If so, map its MMIO
    // region (not in Limine's HHDM) and probe + extend PCR 11.
    if let Some(ref tpm_info) = platform.acpi.tpm {
        serial_println!("[attest] ACPI TPM2 found (start_method={}, control_area={:#x})",
            tpm_info.start_method, tpm_info.control_area);
        attestation::try_tpm(tpm_info.start_method, tpm_info.control_area, hhdm_offset);
    } else {
        serial_println!("[attest] No ACPI TPM2 table — TPM not available");
    }

    // ── ThemisPlatform init: register dom0, hand it the full META pool ──────── //
    // Must happen before boot::vmx() so that VMXON pages can be allocated from
    // ThemisPlatform's MetaAllocator.
    let mut themis = boot::init_themis(&platform);

    // ── Phase 2a–b: VMX feature detection + VMXON on BSP ─────────────────── //
    let mut vmx_state = boot::vmx(&platform, &mut themis);

    // ── Phase 2c: Capability engine + EPT build ───────────────────────────── //
    // `themis` is consumed here; further access via `capa.platform`.
    let capa = boot::capa(&platform, themis);

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
    boot::vmcs(&platform, &mut vmx_state, &capa);

    // ── Collect Limine modules for P7f ────────────────────────────────────── //
    let modules: alloc::vec::Vec<guest::ModuleInfo> = MODULE_REQUEST
        .get_response()
        .map(|r| r.modules().iter().map(|m| guest::ModuleInfo::from_limine_file(m)).collect())
        .unwrap_or_default();

    // ── Phase 7f: Linux kernel loading + boot_params ──────────────────────── //
    let linux = boot::linux(&platform, &modules);

    // ── Phase 7g: VMLAUNCH ────────────────────────────────────────────────── //
    PLATFORM_PTR.store(&capa.platform as *const _ as *mut _, Ordering::Relaxed);

    // ── Initialise per-core scheduling state (CoreContext) ────────────────── //
    // Store dom0's CapabilityRef as the tree root anchor, then pre-populate
    // every core's CoreContext with (root_domain, vp=core_id).  This must
    // happen before AP_LAUNCH_READY so APs can read their CoreContext.
    capa.platform.set_dom0_cap(capa.root_domain.clone());
    let num_cores = cpus.len();
    for core_id in 0..num_cores {
        capa.platform.set_core_context(core_id, capa.root_domain.clone(), core_id as u32);
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

    boot::launch(&linux, &vmx_state, &capa.platform);
}

// ── AP entry point ───────────────────────────────────────────────────────── //

/// Application processor entry point — called by Limine for each AP.
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
    crate::vmx::enable_vmx_on_core(vmxon_phys)
        .expect("AP VMXON failed");

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

    let inactive = platform.take_vcpu(0, id)
        .unwrap_or_else(|| panic!("AP{}: no InactiveVcpu in PlatformDomain", id));

    let mut active = inactive.activate().expect("AP activate failed");

    // Enter the monitor loop — never returns.
    vmexit::monitor_loop(&mut active);
}

// ── Panic handler ────────────────────────────────────────────────────────── //

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("!!! PANIC: {}", info);
    loop {
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}

