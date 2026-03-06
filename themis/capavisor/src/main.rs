#![no_std]
#![no_main]
#![feature(naked_functions)]
// Enable heap-allocated types (Vec, Box, BTreeMap, …) via the global allocator
// declared below.  The allocator is *empty* at this stage; it is initialised
// during Phase 1 boot once we have carved out a heap region from the Limine
// memory map.
extern crate alloc;

use core::fmt;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use limine::request::{HhdmRequest, MemoryMapRequest, ModuleRequest, MpRequest, RsdpRequest};
use limine::BaseRevision;
use linked_list_allocator::LockedHeap;

mod acpi;
mod boot;
mod domain;
mod guest;
mod mem;
mod pci;
mod platform;
mod vmcs;
mod vmexit;
mod vmx;

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

// ── Limine protocol requests ─────────────────────────────────────────────── //

#[used] static BASE_REVISION:   BaseRevision       = BaseRevision::new();
#[used] static MEMMAP_REQUEST:  MemoryMapRequest   = MemoryMapRequest::new();
#[used] static HHDM_REQUEST:    HhdmRequest        = HhdmRequest::new();
#[used] static RSDP_REQUEST:    RsdpRequest        = RsdpRequest::new();
#[used] static MP_REQUEST:      MpRequest          = MpRequest::new();
#[used] static MODULE_REQUEST:  ModuleRequest      = ModuleRequest::new();

// ── Global heap allocator ────────────────────────────────────────────────── //

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

// ── SMP barrier ─────────────────────────────────────────────────────────── //

/// Number of APs that have signalled readiness to the BSP.
pub(crate) static AP_READY_COUNT: AtomicU64 = AtomicU64::new(0);
/// Spinlock for serializing AP serial output.
pub(crate) static SERIAL_LOCK: AtomicBool = AtomicBool::new(false);

// ── BSP entry point ──────────────────────────────────────────────────────── //

/// BSP entry point called by the Limine bootloader.
#[no_mangle]
pub extern "C" fn _start() -> ! {
    SerialPort::init();
    assert!(BASE_REVISION.is_supported(), "unsupported Limine revision");

    serial_println!();
    serial_println!("========================================");
    serial_println!("  Themis capavisor — Limine OK");
    serial_println!("========================================");
    serial_println!();

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

    // ── ThemisPlatform init: register dom0, hand it the full META pool ──────── //
    // Must happen before boot::vmx() so that VMXON pages can be allocated from
    // ThemisPlatform's MetaAllocator.
    let themis = boot::init_themis(&platform);

    // ── Phase 2a–b: VMX feature detection + VMXON on BSP ─────────────────── //
    let mut vmx_state = boot::vmx(&platform, &themis);

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
    let _vmcs = boot::vmcs(&platform, &mut vmx_state, &capa);

    // ── Collect Limine modules for P7f ────────────────────────────────────── //
    let modules: alloc::vec::Vec<guest::ModuleInfo> = MODULE_REQUEST
        .get_response()
        .map(|r| r.modules().iter().map(|m| guest::ModuleInfo::from_limine_file(m)).collect())
        .unwrap_or_default();

    // ── Phase 7f: Linux kernel loading + boot_params ──────────────────────── //
    let linux = boot::linux(&platform, &modules);

    // ── Phase 7g: VMLAUNCH ────────────────────────────────────────────────── //
    serial_println!();
    serial_println!("Halting — VMLAUNCH (P7g) not yet implemented.");
    serial_println!(
        "(kernel_entry={:#x} boot_params={:#x})",
        linux.kernel_entry_phys, linux.boot_params_phys,
    );
    loop {
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    }
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

    loop {
        core::arch::asm!("hlt", options(nomem, nostack));
    }
}

// ── Panic handler ────────────────────────────────────────────────────────── //

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("!!! PANIC: {}", info);
    loop {
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}

