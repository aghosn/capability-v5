#![no_std]
#![no_main]
// Enable heap-allocated types (Vec, Box, BTreeMap, …) via the global allocator
// declared below.  The allocator is *empty* at this stage; it is initialised
// during Phase 1 boot once we have carved out a heap region from the Limine
// memory map.
extern crate alloc;

use core::fmt;
use core::panic::PanicInfo;

use limine::request::{HhdmRequest, MemoryMapRequest, ModuleRequest, MpRequest, RsdpRequest};
use limine::BaseRevision;
use linked_list_allocator::LockedHeap;

mod guest;

// ── Serial console (COM1, 0x3F8) ────────────────────────────────────────── //

struct SerialPort;

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
                // Spin until the transmit holding register is empty (bit 5 of LSR).
                while (x86::io::inb(0x3F8 + 5) & 0x20) == 0 {}
                x86::io::outb(0x3F8, b);
            }
        }
        Ok(())
    }
}

/// Print to the serial console (COM1).
macro_rules! serial_print {
    ($($arg:tt)*) => { let _ = core::fmt::write(&mut SerialPort, format_args!($($arg)*)); };
}

macro_rules! serial_println {
    ()            => { serial_print!("\n") };
    ($($arg:tt)*) => { serial_print!("{}\n", format_args!($($arg)*)) };
}

// ── Limine protocol requests ─────────────────────────────────────────────── //

/// Limine protocol revision this kernel targets.  Limine will refuse to boot
/// us if it only supports an older revision.
#[used]
static BASE_REVISION: BaseRevision = BaseRevision::new();

/// Ask Limine for the physical memory map (E820-unified).
#[used]
static MEMMAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

/// Ask Limine for the Higher-Half Direct Map offset (phys + HHDM = virt).
#[used]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

/// Ask Limine for the RSDP physical address (entry point to ACPI tables).
#[used]
static RSDP_REQUEST: RsdpRequest = RsdpRequest::new();

/// Ask Limine to boot all application processors and give us their LAPIC IDs.
#[used]
static MP_REQUEST: MpRequest = MpRequest::new();

/// Ask Limine for any modules declared in limine.conf (dom0 kernel, initrd, …).
#[used]
static MODULE_REQUEST: ModuleRequest = ModuleRequest::new();

// ── Global heap allocator ────────────────────────────────────────────────── //

/// Initialised with an empty heap during Phase 1 boot.
/// Until `init_heap()` is called all `alloc` operations will panic.
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

// ── Entry point ─────────────────────────────────────────────────────────── //

/// BSP entry point called by the Limine bootloader.
///
/// At this point:
/// - The CPU is in 64-bit long mode, paging enabled.
/// - A temporary stack is set up by Limine.
/// - Physical memory is identity-mapped via the HHDM.
/// - No allocator, no serial, no ACPI yet — those are Phase 1.
#[no_mangle]
pub extern "C" fn _start() -> ! {
    SerialPort::init();

    // Verify the bootloader honours our requested revision.
    assert!(BASE_REVISION.is_supported(), "unsupported Limine revision");

    serial_println!();
    serial_println!("========================================");
    serial_println!("  Themis capavisor reached — Limine OK");
    serial_println!("========================================");
    serial_println!();

    // ── Module discovery ──────────────────────────────────────────────── //

    if let Some(response) = MODULE_REQUEST.get_response() {
        let files = response.modules();
        serial_println!("Limine modules: {} loaded", files.len());
        let mut kernel_found = false;
        for (i, file) in files.iter().enumerate() {
            let info = guest::ModuleInfo::from_limine_file(file);
            serial_println!(
                "  [{}] cmdline={:?}  path={:?}  base={:#x}  size={} ({} KiB)",
                i,
                info.cmdline,
                info.path,
                info.base as usize,
                info.size,
                info.size / 1024,
            );
            if info.cmdline == "dom0-kernel" {
                serial_println!("  → dom0 kernel found at {:#x} ({} KiB)", info.base as usize, info.size / 1024);
                kernel_found = true;

                match guest::linux::BootHeader::from_module(&info) {
                    Ok(hdr) => {
                        serial_println!();
                        serial_println!("  Linux boot header (protocol v{}.{:02}):",
                            hdr.version >> 8, hdr.version & 0xff);
                        serial_println!("    pref_address      = {:#x}", hdr.pref_address);
                        serial_println!("    kernel_alignment  = {:#x}", hdr.kernel_alignment);
                        serial_println!("    init_size         = {:#x} ({} KiB)", hdr.init_size, hdr.init_size / 1024);
                        serial_println!("    payload_offset    = {:#x} (file offset {:#x})",
                            hdr.payload_offset, hdr.payload_file_offset());
                        serial_println!("    payload_length    = {:#x} ({} KiB)",
                            hdr.payload_length, hdr.payload_length / 1024);
                        serial_println!("    code32_start      = {:#x}", hdr.code32_start);
                        serial_println!("    relocatable       = {}", hdr.relocatable);
                        serial_println!("    64-bit capable    = {}", hdr.is_64bit());
                        serial_println!("    can load above 4G = {}", hdr.can_load_above_4g());
                        serial_println!("    cmdline_size      = {}", hdr.cmdline_size);
                    }
                    Err(e) => {
                        serial_println!("  ⚠ failed to parse Linux boot header: {:?}", e);
                    }
                }
            }
        }
        if !kernel_found {
            serial_println!("  → dom0-kernel module not found (ISO-only boot?)");
        }
    } else {
        serial_println!("No module response from Limine (no modules declared in limine.conf).");
    }

    serial_println!();

    // TODO Phase 1: parse memory map, initialise heap, ACPI, PCI.
    // TODO Phase 2: VT-x VMXON, VMCS setup.

    serial_println!("Halting (Phase 1 not implemented yet).");

    loop {
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    }
}

// ── AP entry point ───────────────────────────────────────────────────────── //

/// Application processor entry point — called by Limine for each AP.
///
/// Limine boots each AP and calls this function with a pointer to the
/// `limine::smp::CpuInfo` describing the core.  At this stage the function
/// just parks the AP; Phase 1 will set up a proper mailbox.
pub extern "C" fn ap_entry(_cpu: *const limine::mp::Cpu) -> ! {
    loop {
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
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
