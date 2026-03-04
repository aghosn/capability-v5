#![no_std]
#![no_main]
// Enable heap-allocated types (Vec, Box, BTreeMap, …) via the global allocator
// declared below.  The allocator is *empty* at this stage; it is initialised
// during Phase 1 boot once we have carved out a heap region from the Limine
// memory map.
extern crate alloc;

use core::panic::PanicInfo;

use limine::request::{HhdmRequest, MemoryMapRequest, MpRequest, RsdpRequest};
use limine::BaseRevision;
use linked_list_allocator::LockedHeap;

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
    // Verify the bootloader honours our requested revision.
    assert!(BASE_REVISION.is_supported(), "unsupported Limine revision");

    // TODO Phase 1: parse memory map, initialise heap, serial console, ACPI, PCI.
    // TODO Phase 2: VT-x VMXON, VMCS setup.

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
fn panic(_info: &PanicInfo) -> ! {
    // TODO Phase 1: print panic info to serial before halting.
    loop {
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}
