//! PL011 UART driver for AArch64 (QEMU `virt` machine).
//!
//! The QEMU `virt` machine exposes a PL011 at MMIO base 0x0900_0000.
//! This is a minimal polled-mode driver: no interrupts, no FIFOs,
//! just write-and-wait. Sufficient for boot-time serial console.

use core::fmt;

/// QEMU `virt` PL011 MMIO base address.
const PL011_BASE: usize = 0x0900_0000;

// PL011 register offsets.
const UARTDR: usize = 0x000; // Data register
const UARTFR: usize = 0x018; // Flag register
const UARTIBRD: usize = 0x024; // Integer baud rate divisor
const UARTFBRD: usize = 0x028; // Fractional baud rate divisor
const UARTLCR_H: usize = 0x02C; // Line control register
const UARTCR: usize = 0x030; // Control register
const UARTIMSC: usize = 0x038; // Interrupt mask set/clear

// Flag register bits.
const FR_TXFF: u32 = 1 << 5; // TX FIFO full

/// Effective base address (may be offset by HHDM at runtime).
/// At Limine entry time, HHDM maps all physical memory at a fixed VA offset.
/// We start with the raw physical address; `init()` patches it if needed.
static mut UART_BASE: usize = PL011_BASE;

/// Initialize the PL011 UART.
///
/// With base revision ≤1, Limine identity-maps the first 4 GiB so we can
/// access the UART at its physical address directly. With base revision 3,
/// device MMIO is NOT in the HHDM and we'd need our own page table mapping.
/// For M1 bringup we use revision 1 + physical address.
pub fn init_physical() {
    unsafe {
        UART_BASE = PL011_BASE;
    }

    let b = PL011_BASE as *mut u32;
    unsafe {
        // Disable UART while configuring.
        b.byte_add(UARTCR).write_volatile(0);

        // Clear all interrupts.
        b.byte_add(UARTIMSC).write_volatile(0);

        // Baud rate: 115200 with 24 MHz reference clock (QEMU default).
        // Divider = 24_000_000 / (16 * 115200) = 13.0208...
        // IBRD = 13, FBRD = round(0.0208 * 64) = 1
        b.byte_add(UARTIBRD).write_volatile(13);
        b.byte_add(UARTFBRD).write_volatile(1);

        // 8 data bits, no parity, 1 stop bit, enable FIFOs.
        b.byte_add(UARTLCR_H).write_volatile((0b11 << 5) | (1 << 4)); // WLEN=8, FEN=1

        // Enable UART, TX, RX.
        b.byte_add(UARTCR).write_volatile((1 << 0) | (1 << 8) | (1 << 9)); // UARTEN | TXE | RXE
    }
}

/// Initialize using HHDM-mapped address (for base revision 3+, future use).
#[allow(dead_code)]
pub fn init(hhdm_offset: u64) {
    let base = PL011_BASE as u64 + hhdm_offset;
    unsafe {
        UART_BASE = base as usize;
    }
    // Same register init as init_physical(), but through HHDM VA.
    let b = base as *mut u32;
    unsafe {
        b.byte_add(UARTCR).write_volatile(0);
        b.byte_add(UARTIMSC).write_volatile(0);
        b.byte_add(UARTIBRD).write_volatile(13);
        b.byte_add(UARTFBRD).write_volatile(1);
        b.byte_add(UARTLCR_H).write_volatile((0b11 << 5) | (1 << 4));
        b.byte_add(UARTCR).write_volatile((1 << 0) | (1 << 8) | (1 << 9));
    }
}

/// Write a single byte, blocking until the TX FIFO has space.
pub fn putc(byte: u8) {
    let base = unsafe { UART_BASE } as *mut u32;
    unsafe {
        // Wait for TX FIFO not full.
        while base.byte_add(UARTFR).read_volatile() & FR_TXFF != 0 {
            core::hint::spin_loop();
        }
        base.byte_add(UARTDR).write_volatile(byte as u32);
    }
}

/// fmt::Write adapter for use by the serial_println! macro.
pub struct Pl011Writer;

impl fmt::Write for Pl011Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            putc(b);
        }
        Ok(())
    }
}
