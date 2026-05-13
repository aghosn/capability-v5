//! 16550 UART serial driver on COM1 (port 0x3F8).

use core::fmt;

const COM1: u16 = 0x3F8;

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags));
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nostack, preserves_flags));
    val
}

/// Initialise COM1 at 115200 baud, 8N1.
pub fn init() {
    unsafe {
        outb(COM1 + 1, 0x00); // Disable interrupts
        outb(COM1 + 3, 0x80); // Enable DLAB
        outb(COM1 + 0, 0x01); // Divisor = 1 → 115200 baud
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x03); // 8 bits, no parity, 1 stop
        outb(COM1 + 2, 0xC7); // Enable FIFO, clear, 14-byte threshold
        outb(COM1 + 4, 0x03); // RTS/DSR set
    }
}

fn write_byte(b: u8) {
    unsafe {
        // Wait for transmit holding register empty.
        while (inb(COM1 + 5) & 0x20) == 0 {
            core::hint::spin_loop();
        }
        outb(COM1, b);
    }
}

pub struct SerialWriter;

impl fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            write_byte(b);
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        let _ = core::fmt::Write::write_fmt(
            &mut $crate::serial::SerialWriter,
            format_args!($($arg)*),
        );
    };
}

#[macro_export]
macro_rules! println {
    ()            => { $crate::print!("\n") };
    ($($arg:tt)*) => { $crate::print!("{}\n", format_args!($($arg)*)) };
}
