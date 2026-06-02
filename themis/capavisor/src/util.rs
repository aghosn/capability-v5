//! Small arch-neutral helpers shared across the capavisor.

extern crate alloc;

/// Format a byte count as a human-readable string ("X MiB" if ≥1 MiB,
/// otherwise "X KiB"). Truncating integer division — for log lines.
pub fn fmt_kib(bytes: u64) -> alloc::string::String {
    if bytes >= 1024 * 1024 {
        alloc::format!("{} MiB", bytes / (1024 * 1024))
    } else {
        alloc::format!("{} KiB", bytes / 1024)
    }
}
