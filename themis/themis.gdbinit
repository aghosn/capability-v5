# .gdbinit — Themis capavisor debug session
#
# Loaded automatically by scripts/debug.sh after `target remote :1234`.
# Place this file in the workspace root so `gdb -x themis.gdbinit` finds it.

# Show disassembly for each step (handy for bare-metal assembly bringup)
set disassemble-next-line on

# Suppress "this file uses .gdbinit" prompts in nested sessions
set auto-load safe-path /

# ── Symbol file ─────────────────────────────────────────────────────────── #
# The ELF was linked with a higher-half VMA (0xffffffff80000000) baked in,
# so we just load it and GDB uses the ELF section VMAs as-is.
add-symbol-file target/x86_64-unknown-none/debug/capavisor

# ── Useful breakpoints ────────────────────────────────────────────────────── #
# Uncomment to break at the BSP entry before any Rust code runs:
# hbreak _start
#
# Break at the Rust-level main entry (after BSP stack is set up):
# b capavisor::_start

# ── Print helpers ─────────────────────────────────────────────────────────── #
define print-cr3
    p/x $cr3
end
document print-cr3
Print the current CR3 (page-table root).
end

define print-vmcs
    echo "VMCS dump not yet implemented — add VMREAD helpers here\n"
end

# ── dom0 Linux kernel symbols ─────────────────────────────────────────────── #
#
# Usage:  load-vmlinux <path-to-vmlinux> [load-address]
#
# Load the uncompressed Linux vmlinux ELF so GDB can resolve dom0 kernel
# symbols.  The load address should match where Themis placed the
# decompressed kernel in guest physical memory (typically pref_address
# from the boot header, i.e. 0x1000000).
#
# If no address is given, defaults to 0x1000000 (standard Linux pref_address).
#
# Example:
#   load-vmlinux guest/vmlinux
#   load-vmlinux /path/to/vmlinux 0x1000000
#
define load-vmlinux
    if $argc == 0
        echo Usage: load-vmlinux <path-to-vmlinux> [load-address]\n
        echo Example: load-vmlinux guest/vmlinux 0x1000000\n
    else
        if $argc == 1
            add-symbol-file $arg0 0x1000000
        end
        if $argc == 2
            add-symbol-file $arg0 $arg1
        end
    end
end
document load-vmlinux
Load Linux vmlinux symbols at the given GPA (default: 0x1000000).
Use once Themis has decompressed and placed the dom0 kernel in memory.
The vmlinux ELF must match the bzImage that Limine loaded.
end

# ── dom0 kernel text range ────────────────────────────────────────────────── #
#
# Print the GPA range of the dom0 kernel .text section.  This helps locate
# dmesg ring buffer, function addresses, and crash sites in the guest.
#
# Phase 7+ will populate a Themis domain descriptor with the actual values;
# for now this reads the boot header pref_address and init_size that Themis
# parsed and prints the estimated range.
#
define dmesg-hint
    echo dom0 kernel placement (from Linux boot header):\n
    echo   pref_address  = 0x1000000 (16 MiB) — typical _text start\n
    echo   init_size     = see serial output from boot header dump\n
    echo \n
    echo To find the dmesg ring buffer once dom0 is running:\n
    echo   1. load-vmlinux guest/vmlinux\n
    echo   2. p/x &__log_buf          — kernel log buffer address\n
    echo   3. p/x log_buf_len         — buffer length\n
    echo   4. x/200s <__log_buf addr> — dump recent messages\n
    echo \n
    echo For crash analysis, the kernel text section is typically at:\n
    echo   [0x1000000, 0x1000000 + init_size)\n
end
document dmesg-hint
Print hints for locating the dom0 kernel text section and dmesg ring buffer.
Once vmlinux symbols are loaded, use 'p/x &__log_buf' for the real address.
end

echo [.gdbinit] Themis debug session ready.\n
