# .gdbinit — Themis capavisor debug session
#
# Loaded automatically by scripts/debug.sh after `target remote :1234`.
# Place this file in the workspace root so `gdb -x .gdbinit` finds it.

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

echo [.gdbinit] Themis debug session ready.\n
