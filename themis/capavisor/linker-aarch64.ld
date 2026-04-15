/* Limine higher-half kernel linker script for AArch64.
 *
 * Mirrors the x86-64 layout: kernel at 0xffff_ffff_8000_0000 (top 2 GiB),
 * which is where the Limine protocol places higher-half kernels on aarch64.
 * Limine maps the physical frames there before handing control to _start.
 */

OUTPUT_FORMAT(elf64-littleaarch64)
OUTPUT_ARCH(aarch64)

ENTRY(_start)

PHDRS {
    text    PT_LOAD FLAGS((1 << 0) | (1 << 2)); /* R + X */
    rodata  PT_LOAD FLAGS((1 << 2));             /* R     */
    data    PT_LOAD FLAGS((1 << 1) | (1 << 2)); /* R + W */
}

SECTIONS {
    . = 0xffffffff80000000;

    /* ── executable ─────────────────────────────────────────────────────── */
    .text : {
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    /* ── read-only data ──────────────────────────────────────────────────── */
    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    /* Limine request sections must be in read-only memory and kept by the
     * linker even if nothing references them from Rust code. */
    .requests_start_marker : {
        KEEP(*(.requests_start_marker))
    } :rodata

    .requests : {
        KEEP(*(.requests .requests.*))
    } :rodata

    .requests_end_marker : {
        KEEP(*(.requests_end_marker))
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    /* ── writable data ───────────────────────────────────────────────────── */
    .data : {
        *(.data .data.*)
    } :data

    /* .bss must be the last section in :data so the binary doesn't bloat
     * with zeroes — the bootloader will zero it for us. */
    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /* Discard DWARF exception-handling sections; we use panic=abort. */
    /DISCARD/ : {
        *(.eh_frame)
        *(.note .note.*)
    }
}
