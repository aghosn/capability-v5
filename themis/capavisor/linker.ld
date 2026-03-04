/* Limine higher-half kernel linker script for x86-64.
 *
 * The kernel is placed at the top 2 GiB of the virtual address space
 * (0xffffffff80000000), which is where the Limine protocol requires
 * higher-half kernels to be loaded.  Limine maps the physical frames
 * there before handing control to _start.
 */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)

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
