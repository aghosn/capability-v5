/* AArch64 direct-boot linker script for QEMU `-kernel` boot.
 *
 * QEMU loads the ELF at the entry address. We link at 0x4010_0000 to stay
 * above the DTB blob that QEMU places near RAM start (0x4000_0000).
 * The CPU enters at EL2 with MMU OFF, so VMA == LMA (identity-mapped).
 */

OUTPUT_FORMAT(elf64-littleaarch64)
OUTPUT_ARCH(aarch64)

ENTRY(_start)

KERNEL_BASE = 0x40100000;

PHDRS {
    text    PT_LOAD FLAGS((1 << 0) | (1 << 2)); /* R + X */
    rodata  PT_LOAD FLAGS((1 << 2));             /* R     */
    data    PT_LOAD FLAGS((1 << 1) | (1 << 2)); /* R + W */
}

SECTIONS {
    . = KERNEL_BASE;

    /* ── executable ─────────────────────────────────────────────────────── */
    .text : {
        *(.text.entry)          /* _start must be first */
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    /* ── read-only data ──────────────────────────────────────────────────── */
    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    /* ── writable data ───────────────────────────────────────────────────── */
    .data : {
        *(.data .data.*)
    } :data

    . = ALIGN(16);
    __bss_start = .;
    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data
    . = ALIGN(16);
    __bss_end = .;

    /* Discard DWARF exception-handling sections; we use panic=abort. */
    /DISCARD/ : {
        *(.eh_frame)
        *(.note .note.*)
    }
}
