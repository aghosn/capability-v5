/*
 * Eunomia linker script — PVH boot, identity-mapped at 1 MiB.
 *
 * CHV loads ELF segments at the physical addresses specified here.
 * PVH enters in 32-bit protected mode; the boot stub sets up paging
 * with an identity map before jumping to 64-bit Rust code.
 */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)

ENTRY(_pvh_start)

PHDRS {
    note    PT_NOTE FLAGS(4);           /* R       — PVH ELF note     */
    text    PT_LOAD FLAGS(5);           /* R + X   — code              */
    rodata  PT_LOAD FLAGS(4);           /* R       — read-only data    */
    data    PT_LOAD FLAGS(6);           /* R + W   — mutable data      */
}

SECTIONS {
    . = 0x100000;               /* 1 MiB — classic kernel load address */

    /* ── PVH note (must be in a PT_NOTE segment for linux-loader) ─── */
    .note : {
        KEEP(*(.note.pvh))
    } :note

    /* ── Executable code ─────────────────────────────────────────── */
    .text : {
        *(.text .text.*)
    } :text

    . = ALIGN(4096);

    /* ── Read-only data ──────────────────────────────────────────── */
    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    . = ALIGN(4096);

    /* ── Mutable data ────────────────────────────────────────────── */
    .data : {
        *(.data .data.*)
    } :data

    . = ALIGN(4096);

    /*
     * Page tables live in their own section so BSS zeroing (which runs
     * after paging is already enabled) does not clobber them.
     */
    .page_tables (NOLOAD) : {
        *(.page_tables)
    } :data

    . = ALIGN(4096);

    /* ── BSS (zeroed by 64-bit boot code) ────────────────────────── */
    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } :data

    . = ALIGN(4096);

    /* ── Boot stack (64 KiB) ─────────────────────────────────────── */
    __stack_bottom = .;
    . += 0x10000;
    __stack_top = .;

    /* ── Discard ─────────────────────────────────────────────────── */
    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}
