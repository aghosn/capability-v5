//! Eunomia — minimal micro-kernel for Themis guests.
//!
//! Boots via PVH (32-bit protected mode entry from CHV), transitions to
//! 64-bit long mode, and prints a banner over COM1 serial.

#![no_std]
#![no_main]

mod serial;

use core::arch::global_asm;
use core::panic::PanicInfo;

// ── PVH ELF note ────────────────────────────────────────────────────────── //
//
// linux-loader scans PT_NOTE segments for name="Xen", type=18
// (XEN_ELFNOTE_PHYS32_ENTRY) to locate the 32-bit PVH entry point.

global_asm!(
    r#"
.section .note.pvh, "a"
.align 4
.long 4                         /* namesz  = len("Xen\0") */
.long 4                         /* descsz  = 4 (32-bit addr) */
.long 18                        /* type    = XEN_ELFNOTE_PHYS32_ENTRY */
.asciz "Xen"                    /* name */
.align 4
.long _pvh_start                /* 32-bit physical entry address */
.align 4
"#,
    options(att_syntax),
);

// ── 32-bit → 64-bit boot stub ──────────────────────────────────────────── //
//
// PVH ABI: entered in 32-bit protected mode, paging OFF, %ebx =
// pointer to hvm_start_info.  We build identity-mapped page tables
// (2 MiB pages covering first 1 GiB), enable long mode, and jump
// to 64-bit Rust code.

global_asm!(
    r#"
.section .text
.code32
.global _pvh_start
_pvh_start:
    cli
    mov %ebx, %esi                  /* save hvm_start_info ptr */

    /* ── Zero 3 pages for page tables (PML4 + PDPT + PD) ──────── */
    movl $page_tables, %edi
    xor  %eax, %eax
    movl $(4096 * 3 / 4), %ecx
    rep stosl                       /* EDI now past page_tables */

    /* PML4[0] → PDPT */
    movl $(page_tables + 0x1000 + 0x3), %eax
    movl %eax, page_tables

    /* PDPT[0] → PD */
    movl $(page_tables + 0x2000 + 0x3), %eax
    movl %eax, (page_tables + 0x1000)

    /* PD: 512 × 2 MiB identity-mapped pages (covers first 1 GiB) */
    movl $(page_tables + 0x2000), %edi
    movl $0x83, %eax                /* Present | Writable | PageSize */
    movl $512, %ecx
.Lfill_pd:
    movl %eax, (%edi)
    addl $8, %edi
    addl $0x200000, %eax
    decl %ecx
    jnz  .Lfill_pd

    /* ── Enable long mode ──────────────────────────────────────── */
    movl $page_tables, %eax
    mov  %eax, %cr3                 /* CR3 = PML4 */

    mov  %cr4, %eax
    orl  $(1 << 5), %eax            /* CR4.PAE */
    mov  %eax, %cr4

    movl $0xC0000080, %ecx          /* IA32_EFER */
    rdmsr
    orl  $(1 << 8), %eax            /* EFER.LME */
    wrmsr

    mov  %cr0, %eax
    orl  $(1 << 31), %eax           /* CR0.PG */
    mov  %eax, %cr0

    lgdt (gdt64_ptr)
    ljmpl $0x08, $_start64          /* load 64-bit CS */

/* ── 64-bit entry ──────────────────────────────────────────────── */
.code64
.global _start64
_start64:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    lea  __stack_top(%rip), %rsp

    /* Zero BSS */
    lea  __bss_start(%rip), %rdi
    lea  __bss_end(%rip), %rcx
    sub  %rdi, %rcx
    shr  $3, %rcx
    xor  %eax, %eax
    rep  stosq

    /* Call Rust — hvm_start_info pointer as first argument */
    movl %esi, %edi
    call rust_main

.Lhalt:
    hlt
    jmp  .Lhalt

/* ── Static page tables (own section, not in BSS) ─────────────── */
.section .page_tables, "aw", @nobits
.align 4096
.global page_tables
page_tables:
    .space 4096 * 3

/* ── 64-bit GDT ───────────────────────────────────────────────── */
.section .rodata
.align 8
gdt64:
    .quad 0x0000000000000000        /* NULL */
    .quad 0x00AF9A000000FFFF        /* Code64: L=1, P=1, S=1, E=1 */
    .quad 0x00CF92000000FFFF        /* Data64: G=1, DB=1, P=1, S=1, W=1 */
gdt64_ptr:
    .word gdt64_ptr - gdt64 - 1    /* limit */
    .long gdt64                    /* 32-bit base (for lgdt in .code32) */
"#,
    options(att_syntax),
);

#[no_mangle]
pub extern "C" fn rust_main(hvm_start_info: u64) -> ! {
    serial::init();
    println!("Eunomia v0.1.0 booted");
    println!("hvm_start_info @ {:#x}", hvm_start_info);

    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}

// ── Panic handler ───────────────────────────────────────────────────────── //

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("PANIC: {}", info);
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}
