//! IDT — Interrupt Descriptor Table with exception handlers.
//!
//! Sets up handlers for CPU exceptions.  Each handler prints fault info
//! and halts.  Double-fault (#DF) uses IST1 for a separate stack.

use crate::gdt;
use core::mem;

/// Number of IDT entries (full x86-64 IDT).
const IDT_SIZE: usize = 256;

/// 64-bit IDT gate descriptor.
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,       // bits [2:0] = IST index, rest zero
    type_attr: u8, // P | DPL | 0 | type
    offset_mid: u16,
    offset_high: u32,
    _reserved: u32,
}

impl IdtEntry {
    const EMPTY: Self = Self {
        offset_low: 0,
        selector: 0,
        ist: 0,
        type_attr: 0,
        offset_mid: 0,
        offset_high: 0,
        _reserved: 0,
    };

    /// Build an interrupt gate (DPL=0, present).
    fn interrupt_gate(handler: u64, ist: u8) -> Self {
        Self {
            offset_low: handler as u16,
            selector: gdt::KERNEL_CS,
            ist,
            type_attr: 0x8E, // P=1, DPL=0, type=0xE (64-bit interrupt gate)
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            _reserved: 0,
        }
    }
}

static mut IDT: [IdtEntry; IDT_SIZE] = [IdtEntry::EMPTY; IDT_SIZE];

#[repr(C, packed)]
struct IdtPtr {
    limit: u16,
    base: u64,
}

/// Stack frame pushed by the CPU on interrupt/exception entry.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct InterruptFrame {
    // Pushed by our stub (see `exception_stubs` assembly).
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    // Pushed by our stub.
    pub vector: u64,
    pub error_code: u64,
    // Pushed by CPU.
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

// Exception names for display.
static EXCEPTION_NAMES: [&str; 32] = [
    "#DE Divide Error",
    "#DB Debug",
    "NMI",
    "#BP Breakpoint",
    "#OF Overflow",
    "#BR Bound Range",
    "#UD Invalid Opcode",
    "#NM Device Not Available",
    "#DF Double Fault",
    "Coprocessor Segment Overrun",
    "#TS Invalid TSS",
    "#NP Segment Not Present",
    "#SS Stack-Segment Fault",
    "#GP General Protection",
    "#PF Page Fault",
    "Reserved",
    "#MF x87 FPU Error",
    "#AC Alignment Check",
    "#MC Machine Check",
    "#XM SIMD Exception",
    "#VE Virtualization",
    "#CP Control Protection",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "#HV Hypervisor Injection",
    "#VC VMM Communication",
    "#SX Security",
    "Reserved",
];

/// Common Rust handler called from the assembly stubs.
#[no_mangle]
extern "C" fn exception_handler(frame: &InterruptFrame) {
    let vec = frame.vector as usize;
    let name = if vec < 32 {
        EXCEPTION_NAMES[vec]
    } else {
        "Unknown"
    };
    eunomia::println!("EXCEPTION: {} (vector {})", name, vec);
    eunomia::println!("  error_code = {:#x}", frame.error_code);
    eunomia::println!("  RIP = {:#018x}  CS  = {:#x}", frame.rip, frame.cs);
    eunomia::println!("  RSP = {:#018x}  SS  = {:#x}", frame.rsp, frame.ss);
    eunomia::println!("  RFLAGS = {:#018x}", frame.rflags);
    eunomia::println!("  RAX={:#018x} RBX={:#018x}", frame.rax, frame.rbx);
    eunomia::println!("  RCX={:#018x} RDX={:#018x}", frame.rcx, frame.rdx);
    eunomia::println!("  RSI={:#018x} RDI={:#018x}", frame.rsi, frame.rdi);
    eunomia::println!("  RBP={:#018x} R8 ={:#018x}", frame.rbp, frame.r8);
    eunomia::println!("  R9 ={:#018x} R10={:#018x}", frame.r9, frame.r10);
    eunomia::println!("  R11={:#018x} R12={:#018x}", frame.r11, frame.r12);
    eunomia::println!("  R13={:#018x} R14={:#018x}", frame.r13, frame.r14);
    eunomia::println!("  R15={:#018x}", frame.r15);

    if vec == 14 {
        let cr2: u64;
        unsafe {
            core::arch::asm!("mov {}, cr2", out(reg) cr2);
        }
        eunomia::println!("  CR2 (fault addr) = {:#018x}", cr2);
    }

    // Halt after exception.
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}

// ── Exception stub generation ──────────────────────────────────────────── //
//
// For each vector 0–31 we generate a small stub that:
//   1. pushes a dummy error code (0) if the CPU doesn't push one
//   2. pushes the vector number
//   3. saves all GPRs
//   4. calls exception_handler(rsp) — RSP points at InterruptFrame
//   5. restores GPRs and iretq
//
// Vectors that push an error code: 8, 10, 11, 12, 13, 14, 17, 21, 29, 30.

core::arch::global_asm!(
    r#"
.macro exc_stub_no_err vec
.global __exc_stub_\vec
__exc_stub_\vec:
    pushq $0                    /* dummy error code */
    pushq $\vec                 /* vector number */
    jmp __exc_common
.endm

.macro exc_stub_err vec
.global __exc_stub_\vec
__exc_stub_\vec:
    /* CPU already pushed error code */
    pushq $\vec                 /* vector number */
    jmp __exc_common
.endm

/* Common handler: save regs, call Rust, restore, iretq. */
__exc_common:
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    mov %rsp, %rdi              /* arg0 = &InterruptFrame */
    call exception_handler

    /* If handler returns (it shouldn't, but just in case): */
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    addq $16, %rsp              /* pop vector + error code */
    iretq

/* Generate stubs for all 32 exception vectors. */
exc_stub_no_err  0
exc_stub_no_err  1
exc_stub_no_err  2
exc_stub_no_err  3
exc_stub_no_err  4
exc_stub_no_err  5
exc_stub_no_err  6
exc_stub_no_err  7
exc_stub_err     8
exc_stub_no_err  9
exc_stub_err    10
exc_stub_err    11
exc_stub_err    12
exc_stub_err    13
exc_stub_err    14
exc_stub_no_err 15
exc_stub_no_err 16
exc_stub_err    17
exc_stub_no_err 18
exc_stub_no_err 19
exc_stub_no_err 20
exc_stub_err    21
exc_stub_no_err 22
exc_stub_no_err 23
exc_stub_no_err 24
exc_stub_no_err 25
exc_stub_no_err 26
exc_stub_no_err 27
exc_stub_no_err 28
exc_stub_err    29
exc_stub_err    30
exc_stub_no_err 31
"#,
    options(att_syntax),
);

// Import stub symbols.
extern "C" {
    fn __exc_stub_0();
    fn __exc_stub_1();
    fn __exc_stub_2();
    fn __exc_stub_3();
    fn __exc_stub_4();
    fn __exc_stub_5();
    fn __exc_stub_6();
    fn __exc_stub_7();
    fn __exc_stub_8();
    fn __exc_stub_9();
    fn __exc_stub_10();
    fn __exc_stub_11();
    fn __exc_stub_12();
    fn __exc_stub_13();
    fn __exc_stub_14();
    fn __exc_stub_15();
    fn __exc_stub_16();
    fn __exc_stub_17();
    fn __exc_stub_18();
    fn __exc_stub_19();
    fn __exc_stub_20();
    fn __exc_stub_21();
    fn __exc_stub_22();
    fn __exc_stub_23();
    fn __exc_stub_24();
    fn __exc_stub_25();
    fn __exc_stub_26();
    fn __exc_stub_27();
    fn __exc_stub_28();
    fn __exc_stub_29();
    fn __exc_stub_30();
    fn __exc_stub_31();
}

fn stub_addr(vec: usize) -> u64 {
    let stubs: [unsafe extern "C" fn(); 32] = [
        __exc_stub_0,
        __exc_stub_1,
        __exc_stub_2,
        __exc_stub_3,
        __exc_stub_4,
        __exc_stub_5,
        __exc_stub_6,
        __exc_stub_7,
        __exc_stub_8,
        __exc_stub_9,
        __exc_stub_10,
        __exc_stub_11,
        __exc_stub_12,
        __exc_stub_13,
        __exc_stub_14,
        __exc_stub_15,
        __exc_stub_16,
        __exc_stub_17,
        __exc_stub_18,
        __exc_stub_19,
        __exc_stub_20,
        __exc_stub_21,
        __exc_stub_22,
        __exc_stub_23,
        __exc_stub_24,
        __exc_stub_25,
        __exc_stub_26,
        __exc_stub_27,
        __exc_stub_28,
        __exc_stub_29,
        __exc_stub_30,
        __exc_stub_31,
    ];
    stubs[vec] as u64
}

/// Initialise and load the IDT.  Must be called after `gdt::init()`.
pub fn init() {
    unsafe {
        let idt = &mut *(&raw mut IDT);

        // Exception gates (vectors 0–31).
        for vec in 0..32 {
            let ist = if vec == 8 { gdt::IST_DF } else { 0 };
            idt[vec] = IdtEntry::interrupt_gate(stub_addr(vec), ist);
        }

        // Timer interrupt (vector 32).
        idt[eunomia::timer::TIMER_VECTOR as usize] =
            IdtEntry::interrupt_gate(timer_isr_stub as *const () as u64, 0);

        let ptr = IdtPtr {
            limit: (mem::size_of::<[IdtEntry; IDT_SIZE]>() - 1) as u16,
            base: (&raw const IDT) as u64,
        };

        core::arch::asm!("lidt [{}]", in(reg) &ptr);
    }
}

// ── Timer ISR ──────────────────────────────────────────────────────────── //
//
// Minimal stub: increment tick counter, send EOI, iretq.
// Written as a naked function to avoid compiler-generated prologue.

#[unsafe(naked)]
unsafe extern "C" fn timer_isr_stub() {
    core::arch::naked_asm!(
        "push rax",
        "push rcx",
        "push rdx",

        // TIMER_TICKS.fetch_add(1, Relaxed)
        "mov rax, 1",
        "lock xadd [{ticks}], rax",

        // EOI: write 0 to LAPIC EOI register.
        "xor eax, eax",
        "mov dword ptr [{eoi}], eax",

        "pop rdx",
        "pop rcx",
        "pop rax",
        "iretq",
        ticks = sym eunomia::timer::TIMER_TICKS,
        eoi = const 0xFEE0_00B0u64,
    );
}
