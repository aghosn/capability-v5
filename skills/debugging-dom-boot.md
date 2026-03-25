# Skill: Debugging a Domain Boot with Kernel Instrumentation

## When to Use

Use this skill when a guest domain (dom1, dom2, …) is stuck or looping during boot
and normal debugging is not viable because:

- The domain is stuck before printk/serial is functional (early `setup_arch`, CPU
  identification, etc.)
- The domain is in a tight VM-exit loop that produces no useful output
- You need to identify exactly which kernel path is reached before the failure
- The failure is deep enough that adding printk would require printk to already work

Do **not** use this skill for issues that occur after the kernel console is up — use
normal `dmesg` / serial output in that case.

---

## Background

All VMCALL exits from any domain (dom0, dom1, …) are dispatched directly to
`handle_vmcall()` in `capavisor/src/vmexit.rs`.  This means a guest kernel can call
into the capavisor at any point — including before APIC, timers, or serial are
initialised — and the capavisor will print a message to its own serial output.

The `THEMIS_DBG_PRINT` hypercall (opcode `0x1c`, defined in
`themis-abi/src/lib.rs`) takes a single `u64` in `RDI` and prints:

```
[DBG] dom=N val=0xXXXX
```

This output appears in the capavisor serial log regardless of the state of the guest
domain or any intermediate hypervisor layer (CHV, dom0, etc.).

---

## The `themis_trace()` Macro

Defined in `../linux/arch/x86/include/asm/special_insns.h`:

```c
static __always_inline void themis_trace(unsigned int code)
{
    asm volatile("vmcall"
                 :
                 : "a"(0x1cUL), "D"((unsigned long)code)
                 : "memory");
}
```

Include it anywhere in kernel C code with:

```c
#include <asm/special_insns.h>
```

Call it with any distinguishable 32-bit value. The value appears verbatim in the
`[DBG]` output.

---

## Step-by-Step Procedure

### 1. Identify the suspect region

From the existing `[DBG]` output or the looping RIP, identify which kernel source
file and function is failing.  Cross-reference the looping RIP with `System.map`:

```bash
grep -B2 "<hex_addr>" ../linux/System.map
```

Or disassemble the instrumented vmlinux:

```bash
objdump -d --start-address=0xffffffff810XXXXX --stop-address=0xffffffff810YYYYY \
    ../linux/vmlinux | head -40
```

### 2. Add `themis_trace()` calls

Insert traces around the suspect region using **new codes** not already in use (see
the trace code registry below).  A typical pattern:

```c
#include <asm/special_insns.h>

void some_function(void)
{
    themis_trace(0x100);   /* entry */
    step_a();
    themis_trace(0x101);   /* after step_a */
    step_b();
    themis_trace(0x102);   /* after step_b — if this never prints, step_b is the problem */
    ...
}
```

The last trace that **does** appear in the log is the last point reached before the
failure.

### 3. Build the kernel

```bash
cd ../linux
make -j$(nproc) bzImage
```

`make olddefconfig` is only needed if `.config` is stale or missing.

### 4. Deploy

```bash
cd <repo-root>
NESTED_KERNEL=../linux/arch/x86/boot/bzImage bash themis/scripts/update-bins.sh
```

`run-dom1.sh` automatically prefers `/opt/bins/nested/bzImage` when it exists.

### 5. Run and collect output

Boot the stack and capture the capavisor serial output.  Filter for `[DBG]` lines:

```bash
grep "\[DBG\]" /tmp/out.txt
```

The sequence of `val=` codes shows exactly how far the kernel reached.

### 6. Iterate

Narrow down with more traces until the failing line/call is identified, then fix the
root cause.  Remove or gate traces with `#ifdef THEMIS_DEBUG` when done.

---

## Capavisor-Side Requirements

These are already implemented; do not remove them:

| File | What it does |
|------|--------------|
| `themis-abi/src/lib.rs` | `THEMIS_DBG_PRINT = 0x1c` opcode constant |
| `capavisor/src/hypercall.rs` | Handler: prints `[DBG] dom=N val=0xXXXX` via `serial_println!` |
| `capavisor/src/vmexit.rs` | Child-domain `EXIT_REASON_VMCALL` arm routes to `handle_vmcall()` + `next_instruction()` — same path as dom0 |

If a VMCALL from a child domain is **not** reaching the capavisor (symptom: no `[DBG]`
output at all despite the kernel clearly executing), check:

1. The `EXIT_REASON_VMCALL` arm exists in the child-exit dispatch block in `vmexit.rs`
   (before the `_ =>` catch-all that forwards to CHV).
2. The `bins.img` was rebuilt **after** those changes (`bash themis/scripts/build-bins.sh`).
3. The instrumented bzImage is actually packed: `update-bins.sh` should print
   `✔ Updated guest/bins.img`.
4. `run-dom1.sh` is picking up the nested kernel (look for
   `→ Using instrumented nested kernel:` in the output).

---

## Trace Code Registry

Add new codes here when you use them.  Do **not** reuse existing codes.

| Code(s) | File | Function | Notes |
|---------|------|----------|-------|
| `0x00` | `init/main.c` | `start_kernel` | entry |
| `0x01` | `arch/x86/kernel/cpu/common.c` | `early_identify_cpu` | entry |
| `0x02` | `arch/x86/kernel/cpu/common.c` | `identify_cpu` | entry |
| `0x03` | `arch/x86/kernel/cpu/common.c` | `get_cpu_cap` | entry |
| `0x04` | `arch/x86/kernel/cpu/common.c` | `get_cpu_cap` | after `cpuid(1)` |
| `0x041`–`0x047` | `arch/x86/kernel/cpu/common.c` | `get_cpu_cap` | per-leaf checkpoints (6, 7, 0xd, 0x80000000, 0x80000001, 0x80000007/8, AMD extended) |
| `0x04f` | `arch/x86/kernel/cpu/common.c` | `get_cpu_cap` | return |
| `0x05`–`0x06` | `arch/x86/kernel/cpu/common.c` | `identify_boot_cpu` | entry / exit |
| `0x07`–`0x08` | `init/main.c` | `start_kernel` | before / after `calibrate_delay` |
| `0x0A`–`0x0F` | `arch/x86/kernel/cpu/common.c` | `early_identify_cpu` | post-`get_cpu_cap` stages (0x0A after get_cpu_cap, 0x0B after get_cpu_address_sizes, 0x0C/0x0D around c_early_init, 0x0E/0x0F around c_bsp_init) |
| `0x10`–`0x1F` | `init/main.c` | `do_initcall_level` | entering level N (`0x10\|N`) |
| `0x1010`–`0x101F` | `init/main.c` | `do_initcall_level` | completed level N |
| `0x20`–`0x21` | `init/main.c` | `do_basic_setup` | entry / exit |
| `0x30`–`0x36` | `init/main.c` | `kernel_init_freeable` | staged checkpoints |
| `0x40`–`0x44` | `init/main.c` | `kernel_init` | free_initmem, init process launch |
| `0x50`–`0x51` | `arch/x86/kernel/apic/apic.c` | `setup_local_APIC` | entry / APIC enable |
| `0x60`–`0x62` | `arch/x86/kernel/apic/apic.c` | `calibrate_APIC_clock` | entry / loop start / loop done |
| `0x70`–`0x72` | `arch/x86/kernel/tsc.c` | `init_tsc_clocksource` | entry / registered / deferred |
| `0x80`–`0x86` | `arch/x86/kernel/signal.c` | signal handling | fault, rt_sigreturn stages |
| `0x90`–`0x90FF` | `arch/x86/kernel/signal.c` | `handle_signal` | init signal delivery |
| `0xA0`–`0xB2` | `arch/x86/kernel/fpu/signal.c` | FPU/XSAVE restore | failure diagnostics |
| `0xC0`–`0xC6` | `kernel/module/main.c` | `do_init_module` | module init lifecycle |
| `0x210` | `arch/x86/kernel/setup.c` | `setup_arch` | after `early_cpu_init()` |
| `0x211` | `arch/x86/kernel/setup.c` | `setup_arch` | after `e820__memory_setup()` |
| `0x212` | `arch/x86/kernel/setup.c` | `setup_arch` | after `acpi_boot_table_init` |
| `0x213` | `arch/x86/kernel/setup.c` | `setup_arch` | after `acpi_boot_init` |
| `0x214` | `arch/x86/kernel/setup.c` | `setup_arch` | after `mcheck_init` (near end of setup_arch) |
| `0x215` | `arch/x86/kernel/setup.c` | `setup_arch` | after `init_hypervisor_platform()` |
| `0x216` | `arch/x86/kernel/setup.c` | `setup_arch` | after `cache_bp_init()` |
| `0x217` | `arch/x86/kernel/setup.c` | `setup_arch` | after `check_x2apic()` |
| `0x218` | `arch/x86/kernel/setup.c` | `setup_arch` | after `init_mem_mapping()` |
| `0x220` | `arch/x86/kernel/setup.c` | `setup_arch` | after `parse_setup_data()` |
| `0x221` | `arch/x86/kernel/setup.c` | `setup_arch` | after `x86_configure_nx()` |
| `0x222` | `arch/x86/kernel/setup.c` | `setup_arch` | after `parse_early_param()` |
| `0x223` | `arch/x86/kernel/setup.c` | `setup_arch` | after `efi_memblock_x86_reserve_range()` (no-op if non-EFI) |
| `0x224` | `arch/x86/kernel/setup.c` | `setup_arch` | after `x86_report_nx()` |
| `0x225` | `arch/x86/kernel/setup.c` | `setup_arch` | after `apic_setup_apic_calls()` |
| `0x226` | `arch/x86/kernel/setup.c` | `setup_arch` | after `e820__finish_early_params()` |
| `0x227` | `arch/x86/kernel/setup.c` | `setup_arch` | after `efi_init()` (no-op if non-EFI) |
| `0x228` | `arch/x86/kernel/setup.c` | `setup_arch` | after `dmi_setup()` |
| `0x280` | `arch/x86/kernel/setup.c` | `setup_arch` | after `early_platform_quirks()` |
| `0x281` | `arch/x86/kernel/setup.c` | `setup_arch` | after `early_acpi_boot_init()` |
| `0x282` | `arch/x86/kernel/setup.c` | `setup_arch` | after `initmem_init()` |
| `0x283` | `arch/x86/kernel/setup.c` | `setup_arch` | after `memblock_find_dma_reserve()` |
| `0x284` | `arch/x86/kernel/setup.c` | `setup_arch` | after `pagetable_init()` |
| `0x285` | `arch/x86/kernel/setup.c` | `setup_arch` | after `kasan_init()` |
| `0x286` | `arch/x86/kernel/setup.c` | `setup_arch` | after `early_quirks()` |
| `0x290` | `arch/x86/kernel/acpi/boot.c` | `early_acpi_boot_init` | entry |
| `0x291` | `arch/x86/kernel/acpi/boot.c` | `early_acpi_boot_init` | after `acpi_table_init_complete()` |
| `0x292` | `arch/x86/kernel/acpi/boot.c` | `early_acpi_boot_init` | after `acpi_table_parse(BOOT)` |
| `0x293` | `arch/x86/kernel/acpi/boot.c` | `early_acpi_boot_init` | after blacklist check |
| `0x294` | `arch/x86/kernel/acpi/boot.c` | `early_acpi_boot_init` | after `early_acpi_process_madt()` |
| `0x295` | `arch/x86/kernel/acpi/boot.c` | `early_acpi_boot_init` | after `acpi_reduced_hw_init()` |

**Next free range: `0x229`**

---

## ⚠️ Verifying Dom1 Output — Do NOT Confuse With Dom0

**Critical rule**: Never claim dom1 has booted based on systemd/kernel messages in
`/tmp/out.txt` without first verifying those messages come from dom1, not dom0.

### The output streams

| Stream | Source | Where it appears |
|--------|--------|------------------|
| Capavisor `serial_println!` | L0 hypervisor | `/tmp/out.txt` (QEMU serial) — always reliable |
| `[DBG] dom=N val=...` | Guest VMCALL → capavisor | `/tmp/out.txt` — reliable, tagged with domain ID |
| Dom0 kernel `printk` | Dom0 `console=ttyS0` | `/tmp/out.txt` — dom0's serial goes to QEMU serial |
| Dom0 systemd output | Dom0 boot services | `/tmp/out.txt` — appears as `[  OK  ]` lines **before** child VMCS creation |
| Dom1 kernel `printk` | Dom1 `console=ttyS0` → CHV serial | **NOT in `/tmp/out.txt`** unless CHV's serial chains to dom0's ttyS0. See below. |

### How to tell dom0 vs dom1 output apart

1. **Check line ordering**: dom1 output MUST appear **after** the `child VMCS:` line
   and `[REGISTER_DOORBELL]` lines in `/tmp/out.txt`. If systemd messages appear
   before these lines, they are **dom0's boot**, not dom1's.

2. **Check kernel version**: dom0 is `6.8.0-101-generic #101-Ubuntu`; dom1 uses
   the instrumented kernel `6.8.0-dirty #24` (or similar). Look for `Linux version`
   or `Tainted:` lines to identify which kernel.

3. **Check timestamps**: dom0 systemd starts at dom0 uptime ~12-17s. Dom1 would
   start at its own t=0 (which maps to a later dom0 uptime).

4. **Use `[DBG] dom=1` lines**: these are the ONLY reliable dom1 progress indicators
   since they go through the capavisor serial and are tagged with the domain ID.

### Dom1 serial output chain (current issue)

CHV runs with `--serial tty`, which opens `/dev/tty` in dom0. This means:

- Dom1 kernel writes to its virtual ttyS0 (I/O port 0x3F8)
- CHV's UART emulation captures the bytes
- CHV writes them to `/dev/tty` inside dom0

**Known issue**: dom1's console output does NOT appear in `/tmp/out.txt`. The
CHV→`/dev/tty`→dom0 ttyS0→QEMU serial chain may not be working. Possible causes:

- CHV's `/dev/tty` is not connected to dom0's serial console
- I/O port exits for serial (0x3F8) may not be properly forwarded to CHV
- CHV's UART emulation in the Themis backend may not be processing the bytes

To verify dom1 boot without serial: use `[DBG]` trace codes (see above), check
`[CHILD-EXIT]` RIP addresses (kernel virtual addresses `0xffffffff81...` confirm
Linux is running), and try pinging dom1 (`ping 192.168.100.2` from dom0).
