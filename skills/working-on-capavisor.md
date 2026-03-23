# Skill: Working on the Capavisor (themis/capavisor/)

## When to Use

Use this skill when modifying `themis/capavisor/src/`, any `themis/crates/`, or
anything that touches the monitor loop, vmexit handlers, hypercall dispatch, or
`ThemisPlatform`. Always read `skills/agent-workflow.md` first.

---

## This Is an Active, Incomplete Codebase

The capavisor is under active development. Expect:

- **TODOs and FIXMEs in the code** — these are real known gaps, not oversights to
  silently remove. Read them before changing nearby code; they often describe a design
  intent or a deferred correctness concern.
- **Incomplete dispatch** — not all hypercall opcodes are implemented; some return
  `HypercallResult::unimpl()`. When adding an opcode, implement it fully rather than
  leaving a stub, unless the work is explicitly phased.
- **The vmexit dispatch is not yet unified** — there is a known TODO about the dual
  dom0/child dispatch paths in `vmexit.rs`. Do not work around it with more
  special-casing; move toward unification when touching that code.
- **Some `apply_update` handlers may be stubs or incomplete** — always check
  `platform.rs::apply_update` when adding a new `Update` variant and verify the
  hardware effect is actually implemented, not just matched and ignored.
- **Test coverage is partial** — the capability engine has good coverage, but the
  capavisor integration layer does not yet have automated tests. When you add
  something and cannot write a full automated test for it, document the manual test
  procedure in `todo.md` so it is not forgotten.
- **When in doubt, ask before assuming** — if something looks wrong but might be
  intentional, leave a comment and note it in `todo.md` rather than silently changing
  it. The user has full context; agents do not.

---

## Core Principles — Read These Before Touching Any Code

These are not guidelines; they are invariants. Violating any of them is a bug.

### 1. Capability Engine First, Always (Axiom A1)

Every operation that changes domain state or memory ownership **must go through the
capability engine** before any hardware change. The canonical pattern is:

```rust
execute(platform, exclusive, || {
    Capability::domain_mediated_op(&caller, ...).map(|(result, batch)| (result, batch))
})?;
```

`execute()` acquires the global RW lock, runs the pure tree mutation, then calls
`Platform::apply_update` for each hardware change. **Never call `apply_update` directly.
Never modify EPT, IOMMU, or VMCS state in a way that bypasses `execute()`.**

Use `execute(platform, /*exclusive=*/false, ...)` for non-destructive operations
(carve, alias, send, create, seal). Use `execute(platform, /*exclusive=*/true, ...)`
for any revoke.

### 2. Use the Domain-Mediated Interface (Axiom A9)

Call `Capability::carve`, `Capability::send`, `Capability::revoke`, etc. — the
domain-mediated methods that validate ownership and `MonitorAPI` permissions.
Never call `#[doc(hidden)]` internal primitives like `Capability::carve_child`,
`Capability::alias_child`, or `Capability::revoke_child` from capavisor code.
Those exist for the capability engine's own internal use only.

See `skills/working-on-capability-engine.md` for the full API table.

### 3. Domains Are Adversarial — Never Trust Domain-Supplied Inputs

Code running inside a domain (dom0, dom1, any child) is **not trusted**. The capavisor
must treat all data crossing the VMCALL boundary as potentially malicious:

- **Argument registers** (rdi, rsi, rdx, rcx, r8) come from guest code. Validate them.
  The capability engine validates handles and access rights; your job is to not
  dereference or act on raw values before the engine has checked them.
- **The `caller` is never taken from guest registers.** It is obtained from the
  capavisor's own `CoreContext` via `platform.get_core_cap(core_id)`. The guest cannot
  forge a different caller identity.
- **Sizes and addresses from guests may be zero, wrap around, or alias capavisor
  memory.** The engine checks containment and overlap, but always be alert to new
  code paths that might act on raw values before the engine validates them.
- **A domain can invoke any opcode.** What it is allowed to do is determined entirely
  by the capability state (what handles it holds, what its `MonitorAPI` allows) —
  not by which domain it is or what "tier" it occupies.

### 4. Dom0 Is Not Privileged

Dom0 is the first domain created at boot with all initial resources. After boot, it has
**exactly the same hypercall ABI** as any child domain. `handle_vmcall` in
`hypercall.rs` is called for both dom0 and child domain VMCALLs — the same dispatch
table, the same engine calls, the same permission checks.

Do not add special-casing for dom0 (e.g., `if domain_id == 0 { skip_check() }`).
The capability state already encodes what each domain is allowed to do. If dom0 can do
something a child cannot, it is because dom0 holds a capability the child does not,
not because dom0 has a bypass path.

The vmexit dispatch currently has a TODO about unifying the dom0 and child domain
paths — that is the direction to move in, not away from.

### 5. Capavisor Memory Is Never Accessible to Domains (Axiom A5)

Capavisor code, stacks, page tables, and the META pool (VMCS, EPT tables, VAPIC, PID,
COMM pages) must **never** appear in any domain's EPT. At boot, `passthrough_regions`
explicitly excludes `BOOTLOADER_RECLAIMABLE` and `KERNEL_AND_MODULES` Limine entries.
When implementing new features that allocate capavisor-internal memory, always
allocate from the `MetaAllocator` (which is carved from the META pool) and verify
that nothing adds those pages to `apply_update`'s `ChangeRights` path for a domain.

### 6. Boot Is the Only Exception to "Capability First"

The boot path (`boot.rs`) is the **single** place where hardware is enumerated and
the initial capability state is constructed from physical reality:

```
platform()    → discover RAM, ACPI, SMP, PCI
init_themis() → register domain 0, hand full META pool to ThemisPlatform
vmx()         → feature detect, VMXON (uses ThemisPlatform)
capa()        → capability engine init, dom0 EPT (uses ThemisPlatform)
vmcs()        → VMCS setup (uses ThemisPlatform)
```

After `capa()` completes, the capability state is the source of truth. Everything
from that point on must follow the "capability engine first, then hardware" order.
Do not add new boot-time hardware configuration after the capability state is built
unless it is truly a one-time platform initialization that has no ongoing capability
analogue (e.g., MSR feature enable on each AP).

### 7. Cross-Core Consistency Is Handled by `execute()` — Do Not Reimplement It

The IPI/barrier protocol in `execute()` ensures that EPT changes, TLB flushes, and
VMCS redirections are applied atomically across all cores. You do not need to
implement your own cross-core synchronisation for hardware state changes as long as
you go through `execute()` + `apply_update`. If you find yourself writing
`send_ipi` calls outside of `ThemisPlatform::apply_update`, stop and reconsider.

### 8. Modularity — One Handler Pattern, Used Everywhere

All hypercall handlers follow the same structure. New handlers must follow it too:

```rust
fn do_my_op(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    arg0: u64,
    /* ... */
) -> HypercallResult {
    // 1. Decode arguments (raw u64 → typed values)
    let handle = arg0 as LocalHandle;

    // 2. Call execute() with the domain-mediated method
    match execute(platform, /*exclusive=*/false, || {
        Capability::my_op(&caller.clone(), handle, ...).map(|(res, batch)| (res, batch))
    }) {
        Ok((result, _)) => HypercallResult::success_1(result as u64),
        Err(e) => HypercallResult::error(map_error(&e)),
    }
}
```

Keep `do_X` functions thin. Business logic belongs in the capability engine, not here.
Duplication between dom0 and child handling is a sign something should be unified.

---

## Adding a New VMEXIT Handler

`vmexit.rs` has two dispatch layers:

1. **Inner match** (child domain path, lines ~260–370): fires when `domain_id != 0`.
   Handles exits that the capavisor deals with directly for child domains. Everything
   else falls through to `forward_child_exit`.

2. **Outer match** (dom0/default path, line ~379 onward): the full dispatch for dom0
   and any exit not handled by the inner match.

**Steps for a new exit type:**

1. Add the `EXIT_REASON_X: u32 = N;` constant at the top of `vmexit.rs` if it is not
   already there (check Intel SDM Vol 3C §27.9.1 for the value).

2. Decide the policy: should child domains handle this exit natively in the capavisor,
   or forward it to the parent?
   - **Native in capavisor** (e.g., APIC access, preemption timer, CPUID hypervisor
     leaves): add to the inner match. The capavisor handles it without the parent's
     knowledge.
   - **Forward to parent** (e.g., EPT violation, I/O, most device exits): call
     `forward_child_exit(vcpu, EXIT_REASON_X)`. The parent's vmexit handler or CHV
     backend will see it as an intercept message via the COMM page.

3. Add the same exit reason to the outer match (dom0 path) with the appropriate
   handler. Prefer reusing the same handler function for both paths.

4. If the handler needs to modify domain or memory state, do it through
   `handle_vmcall`-style `execute()` calls, not directly.

5. If the exit must advance the guest RIP (e.g., CPUID, VMCALL, MSR), call
   `next_instruction(vcpu)` after handling.

---

## Adding a New Hypercall

A hypercall spans four files. Do all four atomically (one commit):

### 1. `themis/crates/themis-abi/src/`

Add the opcode constant and document the register convention:

```rust
// themis-abi/src/opcodes.rs
pub const THEMIS_MY_OP: u64 = 0xNN;
```

Register convention (all hypercalls use the same ABI):
- `rax` = opcode (in) / error code (out, 0 = success)
- `rdi` = arg0 (in) / result0 (out)
- `rsi` = arg1 (in) / result1 (out)
- `rdx` = arg2 (in) / result2 (out)
- `rcx` = arg3 (in)
- `r8`  = arg4 (in)

Document what each argument encodes and what the return values mean in a comment on
the opcode constant.

### 2. `themis/capavisor/src/hypercall.rs`

Add the `do_my_op` function (see the handler pattern above), then add an arm to the
`match opcode` block in `handle_vmcall`:

```rust
opcodes::THEMIS_MY_OP => Some(do_my_op(platform, &caller, arg0, arg1)),
```

### 3. `themis/capavisor/src/vmexit.rs` (usually no change needed)

`EXIT_REASON_VMCALL` already routes to `handle_vmcall` for both dom0 and child
domains. Only touch `vmexit.rs` if the new hypercall needs special pre/post
processing at the vmexit level (rare).

### 4. `thhv.ko` / `thhv_hvcall.c` in dom0 userspace

Add the corresponding ioctl or in-kernel wrapper so dom0 can invoke the new
hypercall without inline assembly. See the existing `THEMIS_CARVE` ioctl as the
reference pattern. If the hypercall is for dom0's own kernel module, update
`thhv.h` with the new ioctl constant and add the kernel-side handler in `thhv.c`.

---

## ThemisPlatform and `apply_update`

`platform.rs` is the only place that translates `Update` variants into hardware
operations. When you need to handle a new `Update` variant:

| `Update` variant | Hardware action |
|-----------------|----------------|
| `ChangeRights { rights: non-NONE }` | Map pages in domain's EPT (lazy: build on first access) |
| `ChangeRights { rights: NONE }` | Unmap pages from domain's EPT + INVEPT |
| `ZeroMemory` | Zero physical pages (HHDM) |
| `RevokeDomain` | Handled by `on_domain_revoked` (redirect core, free VMCS/EPT) |
| `CommRegion` | Map the COMM page in capavisor's HHDM view for the target VP |
| `UncommRegion` | Unmap the COMM page from capavisor's HHDM view |
| `FlushTLB` | INVEPT for the domain |

`apply_update` is called between the two barriers of the cross-core protocol — all
affected cores are stopped at this point. Keep it fast and non-blocking.

---

## Module Reference

| File | Role |
|------|------|
| `main.rs` | Entry point; calls boot phases; starts AP monitor loops |
| `boot.rs` | Hardware discovery → initial capability state (the special init path) |
| `platform.rs` | `ThemisPlatform`: `Platform` trait impl; `apply_update`; IPI/barrier; domain registry |
| `vmexit.rs` | Monitor loop; exit reason dispatch; `handle_vmexit`; `forward_child_exit` |
| `hypercall.rs` | `handle_vmcall` opcode dispatch; `do_X` handlers; `forward_interrupt_to_handler` |
| `vmcs.rs` | VMCS field setup and helpers; `ActiveVcpu`/`InactiveVcpu` |
| `domain.rs` | Capavisor-side domain state (VMCS phys, VAPIC phys, PID phys) |
| `mem/` | `MetaAllocator`, physical inventory, paging helpers |
| `acpi.rs` | ACPI table parsing (MADT, DMAR) |
| `iommu_ir.rs` | VT-d / IOMMU interrupt remapping |
| `msr_virt.rs` | MSR virtualisation (x2APIC, KVM leaves, etc.) |
| `gdt.rs` | Host GDT/TSS setup |
| `guest/` | Guest boot helpers (Linux e820, module layout) |

---

## Build and Test

```bash
# Build all capavisor binaries (from repo root)
cargo build-bins

# Build inside Docker (reproducible, matches CI)
cargo build-bins-docker

# Boot capavisor + dom0 and capture trace
cargo themis > /tmp/out.txt 2>&1 &   # see skills/running-inside-dom0.md

# SSH into dom0 and run tests
ssh -p 2222 cloud@localhost
```

See `skills/running-inside-dom0.md` for the full boot-and-test procedure.

---

## Common Mistakes to Avoid

| Mistake | Correct approach |
|---------|-----------------|
| Calling `Capability::carve_child` directly from capavisor | Use `Capability::carve` (domain-mediated) inside `execute()` |
| Checking `domain_id == 0` to grant extra permission | Let the capability state determine permissions |
| Modifying EPT entries outside `apply_update` | All EPT changes go through `execute()` → `apply_update` |
| Allocating capavisor-internal memory from the physical inventory | Use `MetaAllocator::alloc` — never from the capability pool |
| Adding a new `Update` variant without handling it in `apply_update` | Handle all variants; a missing arm is a silent no-op |
| Responding to an IPI / cross-core event without checking `execute()`'s barrier state | The barrier protocol in `ThemisPlatform` handles this; do not add ad-hoc synchronisation |
| Trusting a handle value from guest registers without engine validation | Pass the raw handle to the domain-mediated method; the engine checks ownership |
