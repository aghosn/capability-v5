# Capavisor Cleanup Design

## Overview

`themis/capavisor/src/` is functional but shows clear organic growth: **17,445 LOC** with several files acting as catch-all integration layers. The biggest quality risk is not only file size: long functions mix capability-engine validation, VMCS/VCPU mechanics, COMM-page marshaling, interrupt policy, ad-hoc debug traces, and low-level x86 constants. `hypercall.rs` is the highest priority because it contains the worst functions (`do_switch`, `forward_child_exit`, `forward_interrupt_to_handler`) directly on the security-critical SWITCH/interrupt path.

### Comparison with Tyche (`~/Documents/Programs/vmxvmm/monitor/tyche`)

Tyche is a comparable capability-based monitor (x86_64 + RISC-V VMX hypervisor) with a much tighter split:

| Project | Total LOC | Largest file | Module split |
|---|---:|---:|---|
| **Themis capavisor** | 17,445 | `hypercall.rs` 3,073 | flat: `hypercall.rs`, `platform.rs`, `monitor.rs`, `arch/x86_64/*.rs` |
| **Tyche monitor** | 7,332 | `x86_64/platform.rs` 1,214 | per-arch split: `arch.rs`, `init.rs`, `state.rs`, `context.rs`, `vmx_helper.rs`, `cpuid_filter.rs`, `platform.rs`, `perf.rs` |

Themis is **2.4× larger** for a comparable feature set. Tyche's organization is worth studying as a target layout:

- VMX setup lives in `vmx_helper.rs` (325 LOC), not inline in a hypercall dispatcher.
- VMCS/VCPU lifecycle is in `context.rs` (1,030 LOC) and `state.rs` (369 LOC), cleanly separated from hypercall logic.
- The monitor/dispatch layer (`monitor.rs`, 1,178 LOC) is arch-agnostic; arch-specific code is fully under `x86_64/` or `riscv/`.
- CPUID policy is a dedicated `cpuid_filter.rs` (small file) — in Themis it's 129 lines inline inside `vmexit.rs::handle_cpuid_local`.

The cleanup target should not just be "split big functions" but **adopt this kind of arch-isolated, single-responsibility layout**. A `hypercall.rs` file of 3,000+ LOC is itself the problem.

### Existing constants we should reuse instead of reinventing

A significant portion of the "magic numbers" listed below are **already provided by the `x86` crate (v0.52)** which is in `themis/capavisor/Cargo.toml`. We are paying the cost of redefinition for no reason. Specifically:

- All **VMCS field IDs** (`x86::vmx::vmcs::ro::*`, `vmcs::control::*`, `vmcs::guest::*`, `vmcs::host::*`). Already used in `vcpu.try_get(...)` paths — but raw VMCS field IDs are sometimes still hardcoded; audit and replace.
- **Control-field bitflags** as proper `bitflags!` types: `x86::vmx::vmcs::control::{PrimaryControls, SecondaryControls, PinbasedControls, EntryControls, ExitControls}`. The ~250-line `vmcs.rs::write_control_fields` currently uses raw `1 << N` bitmask math — should be rewritten to use these named flags directly.
- **RFLAGS bits**: `x86::bits64::rflags::RFlags::FLAGS_IF` instead of literal `1 << 9` in interrupt-injection guards (`hypercall.rs:1710`, `2185`).
- **EPT violation qualification bits**: `x86::vmx::vmcs::ro::*` constants plus per-bit flags (`EPT_VIOLATION_VE` etc.).

What the `x86` crate does **not** provide and we must still define ourselves (but in ONE place, not inline in `hypercall.rs`):

- VMX **exit-reason values** (codes 0–63 like `EXTERNAL_INTERRUPT=1`, `IO_INSTRUCTION=30`, `EPT_VIOLATION=48`). Currently re-declared locally inside `forward_child_exit` — must move to `arch/x86_64/vmexit.rs::exit_reasons` and imported.
- **I/O exit qualification bit layout** (size/direction/imm/port).
- **VMENTRY_INTERRUPTION_INFO format** (valid bit `1<<31`, type, vector).
- **Interruptibility state bits** (STI=0x1, MOV-SS=0x2).
- **Segment access-right encodings** (`0xC09B`, `0xC093`, etc.).

These should live in `arch/x86_64/consts.rs` or in dedicated focused modules (`vmcs::controls`, `vmexit::reasons`, `apic::regs`).

### Estimated impact of the refactor

Conservative estimate by area:

| Area | Current LOC | After | Saved |
|---|---:|---:|---:|
| `vmcs.rs::write_control_fields` (use `x86` bitflags) | 259 | ~120 | ~140 |
| `vmcs.rs::write_guest_state`+`write_host_state` (named seg consts + helper) | 207 | ~140 | ~65 |
| `hypercall.rs::do_switch` (extract helpers) | 309 | ~180 | ~130 |
| `hypercall.rs::forward_child_exit` (shared VMCS swap + IO decode) | 243 | ~120 | ~120 |
| `hypercall.rs::forward_interrupt_to_handler` (shared helpers) | 197 | ~100 | ~95 |
| `hypercall.rs::do_add_vp` (extract VP meta alloc) | 270 | ~150 | ~120 |
| `hypercall.rs::handle_vmcall` (submodule dispatch) | 112 | ~60 | ~50 |
| Dedup EXIT_REASON/IO decode/RIP-advance/RFLAGS magic | ~80 | ~10 | ~70 |
| Strip `[DB-*]` doorbell debug instrumentation | ~80 | 0 | ~80 |
| `boot.rs::platform`+`init_themis`+`capa` splits | 1,268 | ~900 | ~370 |
| `main.rs::_start`+`_start_rust` splits | 532 | ~420 | ~110 |
| `linux.rs::load_linux` (helpers + drop debug dumps) | 204 | ~140 | ~65 |
| `acpi.rs::strip_dmar`, `attestation.rs::try_tpm`, `vmexit.rs` CPUID/APIC/doorbell handlers | ~600 | ~430 | ~170 |
| Page-size/mask/offset magic-number consolidation | ~40 occ. | shared | ~30 |

**Direct removal: ~1,600 LOC (~9% of capavisor).** Helpers gained: ~300 LOC across new files (`vmcs_swap.rs`, `comm_marshal.rs`, `io_decode.rs`, `arch/x86_64/layout.rs`, `arch/x86_64/consts.rs`).

**Net saved: ~1,300 LOC.** Most importantly, `hypercall.rs` shrinks from 3,073 → ~1,800 LOC and, combined with the proposed submodule split (`hypercall/{switch,memory,interrupt,doorbell,attest,vp}.rs`), no single file would exceed ~600 LOC — bringing Themis closer to the Tyche layout.

File size snapshot (LOC):

| LOC | File |
|---:|---|
| 3,073 | `themis/capavisor/src/hypercall.rs` |
| 1,996 | `themis/capavisor/src/platform.rs` |
| 1,787 | `themis/capavisor/src/arch/x86_64/boot.rs` |
| 1,398 | `themis/capavisor/src/arch/x86_64/vmexit.rs` |
| 975 | `themis/capavisor/src/main.rs` |
| 755 | `themis/capavisor/src/arch/x86_64/acpi.rs` |
| 686 | `themis/capavisor/src/arch/x86_64/vmcs.rs` |
| 618 | `themis/capavisor/src/guest/linux.rs` |
| 529 | `themis/capavisor/src/arch/aarch64/vectors.rs` |
| 379 | `themis/capavisor/src/attestation.rs` |
| 377 | `themis/capavisor/src/arch/aarch64/stage2.rs` |
| 360 | `themis/capavisor/src/arch/x86_64/x86_platform.rs` |
| 299 | `themis/capavisor/src/monitor.rs` |

## Long functions

Functions exceeding 100 lines in `themis/capavisor/src/`:

### `arch/x86_64/boot.rs::platform` — lines 89-664, 576 lines

- **What it does:** Discovers memory, builds UC ranges, e820 entries, passthrough regions, ACPI/DMAR/TPM data, CPU topology, memory partitioning, and platform boot metadata.
- **Extraction proposal:**
  - `build_uc_ranges(entries)` (~120-137): collect MMIO regions for uncacheable EPT mappings.
  - `build_e820_and_passthrough(entries)` (~139-190): produce non-RAM e820 records and passthrough regions.
  - `add_fixed_mmio_regions(...)` (~192-230): add ISA hole, APIC, IOAPIC, HPET, TPM ranges.
  - `discover_acpi(rsdp_phys, hhdm_offset)` (~ACPI-heavy middle section): parse MADT/DMAR/TPM2 and return an ACPI summary.
  - `partition_physical_memory(inventory, acpi, cpu_count)` (~tail): compute META/COMM/dom0 regions.
- **Smells:** Boot policy, hardware discovery, memory accounting, and guest-visible e820 construction are interleaved. Several fixed MMIO addresses are inline.

### `arch/x86_64/boot.rs::init_themis` — lines 752-1171, 420 lines

- **What it does:** Initializes `ThemisPlatform`, registers dom0, maps META, initializes VT-d interrupt remapping, builds DomainComm metadata, and prepares platform-side state.
- **Extraction proposal:**
  - `bootstrap_root_domain(platform, info)` (~756-768): register root domain and give META.
  - `log_meta_layout(info)` (~770-793): logging only.
  - `init_interrupt_remapping_tables(platform, acpi)` (~795-858): allocate/write IRTA tables.
  - `enable_interrupt_remapping(platform)` (~860 onward): issue GCMD/SIRTP/IRE commands.
  - `init_dom0_domcomm(platform, info)` (~DomainComm tail): map/setup DomainComm pages.
- **Smells:** Device MMIO programming and high-level domain bootstrap live in one function. VT-d register offsets and command bits should be grouped in an `iommu` module.

### `main.rs::_start_rust` — lines 549-897, 349 lines

- **What it does:** AArch64 direct-boot path: serial, FDT parsing, MMU/EL2 setup, Stage-2 mappings, module discovery, FDT patching, and entering Linux.
- **Extraction proposal:**
  - `locate_fdt(fdt_ptr)` (~568-583): validate supplied FDT or scan known RAM base.
  - `parse_aarch64_fdt(fdt_addr)` (~593-664): discover RAM and GIC data.
  - `setup_el2_runtime()` (~666-678): MMU, vectors, EL2 regs, VTCR.
  - `load_boot_descriptor(image_end)` (~699-743): parse modules and locate kernel/initrd/FDT.
  - `build_stage2_map(layout)` (~764-830): map RAM and devices.
- **Smells:** Development-only AArch64 path contains many QEMU magic addresses and comments that belong in constants/layout structs.

### `hypercall.rs::do_switch` — lines 1082-1390, 309 lines

- **What it does:** Implements `THEMIS_SWITCH`: snapshots dirty COMM regs, validates register writes, switches capability run state, swaps active VMCS from parent to child, drains software PIR pending interrupts, applies VMCS register writes, and handles interrupt-return bookkeeping.
- **Extraction proposal:**
  - `snapshot_dirty_comm_regs(platform, caller, child_handle, vp_idx)` (~1101-1159): read/clear COMM dirty masks and return validated pending writes.
  - `resolve_switch_target(platform, caller, child_handle, vp_id)` (~1161-1185): call `Capability::switch` and resolve child/parent domains.
  - `swap_parent_to_child_vcpu(platform, vcpu, switch_ctx, vp_idx)` (~1187-1254): deactivate parent, activate child, update PID/IRTE NDST.
  - `drain_software_pir(platform, child_active)` (~1261-1345): snapshot PIR, inject one vector, restore remaining bits, update interrupt-window exiting.
  - `apply_pending_regs(child_active, pending)` (~1204-1212 and 1347-1350): split GPR vs VMCS writes and apply at the correct phase.
- **Smells:** Very high risk mixed abstraction levels. The capability transition, raw `ptr::read/write`, VMCS activation, PID/PIR internals, debug doorbell traces, and register marshalling are all in one function. It also has ad-hoc rollback attempts (`Capability::switch(caller, 0, 0, platform)`) that deserve a named helper or engine API.

### `arch/x86_64/boot.rs::capa` — lines 1219-1490, 272 lines

- **What it does:** Creates root capability state, memory capabilities, passthrough capabilities, META/COMM capabilities, and initial dom0 domain/VP policy.
- **Extraction proposal:**
  - `create_root_domain(info)` (~1227-1233): initialize root domain object.
  - `add_dom0_ram_caps(root, partition)` (~1236-1264): add RAM capabilities.
  - `add_passthrough_caps(root, passthrough_regions)` (~1266-1295): add MMIO/firmware caps.
  - `add_meta_caps(root, meta_regions)` (~1297-1323): mark META capabilities.
  - `create_comm_capability(root, comm_region)` (~1325 onward): create and carve COMM root.
- **Smells:** Capability model construction is sound but verbose. Hardware-derived regions and capability table mutation are mixed directly with logging.

### `hypercall.rs::do_add_vp` — lines 799-1068, 270 lines

- **What it does:** Handles `ADD_VP`: resolves child, preallocates VMCS/VAPIC/PID/MSR/IO bitmap META pages, initializes PID/VAPIC/bitmaps, calls engine `add_vp`, sets up child VMCS, and stores the inactive VCPU.
- **Extraction proposal:**
  - `resolve_child_domain_id(caller, child_handle)` (~809-823): common child-handle resolver.
  - `allocate_vp_meta(platform, child_domain_id)` (~825-894): allocate VMCS/VAPIC/PID/MSR/IO bitmaps and return a `VpMetaPages` struct.
  - `init_pid_page(pid_phys, hhdm)` (~896-901): zero PID.
  - `init_vapic_page(vapic_phys, hhdm, vp_idx)` (~903-926): write initial APIC registers.
  - `init_child_bitmaps(msr_bitmap_phys, io_a, io_b, hhdm)` (~928-993): initialize IO/MSR bitmap policy.
- **Smells:** A1 is slightly obscured: META allocation and hardware page initialization happen before engine `add_vp`, then rolled back on failure. This may be intentional for META allocation, but it should be isolated and documented as preallocation, not interleaved in the handler.

### `arch/x86_64/vmcs.rs::write_control_fields` — lines 200-458, 259 lines

- **What it does:** Writes VMCS execution, exit, entry, EPT, VPID, APIC, bitmap, preemption timer, and posted-interrupt control fields.
- **Extraction proposal:**
  - `write_pinbased_controls(child)` (~211-228): pin controls.
  - `write_primary_controls(child)` (~229-247): primary proc controls.
  - `write_secondary_controls(child, apic_access_phys)` (~248-285): secondary controls and APIC access support.
  - `write_entry_exit_controls(child)` (~293-323): VM-entry/VM-exit controls.
  - `write_bitmap_and_interrupt_controls(...)` (~384-458): IO/MSR bitmaps, timer, posted interrupt fields.
- **Smells:** Dense bitmask construction with many raw `1 << N` values. Use named bit constants grouped by VMCS control category.

### `hypercall.rs::forward_child_exit` — lines 1485-1727, 243 lines

- **What it does:** Returns from child to parent on forwarded exits: reads ExitPolicy read-set, calls `switch_return_with_exit`, writes filtered registers and intercept message to the child COMM page, optionally decodes MMIO instruction bytes, advances child RIP, swaps VMCS to parent, and returns SWITCH results to parent.
- **Extraction proposal:**
  - `compute_forwarded_exit_read_set(child_cap, exit_reason)` (~1505-1510): policy read-set lookup.
  - `marshal_intercept_message(platform, vcpu, child_arc, child_vp_id, exit_reason, read_set)` (~1523-1645): all COMM-page register/intercept writeback.
  - `decode_io_exit(exit_qual, vcpu)` (~1564-1584): shared IO qualification decoder.
  - `copy_ept_fault_instruction(platform, vcpu, child_arc, msg)` (~1604-1639): MMIO instruction-byte fetch.
  - `swap_child_to_parent_vcpu(platform, vcpu, return_ctx)` (~1657-1727): deactivate child, activate parent, update PID, set return regs, advance parent RIP.
- **Smells:** This function is the central example of mixed concerns: engine state transition, COMM ABI, VMCS reads, x86 decode, pointer ownership tricks, and quantum-sched injection are interleaved. It also locally redefines `EXIT_REASON_EPT_VIOLATION = 48` and `IO_EXIT_REASON = 30` instead of using `vmexit` constants.

### `guest/linux.rs::load_linux` — lines 415-618, 204 lines

- **What it does:** Loads bzImage and initrd, writes command line and boot params, builds e820, and returns Linux entry info.
- **Extraction proposal:**
  - `copy_protected_mode_kernel(kernel, hdr, hhdm)` (~435-454).
  - `place_initrd_high(initrd, dom0_regions, hhdm)` (~456-504).
  - `write_cmdline(cmdline, hhdm)` (~506-514).
  - `build_dom0_e820(dom0_regions, meta_regions, non_ram, comm_region)` (~535-598).
  - `write_boot_params(bp, hhdm)` (~600-604).
- **Smells:** Boot layout policy, copying bytes, debug hex dumps, and e820 synthesis are coupled. The initrd debug dump should be removed or hidden behind a debug flag.

### `platform.rs::apply_update` — lines 1591-1790, 200 lines

- **What it does:** Materializes capability-engine `Update`s into platform state: domain registration, META accounting, EPT/SLPT mapping, revocation cleanup, zeroing, TLB flush, and COMM-region registration.
- **Extraction proposal:**
  - `apply_create_domain(domain_id, parent_id)` (~1593-1598).
  - `apply_give_meta(domain_id, start, size)` (~1600-1616).
  - `apply_change_rights(update)` (~1618-1709): map/unmap EPT and IOMMU SLPT.
  - `apply_revoke_domain(domain)` (~1716-1727): free EPT/SLPT/domain state.
  - `apply_comm_region(update)` (~1750-1778): VP/domain COMM accounting.
- **Smells:** This is intentionally the hardware-write choke point (A1), so splitting must preserve locality, but the large match currently hides dangerous details (e.g., LAPIC sentinel GPA `0xFEE0_0000`, `u32::MAX` COMM sentinel, IOMMU mirror mapping).

### `hypercall.rs::forward_interrupt_to_handler` — lines 2009-2205, 197 lines

- **What it does:** Handles external interrupt forwarding: checks interrupt policy, optionally injects directly, routes interrupt via `SwitchManager`, performs lazy-unwind state transition, copies filtered regs to COMM page, swaps child to handler VMCS, injects vector if IF/unblocked, and returns `ERR_RETRY` to handler.
- **Extraction proposal:**
  - `classify_interrupt_delivery(platform, child_cap, vector)` (~2025-2078): return direct-deliver vs route-to-handler.
  - `route_interrupt_handler(platform, child_cap, vector, core_id)` (~2080-2092): wrap `route_interrupt` and fallback behavior.
  - `copy_interrupt_read_set_to_comm(platform, vcpu, intr_ctx, read_set)` (~2123-2152): shared COMM register copy.
  - `swap_interrupted_to_handler(platform, vcpu, intr_ctx)` (~2154-2177): deactivate child, activate handler, update PID NDST.
  - `inject_or_defer_vector(handler_active, vector)` (~2179-2191): IF/blocking guard and injection.
- **Smells:** Direct-delivery policy, handler routing, engine lazy-unwind, VMCS swapping, and debug prints are all in one function. This should be one of the first refactors after extracting common VMCS swap/COMM helpers.

### `hypercall.rs::do_attest_self` — lines 522-713, 192 lines

- **What it does:** Builds unsigned or signed structured attestation, dequeues an `AttestRequest`, signs digest, optionally TPM-quotes, and enqueues report chunks through DomainComm.
- **New target — common-base wire format with signed-as-extension:**

  ```
  Common base (= today's unsigned, unchanged for parser compatibility):
    [AttestReport hdr 40B]    — flags |= DOMCOMM_ATTEST_F_SEALED on signed path
    [MemCapEntry × nr_mem_caps]
    [DomCapEntry × nr_dom_caps]
    [PaMapEntry  × nr_pa_entries]

  Signed payload = common base + signed envelope tail:
    [ … common base above, unchanged … ]
    [SignedEnvelope 98B] {
        signature[64]   — Ed25519 over (common_base ‖ nonce ‖ user_pub_key)
        pub_key[32]
        nonce[32]
        user_pub_key[32]
        tpm_quote_size u16 | tpm_sig_size u16 | ak_pub_size u16 | reserved u16
    }
    [tpm_quote] [tpm_sig] [ak_pub]
  ```

  Discriminator: `flags & DOMCOMM_ATTEST_F_SEALED` (in-band, no more total-size guessing). Envelope offset is computed from header counts: `40 + nr_mem_caps*40 + nr_dom_caps*16 + nr_pa_entries*24`.

- **Why this shape:**
  - **Single source of truth** for header serialization (`StructuredAttestation::to_bytes()` already exists in `capa-engine/src/attest.rs:105`); kills the manual hypercall-side struct-literal duplicate at `hypercall.rs:538-549`.
  - **Signature now covers the cap inventory** — today's Ed25519 only signs the 40-byte header + nonce + user_pub_key; cap entries and TPM blobs are *not* under the signature (security gap).
  - **`DOMCOMM_ATTEST_F_SEALED` becomes live** — defined in `domcomm.rs:48`, never set anywhere today; receiver currently discriminates by total payload size (brittle).
  - **`SignedAttestReport` (208 B fused struct) goes away**; `AttestReport` is the one true header. `SignedEnvelope` (98 B) is the per-signature appendix.
  - **Unsigned parser unchanged** — critical because dom0's `thhv_translate.c:516 thhv_pa_map_init_from_attestation` walks `[mem_caps → dom_caps → pa_map]` at boot to learn its capability handles. Without that report dom0 cannot CARVE memory to create dom1.

- **Helper extraction inside `do_attest_self` (~200 LOC → ~60 LOC):**
  - `build_attest_header(attest, sealed: bool) -> domcomm::AttestReport`.
  - `serialize_common_base(attest, out: &mut Vec<u8>)` — wraps `to_bytes()`.
  - `consume_attest_request(platform, domain_id, expected_seq)` — TX dequeue + validation.
  - `build_signed_envelope(common_base_bytes, attest_req, tpm_result) -> Vec<u8>`.
  - `with_locked_domcomm<R>(platform, domain_id, f)` — replaces the dup at L552-559 / L684-691.
  - `enqueue_attest_chunk(pd, payload, offset) -> HypercallResult` — shared chunking tail.

- **Coordinated cross-component update (single phase, one commit per crate):**
  1. `themis-abi/src/domcomm.rs`: drop `SignedAttestReport`, add `SignedEnvelope` (98 B), update size-assertions, document SEALED semantics.
  2. `capa-engine/src/attest.rs`: keep `to_bytes()` (it's already correct); add `to_bytes_into(&self, out: &mut Vec<u8>)` if useful for the envelope-hash-input path.
  3. `themis/capavisor/src/hypercall.rs`: rewrite `do_attest_self` per the helpers above.
  4. `thhv/inc/thhv.h`: add `struct domcomm_signed_envelope`; remove the stale "168 bytes" comment at L927; clarify `domcomm_attest_report` doc to note the optional envelope tail.
  5. `thhv/test/test_attestation.c`: update verifier — envelope offset is computed from the header, signature input is `entire_common_base || nonce || user_pub_key`.
  6. **No kernel-driver changes** (`thhv_main.c` is pure pass-through to userspace).

- **Critical preservation:** the dom0 bootstrap path in `thhv/src/thhv_translate.c:516 thhv_pa_map_init_from_attestation` uses the **unsigned** attestation today and parses `[hdr][mem_caps][dom_caps][pa_map]` by hardcoded order. This refactor preserves that exact unsigned wire format. Any change to the entry order or header layout breaks dom0 boot and therefore dom1 creation.

- **Three side-issues to flag separately (NOT blocking this refactor):**
  1. **Kernel does not reassemble multi-chunk reports.** `thhv_pa_map_init_from_attestation` calls `domcomm_rx_dequeue` once into a 4080 B buffer (`thhv_translate.c:553`); same for `thhv_main.c:196`. The capavisor's offset-chunking in `do_attest_self` is therefore functionally dead today. Either wire reassembly into the kernel or document/assert a hard 4080 B cap. For typical dom0 sizing (~5-10 mem_caps + a few pa_map ranges) this is silently fine, but it's a brittle assumption that will break the first time a dom0 has many capabilities.
  2. **`chunk_index`/`total_chunks` are dead fields.** Hardcoded `(0, 1)` in `capa-engine/src/attest.rs:127-128` and in the signed branch. Either wire to (1) or remove from the wire format.
  3. **`DOMCOMM_ATTEST_F_SEALED` never set today.** Fixed by this refactor.

- **Smells:** Cryptographic envelope construction, TPM operations, DomainComm queue I/O, and hypercall return conventions are mixed. TPM quote buffers are fixed-size magic arrays.

### `main.rs::_start` — lines 223-405, 183 lines

- **What it does:** x86 entry: heap/serial/attestation setup, Limine response parsing, platform discovery, TPM probe, ThemisPlatform/capability/VMCS initialization, Linux module loading, core context setup, and monitor launch.
- **Extraction proposal:**
  - `init_heap_and_serial()` (~223-246).
  - `measure_capavisor_binary()` (~248-279).
  - `read_limine_boot_info()` (~281-312).
  - `build_capavisor_state(boot_info)` (~314-355).
  - `init_core_contexts(platform, root_domain, cpus)` (~371-398).
- **Smells:** Mostly orchestration, but still too much inline detail and logging. Split by boot phase to make the high-level lifecycle readable.

### `mem/inventory.rs::partition` — lines 132-273, 142 lines

- **What it does:** Computes META/COMM reservation size, carves it from top of usable RAM, adjusts dom0-owned memory, and splits reserved memory into COMM + META regions.
- **Extraction proposal:**
  - `estimate_meta_pages(available, fixed_pages, comm_pages)` (~144-159).
  - `reserve_top_of_ram(total_reserved)` (~164-217).
  - `remove_reserved_from_dom0_owned(...)` (~201-216).
  - `split_comm_from_meta(reserved_regions, comm_pages)` (~225-258).
- **Smells:** Arithmetic-heavy memory layout code with implicit page-size constants. It is a correctness-sensitive allocator and should use typed page-size helpers.

### `arch/x86_64/acpi.rs::strip_dmar` — lines 623-755, 133 lines

- **What it does:** Copies or rewrites ACPI DMAR table content so dom0 sees an appropriate view without conflicting with capavisor-owned VT-d state.
- **Extraction proposal:**
  - `parse_dmar_header(table)` (~623-640): validate and expose header fields.
  - `copy_allowed_dmar_entries(...)` (~mid-function): filter entries.
  - `recompute_sdt_checksum(...)` (~tail): fix checksum.
  - `write_stripped_dmar(...)`: separate byte copy from policy.
- **Smells:** Byte-level ACPI parsing and policy filtering are in one routine. Needs stronger typed structs for DMAR subtables.

### `arch/x86_64/vmexit.rs::handle_cpuid_local` — lines 797-925, 129 lines

- **What it does:** Implements local CPUID behavior, masks unsupported/undesired features, returns Themis custom leaves, DomainComm discovery, limits, and fallback values.
- **Extraction proposal:**
  - `mask_host_cpuid_features(leaf, subleaf, regs)` (~806-842): generic feature masking.
  - `handle_themis_cpuid_leaf(platform, leaf, subleaf)` (~843-903): custom leaves.
  - `handle_debug_cpuid_leaf(leaf)` (~904-909): debug range behavior.
  - `handle_tsc_cpuid_leaf()` (~910-916): leaf `0x15` constants.
- **Smells:** Policy decisions and low-level CPUID register values are inline. Custom leaves should move to `themis-abi` or an ABI-owned module so CHV/thhv/capavisor agree.

### `arch/aarch64/boot.rs::platform` — lines 53-179, 127 lines

- **What it does:** AArch64 platform discovery stub/path, likely parses memory/device info and returns `PlatformInfo` for the ARM backend.
- **Extraction proposal:**
  - `discover_arm_memory(...)`.
  - `discover_arm_interrupt_controller(...)`.
  - `build_arm_passthrough_regions(...)`.
  - `build_arm_platform_info(...)`.
- **Smells:** AArch64 bringup is still experimental and tends to embed QEMU defaults. Keep ARM-specific constants in a small `layout` module.

### `hypercall.rs::handle_grow` — lines 2426-2550, 125 lines

- **What it does:** Handles DomainComm ring grow messages: parses `GrowRequest`, validates COMM capability, extends RX/TX page list, updates header metadata, and enqueues `GROW_ACK`.
- **Extraction proposal:**
  - `parse_grow_request(payload)` (~2435-2451).
  - `validate_grow_request(req)` (~2461-2466).
  - `resolve_comm_memory_cap(caller, cap_handle)` (~2468-2501).
  - `append_ring_pages(pd, is_rx, hpa_start, nr_pages)` (~2514-2534).
  - `send_grow_ack(pd, status/new_count/new_capacity)` (~2536-2550).
- **Smells:** Domain-supplied ring growth, capability lookup, and direct shared-memory header mutation are mixed. Hardcoded `256` page cap and `0x1000` page size should be named.

### `attestation.rs::try_tpm` — lines 196-309, 114 lines

- **What it does:** Maps TPM MMIO, probes TIS/CRB, performs startup, extends PCR, reads PCR, creates AK, and marks TPM state available.
- **Extraction proposal:**
  - `map_tpm_transport(start_method, hhdm)` (~199-229).
  - `probe_and_start_tpm(tpm)` (~239-250).
  - `extend_and_verify_pcr(tpm, measurement)` (~252-282).
  - `create_attestation_key(tpm)` (~284-305).
- **Smells:** Hardware mapping, TPM state-machine operations, and global atomic state updates are in one function. TPM transport sizes (`0x5000`) should be constants in the TPM module.

### `platform.rs::domcomm_tx_dequeue` — lines 647-758, 112 lines

- **What it does:** Reads one message from a domain-produced DomainComm TX ring with bounds checks, padding handling, payload copy, and tail advancement.
- **Extraction proposal:**
  - `read_ring_indices(ring)` (~665-673).
  - `validate_available(head, tail, capacity)` (~675-685).
  - `locate_ring_page(page_hpas, offset, capacity)` (~687-703).
  - `read_msg_header(page, off)` (~704-710).
  - `consume_padding_or_payload(...)` (~712-756).
- **Smells:** Recursive padding handling plus unsafe shared-memory parsing deserves a small ring-buffer abstraction shared with RX enqueue.

### `hypercall.rs::handle_vmcall` — lines 137-248, 112 lines

- **What it does:** Global hypercall dispatcher: reads opcode/args, resolves caller, dispatches every opcode to `do_*`, and handles debug/read PCR/unimplemented cases.
- **Extraction proposal:**
  - `current_hypercall_context(vcpu)` (~137-160): platform/core/caller/opcode/args.
  - `dispatch_memory_hypercall(...)` (~163-171).
  - `dispatch_vp_hypercall(...)` (~175-180, 188-189, 203-210).
  - `dispatch_domcomm_hypercall(...)` (~175-178, 234-238).
  - `dispatch_debug_hypercall(...)` (~212-230).
- **Smells:** Single giant match is manageable now but will keep growing. It should become a submodule dispatch table after `hypercall.rs` split.

### `arch/x86_64/boot.rs::vmcs` — lines 1502-1612, 111 lines

- **What it does:** Allocates and initializes VMCS/VAPIC/PID pages for dom0 VPs, handles AP VMCS setup, and restores BSP VMCS.
- **Extraction proposal:**
  - `allocate_dom0_vp_pages(...)` (~early function).
  - `setup_dom0_bsp_vmcs(...)`.
  - `setup_dom0_ap_vmcs(...)`.
  - `store_dom0_vcpu_slots(...)`.
- **Smells:** Boot-time VMCS setup duplicates ADD_VP concepts and should share `VpMetaPages`/VMCS setup helpers where possible.

### `arch/x86_64/vmexit.rs::handle_ept_doorbell` — lines 1290-1398, 109 lines

- **What it does:** Fast-paths EPT-violation doorbells by matching GPA/size/value, enqueueing a DomainComm notification to parent, and advancing RIP.
- **Extraction proposal:**
  - `decode_ept_write(qual, vcpu)` (~1299-1319): write flag, size, value.
  - `match_doorbell_entry(child_pd, gpa, size, value)` (~1336-1349).
  - `enqueue_doorbell_notify(parent_pd, doorbell_id, gpa, value, size)` (~1372-1386).
  - `parent_domain_for_child(child_arc)` (~1364-1367).
- **Smells:** Debug prints are unconditional (`[DOORBELL-DBG]`), and EPT qualification decoding should be shared with other EPT handlers.

### `arch/x86_64/vmcs.rs::write_guest_state` — lines 568-672, 105 lines

- **What it does:** Writes initial guest segment, descriptor-table, control-register, MSR, PAT, debug, link pointer, and timer VMCS fields.
- **Extraction proposal:**
  - `write_guest_segments()` (~568-611).
  - `write_guest_control_regs()` (~CR0/CR3/CR4 area).
  - `write_guest_msrs_and_pat()` (~MSR/PAT area).
  - `write_guest_misc_state()` (~debug/link/timer fields).
- **Smells:** Magic access-right values (`0xC09B`, `0xC093`, `0x10000`) should be named segment constants.

### `arch/x86_64/vmexit.rs::decode_apic_write_value` — lines 1068-1170, 103 lines

- **What it does:** Fetches the guest instruction bytes at RIP and decodes common MOV encodings to recover an APIC write value.
- **Extraction proposal:**
  - `fetch_guest_instruction(vcpu, platform)` (~1072-1084): GVA→GPA→HPA and copy bytes.
  - `skip_x86_prefixes(buf)` (~1086-1100).
  - `decode_mov_rm32_r32(buf, rex, vcpu)` (~1112-1136).
  - `decode_mov_rm32_imm32(buf)` (~1137-1167).
- **Smells:** Hand-rolled instruction decoder with many opcode/prefix constants; should be isolated and tested or replaced by a tiny decode helper used by MMIO/APIC paths.

### `arch/x86_64/vmcs.rs::write_host_state` — lines 462-564, 103 lines

- **What it does:** Writes VMCS host segment selectors, descriptor tables, sysenter/MSR fields, CRs, RSP/RIP, and host bases.
- **Extraction proposal:**
  - `write_host_segments()`.
  - `write_host_descriptor_tables()`.
  - `write_host_control_regs()`.
  - `write_host_msrs()`.
- **Smells:** Similar to guest state: many low-level VMCS writes and raw MSR constants in one block.

## Hardcoded numbers / magic constants

Recommended rule: keep Intel/AMD architectural numeric values in `arch/x86_64/consts.rs` or focused submodules (`vmcs::controls`, `vmexit::reasons`, `apic::regs`, `io::ports`); shared Themis ABI values should live under `themis-abi` (`opcodes`, `vectors`, `synthetic_exits`, `cpuid`, `domcomm`).

| Finding | Literal | Represents | Recommendation |
|---|---:|---|---|
| `main.rs:83`, `86`, `88` | `0x3F8 + 3`, `0x3F8 + 4`, `0x80`, `0x03` | COM1 UART registers/control values | Move to `serial` constants: `COM1_BASE`, `UART_LCR`, `UART_MCR`, `UART_LCR_DLAB`, `UART_8N1`. |
| `arch/x86_64/boot.rs:198-199` | `0xA0000`, `0x100000` | Legacy ISA/VGA BIOS hole | `arch::x86_64::layout::{ISA_HOLE_BASE, ISA_HOLE_END}`. |
| `arch/x86_64/boot.rs:222-224` | `0xFEC0_0000`, `0xFED0_0000`, `0xFEE0_0000`, `0x1000` | IOAPIC, HPET, LAPIC fixed MMIO pages | `arch::x86_64::layout::{IOAPIC_BASE, HPET_BASE, LAPIC_BASE, MMIO_PAGE_SIZE}`. |
| `platform.rs:1538`, `hypercall.rs:1896` | `0xFEE0_0000` | xAPIC MMIO base used for IPI/PID NDST updates | Reuse `arch::x86_64::layout::LAPIC_BASE`. |
| `platform.rs:1644` | `0xFEE0_0000`, `0x1000` | APIC-access sentinel mapping | `arch::x86_64::layout::{LAPIC_BASE, PAGE_SIZE_4K}`. |
| `arch/x86_64/boot.rs:629`, `attestation.rs:202`, `218` | `0x5000` | TPM TIS/CRB 5-page MMIO window | `tpm2::TPM_MMIO_WINDOW_SIZE` or `tpm2::{TIS_MMIO_SIZE, CRB_MMIO_SIZE}`. |
| `arch/x86_64/boot.rs:285` | `num_cores * 3 + 4` | Per-core VMXON/VMCS? plus shared arch pages | Name as `arch_fixed_meta_pages(num_cores)` with constants for per-core/shared components. |
| `hypercall.rs:828-841`, `868` | `3`, `6` META pages | Per-VP VMCS/VAPIC/PID plus first-VP bitmaps | `VP_META_PAGES`, `FIRST_VP_EXTRA_META_PAGES`; keep in `domain`/`vmcs` module. |
| `hypercall.rs:900` | `64` | Posted Interrupt Descriptor size | `POSTED_INTR_DESCRIPTOR_SIZE`. |
| `hypercall.rs:935-936`, `980`, `platform.rs:689-690`, `715`, `726`, `1763-1765`, `2503`, `2519`, `2532` | `4096`, `0x1000`, `0xFFF` | 4 KiB page size/mask | Use existing `PAGE_SIZE`/`PAGE_MASK` constants; expose as `const PAGE_SIZE_4K: usize/u64`. |
| `hypercall.rs:907-925` | APIC offsets `0x020`, `0x030`, `0x0E0`, `0x0F0`, `0x320`... | VAPIC register offsets and initial values | Move to `apic::{APIC_ID, APIC_VER, APIC_DFR, APIC_SVR, LVT_*}` and `init_vapic_page()`. |
| `hypercall.rs:950-951` | `0x3F8..=0x3FF` | COM1 UART I/O ports trapped for child | `io_ports::COM1_RANGE`. |
| `hypercall.rs:955-958` | `0x40-0x43`, `0x60`, `0x64`, `0x608`, `0xEC` | PIT/i8042/PM timer/CHV timer vector notes | `themis_abi::vectors::CHV_TIMER` for `0xEC`; `io_ports::*` for ports. |
| `hypercall.rs:986-988` | `0x6E0`, `2048`, `/8`, `%8` | IA32_TSC_DEADLINE MSR and MSR write-bitmap low offset | `msr_virt::{IA32_TSC_DEADLINE, MSR_BITMAP_WR_LOW_BASE}` helper. |
| `hypercall.rs:1534`, `1570` | `48`, `30` | EPT violation and I/O instruction exit reasons | Use `crate::arch::vmexit::{EXIT_REASON_EPT_VIOLATION, EXIT_REASON_IO_INSTRUCTION}`. |
| `hypercall.rs:1572-1576` | `0b111`, shifts `3`, `6`, `16`, mask `0xFFFF` | I/O exit qualification fields | `vmexit::decode_io_exit_qualification()`. |
| `hypercall.rs:1618-1620`, `arch/x86_64/vmexit.rs:1082-1084` | `16`, `0x1000`, `0xFFF` | Max instruction bytes and page-crossing limit | `x86_decode::MAX_INSN_LEN`, page constants. |
| `hypercall.rs:1696` | `unwrap_or(3)` | VMCALL instruction length fallback | Prefer `VMEXIT_INSTRUCTION_LEN`; if fallback is needed, `x86::insn::VMCALL_LEN`. |
| `hypercall.rs:1710-1713`, `2185-2188` | `1 << 9`, `0x3`, `1 << 31` | RFLAGS.IF, interruptibility STI/MOVSS bits, VM-entry valid bit | Use existing `RFLAGS_IF`, `INTERRUPTIBILITY_STI_MOV_SS`, `VMENTRY_INTR_INFO_VALID`. |
| `hypercall.rs:2462` | `256` | Maximum pages accepted for DomainComm grow | `domcomm::MAX_GROW_PAGES` in `themis-abi`. |
| `hypercall.rs:2766` | `255` | Max interrupt vector | `MAX_VECTOR` or `u8::MAX as u64`; put in `themis_abi::vectors`. |
| `hypercall.rs:2902` | `0u8..=254` | Program IRTE vectors except 255 | Use `vectors::ALL_DELIVERABLE` or document reserved vector 255. |
| `arch/x86_64/vmcs.rs:70`, `74` | `0x0002`, `0x2016` | VMCS posted-interrupt field IDs | Existing constants are good; move to `vmcs::fields` and avoid raw `as u32` casts elsewhere. |
| `arch/x86_64/vmcs.rs:212-320` | many `1 << N` | VMCS control bits | Define named bit constants: `PIN_ACTIVATE_PREEMPTION_TIMER`, `PROC_USE_MSR_BITMAPS`, `EXIT_ACK_INTERRUPT_ON_EXIT`, etc. |
| `arch/x86_64/vmcs.rs:543-544` | `0xC000_0100`, `0xC000_0101` | IA32_FS_BASE / IA32_GS_BASE MSRs | Use `x86::msr` constants if available or local `msr_consts`. |
| `arch/x86_64/vmcs.rs:585-593` | `0xC09B`, `0xC093`, `0x10000` | Guest segment access-right encodings | `segment::AR_CODE64`, `AR_DATA64`, `AR_UNUSABLE`. |
| `arch/x86_64/vmcs.rs:641` | `0x0007_0406_0007_0406` | IA32_PAT default | `DEFAULT_IA32_PAT`. |
| `arch/x86_64/vmexit.rs:31-79` | `0x800..0x83F`, APIC MSR values | x2APIC MSR register range | Already constants; consider moving to `apic.rs`. |
| `arch/x86_64/vmexit.rs:121-129` | `0x40000000..`, `0xDEAD0000..` | Themis CPUID and debug ranges | Move shared CPUID leaf definitions to `themis-abi::cpuid`. |
| `arch/x86_64/vmexit.rs:827-914` | `0x7`, `0x340`, `25_000_000`, `120` | CPUID XSAVE/TSC leaf emulation | Name as CPUID policy constants or make CHV-provided policy. |
| `arch/x86_64/vmexit.rs:1086-1165` | x86 opcodes/prefixes `0x89`, `0xC7`, `0x40..=0x4F`, etc. | Hand-rolled instruction decode | Move to `x86_decode.rs` with named opcode/prefix constants and tests. |
| `arch/aarch64/fdt_patch.rs:17`, `101-102` | `+3`, `4`, `8` | FDT 4-byte alignment/token sizes | `FDT_ALIGN`, `FDT_PROP_HEADER_SIZE`; not a RIP advance but still magic alignment. |
| `arch/aarch64/*`, `main.rs::_start_rust` | `0x4000_0000`, `0x0800_0000`, `0x0900_0000`, `0x20_0000`, `0x4000_0000` | QEMU virt RAM/GIC/UART/block sizes | Put AArch64 dev layout constants in `arch/aarch64/layout.rs`. |

## Duplicated logic

### VMCS field read/write boilerplate

- **Sites:** `arch/x86_64/vmcs.rs:200-458`, `462-564`, `568-672`; `arch/x86_64/vmexit.rs:419-470`, `797-925`, `1007-1060`; `hypercall.rs:1347-1350`, `1558-1562`, `1693-1697`, `2179-2195`; `arch/x86_64/x86_platform.rs:126-132`, `152-158`, `193-198`.
- **Proposal:** Create `arch/x86_64/vmcs_access.rs` or extend `ActiveVcpu` with typed helpers:
  - `advance_by_vmexit_len(vcpu, fallback: Option<u64>)`
  - `inject_external_interrupt_if_ready(vcpu, vector) -> InjectResult`
  - `read_exit_metadata(vcpu) -> ExitMetadata`
  - `write_switch_return(vcpu, status, rdi)`

### Child-domain handle resolution

- **Sites:** `hypercall.rs:809-823`, `1105-1122`, `2594-2607`, `2649-2662`, `2807-2821`, plus similar manual paths in memory/device handlers.
- **Proposal:** Add `resolve_child_domain(caller, handle) -> Result<(DomainId, CapabilityRef<Domain>), HypercallResult>` in `hypercall/common.rs`. This keeps A9 intact while removing repeated weak-upgrade boilerplate.

### `platform.domain_arc(id).ok_or(...)` / `expect(...)`

- **Sites:** `hypercall.rs:842-845`, `1118-1120`, `1179-1185`, `1223-1226`, `1524-1526`, `1665-1667`, `2124-2126`, `2162-2164`, `2609-2612`, `2664-2667`, `2698-2700`, `2723-2726`, `2823-2826`, `2887-2896`; `platform.rs:1909-1917`, `1942-1950`; `vmexit.rs:1308`, `1369`.
- **Proposal:** Add `platform.require_domain_arc(id, err_context)` returning `Result<Arc<Mutex<PlatformDomain>>, CapaError/HypercallResult>` and use explicit error propagation instead of mixed `expect`/`ERR_NOTFOUND`.

### COMM-page register marshaling

- **Sites:** dirty read path in `do_switch` (`hypercall.rs:1124-1159`), forwarded-exit writeback (`1540-1553`), interrupt read-set copy (`2123-2152`), register access implementation (`platform.rs:1896-1958`).
- **Proposal:** New module `hypercall/comm.rs` or `comm_page.rs`:
  - `comm_page_for_vp(platform, domain_id, vp_id) -> Option<&mut VpCommPage>`
  - `copy_regs_to_comm(vcpu, comm, read_set)`
  - `snapshot_dirty_regs(comm) -> DirtyRegSnapshot`
  - `apply_dirty_regs_to_vcpu(snapshot, inactive/active)`

### DomainComm ring handling

- **Sites:** `platform.rs:560-638` RX enqueue, `platform.rs:647-758` TX dequeue, `hypercall.rs:678-687`, `707-711`, `2536-2550`, `2737-2743`, `vmexit.rs:1380-1386`.
- **Proposal:** A `domcomm_ring` helper with typed `enqueue_msg<T>()`, `enqueue_bytes()`, `dequeue_msg<T>()`, padding handling, and sequence counter support. It should centralize page wrapping and bounds checks.

### I/O exit qualification decoding

- **Sites:** `vmexit.rs:339-344` and `hypercall.rs:1564-1584` independently decode I/O exit qualification.
- **Proposal:** `arch/x86_64/vmexit_decode.rs::decode_io_exit(qual, rdx, rax) -> IoExit` with fields `port`, `size`, `direction`, `value`.

### EPT/MMIO instruction byte fetch

- **Sites:** `hypercall.rs:1604-1639` and `vmexit.rs:1068-1084` both translate guest RIP and copy up to 16 instruction bytes.
- **Proposal:** `x86_decode::fetch_guest_insn(vcpu, platform, ept_root) -> Option<InsnBytes>`.

### VMCS swap / context-switch boilerplate

- **Sites:** parent→child in `do_switch` (`1214-1367`), child→parent in `forward_child_exit` (`1657-1727`), child→handler in `forward_interrupt_to_handler` (`2154-2204`), boot/AP activation in `arch/x86_64/boot.rs:1583-1608`, `1755-1781`, `main.rs:952`.
- **Proposal:** Introduce `VcpuSwap` helper:
  - `deactivate_current_into(platform, vcpu, domain_id, vp_id)`
  - `activate_from_slot(platform, domain_id, vp_id) -> ActiveVcpu`
  - `replace_current_vcpu(vcpu, new_active)`
  - `update_pid_and_irte_destination(active, platform, maybe_child_cap)`

### Interrupt injection readiness checks

- **Sites:** `hypercall.rs:1708-1718`, `2182-2191`, and PIR drain in `1288-1315`.
- **Proposal:** `interrupts::guest_can_accept_interrupt(vcpu) -> bool` and `interrupts::inject_external(vcpu, vector)` using named constants.

### Debug print patterns

- **Sites:** `[DB-*]` prints listed below; high-frequency `[INTR_FWD]`, `[DOORBELL-DBG]`, `[domcomm]`, `[attest]` prints scattered across hot paths.
- **Proposal:** Add feature-gated macros: `trace_doorbell!`, `trace_switch!`, `trace_intr!`, `trace_domcomm!`. Runtime debug should be rate-limited centrally rather than open-coded static counters.

## Mixed concerns

- `hypercall.rs::do_switch` mixes dirty COMM-page marshaling, capability `switch`, VMCS ownership transfer, PID/IRTE hardware updates, software PIR queue draining, register writes, and doorbell debug tracing. Split along `validate/transition`, `marshal`, and `hardware swap` boundaries.
- `hypercall.rs::forward_child_exit` mixes ExitPolicy read-set enforcement, engine return-switch, intercept ABI construction, I/O qualification decoding, EPT instruction-byte decode, RIP advancement policy, and VMCS swap to parent. The intercept ABI should be a pure marshaling helper.
- `hypercall.rs::forward_interrupt_to_handler` mixes interrupt policy lookup, direct-delivery optimization, `SwitchManager` routing, lazy-unwind engine transition, COMM register copy, VMCS swap, injection readiness checks, and diagnostics.
- `platform.rs::apply_update` is necessarily the hardware-write choke point, but the `ChangeRights` arm mixes EPT mapping, IOMMU SLPT mirroring, LAPIC sentinel detection, hardware feature probing, and logging. Keep `apply_update` as the dispatch point but extract each update into a small method.
- `arch/x86_64/vmexit.rs::classify_and_handle_internal` and `handle_local_exit` mix semantic exit classification, local hardware emulation, policy forwarding setup, doorbell fast-path, and debug/fatal dumping. Classification should be side-effect-light; local emulation should be separate.
- `arch/x86_64/boot.rs::{platform,init_themis,capa,vmcs}` mix boot hardware discovery, capability-state construction, platform allocator setup, VT-d programming, and guest boot ABI construction. Boot phases should be explicit modules.
- `hypercall.rs::do_add_vp` is a subtle A1/A5 area: preallocates and initializes META pages before engine `add_vp`, then rolls back. Encapsulate this as a `PreparedVpMeta` RAII-like object with `commit()`/`rollback()` semantics so the exception to normal ordering is obvious and auditable.

## Debug instrumentation cleanup

All current `[DB-*]` prints greppable as `\[DB-`:

| File:line | Tag | Current purpose | Cleanup recommendation |
|---|---|---|---|
| `arch/x86_64/x86_platform.rs:87` | `[DB-ENTRY]` | Doorbell re-entry VMENTER RIP trace | Remove after doorbell fix or gate behind `feature = "doorbell-trace"`. |
| `arch/x86_64/x86_platform.rs:100` | `[DB-EXIT]` | Doorbell post-exit reason/RIP trace | Same feature gate; use `trace_doorbell!`. |
| `monitor.rs:231` | `[DB-INTR]` | Logs external interrupt routing decision while doorbell trace count active | Remove or feature-gate; do not leave in generic monitor. |
| `hypercall.rs:1095` | `[DB-SWITCH]` | Logs `do_switch` invocation while doorbell tracing | Remove or feature-gate. |
| `hypercall.rs:1167` | `[DB-SWITCH]` | Logs failed `Capability::switch` during doorbell trace | Replace with normal `serial_debug!` if still useful. |
| `hypercall.rs:1377` | `[DB-TRACE]` | Child re-entry state dump after doorbell | Remove or feature-gate; currently in hot SWITCH path. |
| `hypercall.rs:2052` | `[DB-FWD]` | Interrupt forward trace during doorbell debugging | Remove or feature-gate. |

Related non-`[DB-*]` doorbell debug that should be reviewed in the same cleanup:

- `arch/x86_64/vmexit.rs:1329`, `1353`, `1357` — `[DOORBELL-DBG]` unconditional prints.
- `hypercall.rs:2746` — `[CAPAVISOR] A doorbell rung` unconditional print.
- `hypercall.rs:2034-2048` — `FWD_COUNT` rate-limited diagnostic in `forward_interrupt_to_handler`.

## Module boundaries

`hypercall.rs` should stop being a 3,073-line omnibus. Suggested split:

```text
themis/capavisor/src/hypercall/
├── mod.rs              # public handle_vmcall(), common types, dispatch table
├── common.rs           # HypercallContext, error mapping, child/domain resolution
├── memory.rs           # CARVE, ALIAS, SEND, ACCEPT, REJECT, REVOKE_MEM, MAP_SELF
├── domain.rs           # CREATE_DOMAIN, SEAL, REVOKE_DOMAIN, SET_POLICY
├── vp.rs               # ADD_VP, GET_REG, SET_REG, register mapping helpers
├── switch.rs           # SWITCH, forward_child_exit, VcpuSwap helpers
├── interrupt.rs        # INJECT_INTERRUPT, forward_interrupt_to_handler, IRTE helpers
├── comm.rs             # REGISTER_COMM, DomainComm notify/grow, COMM-page marshal
├── doorbell.rs         # REGISTER/UNREGISTER/RING doorbell and EPT doorbell helpers
├── device.rs           # ASSIGN_DEVICE, RELEASE_DEVICE
└── attest.rs           # ATTEST_SELF, READ_PCR glue
```

Boundary rules:

- `mod.rs` owns only dispatch and context extraction.
- `common.rs` owns repeated handle resolution and error mapping.
- `switch.rs` owns VMCS swap helpers used by SWITCH, forwarded exits, and interrupt forwarding.
- `comm.rs` owns `VpCommPage` register copy/dirty-mask logic and DomainComm ring wrappers.
- `doorbell.rs` owns both VMCALL ring-doorbell and EPT-violation doorbell matching, so the two paths stay consistent.
- `interrupt.rs` owns interrupt policy routing glue but should still call the capability-engine interface for state transitions (A9).

## Prioritized cleanup checklist

1. **Remove/gate doorbell debug prints**: delete or feature-gate all `[DB-*]`, `[DOORBELL-DBG]`, and `[CAPAVISOR] A doorbell rung` prints. Lowest risk, immediate signal/noise improvement.
2. **Introduce shared constants**: add named constants for page size/masks, LAPIC/IOAPIC/HPET bases, VMCALL length fallback, interrupt info bits, RFLAGS.IF, and common vectors. Replace only obvious local literals first.
3. **Extract I/O exit decoder**: replace duplicate decoding in `vmexit.rs` and `forward_child_exit` with `decode_io_exit_qualification()`.
4. **Extract interrupt injection readiness helper**: centralize IF/blocking checks and `VMENTRY_INTERRUPTION_INFO_FIELD` construction.
5. **Extract COMM register copy helpers**: implement `copy_regs_to_comm()` and `snapshot_dirty_comm_regs()`; use in `do_switch`, `forward_child_exit`, `forward_interrupt_to_handler`, and platform register access.
6. **Extract child-domain resolution helper**: replace repeated weak-upgrade/domain-id patterns in hypercall handlers.
7. **Extract VMCS swap helper**: create a small `VcpuSwap` abstraction for deactivate/store/activate/update-PID/replace-current. Apply first to `forward_child_exit`, then `forward_interrupt_to_handler`, then `do_switch`.
8. **Split `hypercall.rs` module shell**: create `hypercall/mod.rs` plus `common.rs`; move functions in small batches without logic changes.
9. **Move doorbell code to `hypercall/doorbell.rs`**: unify EPT doorbell and VMCALL ring-doorbell notification construction.
10. **Move interrupt forwarding to `hypercall/interrupt.rs`**: after VMCS swap and injection helpers exist, relocate `forward_interrupt_to_handler`, `inject_via_pid`, `sync_irte_ndst`, and IRTE programming.
11. **Move SWITCH/forward-exit to `hypercall/switch.rs`**: extract `do_switch` and `forward_child_exit`; keep public wrappers stable.
12. **Extract `do_add_vp` preparation object**: create `PreparedVpMeta` with rollback/commit semantics to make META preallocation auditable.
13. **Extract `platform.rs::apply_update` arms**: keep `apply_update` as a match, but delegate to `apply_change_rights`, `apply_comm_region`, etc.
14. **Refactor DomainComm rings**: introduce typed enqueue/dequeue helpers, remove recursive padding handling, add named max grow/page constants.
15. **Refactor VMCS controls**: replace raw `1 << N` bitmasks in `vmcs.rs` with named constants grouped by VMCS control class.
16. **Refactor `arch/x86_64/boot.rs::platform`**: split memory map/e820/passthrough/ACPI/platform-info construction.
17. **Refactor `arch/x86_64/boot.rs::init_themis`**: move VT-d interrupt remapping initialization into `iommu_ir`/`vtd` helpers.
18. **Refactor CPUID ABI constants**: move Themis CPUID leaves and capacity constants to `themis-abi` or an ABI module shared with CHV/thhv.
19. **Isolate x86 instruction decode**: move APIC/MMIO instruction-byte fetch and MOV decode to a small testable module.
20. **Refactor boot entrypoints**: split `main.rs::_start` and AArch64 `_start_rust` into phase functions once lower-risk hot-path cleanup is complete.
