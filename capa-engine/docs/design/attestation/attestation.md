# Themis Attested Boot — Design Document

## 1. Overview

Themis's attestation scheme has two interlocking parts (from the EuroS&P paper §4, §5.1):

1. **Hardware root of trust** — the bootloader measures the capavisor binary, boot-info,
   and attestation public key into a TPM PCR, binding the capavisor to the physical machine.
2. **Signed domain reports** — capavisor signs domain attestation reports with the private
   key established at boot.  A verifier receives both the TPM quote (proves key binding)
   and the signed domain report (proves TD configuration).

Together these allow a remote verifier to establish:
- This exact capavisor binary is running on this physical machine (TPM quote + PCR value).
- The domain's resource configuration is exactly as described (signed domain report).
- The signing key is the same key measured in the TPM PCR (binding chain).

---

## 2. Current State

| Component | Location | Status |
|-----------|----------|--------|
| `AttestReport` struct (domain config blob) | `themis-abi/src/domcomm.rs` | Done |
| `attest_domain()` in capability engine | `capability_engine::attest` | Done |
| `do_attest_self` hypercall (0x0C) | `capavisor/src/hypercall.rs` | Done (signed) |
| `THEMIS_ATTEST` (0x0D) hypercall dispatch | `hypercall.rs` | Done |
| Ed25519 keygen + SHA-256 measurement | `capavisor/src/attestation.rs` | Done |
| TPM 2.0 TIS MMIO driver | `themis/crates/tpm2/` | Done |
| QEMU swtpm integration | `scripts/setup-swtpm.sh`, `run-qemu.sh` | Done |
| thhv ioctls (ATTEST_SELF, READ_PCR) | `thhv/` | Done |
| On-demand attestation (driver requests) | `thhv/` + `capavisor/` | Done |
| **TPM MMIO probe from ACPI** | `capavisor/src/acpi.rs` | **In progress** |
| **TPM exclusion from dom0 EPT** | `capavisor/src/boot.rs` | **In progress** |

**Remaining work** (§13):
- Parse ACPI TPM2 table for TPM discovery (replace memory-map scan)
- Map TPM MMIO via `map_phys_range()` before probing
- Exclude TPM region from dom0's EPT passthrough (capavisor-exclusive)
- Test end-to-end with swtpm (PCR extend + readback)

---

## 3. Threat Model (from paper §3.2)

The hardware (CPU, TPM, physical devices) is trusted and part of the TCB.
The capavisor binary and bootloader are part of the TCB.
**Dom0 is not trusted** — it must not be able to forge attestations or learn the private key.

Consequences:
- The attestation private key **must never enter dom0's address space**.
- It lives in capavisor's META pool (not mapped into any domain's EPT).
- Key generation happens **before** control is handed to capavisor, and before dom0 exists.

---

## 4. Attested Boot Flow

```
[Physical boot]
  UEFI/firmware → Limine bootloader
       │
       ├─ Enumerate CPUs, DRAM, devices → build boot-info
       ├─ Generate attestation key pair (Ed25519, seeded from RDRAND/RDSEED)
       ├─ Compute: measurement = SHA-256(capavisor_binary ‖ boot_info ‖ pub_key)
       ├─ TPM2_PCR_Extend(PCR=11, hash_alg=SHA-256, digest=measurement)
       ├─ Load capavisor binary into reserved META memory
       └─ Jump to capavisor entry with {boot_info, private_key_bytes} in known location

[Capavisor boot — capavisor/src/main.rs]
       │
       ├─ Read private_key_bytes from boot handoff region
       ├─ Store in AttestedKey (inside META, never in any domain EPT)
       ├─ Zero the boot handoff region (key hygiene)
       └─ Proceed with normal boot (init capability engine, create dom0, ...)

[Domain attestation — do_attest_self / do_attest]
       │
       ├─ capability_engine::attest::attest_domain(caller) → AttestReport
       ├─ Serialize report to bytes
       ├─ signature = Ed25519_sign(private_key, SHA-256(report_bytes ‖ nonce))
       └─ Deliver {report, signature, pub_key} via DomainComm RX ring

[Remote verification]
       │
       ├─ Obtain TPM quote (TPM2_Quote PCR=11) → quote includes PCR[11] value
       ├─ Verify quote signature against platform EK/AIK certificate chain
       ├─ Check PCR[11] == SHA-256(expected_capavisor ‖ expected_boot_info ‖ pub_key)
       └─ Verify domain report signature against pub_key from PCR[11]
```

---

## 5. Key Algorithm Choice

**Ed25519** (Edwards-curve Digital Signature Algorithm over Curve25519):

- Available in `no_std` via `ed25519-dalek` crate (feature `no_std` + `alloc`-free mode)
- 32-byte private key, 32-byte public key, 64-byte signature — compact for report fields
- Fast: ~10µs sign, ~50µs verify on x86_64
- Well-audited, widely deployed

Alternative: P-256 (NIST curve) — better interop with TPM attestation key formats, but
slower and more complex to implement in no_std.  **Ed25519 chosen for initial implementation**;
can be extended to P-256 for production TPM key binding.

Hash: **SHA-256** via `sha2` crate (no_std support).

---

## 6. Boot Handoff Mechanism

The bootloader must pass the Ed25519 private key to capavisor.  Two options:

**Option A (chosen): Limine boot module**
- Bootloader writes a fixed-layout `BootAttestation` struct into a dedicated Limine
  boot module (type tag `THEMIS_ATTEST_MODULE`).
- Capavisor reads it from the Limine module list in `main.rs` / `boot.rs`.
- The region is zeroed after reading.

**Option B: Reserved physical memory page**
- Bootloader writes to a hardcoded physical address (e.g., 0x1000).
- Capavisor reads from that PA at startup.
- Simpler but couples to physical memory layout.

Option A chosen for cleanliness.  The struct:
```rust
#[repr(C)]
pub struct BootAttestation {
    pub magic: u64,                     // BOOT_ATTEST_MAGIC = 0x54484D5F41545354 ("THM_ATST")
    pub pub_key: [u8; 32],              // Ed25519 public key
    pub priv_key: [u8; 32],             // Ed25519 private key (ZERO AFTER READING)
    pub measurement: [u8; 32],          // SHA-256(binary ‖ boot_info ‖ pub_key)
    pub pcr_index: u32,                 // PCR index used (default 11)
    pub reserved: [u8; 20],
}                                       // 128 bytes total
```

---

## 7. AttestReport Extension (Signed)

The existing `AttestReport` struct describes TD configuration but has no signature.
Extend with a signed wrapper:

```rust
#[repr(C)]
pub struct SignedAttestReport {
    pub report: AttestReport,           // existing 40-byte struct
    pub signature: [u8; 64],           // Ed25519 signature over SHA-256(report_bytes ‖ nonce)
    pub pub_key: [u8; 32],             // capavisor's attestation public key
    pub nonce: [u8; 32],               // verifier-supplied nonce (from hypercall arg)
}                                       // 168 bytes total
```

The report serialisation for signing:
`SHA-256(report_bytes ‖ nonce)` where `report_bytes` is the flat `AttestReport` struct.

---

## 8. TPM Integration

### PCR Selection

Use **PCR 11** — reserved for OS use by the TPM spec, not touched by UEFI/Limine.
This ensures the PCR starts at 0 and our single extend is the definitive measurement.

PCR extend operation:
```
TPM2_PCR_Extend(
    pcrHandle = TPM2_PT_PCR_11,
    digests = [{ hashAlg = TPM_ALG_SHA256, digest = SHA-256(capavisor ‖ boot_info ‖ pub_key) }]
)
```

### Dev Environment (QEMU + swtpm)

QEMU supports TPM 2.0 emulation via `swtpm`.  The key insight is that QEMU's
`tpm_emulator` backend talks the **PTM protocol** over swtpm's `--ctrl` socket.
Start swtpm with `--ctrl` only (no `--server`), and do NOT pass `--flags startup-clear`
(the firmware sends TPM2_Startup itself).

```bash
# Start swtpm (once, before QEMU) — ctrl socket only
mkdir -p /tmp/themis-swtpm
swtpm socket --tpm2 \
  --ctrl type=unixio,path=/tmp/themis-swtpm/swtpm-sock \
  --tpmstate dir=/tmp/themis-swtpm \
  --log file=/tmp/themis-swtpm/swtpm.log,level=5

# QEMU extra args (chardev connects to the ctrl socket):
-chardev socket,id=chrtpm,path=/tmp/themis-swtpm/swtpm-sock
-tpmdev emulator,id=tpm0,chardev=chrtpm
-device tpm-tis,tpmdev=tpm0
```

> **Bug history**: the original setup used separate `--server` and `--ctrl` sockets
> and connected QEMU's chardev to `--server`.  QEMU sends PTM commands (not raw TPM
> commands) → swtpm's `recv_msg` blocked forever → deadlock.  Fixed in commit
> `9246045` by connecting to `--ctrl` only.

Use `tpm-tis` (not `tpm-crb`) because our driver (`themis/crates/tpm2/`) implements
the TIS FIFO interface.  CRB uses a different register protocol.

Automated: `QEMU_TPM=1 cargo themis` — see `themis/scripts/setup-swtpm.sh` and
`run-qemu.sh` for the integration.

Reading PCR 11 from dom0:
```bash
tpm2_pcrread sha256:11
```

### Real Hardware (TPM 2.0)

Real hardware has a physical TPM 2.0 chip (most x86_64 laptops/servers since 2016).
The capavisor talks to it via:
- **FIFO interface** (TIS — TPM Interface Specification): MMIO at 0xFED40000
- Or **CRB interface** (Command Response Buffer): MMIO at ACPI TPM2 table address

The TIS base address `0xFED40000` is fixed by the TCG PC Client Platform spec.
The ACPI TPM2 table confirms TPM presence and provides the start method.

For dom0 verification: use `tpm2-tools` (`tpm2_quote`, `tpm2_pcrread`).
Note: dom0 cannot access the TPM directly — its MMIO region is excluded from
dom0's EPT (capavisor-exclusive, like META pages).

---

## 9. No-std Crate Dependencies

Add to `themis/capavisor/Cargo.toml` and the bootloader:

```toml
ed25519-dalek = { version = "2", default-features = false, features = ["zeroize"] }
sha2 = { version = "0.10", default-features = false }
rand_core = { version = "0.6", default-features = false }
zeroize = { version = "1", default-features = false }
```

For CSRNG seeding in the bootloader (pre-OS, bare metal):
- Use `RDRAND` / `RDSEED` x86 instructions directly.
- Wrap in a `RngCore` impl for `ed25519-dalek::SigningKey::generate()`.

---

## 10. QEMU Dev vs Real Hardware Summary

| Aspect | QEMU (dev) | Real hardware |
|--------|-----------|---------------|
| TPM | swtpm socket emulator | Physical TPM 2.0 chip |
| PCR extend | `TPM2_PCR_Extend` → swtpm | `TPM2_PCR_Extend` → MMIO TIS/CRB |
| Quote | swtpm-generated quote | Platform EK-signed quote |
| CSRNG | RDRAND (QEMU emulated) | RDRAND (hardware) |
| Verification | swtpm PCR readback | `tpm2_quote` + cert chain |
| TxT / DRTM | Not available | Optional (Intel TxT) |

In QEMU, the quote is self-signed by the swtpm's EK.  For production,
the EK certificate chain roots to the TPM manufacturer CA.

---

## 11. Implementation Plan (Phase 20)

See `todo.md` Phase 20 for tracked items.  Dependency order:

```
P20a (BootAttestation struct + SignedAttestReport in themis-abi)
  │
  ├─► P20b (Limine pre-boot binary: keygen + SHA-256 + PCR extend)
  │     └─► P20c (Pass BootAttestation to capavisor via Limine module)
  │           └─► P20d (Capavisor: read key, store in META, zero handoff)
  │                 └─► P20e (Capavisor: sign AttestReport in do_attest_self)
  │
  └─► P20f (QEMU: swtpm integration in run-qemu.sh / run-dom0.sh)
        └─► P20g (dom0 verification tool: read PCR 11 + verify signed report)
```

P20a–P20h are **done** (see §2).

---

## 12. Open Questions

1. ~~**Limine custom module**~~ — resolved: keygen happens inside capavisor `_start()`
   using RDRAND (no separate pre-boot binary needed).

2. **Key freshness** — Ed25519 key pair is ephemeral (fresh every boot via RDRAND).
   **Implemented as recommended.**

3. ~~**Nonce delivery**~~ — resolved: nonce is passed via DomainComm TX ring (32 bytes
   in the hypercall argument buffer).

4. **DRTM (Intel TxT)** — reduces TCB to just the capability engine, excluding the
   bootloader.  Deferred: prototype with SRTM first, add TxT support later.

---

## 13. TPM MMIO Probe Fix (current work)

### Problem

The capavisor's TPM probe is skipped because:

1. **MMIO not in HHDM** — Limine base revision 3 only maps USABLE, BOOTLOADER,
   KERNEL+MODULES, and FRAMEBUFFER regions in the HHDM.  The TPM TIS MMIO at
   `0xFED40000` is device MMIO — not in any Limine memory map entry — so reading
   it would #PF → triple fault.

2. **Memory map check too conservative** — `main.rs` scans the Limine memory map
   for the TIS base address.  Since device MMIO isn't in the memory map, the check
   fails and TPM is skipped.  This was the correct safety measure but wrong
   discovery mechanism.

3. **TIS vs CRB mismatch** — QEMU was configured with `tpm-crb` but our driver uses
   TIS.  CRB and TIS have different register protocols (CRB uses control area +
   command/response buffers; TIS uses FIFO at offset 0x24).

### Solution

1. **ACPI TPM2 table discovery** — parse the ACPI TPM2 table (signature `"TPM2"`,
   `acpi::sdt::Signature::TPM2`) to confirm TPM presence.  The table contains the
   start method (TIS vs CRB) and control area address.  This replaces the memory-map
   scan.  Same pattern as DMAR parsing in `acpi.rs`.

2. **Explicit MMIO mapping** — call `map_phys_range(tpm_base, 0x5000, hhdm_offset)`
   to add page table entries for the TIS region (5 pages: localities 0–4).  Same
   approach used for DRHD MMIO regions, ECAM, and COMM pages.

3. **Split attestation init** — keygen + measurement stays early in `_start()`.
   TPM probe moves to after `boot::platform()` returns (when ACPI info is available).
   `tpm_available` becomes an `AtomicBool` instead of part of the `Once<>` state.

4. **Dom0 EPT exclusion** — the TPM MMIO region is filtered out of
   `passthrough_regions` in `boot.rs` so it never appears in dom0's EPT.
   This makes the TPM capavisor-exclusive (same as META pages, per axiom A5).

5. **QEMU device type** — switch from `tpm-crb` to `tpm-tis` to match our driver.
   The old "tpm-tis hangs" was actually the wrong-socket bug (§8 bug history).

### ACPI TPM2 table layout (TCG PTP rev 4)

```
Offset  Size  Field
0       36    Standard ACPI SDT header
36       2    Platform Class (0=client, 1=server)
38       2    Reserved
40       8    Address of Control Area (u64; 0 for TIS, CRB base for CRB)
48       4    Start Method (6=MMIO, 7=CRB, 8=CRB+ACPI)
52      12    Start Method Specific Parameters (optional)
```

### File changes

| File | Change |
|------|--------|
| `capavisor/src/acpi.rs` | Parse TPM2 table → `TpmInfo { control_area, start_method }` |
| `capavisor/src/attestation.rs` | Split `init()` / `try_tpm()`, AtomicBool |
| `capavisor/src/main.rs` | Remove memmap scan, wire ACPI → `try_tpm()` |
| `capavisor/src/boot.rs` | Exclude TPM from `passthrough_regions` |
| `scripts/run-qemu.sh` | `tpm-crb` → `tpm-tis` |

### Design note: TIS_BASE is spec-defined

The TIS base address `0xFED40000` is the TCG-spec-mandated fixed address for the
TPM Interface Specification on x86 PC platforms.  It's not an implementation detail
or a magic number — it's the hardware standard, analogous to the LAPIC at
`0xFEE00000` or IOAPIC at `0xFEC00000`.  The ACPI TPM2 table confirms *presence*;
the address itself comes from the spec.  The `tpm2::TIS_BASE` constant remains as
the canonical reference.

For future CRB support: the control area address from the TPM2 table would be
used directly (it's at `TIS_BASE + 0x40` for QEMU's CRB implementation).
