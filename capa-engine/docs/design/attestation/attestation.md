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
| TPM 2.0 driver (TIS + CRB transports) | `themis/crates/tpm2/` | Done (P20k) |
| QEMU swtpm integration | `scripts/setup-swtpm.sh`, `run-qemu.sh` | Done |
| thhv ioctls (ATTEST_SELF, READ_PCR) | `thhv/` | Done |
| On-demand attestation (driver requests) | `thhv/` + `capavisor/` | Done |
| TPM MMIO probe from ACPI | `capavisor/src/acpi.rs` | Done (P20i) |
| TPM exclusion from dom0 EPT + ACPI strip | `capavisor/src/boot.rs`, `acpi.rs` | Done (P20i) |
| TPM2_CreatePrimary + Quote | `themis/crates/tpm2/` | Done (P20j) |
| User pub_key binding in attestation | `hypercall.rs`, `domcomm.rs` | Done (P20j) |
| TX ring attestation request | `thhv/`, `hypercall.rs` | Done (P20j) |
| Userspace crypto verification test | `thhv/test/test_attestation.c` | Done (P20j) |
| CRB transport + runtime selection | `tpm2/src/crb.rs`, `attestation.rs` | Done (P20k) |

All attestation features are **complete and tested**.

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
-device tpm-crb,tpmdev=tpm0     # CRB (default)
# -device tpm-tis,tpmdev=tpm0   # TIS (alternative, use QEMU_TIS=1)
```

> **Bug history**: the original setup used separate `--server` and `--ctrl` sockets
> and connected QEMU's chardev to `--server`.  QEMU sends PTM commands (not raw TPM
> commands) → swtpm's `recv_msg` blocked forever → deadlock.  Fixed in commit
> `9246045` by connecting to `--ctrl` only.

The capavisor auto-detects the transport from the ACPI TPM2 table's StartMethod field:
- **StartMethod=6** → TIS (FIFO byte-at-a-time interface)
- **StartMethod=7** → CRB (bulk memory-mapped command/response buffers)

**CRB is the default** since it is the modern transport and offers better performance.
Use `QEMU_TIS=1` to fall back to TIS.

Automated: `QEMU_TPM=1 cargo themis` — see `themis/scripts/setup-swtpm.sh` and
`run-qemu.sh` for the integration.

Reading PCR 11 from dom0:
```bash
tpm2_pcrread sha256:11
```
Note: dom0 **cannot** access the TPM directly — its MMIO region is excluded from
dom0's EPT.  PCR reads are only available via the `READ_PCR` ioctl (capavisor proxies).

### Real Hardware (TPM 2.0)

Real hardware has a physical TPM 2.0 chip (most x86_64 laptops/servers since 2016).
The capavisor reads the ACPI TPM2 table to determine the transport:

- **TIS** (StartMethod=6): FIFO interface at 0xFED40000. Byte-at-a-time
  register access. Simpler but slower.
- **CRB** (StartMethod=7): Command Response Buffer at ACPI-advertised address.
  Bulk memory-mapped buffers. Modern default on most hardware.

Both transports use the same MMIO base (0xFED40000) with different register layouts.
The ACPI TPM2 table confirms TPM presence and provides the start method.

For dom0 verification: use the `test_attestation` binary which performs full
Ed25519 + TPM RSA-2048 signature verification. Dom0 cannot access the TPM
directly — its MMIO region is excluded from dom0's EPT (capavisor-exclusive).

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

## 13. TPM MMIO Probe Fix (done, commit 65f3283)

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

---

## 14. Full TPM Attestation with User Binding (P20j) — DONE

### Two-Layer Attestation Model

The attestation scheme has two interlocking layers:

**Layer 1 — Platform Attestation (TPM Quote)**

The TPM proves that a specific capavisor binary with a specific Ed25519 public key
is running on genuine hardware:

```
PCR[11] = SHA-256(capavisor_binary ‖ ed25519_pub_key)

TPM2_Quote(AK, nonce, PCR_selection=[11])
  → TPMS_ATTEST { magic, type=QUOTE, qualifiedSigner, PCR_digest, nonce, clock... }
  → signed by RSA-2048 Attestation Key (AK) inside the TPM
```

The AK is created at boot via `TPM2_CreatePrimary` under the Owner hierarchy.
Its public key is included in the attestation response so verifiers can check the
TPM signature.

**Layer 2 — Domain Attestation (Capavisor Signature)**

The capavisor proves a domain's resource configuration for a specific verifier:

```
Ed25519_sign(capavisor_priv_key, SHA-256(report ‖ nonce ‖ user_pub_key))
```

The `user_pub_key` is the verifier's public key, binding the attestation to a
specific requesting party.  This prevents cross-user replay: an attestation
generated for Alice cannot convince Bob, because Bob's public key is not in the
signed hash.

**Binding chain:**

```
TPM manufacturer cert → EK → AK → Quote(PCR[11])
                                        ↓
                              PCR[11] contains ed25519_pub_key
                                        ↓
                              ed25519_pub_key verifies domain attestation signature
                                        ↓
                              signature covers user_pub_key (verifier identity)
```

### Wire Format

The signed attestation response is variable-length (TPM blobs vary in size):

```
SignedAttestReportHeader {            // fixed part
    report: AttestReport,             //  40 bytes — domain state
    signature: [u8; 64],              //  64 bytes — Ed25519(SHA-256(report ‖ nonce ‖ user_pub_key))
    pub_key: [u8; 32],                //  32 bytes — capavisor Ed25519 public key
    nonce: [u8; 32],                  //  32 bytes — echoed back
    user_pub_key: [u8; 32],           //  32 bytes — verifier's public key (echoed back)
    tpm_quote_size: u16,              //   2 bytes — TPMS_ATTEST blob length (0 if no TPM)
    tpm_sig_size: u16,                //   2 bytes — TPM signature length (0 if no TPM)
    ak_pub_size: u16,                 //   2 bytes — AK public area length (0 if no TPM)
    reserved: u16,                    //   2 bytes
}                                     // 240 bytes total fixed header
// Followed by variable-length TPM data:
//   tpm_quote[tpm_quote_size]        — raw TPMS_ATTEST bytes
//   tpm_sig[tpm_sig_size]            — raw TPMT_SIGNATURE bytes
//   ak_pub[ak_pub_size]              — raw TPMT_PUBLIC bytes
```

When no TPM is available, all `*_size` fields are 0 and no variable data follows.
The verifier decides whether Ed25519-only attestation is acceptable.

### Request/Response Protocol

**VMCALL convention:**

| Mode | arg0 | arg1 | Behavior |
|------|------|------|----------|
| Unsigned (init) | 0 | 0 | Legacy: nonce=0 via registers, returns PA map + caps |
| Signed (attest) | 1 | TX ring msg sequence | Read AttestRequest from TX ring |

**Request flow (signed path):**

```
Userspace                    thhv.ko                  Capavisor
    │                           │                         │
    │ ioctl(ATTEST_SELF,        │                         │
    │   {nonce, user_pub_key})  │                         │
    │──────────────────────────>│                         │
    │                           │ mutex_lock(attest_lock) │
    │                           │ TX enqueue(ATTEST_REQ,  │
    │                           │   {nonce, user_pub_key})│
    │                           │   → sequence = S        │
    │                           │                         │
    │                           │ VMCALL(0x0C, 1, S, 0,0) │
    │                           │────────────────────────>│
    │                           │                         │ dequeue TX head
    │                           │                         │ verify seq == S
    │                           │                         │   (ERR_RACE if ≠)
    │                           │                         │ build report
    │                           │                         │ Ed25519 sign
    │                           │                         │ TPM2_Quote(AK,nonce,[11])
    │                           │                         │ RX enqueue(ATTEST, blob)
    │                           │<────────────────────────│
    │                           │ RX dequeue(signed blob) │
    │                           │ mutex_unlock            │
    │<──────────────────────────│                         │
    │ verify Ed25519 sig        │                         │
    │ verify TPM quote          │                         │
    │ check nonce, user_pub_key │                         │
```

**Defense in depth (axiom A2 — dom0 is not trusted):**

1. **thhv (cooperative):** `DEFINE_MUTEX(attest_lock)` serializes the
   `{TX enqueue, VMCALL}` pair across all vCPUs. Prevents races in practice.
2. **Capavisor (defensive):** Dequeues TX ring head, verifies
   `msg.sequence == arg1`. If mismatch → `ERR_RACE`. The capavisor never
   assumes dom0 correctly serialized its operations.

### TPM Driver Additions

New commands needed in `themis/crates/tpm2/`:

| Command | Code | Purpose |
|---------|------|---------|
| `TPM2_CreatePrimary` | `0x0000_0131` | Create RSA-2048 AK under Owner hierarchy |
| `TPM2_Quote` | `0x0000_0158` | Sign PCR values with AK |

The AK uses RSA-2048 with RSASSA scheme (SHA-256 hash).  Created once at boot
in `try_tpm()` after `PCR_Extend`.  The handle is stored in `AttestationState`.

`CMD_BUF_SIZE` increases from 256 to 1024 to accommodate the larger
`CreatePrimary` response (RSA-2048 public key is 256 bytes alone).

### Implementation Phases

| Phase | Todo | Dependencies |
|-------|------|-------------|
| 1 (parallel) | P20j-1: TPM driver commands | None |
| 1 (parallel) | P20j-3: ABI struct updates | None |
| 2 (parallel) | P20j-2: AK creation at boot | P20j-1 |
| 2 (parallel) | P20j-5: thhv ABI + ioctl | P20j-3 |
| 3 | P20j-4: Hypercall handler update | P20j-2, P20j-3 |
| 4 | P20j-6: Userspace verification test | P20j-4, P20j-5 |
| 5 | P20j-7: Documentation | All |

### Graceful Degradation

| Scenario | Behavior |
|----------|----------|
| TPM present | Full attestation: Ed25519 + TPM Quote |
| No TPM | Ed25519-only: `tpm_quote_size=0`, verifier decides acceptability |
| nonce=0 | Unsigned PA map + caps (unchanged, for thhv init) |
| TX ring sequence mismatch | `ERR_RACE` returned, no attestation |

For future CRB support: the control area address from the TPM2 table would be
used directly (it's at `TIS_BASE + 0x40` for QEMU's CRB implementation).

### Verification Test (P20j-6)

`thhv/test/test_attestation.c` performs end-to-end cryptographic verification:

1. **Unsigned path**: Calls ioctl with nonce=0, verifies report returned.
2. **Signed path**: Sends random nonce + user\_pub\_key, then:
   - Verifies nonce and user\_pub\_key are echoed correctly
   - **Ed25519 verify**: Reconstructs `SHA-256(report ‖ nonce ‖ user_pub_key)`,
     verifies signature against capavisor's public key (OpenSSL EVP)
   - **TPM RSA-2048 verify**: Parses TPMT\_SIGNATURE header
     (`alg=RSASSA, hash=SHA256`), reconstructs RSA public key from AK modulus
     (e=65537), verifies signature over TPMS\_ATTEST blob (OpenSSL EVP)

Build: `cargo build-bins` (links `-lcrypto`)
Run: `sudo /opt/bins/thhv/tests/test_attestation` inside dom0

### Bug Fixes During Implementation

- **ioctl RX ring leak**: The unsigned ioctl path issued VMCALL but never
  dequeued the report from the RX ring, leaving stale data that would poison
  subsequent signed attestation calls. Fixed: both paths now dequeue under
  `attest_lock` mutex.
- **Stack overflow risk**: `struct thhv_attest_self` (~4KB) was on the kernel
  stack. Moved to `kmalloc`/`kfree`.

---

## 15. CRB Transport Support (P20k) — DONE

### Motivation

TIS (FIFO) was the original TPM transport. CRB (Command Response Buffer) is the
modern interface specified in TCG PC Client Platform TPM Profile (PTP) rev 4.
Most real hardware since ~2018 defaults to CRB. Supporting both ensures Themis
works on all TPM 2.0 platforms.

### Architecture

The TPM driver uses an enum-based dispatch (no `dyn Trait`, compatible with `no_std`):

```rust
pub enum Tpm2 {
    Tis(TisTransport),   // FIFO interface (StartMethod=6)
    Crb(CrbTransport),   // Command Response Buffer (StartMethod=7)
}
```

Transport selection happens at boot in `attestation.rs::try_tpm()`, which reads
the ACPI TPM2 table's `StartMethod` field.

### CRB Register Layout (TCG PTP Spec Table 18)

All offsets from locality base (0xFED40000):

| Register | Offset | Description |
|----------|--------|-------------|
| LOC_STATE | 0x00 | Locality state (TPM assigned, active locality) |
| LOC_CTRL | 0x08 | Locality control (request/relinquish) |
| LOC_STS | 0x0C | Locality status (granted, been seized) |
| INTF_ID | 0x30 | Interface ID (type, version, vendor) |
| CTRL_REQ | 0x40 | Control request (goReady, goIdle) |
| CTRL_STS | 0x44 | Control status (tpmIdle, tpmSts) |
| CTRL_CANCEL | 0x48 | Cancel current command |
| CTRL_START | 0x4C | Start command processing |
| CTRL_CMD_SIZE | 0x58 | Command buffer size |
| CTRL_CMD_LADDR | 0x5C | Command buffer physical address (low 32) |
| CTRL_CMD_HADDR | 0x60 | Command buffer physical address (high 32) |
| CTRL_RSP_SIZE | 0x64 | Response buffer size |
| CTRL_RSP_ADDR | 0x68 | Response buffer physical address |
| DATA_BUFFER | 0x80 | Shared command/response data buffer |

**Key insight**: `CTRL_CMD_LADDR` and `CTRL_RSP_ADDR` return **physical addresses**.
In the capavisor (paging enabled, HHDM mapping), we use the data buffer at the
well-known offset 0x80 from the already-mapped locality base instead of reading
these registers. This avoids physical-to-virtual translation issues.

### CRB transact() Flow

1. Request locality 0 (write LOC_CTRL, poll LOC_STS)
2. Send goReady (write CTRL_REQ, poll CTRL_STS for tpmIdle=0)
3. Write command bytes to data buffer (locality_base + 0x80)
4. Write CTRL_START = 1 to trigger TPM processing
5. Poll CTRL_START until it clears (TPM done)
6. Read response from data buffer, parse response header for size

### Files Changed

| File | Change |
|------|--------|
| `themis/crates/tpm2/src/crb.rs` | NEW: CRB transport implementation |
| `themis/crates/tpm2/src/tis.rs` | Refactored: `Tpm2` → `TisTransport` |
| `themis/crates/tpm2/src/lib.rs` | `Tpm2` enum with dispatch to TIS/CRB |
| `themis/capavisor/src/attestation.rs` | `try_tpm()` takes StartMethod, selects transport |
| `themis/capavisor/src/hypercall.rs` | Uses `tpm_driver()` accessor |
| `themis/scripts/run-qemu.sh` | CRB default; `QEMU_TIS=1` for TIS |

### Testing

Both transports pass the full attestation test suite:
```
QEMU_TPM=1 cargo themis                  # CRB (default)
QEMU_TPM=1 QEMU_TIS=1 cargo themis      # TIS (fallback)
# Then in dom0:
sudo insmod /opt/bins/thhv/thhv.ko
sudo /opt/bins/thhv/tests/test_attestation
# → ALL TESTS PASSED (Ed25519 + TPM RSA-2048 verification)
```
