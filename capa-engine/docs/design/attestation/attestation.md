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

The following **already exists**:

| Component | Location | Status |
|-----------|----------|--------|
| `AttestReport` struct (domain config blob) | `themis-abi/src/domcomm.rs` | Done |
| `attest_domain()` in capability engine | `capability_engine::attest` | Done (unsigned) |
| `do_attest_self` hypercall (0x0C) | `capavisor/src/hypercall.rs` | Stub (returns domain_id only) |
| `THEMIS_ATTEST` (0x0D) hypercall dispatch | `hypercall.rs` | Stub |
| DomainComm attestation delivery at boot | `capavisor/src/boot.rs:1409` | Done (unsigned) |

**What is missing** (this document's scope):
- Attestation key pair generation (before capavisor starts)
- PCR extend with hash(capavisor || boot-info || pub_key)
- Capavisor receives and stores the private key
- `AttestReport` extended with a signature field
- `do_attest_self` delivers the full signed blob
- TPM integration (QEMU swtpm for dev, real TPM 2.0 for hardware)

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

QEMU supports TPM 2.0 emulation via `swtpm`:

```bash
# Start swtpm (once, before QEMU)
mkdir -p /tmp/swtpm-state
swtpm socket --tpm2 \
  --server type=unixio,path=/tmp/swtpm.sock \
  --ctrl type=unixio,path=/tmp/swtpm.ctrl \
  --tpmstate dir=/tmp/swtpm-state \
  --flags not-need-init,startup-clear &

# QEMU extra args:
-chardev socket,id=chrtpm,path=/tmp/swtpm.sock
-tpmdev emulator,id=tpm0,chardev=chrtpm
-device tpm-tis,tpmdev=tpm0
```

The TPM device appears as `/dev/tpm0` in dom0.  Reading PCR 11:
```bash
tpm2_pcrread sha256:11
```

### Real Hardware (TPM 2.0)

Real hardware has a physical TPM 2.0 chip (most x86_64 laptops/servers since 2016).
The bootloader talks to it via:
- **FIFO interface** (TIS — TPM Interface Specification): MMIO at 0xFED40000
- Or **CRB interface** (Command Response Buffer): MMIO at ACPI TPM2 table address

The Limine-side key generation + PCR extend code must implement a minimal TPM 2.0
command stack (just `TPM2_PCR_Extend` and optionally `TPM2_GetRandom` for key seeding).

For dom0 verification: use `tpm2-tools` (`tpm2_quote`, `tpm2_pcrread`).

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

P20f (QEMU swtpm) is independent of P20b–e and can proceed in parallel.
P20g requires P20e and P20f.

---

## 12. Open Questions

1. **Limine custom module** — does the Limine version we use support custom boot
   modules with arbitrary entry points, or do we need a separate pre-boot binary
   loaded as a Limine module that runs before capavisor?

2. **Key freshness** — should the Ed25519 key pair be fresh on every boot (ephemeral),
   or stored in TPM NV memory across reboots?  Ephemeral is simpler and avoids
   key reuse concerns.  **Recommend ephemeral for initial implementation.**

3. **Nonce delivery** — the verifier's nonce must reach `do_attest` somehow.  Currently
   hypercall args are registers (RDI, RSI, RDX).  A 32-byte nonce fits in 4 registers
   or a shared memory page.  **Use 4 registers (4 × u64 = 32 bytes) for simplicity.**

4. **DRTM (Intel TxT)** — reduces TCB to just the capability engine, excluding the
   bootloader.  Deferred: prototype with SRTM first, add TxT support later.
