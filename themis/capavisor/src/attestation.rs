//! Capavisor attestation — boot-time key generation and TPM measurement.
//!
//! This module implements the attested boot flow described in the EuroS&P
//! paper §5.1:
//!
//! 1. Generate an Ed25519 key pair (seeded from RDRAND).
//! 2. Compute measurement = SHA-256(capavisor_binary ‖ boot_info ‖ pub_key).
//! 3. Extend TPM PCR 11 with the measurement (if TPM is present).
//! 4. Store the signing key in a static (META pool — never in any domain's EPT).
//!
//! The signing key is used later by `do_attest_self` / `do_attest` to sign
//! domain attestation reports.
//!
//! # Safety
//!
//! The attestation state is initialized once during BSP boot (before any AP
//! runs or any domain exists) and is read-only thereafter.  Access is safe
//! without synchronization because:
//! - Writes happen only in `init()`, called from `_start()` on the BSP.
//! - Reads happen only after `AP_LAUNCH_READY` is set (Release/Acquire barrier).

use core::sync::atomic::{AtomicBool, Ordering};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Sha256, Digest};
use spin::Once;
use themis_abi::domcomm::{ATTEST_KEY_SIZE, ATTEST_PCR_INDEX};
use tpm2::Tpm2;

use crate::serial_println;

// ── Attestation state (capavisor-only, in META pool) ─────────────────────── //

/// Global attestation state, initialized once at boot.
static ATTEST_STATE: Once<AttestationState> = Once::new();

/// Whether a TPM was probed and PCR extend succeeded.
/// Separate from `ATTEST_STATE` because the TPM probe happens later
/// (after ACPI parsing) than keygen+measurement.
static TPM_AVAILABLE: AtomicBool = AtomicBool::new(false);

struct AttestationState {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    measurement: [u8; 32],
}

// ── RDRAND-based random byte generation ──────────────────────────────────── //

/// Fill `buf` with random bytes from the x86 RDRAND instruction.
///
/// Retries up to 10 times per u64 (per Intel SDM recommendation).
/// Panics if RDRAND is not supported or consistently fails.
fn rdrand_fill(buf: &mut [u8]) {
    let mut offset = 0;
    while offset < buf.len() {
        let val = rdrand64();
        let remaining = buf.len() - offset;
        let chunk = remaining.min(8);
        buf[offset..offset + chunk].copy_from_slice(&val.to_le_bytes()[..chunk]);
        offset += chunk;
    }
}

fn rdrand64() -> u64 {
    for _ in 0..10 {
        let mut val: u64;
        let ok: u8;
        unsafe {
            core::arch::asm!(
                "rdrand {val}",
                "setc {ok}",
                val = out(reg) val,
                ok = out(reg_byte) ok,
                options(nomem, nostack),
            );
        }
        if ok != 0 {
            return val;
        }
    }
    panic!("RDRAND failed after 10 retries");
}

// ── Public API ───────────────────────────────────────────────────────────── //

/// Initialize the attestation subsystem (keygen + measurement only).
///
/// Must be called once from `_start()` after serial init and heap init,
/// before any domain is created.  TPM probing is deferred to [`try_tpm()`]
/// which runs after ACPI parsing discovers the TPM base address.
///
/// `elf_file_addr` is the virtual address of the raw ELF file bytes (from
/// Limine's `ExecutableFileRequest`).  This is the pristine binary as loaded
/// from the boot medium — deterministic and excludes `.bss`.
/// `elf_file_size` is the size of that raw ELF file in bytes.
pub fn init(elf_file_addr: u64, elf_file_size: u64) {
    serial_println!("[attest] Initializing attestation subsystem...");

    // Step 1: Generate Ed25519 key pair from RDRAND
    let mut seed = [0u8; ATTEST_KEY_SIZE];
    rdrand_fill(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let pub_key_bytes = verifying_key.to_bytes();

    // Zero the seed on the stack
    zeroize_bytes(&mut seed);

    serial_println!("[attest] Ed25519 key pair generated");
    serial_println!("[attest]   pub_key: {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        pub_key_bytes[0], pub_key_bytes[1], pub_key_bytes[2], pub_key_bytes[3],
        pub_key_bytes[28], pub_key_bytes[29], pub_key_bytes[30], pub_key_bytes[31]);

    // Step 2: Compute measurement = SHA-256(elf_file ‖ pub_key)
    //
    // We hash the raw ELF file (the pristine binary from the boot medium,
    // provided by Limine's ExecutableFileRequest) concatenated with the
    // public key.  This is deterministic and reproducible — a verifier can
    // independently hash the same ELF file.  Unlike the in-memory loaded
    // image, the raw ELF excludes .bss and any runtime-mutated state.
    let measurement = {
        let mut hasher = Sha256::new();
        let binary_slice = unsafe {
            core::slice::from_raw_parts(elf_file_addr as *const u8, elf_file_size as usize)
        };
        hasher.update(binary_slice);
        hasher.update(&pub_key_bytes);
        let result = hasher.finalize();
        let mut m = [0u8; 32];
        m.copy_from_slice(&result);
        m
    };

    serial_println!("[attest] measurement: {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        measurement[0], measurement[1], measurement[2], measurement[3],
        measurement[28], measurement[29], measurement[30], measurement[31]);

    // Step 3: Store state (TPM probe deferred to try_tpm())
    ATTEST_STATE.call_once(|| AttestationState {
        signing_key,
        verifying_key,
        measurement,
    });

    serial_println!("[attest] Attestation keygen complete (TPM probe deferred)");
}

/// Probe the TPM and extend PCR 11 with the boot measurement.
///
/// Called after ACPI parsing discovers a TPM2 table.  Maps the TPM's TIS
/// MMIO region into the HHDM (Limine doesn't map device MMIO), then probes,
/// sends TPM2_Startup, and extends PCR 11.
///
/// `tpm_phys_base` is the physical base of the TIS MMIO region (typically
/// `0xFED4_0000` — the TCG-spec-defined fixed address for x86).
/// `hhdm_offset` is the Limine HHDM offset for phys→virt translation.
pub fn try_tpm(tpm_phys_base: u64, hhdm_offset: u64) {
    let state = ATTEST_STATE.get().expect("attestation not initialized");

    // Map the TIS MMIO region (5 pages: localities 0–4) into the HHDM.
    // Limine base revision 3 only maps RAM/ACPI/bootloader regions; device
    // MMIO like the TPM needs explicit page table entries.
    const TIS_SIZE: u64 = 0x5000; // 5 × 4 KiB pages
    serial_println!("[attest] Mapping TPM TIS MMIO: phys {:#x}..{:#x}",
        tpm_phys_base, tpm_phys_base + TIS_SIZE);
    crate::mem::map_phys_range(tpm_phys_base, TIS_SIZE, hhdm_offset);

    let tpm_virt = tpm_phys_base + hhdm_offset;
    let tpm = Tpm2::new(tpm_virt);

    if !tpm.probe() {
        serial_println!("[attest] No TPM detected at phys {:#x} (virt {:#x})",
            tpm_phys_base, tpm_virt);
        return;
    }

    serial_println!("[attest] TPM detected at phys {:#x}", tpm_phys_base);

    // Startup (may already be done by firmware — that's OK)
    if let Err(e) = tpm.startup() {
        serial_println!("[attest] TPM2_Startup failed: {:?}", e);
        return;
    }

    // Extend PCR 11 with the boot measurement
    match tpm.pcr_extend(ATTEST_PCR_INDEX, &state.measurement) {
        Ok(()) => {
            serial_println!("[attest] TPM2_PCR_Extend(PCR={}) OK", ATTEST_PCR_INDEX);
        }
        Err(e) => {
            serial_println!("[attest] TPM2_PCR_Extend failed: {:?}", e);
            return;
        }
    }

    // Read back PCR 11 to verify
    match tpm.pcr_read(ATTEST_PCR_INDEX) {
        Ok(pcr_val) => {
            serial_println!("[attest] PCR[{}] = {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
                ATTEST_PCR_INDEX,
                pcr_val[0], pcr_val[1], pcr_val[2], pcr_val[3],
                pcr_val[28], pcr_val[29], pcr_val[30], pcr_val[31]);
        }
        Err(e) => {
            serial_println!("[attest] TPM2_PCR_Read failed (non-fatal): {:?}", e);
        }
    }

    TPM_AVAILABLE.store(true, Ordering::Release);
    serial_println!("[attest] TPM available — PCR extend succeeded");
}

// ── Accessor functions (for P20e: signed attestation hypercall) ──────────── //

/// Returns the capavisor's Ed25519 public key (32 bytes).
///
/// Panics if called before `init()`.
pub fn public_key() -> [u8; ATTEST_KEY_SIZE] {
    ATTEST_STATE
        .get()
        .expect("attestation not initialized")
        .verifying_key
        .to_bytes()
}

/// Returns the boot measurement hash (32 bytes).
pub fn measurement() -> [u8; 32] {
    ATTEST_STATE
        .get()
        .expect("attestation not initialized")
        .measurement
}

/// Returns whether a TPM was detected and the PCR extend succeeded.
pub fn tpm_available() -> bool {
    TPM_AVAILABLE.load(Ordering::Acquire)
}

/// Sign `data` with the capavisor's Ed25519 signing key.
///
/// Returns a 64-byte Ed25519 signature.
///
/// Panics if called before `init()`.
pub fn sign(data: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    let state = ATTEST_STATE
        .get()
        .expect("attestation not initialized");
    let sig = state.signing_key.sign(data);
    sig.to_bytes()
}

// ── Helpers ──────────────────────────────────────────────────────────────── //

/// Zero a byte slice (compiler-visible side effect prevents optimization).
fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}
