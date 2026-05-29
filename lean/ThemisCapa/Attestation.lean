/-
  ThemisCapa.Attestation — Attestation report types.

  Mirrors `capa-engine/src/attest.rs`:
    * `AttestationReport`     — textual + signed report
    * `MemCapInfo`            — per-MemCap entry in a structured report
    * `DomCapInfo`            — per-DomCap entry
    * `PaMapInfo`             — single GPA→HPA translation
    * `StructuredAttestation` — full structured report payload

  The wire serializer (`to_bytes`) is platform code and not modeled.
-/
import ThemisCapa.Basic

namespace ThemisCapa
namespace Attestation

/-- Textual attestation report + optional platform signature. -/
structure AttestationReport where
  domainId  : Nat                -- u64 in Rust
  report    : String
  signature : Option (List Nat)  -- Vec<u8>
deriving Repr

namespace AttestationReport
def mk' (domainId : Nat) (report : String) : AttestationReport :=
  ⟨domainId, report, none⟩
def withSignature (r : AttestationReport) (sig : List Nat) : AttestationReport :=
  { r with signature := some sig }
end AttestationReport

/-- A memory-capability entry in a structured attestation. -/
structure MemCapInfo where
  handle     : LocalHandle
  gpa        : Nat   -- GPA (falls back to HPA when no GPA mapping)
  hpa        : Nat   -- HPA (raw host physical address)
  size       : Nat
  rights     : Nat   -- raw 3-bit rights bitmap
  attributes : Nat   -- raw 5-bit attributes bitmap
deriving Repr

/-- A domain-capability entry in a structured attestation. -/
structure DomCapInfo where
  handle   : LocalHandle
  domainId : Nat
deriving Repr

/-- A GPA→HPA translation entry. -/
structure PaMapInfo where
  gpa  : Nat
  hpa  : Nat
  size : Nat
deriving Repr

/-- Structured attestation report for a domain. -/
structure StructuredAttestation where
  domainId : Nat
  flags    : Nat
  numVps   : Nat
  apiFlags : Nat
  memCaps  : List MemCapInfo
  domCaps  : List DomCapInfo
  paMap    : List PaMapInfo
deriving Repr

end Attestation
end ThemisCapa
