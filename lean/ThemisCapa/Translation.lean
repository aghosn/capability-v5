/-
  ThemisCapa.Translation — Address-translation and cache-coloring.

  Mirrors `capa-engine/src/translation.rs`. These types are gated by the
  `address_translation` / `cache_coloring` Cargo features in Rust; the
  spec includes them unconditionally so refinement proofs against either
  feature configuration can be expressed by erasure.

  Axiom A4 (IOVA = GPA) becomes a Lean theorem statement: for every
  child domain the per-domain `AddressMap` agrees with the IOMMU view.
-/
import ThemisCapa.Basic

namespace ThemisCapa
namespace Translation

-- ── ColorBitmap ─────────────────────────────────────────────────────

/-- Cache-coloring bitmap: a finite set of allowed colors, modeled as a
    list of `u64` words. The number of words is bounded by the number of
    cache colors of the platform. -/
structure ColorBitmap where
  words : List Nat
deriving Repr

namespace ColorBitmap

/-- All colors allowed up to `numColors`. We do not encode the bit-level
    invariant here; refinement against the Rust bit-twiddling impl is
    deferred. -/
def all (numColors : Nat) : ColorBitmap :=
  let numWords := (numColors + 63) / 64
  ⟨List.replicate numWords (2 ^ 64 - 1)⟩

def empty : ColorBitmap := ⟨[]⟩

end ColorBitmap

-- ── MappingEntry / MapEntry / AddressMap ────────────────────────────

/-- A single (HPA, GPA, size, rights) mapping within an `AddressMap`. -/
structure MappingEntry where
  hpa    : Nat
  gpa    : Nat
  size   : Nat
deriving DecidableEq, Repr

/-- One entry in an `AddressMap`: covers a contiguous GPA range and may
    optionally pin a set of cache colors. -/
structure MapEntry where
  gpaStart   : Nat
  size       : Nat
  colorBitmap : Option ColorBitmap
deriving Repr

/-- Per-domain HPA↔GPA translation bookkeeping.
    Keyed by GPA start; value is the mapping descriptor. -/
structure AddressMap where
  entries : List (Nat × MapEntry)  -- (gpaStart, entry); sorted in Rust
deriving Repr

namespace AddressMap
def empty : AddressMap := ⟨[]⟩
end AddressMap

end Translation
end ThemisCapa
