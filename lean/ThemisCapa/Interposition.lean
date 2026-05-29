/-
  ThemisCapa.Interposition — CPUID / MSR interposition policy.

  Mirrors `capa-engine/src/interposition.rs`. The Rust module defines a
  generic `ProcFeaturePolicy<T: ProcFeature>` parameterized by either
  `Cpuid` or `Msr`; the spec collapses both to a single concrete shape
  because all spec-relevant operations are agnostic to the resource kind.

  Detailed structures live here rather than in `Domain.lean` to keep that
  file focused on per-domain policy aggregation.
-/
import ThemisCapa.Basic
import ThemisCapa.Domain

namespace ThemisCapa
namespace Interposition

/-- A processor-feature key.
    For CPUID: `(leaf, subleaf)`.
    For MSR:   `(msr, 0)` — subleaf ignored. -/
structure FeatureKey where
  leaf    : Nat
  subleaf : Nat
deriving DecidableEq, Repr

/-- A range of feature keys: `[start .. finish]` inclusive.
    For CPUID this is the (leaf, subleaf) rectangular range used by the
    Rust `insert_range`. For MSR `subleaf` is always 0. -/
structure FeatureRange where
  start  : FeatureKey
  finish : FeatureKey
deriving Repr

/-- A single emulate point: a (leaf, subleaf, word_index) tuple bound to
    a u64 emulated value. Matches `ProcFeaturePolicy::Emulate` in Rust. -/
structure EmulatePoint where
  key      : FeatureKey
  wordIdx  : Nat   -- 0..3 for CPUID (EAX/EBX/ECX/EDX), 0..1 for MSR
  value    : Nat   -- packed u64
deriving Repr

/-- Per-resource policy, separate from the aggregation in `DomainPolicy`.
    The `default` action covers any key not in `ranges` or `emulate`.

    The Rust code stores ranges and emulate points in separate ordered
    maps; we model them as plain lists for the spec. -/
structure ProcFeaturePolicy where
  default : DefaultAction
  ranges  : List (FeatureRange × DefaultAction)  -- per-range trap/native override
  emulate : List EmulatePoint                    -- per-point emulated values
deriving Repr

namespace ProcFeaturePolicy
def empty (default : DefaultAction) : ProcFeaturePolicy :=
  ⟨default, [], []⟩
end ProcFeaturePolicy

/-- Mirror of `ProcFeatureConfig<T>` from Rust. Reserved for future
    spec-level refinements where the kind discriminator matters. -/
abbrev CpuidPolicy := ProcFeaturePolicy
abbrev MsrPolicy   := ProcFeaturePolicy

end Interposition
end ThemisCapa
