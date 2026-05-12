# ThemisCapa — Lean 4 Formal Specification

Lean 4 specification of the Themis capability model, mirroring the Rust
implementation in [`capa-engine/src/`](../capa-engine/src/).

## Quick Start

```bash
# Install Lean 4 via elan (if not already installed)
curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh

# Type-check all definitions and verify all proofs
cd lean/
lake build
```

No external dependencies — pure Lean 4.16.0.

## Module Structure

| Module | Description |
|--------|-------------|
| `ThemisCapa.Basic` | Core types: `Rights` (3-bit permission bitmap), `Attributes` (5-bit metadata), `Access` (address range + rights), `CapaError` |
| `ThemisCapa.Domain` | `MonitorAPI` (13-bit permission bitmap), `DomainPolicy`, `VpRunState` (VP scheduling state machine), `InterruptPolicy` |
| `ThemisCapa.Capability` | `MemCap` and `DomCap` — nodes in the Capability Derivation Tree (CDT). Predicates for overlap, containment, lookup |
| `ThemisCapa.State` | `SystemState` (global CDT + per-core state), `HwUpdate` (EPT changes, memory zeroing, domain lifecycle) |
| `ThemisCapa.Operations` | Pre/post-condition structures for all 8 capability operations: carve, alias, send, revoke, create, seal, switch, revoke_domain |
| `ThemisCapa.Properties` | 8 safety theorems with complete proofs (no `sorry`) |

## Safety Properties (proved)

| Property | Statement | Theorem |
|----------|-----------|---------|
| **P1** Derivation monotonicity | `child.rights ⊆ parent.rights` after carve/alias | `carve_preserves_monotonicity`, `alias_preserves_monotonicity` |
| **P2** Memory exclusivity | No two carved siblings overlap | `carve_maintains_exclusivity` |
| **P3** Capability confinement | Every held capability was derived from an ancestor | `confinement` (definition) |
| **P4** Operation authority | Operations require sealed domain + permission bit | `carve_requires_authority`, `send_requires_authority` |
| **P5** Revocation completeness | Revoked child removed from parent's children | `revoke_is_complete` |
| **P6** No authority amplification | Send preserves capability rights | `send_no_amplification` |
| **P7** Sealed domain immutability | Seal freezes the domain policy | `seal_freezes_policy` |
| **P8** Policy monotonicity | Child domain policy ⊆ parent policy | `create_policy_monotonic` |

## Correspondence to Rust

| Lean type | Rust type | Source |
|-----------|-----------|--------|
| `Rights` | `Rights` (3-bit bitmap) | `capa-engine/src/memory.rs` |
| `Attributes` | `Attributes` (5-bit bitmap) | `capa-engine/src/memory.rs` |
| `Access` | `Access { start, size, rights }` | `capa-engine/src/memory.rs` |
| `MonitorAPI` | `MonitorAPI` (13-bit bitmap) | `capa-engine/src/domain.rs` |
| `DomainPolicy` | `DomainPolicy` | `capa-engine/src/domain.rs` |
| `VpRunState` | `VpRunState` enum | `capa-engine/src/domain.rs` |
| `MemCap` | `Capability<MemoryRegion>` | `capa-engine/src/capability.rs` |
| `DomCap` | `Capability<Domain>` | `capa-engine/src/capability.rs` |
| `CarvePre`/`CarvePost` | `Capability::<Domain>::carve()` | `capa-engine/src/capability.rs` |
| `HwUpdate` | `Update` enum | `capa-engine/src/update.rs` |

## Future Work

- **Deeper invariants**: prove that `WellFormedTree` is preserved across
  arbitrary sequences of operations (inductive invariant).
- **Revocation cascade**: formally verify that `revoke_domain` transitively
  destroys all descendant domains and their capabilities.
- **Liveness**: prove the system is deadlock-free under the VP state machine.
- **Refinement**: establish a simulation relation between the Lean spec and
  the Rust implementation (manual or via extraction).

## Related Documentation

- [`docs/capability-engine/semantics.md`](../docs/capability-engine/semantics.md) — informal specification
- [`CONTEXT.md`](../CONTEXT.md) — axioms A1–A11, architecture overview
- [`skills/working-on-capability-engine.md`](../skills/working-on-capability-engine.md) — Rust codebase guide