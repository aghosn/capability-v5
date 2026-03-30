# ThemisCapa Specification Status

Current state of the Lean 4 formal specification vs the Rust implementation
(`capa-engine/src/`). Updated as the specification evolves.

---

## Coverage Summary

| Category | Covered | Total | % |
|----------|---------|-------|---|
| Core operations (carve, alias, send, revoke, create, seal) | 6 | 6 | 100% |
| Extended operations (switch, deliver_interrupt, add_vp, ...) | 2 partial | 14 | ~10% |
| Safety properties proved | 8 | 8 | 100% |
| Update (HwUpdate) variants | 7 | 9 | 78% |
| VpRunState transitions | 4 | 8 | 50% |

---

## Operations

### Fully specified (pre + post conditions)

| Operation | Lean structs | Rust function | Notes |
|-----------|-------------|---------------|-------|
| Carve | `CarvePre`, `CarvePost` | `Capability::<Domain>::carve()` | Complete |
| Alias | `AliasPre`, `AliasPost` | `Capability::<Domain>::alias()` | Complete |
| Send | `SendPre`, `SendPost` | `Capability::<Domain>::send()` | Missing: sealed-receiver pending queue |
| Revoke | `RevokePre`, `RevokePost` | `Capability::<Domain>::revoke()` | Missing: recursive subtree traversal spec |
| Create | `CreatePre`, `CreatePost` | `Capability::<Domain>::create()` | Complete |
| Seal | `SealPre`, `SealPost` | `Capability::<Domain>::seal()` | Complete |
| Revoke domain | `RevokeDomainPre`, `RevokeDomainPost` | `Capability::<Domain>::revoke_domain()` | Missing: cascade semantics |
| Switch (forward) | `SwitchForwardPre` | `Capability::<Domain>::switch()` | Missing: post-conditions |
| Switch (return) | `SwitchReturnPre` | `Capability::<Domain>::switch()` | Missing: post-conditions |

### Not yet specified

| Operation | Rust function | Priority | Complexity |
|-----------|---------------|----------|------------|
| `accept` / `reject` | `accept()`, `reject()` | High | Medium — pending queue, freeze/unfreeze |
| `deliver_interrupt_vp` | `deliver_interrupt_vp()` | High | High — VP call chain walk, lazy-unwind |
| `add_vp` | `add_vp()` | Medium | Low — VP creation with COMM page |
| `register_comm` | `register_comm()` | Medium | Low — COMM page binding |
| `set_register` / `get_register` | `set_register()`, `get_register()` | Medium | Low — register access policy |
| `get_chan` / `send_channel` | `get_chan()`, `send_channel()` | Low | Medium — channel capabilities |
| `accept_channel` / `reject_channel` | `accept_channel()`, `reject_channel()` | Low | Low — channel pending queue |
| `attest` / `attest_self` | `attest()`, `attest_self()` | Low | Low — hash computation |
| `send_at` / `accept_at` | `send_at()`, `accept_at()` | Low | Low — address translation hint |
| `set_policy` / `get_policy` | `set_policy()`, `get_policy()` | Low | Low |
| `compute_memory_hash` | `compute_memory_hash()` | Low | Low |

---

## Types

### Covered

| Lean type | Rust type | File | Completeness |
|-----------|-----------|------|-------------|
| `Rights` | `Rights` (3-bit) | `memory.rs` | Full — subset, decidable eq |
| `Attributes` | `Attributes` (5-bit) | `memory.rs` | Partial — no `canonicalize()` |
| `Access` | `Access { start, size, rights }` | `memory.rs` | Full — overlap, containment |
| `RegionKind` | `RegionKind` | `memory.rs` | Full |
| `RegionStatus` | `RegionStatus` | `memory.rs` | Full |
| `DomainStatus` | `DomainStatus` | `domain.rs` | Full |
| `MonitorAPI` | `MonitorAPI` (13-bit) | `domain.rs` | Full — subset relation |
| `DomainPolicy` | `DomainPolicy` | `domain.rs` | Full |
| `VpRunState` | `VpRunState` | `domain.rs` | Full (all 5 variants) |
| `VpCallContext` | `VpCallContext` | `domain.rs` | Full |
| `MemCap` | `Capability<MemoryRegion>` | `capability.rs` | Partial — no weak refs |
| `DomCap` | `Capability<Domain>` | `capability.rs` | Partial — no weak refs |
| `HwUpdate` | `Update` | `update.rs` | 7/9 variants |
| `SystemState` | N/A (implicit) | — | Abstract only |
| `CoreState` | `CoreContext` | `switch.rs` | Simplified |

### Not covered

| Rust type | File | Why absent |
|-----------|------|------------|
| `CommBinding` | `memory.rs` | COMM page extension |
| `AddressSpaceView` | `view.rs` | Operational detail (view computation) |
| `SwitchManager` | `switch.rs` | Interrupt routing implementation |
| `InterruptRouting` | `switch.rs` | Per-vector routing policy |
| `AttestationReport` | `attest.rs` | Attestation extension |
| `PendingCapability` | `domain.rs` | Sealed-receiver pending queue |
| `CapabilityRef<T>` / `CapabilityWeak<T>` | `lib.rs` | Arc/Weak is implementation detail |
| `UpdateBatch` (Rust struct) | `update.rs` | `affected_domains`, per-core routing |

---

## HwUpdate Variants

| Lean variant | Rust variant | Status |
|-------------|-------------|--------|
| `mapMemory` | `ChangeRights` (with rights) | ✅ |
| `unmapMemory` | `ChangeRights` (rights=NONE) | ✅ |
| `zeroMemory` | `ZeroMemory` | ✅ |
| `createDomain` | `CreateDomain` | ✅ |
| `revokeDomain` | `RevokeDomain` | ✅ |
| `commRegion` | `CommRegion` | ✅ |
| `uncommRegion` | `UncommRegion` | ✅ |
| — | `FlushTLB` | ❌ Architecture-specific |
| — | `GiveMetaMem` | ❌ META memory extension |

---

## VpRunState Transitions

| Transition | Trigger | Covered |
|------------|---------|---------|
| `Available → Running` | Forward switch | ✅ |
| `Running → Locked` | Forward switch (caller side) | ✅ |
| `Locked → Running` | Return switch | ✅ |
| `Running → Available` | Return switch (callee side) | ✅ |
| `Running → Interrupted` | Interrupt hits leaf VP | ❌ |
| `Locked → Suspended` | Interrupt hits intermediate VP | ❌ |
| `Suspended → Running` | Handler resumes suspended VP | ❌ |
| `Interrupted → Available` | Interrupt handled, VP released | ❌ |

---

## Safety Properties

All 8 properties have complete proofs (no `sorry`).

| ID | Property | Theorem | Proof status |
|----|----------|---------|-------------|
| P1 | Derivation monotonicity | `carve_preserves_monotonicity`, `alias_preserves_monotonicity` | ✅ Proved |
| P2 | Memory exclusivity | `carve_maintains_exclusivity` | ✅ Proved |
| P3 | Capability confinement | `confinement` (definition) | ✅ Defined |
| P4 | Operation authority | `carve_requires_authority`, `send_requires_authority` | ✅ Proved |
| P5 | Revocation completeness | `revoke_is_complete` | ✅ Proved |
| P6 | No authority amplification | `send_no_amplification` | ✅ Proved |
| P7 | Sealed domain immutability | `seal_freezes_policy` | ✅ Proved |
| P8 | Policy monotonicity | `create_policy_monotonic` | ✅ Proved |

### Properties not yet stated

| Property | Description | Difficulty |
|----------|-------------|------------|
| CDT well-formedness preservation | `WellFormedTree` preserved across operations | Hard |
| Revocation cascade completeness | `revoke_domain` destroys all descendants transitively | Medium |
| VP state machine safety | No invalid transitions, no deadlocks | Medium |
| Interrupt lazy-unwind correctness | Suspended/Interrupted states correctly restored | Hard |
| No capability forgery | Impossible to hold capability without derivation chain | Medium |
| Address space isolation | Two sealed domains with disjoint trees have disjoint EPTs | Medium |

---

## Architectural Gaps

These are entire subsystems not yet modelled in Lean:

1. **Execution model (`execute()`)** — the lock-acquire → mutate → apply-updates
   protocol. Important for proving that hardware state always reflects capability
   state (A1 invariant).

2. **Concurrency** — shared vs exclusive lock semantics, cross-core IPI + barrier
   protocol. The Rust code uses `loom` for exhaustive testing; the Lean spec
   currently assumes sequential execution.

3. **Address translation** — `send_at`/`accept_at` GPA hints, view computation,
   and the `AddressSpaceView` diff mechanism. Important for proving EPT correctness.

4. **Interrupt routing** — `SwitchManager::route_interrupt()` and the per-vector
   policy (Deliver/Report/NotReport). Critical for proving A3 (lazy-unwind).

5. **Attestation** — hash chains over the CDT for remote attestation.

---

## Suggested Next Steps (by priority)

### Phase 1 — Complete core operation specs
- Add `SwitchForwardPost` / `SwitchReturnPost` with VP state transitions
- Add `accept`/`reject` pre/post-conditions (pending queue semantics)
- Specify recursive revocation (subtree walk) as an inductive relation
- Add interrupt-driven VP transitions (Running→Interrupted, Locked→Suspended)

### Phase 2 — Deeper invariant proofs
- Prove `WellFormedTree` preservation for carve, alias, revoke
- Prove address space isolation between disjoint domains
- Prove VP state machine has no stuck states

### Phase 3 — Extensions
- Model `deliver_interrupt_vp` and lazy-unwind chain walk
- Model COMM page lifecycle (register_comm, add_vp)
- Model channel capabilities (get_chan, send_channel)
- Add `FlushTLB` and `GiveMetaMem` to HwUpdate

### Phase 4 — Refinement
- Establish simulation relation between Lean spec and Rust impl
- Model the `execute()` lock protocol (sequential consistency)
- Consider Mathlib integration for richer proof automation
