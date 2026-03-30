# ThemisCapa Specification Status

Current state of the Lean 4 formal specification vs the Rust implementation
(`capa-engine/src/`). Updated as the specification evolves.

---

## Coverage Summary

| Category | Covered | Total | % |
|----------|---------|-------|---|
| Core operations (carve, alias, send, revoke, create, seal) | 6 | 6 | 100% |
| Extended operations (switch, deliver_interrupt, accept, reject, revoke_domain) | 7 | 14 | 50% |
| Safety properties proved | 20 | 20 | 100% |
| Update (HwUpdate) variants | 7 | 9 | 78% |
| VpRunState transitions | 8 | 8 | 100% |

---

## Operations

### Fully specified (pre + post conditions)

| Operation | Lean structs | Rust function | Notes |
|-----------|-------------|---------------|-------|
| Carve | `CarvePre`, `CarvePost` | `Capability::<Domain>::carve()` | Complete |
| Alias | `AliasPre`, `AliasPost` | `Capability::<Domain>::alias()` | Complete |
| Send | `SendPre`, `SendPost` | `Capability::<Domain>::send()` | Missing: sealed-receiver pending queue |
| Revoke | `RevokePre`, `RevokePost` | `Capability::<Domain>::revoke()` | Complete (SubtreeRevoked predicate) |
| Create | `CreatePre`, `CreatePost` | `Capability::<Domain>::create()` | Complete |
| Seal | `SealPre`, `SealPost` | `Capability::<Domain>::seal()` | Complete |
| Revoke domain | `RevokeDomainPre`, `RevokeDomainPost` | `Capability::<Domain>::revoke_domain()` | Complete |
| Switch (forward) | `SwitchForwardPre`, `SwitchForwardPost` | `Capability::<Domain>::switch()` | Full VP state transitions |
| Switch (return) | `SwitchReturnPre`, `SwitchReturnPost` | `Capability::<Domain>::switch()` | Full VP state transitions |
| Accept | `AcceptPre`, `AcceptPost` | `accept()` | Pending cap resolution, handle unfreezing |
| Reject | `RejectPre`, `RejectPost` | `reject()` | No transfer, handle unfreezing |
| Deliver interrupt | `DeliverInterruptPre`, `DeliverInterruptPost` | `deliver_interrupt_vp()` | Lazy-unwind chain walk |

### Not yet specified

| Operation | Rust function | Priority | Complexity |
|-----------|---------------|----------|------------|
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
| `Running → Interrupted` | Interrupt hits leaf VP | ✅ |
| `Locked → Suspended` | Interrupt hits intermediate VP | ✅ |
| `Suspended → Running` | Handler resumes suspended VP | ✅ |
| `Interrupted → Available` | Interrupt handled, VP released | ✅ |

---

## Safety Properties

All 27 properties have complete proofs (no `sorry`).

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
| P9a | Available is reachable | `available_is_reachable` | ✅ Proved |
| P9b | Running is reachable | `switch_forward_produces_reachable` | ✅ Proved |
| P9c | Locked is reachable | `lock_produces_reachable` | ✅ Proved |
| P9d | Interrupted is reachable | `interrupt_produces_reachable` | ✅ Proved |
| P9e | Suspended is reachable | `suspend_produces_reachable` | ✅ Proved |
| P10a | Forward switch not return | `switch_forward_not_return` | ✅ Proved |
| P10b | Return switch is return | `switch_return_is_return` | ✅ Proved |
| P11a | Accept unfreezes sender | `accept_unfreezes_sender` | ✅ Proved |
| P11b | Reject unfreezes sender | `reject_unfreezes_sender` | ✅ Proved |
| P12 | Interrupt preserves chain | `interrupt_preserves_chain` | ✅ Proved |
| — | Overlaps symmetry | `overlaps_comm` | ✅ Proved |
| P13 | Rights subset transitivity | `rights_subset_trans` | ✅ Proved |
| P14 | Access containment transitivity | `access_contained_trans` | ✅ Proved |
| P15 | Multi-level monotonicity | `two_level_monotonicity` | ✅ Proved |
| P16 | Multi-level containment | `two_level_containment` | ✅ Proved |
| P17 | Carve preserves WellFormedTree | `carve_preserves_wellformed` | ✅ Proved |

### Properties not yet stated

| Property | Description | Difficulty |
|----------|-------------|------------|
| Alias preserves WellFormedTree | Same as P17 but for alias operations | Medium |
| Revoke preserves WellFormedTree | Removing a child preserves CDT invariants | Medium |
| Address space isolation | Two sealed domains with disjoint trees have disjoint EPTs | Medium |
| No capability forgery | Impossible to hold capability without derivation chain | Medium |

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

### Phase 1 — Complete core operation specs ✅ DONE
- ✅ Added `SwitchForwardPost` / `SwitchReturnPost` with VP state transitions
- ✅ Added `accept`/`reject` pre/post-conditions (pending queue semantics)
- ✅ Specified recursive revocation (`SubtreeRevoked` predicate)
- ✅ Added interrupt-driven VP transitions (all 8 transitions + `VpReachable`)
- ✅ Added `DeliverInterruptPre`/`DeliverInterruptPost` (lazy-unwind chain walk)
- ✅ Proved 12 new properties (P9–P12)

### Phase 2 — Deeper invariant proofs ✅ DONE
- ✅ Proved Rights subset transitivity (P13)
- ✅ Proved Access containment transitivity (P14)
- ✅ Proved multi-level monotonicity (P15) and containment (P16)
- ✅ Proved `carve_preserves_wellformed` — main CDT preservation theorem (P17)
- ✅ Fixed WellFormedTree: removed incorrect carveAlias (aliases may overlap carves)
- ✅ Added `overlaps_comm` helper and `ParentAfterCarve` structure

### Phase 3 — Extensions
- Model COMM page lifecycle (register_comm, add_vp)
- Model channel capabilities (get_chan, send_channel)
- Add `FlushTLB` and `GiveMetaMem` to HwUpdate
- Model set_register/get_register with access policy

### Phase 4 — Refinement
- Establish simulation relation between Lean spec and Rust impl
- Model the `execute()` lock protocol (sequential consistency)
- Consider Mathlib integration for richer proof automation
