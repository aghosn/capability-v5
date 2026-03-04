# Capability Engine — Known Issues & TODO

## Security / Correctness

- [x] **#1** `seal_domain_op` does not check `MonitorAPI::SEAL` permission — any domain can seal its children regardless of policy. (`capability.rs:1079`)

- [x] **#2** Alias revocation does not unmap the receiver domain — revoking a sent alias leaves the receiver's EPT mapping intact. `revoke_subtree` only emits `ChangeRights(NONE)` for carved children. (`capability.rs:372`)

- [x] **#3** `send_memory_sealed`: attributes are mutated before the authoritative freeze-commit check — if the freeze fails, the original capability's attributes are permanently changed. (`capability.rs:791`)

- [x] **#4** `set_policy` TOCTOU with concurrent `seal_domain_op` — sealed-check is done under `read()`, write lock acquired separately; a concurrent seal between the two lets policy be written onto an already-sealed domain. (`capability.rs:1654`)

## Invariant / Enforcement Gaps

- [x] **#5** `set_policy(Cores, narrower_mask)` does not adjust `num_vprocessors` — domain can end up with more VPs than cores, violating the invariant. (`capability.rs:1662`, `domain.rs:373`)

- [x] **#6** Interrupt policy monotonicity not enforced for `DefaultInterruptVisibility` and per-vector `VectorVisibility` — a child can be granted `Deliver` where the parent has `NotReport`. (`capability.rs:1676`)

- [x] **#7** `ChangeRights.physical` is always set equal to the virtual `address` (identity-map assumption hardcoded in `revoke_subtree`). This is correct for the current identity-mapped deployment but must be revisited for non-identity-mapped platforms. (`capability.rs:379`)
  - _Documented assumption in `update.rs` comment; no code change needed right now._

## Platform API / Unimplemented Features

- [x] **#8** `Attributes::HASH` — add `Platform::measure_region(address, size) -> [u8; 32]` and a `Capability::compute_memory_hash(caller, handle, platform)` operation that populates `content_hash`. (`platform.rs`, `capability.rs`, `memory.rs`)

- [x] **#9** `Attributes::META` — implemented: excluded from address space/view, exclusive-only source, no re-send/carve/alias, implies CLEAN+VITAL at revocation, sealed receiver goes through pending/accept. Full docs in `2026/docs/semantics/memory.md`.

- [x] **#10** `MonitorAPI::GETCHAN` / channel operations — implemented: `get_chan`, `send_channel`, `accept_channel`, `reject_channel`. Channels appear in attestation, carry `ATTEST | GETCHAN | SEND` permissions, and use move semantics on transfer. Full docs in `2026/docs/semantics/domain.md`.

- [ ] **#11** `UpdateBatch::snapshots` — the field exists for rollback but is never populated. Rollback mechanism is absent. _Deferred — document as future work._

- [ ] **#12** `MonitorAPI::ENUMERATE` / `enumerate_pending` — the bit is defined and `get_pending_ids()` exists on `Domain`, but there is no `Capability::enumerate_pending` operation. _Deferred — semantics TBD._

- [x] **#13** `revoke_domain` does not revoke memory capabilities owned by the revoked domain. `revoke_domain_subtree` only emits `RevokeDomain`; any memory the domain held is never walked, so parent domains do not receive the `Map`/`ChangeRights` updates needed to regain access to those regions. The `Unmap` for the revoked domain itself is not needed — its full address space disappears with it — but non-revoked ancestor domains that had carved regions sent into the revoked domain must have those regions restored. Currently the CLI works around this by manually scanning owned memory capabilities when it sees a `RevokeDomain` update (`CLI-2026/src/update_processor.rs`), but this logic belongs in the library. The fix should walk each revoked domain's `memory_capabilities` table inside `revoke_domain_subtree` and call `revoke_subtree` on each owned root capability so that the correct restore updates (`Map`/`ChangeRights`) are generated for all non-revoked domains up the capability tree.

## Test Gaps

- [x] **#T1** No test verifies that a domain without `MonitorAPI::SEAL` is denied by `seal_domain_op` (depends on fix #1).
- [x] **#T2** No test verifies that an alias receiver loses access after the alias is revoked (depends on fix #2).
- [x] **#T3** No test for `send_memory_sealed` attribute-mutation atomicity on failed freeze (depends on fix #3).
- [x] **#T4** No test for `UpdateProcessor` methods (`submit_updates`, `mark_in_progress`, `mark_completed`, etc.).
- [x] **#T5** No test for multi-level `Suspended` chain cleanup (`Suspended → Suspended → Interrupted`).

## Code Quality

- [x] **#C1** Section header for domain-mediated operations in `capability.rs` is split around a free function, producing a confusing `(continued)` banner. Consolidate into one contiguous section.

- [x] **#C2** Domain-mediated public function names are verbose. Rename to shorter forms: `carve_memory→carve`, `alias_memory→alias`, `send_memory→send`, `accept_memory→accept`, `reject_memory→reject`, `revoke_memory_child→revoke`, `seal_domain→seal`, `create_domain→create`, `switch_domain→switch`. Update all call sites in `src/` and `tests/`.

- [x] **#C3** Docs code snippets use the old verbose `Capability::` call names. Update `docs/semantics/memory.md`, `domain.md`, and `capabilities.md` to use the new short names from #C2.

- [x] **#C4** Public functions in `capability.rs` lack `# Errors` doc sections. Every `pub fn` returning `Result` should list each `CapaError` variant it can return with a one-line explanation.


## Future Work / Design

- [ ] **#F1** **GPA Remapping Layer** — On certain platforms the monitor needs to project physical
  memory into a *guest virtual address space* (GPA): a domain still holds capabilities over physical
  ranges, but those ranges are accessible at domain-chosen guest virtual addresses rather than at
  their identity-mapped physical address.  This is the deeper issue behind the `ChangeRights.physical
  == start` identity-map assumption documented in #7.

  ### Problem statement

  Today every `UpdateBatch` entry uses `physical == virtual == start` because the only deployment
  is fully identity-mapped.  On a platform with a two-dimensional page table (e.g. Intel EPT / AMD
  NPT) the monitor controls a *GPA→HPA* mapping per domain.  The capability still tracks the
  physical range (HPA) but sends/receives must also maintain the per-domain GPA mapping.

  ### Requirements

  1. **Feature-gated** — the entire remapping layer must be hidden behind a Cargo feature
     (e.g. `feature = "gpa_remap"`).  When the feature is absent the library behaves exactly as
     today (identity map, zero overhead).

  2. **Isolated layer** — remapping logic lives in its own module/file and does not scatter
     conditionals through the core capability engine.  The public API surface of the engine does
     not change for non-remap builds.

  3. **No double-mapping of a physical page** — a given HPA range may appear at most once in any
     single domain's GPA space.  Enforced at `send`/`accept` time: if the incoming physical range
     already has a GPA mapping in the receiver, the operation is rejected.

  4. **No aliasing of a GPA** — a guest virtual address may map to at most one physical address
     within a domain.  Enforced at remap-registration time.

  5. **Carved-gap exclusion** — after a domain carves a sub-region and sends it away, the gap left
     in the parent's GPA space is *frozen*: no new GPA mapping may cover that physical range until
     the child is revoked and the parent regains the region.  This prevents a collision at revocation
     time where the remap engine would need to restore a GPA that is already occupied.

  6. **API extension** — `send` (and potentially `carve`/`alias`) gains an optional `GpaHint`
     argument when the feature is active.  The hint specifies the guest virtual base address at
     which the transferred region should be mapped in the receiver's address space.  When absent the
     platform may choose an address or leave the region unmapped-in-GPA (identity fallback).

  7. **UpdateBatch correctness** — the `Map`, `Unmap`, `ChangeRights`, and `ZeroMemory` update
     variants must carry the correct GPA (`virtual` field) when the feature is active.  The
     `physical` field always carries the HPA.  Revocation must restore the *original* GPA in the
     parent (stored at `send` time), not the identity address.

  8. **Attestation** — the GPA mapping for each memory region should appear in the attestation
     report when the feature is active so that the verifier can inspect the layout.

  ### Design document

  Before implementation: write `docs/design/gpa_remap.md` covering the data-model changes
  (`MemoryRegion` gains an optional `gpa: u64` field), the bookkeeping needed in `Domain`
  (a `gpa_map: BTreeMap<u64, SubHandle>` for collision detection), the modified update-emission
  paths, and the interaction with the loom concurrency model.

