
## Platform API / Unimplemented Features

- [ ] **#U1** `UpdateBatch::snapshots` — the field exists for rollback but is never populated. Rollback mechanism is absent. _Deferred — document as future work._
- [ ] **#U2** `MonitorAPI::ENUMERATE` / `enumerate_pending` — the bit is defined and `get_pending_ids()` exists on `Domain`, but there is no `Capability::enumerate_pending` operation. _Deferred — semantics TBD._
- [ ] **#U3** Implement coloring as described in `./2026/docs/design/address_translation.md`.
