# Switching and Interrupts

## Domain Switches

A **switch** is a transfer of execution from one domain to another on the same core. It is the only authorised way for a domain to yield control — there is no implicit preemption at the capability engine level.

### `SwitchManager`

The `SwitchManager` owns a `Vec<Arc<CoreContext>>`, one entry per physical core. Each `CoreContext` tracks:

```rust
pub struct CoreContext {
    pub state:   RwLock<CoreState>,  // Idle | Running(domain_id)
    pub core_id: u64,
}
```

Before any switch can proceed the engine checks that the `from` domain is *actually* recorded as running on the requested core — a domain cannot switch on behalf of another domain.

### Preconditions for a forward switch (`to = Some(target)`)

All of the following must hold or the call returns an error:

| Check | Error |
|-------|-------|
| `from` is currently `Running` on `core_id` | `InvalidOperation` |
| `target` is `Sealed` | `DomainNotSealed` |
| `target.policy.cores` has bit `core_id` set | `PermissionDenied` |
| `target` is a **direct child or direct parent** of `from` in the domain CDT | `InvalidOperation` |

The CDT adjacency rule is the key restriction: a domain can only switch to its immediate parent or to one of its immediate children. Jumping to an unrelated domain (even in the same tree) is rejected. This means execution can only move one level at a time in the domain hierarchy, preserving the containment model.

The adjacency check is done by pointer equality (`Arc::ptr_eq`), not by ID comparison, to avoid TOCTOU races.

### Return switches (`to = None`)

Passing `None` as the target is a **return**: the engine resolves the parent via the `from` domain's weak parent pointer and redirects the core to it. If `from` has no parent (it is the root domain) the call returns `InvalidOperation`.

Return switches set `SwitchContext::is_return = true`, which callers can use to distinguish a domain call from a domain return.

### Effect

A successful switch atomically:
1. Reads the new domain's ID.
2. Overwrites `CoreContext::state` with `Running(new_id)`.
3. Returns a `SwitchContext` describing the transition.

No address-space updates are emitted by the switch itself — memory mappings are changed by capability operations (`send`, `carve`, `revoke`), not by the act of switching.

---

## Interrupt Routing

When a hardware interrupt arrives on a core running domain `D`, the engine walks the domain CDT **upward** from `D` to find the domain that should handle it.

### `route_interrupt(vector, interrupted, core_id) → Result<(handler_id, reported_to)>`

The walk follows the `InterruptPolicy` of each domain encountered:

```
interrupted (D)
    │  policy: Report  → add D to reported_to, keep walking
    │
  parent (P)
    │  policy: NotReport → skip, keep walking
    │
grandparent (G)
    │  policy: Deliver  → return (G.id, [D.id])
```

Each domain consulted has a `VectorPolicy` for the interrupt vector (with a default policy for vectors not explicitly overridden):

| Visibility | Behaviour |
|------------|-----------|
| `Deliver` | This domain is the handler. Walk stops and `(domain_id, reported_to)` is returned. |
| `Report` | Domain is added to `reported_to`; walk continues to parent. |
| `NotReport` | Domain is silently skipped; walk continues to parent. |

If the walk reaches the root without finding a `Deliver` domain, `InvalidOperation("No interrupt handler found")` is returned.

`reported_to` is an ordered list of domain IDs (from interrupted domain upward) that have `Report` visibility and thus need to be notified that an interrupt is in flight.

### `resume_after_interrupt(vector, handler, original_interrupted) → Result<Vec<u64>>`

After the handler finishes, the engine walks back **down** from the handler to the originally interrupted domain, collecting all domains with `Report` visibility in that path. This gives callers the list of domains to notify when the interrupt is complete.

The path is rebuilt bottom-up (from `original_interrupted` to `handler`) and then reversed, so the notified slice is top-down (handler-side first).

### `VectorPolicy` register masks

Each `VectorPolicy` carries two 64-bit bitmasks:

```rust
pub read_set:  u64,  // registers readable during interrupt handling
pub write_set: u64,  // registers writable during interrupt handling
```

These constrain which virtual processor state a `Report` domain may observe or modify while the interrupt is in flight. The engine records them in the policy but enforcement is left to the platform implementation.

---

## Interaction Between Switches and Revocation

When a domain is revoked while it is running on a core, the platform calls `on_domain_revoked(domain_id, fallback)`. The `fallback` is the first non-revoked ancestor domain ID, pre-computed by the capability engine during `revoke_child_domain`. The platform must redirect that core to `fallback` so it resumes executing a valid domain.

For vital-memory-triggered revocations the engine has no domain CDT context, so `fallback` is `None` and the platform must resolve the parent from its own `register_domain` map.
