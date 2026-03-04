# API Operations — End-to-End Flow

This document describes the full lifecycle of a capability system session using the CLI command vocabulary. It shows how operations compose and depend on one another.

The CLI (`CLI-2026/`) is the reference interactive environment for experimenting with these operations. All examples below use `cap>` to denote CLI prompts. See the [tutorial index](../cli/tutorials.md) for 13 interactive walkthroughs covering each operation.

---

## The Full Lifecycle

### 1. Initialization

Every session starts with `init`, which creates the root domain and the root memory region (`r0`):

```
cap> init root 0x1000000
✓ Created root domain 'root' and memory region 'r0' (size: 0x1000000)
```

The root domain is **pre-sealed** and owns all cores. `r0` is an exclusive, RWX memory region covering the entire physical inventory.

---

### 2. Domain Creation

Child domains are created under a sealed parent. The child's core mask and API permissions must be subsets of the parent's:

```
cap> create-domain root app 0b1111 CREATE,SEAL,CARVE,SEND,ATTEST
✓ Created domain 'app' (ID: 1, cores: 0b1111)
```

A newly created domain is **unsealed**. It cannot execute, and capability operations cannot be called from it yet. The domain can be configured (memory carved and sent to it, interrupt policies set) before sealing.

---

### 3. Carving and Aliasing Memory

Memory is distributed by creating children of an existing memory region:

**Carve** — exclusive ownership. The parent loses access to the carved range:

```
cap> carve r0 app_mem 0x100000 0x200000 RWX
✓ Carved memory region 'app_mem' [0x100000..0x300000)
```

**Alias** — shared access. Both parent and child can access the range simultaneously:

```
cap> alias r0 shared_buf 0x800000 0x10000 RW
✓ Aliased memory region 'shared_buf' [0x800000..0x810000)
```

Rights can be attenuated (narrowed) at any derivation step but never amplified.

---

### 4. Sending Capabilities to Domains

A memory region is sent to a domain to grant it access. Handles are auto-allocated:

```
cap> send app_mem app
✓ Sent 'app_mem' to unsealed domain 'app' with auto-allocated handle 1
```

Optional ownership attributes can be set at send time:
- `CLEAN` — zero the memory before restoring parent access on revocation.
- `VITAL` — if this region is revoked, also revoke the domain that owns it.

```
cap> send app_mem app CLEAN,VITAL
```

Sending to an unsealed domain is the normal setup path. Sending to a **sealed** domain requires the domain to have `RECEIVE_AFTER_SEAL` in its API — the capability lands in a pending queue and must be explicitly accepted (see [domain.md § Pending Capabilities](domain.md#pending-capabilities--receive_after_seal)).

---

### 5. Sealing Domains

Once configured, a domain is sealed to make it executable:

```
cap> seal app
✓ Sealed domain 'app'
```

Sealing is one-way. After sealing:
- The domain's policy is frozen.
- The domain can now invoke `MonitorAPI` operations (subject to its policy).
- The domain can be switched to on a core.

---

### 6. Inspecting State

```
cap> list
# Prints all domains, memory regions, and current core assignments.

cap> view app
# Prints the merged address-space view for domain 'app'.

cap> attest app
# Generates and prints an attestation report for domain 'app'.
```

---

### 6b. Channels

A channel is a restricted capability that grants communication access to a domain without administrative control. It is obtained via `get-chan`:

```
cap> get-chan root dom1
✓ Created channel capability to 'dom1' (handle: 2)
```

Once obtained, a channel can be used to attest or send memory to the target:

```
cap> attest chan1          # report is for dom1; checks root has ATTEST
cap> send mem1 chan1       # forwards to dom1; checks root has SEND
```

Channels can be transferred to other domains (move semantics):

```
cap> send-channel dom0 chan1 dom2
✓ Channel in transit (pending ID: 1)

cap> accept-channel dom2 1
✓ dom2 now holds channel to dom1
```

See [domain.md § get-chan](domain.md#get-chan--obtain-a-channel-capability) for full semantics.

---

### 7. Switching and Interrupts

Execution is transferred between domains via explicit switches. A switch can only move one level in the domain hierarchy at a time (parent ↔ direct child):

```
cap> switch app 0 0
✓ Core 0 now executing domain 'app' (VP 0)
```

Interrupt routing is handled automatically based on per-domain interrupt policies set before sealing:

```
cap> set-interrupt-policy app 42 REPORT
cap> set-default-interrupt-policy app NOTREPORT
cap> seal app

cap> interrupt 42 0
✓ Interrupt 42 routed: app(REPORT) → root(DELIVER)
```

See [semantics/domain.md § Interrupt Policy](domain.md#interrupt-policy) and [implementation/switch.md](../implementation/switch.md) for the full interrupt routing rules.

---

### 8. Revocation

Revoking a child capability destroys it and all capabilities derived from it:

```
cap> revoke r0 app_mem
✓ Revoked 'app_mem' and all its descendants. Parent 'r0' regains access.
```

Domain revocation cascades through the domain subtree:

```
cap> revoke root app
✓ Revoked domain 'app' and all child domains.
```

---

## Operation Dependency Summary

```
init
 └─ create-domain        (parent must be sealed)
     └─ seal             (after configuration)
          ├─ get-chan     (requires GETCHAN; target must be sealed)
          │   └─ send-channel / accept-channel / reject-channel
          ├─ switch      (requires sealed target)
          └─ revoke      (requires REVOKE API permission on caller)

init
 └─ carve / alias        (parent memory must exist)
     └─ send             (memory region + target domain must exist)
         └─ revoke       (parent must hold the REVOKE permission)
```

All capability operations (carve, alias, send, revoke on memory; create-domain, revoke on domains) require the **operating domain** to be sealed and to hold the corresponding `MonitorAPI` permission bit. Root domain capabilities bypass this check (root is always sealed with all permissions).
