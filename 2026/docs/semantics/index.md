# Capability Engine — Semantics Wiki

This wiki describes the **high-level semantics** of the capability-based security system implemented in `2026/`. It is organised as a set of self-contained articles, each covering one aspect of the model.

## Articles

| Article | Summary |
|---------|---------|
| [Capabilities and the CDT](capabilities.md) | What a capability is, the Capability Derivation Tree, ownership, and handles |
| [Memory Capabilities](memory-capabilities.md) | Memory regions, access rights, attributes, and the exclusive/aliased distinction |
| [Domain Capabilities](domain-capabilities.md) | Trust domains, policies, sealing, the monitor API, and virtual processor states |
| [Operations](operations.md) | Alias, Carve, Send, Revoke, Create-Domain, Seal — rules and invariants |
| [Revocation](revocation.md) | Cascading revocation, the CLEAN and VITAL attributes, address-space restoration |
| [Switching and Interrupts](switching-and-interrupts.md) | Domain switches, return paths, interrupt routing through the CDT |
| [Address-Space Updates](updates.md) | UpdateBatch, update kinds, atomicity, and the Platform trait |
| [Monotonicity and Safety Properties](properties.md) | The invariants the engine enforces and why they matter |

## Background

The design follows the research paper  
*"Composable Isolation as a Foundation to Manage Trust in the Cloud"* (EuroS&P 2026).  
The central idea is that **every resource** (memory region, trust domain) is represented as a node in a tree called the **Capability Derivation Tree (CDT)**. Authority can only ever be *derived downward* — a child can hold at most the rights its parent holds. This single rule is the root of all safety properties described in this wiki.
