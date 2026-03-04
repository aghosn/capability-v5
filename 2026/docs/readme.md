# Capability Engine — Documentation

This folder contains the design and implementation documentation for the capability engine.

## Structure

```
docs/
├── readme.md              — this file
├── semantics/             — capability model semantics (what the engine does)
│   ├── capabilities.md    — the Capability Derivation Tree, handles, ownership, safety properties
│   ├── api.md             — end-to-end API flow using CLI-style operations
│   ├── memory.md          — memory region capabilities: rights, attributes, operations
│   └── domain.md          — domain capabilities: lifecycle, policy, operations
├── implementation/        — implementation notes (how the engine does it)
│   ├── readme.md          — module overview and data-flow diagram
│   ├── capabilities.md    — Capability<T> internals, extension traits
│   ├── concurrency.md     — global RW lock, execute(), IPI/barrier protocol, loom
│   ├── updates.md         — Update enum, UpdateBatch, UpdateProcessor
│   ├── platform.md        — Platform trait, contract per method, reference implementations
│   └── switch.md          — SwitchManager, VP states, switching, interrupt routing
└── cli/                   — CLI simulator documentation
    ├── readme.md          — architecture, key concepts, quick start
    └── tutorials.md       — tutorial index and authoring guide
└── design/                — design documents for planned features
    └── address_translation.md — address translation layer (GPA, cache colors)
```

## Where to Start

**Unfamiliar with the model?** Start with [semantics/capabilities.md](semantics/capabilities.md) for the core concepts, then read [semantics/api.md](semantics/api.md) for an end-to-end walkthrough.

**Looking for memory or domain semantics?** See [semantics/memory.md](semantics/memory.md) and [semantics/domain.md](semantics/domain.md) — each includes allowed operations with success and failure examples.

**Working on the implementation?** Start with [implementation/readme.md](implementation/readme.md) for the module map, then dive into the specific module document.

**Adding a new platform backend?** See [implementation/platform.md](implementation/platform.md).

**Using the CLI simulator?** See [cli/readme.md](cli/readme.md) for architecture and commands, [cli/tutorials.md](cli/tutorials.md) for the 13 interactive tutorials.
