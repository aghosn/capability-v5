# CLI Simulator

The CLI (`CLI-capa-engine/`) is an interactive REPL for experimenting with the capability engine. It wraps the engine library and provides named references, session management, and visualisation on top of the raw capability API.

## Quick Start

```bash
cd capa-cli
cargo run
```

```
cap> init root 0x1000000
cap> create-domain root app 0b1111 GET,ATTEST,SWITCH
cap> carve r0 mem1 0x1000 0x1000 RWX
cap> send mem1 app CLEAN
cap> seal app
cap> view app
```

## Architecture

```
CLI-capa-engine/
├── src/
│   ├── main.rs              — REPL loop, rustyline integration
│   ├── state.rs             — CliState: named maps for domains, memories, channels
│   ├── platform.rs          — CliPlatform (implements engine's Platform trait)
│   ├── update_processor.rs  — translates UpdateBatch into CliState mutations
│   ├── completer.rs         — tab completion and inline hints
│   ├── parser.rs            — number, rights, and attribute parsing
│   └── commands/
│       ├── mod.rs            — command dispatcher
│       ├── domain.rs         — create-domain, seal, revoke, pending, channels
│       ├── memory.rs         — carve, alias, send
│       ├── info.rs           — list, view, attest, mem-usage
│       ├── execution.rs      — switch, interrupt
│       ├── session_cmd.rs    — save-session, load, export-as-unit-test, reset
│       └── tutos.rs          — tutorial loader and runner
├── tutos/                   — tutorial scripts (see tutorials.md)
└── tests/
    └── tutorial_tests.rs    — integration tests that run every tutorial
```

The CLI holds no capability logic of its own — every operation delegates to `capability_engine::Capability::*` via `execute()`. The `CliPlatform` embeds a `SwitchManager` for context-switch simulation and an `UpdateProcessor` for consuming update batches.

## Key Concepts

**Named references.** The engine uses opaque `Handle` integers. The CLI maps human-readable names to `Arc<RwLock<Capability<T>>>` pointers so you can write `send mem1 app` instead of juggling handle IDs.

**Update processing.** Every engine operation returns an `UpdateBatch`. The CLI's `process_updates` function walks the batch and keeps `CliState` in sync — adding/removing domain and memory entries, printing a summary of changes.

**Sessions.** Commands are recorded in order. `save-session` writes them as a plain-text script replayable with `load`. `export-as-unit-test` emits a Rust test file that calls the engine API directly.

## Command Reference

See the [CLI README](../../CLI-capa-engine/README.md) for the full command table, number formats, and troubleshooting.

## Tutorials

The CLI ships with 13 interactive tutorials. See [tutorials.md](tutorials.md) for the full list and descriptions.

Run a tutorial:

```
cap> tutos        # list all tutorials
cap> tutos 1      # run tutorial 1
```

Tutorials are plain-text scripts in `CLI-capa-engine/tutos/` with `@msg` annotations for explanatory text. They are executed through the same `load` mechanism as saved sessions and are integration-tested via `cargo test --test tutorial_tests`.
