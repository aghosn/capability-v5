---
applyTo: "capa-engine/**"
---
# Capability Engine Instructions

Before modifying any file under `capa-engine/`, read `skills/working-on-capability-engine.md`.

Key rules:
- All operations go through the domain-mediated API (`Capability::<Domain>::*`)
- All calls wrapped in `execute(&platform, exclusive, || { ... })`
- Shared lock for non-destructive ops; exclusive lock for any revoke
- Run `cargo test` after every change; `cargo loom` after concurrent code changes
- New features require at least one unit/integration test
- Verify `cd capa-cli/ && cargo build --release` still works (API compatibility)
