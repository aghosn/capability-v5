---
applyTo: "lean-exec/**"
---
# Lean Executable Model Instructions

Before modifying any file under `lean-exec/`, read `skills/working-on-lean-exec.md`.

Key rules:
- lean-exec models ONLY the capa-engine — no CLI concerns in the engine model
- CLI-layer concepts (user-facing UIDs, names, formatting) belong in `lean_backend.rs`, NOT here
- `ExecState` and `ExecDomain` fields must have counterparts in `capa-engine/src/`
- `FFI.lean` marshals data only — CLI logic belongs in `capa-cli/src/lean_backend.rs`
- `CapNodeId` is the internal flat-store key (replaces Arc pointers); it is NOT a user-facing ID
- Build with `cd lean-exec/ && lake build` for standalone, or
  `cd capa-cli/ && cargo build --release --features lean-backend` for FFI mode
- Run differential tests after changes: compare `--backend rust` vs `--backend lean` on tutos
