---
applyTo: "themis/capavisor/**"
---
# Capavisor Instructions

Before modifying any file under `themis/capavisor/`, read `skills/working-on-capavisor.md`.

Key rules:
- A1: Capability engine validates before hardware. `execute() → apply_update()` only.
- A2: Dom0 is NOT privileged. Never add `if domain_id == 0` bypasses.
- A5: META pool never in guest EPT. Use `MetaAllocator::alloc`.
- A9: Use domain-mediated interface. Never access capability tree directly.
- All hypercall handlers follow the `do_X` pattern (decode → execute → result).
- New hypercalls span 4 files: themis-abi opcodes, hypercall.rs, vmexit.rs, thhv.ko.
- Build with `cargo build-bins` from repo root after changes.
