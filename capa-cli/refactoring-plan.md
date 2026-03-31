# Refactoring Plan: Backend Trait Abstraction

## Goal

Introduce a `Backend` trait that abstracts the capability engine, enabling
`capa-cli` to swap between:
- **RustBackend** — wraps the current `capa-engine` Rust library
- **LeanBackend** — calls `lean-exec` via C FFI

This enables differential testing: run the same session file through both
backends and verify identical output. The CLI handles ALL parsing and display;
the backend handles ONLY state-machine computation.

## Current Architecture (before refactoring)

```
capa-cli
  ├── CliState
  │     domains: HashMap<String, Arc<RwLock<Capability<Domain>>>>
  │     memories: HashMap<String, Arc<RwLock<Capability<MemoryRegion>>>>
  │     platform: Arc<CliPlatform>
  │
  ├── commands/domain.rs   ── calls Capability::create, seal, revoke, ...
  ├── commands/memory.rs   ── calls Capability::carve, alias, send, ...
  ├── commands/execution.rs ── calls Capability::<Domain>::switch, ...
  ├── commands/info.rs     ── reads .data.*, .owned.*, .children for display
  └── update_processor.rs  ── processes UpdateBatch (Update enum variants)
```

**Problem:** The CLI holds `Arc<RwLock<Capability<T>>>` directly and reads
internal engine fields (~50+ `.data.*` accesses). This makes it impossible to
swap to a different engine implementation.

## Target Architecture (after refactoring)

```
capa-cli
  ├── CliState
  │     domain_names: HashMap<String, DomainId>
  │     mem_names: HashMap<String, MemCapUid>
  │     backend: Box<dyn Backend>
  │
  ├── backend.rs           ── Backend trait + DTO structs (NEW)
  ├── rust_backend.rs      ── RustBackend impl (wraps capa-engine) (NEW)
  ├── lean_backend.rs      ── LeanBackend impl (C FFI) (NEW, feature-gated)
  │
  ├── commands/domain.rs   ── calls state.backend.create_domain(), ...
  ├── commands/memory.rs   ── calls state.backend.carve(), ...
  ├── commands/execution.rs ── calls state.backend.switch_forward(), ...
  ├── commands/info.rs     ── calls state.backend.list_domains(), renders DTOs
  └── update_processor.rs  ── iterates Vec<HwUpdate> for display
```

**CLI only holds:** `name → DomainId` and `name → MemCapUid` mappings.
The backend resolves all internal handles, Arc references, and capability
tree lookups. No engine-internal types leak to the CLI.

## Backend Trait

```rust
pub type DomainId = u64;
pub type MemCapUid = u64;

pub trait Backend {
    // --- Lifecycle ---
    fn init(&mut self, size: u64) -> Result<InitResult>;
    fn reset(&mut self, num_cores: usize);

    // --- Memory ---
    fn carve(&mut self, owner: DomainId, parent: MemCapUid,
             start: u64, size: u64, rights: u8) -> Result<(MemCapUid, Vec<HwUpdate>)>;
    fn alias(&mut self, owner: DomainId, parent: MemCapUid,
             start: u64, size: u64, rights: u8) -> Result<(MemCapUid, Vec<HwUpdate>)>;
    fn send(&mut self, mem: MemCapUid, receiver: DomainId,
            attrs: u8, gpa: Option<u64>) -> Result<Vec<HwUpdate>>;
    fn accept(&mut self, domain: DomainId, pending_id: u64,
              gpa: Option<u64>) -> Result<(MemCapUid, Vec<HwUpdate>)>;
    fn reject(&mut self, domain: DomainId, pending_id: u64) -> Result<()>;
    fn revoke_mem(&mut self, owner: DomainId, parent: MemCapUid,
                  child: MemCapUid) -> Result<Vec<HwUpdate>>;

    // --- Domains ---
    fn create_domain(&mut self, parent: DomainId, cores: u64,
                     api: u64) -> Result<(DomainId, Vec<HwUpdate>)>;
    fn seal(&mut self, owner: DomainId, child: DomainId) -> Result<()>;
    fn revoke_domain(&mut self, parent: DomainId,
                     child: DomainId) -> Result<Vec<HwUpdate>>;

    // --- Channels ---
    fn get_chan(&mut self, caller: DomainId, target: DomainId) -> Result<DomainId>;
    fn send_channel(&mut self, caller: DomainId, chan: DomainId,
                    receiver: DomainId) -> Result<()>;
    fn accept_channel(&mut self, receiver: DomainId,
                      pending_id: u64) -> Result<DomainId>;
    fn reject_channel(&mut self, receiver: DomainId,
                      pending_id: u64) -> Result<()>;

    // --- VP & Switch ---
    fn add_vp(&mut self, parent: DomainId, child: DomainId,
              comm: MemCapUid, vp_id: u32) -> Result<Vec<HwUpdate>>;
    fn register_comm(&mut self, owner: DomainId, mem: MemCapUid,
                     child: DomainId, vp_id: u32) -> Result<Vec<HwUpdate>>;
    fn switch_forward(&mut self, domain: DomainId, core: u64,
                      vp_id: u64) -> Result<SwitchContextDto>;
    fn switch_return(&mut self, core: u64) -> Result<SwitchContextDto>;
    fn deliver_interrupt(&mut self, vector: u8, domain: DomainId,
                         core: u64) -> Result<()>;

    // --- Policy & Registers ---
    fn set_policy(&mut self, parent: DomainId, child: DomainId,
                  field: &str, value: u64) -> Result<()>;
    fn get_policy(&self, parent: DomainId, child: DomainId,
                  field: &str) -> Result<u64>;
    fn set_register(&mut self, parent: DomainId, child: DomainId,
                    vp: u64, reg: u64, value: u64) -> Result<()>;
    fn get_register(&self, parent: DomainId, child: DomainId,
                    vp: u64, reg: u64) -> Result<u64>;
    fn set_interrupt_policy(&mut self, domain: DomainId,
                            vector: u8, visibility: u64) -> Result<()>;

    // --- Queries (for display) ---
    fn list_domains(&self) -> Vec<DomainInfoDto>;
    fn get_domain_mem_caps(&self, id: DomainId) -> Vec<MemCapInfoDto>;
    fn get_domain_dom_caps(&self, id: DomainId) -> Vec<DomCapInfoDto>;
    fn get_pending_caps(&self, id: DomainId) -> Vec<PendingCapDto>;
    fn get_address_space(&self, id: DomainId) -> Vec<AddressRegionDto>;
    fn get_core_states(&self) -> Vec<CoreStateDto>;
    fn attest(&self, id: DomainId) -> Result<String>;
}
```

## DTO Structs

```rust
pub struct InitResult {
    pub domain_id: DomainId,
    pub mem_uid: MemCapUid,
}

pub struct DomainInfoDto {
    pub id: DomainId,
    pub status: String,             // "Unsealed" | "Sealed" | "Revoked"
    pub is_channel: bool,
    pub channel_target: Option<DomainId>,
    pub cores_bitmap: u64,
    pub api_flags: String,          // "CREATE,SEND,ATTEST,..."
    pub num_vps: usize,
    pub vp_states: Vec<VpStateDto>,
}

pub struct VpStateDto {
    pub vp_id: u64,
    pub state: String,              // "Available" | "Running" | "Locked" | ...
}

pub struct MemCapInfoDto {
    pub uid: MemCapUid,
    pub local_handle: u64,
    pub start: u64,
    pub end: u64,
    pub rights: String,
    pub kind: String,               // "Carve" | "Alias"
    pub status: String,             // "Exclusive" | "Aliased"
    pub attributes: String,
    pub owner_id: DomainId,
    pub num_children: usize,
    pub children: Vec<MemCapInfoDto>,
}

pub struct DomCapInfoDto {
    pub local_handle: u64,
    pub domain_id: DomainId,
    pub is_channel: bool,
}

pub struct PendingCapDto {
    pub pending_id: u64,
    pub sender_id: DomainId,
    pub start: u64,
    pub end: u64,
    pub rights: String,
}

pub struct CoreStateDto {
    pub core_id: u64,
    pub state: String,              // "idle" | "running"
    pub domain_id: Option<DomainId>,
    pub vp_id: Option<u64>,
}

pub struct SwitchContextDto {
    pub from_domain: DomainId,
    pub to_domain: DomainId,
    pub core_id: u64,
    pub from_vp: Option<u64>,
    pub to_vp: Option<u64>,
}

pub struct AddressRegionDto {
    pub gpa: u64,
    pub size: u64,
    pub rights: String,
    pub is_identity_mapped: bool,
}

pub struct HwUpdate {
    pub kind: String,               // "MapMemory" | "UnmapMemory" | "ZeroMemory" | ...
    pub domain_id: DomainId,
    pub gpa: u64,
    pub size: u64,
    pub rights: Option<String>,
}
```

## Implementation Phases

### Phase 10a: `backend.rs` — Define the trait + DTOs ✅ DONE
Created `capa-cli/src/backend.rs` with `Backend` trait (~30 methods) and all
DTO structs. Commit `f3c4e82`.

### Phase 10b: `rust_backend.rs` — Wrap existing capa-engine ✅ DONE
Created `capa-cli/src/rust_backend.rs` (1065 lines). Wraps all `Capability::*`
calls with UID tracking, handle resolution, error/update conversion. Uses
domain-mediated API throughout (except init bootstrap and `add_vprocessor`
which has no mediated API). Commit `f3c4e82`.

### Phase 10c: Refactor CLI to use Backend trait ← NEXT
Four sub-steps (can be done incrementally, one file at a time):

1. **`state.rs`**: Replace `domains`/`memories` with `domain_names`/`mem_names` +
   `backend: Box<dyn Backend>`. Remove `platform` field (moved into backend).

2. **`commands/domain.rs`**: Replace `Capability::create(...)` with
   `state.backend.create_domain(parent_id, cores, api)`. Replace all Arc
   lookups with DomainId/MemCapUid lookups from `state.domain_names`/`mem_names`.

3. **`commands/memory.rs`**: Replace `Capability::carve/alias/send/accept/reject`
   with `state.backend.carve/alias/send/accept/reject`. The backend resolves
   sender domain + handles internally.

4. **`commands/execution.rs`**: Replace `Capability::<Domain>::switch` with
   `state.backend.switch_forward/switch_return`.

5. **`commands/info.rs`**: Replace all `.data.*` reads with
   `state.backend.list_domains()`, `state.backend.get_domain_mem_caps(id)`, etc.

6. **`update_processor.rs`**: Work with `Vec<HwUpdate>` instead of `UpdateBatch`.

### Phase 10d: Lean FFI exports
In `lean-exec/LeanExec/FFI.lean`, export C-callable functions matching each
Backend method. Build lean-exec as a shared library.

### Phase 10e: `lean_backend.rs` — Call Lean via FFI
Create `capa-cli/src/lean_backend.rs` (feature-gated behind `lean-backend`):
- Links against `libleanexec.so`
- Each trait method calls the corresponding `extern "C"` function
- Marshals Rust types to/from C primitives

### Phase 10f: `--backend` flag + differential testing
- Add `--backend rust|lean` CLI argument
- Create `tests/diff-test.sh`: runs tutorial sessions through both backends,
  diffs output

## File Changes Summary

| File | Change |
|------|--------|
| `src/backend.rs` | NEW — Backend trait + DTOs |
| `src/rust_backend.rs` | NEW — RustBackend wrapping capa-engine |
| `src/lean_backend.rs` | NEW — LeanBackend via C FFI (feature-gated) |
| `src/state.rs` | MODIFY — replace Arc maps with ID maps + backend |
| `src/commands/domain.rs` | MODIFY — use backend methods |
| `src/commands/memory.rs` | MODIFY — use backend methods |
| `src/commands/execution.rs` | MODIFY — use backend methods |
| `src/commands/info.rs` | MODIFY — use DTO queries |
| `src/update_processor.rs` | MODIFY — Vec<HwUpdate> |
| `src/platform.rs` | MODIFY — move into RustBackend |
| `src/main.rs` | MODIFY — --backend flag, instantiate backend |
| `Cargo.toml` | MODIFY — lean-backend feature flag |
