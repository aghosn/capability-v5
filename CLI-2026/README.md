# Capability Engine CLI Simulator

An interactive command-line interface for experimenting with the Capability Engine V2.

## Features

- **Interactive REPL**: Experiment with capability operations in real-time
- **Tab Completion & Inline Hints**: Complete command names and capability names with TAB; usage hints appear as you type
- **Command History**: Navigate previous commands with arrow keys (persisted in `.capability_cli_history`)
- **Session Replay**: Save your session as replayable CLI commands and reload with `load`
- **Unit Test Export**: Export your session as a Rust unit test via `export-as-unit-test`
- **Interactive Tutorials**: Ten built-in guided tutorials covering basic to advanced scenarios
- **Auto-List Mode**: Toggle automatic `list` output after every command
- **Memory Usage Reporting**: Inspect logical memory footprint of all capability objects
- **Colored Output**: Visual feedback for better readability

## Installation

```bash
cd CLI-2026
cargo build --release
```

## Usage

```bash
cargo run
# or
./target/release/capability-cli
```

## Quick Start

```
cap> init root 0x1000000
✓ Created root domain 'root' and memory region 'r0' (size: 0x1000000)

cap> create-domain root child1 0b1111 GET,ATTEST,SWITCH
✓ Created domain 'child1' (ID: 1, cores: 0b1111)

cap> carve r0 mem1 0x1000 0x1000 RWX
✓ Carved memory region 'mem1' [0x1000..0x2000)

cap> send mem1 child1 CLEAN
✓ Sent 'mem1' to unsealed domain 'child1' with auto-allocated handle 1

cap> seal child1
✓ Sealed domain 'child1'

cap> view child1
Address Space for Domain 1:
Total accessible: 4096 bytes
Regions (1):
  0: [0x1000..0x2000) RWX

cap> mem-usage
...

cap> save-session my_session.txt
✓ Session saved to 'my_session.txt' (replay with: load my_session.txt)
```

> **Note:** `init <name> <size>` always names the root memory region `r0`.

## Command Reference

### Initialization

| Command | Description |
|---------|-------------|
| `init <name> <size>` | Create the root domain `<name>` and root memory region `r0` of the given size |

Example: `init root 0x1000000`

### Domain Management

| Command | Description |
|---------|-------------|
| `create-domain <parent> <name> <cores> <api>` | Create a child domain under `<parent>` |
| `seal <domain>` | Seal a domain (required before execution) |
| `set-interrupt-policy <domain> <vector> <visibility>` | Set policy for a specific interrupt vector |
| `set-default-interrupt-policy <domain> <visibility>` | Set the default policy for all vectors |
| `enumerate-pending <domain>` | List capabilities waiting to be accepted |
| `accept-capability <domain> <pending_id> [handle]` | Accept a pending capability |
| `reject-capability <domain> <pending_id>` | Discard a pending capability |

- **`<cores>`**: bitmask of allowed cores, e.g. `0b1111` (all 4) or `0b0011` (cores 0–1)
- **`<api>`**: comma-separated flags — `CREATE`, `SET`, `GET`, `SEND`, `SEAL`, `ATTEST`, `ENUMERATE`, `SWITCH`, `ALIAS`, `CARVE`, `REVOKE`, `GETCHAN`, `RECEIVE_AFTER_SEAL`, `ALL`, `NONE`
- **`<visibility>`**: `DELIVER`, `REPORT`, or `NOTREPORT`

### Memory Operations

| Command | Description |
|---------|-------------|
| `carve <parent> <name> <start> <size> <rights>` | Carve an exclusive sub-region from `<parent>` |
| `alias <parent> <name> <start> <size> <rights>` | Create a shared (aliased) sub-region from `<parent>` |

- **`<rights>`**: `R`, `RW`, `RX`, or `RWX`

### Capability Transfer

| Command | Description |
|---------|-------------|
| `send <mem> <domain> [attrs]` | Send a memory capability to a domain (handle auto-allocated) |
| `revoke <parent> <child>` | Revoke a child capability (domain or memory) |

- **`[attrs]`**: optional comma-separated flags — `CLEAN` (zero on revoke), `VITAL` (domain revoked when this is revoked), `META`, `NONE`
- Sending to a sealed domain with `RECEIVE_AFTER_SEAL` places the capability in the pending queue

### Information

| Command | Description |
|---------|-------------|
| `attest <domain>` | Generate an attestation report |
| `view <domain>` | Show address space layout for a domain |
| `list` | List all domains, memory regions, and per-core status |
| `mem-usage` | Report logical memory footprint of all capability objects |

### Execution

| Command | Description |
|---------|-------------|
| `switch <domain> <core>` | Switch to `<domain>` on `<core>` |
| `interrupt <vector> <core>` | Deliver an interrupt to the current domain on `<core>` |

Legacy two-argument forms are also accepted:
- `switch <core> <from> <to>`
- `interrupt <vector> <domain> <core>`

### Session Management

| Command | Description |
|---------|-------------|
| `save-session <filename>` | Save session as replayable CLI commands |
| `load <filename>` | Load and execute a saved session file |
| `export-as-unit-test <filename>` | Export session as a Rust unit test |
| `clear-session` | Clear the in-memory session history |
| `reset` | Reset CLI to its initial empty state |
| `auto-list` | Toggle auto-`list` after every command |

### Learning

| Command | Description |
|---------|-------------|
| `tutos` | List all available tutorials |
| `tutos <number>` | Run a specific tutorial interactively |

Ten tutorials are included:

| # | Title |
|---|-------|
| 1 | Memory Carving — Exclusive Ownership |
| 2 | Memory Aliasing — Shared Access |
| 3 | Capability Transfer with Send |
| 4 | Domain Switching — Context Switches |
| 5 | Interrupt Routing and Policies |
| 6 | Confidential VM with VirtIO Buffer |
| 7 | Nested Enclave Architecture |
| 8 | Sandboxed Execution Environment |
| 9 | Domain Encapsulation and Communication |
| 10 | Pending Capabilities and RECEIVE_AFTER_SEAL |

## Number Formats

| Format | Syntax | Example |
|--------|--------|---------|
| Hexadecimal | `0x` prefix | `0x1000`, `0x1000000` |
| Binary | `0b` prefix | `0b1111`, `0b0011` |
| Decimal | no prefix | `4096`, `16777216` |

## Session Workflow

`save-session` saves your session as plain CLI commands that can be replayed with `load`. Use `export-as-unit-test` to turn a session into a Rust unit test:

```bash
# In the CLI
cap> init root 0x1000000
cap> create-domain root child1 0b1111 GET,ATTEST,SWITCH
cap> carve r0 mem1 0x1000 0x1000 RWX
cap> send mem1 child1 CLEAN
cap> seal child1
cap> export-as-unit-test test_basic.rs

# Place the generated test in the engine test suite and run it
$ cp test_basic.rs ../2026/tests/
$ cd ../2026 && cargo test test_basic
```

## Examples

### CVM with Exclusive Memory

```
init root 0x1000000
create-domain root cvm 0b1111 GET,ATTEST,SWITCH
carve r0 cvm_mem 0x100000 0x100000 RWX
send cvm_mem cvm CLEAN
seal cvm
view cvm
```

### Nested Enclave Hierarchy

```
init root 0x1000000
create-domain root cvm 0b1111 CREATE,SEAL,CARVE,SEND,ATTEST
carve r0 cvm_mem 0x100000 0x200000 RWX
send cvm_mem cvm
seal cvm
create-domain cvm enclave 0b0011 GET,ATTEST
carve cvm_mem enclave_mem 0x100000 0x100000 RW
send enclave_mem enclave CLEAN
seal enclave
view enclave
```

### Shared Memory Between Domains

```
init root 0x2000000
create-domain root dom1 0b1111 GET,ATTEST,SWITCH
create-domain root dom2 0b1111 GET,ATTEST,SWITCH
alias r0 shared 0x200000 0x80000 RW
send shared dom1
send shared dom2
seal dom1
seal dom2
list
```

### Pending Capabilities (sealed receiver)

```
init root 0x1000000
create-domain root receiver 0b1111 GET,ATTEST,RECEIVE_AFTER_SEAL
seal receiver
carve r0 gift 0x1000 0x1000 RW
send gift receiver
enumerate-pending receiver
accept-capability receiver 0
```

## Troubleshooting

**"Domain not found"** — Use `list` to see exact names; names are case-sensitive.

**"Failed to carve"** — The requested range must lie within the parent region and must not overlap any existing carved child.

**"Monotonicity violation"** — Child domain core masks and API flags must be subsets of the parent's.

**"Domain not sealed"** — Most capability operations (carve, send, etc.) require the owning domain to be sealed first.

**"Send not allowed"** — The owning domain must have the `SEND` API flag.

## Architecture

| Crate | Role |
|-------|------|
| `rustyline` | Interactive line editing, history, tab completion |
| `colored` | Terminal colour output |
| `parking_lot` | Efficient `RwLock` for shared state |
| `capability-engine-v2` | Core capability and domain logic |

Commands are organised in `src/commands/` by concern: `domain`, `memory`, `info`, `execution`, `session_cmd`, `tutos`. The dispatcher in `mod.rs` routes parsed input to the appropriate handler. Tab completion and inline hints are driven by the static `COMMANDS` table in `src/completer.rs`.
