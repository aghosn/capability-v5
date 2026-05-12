# lean-exec — Executable Lean 4 Model of Themis Capabilities

An executable Lean 4 model that implements the full Themis capability state
machine as computable functions. Imports type definitions from the
[ThemisCapa](../lean/) proof model and assumes single-threaded execution.

## Quick Start

### Prerequisites

- [Lean 4 / elan](https://lean-lang.org/lean4/doc/setup.html) — the `lean-toolchain` file pins `v4.29.0`

### Build

```bash
cd lean-exec
lake build
```

First build fetches Mathlib dependencies and compiles ~39 jobs. Subsequent
builds are incremental.

### Run the REPL

```bash
.lake/build/bin/leanexec
```

You get an interactive prompt:

```
╔══════════════════════════════════════════════════════════════╗
║  LeanExec — Executable Lean 4 model of Themis capabilities  ║
║  Type 'help' for commands, 'quit' to exit.                 ║
╚══════════════════════════════════════════════════════════════╝

capa> init root 0x1000000
Initialized: domain 'root' (id=0), root mem 'r0' (uid=0), size=0x1000000

capa> create-domain root child1 0b1111 GET,ATTEST,SWITCH
Created domain 'child1' (id=1), handle=h0 in 'root'

capa> carve r0 mem1 0x1000 0x1000 RWX
Carved 'mem1' (uid=1) from 'r0'

capa> send mem1 child1 CLEAN
Sent 'mem1' to 'child1'

capa> seal child1
Sealed domain 'child1'

capa> list
═══ Domains ═══
  [0] root — Sealed
    MemCaps:
      h0 → uid0 (r0): Carve Exclusive [0x0..0x1000000) RWX attrs=NONE
    DomCaps:
      h0 → child1 (id=1)
  [1] child1 — Sealed
    MemCaps:
      h0 → uid1 (mem1): Carve Exclusive [0x1000..0x2000) RWX attrs=NONE

capa> quit
```

### Load a session file

Session files are plain text, one command per line (`#` for comments).
The same files used by `capa-cli` work here:

```bash
# Interactive: load from within the REPL
capa> load ../capa-cli/examples/example_session.txt

# Non-interactive: pipe commands
echo -e "init root 0x1000000\nlist\nquit" | .lake/build/bin/leanexec
```

## Command Reference

| Command | Description |
|---------|-------------|
| `init <name> <size>` | Initialize root domain + memory |
| `create-domain <parent> <name> <cores> <api>` | Create child domain |
| `carve <parent> <name> <start> <size> <rights>` | Carve memory region |
| `alias <parent> <name> <start> <size> <rights>` | Alias memory region |
| `send <mem> <domain> [attrs] [at <gpa>]` | Send memory to domain |
| `seal <domain>` | Seal domain |
| `revoke <parent> <child>` | Revoke domain or memcap |
| `switch <domain> <core> <vp_id>` | Forward switch to VP |
| `switch <core>` | Return switch |
| `interrupt <vector> <domain> <core>` | Deliver interrupt |
| `list` | Show full state (all domains, cores, VPs) |
| `view <domain>` | Show domain address space |
| `enumerate-pending <domain>` | List pending transfers |
| `accept-capability <domain> <id> [at <gpa>]` | Accept pending memcap |
| `reject-capability <domain> <id>` | Reject pending memcap |
| `get-chan <target> <name>` | Get channel capability |
| `send-channel <chan> <receiver>` | Send channel to domain |
| `accept-channel <receiver> <id> <name>` | Accept pending channel |
| `reject-channel <receiver> <id>` | Reject pending channel |
| `add-vp <parent> <child> <comm> <vp_id>` | Add VP with COMM page |
| `register-comm <mem> <child> <vp_id>` | Register COMM page |
| `set-policy <parent> <child> <field> <value>` | Set policy field |
| `get-policy <parent> <child> <field>` | Get policy field |
| `set-register <parent> <child> <vp> <reg> <val>` | Set VP register |
| `get-register <parent> <child> <vp> <reg>` | Get VP register |
| `attest <domain>` | Attestation hash |
| `set-interrupt-policy <domain> <vec> <vis>` | Set interrupt visibility |
| `load <file>` | Load commands from file |
| `reset [numCores]` | Reset state (default 4 cores) |
| `help` | Show command help |
| `quit` / `exit` | Exit REPL |

Number formats: decimal (`42`), hex (`0x1000`), binary (`0b1111`).

Rights: `R`, `W`, `X`, `RW`, `RWX`, etc.

API flags: comma-separated from `GET`, `SEND`, `REVOKE`, `SEAL`, `ATTEST`,
`SWITCH`, `INTERRUPT`, `ALL`.

Attributes: `CLEAN`, `DEVICE`, `NONE`.

## Architecture

```
lean-exec/
├── Main.lean                      # Entry point
├── LeanExec.lean                  # Root import
└── LeanExec/
    ├── Types.lean                 # Type instances + flat executable structures
    ├── State.lean                 # ExecState (domain/memcap flat maps)
    ├── Monad.lean                 # CapaM = ExceptT CapaError (StateM ExecState)
    ├── Engine.lean                # Command dispatch + name→ID tracking
    ├── Cli.lean                   # Parser, REPL loop, session file loading
    └── Operations/
        ├── Memory.lean            # init, carve, alias, send, accept, reject, revoke
        ├── Domain.lean            # create, seal, revoke_domain
        ├── Channel.lean           # getChan, send/accept/reject channel
        ├── Switch.lean            # VP state machine, switch fwd/ret, interrupts
        ├── Policy.lean            # set/get policy, registers, interrupt policy
        └── Query.lean             # address space, enumerate, attest
```

All operations run in the `CapaM` monad — a pure state machine with no
concurrency, IO, or hardware interaction. The Lean proof model's types
(`ThemisCapa.Basic`, `ThemisCapa.Domain`, etc.) are imported directly;
future refinement proofs can bridge executable functions to the 83 existing
safety theorems.

## How It Differs from the Proof Model (`lean/`)

| Aspect | Proof model (`lean/`) | Executable model (`lean-exec/`) |
|--------|----------------------|-------------------------------|
| Style | Relational specs (`CarvePre/CarvePost : Prop`) | Computable functions (`carve : CapaM Unit`) |
| Executability | Not executable (propositions, not programs) | Fully executable, compiles to native binary |
| Concurrency | Not modeled | Single-threaded (no locking) |
| State | Nested inductive trees | Flat maps (domain/memcap by ID) |
| Purpose | Prove safety properties (83 theorems) | Run and test the state machine |
| CLI | None | Full REPL with same syntax as `capa-cli` |

## Relationship to capa-cli

`lean-exec` accepts the same command syntax as `capa-cli` (the Rust
implementation). Session files are interchangeable. The `capa-cli` binary
supports `--backend lean` to run the Lean model as a swappable backend
via C FFI, enabling differential testing against the Rust engine. See the
[regression README](../capa-cli/regression/README.md) and the
[root README](../README.md#differential-testing-lean--rust) for
how to run the cross-backend test suite.
