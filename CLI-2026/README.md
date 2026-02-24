# Capability Engine CLI Simulator

An interactive command-line interface for experimenting with the Capability Engine V2.

## Features

- **Interactive REPL**: Experiment with capability operations in real-time
- **Command History**: Navigate previous commands with arrow keys
- **Session Recording**: Save your session as a reusable unit test
- **Colored Output**: Visual feedback for better user experience
- **Comprehensive Help**: Built-in documentation for all commands

## Installation

```bash
cd CLI-2026
cargo build --release
```

## Usage

Start the CLI:

```bash
cargo run
```

Or run the compiled binary:

```bash
./target/release/capability-cli
```

## Quick Start Example

```
cap> init root 0x1000000
✓ Created root domain 'root_domain' and memory region 'root_mem' (size: 0x1000000)

cap> create-domain root_domain child1 0b1111 GET,ATTEST,SWITCH
✓ Created domain 'child1' (ID: 1, cores: 0b1111)

cap> carve root_mem mem1 0x1000 0x1000 RWX
✓ Carved memory region 'mem1' [0x1000..0x2000) RWX (0 updates)

cap> send mem1 child1 10 CLEAN
✓ Sent 'mem1' to 'child1' with handle 10 (1 updates)

cap> seal child1
✓ Sealed domain 'child1'

cap> view child1
Address Space View:
Address Space for Domain 1:
Total accessible: 4096 bytes
Regions (1):
  0: [0x1000..0x2000) RWX

cap> list
Domains:
  • root_domain (ID: 0, status: Sealed)
  • child1 (ID: 1, status: Sealed)

Memory Regions:
  • root_mem [0x0..0x1000000) RWX (kind: Root)
  • mem1 [0x1000..0x2000) RWX (kind: Carve)

cap> save-session my_test.rs
✓ Session saved to 'my_test.rs'
```

## Command Reference

### Initialization

- **`init <name> <size>`** - Initialize root domain and memory region
  - Example: `init root 0x1000000`

### Domain Management

- **`create-domain <parent> <name> <cores> <api>`** - Create a child domain
  - Example: `create-domain root_domain child1 0b1111 GET,ATTEST,SWITCH`
  - API flags: CREATE, SET, GET, SEND, SEAL, ATTEST, ENUMERATE, SWITCH, ALIAS, CARVE, REVOKE, GETCHAN, ALL, NONE

- **`seal <domain>`** - Seal a domain (make it ready for execution)
  - Example: `seal child1`

### Memory Operations

- **`carve <parent> <name> <start> <size> <rights>`** - Carve exclusive memory from parent
  - Example: `carve root_mem mem1 0x1000 0x1000 RWX`
  - Rights: R (read), W (write), X (execute), or combinations like RW, RWX

- **`alias <parent> <name> <start> <size> <rights>`** - Create aliased (shared) memory
  - Example: `alias root_mem mem2 0x2000 0x1000 RW`

### Capability Transfer

- **`send <mem> <domain> <handle> [attrs]`** - Send memory capability to domain
  - Example: `send mem1 child1 10 CLEAN`
  - Attributes: CLEAN, VITAL, NONE

- **`revoke <parent> <child>`** - Revoke a child capability
  - Example: `revoke root_mem mem1`

### Information

- **`attest <domain>`** - Generate attestation report for domain
  - Example: `attest child1`

- **`view <domain>`** - Show address space view for domain
  - Example: `view child1`

- **`list`** - List all domains and memory regions

### Execution

- **`switch <core> <from> <to>`** - Switch between domains on a core
  - Example: `switch 0 root_domain child1`

- **`interrupt <vector> <domain> <core>`** - Simulate an interrupt
  - Example: `interrupt 6 child1 0`

### Session Management

- **`save-session <filename>`** - Save current session as a unit test
  - Example: `save-session my_test.rs`
  - The generated test can be placed in `../2026/tests/` and run with `cargo test`

- **`clear-session`** - Clear session history

### Other

- **`help`** - Show help message
- **`exit`** or **`quit`** - Exit the CLI

## Number Formats

The CLI supports multiple number formats:

- **Hexadecimal**: Prefix with `0x` (e.g., `0x1000`, `0x1000000`)
- **Binary**: Prefix with `0b` (e.g., `0b1111`, `0b1100`)
- **Decimal**: No prefix (e.g., `4096`, `1000000`)

## Session Export

The `save-session` command exports your interactive session as a Rust unit test. This is useful for:

1. **Regression Testing**: Turn exploration into permanent test cases
2. **Documentation**: Create executable examples
3. **Reproducibility**: Share exact sequences of operations

Example workflow:

```bash
# In CLI
cap> init root 0x1000000
cap> create-domain root_domain child1 0b1111 GET,ATTEST
cap> carve root_mem mem1 0x1000 0x1000 RWX
cap> send mem1 child1 10 CLEAN
cap> seal child1
cap> save-session test_basic_workflow.rs

# Copy to test directory
$ cp test_basic_workflow.rs ../2026/tests/

# Run the test
$ cd ../2026
$ cargo test test_basic_workflow
```

## Command History

The CLI maintains a command history in `.capability_cli_history`. Use arrow keys to navigate:

- **Up Arrow**: Previous command
- **Down Arrow**: Next command
- **Ctrl+R**: Search history (rustyline feature)

## Architecture

The CLI is built on:

- **rustyline**: Interactive line editing and history
- **colored**: Terminal color output
- **capability-engine**: The core capability system

The session recorder translates CLI commands into valid Rust test code, maintaining the exact semantics of your interactive session.

## Tips

1. **Use tab completion** (if your terminal supports it) for long names
2. **Start with `list`** after commands to see the current state
3. **Use `view <domain>`** to verify address space layouts
4. **Save sessions frequently** to preserve complex setups
5. **Use descriptive names** for better generated test code

## Examples

### Creating a CVM with Exclusive Memory

```
init root 0x1000000
create-domain root_domain cvm 0b1111 GET,ATTEST,SWITCH
carve root_mem cvm_mem 0x100000 0x100000 RWX
send cvm_mem cvm 10 CLEAN
seal cvm
view cvm
```

### Creating an Enclave Hierarchy

```
init root 0x1000000
create-domain root_domain cvm 0b1111 CREATE,SEAL,CARVE,ATTEST
carve root_mem cvm_mem 0x100000 0x200000 RWX
send cvm_mem cvm 10 NONE
seal cvm
create-domain cvm enclave 0b0011 GET,ATTEST
carve cvm_mem enclave_mem 0x100000 0x100000 RW
send enclave_mem enclave 20 CLEAN
seal enclave
view enclave
save-session test_enclave_hierarchy.rs
```

### Shared Memory Between Domains

```
init root 0x2000000
create-domain root_domain dom1 0b1111 GET,ATTEST,SWITCH
create-domain root_domain dom2 0b1111 GET,ATTEST,SWITCH
alias root_mem shared_mem 0x200000 0x80000 RW
send shared_mem dom1 10 NONE
send shared_mem dom2 11 NONE
seal dom1
seal dom2
list
```

## Troubleshooting

### "Domain not found"
Make sure you use the exact name given when creating the domain. Use `list` to see all available names.

### "Failed to carve"
Check that the memory range is valid and within the parent region's bounds.

### "Monotonicity violation"
Child domain policies must be subsets of parent policies. Reduce the API permissions or core mask.

### Session export issues
The generated test may need minor adjustments for proper capability ID management in complex scenarios.

## Contributing

This CLI is part of the Capability Engine V2 project. For issues or feature requests, please refer to the main project repository.
