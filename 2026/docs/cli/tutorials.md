# CLI Tutorials

The CLI includes 13 interactive tutorials that demonstrate capability engine concepts from basic operations to real-world architectures. Run them with `tutos <number>`.

## Basic Tutorials (1–7)

These cover the fundamental building blocks of the capability model.

| # | File | Topic | Concepts |
|---|------|-------|----------|
| 1 | `01-basic-carve.txt` | Memory Carving | Exclusive sub-regions, rights attenuation, parent access loss |
| 2 | `02-basic-alias.txt` | Memory Aliasing | Shared sub-regions, overlapping access, alias vs carve |
| 3 | `03-basic-send.txt` | Capability Transfer | Sending memory to domains, ownership attributes (CLEAN, VITAL) |
| 4 | `04-basic-switch.txt` | Domain Switching | Context switches, VP call chains, core assignment |
| 5 | `05-basic-interrupts.txt` | Interrupt Routing | Interrupt policies (DELIVER, REPORT, NOTREPORT), VP suspension |
| 6 | `06-pending-capabilities.txt` | Pending Capabilities | RECEIVE_AFTER_SEAL, pending queue, accept/reject lifecycle |
| 7 | `07-meta-regions.txt` | META Regions | Monitor-private memory, attestation visibility, forbidden operations |

## Advanced Tutorials (8–13)

These build on the basics to demonstrate realistic system architectures.

| # | File | Topic | Concepts |
|---|------|-------|----------|
| 8 | `08-cvm-virtio.txt` | CVM with VirtIO | Confidential VM, shared I/O buffer, attestation |
| 9 | `09-nested-enclave.txt` | Nested Enclaves | CVM with inner enclave, hierarchical isolation |
| 10 | `10-sandbox.txt` | Sandboxed Execution | Aliased memory sandbox, limited permissions |
| 11 | `11-encapsulation.txt` | Domain Encapsulation | Isolation boundaries, parent-mediated communication |
| 12 | `12-sibling-attestation.txt` | Sibling Attestation | Channels between enclaves, cross-attestation, shared memory |
| 13 | `13-driver-channels.txt` | Driver Channels | Channel-based driver isolation, CVM ↔ device communication |

## Writing Tutorials

Tutorials are plain-text files in `CLI-2026/tutos/`. Each line is either:

- A CLI command (executed normally)
- `@msg <text>` — printed as explanatory text (not executed)
- `# comment` — ignored
- `# EXPECT_FAIL` — marks the next command as intentionally failing

Register new tutorials in `index.txt` (pipe-delimited: `filename|title|description`) and add a test function in `tests/tutorial_tests.rs`.

## Related Documentation

- [Memory semantics](../semantics/memory.md) — carve, alias, rights, attributes (tutorials 1–3, 7)
- [Domain semantics](../semantics/domain.md) — lifecycle, channels, pending caps, attestation (tutorials 4–6, 8–13)
- [API walkthrough](../semantics/api.md) — end-to-end operation flow
- [Switch and interrupts](../implementation/switch.md) — VP states, interrupt routing (tutorial 5)
