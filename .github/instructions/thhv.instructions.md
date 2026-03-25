---
applyTo: "thhv/**"
---
# thhv Kernel Module Instructions

Before modifying `thhv/`, read the thhv section of `CONTEXT.md` (§3 Component Map,
§4 Hypercalls, §5 IOEVENTFD/IRQFD) and `skills/working-on-capavisor.md` §"Adding a
New Hypercall" step 4.

Key rules:
- A7: thhv.ko is the ONLY dom0↔capavisor interface. All VMCALL wrappers live here.
- New hypercalls need: opcode in themis-abi, ioctl constant in thhv.h, handler in thhv.c.
- A6: COMM page is allocated by userspace, pinned by driver. Never allocate in kernel.
- Build requires matching kernel headers (check `dom0-kernel-version.txt`).
- Build with `cargo build-bins` from repo root after changes.
