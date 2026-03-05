#!/usr/bin/env bash
# gdb.sh — Attach rust-gdb to an already-running QEMU GDB stub.
#
# Usage:
#   cargo gdb                # from workspace root via Cargo alias
#   bash scripts/gdb.sh      # directly
#
# This connects to a QEMU instance that was started separately (e.g. via
# `cargo themis` with QEMU_EXTRA_ARGS="-s -S"`, or via `cargo themis-debug`
# in another terminal).
#
# The GDB stub is expected on localhost:1234 (QEMU default).
#
# Environment knobs:
#   GDB_PORT=1234            GDB remote port (default: 1234)
#   GDB=rust-gdb             GDB binary override

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

GDB_PORT="${GDB_PORT:-1234}"

# Select GDB binary (prefer rust-gdb for pretty printers)
GDB="${GDB:-$(command -v rust-gdb 2>/dev/null || command -v gdb)}"

echo "→ Attaching $GDB to localhost:${GDB_PORT} ..."

cd "$WORKSPACE_ROOT"
exec "$GDB" \
    -ex "target remote :${GDB_PORT}" \
    -x "themis.gdbinit"
