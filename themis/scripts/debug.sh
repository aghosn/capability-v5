#!/usr/bin/env bash
# debug.sh — Boot Themis in QEMU with GDB remote stub enabled, then launch
#             GDB in the foreground connected to it.
#
# Usage:
#   cargo debug             # from workspace root via Cargo alias
#   bash scripts/debug.sh
#
# Requires: gdb or rust-gdb, qemu-system-x86_64
# Uses the .gdbinit in the workspace root for initial GDB commands.
#
# Environment knobs (same as run-qemu.sh):
#   QEMU_MEM, QEMU_CPUS, QEMU_ENABLE_KVM, QEMU_EXTRA_ARGS

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Always build debug profile for symbolised output
PROFILE=debug bash "$SCRIPT_DIR/build-iso.sh"

ISO="$WORKSPACE_ROOT/target/themis.iso"

QEMU_CPUS="${QEMU_CPUS:-4}"
QEMU_MEM="${QEMU_MEM:-1G}"

KVM_ARGS=""
if [[ "${QEMU_ENABLE_KVM:-1}" == "1" ]] && [[ -e /dev/kvm ]]; then
    KVM_ARGS="-enable-kvm -cpu host,+vmx"
else
    KVM_ARGS="-cpu qemu64,+vmx"
fi

echo "→ Starting QEMU (GDB stub on :1234) ..."

IMAGE_NAME="jammy-server-cloudimg-amd64.img"
DISK_ARGS=""
if [[ -f "$WORKSPACE_ROOT/guest/$IMAGE_NAME" ]]; then
    DISK_ARGS+="-drive file=$WORKSPACE_ROOT/guest/$IMAGE_NAME,format=qcow2,if=ide "
fi

qemu-system-x86_64 \
    $KVM_ARGS \
    -smp "$QEMU_CPUS" \
    -m "$QEMU_MEM" \
    -cdrom "$ISO" \
    -boot d \
    -serial stdio \
    -display none \
    -no-reboot \
    -s -S \
    ${DISK_ARGS} \
    ${QEMU_EXTRA_ARGS:-} &

QEMU_PID=$!

# Give QEMU a moment to open the GDB port
sleep 0.5

# Select GDB binary (prefer rust-gdb for pretty printers)
GDB="${GDB:-$(command -v rust-gdb 2>/dev/null || command -v gdb)}"

echo "→ Attaching $GDB (workspace: $WORKSPACE_ROOT) ..."

cd "$WORKSPACE_ROOT"
"$GDB" \
    -ex "target remote :1234" \
    -x ".gdbinit" \
    || true

# Kill QEMU when GDB exits
kill "$QEMU_PID" 2>/dev/null || true
