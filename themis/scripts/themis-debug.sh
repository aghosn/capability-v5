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
#   QEMU_MEM, QEMU_CPUS, QEMU_ENABLE_KVM, QEMU_BIOS, QEMU_EXTRA_ARGS

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

# ── Firmware: UEFI (default) or legacy BIOS ─────────────────────────────────
FIRMWARE_ARGS=""
if [[ "${QEMU_BIOS:-0}" != "1" ]]; then
    OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
    OVMF_VARS_TEMPLATE="${OVMF_VARS_TEMPLATE:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
    OVMF_VARS="$WORKSPACE_ROOT/target/ovmf_vars.fd"
    if [[ -f "$OVMF_CODE" ]]; then
        if [[ ! -f "$OVMF_VARS" ]] && [[ -f "$OVMF_VARS_TEMPLATE" ]]; then
            cp "$OVMF_VARS_TEMPLATE" "$OVMF_VARS"
        fi
        FIRMWARE_ARGS="-drive if=pflash,format=raw,readonly=on,file=$OVMF_CODE"
        if [[ -f "$OVMF_VARS" ]]; then
            FIRMWARE_ARGS+=" -drive if=pflash,format=raw,file=$OVMF_VARS"
        fi
    else
        echo "WARNING: OVMF not found at $OVMF_CODE — falling back to BIOS"
    fi
fi

echo "→ Starting QEMU (GDB stub on :1234) ..."

source "$SCRIPT_DIR/dom0-lib.sh"
DISK_ARGS=""
if [[ -n "${DOM0_VERSION:-}" ]]; then
    dom0_select "$DOM0_VERSION"
    if [[ -f "$WORKSPACE_ROOT/guest/$DOM0_IMAGE_NAME" ]]; then
        DISK_ARGS+="-drive id=dom0,file=$WORKSPACE_ROOT/guest/$DOM0_IMAGE_NAME,format=qcow2,if=none "
        DISK_ARGS+="-device virtio-blk-pci,drive=dom0 "
    fi
elif _detected=$(dom0_detect_from_guest_dir "$WORKSPACE_ROOT/guest"); then
    dom0_select "$_detected"
    DISK_ARGS+="-drive id=dom0,file=$WORKSPACE_ROOT/guest/$DOM0_IMAGE_NAME,format=qcow2,if=none "
    DISK_ARGS+="-device virtio-blk-pci,drive=dom0 "
fi

qemu-system-x86_64 \
    $KVM_ARGS \
    -machine q35 \
    -device intel-iommu \
    ${FIRMWARE_ARGS} \
    -smp "$QEMU_CPUS" \
    -m "$QEMU_MEM" \
    -cdrom "$ISO" \
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
    -x "themis.gdbinit" \
    || true

# Kill QEMU when GDB exits
kill "$QEMU_PID" 2>/dev/null || true
