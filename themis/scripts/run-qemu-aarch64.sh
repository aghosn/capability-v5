#!/usr/bin/env bash
# run-qemu-aarch64.sh — Build the AArch64 ISO and boot Themis under
#                        qemu-system-aarch64 with the `virt` machine.
#
# Usage:
#   bash scripts/run-qemu-aarch64.sh
#
# Prerequisites:
#   • qemu-system-aarch64  (sudo apt install qemu-system-arm)
#   • AAVMF firmware       (sudo apt install qemu-efi-aarch64)
#   • xorriso, limine, aarch64-unknown-none Rust target
#
# Environment knobs:
#   PROFILE=release       build with --release (default: debug)
#   QEMU_CPUS=1           number of vCPUs (default: 1)
#   QEMU_MEM=1G           guest RAM (default: 1G)
#   QEMU_EXTRA_ARGS       additional QEMU arguments

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Build ISO first
bash "$SCRIPT_DIR/build-iso-aarch64.sh"

ISO="$WORKSPACE_ROOT/target/themis-aarch64.iso"

QEMU_CPUS="${QEMU_CPUS:-1}"
QEMU_MEM="${QEMU_MEM:-1G}"

# ── Locate AAVMF firmware ─────────────────────────────────────────────────

FIRMWARE=""
for candidate in \
    "/usr/share/AAVMF/AAVMF_CODE.fd" \
    "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd" \
    "/usr/share/OVMF/AAVMF/AAVMF_CODE.fd"
do
    if [[ -f "$candidate" ]]; then
        FIRMWARE="$candidate"
        break
    fi
done

if [[ -z "$FIRMWARE" ]]; then
    echo "ERROR: AAVMF firmware not found." >&2
    echo "       Install: sudo apt install qemu-efi-aarch64" >&2
    exit 1
fi

echo "→ Firmware: $FIRMWARE"
echo "→ ISO:      $ISO"
echo "→ CPUs:     $QEMU_CPUS  RAM: $QEMU_MEM"
echo

# ── Launch QEMU ───────────────────────────────────────────────────────────

exec qemu-system-aarch64 \
    -machine virt,gic-version=3,virtualization=on \
    -cpu cortex-a76 \
    -smp "$QEMU_CPUS" \
    -m "$QEMU_MEM" \
    -bios "$FIRMWARE" \
    -cdrom "$ISO" \
    -nographic \
    -serial mon:stdio \
    ${QEMU_EXTRA_ARGS:-}
