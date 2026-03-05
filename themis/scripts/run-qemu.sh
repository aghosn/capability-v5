#!/usr/bin/env bash
# run-qemu.sh — Build the ISO and boot Themis under QEMU.
#
# Usage:
#   cargo themis             # from workspace root via Cargo alias
#   bash scripts/run-qemu.sh
#
# Environment knobs:
#   PROFILE=release         build with --release (default: debug)
#   QEMU_CPUS=4             number of vCPUs (default: 4)
#   QEMU_MEM=1G             guest RAM (default: 1G)
#   QEMU_ENABLE_KVM=1       use KVM acceleration (default: 1 if available)
#   QEMU_BIOS=1             use legacy BIOS instead of UEFI (default: 0)
#   QEMU_EXTRA_ARGS         additional arguments appended to the QEMU command

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Build ISO first
bash "$SCRIPT_DIR/build-iso.sh"

ISO="$WORKSPACE_ROOT/target/themis.iso"

QEMU_CPUS="${QEMU_CPUS:-4}"
QEMU_MEM="${QEMU_MEM:-1G}"

# Detect KVM availability
KVM_ARGS=""
if [[ "${QEMU_ENABLE_KVM:-1}" == "1" ]] && [[ -e /dev/kvm ]]; then
    KVM_ARGS="-enable-kvm -cpu host,+vmx"
else
    echo "WARNING: KVM not available — running without hardware acceleration"
    KVM_ARGS="-cpu qemu64,+vmx"
fi

# ── Firmware: UEFI (default) or legacy BIOS ─────────────────────────────────
FIRMWARE_ARGS=""
if [[ "${QEMU_BIOS:-0}" != "1" ]]; then
    OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
    if [[ -f "$OVMF_CODE" ]]; then
        FIRMWARE_ARGS="-drive if=pflash,format=raw,readonly=on,file=$OVMF_CODE"
    else
        echo "WARNING: OVMF not found at $OVMF_CODE — falling back to BIOS"
        echo "         Install: sudo apt install ovmf"
    fi
fi

echo "→ Booting $ISO (${QEMU_CPUS} CPUs, ${QEMU_MEM} RAM)"

# ── Optional dom0 disk ──────────────────────────────────────────────────────
# Present when scripts/fetch-dom0.sh has been run and image has been seeded.
IMAGE_NAME="jammy-server-cloudimg-amd64.img"
DISK_ARGS=""
if [[ -f "$WORKSPACE_ROOT/guest/$IMAGE_NAME" ]]; then
    DISK_ARGS+="-drive file=$WORKSPACE_ROOT/guest/$IMAGE_NAME,format=qcow2,if=virtio "
    echo "  + virtio disk: guest/$IMAGE_NAME  (Limine reads /boot/vmlinuz from here)"
fi

exec qemu-system-x86_64 \
    $KVM_ARGS \
    ${FIRMWARE_ARGS} \
    -smp "$QEMU_CPUS" \
    -m "$QEMU_MEM" \
    -cdrom "$ISO" \
    -serial stdio \
    -display none \
    -no-reboot \
    ${DISK_ARGS} \
    ${QEMU_EXTRA_ARGS:-}
