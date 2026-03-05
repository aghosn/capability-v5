#!/usr/bin/env bash
# run-qemu.sh — Build the ISO and boot Themis under QEMU.
#
# Usage:
#   cargo themis             # from workspace root via Cargo alias
#   cargo themis             # release-like debug session
#   bash scripts/run-qemu.sh
#
# Environment knobs:
#   PROFILE=release         build with --release (default: debug)
#   QEMU_CPUS=4             number of vCPUs (default: 4)
#   QEMU_MEM=1G             guest RAM (default: 1G)
#   QEMU_ENABLE_KVM=1       use KVM acceleration (default: 1 if available)
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

echo "→ Booting $ISO (${QEMU_CPUS} CPUs, ${QEMU_MEM} RAM)"

# ── Optional dom0 disk ──────────────────────────────────────────────────────
# Present when scripts/fetch-dom0.sh has been run and image has been seeded.
IMAGE_NAME="jammy-server-cloudimg-amd64.img"
DISK_ARGS=""
if [[ -f "$WORKSPACE_ROOT/guest/$IMAGE_NAME" ]]; then
    # IDE interface required: Limine runs at BIOS level and can only access
    # drives via INT 13h — virtio-blk is invisible until an OS driver loads.
    DISK_ARGS+="-drive file=$WORKSPACE_ROOT/guest/$IMAGE_NAME,format=qcow2,if=ide "
    echo "  + ide hda: guest/$IMAGE_NAME  (Limine reads /boot/vmlinuz from here)"
fi

exec qemu-system-x86_64 \
    $KVM_ARGS \
    -smp "$QEMU_CPUS" \
    -m "$QEMU_MEM" \
    -cdrom "$ISO" \
    -boot d \
    -serial stdio \
    -display none \
    -no-reboot \
    ${DISK_ARGS} \
    ${QEMU_EXTRA_ARGS:-}
