#!/usr/bin/env bash
# run-qemu.sh — Build the ISO and boot Themis under QEMU.
#
# Usage:
#   cargo qemu              # release-like debug session
#   cargo qemu              # from workspace root via Cargo alias
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

exec qemu-system-x86_64 \
    $KVM_ARGS \
    -smp "$QEMU_CPUS" \
    -m "$QEMU_MEM" \
    -cdrom "$ISO" \
    -boot d \
    -serial stdio \
    -display none \
    -no-reboot \
    ${QEMU_EXTRA_ARGS:-}
