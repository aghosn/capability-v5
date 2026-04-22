#!/usr/bin/env bash
# aarch64-direct.sh — Build and boot Themis capavisor via QEMU direct `-kernel`
#                     at EL2 (no Limine, no UEFI firmware).
#
# Usage:
#   cargo aarch64-direct          (via xtask alias)
#   bash scripts/aarch64-direct.sh
#
# Prerequisites:
#   • qemu-system-aarch64  (sudo apt install qemu-system-arm)
#   • aarch64-unknown-none Rust target
#
# Environment knobs:
#   PROFILE=release       build with --release (default: debug)
#   QEMU_CPUS=4           number of vCPUs (default: 4)
#   QEMU_MEM=1G           guest RAM (default: 1G)
#   QEMU_EXTRA_ARGS       additional QEMU arguments

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PROFILE="${PROFILE:-debug}"
BUILD_FLAGS=""
if [[ "$PROFILE" == "release" ]]; then
    BUILD_FLAGS="--release"
fi

QEMU_CPUS="${QEMU_CPUS:-4}"
QEMU_MEM="${QEMU_MEM:-1G}"

# ── Build the capavisor ELF ───────────────────────────────────────────────

echo "→ Building capavisor (aarch64, direct-boot, ${PROFILE})..."
cargo build \
    --manifest-path "$WORKSPACE_ROOT/capavisor/Cargo.toml" \
    --target aarch64-unknown-none \
    --features direct-boot \
    $BUILD_FLAGS

ELF="$WORKSPACE_ROOT/target/aarch64-unknown-none/${PROFILE}/capavisor"

if [[ ! -f "$ELF" ]]; then
    echo "ERROR: ELF not found at $ELF" >&2
    exit 1
fi

echo "→ ELF:  $ELF"
echo "→ CPUs: $QEMU_CPUS  RAM: $QEMU_MEM"
echo

# ── Launch QEMU ───────────────────────────────────────────────────────────
# - virtualization=on: CPU enters at EL2 (required for hypervisor)
# - -kernel: direct ELF load (QEMU reads entry point from ELF header)
# - No firmware/BIOS needed; QEMU provides FDT in X0

exec qemu-system-aarch64 \
    -machine virt,gic-version=3,virtualization=on \
    -cpu cortex-a76 \
    -smp "$QEMU_CPUS" \
    -m "$QEMU_MEM" \
    -kernel "$ELF" \
    -nographic \
    -serial mon:stdio \
    ${QEMU_EXTRA_ARGS:-}
