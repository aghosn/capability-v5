#!/usr/bin/env bash
# aarch64-direct.sh — Build and boot Themis capavisor via QEMU direct `-kernel`
#                     at EL2 (no Limine, no UEFI firmware).
#
# Usage:
#   cargo aarch64-direct          (via xtask alias)
#   bash scripts/aarch64-direct.sh
#
# For M5b (Linux guest boot):
#   LINUX_IMAGE=/path/to/Image cargo aarch64-direct
#   LINUX_IMAGE=/path/to/Image INITRD=/path/to/initrd.img cargo aarch64-direct
#
# Prerequisites:
#   • qemu-system-aarch64  (sudo apt install qemu-system-arm)
#   • aarch64-unknown-none Rust target
#
# Environment knobs:
#   PROFILE=release       build with --release (default: debug)
#   QEMU_CPUS=1           number of vCPUs (default: 1)
#   QEMU_MEM=1G           guest RAM (default: 1G)
#   LINUX_IMAGE=<path>    ARM64 Linux Image to load at 0x41000000
#   INITRD=<path>         initrd/initramfs to load at 0x44000000
#   QEMU_EXTRA_ARGS       additional QEMU arguments

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PROFILE="${PROFILE:-debug}"
BUILD_FLAGS=""
if [[ "$PROFILE" == "release" ]]; then
    BUILD_FLAGS="--release"
fi

QEMU_CPUS="${QEMU_CPUS:-1}"
QEMU_MEM="${QEMU_MEM:-1G}"
# Auto-discover ARM64 kernel if not explicitly set
if [[ -z "${LINUX_IMAGE:-}" ]]; then
    DEFAULT_IMAGE="$WORKSPACE_ROOT/guest/aarch64/Image"
    if [[ -f "$DEFAULT_IMAGE" ]]; then
        LINUX_IMAGE="$DEFAULT_IMAGE"
    fi
else
    LINUX_IMAGE="$LINUX_IMAGE"
fi

INITRD="${INITRD:-}"

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

# ── Build loader arguments for Linux Image / initrd ─────────────────────

LOADER_ARGS=""
if [[ -n "${LINUX_IMAGE:-}" ]]; then
    if [[ ! -f "$LINUX_IMAGE" ]]; then
        echo "ERROR: Linux Image not found at $LINUX_IMAGE" >&2
        exit 1
    fi
    echo "→ Linux Image: $LINUX_IMAGE (loaded at 0x41000000)"
    LOADER_ARGS="$LOADER_ARGS -device loader,file=$LINUX_IMAGE,addr=0x41000000"
else
    echo "→ No Linux kernel found. The capavisor will boot standalone."
    echo "  To boot Linux:  cargo fetch-aarch64-kernel && cargo aarch64-direct"
    echo "  Or manually:    LINUX_IMAGE=/path/to/Image cargo aarch64-direct"
    echo
fi

if [[ -n "$INITRD" ]]; then
    if [[ ! -f "$INITRD" ]]; then
        echo "ERROR: initrd not found at $INITRD" >&2
        exit 1
    fi
    echo "→ Initrd: $INITRD (loaded at 0x44000000)"
    LOADER_ARGS="$LOADER_ARGS -device loader,file=$INITRD,addr=0x44000000"
fi

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
    $LOADER_ARGS \
    ${QEMU_EXTRA_ARGS:-}
