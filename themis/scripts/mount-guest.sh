#!/usr/bin/env bash
# Mount the dom0 cloud image for inspection.
# Usage:
#   sudo bash scripts/mount-guest.sh                              # auto-detect
#   sudo bash scripts/mount-guest.sh guest/jammy-server-*.img     # explicit
#   sudo DOM0_VERSION=jammy bash scripts/mount-guest.sh           # by version
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -n "${1:-}" ]]; then
    # Explicit path given as argument.
    IMG="$1"
else
    source "$SCRIPT_DIR/dom0-lib.sh"
    if [[ -n "${DOM0_VERSION:-}" ]]; then
        dom0_select "$DOM0_VERSION"
    elif _detected=$(dom0_detect_from_guest_dir "$WORKSPACE_ROOT/guest"); then
        dom0_select "$_detected"
    else
        dom0_select ""
    fi
    IMG="$WORKSPACE_ROOT/guest/$DOM0_IMAGE_NAME"
fi

if [[ ! -f "$IMG" ]]; then
    echo "ERROR: image not found: $IMG" >&2
    exit 1
fi

# Resolve to absolute path so qemu-nbd works regardless of cwd.
IMG="$(realpath "$IMG")"

MNT="/tmp/mnt"

modprobe nbd max_part=16

# Clean up any stale nbd0 session from a previous run.
umount "$MNT" &>/dev/null || true
qemu-nbd -d /dev/nbd0 &>/dev/null || true
sleep 0.5

qemu-nbd -c /dev/nbd0 "$IMG"

# Wait for the kernel to discover partitions (up to 5 seconds).
for i in $(seq 1 10); do
    if ls /dev/nbd0p* &>/dev/null; then
        break
    fi
    sleep 0.5
done

if ! ls /dev/nbd0p* &>/dev/null; then
    echo "ERROR: no partitions found on $IMG" >&2
    qemu-nbd -d /dev/nbd0
    exit 1
fi

mkdir -p "$MNT"

# Find the root partition: try the largest ext4/xfs partition.
ROOT_PART=""
for part in /dev/nbd0p*; do
    if mount -o ro "$part" "$MNT" &>/dev/null; then
        if [[ -d "$MNT/etc" ]]; then
            ROOT_PART="$part"
            umount "$MNT"
            break
        fi
        umount "$MNT"
    fi
done

if [[ -z "$ROOT_PART" ]]; then
    echo "ERROR: could not find root partition in $IMG" >&2
    echo "Available partitions: $(ls /dev/nbd0p*)" >&2
    qemu-nbd -d /dev/nbd0
    exit 1
fi

mount "$ROOT_PART" "$MNT"
echo "Mounted $(basename "$IMG") at $MNT"
echo "Unmount with:  sudo umount $MNT && sudo qemu-nbd -d /dev/nbd0"
