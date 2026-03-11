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
NBD_MAX=15   # nbd0..nbd15

modprobe nbd max_part=16

# ── Clean up stale mount if $MNT is busy ──────────────────────────────────── #
umount "$MNT" &>/dev/null || true

# ── Find a usable nbd device ──────────────────────────────────────────────── #
# If /dev/nbdN has a non-zero size it is already connected (possibly zombie'd
# from a crashed previous run).  Try to disconnect it; if that fails, skip it
# and try the next device.
NBD=""
for n in $(seq 0 $NBD_MAX); do
    dev="/dev/nbd$n"
    [[ -b "$dev" ]] || continue

    sz=$(blockdev --getsize64 "$dev" 2>/dev/null || echo 0)
    if (( sz != 0 )); then
        # Device in use — try to reclaim it.
        qemu-nbd -d "$dev" &>/dev/null || true
        sleep 0.3
        sz=$(blockdev --getsize64 "$dev" 2>/dev/null || echo 0)
    fi
    if (( sz == 0 )); then
        NBD="$dev"
        break
    fi
done

if [[ -z "$NBD" ]]; then
    echo "ERROR: no free nbd device found (nbd0..nbd$NBD_MAX all busy)" >&2
    exit 1
fi

qemu-nbd -c "$NBD" "$IMG"

# Wait for the kernel to discover partitions (up to 5 seconds).
for i in $(seq 1 10); do
    if ls "${NBD}p"* &>/dev/null; then
        break
    fi
    sleep 0.5
done

if ! ls "${NBD}p"* &>/dev/null; then
    echo "ERROR: no partitions found on $IMG (device $NBD)" >&2
    qemu-nbd -d "$NBD"
    exit 1
fi

mkdir -p "$MNT"

# Find the root partition: try each partition looking for /etc.
# Try -o noload first (ext4 with dirty journal from unclean shutdown),
# then fall back to plain ro.
ROOT_PART=""
for part in "${NBD}p"*; do
    if mount -o ro,noload "$part" "$MNT" &>/dev/null || mount -o ro "$part" "$MNT" &>/dev/null; then
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
    echo "Available partitions: $(ls "${NBD}p"*)" >&2
    qemu-nbd -d "$NBD"
    exit 1
fi

mount "$ROOT_PART" "$MNT"
echo "Mounted $(basename "$IMG") at $MNT  (device $NBD)"
echo "Unmount with:  sudo umount $MNT && sudo qemu-nbd -d $NBD"
