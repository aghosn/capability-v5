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

MNT="/tmp/mnt"

modprobe nbd max_part=8
qemu-nbd -c /dev/nbd0 "$IMG"
sleep 1                       # wait for partition scan
mkdir -p "$MNT"
mount /dev/nbd0p1 "$MNT" 2>/dev/null || mount /dev/nbd0p2 "$MNT"
echo "Mounted $(basename "$IMG") at $MNT"
echo "Unmount with:  sudo umount $MNT && sudo qemu-nbd -d /dev/nbd0"
