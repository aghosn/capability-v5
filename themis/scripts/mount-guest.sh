#!/usr/bin/env bash
# Mount the dom0 cloud image for inspection.
# Usage: sudo bash scripts/mount-guest.sh
set -euo pipefail

IMG="$(cd "$(dirname "$0")/.." && pwd)/guest/ubuntu-24.04-server-cloudimg-amd64.img"
MNT="/tmp/mnt"

modprobe nbd max_part=8
qemu-nbd -c /dev/nbd0 "$IMG"
sleep 1                       # wait for partition scan
mkdir -p "$MNT"
mount /dev/nbd0p1 "$MNT" 2>/dev/null || mount /dev/nbd0p2 "$MNT"
echo "Mounted at $MNT"
