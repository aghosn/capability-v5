#!/usr/bin/env bash
# Unmount the dom0 cloud image.
# Usage: sudo bash scripts/umount-guest.sh
set -euo pipefail

umount /tmp/mnt
qemu-nbd -d /dev/nbd0
echo "Unmounted and disconnected."
