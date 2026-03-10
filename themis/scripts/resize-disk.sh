#!/usr/bin/env bash
# resize-disk.sh — Grow a QCOW2 dom0 disk image.
#
# Usage:
#   cargo resize-disk <image> <+sizeG>
#   bash scripts/resize-disk.sh guest/ubuntu-24.04-server-cloudimg-amd64.img 10
#
# After resizing, boot the guest and run inside it:
#   sudo growpart /dev/vda 1
#   sudo resize2fs /dev/vda1

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <image-path> <size-in-GB>"
    echo ""
    echo "  image-path   Path to QCOW2 disk image"
    echo "  size-in-GB   Amount to grow by, in gigabytes (e.g. 10)"
    echo ""
    echo "Example:"
    echo "  $0 guest/ubuntu-24.04-server-cloudimg-amd64.img 10"
    exit 1
fi

IMAGE="$1"
SIZE_GB="$2"

if [[ ! -f "$IMAGE" ]]; then
    echo "ERROR: image not found: $IMAGE"
    exit 1
fi

if ! [[ "$SIZE_GB" =~ ^[0-9]+$ ]] || [[ "$SIZE_GB" -eq 0 ]]; then
    echo "ERROR: size must be a positive integer (got: $SIZE_GB)"
    exit 1
fi

echo "Before:"
qemu-img info "$IMAGE" | grep 'virtual size'

qemu-img resize "$IMAGE" "+${SIZE_GB}G"

echo ""
echo "After:"
qemu-img info "$IMAGE" | grep 'virtual size'

echo ""
echo "✔ Image grown by ${SIZE_GB}G."
echo "  Boot the guest and run:"
echo "    sudo growpart /dev/vda 1"
echo "    sudo resize2fs /dev/vda1"
