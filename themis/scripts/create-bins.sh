#!/usr/bin/env bash
# create-bins.sh — Create the sparse bins.img artifact disk for dom0.
#
# Usage:
#   bash themis/scripts/create-bins.sh
#   BINS_SIZE=4G bash themis/scripts/create-bins.sh
#
# Creates guest/bins.img as a sparse ext2 image, initializes the directory
# layout used by dom0, and writes a placeholder version.txt. Re-runs are
# safe: if bins.img already exists, the script prints a warning and exits 0.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GUEST_DIR="$WORKSPACE_ROOT/guest"
BINS_IMG="$GUEST_DIR/bins.img"
BINS_SIZE="${BINS_SIZE:-2G}"
MNT=""
MOUNTED=false

need() {
    if ! command -v "$1" &>/dev/null; then
        echo "ERROR: '$1' not found. Install: $2" >&2
        exit 1
    fi
}

cleanup() {
    if [[ "$MOUNTED" == true && -n "$MNT" ]] && mountpoint -q "$MNT" 2>/dev/null; then
        fusermount -u "$MNT" 2>/dev/null || true
    fi
    if [[ -n "$MNT" && -d "$MNT" ]]; then
        rmdir "$MNT" 2>/dev/null || true
    fi
}
trap cleanup EXIT

need truncate  "sudo apt install coreutils"
need mkfs.ext2 "sudo apt install e2fsprogs"
need fuse2fs   "sudo apt install fuse2fs e2fsprogs"
need fusermount "sudo apt install fuse3"

mkdir -p "$GUEST_DIR"

if [[ -f "$BINS_IMG" ]]; then
    echo "WARNING: $BINS_IMG already exists; leaving it unchanged."
    exit 0
fi

echo "→ Creating guest/bins.img (${BINS_SIZE})"
truncate -s "$BINS_SIZE" "$BINS_IMG"
mkfs.ext2 -L bins "$BINS_IMG" >/dev/null

MNT="$(mktemp -d)"
fuse2fs -o fakeroot "$BINS_IMG" "$MNT" >/dev/null 2>&1
MOUNTED=true

for _ in {1..50}; do
    if mountpoint -q "$MNT" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if ! mountpoint -q "$MNT" 2>/dev/null; then
    echo "ERROR: failed to mount $BINS_IMG with fuse2fs" >&2
    echo "       Remediation: ensure FUSE is available, then retry." >&2
    exit 1
fi

mkdir -p \
    "$MNT/thhv/tests" \
    "$MNT/cloud-hypervisor" \
    "$MNT/2026/tests" \
    "$MNT/nested"

cat > "$MNT/version.txt" <<'META'
placeholder: run themis/scripts/update-bins.sh to populate build artifacts
META

fusermount -u "$MNT"
MOUNTED=false
rmdir "$MNT"
MNT=""

echo "✔ Created guest/bins.img"
