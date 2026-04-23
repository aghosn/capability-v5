#!/usr/bin/env bash
# fetch-aarch64-kernel.sh — Download and extract an ARM64 Linux kernel Image
#                           for use as the aarch64 dom0 guest.
#
# Usage:
#   cargo fetch-aarch64-kernel          (via xtask alias)
#   bash scripts/fetch-aarch64-kernel.sh
#
# Output:
#   guest/aarch64/Image               uncompressed ARM64 Linux kernel
#   guest/aarch64/version.txt         provenance record
#
# Environment:
#   FORCE=1                           re-download even if present
#   KERNEL_URL=<url>                  override the default kernel package URL
#
# The script downloads the Ubuntu ARM64 kernel .deb, extracts vmlinuz,
# decompresses it (gzip → raw Image), and places it in guest/aarch64/.
#
# Requirements: curl, ar, zstd (or tar), gunzip
#   sudo apt install binutils zstd curl

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GUEST_DIR="$WORKSPACE_ROOT/guest/aarch64"
IMAGE_PATH="$GUEST_DIR/Image"

# Default: Ubuntu 24.04 (Noble) generic ARM64 kernel
KERNEL_PKG="linux-image-unsigned-6.8.0-114-generic"
VMLINUZ_URL="${VMLINUZ_URL:-https://ports.ubuntu.com/pool/main/l/linux/${KERNEL_PKG}_6.8.0-114.114_arm64.deb}"

# ── Check if already present ─────────────────────────────────────────────
if [[ -f "$IMAGE_PATH" && "${FORCE:-}" != "1" ]]; then
    SIZE=$(stat -c%s "$IMAGE_PATH" 2>/dev/null || stat -f%z "$IMAGE_PATH" 2>/dev/null)
    echo "✓ ARM64 kernel Image already present: $IMAGE_PATH ($(numfmt --to=iec "$SIZE" 2>/dev/null || echo "${SIZE} bytes"))"
    echo "  To re-download: FORCE=1 cargo fetch-aarch64-kernel"
    exit 0
fi

mkdir -p "$GUEST_DIR"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  Fetching ARM64 Linux kernel for Themis aarch64 dom0           ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo

# ── Download the kernel .deb ──────────────────────────────────────────────
DEB="$TMPDIR/kernel.deb"
echo "→ Downloading $KERNEL_PKG..."
echo "  URL: $VMLINUZ_URL"
curl -fL --progress-bar -o "$DEB" "$VMLINUZ_URL"
echo "  Downloaded: $(stat -c%s "$DEB" | numfmt --to=iec 2>/dev/null || echo "$(stat -c%s "$DEB") bytes")"

# ── Extract vmlinuz from .deb ─────────────────────────────────────────────
echo "→ Extracting vmlinuz from .deb..."
cd "$TMPDIR"

# .deb is an ar archive containing data.tar.{zst,xz,gz}
ar x "$DEB"

# Find and extract data archive
if [[ -f data.tar.zst ]]; then
    zstd -d data.tar.zst -o data.tar --quiet
elif [[ -f data.tar.xz ]]; then
    xz -d data.tar.xz
elif [[ -f data.tar.gz ]]; then
    gunzip data.tar.gz
fi

# Extract vmlinuz
tar xf data.tar --wildcards '*/vmlinuz-*' 2>/dev/null || true
VMLINUZ=$(find . -name 'vmlinuz-*' -type f | head -1)

if [[ -z "$VMLINUZ" ]]; then
    echo "ERROR: vmlinuz not found in kernel .deb" >&2
    echo "  Contents:" >&2
    tar tf data.tar | head -20 >&2
    exit 1
fi

echo "  Found: $VMLINUZ"

# ── Decompress vmlinuz → Image ────────────────────────────────────────────
# ARM64 vmlinuz is typically gzip-compressed. Find the gzip header and decompress.
echo "→ Decompressing vmlinuz → Image..."

# Check if it's a PE executable (EFI stub) wrapping a gzip payload
# The gzip magic (1f 8b) appears after the PE/EFI stub
GZIP_OFFSET=$(python3 -c "
import sys
data = open('$VMLINUZ', 'rb').read()
# Search for gzip magic bytes
offset = data.find(b'\x1f\x8b\x08')
if offset >= 0:
    print(offset)
else:
    print(-1)
" 2>/dev/null || echo "-1")

if [[ "$GZIP_OFFSET" == "-1" ]]; then
    # Maybe it's already an uncompressed Image
    MAGIC=$(python3 -c "
import struct, sys
f = open('$VMLINUZ', 'rb')
f.seek(0x38)
magic = struct.unpack('<I', f.read(4))[0]
print(hex(magic))
" 2>/dev/null || echo "0x0")
    if [[ "$MAGIC" == "0x644d5241" ]]; then
        echo "  vmlinuz is already an uncompressed ARM64 Image"
        cp "$VMLINUZ" "$IMAGE_PATH"
    else
        echo "ERROR: Cannot find gzip payload in vmlinuz and it's not a raw Image" >&2
        exit 1
    fi
else
    echo "  Found gzip payload at offset $GZIP_OFFSET"
    dd if="$VMLINUZ" bs=1 skip="$GZIP_OFFSET" 2>/dev/null | gunzip > "$IMAGE_PATH" 2>/dev/null || {
        # Some vmlinuz use a self-decompressing stub; try the whole file
        gunzip -c "$VMLINUZ" > "$IMAGE_PATH" 2>/dev/null || {
            echo "ERROR: Failed to decompress vmlinuz" >&2
            exit 1
        }
    }
fi

# ── Verify the Image ─────────────────────────────────────────────────────
MAGIC=$(python3 -c "
import struct
f = open('$IMAGE_PATH', 'rb')
f.seek(0x38)
magic = struct.unpack('<I', f.read(4))[0]
print(hex(magic))
")

if [[ "$MAGIC" != "0x644d5241" ]]; then
    echo "WARNING: Image magic is $MAGIC (expected 0x644d5241 = 'ARM\\x64')"
    echo "  The file may not be a valid ARM64 kernel Image."
fi

SIZE=$(stat -c%s "$IMAGE_PATH" 2>/dev/null || stat -f%z "$IMAGE_PATH")
echo "  Image: $IMAGE_PATH ($(numfmt --to=iec "$SIZE" 2>/dev/null || echo "$SIZE bytes"))"

# ── Write provenance record ──────────────────────────────────────────────
cat > "$GUEST_DIR/version.txt" <<EOF
# ARM64 Linux kernel for Themis aarch64 dom0
# Fetched: $(date -Iseconds)
package: $KERNEL_PKG
url: $VMLINUZ_URL
image: $IMAGE_PATH
size: $SIZE
magic: $MAGIC
EOF

echo
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  ✓ ARM64 kernel ready                                         ║"
echo "║                                                                ║"
echo "║  Boot:  cargo aarch64-direct                                   ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
