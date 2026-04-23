#!/usr/bin/env bash
# fetch-aarch64-dom0.sh — Download an Ubuntu ARM64 cloud image for dom0.
#
# Downloads the Ubuntu Noble (24.04) ARM64 cloud image and creates a
# cloud-init seed ISO for passwordless login.
#
# Output:
#   guest/aarch64/dom0.img     Ubuntu root disk (QCOW2)
#   guest/aarch64/seed.img     Cloud-init seed (ISO9660 CIDATA)
#   guest/aarch64/version.txt  Updated with image provenance
#
# Usage:
#   cargo fetch-aarch64-dom0               # download
#   FORCE=1 cargo fetch-aarch64-dom0       # re-download
#
# Requirements: curl, qemu-img, cloud-localds (cloud-image-utils)
#   sudo apt install qemu-utils cloud-image-utils

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GUEST_DIR="$WORKSPACE_ROOT/guest/aarch64"
FORCE="${FORCE:-0}"

IMAGE_NAME="dom0.img"
IMAGE_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img"
IMAGE_RELEASE="Ubuntu Noble 24.04 LTS (arm64)"

# ── Helpers ────────────────────────────────────────────────────────────────

need() {
    if ! command -v "$1" &>/dev/null; then
        echo "ERROR: '$1' not found. Install: $2" >&2
        exit 1
    fi
}

need curl          "sudo apt install curl"
need qemu-img      "sudo apt install qemu-utils"
need cloud-localds "sudo apt install cloud-image-utils"

mkdir -p "$GUEST_DIR"

# ── 1. Root disk ───────────────────────────────────────────────────────────

echo ""
echo "=== [1/2] Root disk ($IMAGE_RELEASE) ==="
if [[ -f "$GUEST_DIR/$IMAGE_NAME" && "$FORCE" != "1" ]]; then
    echo "  ✔ $IMAGE_NAME already present (set FORCE=1 to re-download)"
else
    echo "  → Downloading $IMAGE_RELEASE cloud image ..."
    curl -fSL --progress-bar "$IMAGE_URL" -o "$GUEST_DIR/$IMAGE_NAME.tmp"
    mv "$GUEST_DIR/$IMAGE_NAME.tmp" "$GUEST_DIR/$IMAGE_NAME"
    echo "  ✔ Downloaded ($(du -sh "$GUEST_DIR/$IMAGE_NAME" | cut -f1))"
fi

# Resize to 4G so there's room for packages/logs.
qemu-img resize "$GUEST_DIR/$IMAGE_NAME" 4G 2>/dev/null || true
echo "  $(qemu-img info --output=human "$GUEST_DIR/$IMAGE_NAME" | grep 'virtual size')"

# ── 2. Cloud-init seed ────────────────────────────────────────────────────

echo ""
echo "=== [2/2] Cloud-init seed image ==="
SEED_IMG="$GUEST_DIR/seed.img"

USER_DATA=$(mktemp)
cat > "$USER_DATA" << 'USERDATA'
#cloud-config
hostname: dom0-arm64
manage_etc_hosts: true
users:
  - name: themis
    groups: [sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    # password: themis (hashed)
    passwd: $6$rounds=4096$themis$IxDD3jeSOb0/VnEPRJGkT3qKxXFsdqe.hWNk0U4AdjNGqOAYlwZpDx3t0Lkm6.EJ7EvQd7GRJXUz5O.lMwCw0
ssh_pwauth: true
disable_root: true
runcmd:
  - systemctl mask systemd-networkd-wait-online.service
  - systemctl mask boot-efi.mount
  - systemctl mask multipathd.service
USERDATA

cloud-localds "$SEED_IMG" "$USER_DATA"
rm -f "$USER_DATA"
echo "  ✔ Seed image created"

# ── Provenance ─────────────────────────────────────────────────────────────

cat > "$GUEST_DIR/version.txt" << EOF
# AArch64 dom0 guest artifacts
image: $IMAGE_RELEASE
url: $IMAGE_URL
fetched: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
kernel: Ubuntu ARM64 generic (from linux-image-unsigned package)
EOF

echo ""
echo "✔ AArch64 dom0 ready in $GUEST_DIR"
echo "  Root disk:  $GUEST_DIR/$IMAGE_NAME"
echo "  Seed:       $SEED_IMG"
echo "  Login:      themis / themis"
