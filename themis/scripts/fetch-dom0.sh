#!/usr/bin/env bash
# fetch-dom0.sh — Download the dom0 root disk and create a cloud-init seed.
#
# Downloads the standard Ubuntu Jammy cloud image and creates a cloud-init
# seed ISO following the standard QEMU cloud-image workflow:
#   https://cloud-images.ubuntu.com/
#
# The image is kept with its original filename so we know exactly what
# version we're running. The dom0 kernel and initrd live inside the disk
# image (/boot/vmlinuz, /boot/initrd.img) — Limine loads them directly
# from the disk at boot time via fslabel(cloudimg-rootfs)://.
#
# Output:
#   guest/jammy-server-cloudimg-amd64.img   Ubuntu root disk (QCOW2)
#   guest/seed.img                          Cloud-init seed (ISO9660 CIDATA)
#   guest/dom0/version.txt                  provenance record
#
# Usage:
#   cargo fetch-dom0                       # download everything
#   FORCE=1 cargo fetch-dom0               # re-download even if present
#
# Requirements: curl, qemu-img, cloud-localds (cloud-image-utils)
#   sudo apt install qemu-utils cloud-image-utils

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GUEST_DIR="$WORKSPACE_ROOT/guest"
DOM0_DIR="$GUEST_DIR/dom0"

FORCE="${FORCE:-0}"

# ── Image ──────────────────────────────────────────────────────────────────

IMAGE_NAME="jammy-server-cloudimg-amd64.img"
IMAGE_URL="https://cloud-images.ubuntu.com/jammy/current/${IMAGE_NAME}"

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

mkdir -p "$DOM0_DIR"

# ── 1. Root disk ───────────────────────────────────────────────────────────

echo ""
echo "=== [1/2] Root disk (Ubuntu Jammy) ==="
if [[ -f "$GUEST_DIR/$IMAGE_NAME" && "$FORCE" != "1" ]]; then
    echo "  ✔ $IMAGE_NAME already present (set FORCE=1 to re-download)"
else
    echo "  → Downloading $IMAGE_NAME ..."
    curl -fSL --progress-bar "$IMAGE_URL" -o "$GUEST_DIR/$IMAGE_NAME"
    echo "  ✔ Downloaded ($(du -sh "$GUEST_DIR/$IMAGE_NAME" | cut -f1))"
fi
echo "  $(qemu-img info --output=human "$GUEST_DIR/$IMAGE_NAME" | grep 'virtual size')"

# ── 2. Cloud-init seed ────────────────────────────────────────────────────

echo ""
echo "=== [2/2] Cloud-init seed image ==="
SEED_IMG="$GUEST_DIR/seed.img"

if [[ -f "$SEED_IMG" && "$FORCE" != "1" ]]; then
    echo "  ✔ seed.img already present"
else
    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR"' EXIT

    cat > "$TMPDIR/user-data" <<'EOF'
#cloud-config
users:
  - name: cloud
    passwd: $6$7125787751a8d18a$sHwGySomUA1PawiNFWVCKYQN.Ec.Wzz0JtPPL1MvzFrkwmop2dq7.4CYf03A5oemPQ4pOFCCrtCelvFBEle/K.
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: False
    shell: /bin/bash
ssh_pwauth: True
runcmd:
  - echo "themis dom0 cloud-init complete" > /dev/ttyS0
EOF

    cat > "$TMPDIR/meta-data" <<'EOF'
instance-id: themis-dom0
local-hostname: dom0
EOF

    cloud-localds "$SEED_IMG" "$TMPDIR/user-data" "$TMPDIR/meta-data"
    echo "  ✔ seed.img created"
fi

# ── Provenance ─────────────────────────────────────────────────────────────

cat > "$DOM0_DIR/version.txt" <<EOF
image:    ${IMAGE_NAME}
url:      ${IMAGE_URL}
fetched:  $(date -u +%Y-%m-%dT%H:%M:%SZ)
kernel:   loaded at runtime from fslabel(cloudimg-rootfs)://boot/vmlinuz
initrd:   loaded at runtime from fslabel(cloudimg-rootfs)://boot/initrd.img
EOF

echo ""
echo "✔ dom0 artifacts ready in guest/:"
echo "   ${IMAGE_NAME}   root disk"
echo "   seed.img                              cloud-init seed"
echo ""
echo "  cargo dom0     — boot dom0 standalone (no Themis)"
echo "  cargo themis   — full Themis boot (Limine loads kernel from disk)"
