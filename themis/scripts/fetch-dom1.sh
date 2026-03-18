#!/usr/bin/env bash
# fetch-dom1.sh — Download the dom1 guest image and create a cloud-init seed.
#
# Dom1 is a separate Ubuntu Noble VM booted by cloud-hypervisor from dom0.
# It uses a fresh copy of the same Noble cloud image as dom0, with its own
# cloud-init seed.
#
# Output:
#   guest/dom1.img          Ubuntu root disk for dom1 (QCOW2, separate from dom0)
#   guest/dom1-seed.img     Cloud-init seed for dom1 first boot
#
# Usage:
#   cargo fetch-dom1                 # from themis/
#   FORCE=1 cargo fetch-dom1        # re-download even if present

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GUEST_DIR="$WORKSPACE_ROOT/guest"
FORCE="${FORCE:-0}"

source "$SCRIPT_DIR/dom0-lib.sh"
dom0_select "noble"

DOM1_IMG="$GUEST_DIR/dom1.img"
DOM1_SEED="$GUEST_DIR/dom1-seed.img"

need() {
    if ! command -v "$1" &>/dev/null; then
        echo "ERROR: '$1' not found. Install: $2" >&2; exit 1
    fi
}

need curl          "sudo apt install curl"
need qemu-img      "sudo apt install qemu-utils"
need cloud-localds "sudo apt install cloud-image-utils"

mkdir -p "$GUEST_DIR"

# ── 1. Dom1 root disk ─────────────────────────────────────────────────────
echo ""
echo "=== [1/2] Dom1 root disk (Ubuntu Noble) ==="
if [[ -f "$DOM1_IMG" && "$FORCE" != "1" ]]; then
    echo "  ✔ dom1.img already present (set FORCE=1 to re-download)"
else
    echo "  → Downloading dom1 image..."
    curl -fSL --progress-bar "$DOM0_IMAGE_URL" -o "$DOM1_IMG"
    echo "  ✔ Downloaded ($(du -sh "$DOM1_IMG" | cut -f1))"
fi

# ── 2. Cloud-init seed ────────────────────────────────────────────────────
echo ""
echo "=== [2/2] Dom1 cloud-init seed ==="
if [[ -f "$DOM1_SEED" && "$FORCE" != "1" ]]; then
    echo "  ✔ dom1-seed.img already present"
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
  - echo "themis dom1 cloud-init complete" > /dev/ttyS0
EOF

    cat > "$TMPDIR/meta-data" <<'EOF'
instance-id: themis-dom1
local-hostname: dom1
EOF

    cloud-localds "$DOM1_SEED" "$TMPDIR/user-data" "$TMPDIR/meta-data"
    echo "  ✔ dom1-seed.img created"
fi

echo ""
echo "✔ Dom1 artifacts ready:"
echo "   guest/dom1.img         root disk"
echo "   guest/dom1-seed.img    cloud-init seed"
echo ""
echo "  First boot:  SEED_DOM1=1 cargo dom0  (or cargo themis)"
echo "  Then inside dom0:  sudo /opt/bins/run-dom1.sh"
