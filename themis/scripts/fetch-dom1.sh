#!/usr/bin/env bash
# fetch-dom1.sh — Download and prepare the dom1 guest image.
#
# Dom1 boots via rust-hypervisor-firmware (firmware approach): hypervisor-fw
# loads GRUB from the disk, which boots the kernel from dom1's own /boot.
# The disk is kept in raw format (required by hypervisor-fw).
#
# During fetch (one-time, on the host):
#   - qcow2 is converted to raw
#   - cloud-init nocloud seed is injected into the root partition
#   - grub.cfg is patched to use root=/dev/vda1 (not LABEL=cloudimg-rootfs)
#
# Output:
#   guest/dom1.raw         Ubuntu root disk, pre-configured (raw)
#   guest/hypervisor-fw    Rust Hypervisor Firmware binary
#
# Usage:
#   cargo fetch-dom1            # from themis/
#   FORCE=1 cargo fetch-dom1   # re-download even if present

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GUEST_DIR="$WORKSPACE_ROOT/guest"
FORCE="${FORCE:-0}"

source "$SCRIPT_DIR/dom0-lib.sh"
dom0_select "noble"

DOM1_RAW="$GUEST_DIR/dom1.raw"
DOM1_SEEDED_MARKER="$GUEST_DIR/.dom1-seeded"
HVF="$GUEST_DIR/hypervisor-fw"
HVF_VERSION="0.5.0"
HVF_URL="https://github.com/cloud-hypervisor/rust-hypervisor-firmware/releases/download/${HVF_VERSION}/hypervisor-fw"

need() {
    if ! command -v "$1" &>/dev/null; then
        echo "ERROR: '$1' not found. Install: $2" >&2; exit 1
    fi
}

need curl      "sudo apt install curl"
need qemu-img  "sudo apt install qemu-utils"

mkdir -p "$GUEST_DIR"

# ── 1. Dom1 root disk (raw) ───────────────────────────────────────────────
echo ""
echo "=== [1/3] Dom1 root disk (Ubuntu Noble, raw) ==="
if [[ -f "$DOM1_RAW" && "$FORCE" != "1" ]]; then
    echo "  ✔ dom1.raw already present (set FORCE=1 to re-download)"
else
    TMP_QCOW="$GUEST_DIR/dom1-tmp.qcow2"
    echo "  → Downloading..."
    curl -fSL --progress-bar "$DOM0_IMAGE_URL" -o "$TMP_QCOW"
    echo "  → Converting to raw..."
    qemu-img convert -p -f qcow2 -O raw "$TMP_QCOW" "$DOM1_RAW"
    rm -f "$TMP_QCOW" "$DOM1_SEEDED_MARKER"
    echo "  ✔ dom1.raw ready ($(du -sh "$DOM1_RAW" | cut -f1))"
fi

# ── 2. Configure the image (one-time) ────────────────────────────────────
# a) Inject cloud-init nocloud seed into root partition (p1)
# b) Patch grub.cfg in boot partition (p16): LABEL=cloudimg-rootfs → /dev/vda1
echo ""
echo "=== [2/3] Configuring dom1.raw ==="
if [[ -f "$DOM1_SEEDED_MARKER" && "$FORCE" != "1" ]]; then
    echo "  ✔ dom1.raw already configured"
else
    LOOP=$(sudo losetup -f --show -P "$DOM1_RAW")
    trap "sudo losetup -d $LOOP 2>/dev/null || true" EXIT

    # ── root partition: inject cloud-init nocloud seed
    MNT_ROOT=$(mktemp -d)
    sudo mount "${LOOP}p1" "$MNT_ROOT"

    SEED_DIR="$MNT_ROOT/var/lib/cloud/seed/nocloud-net"
    sudo mkdir -p "$SEED_DIR"

    sudo tee "$SEED_DIR/meta-data" > /dev/null <<'EOF'
instance-id: themis-dom1
local-hostname: dom1
EOF

    sudo tee "$SEED_DIR/user-data" > /dev/null <<'EOF'
#cloud-config
users:
  - name: cloud
    passwd: $6$7125787751a8d18a$sHwGySomUA1PawiNFWVCKYQN.Ec.Wzz0JtPPL1MvzFrkwmop2dq7.4CYf03A5oemPQ4pOFCCrtCelvFBEle/K.
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: False
    shell: /bin/bash
ssh_pwauth: True
write_files:
  - path: /etc/netplan/99-dom1.yaml
    content: |
      network:
        version: 2
        ethernets:
          eth0:
            match:
              macaddress: "12:34:56:78:90:ab"
            addresses: [192.168.100.2/24]
            routes:
              - to: default
                via: 192.168.100.1
            nameservers:
              addresses: [8.8.8.8, 1.1.1.1]
runcmd:
  - netplan apply
EOF

    sudo umount "$MNT_ROOT"
    rmdir "$MNT_ROOT"
    echo "  ✔ cloud-init seed injected"

    # ── boot partition: patch grub.cfg so root resolves under cloud-hypervisor
    MNT_BOOT=$(mktemp -d)
    sudo mount "${LOOP}p16" "$MNT_BOOT"
    if [[ -f "$MNT_BOOT/grub/grub.cfg" ]]; then
        sudo sed -i 's|root=LABEL=cloudimg-rootfs|root=/dev/vda1|g' "$MNT_BOOT/grub/grub.cfg"
        # Mask slow boot services that hang without internet access.
        sudo sed -i '/linux\s/s|$| systemd.mask=snapd.seeded.service systemd.mask=snapd.service systemd.mask=systemd-networkd-wait-online.service|' "$MNT_BOOT/grub/grub.cfg"
        echo "  ✔ grub.cfg patched (root=/dev/vda1, services masked)"
    fi
    sudo umount "$MNT_BOOT"
    rmdir "$MNT_BOOT"

    sudo losetup -d "$LOOP"
    trap - EXIT
    touch "$DOM1_SEEDED_MARKER"
    echo "  ✔ dom1.raw configured"
fi

# ── 3. Rust Hypervisor Firmware ───────────────────────────────────────────
echo ""
echo "=== [3/3] Rust Hypervisor Firmware (hypervisor-fw ${HVF_VERSION}) ==="
if [[ -f "$HVF" && "$FORCE" != "1" ]]; then
    echo "  ✔ hypervisor-fw already present"
else
    echo "  → Downloading hypervisor-fw..."
    curl -fSL --progress-bar "$HVF_URL" -o "$HVF"
    echo "  ✔ hypervisor-fw ready"
fi

echo ""
echo "✔ Dom1 ready:"
echo "   guest/dom1.raw         root disk (raw, pre-configured)"
echo "   guest/hypervisor-fw    firmware"
echo "  Inside dom0:  sudo /opt/bins/cloud-hypervisor/run-dom1.sh"

