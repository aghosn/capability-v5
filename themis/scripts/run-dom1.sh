#!/usr/bin/env bash
# run-dom1.sh — Boot dom1 under cloud-hypervisor from inside dom0.
#
# Auto-detects the hypervisor backend:
#   - If /dev/thhv is present (or thhv.ko loads successfully): Themis backend
#   - Otherwise: KVM backend
#
# Dom1's disk is passed to dom0 as /dev/vdc by run-qemu.sh / run-dom0.sh.
#
# Usage (from inside dom0):
#   sudo /opt/bins/run-dom1.sh              # normal boot
#   SEED_DOM1=1 sudo /opt/bins/run-dom1.sh  # first boot with cloud-init seed
#
# Login: cloud / cloud123

set -euo pipefail

BINS="/opt/bins"
CHV="$BINS/cloud-hypervisor/cloud-hypervisor"
THHV_KO="$BINS/thhv/thhv.ko"
DOM1_DISK="/dev/vdc"
DOM1_SEED="/dev/vdd"  # only present when SEED_DOM1=1 was set at QEMU launch

OVMF="${OVMF:-/usr/share/OVMF/OVMF.fd}"
CHV_CPUS="${CHV_CPUS:-2}"
CHV_MEM="${CHV_MEM:-1G}"

if [[ ! -b "$DOM1_DISK" ]]; then
    echo "ERROR: dom1 disk $DOM1_DISK not found."
    echo "       Make sure QEMU was started with dom1.img attached (it is automatic"
    echo "       when guest/dom1.img exists on the host)."
    exit 1
fi

if [[ ! -f "$CHV" ]]; then
    echo "ERROR: cloud-hypervisor binary not found at $CHV"
    exit 1
fi

# Load thhv.ko if /dev/thhv is not yet present.
if [[ ! -c /dev/thhv ]]; then
    if [[ -f "$THHV_KO" ]]; then
        echo "→ Loading thhv.ko..."
        sudo insmod "$THHV_KO" || true
    fi
fi

if [[ -c /dev/thhv ]]; then
    echo "→ Backend: Themis (/dev/thhv)"
else
    echo "→ Backend: KVM (/dev/kvm)"
fi

DISK_ARGS="path=$DOM1_DISK"
EXTRA_DISKS=""
if [[ "${SEED_DOM1:-0}" == "1" && -b "$DOM1_SEED" ]]; then
    EXTRA_DISKS="--disk path=$DOM1_SEED,readonly=on"
    echo "  + cloud-init seed: $DOM1_SEED"
fi

echo "→ Booting dom1 — ${CHV_CPUS} CPUs, ${CHV_MEM} RAM"
echo "  Login: cloud / cloud123"
echo ""

exec "$CHV" \
    --firmware "$OVMF" \
    --disk path="$DOM1_DISK" \
    $EXTRA_DISKS \
    --cpus boot="$CHV_CPUS" \
    --memory size="$CHV_MEM" \
    --console tty \
    --serial tty \
    ${CHV_EXTRA_ARGS:-}
