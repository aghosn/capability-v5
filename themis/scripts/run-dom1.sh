#!/usr/bin/env bash
# run-dom1.sh — Boot dom1 under cloud-hypervisor from inside dom0.
#
# Auto-detects the hypervisor backend:
#   - If /dev/thhv is present (or thhv.ko loads successfully): Themis backend
#   - Otherwise: KVM backend
#
# Uses dom0's own kernel + initrd (same Ubuntu Noble image) for direct kernel
# boot, bypassing GRUB and the LABEL=cloudimg-rootfs issue entirely.
#
# Usage (from inside dom0):
#   sudo /opt/bins/cloud-hypervisor/run-dom1.sh              # normal boot
#   SEED_DOM1=1 sudo /opt/bins/cloud-hypervisor/run-dom1.sh  # first boot with cloud-init seed
#
# Login: cloud / cloud123

set -euo pipefail

BINS="/opt/bins"
CHV="$BINS/cloud-hypervisor/cloud-hypervisor"
THHV_KO="$BINS/thhv/thhv.ko"
DOM1_DISK="$BINS/dom1/dom1.raw"
HVF="$BINS/dom1/hypervisor-fw"

CHV_CPUS="${CHV_CPUS:-2}"
CHV_MEM="${CHV_MEM:-1G}"

if [[ ! -f "$DOM1_DISK" ]]; then
    echo "ERROR: dom1 disk not found at $DOM1_DISK"
    exit 1
fi
if [[ ! -f "$HVF" ]]; then
    echo "ERROR: hypervisor-fw not found at $HVF"
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
        insmod "$THHV_KO" || true
    fi
fi

if [[ -c /dev/thhv ]]; then
    echo "→ Backend: Themis (/dev/thhv)"
else
    echo "→ Backend: KVM (/dev/kvm)"
fi

# ── Networking: TAP + NAT ─────────────────────────────────────────────────
TAP="tap-dom1"
DOM1_IP="192.168.100.2"
GW_IP="192.168.100.1"

if ! ip link show "$TAP" &>/dev/null 2>&1; then
    ip tuntap add "$TAP" mode tap
fi
ip addr flush dev "$TAP" 2>/dev/null || true
ip addr add "${GW_IP}/24" dev "$TAP"
ip link set "$TAP" up
sysctl -qw net.ipv4.ip_forward=1
iptables -t nat -C POSTROUTING -s 192.168.100.0/24 -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -j MASQUERADE
echo "  + networking: tap=$TAP gw=$GW_IP dom1=$DOM1_IP"

echo "→ Booting dom1 — ${CHV_CPUS} CPUs, ${CHV_MEM} RAM"
echo "  Login: cloud / cloud123"
echo ""

exec "$CHV" \
    --kernel "$HVF" \
    --disk path="$DOM1_DISK" \
    --net tap="$TAP",mac=12:34:56:78:90:ab \
    --cpus boot="$CHV_CPUS" \
    --memory size="$CHV_MEM" \
    --serial tty \
    --console off \
    --seccomp log \
    ${CHV_EXTRA_ARGS:-}
