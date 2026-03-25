#!/usr/bin/env bash
# run-dom1.sh — Boot dom1 under cloud-hypervisor from inside dom0.
#
# Auto-detects the hypervisor backend:
#   - If /dev/thhv is present (or thhv.ko loads successfully): Themis backend
#   - Otherwise: KVM backend
#
# Uses dom0's own kernel + initrd for direct kernel boot, bypassing GRUB.
# Slow/network-dependent services are masked via the kernel cmdline.
#
# Usage (from inside dom0):
#   sudo /opt/bins/cloud-hypervisor/run-dom1.sh

set -euo pipefail

BINS="/opt/bins"
CHV="$BINS/cloud-hypervisor/cloud-hypervisor"
THHV_KO="$BINS/thhv/thhv.ko"
DOM1_DISK="$BINS/dom1/dom1.raw"

CHV_CPUS="${CHV_CPUS:-2}"
CHV_MEM="${CHV_MEM:-1G}"

if [[ ! -f "$DOM1_DISK" ]]; then
    echo "ERROR: dom1 disk not found at $DOM1_DISK"
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

# Auto-detect kernel and initramfs — prefer versioned files, fall back to unversioned.
# If a debug/instrumented kernel was packed into bins.img, prefer it.
KERNEL_IMG=""
INITRAMFS_IMG=""

if [[ -f "$BINS/nested/bzImage" ]]; then
    echo "  → Using instrumented nested kernel: $BINS/nested/bzImage"
    KERNEL_IMG="$BINS/nested/bzImage"
else
    for f in $(ls /boot/vmlinuz-* 2>/dev/null | sort -V); do KERNEL_IMG="$f"; done
    [[ -z "$KERNEL_IMG" && -f /boot/vmlinuz ]] && KERNEL_IMG=/boot/vmlinuz
fi

for f in $(ls /boot/initrd.img-* 2>/dev/null | sort -V); do
    # Skip broken/empty files (e.g. interrupted kernel upgrades leave 0-byte .new files)
    [[ -s "$f" ]] && INITRAMFS_IMG="$f"
done
[[ -z "$INITRAMFS_IMG" && -f /boot/initrd.img ]] && INITRAMFS_IMG=/boot/initrd.img

if [[ -z "$KERNEL_IMG" ]]; then echo "ERROR: no kernel found in /boot"; exit 1; fi
echo "  kernel:    $KERNEL_IMG"
if [[ -n "$INITRAMFS_IMG" ]]; then
    echo "  initramfs: $INITRAMFS_IMG"
    INITRAMFS_ARGS="--initramfs $INITRAMFS_IMG"
else
    echo "  initramfs: none"
    INITRAMFS_ARGS=""
fi
echo ""

exec "$CHV" \
    --kernel "$KERNEL_IMG" \
    ${INITRAMFS_ARGS} \
    --cmdline "console=hvc0 earlyprintk=serial,ttyS0,115200 root=/dev/vda1 rw nokaslr nopv lpj=3000000 tsc=reliable clocksource=tsc keep_bootcon loglevel=7 no_timer_check systemd.mask=snapd.seeded.service systemd.mask=snapd.service systemd.mask=networkd-wait-online.service systemd.mask=multipathd.service" \
    --disk path="$DOM1_DISK" \
    --net tap="$TAP",mac=12:34:56:78:90:ab \
    --cpus boot="$CHV_CPUS",max_phys_bits=34 \
    --memory size="$CHV_MEM" \
    --serial tty \
    --console tty \
    --seccomp false \
    ${CHV_EXTRA_ARGS:-}
