#!/usr/bin/env bash
# run-dom1.sh — Boot dom1 (nested guest) under cloud-hypervisor from inside dom0.
#
# Modes:
#   --kvm       Force KVM backend (skip thhv.ko)
#   --themis    Force Themis backend (fail if thhv.ko unavailable)
#   (default)   Auto-detect: use Themis if /dev/thhv available, else KVM
#
# Kernel selection priority:
#   1. KERNEL env var (explicit path)
#   2. /opt/bins/nested/bzImage (CoCo kernel from bins.img)
#   3. dom0's /boot/vmlinuz-* (highest version, auto-detected)
#
# The CoCo kernel has virtio/ext4/9p built-in — no initramfs needed.
#
# Usage:
#   sudo ./run-dom1.sh              # auto-detect backend + kernel
#   sudo ./run-dom1.sh --themis     # force Themis backend
#   sudo ./run-dom1.sh --kvm        # force KVM backend
#   KERNEL=/path/to/bzImage sudo ./run-dom1.sh
#
# Environment:
#   KERNEL        Override kernel path
#   INITRAMFS     Override initramfs path
#   CHV_CPUS      vCPU count (default: 2)
#   CHV_MEM       Memory (default: 1G)
#   CHV_EXTRA_ARGS  Extra cloud-hypervisor arguments

set -euo pipefail

# ── Paths ─────────────────────────────────────────────────────────────────
BINS="/opt/bins"
CHV="$BINS/cloud-hypervisor/cloud-hypervisor"
THHV_KO="$BINS/thhv/thhv.ko"
DOM1_DISK="$BINS/dom1/dom1.raw"
MODULES_DIR="$BINS/nested/modules"

# ── Defaults ──────────────────────────────────────────────────────────────
CHV_CPUS="${CHV_CPUS:-2}"
CHV_MEM="${CHV_MEM:-1G}"
KERNEL="${KERNEL:-}"
INITRAMFS="${INITRAMFS:-}"
BACKEND_MODE="auto"

# ── Parse arguments ───────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kvm)     BACKEND_MODE="kvm";    shift ;;
        --themis)  BACKEND_MODE="themis"; shift ;;
        --help|-h)
            head -27 "$0" | tail -25
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

# ── Validation ────────────────────────────────────────────────────────────
if [[ ! -f "$DOM1_DISK" ]]; then
    echo "ERROR: dom1 disk not found at $DOM1_DISK"
    echo "  Run: cargo fetch-dom1"
    exit 1
fi
if [[ ! -f "$CHV" ]]; then
    echo "ERROR: cloud-hypervisor not found at $CHV"
    echo "  Run: cargo build-bins"
    exit 1
fi

# ── Backend selection ─────────────────────────────────────────────────────
setup_backend() {
    case "$BACKEND_MODE" in
        kvm)
            if [[ -c /dev/thhv ]]; then
                echo "→ Unloading thhv.ko to force KVM backend..."
                rmmod thhv 2>/dev/null || true
            fi
            if [[ ! -c /dev/kvm ]]; then
                echo "ERROR: /dev/kvm not available"
                exit 1
            fi
            echo "→ Backend: KVM (/dev/kvm)"
            ;;
        themis)
            if [[ ! -c /dev/thhv ]]; then
                if [[ -f "$THHV_KO" ]]; then
                    echo "→ Loading thhv.ko..."
                    insmod "$THHV_KO"
                else
                    echo "ERROR: thhv.ko not found at $THHV_KO"
                    exit 1
                fi
            fi
            echo "→ Backend: Themis (/dev/thhv)"
            ;;
        auto)
            if [[ ! -c /dev/thhv && -f "$THHV_KO" ]]; then
                echo "→ Loading thhv.ko..."
                insmod "$THHV_KO" || true
            fi
            if [[ -c /dev/thhv ]]; then
                echo "→ Backend: Themis (/dev/thhv)"
            else
                echo "→ Backend: KVM (/dev/kvm)"
            fi
            ;;
    esac
}

# ── Kernel selection ──────────────────────────────────────────────────────
select_kernel() {
    local KERNEL_IMG="${KERNEL:-}"
    local INITRAMFS_IMG="${INITRAMFS:-}"
    local KERNEL_SOURCE=""

    # 1) Explicit override
    if [[ -n "$KERNEL_IMG" ]]; then
        KERNEL_SOURCE="env override"

    # 2) CoCo kernel from bins.img
    elif [[ -f "$BINS/nested/bzImage" ]]; then
        KERNEL_IMG="$BINS/nested/bzImage"
        KERNEL_SOURCE="CoCo kernel (bins.img)"

    # 3) dom0 /boot fallback
    else
        for f in $(ls /boot/vmlinuz-* 2>/dev/null | sort -V); do KERNEL_IMG="$f"; done
        [[ -z "$KERNEL_IMG" && -f /boot/vmlinuz ]] && KERNEL_IMG=/boot/vmlinuz
        KERNEL_SOURCE="dom0 /boot"
    fi

    if [[ -z "$KERNEL_IMG" ]]; then
        echo "ERROR: no kernel found"
        echo "  Build one: TARGETS=all cargo build-kernel"
        exit 1
    fi

    # Auto-detect initramfs for dom0 kernels (CoCo kernel doesn't need one)
    if [[ -z "$INITRAMFS_IMG" && "$KERNEL_SOURCE" == "dom0 /boot" ]]; then
        local KVER="${KERNEL_IMG##*/vmlinuz-}"
        if [[ -f "/boot/initrd.img-${KVER}" ]]; then
            INITRAMFS_IMG="/boot/initrd.img-${KVER}"
        fi
    fi

    echo "  kernel:    $KERNEL_IMG ($KERNEL_SOURCE)"
    if [[ -n "$INITRAMFS_IMG" ]]; then
        echo "  initramfs: $INITRAMFS_IMG"
    else
        echo "  initramfs: none (boot drivers built-in)"
    fi

    # Export for use in boot
    SELECTED_KERNEL="$KERNEL_IMG"
    SELECTED_INITRAMFS="$INITRAMFS_IMG"
}

# ── Module installation ──────────────────────────────────────────────────
install_modules() {
    # If CoCo kernel modules are in bins.img, install them into dom1's
    # disk so they're available at runtime. This is a one-time operation
    # per kernel version.
    if [[ -d "$MODULES_DIR" && -d "$MODULES_DIR/lib/modules" ]]; then
        local KVER
        KVER=$(ls "$MODULES_DIR/lib/modules/" | head -1)
        if [[ -n "$KVER" ]]; then
            echo "  modules:   $KVER (from bins.img)"
        fi
    fi
}

# ── Networking: TAP + NAT ─────────────────────────────────────────────────
setup_networking() {
    local TAP="tap-dom1"
    local DOM1_IP="192.168.100.2"
    local GW_IP="192.168.100.1"

    if ! ip link show "$TAP" &>/dev/null 2>&1; then
        ip tuntap add "$TAP" mode tap
    fi
    ip addr flush dev "$TAP" 2>/dev/null || true
    ip addr add "${GW_IP}/24" dev "$TAP"
    ip link set "$TAP" up
    sysctl -qw net.ipv4.ip_forward=1
    iptables -t nat -C POSTROUTING -s 192.168.100.0/24 -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -j MASQUERADE
    echo "  network:   tap=$TAP gw=$GW_IP dom1=$DOM1_IP"
}

# ── Build cmdline ─────────────────────────────────────────────────────────
build_cmdline() {
    local CMDLINE="root=/dev/vda1 rw"

    # Console
    CMDLINE+=" earlyprintk=serial,ttyS0,115200 keep_bootcon"
    CMDLINE+=" console=ttyS0,115200 console=hvc0"

    # Timing (Themis doesn't emulate full PIT/HPET)
    CMDLINE+=" lpj=3000000 tsc=reliable clocksource=tsc no_timer_check"

    # Logging
    CMDLINE+=" loglevel=7"

    # Disable slow services
    CMDLINE+=" systemd.mask=systemd-networkd-wait-online.service"
    CMDLINE+=" systemd.mask=snapd.seeded.service"
    CMDLINE+=" systemd.mask=snapd.service"

    # CoCo kernel: keep KASLR and paravirt, they work fine
    # Dom0 kernel: disable for easier debugging
    if [[ "${SELECTED_KERNEL}" == *"nested"* || "${SELECTED_KERNEL}" == *"guest/kernel"* ]]; then
        CMDLINE+=" nokaslr"
    else
        CMDLINE+=" nokaslr nopv"
    fi

    echo "$CMDLINE"
}

# ── Main ──────────────────────────────────────────────────────────────────
echo "╔═══════════════════════════════════════╗"
echo "║       Themis — dom1 guest boot        ║"
echo "╚═══════════════════════════════════════╝"
echo ""

setup_backend
select_kernel
install_modules
setup_networking

echo ""
echo "→ Booting dom1 — ${CHV_CPUS} vCPUs, ${CHV_MEM} RAM"
echo "  Login: cloud / cloud123"
echo ""

CMDLINE=$(build_cmdline)

INITRAMFS_ARGS=""
if [[ -n "$SELECTED_INITRAMFS" ]]; then
    INITRAMFS_ARGS="--initramfs $SELECTED_INITRAMFS"
fi

exec "$CHV" \
    -v \
    --kernel "$SELECTED_KERNEL" \
    ${INITRAMFS_ARGS} \
    --cmdline "$CMDLINE" \
    --disk path="$DOM1_DISK" \
    --net tap=tap-dom1,mac=12:34:56:78:90:ab \
    --cpus boot="$CHV_CPUS",max_phys_bits=40 \
    --memory size="$CHV_MEM" \
    --serial tty \
    --console tty \
    --seccomp false \
    ${CHV_EXTRA_ARGS:-} >/tmp/chv-stdout.log 2>/tmp/chv-stderr.log
