#!/usr/bin/env bash
# run-dom0.sh — Boot the dom0 Linux disk directly under QEMU, bypassing Themis.
#
# This is a sanity-check: it boots the dom0 image as a plain VM to verify
# that the disk, kernel, and cloud-init configuration are all working before
# integrating with the Themis boot flow.
#
# First boot:   SEED=1 cargo dom0     (provisions cloud user, then shutdown)
# After that:   cargo dom0            (normal boot, no seed needed)
#
# Environment knobs:
#   SEED=1            attach cloud-init seed (first boot only)
#   QEMU_CPUS=4       number of vCPUs (default: 2)
#   QEMU_MEM=4G       guest RAM (default: 4G)
#   QEMU_ENABLE_KVM=1 use KVM acceleration (default: 1 if available)
#   QEMU_NET=1        enable user-mode networking (default: 1)
#   QEMU_NET_FWD      extra port forwards (e.g. "hostfwd=tcp::2222-:22")
#   QEMU_EXTRA_ARGS   additional arguments appended to the QEMU command
#
# Login: user=cloud  password=cloud123  (provisioned by cloud-init seed)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$SCRIPT_DIR/dom0-lib.sh"

# Auto-detect or use DOM0_VERSION env var.
if [[ -n "${DOM0_VERSION:-}" ]]; then
    dom0_select "$DOM0_VERSION"
elif _detected=$(dom0_detect_from_guest_dir "$WORKSPACE_ROOT/guest"); then
    dom0_select "$_detected"
else
    dom0_select ""
fi

DOM0_DISK="$WORKSPACE_ROOT/guest/$DOM0_IMAGE_NAME"
SEED_IMG="$WORKSPACE_ROOT/guest/seed.img"
SEEDED_MARKER="$WORKSPACE_ROOT/guest/.dom0-seeded"

if [[ ! -f "$DOM0_DISK" ]]; then
    echo "ERROR: dom0 disk not found: $DOM0_DISK"
    echo "       Run: cargo fetch-dom0"
    exit 1
fi

QEMU_CPUS="${QEMU_CPUS:-2}"
QEMU_MEM="${QEMU_MEM:-4G}"

# Detect KVM
KVM_ARGS=""
if [[ "${QEMU_ENABLE_KVM:-1}" == "1" ]] && [[ -e /dev/kvm ]]; then
    KVM_ARGS="-enable-kvm -cpu host"
else
    echo "WARNING: KVM not available — running without hardware acceleration"
    KVM_ARGS="-cpu qemu64"
fi

# Cloud-init seed: only attach when SEED=1
SEED_ARG=""
if [[ "${SEED:-0}" == "1" ]]; then
    if [[ ! -f "$SEED_IMG" ]]; then
        echo "ERROR: seed.img not found. Run: cargo fetch-dom0"
        exit 1
    fi
    SEED_ARG="-cdrom $SEED_IMG"
    echo "  + cloud-init seed: guest/seed.img"
    echo "  (first boot — cloud-init will provision user 'cloud')"
    echo "  Wait for login prompt, verify you can log in, then poweroff."
elif [[ ! -f "$SEEDED_MARKER" ]]; then
    echo "WARNING: dom0 image has not been seeded yet."
    echo "         Run:  SEED=1 cargo dom0"
    echo "         then log in (cloud/cloud123), verify, and poweroff."
    echo ""
fi

# ── Networking ───────────────────────────────────────────────────────────────
# User-mode (SLIRP) networking with virtio-net.  Guest gets DHCP 10.0.2.x,
# host-to-guest SSH on localhost:2222.
NET_ARGS=""
if [[ "${QEMU_NET:-1}" == "1" ]]; then
    NET_FWD="hostfwd=tcp::2222-:22"
    [[ -n "${QEMU_NET_FWD:-}" ]] && NET_FWD+=",${QEMU_NET_FWD}"
    NET_ARGS="-netdev user,id=n0,${NET_FWD} -device virtio-net-pci,netdev=n0"
fi

echo "→ Booting guest/$DOM0_IMAGE_NAME directly (no Themis) — ${QEMU_CPUS} CPUs, ${QEMU_MEM} RAM"
echo "  Login: cloud / cloud123"
[[ -n "$NET_ARGS" ]] && echo "  + networking: virtio-net (SLIRP), SSH → localhost:2222"
echo ""

qemu-system-x86_64 \
    $KVM_ARGS \
    -smp "$QEMU_CPUS" \
    -m "$QEMU_MEM" \
    -drive if=virtio,format=qcow2,file="$DOM0_DISK" \
    $SEED_ARG \
    $NET_ARGS \
    -nographic \
    -no-reboot \
    ${QEMU_EXTRA_ARGS:-}

# If we booted with seed and QEMU exited normally, mark as seeded.
if [[ "${SEED:-0}" == "1" ]]; then
    touch "$SEEDED_MARKER"
    echo ""
    echo "✔ dom0 image marked as seeded. From now on, just run: cargo dom0"
fi
