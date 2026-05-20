#!/usr/bin/env bash
# run-eunomia.sh — Boot an Eunomia workload under cloud-hypervisor from dom0.
#
# Usage (inside dom0):
#   sudo /opt/bins/eunomia/run-eunomia.sh                 # smoke (default)
#   sudo /opt/bins/eunomia/run-eunomia.sh timer            # named workload
#   sudo /opt/bins/eunomia/run-eunomia.sh /path/to/elf     # explicit ELF
#
# Environment:
#   CHV_CPUS      vCPU count (default: 1)
#   CHV_MEM       Memory   (default: 128M)
#
# Modes:
#   --kvm         Force KVM backend
#   --themis      Force Themis backend (default: auto-detect)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINS="/opt/bins"
CHV="$BINS/cloud-hypervisor/cloud-hypervisor"
THHV_KO="$BINS/thhv/thhv.ko"

CHV_CPUS="${CHV_CPUS:-1}"
CHV_MEM="${CHV_MEM:-128M}"
BACKEND_MODE="auto"
WORKLOAD=""

# ── Parse arguments ───────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kvm)     BACKEND_MODE="kvm";    shift ;;
        --themis)  BACKEND_MODE="themis"; shift ;;
        --help|-h)
            head -14 "$0" | tail -12
            exit 0
            ;;
        *)
            WORKLOAD="$1"; shift ;;
    esac
done

# ── Backend selection ─────────────────────────────────────────────────────
case "$BACKEND_MODE" in
    kvm)
        if [[ -c /dev/thhv ]]; then
            echo "→ Unloading thhv.ko to force KVM backend..."
            rmmod thhv 2>/dev/null || true
        fi
        echo "→ Backend: KVM"
        ;;
    themis)
        if [[ ! -c /dev/thhv ]]; then
            if [[ -f "$THHV_KO" ]]; then
                echo "→ Loading thhv.ko..."
                insmod "$THHV_KO"
            else
                echo "ERROR: thhv.ko not found" >&2
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

# ── Kernel selection ──────────────────────────────────────────────────────
if [[ -z "$WORKLOAD" ]]; then
    WORKLOAD="smoke"
fi

# If it's a path to an existing file, use it directly
if [[ -f "$WORKLOAD" ]]; then
    KERNEL="$WORKLOAD"
else
    # Look up by workload name in the eunomia dir
    KERNEL="$SCRIPT_DIR/eunomia-${WORKLOAD}"
    if [[ ! -f "$KERNEL" ]]; then
        echo "ERROR: workload not found: $KERNEL" >&2
        echo "Available workloads:"
        ls "$SCRIPT_DIR"/eunomia-* 2>/dev/null | sed 's|.*/eunomia-|  |' || echo "  (none)"
        exit 1
    fi
fi

# ── Validation ────────────────────────────────────────────────────────────
if [[ ! -f "$CHV" ]]; then
    echo "ERROR: cloud-hypervisor not found at $CHV" >&2
    exit 1
fi

echo "╔═══════════════════════════════════════╗"
echo "║     Eunomia — dom1 boot (CHV/PVH)    ║"
echo "╚═══════════════════════════════════════╝"
echo ""
echo "  kernel:  $KERNEL"
echo "  cpus:    $CHV_CPUS"
echo "  memory:  $CHV_MEM"
echo ""

# ── Build CHV command line ─────────────────────────────────────────────────
CHV_ARGS=(
    --kernel "$KERNEL"
    --cpus boot="$CHV_CPUS"
    --memory size="$CHV_MEM"
    --serial tty
    --console off
    --seccomp false
)

# CoCo workloads get the confidential platform flag.
WORKLOAD_NAME="$(basename "$KERNEL" | sed 's/^eunomia-//')"
case "$WORKLOAD_NAME" in
    coco*)
        CHV_ARGS+=(--platform "confidential=on")
        echo "  mode:    confidential (CoCo)"
        ;;
esac

echo ""

exec "$CHV" "${CHV_ARGS[@]}"
