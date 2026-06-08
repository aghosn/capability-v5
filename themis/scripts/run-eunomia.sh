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
        # Provision a capability-backed ivshmem device for doorbell/notification.
        # alias mode: dom0 keeps access, child discovers via CPUID 0x40000004.
        IVSHMEM_PATH="/tmp/eunomia-doorbell-$$"
        truncate -s 4096 "$IVSHMEM_PATH"
        CHV_ARGS+=(--ivshmem "path=${IVSHMEM_PATH},size=4096,mode=alias,count=1")
        echo "  mode:    confidential (CoCo)"
        echo "  ivshmem: ${IVSHMEM_PATH} (4K, alias, doorbell)"
        ;;
esac

echo ""

# coco-illegal-access is a self-contained isolation test: boot dom1 in the
# background, give it time to come up and stamp its sentinel pages, then run
# the attacker against /dev/thhv.  The workload spins forever so a fixed
# sleep is fine.
if [[ "$WORKLOAD_NAME" == "coco-illegal-access" ]]; then
    ATTACKER_BIN="$BINS/thhv/tests/test_coco_attacker"
    if [[ ! -x "$ATTACKER_BIN" ]]; then
        echo "ERROR: $ATTACKER_BIN not found/executable" >&2
        exit 1
    fi

    DOM1_LOG="$(mktemp -t eunomia-dom1.XXXXXX.log)"
    echo "→ launching dom1 in background (log: $DOM1_LOG) ..."
    "$CHV" "${CHV_ARGS[@]}" >"$DOM1_LOG" 2>&1 &
    DOM1_PID=$!

    cleanup() {
        if kill -0 "$DOM1_PID" 2>/dev/null; then
            kill "$DOM1_PID" 2>/dev/null || true
            sleep 1
            kill -9 "$DOM1_PID" 2>/dev/null || true
        fi
    }
    trap cleanup EXIT INT TERM

    echo "→ sleeping 10s to let dom1 boot ..."
    sleep 10

    echo "→ running attacker ..."
    set +e
    "$ATTACKER_BIN" -v
    RC=$?
    set -e

    echo "→ attacker exit code: $RC"
    echo "── dom1 log tail ────────────────────────────────────────────"
    tail -40 "$DOM1_LOG" || true
    echo "─────────────────────────────────────────────────────────────"
    rm -f "$DOM1_LOG"
    exit "$RC"
fi

exec "$CHV" "${CHV_ARGS[@]}"
