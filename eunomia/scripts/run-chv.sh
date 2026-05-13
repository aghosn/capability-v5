#!/usr/bin/env bash
# run-chv.sh — Boot an Eunomia workload under cloud-hypervisor (PVH boot).
#
# This uses the real PVH boot path (XEN_ELFNOTE_PHYS32_ENTRY) rather than
# QEMU's Linux boot protocol.  hvm_start_info is properly populated.
#
# Usage:
#   ./run-chv.sh <workload-elf>
#   ./run-chv.sh                      # defaults to smoke workload
#
# Examples:
#   ./run-chv.sh ../workloads/smoke/target/x86_64-unknown-none/release/eunomia-smoke
#   CHV=/path/to/cloud-hypervisor ./run-chv.sh <elf>
#
# Environment:
#   CHV           Override cloud-hypervisor binary path
#   CHV_CPUS      vCPU count (default: 1)
#   CHV_MEM       Memory   (default: 128M)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EUNOMIA_DIR="$(dirname "$SCRIPT_DIR")"

# ── Defaults ──────────────────────────────────────────────────────────────
CHV_CPUS="${CHV_CPUS:-1}"
CHV_MEM="${CHV_MEM:-128M}"

# ── CHV binary discovery ─────────────────────────────────────────────────
find_chv() {
    if [[ -n "${CHV:-}" && -x "$CHV" ]]; then
        return
    fi
    # 1) Themis build tree
    local BINS="/opt/bins/cloud-hypervisor/cloud-hypervisor"
    if [[ -x "$BINS" ]]; then
        CHV="$BINS"
        return
    fi
    # 2) Repo build (release)
    local REPO_CHV
    REPO_CHV="$(cd "$EUNOMIA_DIR/.." && pwd)/cloud-hypervisor/target/release/cloud-hypervisor"
    if [[ -x "$REPO_CHV" ]]; then
        CHV="$REPO_CHV"
        return
    fi
    # 3) PATH
    if command -v cloud-hypervisor &>/dev/null; then
        CHV="$(command -v cloud-hypervisor)"
        return
    fi
    echo "ERROR: cloud-hypervisor not found."
    echo "  Set CHV=/path/to/cloud-hypervisor or build with: cargo build --release -p cloud-hypervisor"
    exit 1
}

# ── Kernel ELF discovery ─────────────────────────────────────────────────
find_kernel() {
    if [[ $# -ge 1 && -f "$1" ]]; then
        KERNEL="$1"
        return
    fi
    # Default: smoke workload
    local DEFAULT="$EUNOMIA_DIR/workloads/smoke/target/x86_64-unknown-none/release/eunomia-smoke"
    if [[ -f "$DEFAULT" ]]; then
        KERNEL="$DEFAULT"
        return
    fi
    echo "ERROR: No workload ELF specified and default smoke workload not built."
    echo "  Build it:  cd workloads/smoke && cargo build --release"
    echo "  Or pass:   $0 <path-to-elf>"
    exit 1
}

# ── Main ──────────────────────────────────────────────────────────────────
find_chv
find_kernel "$@"

echo "╔═══════════════════════════════════════╗"
echo "║     Eunomia — CHV PVH boot           ║"
echo "╚═══════════════════════════════════════╝"
echo ""
echo "  chv:     $CHV"
echo "  kernel:  $KERNEL"
echo "  cpus:    $CHV_CPUS"
echo "  memory:  $CHV_MEM"
echo ""

exec "$CHV" \
    -v \
    --kernel "$KERNEL" \
    --cpus boot="$CHV_CPUS" \
    --memory size="$CHV_MEM" \
    --serial tty \
    --console off \
    --seccomp false
