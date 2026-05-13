#!/usr/bin/env bash
# run-chv-runner.sh — cargo-compatible runner: takes the ELF binary as argument.
# Used as: cargo run-chv  (via cargo alias)
#
# This script is invoked by the cargo alias with the built binary path.
# It finds cloud-hypervisor and boots the ELF with PVH.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EUNOMIA_DIR="$(dirname "$SCRIPT_DIR")"

KERNEL="${1:?Usage: $0 <elf-binary>}"

# ── CHV binary discovery ─────────────────────────────────────────────────
CHV="${CHV:-}"
if [[ -z "$CHV" ]]; then
    for candidate in \
        "$EUNOMIA_DIR/../cloud-hypervisor/target/release/cloud-hypervisor" \
        "/opt/bins/cloud-hypervisor/cloud-hypervisor" \
        "$(command -v cloud-hypervisor 2>/dev/null || true)"
    do
        if [[ -n "$candidate" && -x "$candidate" ]]; then
            CHV="$candidate"
            break
        fi
    done
fi

if [[ -z "$CHV" ]]; then
    echo "ERROR: cloud-hypervisor not found. Set CHV=/path/to/cloud-hypervisor" >&2
    exit 1
fi

exec "$CHV" \
    --kernel "$KERNEL" \
    --cpus boot="${CHV_CPUS:-1}" \
    --memory size="${CHV_MEM:-128M}" \
    --serial tty \
    --console off \
    --seccomp false \
    ${CHV_EXTRA_ARGS:-} 2>&1
