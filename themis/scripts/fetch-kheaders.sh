#!/usr/bin/env bash
# fetch-kheaders.sh — Download pinned dom0 kernel headers without sudo.
#
# Usage:
#   bash themis/scripts/fetch-kheaders.sh
#
# Reads the pinned dom0 kernel version from dom0-kernel-version.txt, downloads
# the matching Ubuntu linux-headers packages with apt-get download, extracts
# them into themis/target/kheaders/, and prints the KDIR path for thhv builds.
# Re-runs are safe: if the extracted headers directory already exists, the
# script prints "already present" and exits 0.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
KVER_FILE="$SCRIPT_DIR/dom0-kernel-version.txt"
KHEADERS_ROOT="$WORKSPACE_ROOT/target/kheaders"
TMPDIR=""

need() {
    if ! command -v "$1" &>/dev/null; then
        echo "ERROR: '$1' not found. Install: $2" >&2
        exit 1
    fi
}

cleanup() {
    if [[ -n "$TMPDIR" && -d "$TMPDIR" ]]; then
        rm -rf "$TMPDIR"
    fi
}
trap cleanup EXIT

need apt-get  "sudo apt install apt"
need dpkg-deb "sudo apt install dpkg"

if [[ ! -f "$KVER_FILE" ]]; then
    echo "ERROR: pinned kernel version file not found: $KVER_FILE" >&2
    echo "       Remediation: create dom0-kernel-version.txt with the dom0 uname -r value." >&2
    exit 1
fi

KVER="$(tr -d '[:space:]' < "$KVER_FILE")"
if [[ -z "$KVER" ]]; then
    echo "ERROR: dom0 kernel version file is empty: $KVER_FILE" >&2
    exit 1
fi

if [[ "$KVER" == *-generic ]]; then
    KBASE="${KVER%-generic}"
    KDIR="$KHEADERS_ROOT/usr/src/linux-headers-${KVER}"
    PACKAGES=("linux-headers-${KBASE}" "linux-headers-${KVER}")
else
    KBASE="$KVER"
    KDIR="$KHEADERS_ROOT/usr/src/linux-headers-${KVER}-generic"
    PACKAGES=("linux-headers-${KVER}" "linux-headers-${KVER}-generic")
fi

mkdir -p "$KHEADERS_ROOT"

if [[ -d "$KDIR" && -f "$KDIR/Makefile" ]]; then
    echo "already present: $KDIR"
    exit 0
fi

TMPDIR="$(mktemp -d)"

echo "→ Downloading kernel headers for $KVER"
(
    cd "$TMPDIR"
    apt-get download "${PACKAGES[@]}"
)

shopt -s nullglob
DEBS=("$TMPDIR"/*.deb)
shopt -u nullglob

if (( ${#DEBS[@]} == 0 )); then
    echo "ERROR: apt-get download did not produce any .deb files for $KVER" >&2
    echo "       Remediation: run 'sudo apt update' on the host, then retry." >&2
    exit 1
fi

for deb in "${DEBS[@]}"; do
    dpkg-deb --extract "$deb" "$KHEADERS_ROOT"
done

if [[ ! -d "$KDIR" || ! -f "$KDIR/Makefile" ]]; then
    echo "ERROR: extracted headers are incomplete; expected $KDIR/Makefile" >&2
    echo "       Remediation: delete $KHEADERS_ROOT and rerun this script." >&2
    exit 1
fi

echo "✔ Kernel headers ready"
echo "$KDIR"
