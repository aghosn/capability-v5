#!/usr/bin/env bash
# setup-limine.sh — Clone Limine v8.7.0 (binary branch) into tools/limine/
#                   and build the `limine` CLI tool.
#
# Everything stays local to the repository — nothing is installed system-wide.
# The build-iso.sh script already searches tools/limine/ for boot files.
#
# Usage:
#   cargo setup-limine              # via Cargo alias
#   bash scripts/setup-limine.sh    # directly
#
# Requirements: git, cc (gcc or clang)
#
# Pinned release: v8.7.0  (commit aad3edd370955449717a334f0289dee10e2c5f01)
# Branch:         v8.x-binary  (pre-built boot files, only the CLI needs compiling)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

LIMINE_DIR="$WORKSPACE_ROOT/tools/limine"
LIMINE_REPO="https://github.com/limine-bootloader/limine.git"
LIMINE_COMMIT="aad3edd370955449717a334f0289dee10e2c5f01"   # v8.7.0

# ── Helpers ────────────────────────────────────────────────────────────────

need() {
    if ! command -v "$1" &>/dev/null; then
        echo "ERROR: '$1' not found. Install: $2" >&2
        exit 1
    fi
}

need git "sudo apt install git"
need cc  "sudo apt install gcc   (or clang)"

# ── Clone / update ─────────────────────────────────────────────────────────

if [[ -d "$LIMINE_DIR/.git" ]]; then
    CURRENT="$(git -C "$LIMINE_DIR" rev-parse HEAD 2>/dev/null || true)"
    if [[ "$CURRENT" == "$LIMINE_COMMIT" ]]; then
        echo "✔ Limine v8.7.0 already set up in tools/limine/"
        # Ensure the CLI binary exists
        if [[ ! -x "$LIMINE_DIR/limine" ]]; then
            echo "  → Building limine CLI ..."
            make -C "$LIMINE_DIR" -j"$(nproc)" --quiet
        fi
        exit 0
    fi
    echo "  → Limine present but at wrong commit; re-cloning ..."
    rm -rf "$LIMINE_DIR"
fi

mkdir -p "$WORKSPACE_ROOT/tools"

echo "→ Cloning Limine v8.7.0 (binary branch) into tools/limine/ ..."
git clone --depth 1 --branch v8.x-binary "$LIMINE_REPO" "$LIMINE_DIR" --quiet
git -C "$LIMINE_DIR" fetch --depth 1 origin "$LIMINE_COMMIT" --quiet
git -C "$LIMINE_DIR" checkout "$LIMINE_COMMIT" --quiet

# ── Build the CLI tool ─────────────────────────────────────────────────────

echo "  → Building limine CLI ..."
make -C "$LIMINE_DIR" -j"$(nproc)" --quiet

if [[ ! -x "$LIMINE_DIR/limine" ]]; then
    echo "ERROR: limine CLI binary not produced" >&2
    exit 1
fi

# ── Verify ─────────────────────────────────────────────────────────────────

echo ""
echo "✔ Limine v8.7.0 ready in tools/limine/"
echo "  Boot files:  limine-bios.sys  limine-bios-cd.bin  limine-uefi-cd.bin"
echo "  UEFI:        BOOTX64.EFI"
echo "  CLI:         limine"
