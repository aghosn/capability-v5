#!/usr/bin/env bash
# build-iso-aarch64.sh — Build the AArch64 capavisor ELF and package it into
#                         a Limine UEFI-bootable ISO for qemu-system-aarch64.
#
# Usage:
#   bash scripts/build-iso-aarch64.sh
#
# Output:  target/themis-aarch64.iso
#
# Prerequisites:
#   • xorriso              (sudo apt install xorriso)
#   • limine               (cargo setup-limine)
#   • aarch64 Rust target  (rustup target add aarch64-unknown-none)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Prerequisites ──────────────────────────────────────────────────────────

if ! command -v xorriso &>/dev/null; then
    echo "ERROR: xorriso not found. Install: sudo apt install xorriso" >&2
    exit 1
fi

# ── Locate Limine ──────────────────────────────────────────────────────────

LIMINE_DIR="${LIMINE_DIR:-}"

if [[ -z "$LIMINE_DIR" ]]; then
    for candidate in \
        "$WORKSPACE_ROOT/tools/limine" \
        "$HOME/.local/share/limine" \
        "/usr/share/limine"
    do
        if [[ -f "$candidate/BOOTAA64.EFI" ]]; then
            LIMINE_DIR="$candidate"
            break
        fi
    done
fi

if [[ -z "$LIMINE_DIR" ]]; then
    echo "→ Limine not found; running setup-limine.sh ..."
    bash "$SCRIPT_DIR/setup-limine.sh"
    LIMINE_DIR="$WORKSPACE_ROOT/tools/limine"
fi

if [[ ! -f "$LIMINE_DIR/BOOTAA64.EFI" ]]; then
    echo "ERROR: BOOTAA64.EFI not found in $LIMINE_DIR" >&2
    echo "       Run: cargo setup-limine" >&2
    exit 1
fi

# ── Build capavisor (aarch64) ──────────────────────────────────────────────

cd "$WORKSPACE_ROOT"

PROFILE="${PROFILE:-debug}"
FEATURES_FLAG=""
if [[ -n "${CAPAVISOR_FEATURES:-}" ]]; then
    FEATURES_FLAG="--features ${CAPAVISOR_FEATURES}"
fi
if [[ "$PROFILE" == "release" ]]; then
    cargo build --release -p capavisor --target aarch64-unknown-none $FEATURES_FLAG
    ELF="target/aarch64-unknown-none/release/capavisor"
else
    cargo build -p capavisor --target aarch64-unknown-none $FEATURES_FLAG
    ELF="target/aarch64-unknown-none/debug/capavisor"
fi

echo "→ ELF built: $ELF"

# ── Assemble ISO tree ──────────────────────────────────────────────────────

ISO_ROOT="$(mktemp -d)"
trap 'rm -rf "$ISO_ROOT"' EXIT

mkdir -p "$ISO_ROOT/boot/limine"
mkdir -p "$ISO_ROOT/EFI/BOOT"

cp "$ELF" "$ISO_ROOT/boot/capavisor"

# Limine UEFI CD loader + AA64 EFI stub.
cp "$LIMINE_DIR/limine-uefi-cd.bin" "$ISO_ROOT/boot/limine/" 2>/dev/null || true
cp "$LIMINE_DIR/BOOTAA64.EFI"       "$ISO_ROOT/EFI/BOOT/"

cat > "$ISO_ROOT/boot/limine/limine.conf" <<'CONF'
timeout: 0
serial: yes

/Themis Capavisor (AArch64)
    protocol: limine
    kernel_path: boot():/boot/capavisor
CONF

# ── Create ISO ─────────────────────────────────────────────────────────────
# AArch64 is UEFI-only — no BIOS boot needed.

ISO_OUT="$WORKSPACE_ROOT/target/themis-aarch64.iso"
mkdir -p "$WORKSPACE_ROOT/target"

xorriso -as mkisofs \
    --efi-boot boot/limine/limine-uefi-cd.bin \
    -efi-boot-part --efi-boot-image --protective-msdos-label \
    -no-emul-boot \
    "$ISO_ROOT" \
    -o "$ISO_OUT" \
    2>&1 | tail -5

echo "✔ ISO ready: $ISO_OUT"
