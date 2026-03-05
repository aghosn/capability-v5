#!/usr/bin/env bash
# build-iso.sh — Build the Themis capavisor binary and package it into a
#                Limine BIOS/UEFI-bootable ISO image.
#
# Usage:
#   cargo iso                    # from the workspace root
#   bash scripts/build-iso.sh    # directly
#
# Output:  target/themis.iso
#
# Prerequisites:
#   • xorriso     (sudo apt install xorriso)
#   • limine      (cargo setup-limine — clones and builds locally in tools/limine/)
#
# The LIMINE_DIR environment variable can override the default search path.

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

# Search common install locations if not set (local first)
if [[ -z "$LIMINE_DIR" ]]; then
    for candidate in \
        "$WORKSPACE_ROOT/tools/limine" \
        "$HOME/.local/share/limine" \
        "/usr/share/limine" \
        "/usr/local/share/limine"
    do
        if [[ -f "$candidate/limine-bios.sys" ]]; then
            LIMINE_DIR="$candidate"
            break
        fi
    done
fi

# Auto-setup if not found
if [[ -z "$LIMINE_DIR" ]]; then
    echo "→ Limine not found; running setup-limine.sh ..."
    bash "$SCRIPT_DIR/setup-limine.sh"
    LIMINE_DIR="$WORKSPACE_ROOT/tools/limine"
fi

if [[ ! -f "$LIMINE_DIR/limine-bios.sys" ]]; then
    echo "ERROR: Limine boot files not found in $LIMINE_DIR" >&2
    echo "       Run: cargo setup-limine" >&2
    exit 1
fi

LIMINE_DEPLOY="${LIMINE_DEPLOY:-${LIMINE_DIR}/limine}"
if [[ ! -x "$LIMINE_DEPLOY" ]]; then
    # Fall back to PATH
    if command -v limine &>/dev/null; then
        LIMINE_DEPLOY="limine"
    else
        echo "ERROR: limine deploy tool not found (set LIMINE_DEPLOY or put limine on PATH)" >&2
        exit 1
    fi
fi

# ── Build capavisor ────────────────────────────────────────────────────────

cd "$WORKSPACE_ROOT"

PROFILE="${PROFILE:-debug}"
if [[ "$PROFILE" == "release" ]]; then
    cargo build --release -p capavisor
    ELF="target/x86_64-unknown-none/release/capavisor"
else
    cargo build -p capavisor
    ELF="target/x86_64-unknown-none/debug/capavisor"
fi

echo "→ ELF built: $ELF"

# ── Assemble ISO tree ──────────────────────────────────────────────────────

ISO_ROOT="$(mktemp -d)"
trap 'rm -rf "$ISO_ROOT"' EXIT

mkdir -p "$ISO_ROOT/boot/limine"

cp "$ELF"                             "$ISO_ROOT/boot/capavisor"
cp "$LIMINE_DIR/limine-bios.sys"      "$ISO_ROOT/boot/limine/"
cp "$LIMINE_DIR/limine-bios-cd.bin"   "$ISO_ROOT/boot/limine/"
cp "$LIMINE_DIR/limine-uefi-cd.bin"   "$ISO_ROOT/boot/limine/" 2>/dev/null || true

cat > "$ISO_ROOT/boot/limine/limine.conf" <<'CONF'
timeout: 0
serial: yes

/Themis Capavisor
    protocol: limine
    kernel_path: boot():/boot/capavisor
CONF

# Only include dom0 modules if the disk image is present.
# Without these lines Limine boots the capavisor alone (useful for testing).
if [[ -f "$WORKSPACE_ROOT/guest/jammy-server-cloudimg-amd64.img" ]]; then
    cat >> "$ISO_ROOT/boot/limine/limine.conf" <<'CONF'
    module_path: fslabel(cloudimg-rootfs):/boot/vmlinuz
    module_cmdline: dom0-kernel
    module_path: fslabel(cloudimg-rootfs):/boot/initrd.img
    module_cmdline: dom0-initrd
CONF
fi

# Copy UEFI loader (BOOTX64.EFI) for fallback/hard-disk boot.
# Limine v8.x ships BOOTX64.EFI at the top level (no EFI/BOOT/ subdir).
mkdir -p "$ISO_ROOT/EFI/BOOT"
if [[ -f "$LIMINE_DIR/BOOTX64.EFI" ]]; then
    cp "$LIMINE_DIR/BOOTX64.EFI" "$ISO_ROOT/EFI/BOOT/"
elif [[ -f "$LIMINE_DIR/EFI/BOOT/BOOTX64.EFI" ]]; then
    cp "$LIMINE_DIR/EFI/BOOT/BOOTX64.EFI" "$ISO_ROOT/EFI/BOOT/"
fi

# ── Create ISO ─────────────────────────────────────────────────────────────

ISO_OUT="$WORKSPACE_ROOT/target/themis.iso"
mkdir -p "$WORKSPACE_ROOT/target"

xorriso -as mkisofs \
    -b boot/limine/limine-bios-cd.bin \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    --efi-boot boot/limine/limine-uefi-cd.bin \
    -efi-boot-part --efi-boot-image --protective-msdos-label \
    "$ISO_ROOT" \
    -o "$ISO_OUT" \
    2>&1 | tail -5

# ── Install Limine BIOS bootstrapper ──────────────────────────────────────

"$LIMINE_DEPLOY" bios-install "$ISO_OUT"

echo "✔ ISO ready: $ISO_OUT"
