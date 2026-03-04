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
#   • limine      (cargo install limine-install  OR  apt install limine)
#     Alternatively: clone https://github.com/limine-bootloader/limine and
#     build with `make` — copy limine-bios.sys, limine-bios-cd.bin,
#     limine-uefi-cd.bin to ~/.local/share/limine/ or set LIMINE_DIR.
#
# The LIMINE_DIR environment variable can override the default search path.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Locate Limine ──────────────────────────────────────────────────────────

LIMINE_DIR="${LIMINE_DIR:-}"

# Search common install locations if not set
if [[ -z "$LIMINE_DIR" ]]; then
    for candidate in \
        "$HOME/.local/share/limine" \
        "/usr/share/limine" \
        "/usr/local/share/limine" \
        "$WORKSPACE_ROOT/tools/limine"
    do
        if [[ -f "$candidate/limine-bios.sys" ]]; then
            LIMINE_DIR="$candidate"
            break
        fi
    done
fi

if [[ -z "$LIMINE_DIR" ]]; then
    echo "ERROR: Limine boot files not found." >&2
    echo "       Clone https://github.com/limine-bootloader/limine, build it," >&2
    echo "       then set LIMINE_DIR to the directory containing limine-bios.sys" >&2
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

cat > "$ISO_ROOT/boot/limine/limine.cfg" <<'EOF'
TIMEOUT=0

/Themis Capavisor
    PROTOCOL=limine
    KERNEL_PATH=boot:///boot/capavisor
EOF

# Copy UEFI loader if present
if [[ -d "$LIMINE_DIR/EFI/BOOT" ]]; then
    mkdir -p "$ISO_ROOT/EFI/BOOT"
    cp "$LIMINE_DIR/EFI/BOOT/"* "$ISO_ROOT/EFI/BOOT/" 2>/dev/null || true
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
