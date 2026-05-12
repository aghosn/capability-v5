#!/usr/bin/env bash
# build-kernel.sh — Build the Themis CoCo guest kernel from the linux fork.
#
# Usage:
#   bash themis/scripts/build-kernel.sh
#   LINUX_DIR=/path/to/linux bash themis/scripts/build-kernel.sh
#   LINUX_DIR=/path/to/linux JOBS=16 bash themis/scripts/build-kernel.sh
#
# Environment knobs:
#   LINUX_DIR     Path to the aghosn/linux checkout (default: ../linux relative to repo root)
#   KERNEL_PROFILE  Config profile: "minimal" (default, ~245 modules) or "full" (~1750 modules)
#   JOBS          Parallel make jobs (default: $(nproc))
#   TARGETS       What to build: bzImage, modules, or all (default: bzImage)
#   INSTALL_DIR   Where to copy the built kernel (default: themis/guest/kernel/)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

LINUX_DIR="${LINUX_DIR:-$(cd "$REPO_ROOT/.." && pwd)/linux}"
KERNEL_PROFILE="${KERNEL_PROFILE:-minimal}"
JOBS="${JOBS:-$(nproc)}"
TARGETS="${TARGETS:-bzImage}"
INSTALL_DIR="${INSTALL_DIR:-$REPO_ROOT/themis/guest/kernel}"

case "$KERNEL_PROFILE" in
    minimal)
        CONFIG_NAME="themis-coco-x86_64-minimal.config"
        # Try repo-local copy first, fall back to linux tree
        if [ -f "$REPO_ROOT/themis/configs/$CONFIG_NAME" ]; then
            CONFIG_SRC="$REPO_ROOT/themis/configs/$CONFIG_NAME"
        else
            CONFIG_SRC="$LINUX_DIR/configs/$CONFIG_NAME"
        fi
        ;;
    full)
        CONFIG_NAME="themis-coco-x86_64.config"
        CONFIG_SRC="$LINUX_DIR/configs/$CONFIG_NAME"
        ;;
    *)
        echo "ERROR: Unknown KERNEL_PROFILE='$KERNEL_PROFILE'. Use 'minimal' or 'full'."
        exit 1
        ;;
esac

# --- Validation -----------------------------------------------------------

if [ ! -d "$LINUX_DIR" ]; then
    echo "ERROR: Linux source tree not found at: $LINUX_DIR"
    echo "Set LINUX_DIR=/path/to/linux or clone aghosn/linux next to this repo."
    exit 1
fi

if [ ! -f "$LINUX_DIR/Makefile" ] || ! grep -q 'VERSION' "$LINUX_DIR/Makefile" 2>/dev/null; then
    echo "ERROR: $LINUX_DIR does not appear to be a Linux kernel tree."
    exit 1
fi

if [ ! -f "$CONFIG_SRC" ]; then
    echo "ERROR: Kernel config not found at: $CONFIG_SRC"
    echo "Make sure you are on the v6.19.14-themis branch."
    exit 1
fi

# --- Configure -------------------------------------------------------------

echo "=== Themis kernel build ==="
echo "  Linux dir:  $LINUX_DIR"
echo "  Profile:    $KERNEL_PROFILE"
echo "  Config:     $CONFIG_NAME"
echo "  Targets:    $TARGETS"
echo "  Jobs:       $JOBS"
echo ""

if [ ! -f "$LINUX_DIR/.config" ] || ! diff -q "$CONFIG_SRC" "$LINUX_DIR/.config" >/dev/null 2>&1; then
    echo "--- Applying config: $CONFIG_NAME ---"
    cp "$CONFIG_SRC" "$LINUX_DIR/.config"
    make -C "$LINUX_DIR" olddefconfig
fi

# --- Build -----------------------------------------------------------------

if [ "$TARGETS" = "all" ]; then
    BUILD_TARGETS="bzImage modules"
else
    BUILD_TARGETS="$TARGETS"
fi

echo "--- Building: $BUILD_TARGETS ---"
make -C "$LINUX_DIR" -j"$JOBS" $BUILD_TARGETS

# --- Install ---------------------------------------------------------------

if echo "$BUILD_TARGETS" | grep -q 'bzImage'; then
    mkdir -p "$INSTALL_DIR"
    KERNEL_VERSION=$(make -C "$LINUX_DIR" -s kernelrelease)
    BZIMAGE="$LINUX_DIR/arch/x86/boot/bzImage"

    if [ -f "$BZIMAGE" ]; then
        cp "$BZIMAGE" "$INSTALL_DIR/bzImage"
        echo ""
        echo "=== Kernel installed ==="
        echo "  bzImage:  $INSTALL_DIR/bzImage"
        echo "  Version:  $KERNEL_VERSION"
        ls -lh "$INSTALL_DIR/bzImage"
    fi
fi

if echo "$BUILD_TARGETS" | grep -q 'modules'; then
    MODULES_DIR="$INSTALL_DIR/modules"
    echo "--- Installing modules to $MODULES_DIR ---"
    make -C "$LINUX_DIR" -j"$JOBS" modules_install INSTALL_MOD_PATH="$MODULES_DIR"
    echo "  Modules:  $MODULES_DIR"
fi

echo ""
echo "Done."
