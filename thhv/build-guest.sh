#!/usr/bin/env bash
# Build thhv.ko against kernel headers from a dom0 guest disk image.
#
# Usage:
#   sudo bash build-guest.sh                               # auto-detect disk
#   sudo bash build-guest.sh guest/jammy-server-*.img      # explicit disk path
#   sudo DOM0_VERSION=noble bash build-guest.sh            # by version name
#
# The script mounts the disk, finds the kernel headers, builds the module,
# optionally copies thhv.ko onto the disk, then unmounts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
THEMIS_SCRIPTS="$SCRIPT_DIR/../themis/scripts"
MNT="/tmp/mnt"
COPY_TO_GUEST="${COPY_TO_GUEST:-}"   # set to a path (e.g. /root/) to copy .ko

# ── Resolve disk image path ───────────────────────────────────────────────── #

if [[ -n "${1:-}" ]]; then
    DISK="$1"
else
    source "$THEMIS_SCRIPTS/dom0-lib.sh"
    GUEST_DIR="$(cd "$SCRIPT_DIR/../themis/guest" 2>/dev/null && pwd)" || true
    if [[ -z "$GUEST_DIR" || ! -d "$GUEST_DIR" ]]; then
        echo "ERROR: no dom0 disk found in themis/guest/. Run: cargo fetch-dom0" >&2
        exit 1
    fi
    if [[ -n "${DOM0_VERSION:-}" ]]; then
        dom0_select "$DOM0_VERSION"
    elif _detected=$(dom0_detect_from_guest_dir "$GUEST_DIR"); then
        dom0_select "$_detected"
    else
        echo "ERROR: no dom0 disk found in themis/guest/. Run: cargo fetch-dom0" >&2
        exit 1
    fi
    DISK="$GUEST_DIR/$DOM0_IMAGE_NAME"
fi

if [[ ! -f "$DISK" ]]; then
    echo "ERROR: disk image not found: $DISK" >&2
    exit 1
fi

echo "→ Disk: $(basename "$DISK")"

# ── Mount ──────────────────────────────────────────────────────────────────── #

already_mounted=false
if mountpoint -q "$MNT" 2>/dev/null; then
    echo "  (already mounted at $MNT)"
    already_mounted=true
else
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "ERROR: disk not mounted and not running as root." >&2
        echo "       Either mount first:  sudo bash themis/scripts/mount-guest.sh" >&2
        echo "       Or run with sudo:    sudo bash thhv/build-guest.sh" >&2
        exit 1
    fi
    bash "$THEMIS_SCRIPTS/mount-guest.sh" "$DISK"
fi

# Ensure we unmount on exit (unless it was already mounted before we started).
cleanup() {
    if [[ "$already_mounted" == false ]]; then
        echo "→ Unmounting..."
        bash "$THEMIS_SCRIPTS/umount-guest.sh" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ── Find kernel headers ───────────────────────────────────────────────────── #

HEADERS_DIR=""
for d in "$MNT"/usr/src/linux-headers-*-generic; do
    if [[ -d "$d" && -f "$d/Makefile" ]]; then
        HEADERS_DIR="$d"
        break
    fi
done

if [[ -z "$HEADERS_DIR" ]]; then
    echo "ERROR: no kernel headers found in $MNT/usr/src/" >&2
    echo "       Install them in the guest: apt install linux-headers-generic" >&2
    exit 1
fi

KVER=$(basename "$HEADERS_DIR" | sed 's/^linux-headers-//')
echo "→ Kernel headers: $KVER"
echo "→ Headers path:   $HEADERS_DIR"

# ── Build thhv.ko ─────────────────────────────────────────────────────────── #

# Clean stale objects from previous builds (possibly against a different kernel).
rm -f "$SCRIPT_DIR"/src/*.o "$SCRIPT_DIR"/*.o "$SCRIPT_DIR"/*.ko \
      "$SCRIPT_DIR"/*.mod* "$SCRIPT_DIR"/Module.symvers \
      "$SCRIPT_DIR"/modules.order 2>/dev/null
find "$SCRIPT_DIR" -name '.*.cmd' -delete 2>/dev/null

echo "→ Building thhv.ko..."
make -C "$HEADERS_DIR" M="$SCRIPT_DIR" modules 2>&1 | \
    grep -v '^warning: the compiler differs' | \
    grep -v 'unexpected non-allocatable section' | \
    grep -v 'Did you forget to use' | \
    grep -v 'section definitions for use' | \
    grep -v 'Note that for example' | \
    grep -v '^$' | \
    grep -v 'Skipping BTF generation' | \
    grep -v '^make.*Entering\|^make.*Leaving'

if [[ ! -f "$SCRIPT_DIR/thhv.ko" ]]; then
    echo "ERROR: build failed — thhv.ko not produced" >&2
    exit 1
fi

# Clean intermediate objects, keep only thhv.ko.
rm -f "$SCRIPT_DIR"/src/*.o "$SCRIPT_DIR"/thhv.o "$SCRIPT_DIR"/thhv.mod.o \
      "$SCRIPT_DIR"/thhv.mod.c "$SCRIPT_DIR"/thhv.mod \
      "$SCRIPT_DIR"/Module.symvers "$SCRIPT_DIR"/modules.order
find "$SCRIPT_DIR" -name '.*.cmd' -delete 2>/dev/null

echo "→ Built: thhv.ko ($(du -h "$SCRIPT_DIR/thhv.ko" | cut -f1))"

# ── Optionally copy to guest disk ──────────────────────────────────────────── #

if [[ -n "$COPY_TO_GUEST" ]]; then
    DEST="$MNT/$COPY_TO_GUEST"
    mkdir -p "$DEST"
    cp "$SCRIPT_DIR/thhv.ko" "$DEST/thhv.ko"
    echo "→ Copied thhv.ko to guest:$COPY_TO_GUEST/thhv.ko"

    # Also rebuild and copy test binaries if the test source exists.
    TEST_BIN_DIR="$SCRIPT_DIR/test/bin"
    if [[ -d "$SCRIPT_DIR/test" ]]; then
        echo "→ Building test binaries..."
        make -C "$SCRIPT_DIR" tests
        TEST_DEST="$MNT/home/cloud/executables"
        mkdir -p "$TEST_DEST"
        for bin in "$TEST_BIN_DIR"/*; do
            [[ -f "$bin" && -x "$bin" ]] || continue
            cp "$bin" "$TEST_DEST/"
            echo "→ Copied $(basename "$bin") to guest:~/executables/"
        done
        # Fix ownership so the cloud user can run them.
        chown -R 1000:1000 "$TEST_DEST" 2>/dev/null || true
    fi
fi

echo "✓ Done."
