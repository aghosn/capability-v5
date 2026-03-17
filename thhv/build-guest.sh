#!/usr/bin/env bash
# Build thhv.ko against kernel headers from a prefetched headers tree or a
# dom0 guest disk image.
#
# Usage:
#   KHEADERS_DIR=/path/to/linux-headers bash thhv/build-guest.sh
#   bash themis/scripts/fetch-kheaders.sh && bash thhv/build-guest.sh
#   sudo bash build-guest.sh guest/jammy-server-*.img
#   sudo DOM0_VERSION=noble bash build-guest.sh
#
# The script prefers KHEADERS_DIR or extracted headers in themis/target/
# kheaders/. If neither is available it falls back to mounting the dom0 disk,
# finding the kernel headers there, building the module, optionally copying
# thhv.ko onto the disk, then unmounting.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
THEMIS_SCRIPTS="$WORKSPACE_ROOT/themis/scripts"
MNT="/tmp/mnt"
COPY_TO_GUEST="${COPY_TO_GUEST:-}"   # set to a path (e.g. /root/) to copy .ko
DISK=""
HEADERS_DIR=""
HEADERS_SOURCE=""
MOUNTED_BY_US=false

validate_headers_dir() {
    local dir="$1"
    [[ -d "$dir" && -f "$dir/Makefile" ]]
}

candidate_headers_dir_from_kver() {
    local kver_file="$THEMIS_SCRIPTS/dom0-kernel-version.txt"
    local kver

    [[ -f "$kver_file" ]] || return 1
    kver="$(tr -d '[:space:]' < "$kver_file")"
    [[ -n "$kver" ]] || return 1

    if [[ "$kver" == *-generic ]]; then
        printf '%s\n' "$WORKSPACE_ROOT/themis/target/kheaders/usr/src/linux-headers-${kver}"
    else
        printf '%s\n' "$WORKSPACE_ROOT/themis/target/kheaders/usr/src/linux-headers-${kver}-generic"
    fi
}

resolve_disk() {
    if [[ -n "$DISK" ]]; then
        return
    fi

    if [[ -n "${1:-}" ]]; then
        DISK="$1"
    else
        source "$THEMIS_SCRIPTS/dom0-lib.sh"
        GUEST_DIR="$(cd "$WORKSPACE_ROOT/themis/guest" 2>/dev/null && pwd)" || true
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
}

ensure_guest_mounted() {
    if mountpoint -q "$MNT" 2>/dev/null; then
        echo "  (guest already mounted at $MNT)"
        return
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        echo "ERROR: guest mount required but not running as root." >&2
        echo "       Preferred no-sudo path: bash themis/scripts/fetch-kheaders.sh" >&2
        echo "       Then rerun:             bash thhv/build-guest.sh" >&2
        echo "       Or mount first:         sudo bash themis/scripts/mount-guest.sh" >&2
        echo "       Or run with sudo:       sudo bash thhv/build-guest.sh" >&2
        exit 1
    fi

    resolve_disk "${1:-}"
    echo "→ Disk: $(basename "$DISK")"
    bash "$THEMIS_SCRIPTS/mount-guest.sh" "$DISK"
    MOUNTED_BY_US=true
}

cleanup() {
    if [[ "$MOUNTED_BY_US" == true ]]; then
        echo "→ Unmounting..."
        bash "$THEMIS_SCRIPTS/umount-guest.sh" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ── Resolve kernel headers ─────────────────────────────────────────────────── #

if [[ -n "${KHEADERS_DIR:-}" ]]; then
    if ! validate_headers_dir "$KHEADERS_DIR"; then
        echo "ERROR: KHEADERS_DIR does not point to a valid kernel headers tree: $KHEADERS_DIR" >&2
        echo "       Expected to find a Makefile there." >&2
        exit 1
    fi
    HEADERS_DIR="$KHEADERS_DIR"
    HEADERS_SOURCE="KHEADERS_DIR override"
else
    if _candidate=$(candidate_headers_dir_from_kver) && validate_headers_dir "$_candidate"; then
        HEADERS_DIR="$_candidate"
        HEADERS_SOURCE="prefetched headers (pinned dom0 kernel)"
    else
        for d in "$WORKSPACE_ROOT"/themis/target/kheaders/usr/src/linux-headers-*-generic; do
            if validate_headers_dir "$d"; then
                HEADERS_DIR="$d"
                HEADERS_SOURCE="prefetched headers"
                break
            fi
        done
    fi
fi

if [[ -z "$HEADERS_DIR" ]]; then
    ensure_guest_mounted "${1:-}"

    for d in "$MNT"/usr/src/linux-headers-*-generic; do
        if validate_headers_dir "$d"; then
            HEADERS_DIR="$d"
            HEADERS_SOURCE="mounted dom0 guest"
            break
        fi
    done

    if [[ -z "$HEADERS_DIR" ]]; then
        echo "ERROR: no kernel headers found in $MNT/usr/src/" >&2
        echo "       Install them in the guest: apt install linux-headers-generic" >&2
        echo "       Or fetch them on the host: bash themis/scripts/fetch-kheaders.sh" >&2
        exit 1
    fi
fi

KVER=$(basename "$HEADERS_DIR" | sed 's/^linux-headers-//')
echo "→ Using kernel headers from $HEADERS_SOURCE"
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
    ensure_guest_mounted "${1:-}"

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
