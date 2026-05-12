#!/usr/bin/env bash
# update-bins.sh — Copy build artifacts into guest/bins.img without root.
#
# Usage:
#   bash themis/scripts/update-bins.sh
#   PROFILE=release bash themis/scripts/update-bins.sh
#   BINS_TARGETS=thhv,chv bash themis/scripts/update-bins.sh
#   NESTED_KERNEL=path/to/bzImage bash themis/scripts/update-bins.sh
#
# Mounts guest/bins.img via fuse2fs, copies any build artifacts that are
# present, refreshes version.txt, then unmounts and cleans up. Missing
# artifacts are skipped with warnings so partial builds can still be packaged.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$WORKSPACE_ROOT/.." && pwd)"
BINS_IMG="$WORKSPACE_ROOT/guest/bins.img"
PROFILE="${PROFILE:-release}"
BINS_TARGETS="${BINS_TARGETS:-all}"
NESTED_KERNEL="${NESTED_KERNEL:-}"
NESTED_ROOTFS="${NESTED_ROOTFS:-}"

# Auto-detect CoCo kernel if NESTED_KERNEL not explicitly set
if [[ -z "$NESTED_KERNEL" && -f "$WORKSPACE_ROOT/guest/kernel/bzImage" ]]; then
    NESTED_KERNEL="$WORKSPACE_ROOT/guest/kernel/bzImage"
fi
MNT=""
MOUNTED=false

need() {
    if ! command -v "$1" &>/dev/null; then
        echo "ERROR: '$1' not found. Install: $2" >&2
        exit 1
    fi
}

warn_missing() {
    echo "WARNING: $1 not found; skipping." >&2
}

cleanup() {
    if [[ "$MOUNTED" == true && -n "$MNT" ]] && mountpoint -q "$MNT" 2>/dev/null; then
        fusermount -u "$MNT" 2>/dev/null || true
    fi
    if [[ -n "$MNT" && -d "$MNT" ]]; then
        rm -rf "$MNT"
    fi
}
trap cleanup EXIT

should_package() {
    local want="$1"
    local raw=""
    local normalized=""
    local -a package_targets=()

    if [[ "$BINS_TARGETS" == "all" ]]; then
        return 0
    fi

    IFS=',' read -r -a package_targets <<< "$BINS_TARGETS"
    for raw in "${package_targets[@]}"; do
        normalized="${raw//[[:space:]]/}"
        normalized="${normalized,,}"
        case "$want:$normalized" in
            chv:chv|chv:cloud-hypervisor|cloud-hypervisor:chv|cloud-hypervisor:cloud-hypervisor)
                return 0
                ;;
            *)
                if [[ "$want" == "$normalized" ]]; then
                    return 0
                fi
                ;;
        esac
    done

    return 1
}

copy_capa-engine_tests() {
    local cargo_toml="$REPO_ROOT/capa-engine/Cargo.toml"
    local deps_dir="$REPO_ROOT/capa-engine/target/$PROFILE/deps"
    local test_name=""
    local candidate=""
    local copied=0

    [[ -f "$cargo_toml" && -d "$deps_dir" ]] || return 0

    while IFS= read -r test_name; do
        shopt -s nullglob
        for candidate in "$deps_dir/${test_name}-"*; do
            if [[ -f "$candidate" && -x "$candidate" ]]; then
                cp "$candidate" "$MNT/capa-engine/tests/"
                copied=1
            fi
        done
        shopt -u nullglob
    done < <(
        awk '
            /^\[\[test\]\]/ { in_test = 1; next }
            /^\[\[/ { in_test = 0 }
            in_test && $1 == "name" {
                gsub(/"/, "", $3)
                print $3
            }
        ' "$cargo_toml"
    )

    return 0
}

need fuse2fs    "sudo apt install fuse2fs e2fsprogs"
need fusermount "sudo apt install fuse3"
need git        "sudo apt install git"

if [[ ! -f "$BINS_IMG" ]]; then
    echo "ERROR: bins image not found: $BINS_IMG" >&2
    echo "       Remediation: run bash themis/scripts/create-bins.sh first." >&2
    exit 1
fi

MNT="$(mktemp -d)"
fuse2fs -o fakeroot "$BINS_IMG" "$MNT" >/dev/null 2>&1
MOUNTED=true

for _ in {1..50}; do
    if mountpoint -q "$MNT" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if ! mountpoint -q "$MNT" 2>/dev/null; then
    echo "ERROR: failed to mount $BINS_IMG with fuse2fs" >&2
    echo "       Remediation: ensure FUSE is available, then retry." >&2
    exit 1
fi

mkdir -p \
    "$MNT/thhv/tests" \
    "$MNT/cloud-hypervisor" \
    "$MNT/capa-engine/tests" \
    "$MNT/nested"

# ── README ───────────────────────────────────────────────────────────────────
cat > "$MNT/README.md" <<'EOF'
# Themis bins

This partition contains pre-built binaries and guest images for the Themis project.

## Boot dom1 (nested VM)

From inside dom0:

```bash
# First boot (cloud-init provisioning):
SEED_DOM1=1 sudo /opt/bins/cloud-hypervisor/run-dom1.sh

# Subsequent boots:
sudo /opt/bins/cloud-hypervisor/run-dom1.sh
```

Login: `cloud` / `cloud123`

## Contents

| Path | Description |
|------|-------------|
| `cloud-hypervisor/cloud-hypervisor` | Cloud Hypervisor VMM binary |
| `cloud-hypervisor/run-dom1.sh` | Script to boot dom1 |
| `dom1/dom1.raw` | Dom1 root disk (Ubuntu Noble, raw) |
| `dom1/hypervisor-fw` | Rust Hypervisor Firmware |
| `dom1/dom1-seed.img` | Dom1 cloud-init seed (first boot) |
| `thhv/thhv.ko` | Themis kernel module |
| `thhv/tests/` | Themis unit tests |
| `capa-engine/` | Capability engine binaries and tests |
| `nested/` | Nested kernel / rootfs (if built) |
EOF

THHV_KO="$REPO_ROOT/thhv/thhv.ko"
THHV_TEST_DIR="$REPO_ROOT/thhv/test/bin"
CHV_BIN="$REPO_ROOT/cloud-hypervisor/target/$PROFILE/cloud-hypervisor"
CAPENG_BIN="$REPO_ROOT/capa-engine/target/$PROFILE/capa-engine"

if should_package thhv; then
    if [[ -f "$THHV_KO" ]]; then
        cp "$THHV_KO" "$MNT/thhv/thhv.ko"
    else
        warn_missing "$THHV_KO"
    fi

    shopt -s nullglob
    TEST_BINS=("$THHV_TEST_DIR"/*)
    if (( ${#TEST_BINS[@]} > 0 )); then
        cp "${TEST_BINS[@]}" "$MNT/thhv/tests/"
    else
        warn_missing "$THHV_TEST_DIR/*"
    fi
    shopt -u nullglob
fi

if should_package chv; then
    if [[ -f "$CHV_BIN" ]]; then
        cp "$CHV_BIN" "$MNT/cloud-hypervisor/cloud-hypervisor"
    else
        warn_missing "$CHV_BIN"
    fi
    # Always package run-dom1.sh alongside the binary.
    cp "$SCRIPT_DIR/run-dom1.sh" "$MNT/cloud-hypervisor/run-dom1.sh"
    chmod +x "$MNT/cloud-hypervisor/run-dom1.sh"
fi

# ── Dom1 guest image ──────────────────────────────────────────────────────────
DOM1_IMG="$WORKSPACE_ROOT/guest/dom1.raw"
DOM1_HVF="$WORKSPACE_ROOT/guest/hypervisor-fw"
if [[ -f "$DOM1_IMG" ]]; then
    mkdir -p "$MNT/dom1"
    cp "$DOM1_IMG" "$MNT/dom1/dom1.raw"
    [[ -f "$DOM1_HVF" ]] && cp "$DOM1_HVF" "$MNT/dom1/hypervisor-fw"
    echo "  ✔ dom1/dom1.raw + hypervisor-fw packed into bins"
fi

if should_package capa-engine; then
    if [[ -f "$CAPENG_BIN" ]]; then
        cp "$CAPENG_BIN" "$MNT/capa-engine/capa-engine"
    else
        warn_missing "$CAPENG_BIN"
    fi
    copy_capa-engine_tests
fi

if [[ -n "$NESTED_KERNEL" ]]; then
    if [[ -f "$NESTED_KERNEL" ]]; then
        cp "$NESTED_KERNEL" "$MNT/nested/bzImage"
        echo "  ✔ nested/bzImage"
    else
        warn_missing "$NESTED_KERNEL"
    fi
fi

# Pack CoCo kernel modules alongside the kernel.
NESTED_MODULES="${NESTED_MODULES:-$WORKSPACE_ROOT/guest/kernel/modules}"
if [[ -d "$NESTED_MODULES/lib/modules" ]]; then
    mkdir -p "$MNT/nested/modules/lib"
    cp -a "$NESTED_MODULES/lib/modules" "$MNT/nested/modules/lib/"
    # Remove build/source symlinks (point to host paths, broken in guest)
    find "$MNT/nested/modules" -name build -type l -delete 2>/dev/null || true
    find "$MNT/nested/modules" -name source -type l -delete 2>/dev/null || true
    echo "  ✔ nested/modules"
fi

if [[ -n "$NESTED_ROOTFS" ]]; then
    if [[ -f "$NESTED_ROOTFS" ]]; then
        cp "$NESTED_ROOTFS" "$MNT/nested/rootfs.img"
    else
        warn_missing "$NESTED_ROOTFS"
    fi
fi

GIT_REV="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "$MNT/version.txt" <<META
rev: ${GIT_REV}
timestamp: ${TIMESTAMP}
profile: ${PROFILE}
nested_kernel: ${NESTED_KERNEL:-none}
nested_rootfs: ${NESTED_ROOTFS:-none}
META

fusermount -u "$MNT"
MOUNTED=false
rm -rf "$MNT"
MNT=""

echo "✔ Updated guest/bins.img"
