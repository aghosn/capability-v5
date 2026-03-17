#!/usr/bin/env bash
# build-bins.sh — Build requested Themis/dom0 artifacts and refresh guest/bins.img.
#
# Usage:
#   bash themis/scripts/build-bins.sh
#   PROFILE=release bash themis/scripts/build-bins.sh
#   BINS_TARGETS=thhv,chv,2026 bash themis/scripts/build-bins.sh
#   KHEADERS_DIR=/path/to/linux-headers bash themis/scripts/build-bins.sh
#
# Environment knobs:
#   PROFILE       debug | release (default: debug)
#   BINS_TARGETS  all | comma-separated subset of: capavisor,chv,2026,thhv
#   KHEADERS_DIR  explicit kernel headers tree for thhv.ko builds

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$WORKSPACE_ROOT/.." && pwd)"
BINS_IMG="$WORKSPACE_ROOT/guest/bins.img"
PROFILE="${PROFILE:-debug}"
BINS_TARGETS="${BINS_TARGETS:-all}"
KHEADERS_DIR="${KHEADERS_DIR:-}"

usage() {
    cat <<USAGE
Usage:
  bash themis/scripts/build-bins.sh
  PROFILE=release bash themis/scripts/build-bins.sh
  BINS_TARGETS=thhv,chv,2026 bash themis/scripts/build-bins.sh
  KHEADERS_DIR=/path/to/linux-headers bash themis/scripts/build-bins.sh
USAGE
}

need() {
    if ! command -v "$1" &>/dev/null; then
        echo "ERROR: '$1' not found. Install: $2" >&2
        exit 1
    fi
}

warn() {
    echo "WARNING: $*" >&2
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

case "$PROFILE" in
    debug|release) ;;
    *)
        echo "ERROR: unsupported PROFILE='$PROFILE' (expected debug or release)" >&2
        exit 1
        ;;
esac

need cargo "install Rust via rustup"
need make  "sudo apt install build-essential"
need bash  "sudo apt install bash"

CARGO_BUILD_ARGS=(build)
if [[ "$PROFILE" == "release" ]]; then
    CARGO_BUILD_ARGS+=(--release)
fi

SELECTED_TARGETS=()
if [[ "$BINS_TARGETS" != "all" ]]; then
    IFS=',' read -r -a _raw_targets <<< "$BINS_TARGETS"
    for _raw in "${_raw_targets[@]}"; do
        _target="${_raw//[[:space:]]/}"
        _target="${_target,,}"
        [[ -z "$_target" ]] && continue
        case "$_target" in
            capavisor|chv|cloud-hypervisor|2026|thhv)
                SELECTED_TARGETS+=("$_target")
                ;;
            *)
                echo "ERROR: unknown BINS_TARGETS entry '$_raw'" >&2
                echo "       Supported values: all, capavisor, chv, 2026, thhv" >&2
                exit 1
                ;;
        esac
    done

    if (( ${#SELECTED_TARGETS[@]} == 0 )); then
        echo "ERROR: BINS_TARGETS did not contain any valid targets" >&2
        exit 1
    fi
fi

should_build() {
    local want="$1"
    local target

    if [[ "$BINS_TARGETS" == "all" ]]; then
        return 0
    fi

    for target in "${SELECTED_TARGETS[@]}"; do
        case "$want:$target" in
            chv:chv|chv:cloud-hypervisor|cloud-hypervisor:chv|cloud-hypervisor:cloud-hypervisor)
                return 0
                ;;
            *)
                if [[ "$want" == "$target" ]]; then
                    return 0
                fi
                ;;
        esac
    done

    return 1
}

resolve_kheaders_dir() {
    local candidate_glob=("$WORKSPACE_ROOT/target/kheaders/usr/src/linux-headers-"*-generic)

    if [[ -n "$KHEADERS_DIR" ]]; then
        if [[ ! -d "$KHEADERS_DIR" || ! -f "$KHEADERS_DIR/Makefile" ]]; then
            echo "ERROR: KHEADERS_DIR is not a kernel headers tree: $KHEADERS_DIR" >&2
            exit 1
        fi
        printf '%s\n' "$KHEADERS_DIR"
        return 0
    fi

    if (( ${#candidate_glob[@]} > 0 )) && [[ -d "${candidate_glob[0]}" ]]; then
        printf '%s\n' "${candidate_glob[0]}"
        return 0
    fi

    return 1
}

echo "→ build-bins: PROFILE=$PROFILE BINS_TARGETS=$BINS_TARGETS"

if should_build capavisor; then
    echo "→ [capavisor] cargo ${CARGO_BUILD_ARGS[*]} -p capavisor"
    (
        cd "$WORKSPACE_ROOT"
        cargo "${CARGO_BUILD_ARGS[@]}" -p capavisor
    )
else
    echo "→ [capavisor] skipped"
fi

if should_build chv; then
    echo "→ [cloud-hypervisor] cargo ${CARGO_BUILD_ARGS[*]} --features themis"
    (
        cd "$REPO_ROOT/cloud-hypervisor"
        cargo "${CARGO_BUILD_ARGS[@]}" --features themis
    )
else
    echo "→ [cloud-hypervisor] skipped"
fi

if should_build 2026; then
    echo "→ [2026] cargo ${CARGO_BUILD_ARGS[*]}"
    (
        cd "$REPO_ROOT/2026"
        cargo "${CARGO_BUILD_ARGS[@]}"
    )
else
    echo "→ [2026] skipped"
fi

if should_build thhv; then
    if KDIR="$(resolve_kheaders_dir)"; then
        echo "→ [thhv] make -C thhv KDIR=$KDIR"
        make -C "$REPO_ROOT/thhv" KDIR="$KDIR"

        echo "→ [thhv tests] make -C thhv tests"
        make -C "$REPO_ROOT/thhv" tests
    else
        warn "No kernel headers found under themis/target/kheaders/ and KHEADERS_DIR not set; skipping thhv build."
        warn "Run: bash themis/scripts/fetch-kheaders.sh"
    fi
else
    echo "→ [thhv] skipped"
fi

if [[ ! -f "$BINS_IMG" ]]; then
    echo "→ bins.img missing; creating it first"
    bash "$SCRIPT_DIR/create-bins.sh"
fi

echo "→ Refreshing guest/bins.img"
PROFILE="$PROFILE" BINS_TARGETS="$BINS_TARGETS" bash "$SCRIPT_DIR/update-bins.sh"

echo "✔ build-bins complete"
