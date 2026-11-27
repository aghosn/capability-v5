#!/usr/bin/env bash
# Generate shared C constants from Rust; optionally update a Linux checkout.
# Usage: bash themis/scripts/generate-abi-header.sh [--check] [LINUX_DIR]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARGS=()
if [[ "${1:-}" == "--check" ]]; then
    ARGS+=(--check)
    shift
fi
if [[ $# -gt 1 || "${1:-}" == -* ]]; then
    echo "Usage: $0 [--check] [LINUX_DIR]" >&2
    exit 1
fi
ARGS+=("$REPO_ROOT/thhv/inc/themis_abi.h")
if [[ $# -eq 1 ]]; then
    if [[ ! -d "$1/include/linux" ]]; then
        echo "ERROR: Linux include directory not found: $1/include/linux" >&2
        exit 1
    fi
    ARGS+=("$1/include/linux/themis_abi.h")
fi
HOST="$(rustc -vV | sed -n 's/^host: //p')"
cargo run --quiet --manifest-path "$REPO_ROOT/themis/Cargo.toml" \
    --target "$HOST" -p themis-abi --example export_c_header -- "${ARGS[@]}"
