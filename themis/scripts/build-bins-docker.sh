#!/usr/bin/env bash
# build-bins-docker.sh — Run build-bins.sh inside the themis-build container.
#
# Usage:
#   bash themis/scripts/build-bins-docker.sh
#   PROFILE=release bash themis/scripts/build-bins-docker.sh
#   BINS_TARGETS=chv,2026 bash themis/scripts/build-bins-docker.sh
#
# Passes PROFILE, BINS_TARGETS, and KHEADERS_DIR through to the container.
# The themis-build image should contain the native build prerequisites already.
# For interactive troubleshooting inside the container, fetch-kheaders.sh can use
# apt-get directly there without depending on the host package set.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(git -C "$WORKSPACE_ROOT" rev-parse --show-toplevel)"
PROFILE="${PROFILE:-debug}"
BINS_TARGETS="${BINS_TARGETS:-all}"
KHEADERS_DIR="${KHEADERS_DIR:-}"
IMAGE="themis-build:latest"

usage() {
    cat <<USAGE
Usage:
  bash themis/scripts/build-bins-docker.sh
  PROFILE=release bash themis/scripts/build-bins-docker.sh
  BINS_TARGETS=chv,2026 bash themis/scripts/build-bins-docker.sh
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

if ! command -v docker &>/dev/null; then
    echo "ERROR: docker not found on PATH." >&2
    echo "       Install Docker, then retry." >&2
    exit 1
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "ERROR: Docker image '$IMAGE' not found." >&2
    echo "       Build it first with:" >&2
    echo "       docker build -f Dockerfile.build -t themis-build:latest ." >&2
    exit 1
fi

echo "→ Running build-bins inside $IMAGE"
exec docker run --rm \
    -v "$REPO_ROOT":/workspace \
    -v /etc/passwd:/etc/passwd:ro \
    -v /etc/group:/etc/group:ro \
    -w /workspace \
    --user "$(id -u):$(id -g)" \
    --device /dev/fuse \
    --cap-add SYS_ADMIN \
    --security-opt apparmor:unconfined \
    --env PATH="/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    --env CARGO_HOME="/usr/local/cargo" \
    --env RUSTUP_HOME="/usr/local/rustup" \
    --env PROFILE="$PROFILE" \
    --env BINS_TARGETS="$BINS_TARGETS" \
    --env KHEADERS_DIR="$KHEADERS_DIR" \
    "$IMAGE" \
    bash themis/scripts/build-bins.sh "$@"
