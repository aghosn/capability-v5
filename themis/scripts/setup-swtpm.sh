#!/usr/bin/env bash
# setup-swtpm.sh — Start a swtpm instance for QEMU TPM 2.0 emulation.
#
# Usage:
#   bash scripts/setup-swtpm.sh          # start swtpm (idempotent)
#   bash scripts/setup-swtpm.sh --stop   # stop swtpm
#   bash scripts/setup-swtpm.sh --reset  # wipe state + restart
#
# The swtpm control socket is created at /tmp/themis-swtpm/swtpm-sock.
# QEMU's run-qemu.sh connects its chardev to this socket when QEMU_TPM=1.
# IMPORTANT: QEMU connects to the --ctrl socket, NOT --server.  Using a
# separate --server socket causes QEMU to deadlock during TPM init.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Version gate: swtpm 0.7.x deadlocks with QEMU 8.x + OVMF ────────────
MIN_MAJOR=0; MIN_MINOR=8
_ver=$(swtpm --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1 || echo "0.0.0")
_maj=$(echo "$_ver" | cut -d. -f1); _min=$(echo "$_ver" | cut -d. -f2)
if [[ "$_maj" -lt "$MIN_MAJOR" ]] || { [[ "$_maj" -eq "$MIN_MAJOR" ]] && [[ "$_min" -lt "$MIN_MINOR" ]]; }; then
    echo "ERROR: swtpm $_ver is too old (need ≥ ${MIN_MAJOR}.${MIN_MINOR})." >&2
    echo "       Version 0.7.x deadlocks with QEMU 8.x + OVMF." >&2
    echo "       Upgrade:  bash scripts/install-swtpm.sh" >&2
    exit 1
fi

SWTPM_DIR="/tmp/themis-swtpm"
SWTPM_SOCK="$SWTPM_DIR/swtpm-sock"
SWTPM_STATE="$SWTPM_DIR/state"
SWTPM_PID="$SWTPM_DIR/swtpm.pid"

stop_swtpm() {
    if [[ -f "$SWTPM_PID" ]]; then
        local pid
        pid=$(cat "$SWTPM_PID" 2>/dev/null || true)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            echo "→ Stopping swtpm (PID $pid)"
            kill "$pid" 2>/dev/null || true
            # Wait briefly for clean shutdown
            for _ in $(seq 1 10); do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.1
            done
        fi
        rm -f "$SWTPM_PID"
    fi
    rm -f "$SWTPM_SOCK"
}

case "${1:-}" in
    --stop)
        stop_swtpm
        echo "✓ swtpm stopped"
        exit 0
        ;;
    --reset)
        stop_swtpm
        rm -rf "$SWTPM_STATE"
        echo "→ swtpm state wiped"
        ;; # fall through to start
esac

# Check if already running
if [[ -f "$SWTPM_PID" ]]; then
    pid=$(cat "$SWTPM_PID" 2>/dev/null || true)
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        echo "✓ swtpm already running (PID $pid)"
        echo "  socket: $SWTPM_SOCK"
        exit 0
    fi
    # Stale PID file
    rm -f "$SWTPM_PID" "$SWTPM_SOCK"
fi

# Check swtpm is installed
if ! command -v swtpm &>/dev/null; then
    echo "ERROR: swtpm not found. Install with:"
    echo "  bash scripts/install-swtpm.sh"
    exit 1
fi

mkdir -p "$SWTPM_STATE"

echo "→ Starting swtpm (TPM 2.0 emulator)"
# QEMU's tpm_emulator backend connects to the --ctrl socket and uses the
# PTM protocol for both control and TPM commands.  Do NOT add a separate
# --server socket — that causes QEMU to connect to the wrong endpoint and
# deadlock.  Do NOT add --flags startup-clear — the firmware (SeaBIOS/OVMF)
# sends TPM2_Startup itself.
swtpm socket --tpm2 \
    --tpmstate "dir=$SWTPM_STATE" \
    --ctrl "type=unixio,path=$SWTPM_SOCK" \
    --daemon \
    --pid "file=$SWTPM_PID"

# Wait for socket to appear
for _ in $(seq 1 20); do
    [[ -S "$SWTPM_SOCK" ]] && break
    sleep 0.1
done

if [[ ! -S "$SWTPM_SOCK" ]]; then
    echo "ERROR: swtpm socket did not appear at $SWTPM_SOCK"
    exit 1
fi

echo "✓ swtpm running (PID $(cat "$SWTPM_PID"))"
echo "  socket: $SWTPM_SOCK"
echo "  state:  $SWTPM_STATE"
echo ""
echo "  To use with QEMU:  QEMU_TPM=1 cargo themis"
