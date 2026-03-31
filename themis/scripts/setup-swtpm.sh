#!/usr/bin/env bash
# setup-swtpm.sh — Start a swtpm instance for QEMU TPM 2.0 emulation.
#
# Usage:
#   bash scripts/setup-swtpm.sh          # start swtpm (idempotent)
#   bash scripts/setup-swtpm.sh --stop   # stop swtpm
#   bash scripts/setup-swtpm.sh --reset  # wipe state + restart
#
# The swtpm socket is created at /tmp/themis-swtpm/swtpm.sock.
# QEMU's run-qemu.sh picks it up when QEMU_TPM=1 is set.

set -euo pipefail

SWTPM_DIR="/tmp/themis-swtpm"
SWTPM_SOCK="$SWTPM_DIR/swtpm.sock"
SWTPM_CTRL="$SWTPM_DIR/swtpm.ctrl"
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
    rm -f "$SWTPM_SOCK" "$SWTPM_CTRL"
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
    rm -f "$SWTPM_PID" "$SWTPM_SOCK" "$SWTPM_CTRL"
fi

# Check swtpm is installed
if ! command -v swtpm &>/dev/null; then
    echo "ERROR: swtpm not found. Install with:"
    echo "  sudo apt install swtpm swtpm-tools"
    exit 1
fi

mkdir -p "$SWTPM_STATE"

echo "→ Starting swtpm (TPM 2.0 emulator)"
swtpm socket --tpm2 \
    --server "type=unixio,path=$SWTPM_SOCK" \
    --ctrl "type=unixio,path=$SWTPM_CTRL" \
    --tpmstate "dir=$SWTPM_STATE" \
    --flags not-need-init,startup-clear \
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
