#!/usr/bin/env bash
# install-swtpm.sh — Build and install swtpm ≥ 0.8 from source.
#
# Ubuntu 24.04's packaged swtpm (0.7.3) deadlocks with QEMU 8.x + OVMF
# during TPM CRB initialization.  This script builds libtpms and swtpm
# from pinned upstream tags, replacing the broken distro packages.
#
# Usage:
#   bash scripts/install-swtpm.sh           # build + install (needs sudo)
#   bash scripts/install-swtpm.sh --check   # just print version status
#
# Idempotent: skips the build if swtpm is already ≥ the pinned version.
# Works both on the host and inside Docker (where we already run as root).
#
# Pinned versions (known-good combination):
#   libtpms  v0.10.2  (2026-01-02)
#   swtpm    v0.10.1  (2025-04-30)

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────

LIBTPMS_REPO="https://github.com/stefanberger/libtpms.git"
LIBTPMS_TAG="v0.10.2"

SWTPM_REPO="https://github.com/stefanberger/swtpm.git"
SWTPM_TAG="v0.10.1"

MIN_MAJOR=0
MIN_MINOR=8

BUILD_DIR="/tmp/swtpm-build-$$"

# ── Helpers ────────────────────────────────────────────────────────────────

info()  { echo "→ $*"; }
ok()    { echo "✔ $*"; }
err()   { echo "ERROR: $*" >&2; }

# Parse "TPM emulator version X.Y.Z, ..." → "X.Y.Z"
swtpm_version() {
    local v
    v=$(swtpm --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1) || true
    echo "${v:-0.0.0}"
}

# Return 0 if $1 >= MIN_MAJOR.MIN_MINOR
version_ok() {
    local ver="$1"
    local major minor
    major=$(echo "$ver" | cut -d. -f1)
    minor=$(echo "$ver" | cut -d. -f2)
    [[ "$major" -gt "$MIN_MAJOR" ]] && return 0
    [[ "$major" -eq "$MIN_MAJOR" && "$minor" -ge "$MIN_MINOR" ]] && return 0
    return 1
}

need_cmd() {
    if ! command -v "$1" &>/dev/null; then
        err "'$1' not found.  Install: $2"
        exit 1
    fi
}

cleanup() {
    if [[ -d "$BUILD_DIR" ]]; then
        rm -rf "$BUILD_DIR"
    fi
}
trap cleanup EXIT

# ── Check-only mode ───────────────────────────────────────────────────────

if [[ "${1:-}" == "--check" ]]; then
    ver=$(swtpm_version)
    if version_ok "$ver"; then
        ok "swtpm $ver (≥ ${MIN_MAJOR}.${MIN_MINOR}) — OK"
        exit 0
    else
        err "swtpm $ver (< ${MIN_MAJOR}.${MIN_MINOR}) — needs upgrade"
        echo "  Run:  bash scripts/install-swtpm.sh"
        exit 1
    fi
fi

# ── Idempotency check ─────────────────────────────────────────────────────

CURRENT=$(swtpm_version)
if version_ok "$CURRENT"; then
    ok "swtpm $CURRENT already ≥ ${MIN_MAJOR}.${MIN_MINOR} — nothing to do"
    exit 0
fi

info "swtpm $CURRENT < ${MIN_MAJOR}.${MIN_MINOR} — building from source"
info "  libtpms: $LIBTPMS_TAG    swtpm: $SWTPM_TAG"

# ── Privilege check ───────────────────────────────────────────────────────

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
    SUDO="sudo"
    info "Not running as root — will use sudo for install steps"
fi

# ── Install build dependencies ────────────────────────────────────────────

info "Installing build dependencies..."
$SUDO apt-get update -qq
$SUDO apt-get install -y --no-install-recommends \
    autoconf automake build-essential ca-certificates dpkg-dev \
    expect gawk git gnutls-bin gnutls-dev libglib2.0-dev \
    libgmp-dev libjson-glib-dev libseccomp-dev libssl-dev \
    libtasn1-dev libtool libtool-bin pkg-config \
    python3-setuptools socat >/dev/null

# ── Remove conflicting distro packages ────────────────────────────────────
# The distro libtpms (0.9.x) installs to /lib/x86_64-linux-gnu/ and shadows
# our newly built one, causing symbol version errors at runtime.

if dpkg -l swtpm 2>/dev/null | grep -q '^ii'; then
    info "Removing distro swtpm packages (will be replaced by source build)..."
    $SUDO apt-get remove -y swtpm swtpm-tools swtpm-libs 2>/dev/null || true
fi
if dpkg -l libtpms0 2>/dev/null | grep -q '^ii'; then
    info "Removing distro libtpms0 (will be replaced by source build)..."
    $SUDO apt-get remove -y libtpms0 2>/dev/null || true
fi
$SUDO apt-get autoremove -y >/dev/null 2>&1 || true

# ── Ensure tss user exists (swtpm make install needs it) ──────────────────

if ! id tss &>/dev/null; then
    info "Creating tss system user..."
    $SUDO useradd --system --no-create-home --shell /usr/sbin/nologin tss
fi

# ── Build libtpms ─────────────────────────────────────────────────────────

mkdir -p "$BUILD_DIR"

info "Cloning libtpms ($LIBTPMS_TAG)..."
git clone --depth 1 --branch "$LIBTPMS_TAG" "$LIBTPMS_REPO" "$BUILD_DIR/libtpms" --quiet

info "Building libtpms..."
pushd "$BUILD_DIR/libtpms" >/dev/null
./autogen.sh --with-openssl --with-tpm2 --prefix=/usr >/dev/null 2>&1
make -j"$(nproc)" >/dev/null
$SUDO make install >/dev/null
$SUDO ldconfig
popd >/dev/null

ok "libtpms installed"

# ── Build swtpm ───────────────────────────────────────────────────────────

info "Cloning swtpm ($SWTPM_TAG)..."
git clone --depth 1 --branch "$SWTPM_TAG" "$SWTPM_REPO" "$BUILD_DIR/swtpm" --quiet

info "Building swtpm..."
pushd "$BUILD_DIR/swtpm" >/dev/null
./autogen.sh --with-openssl --prefix=/usr >/dev/null 2>&1
make -j"$(nproc)" >/dev/null
$SUDO make install >/dev/null
$SUDO ldconfig
popd >/dev/null

ok "swtpm installed"

# ── Verify ────────────────────────────────────────────────────────────────

INSTALLED=$(swtpm_version)
if version_ok "$INSTALLED"; then
    ok "swtpm $INSTALLED — ready for QEMU TPM 2.0 emulation"
else
    err "swtpm $INSTALLED — install succeeded but version still < ${MIN_MAJOR}.${MIN_MINOR}?"
    err "Check that /usr/bin/swtpm is the newly built binary (not the distro package)"
    exit 1
fi
