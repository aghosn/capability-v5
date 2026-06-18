#!/usr/bin/env bash
# run-qemu.sh — Build the ISO and boot Themis under QEMU.
#
# Usage:
#   cargo themis             # from workspace root via Cargo alias
#   bash scripts/run-qemu.sh
#
# Environment knobs:
#   PROFILE=release         build with --release (default: debug)
#   QEMU_CPUS=4             number of vCPUs (default: 4)
#   QEMU_MEM=4G             guest RAM (default: 4G)
#   QEMU_ENABLE_KVM=1       use KVM acceleration (default: 1 if available)
#   QEMU_BIOS=1             use legacy BIOS instead of UEFI (default: 0)
#   QEMU_NET=1              enable user-mode networking (default: 1)
#   QEMU_NET_FWD            extra port forwards (e.g. "hostfwd=tcp::8080-:8080")
#   QEMU_TPM=0              disable TPM 2.0 via swtpm (default: 1 = enabled)
#   QEMU_TIS=1              use TIS transport instead of CRB (requires QEMU_TPM=1)
#   QEMU_EXTRA_ARGS         additional arguments appended to the QEMU command

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Build ISO first
bash "$SCRIPT_DIR/build-iso.sh"

ISO="$WORKSPACE_ROOT/target/themis.iso"

QEMU_CPUS="${QEMU_CPUS:-4}"
QEMU_MEM="${QEMU_MEM:-4G}"

# Detect KVM availability
KVM_ARGS=""
if [[ "${QEMU_ENABLE_KVM:-1}" == "1" ]] && [[ -e /dev/kvm ]]; then
    KVM_ARGS="-enable-kvm -cpu host,+vmx,phys-bits=40"
else
    echo "WARNING: KVM not available — running without hardware acceleration"
    KVM_ARGS="-cpu qemu64,+vmx,phys-bits=40"
fi

# ── Firmware: UEFI (default) or legacy BIOS ─────────────────────────────────
FIRMWARE_ARGS=""
if [[ "${QEMU_BIOS:-0}" != "1" ]]; then
    OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
    OVMF_VARS_TEMPLATE="${OVMF_VARS_TEMPLATE:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
    OVMF_VARS="$WORKSPACE_ROOT/target/ovmf_vars.fd"
    if [[ -f "$OVMF_CODE" ]]; then
        # Create a per-workspace copy of the NVRAM template if missing.
        if [[ ! -f "$OVMF_VARS" ]] && [[ -f "$OVMF_VARS_TEMPLATE" ]]; then
            cp "$OVMF_VARS_TEMPLATE" "$OVMF_VARS"
        fi
        FIRMWARE_ARGS="-drive if=pflash,format=raw,readonly=on,file=$OVMF_CODE"
        if [[ -f "$OVMF_VARS" ]]; then
            FIRMWARE_ARGS+=" -drive if=pflash,format=raw,file=$OVMF_VARS"
        fi
    else
        echo "WARNING: OVMF not found at $OVMF_CODE — falling back to BIOS"
        echo "         Install: sudo apt install ovmf"
    fi
fi

echo "→ Booting $ISO (${QEMU_CPUS} CPUs, ${QEMU_MEM} RAM)"

# ── Optional dom0 disk ──────────────────────────────────────────────────────
# Present when scripts/fetch-dom0.sh has been run and image has been seeded.
# Must match the version used by build-iso.sh for Limine config consistency.
source "$SCRIPT_DIR/dom0-lib.sh"
DISK_ARGS=""
if [[ -n "${DOM0_VERSION:-}" ]]; then
    dom0_select "$DOM0_VERSION"
    if [[ -f "$WORKSPACE_ROOT/guest/$DOM0_IMAGE_NAME" ]]; then
        DISK_ARGS+="-drive id=dom0,file=$WORKSPACE_ROOT/guest/$DOM0_IMAGE_NAME,format=qcow2,if=none "
        DISK_ARGS+="-device virtio-blk-pci,drive=dom0 "
        echo "  + virtio disk: guest/$DOM0_IMAGE_NAME  (${DOM0_VERSION_NICK})"
    else
        echo "  WARNING: DOM0_VERSION=$DOM0_VERSION but guest/$DOM0_IMAGE_NAME not found"
        echo "           Run: DOM0_VERSION=$DOM0_VERSION cargo fetch-dom0"
    fi
elif _detected=$(dom0_detect_from_guest_dir "$WORKSPACE_ROOT/guest"); then
    dom0_select "$_detected"
    DISK_ARGS+="-drive id=dom0,file=$WORKSPACE_ROOT/guest/$DOM0_IMAGE_NAME,format=qcow2,if=none "
    DISK_ARGS+="-device virtio-blk-pci,drive=dom0 "
    echo "  + virtio disk: guest/$DOM0_IMAGE_NAME  (${DOM0_VERSION_NICK})"
fi

BINS_ARGS=""
if [[ -f "$WORKSPACE_ROOT/guest/bins.img" ]]; then
    BINS_ARGS+="-drive id=bins,file=$WORKSPACE_ROOT/guest/bins.img,format=raw,if=none "
    BINS_ARGS+="-device virtio-blk-pci,drive=bins "
fi

# ── TPM (swtpm) ──────────────────────────────────────────────────────────────
TPM_ARGS=""
if [[ "${QEMU_TPM:-1}" == "1" ]]; then
    SWTPM_SOCK="/tmp/themis-swtpm/swtpm-sock"
    if [[ ! -S "$SWTPM_SOCK" ]]; then
        echo "→ Starting swtpm automatically..."
        bash "$SCRIPT_DIR/setup-swtpm.sh"
    fi
    if [[ -S "$SWTPM_SOCK" ]]; then
        TPM_ARGS="-chardev socket,id=chrtpm,path=$SWTPM_SOCK"
        TPM_ARGS+=" -tpmdev emulator,id=tpm0,chardev=chrtpm"
        if [[ "${QEMU_TIS:-0}" == "1" ]]; then
            TPM_ARGS+=" -device tpm-tis,tpmdev=tpm0"
            echo "  + TPM 2.0 TIS (swtpm): $SWTPM_SOCK"
        else
            TPM_ARGS+=" -device tpm-crb,tpmdev=tpm0"
            echo "  + TPM 2.0 CRB (swtpm): $SWTPM_SOCK"
        fi
    else
        echo "  WARNING: QEMU_TPM=1 but swtpm socket not found at $SWTPM_SOCK"
        echo "           Run: bash scripts/setup-swtpm.sh"
    fi
fi

# ── Networking ───────────────────────────────────────────────────────────────
NET_ARGS=""
if [[ "${QEMU_NET:-1}" == "1" ]]; then
    NET_FWD="hostfwd=tcp::2222-:22"
    [[ -n "${QEMU_NET_FWD:-}" ]] && NET_FWD+=",${QEMU_NET_FWD}"
    NET_ARGS="-netdev user,id=n0,${NET_FWD} -device virtio-net-pci,netdev=n0"
fi

echo "→ Booting $ISO (${QEMU_CPUS} CPUs, ${QEMU_MEM} RAM)"
[[ -n "$NET_ARGS" ]] && echo "  + networking: virtio-net (SLIRP), SSH → localhost:2222"

exec qemu-system-x86_64 \
    $KVM_ARGS \
    -machine q35,kernel-irqchip=split \
    -device intel-iommu,intremap=on \
    ${FIRMWARE_ARGS} \
    -smp "$QEMU_CPUS" \
    -m "$QEMU_MEM" \
    -cdrom "$ISO" \
    -serial mon:stdio \
    -display none \
    -no-reboot \
    ${DISK_ARGS} \
    ${BINS_ARGS} \
    ${TPM_ARGS} \
    ${NET_ARGS} \
    ${QEMU_EXTRA_ARGS:-}
