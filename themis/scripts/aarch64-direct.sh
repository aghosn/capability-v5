#!/usr/bin/env bash
# aarch64-direct.sh — Build and boot Themis capavisor via QEMU direct `-kernel`
#                     at EL2 (no Limine, no UEFI firmware).
#
# Usage:
#   cargo aarch64-direct          (via xtask alias)
#   bash scripts/aarch64-direct.sh
#
# Prerequisites:
#   • qemu-system-aarch64  (sudo apt install qemu-system-arm)
#   • aarch64-unknown-none Rust target
#   • python3 (for boot descriptor generation)
#
# Environment knobs:
#   PROFILE=release       build with --release (default: debug)
#   QEMU_CPUS=1           number of vCPUs (default: 1)
#   QEMU_MEM=1G           guest RAM (default: 1G)
#   LINUX_IMAGE=<path>    ARM64 Linux Image (auto-discovered from guest/aarch64/)
#   INITRD=<path>         initrd/initramfs (auto-discovered from guest/aarch64/)
#   QEMU_EXTRA_ARGS       additional QEMU arguments

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PROFILE="${PROFILE:-debug}"
BUILD_FLAGS=""
if [[ "$PROFILE" == "release" ]]; then
    BUILD_FLAGS="--release"
fi

QEMU_CPUS="${QEMU_CPUS:-1}"
QEMU_MEM="${QEMU_MEM:-2G}"

# Auto-discover ARM64 kernel if not explicitly set
if [[ -z "${LINUX_IMAGE:-}" ]]; then
    DEFAULT_IMAGE="$WORKSPACE_ROOT/guest/aarch64/Image"
    if [[ -f "$DEFAULT_IMAGE" ]]; then
        LINUX_IMAGE="$DEFAULT_IMAGE"
    fi
fi

# Auto-discover initrd if not explicitly set
DEFAULT_INITRD="$WORKSPACE_ROOT/guest/aarch64/initrd.img"
if [[ -z "${INITRD:-}" ]]; then
    if [[ -f "$DEFAULT_INITRD" ]]; then
        INITRD="$DEFAULT_INITRD"
    fi
fi

# Auto-discover dom0 root disk (Ubuntu ARM64 cloud image)
DOM0_DISK=""
DOM0_SEED=""
DEFAULT_DISK="$WORKSPACE_ROOT/guest/aarch64/dom0.img"
DEFAULT_SEED="$WORKSPACE_ROOT/guest/aarch64/seed.img"
if [[ -f "$DEFAULT_DISK" ]]; then
    DOM0_DISK="$DEFAULT_DISK"
    if [[ -f "$DEFAULT_SEED" ]]; then
        DOM0_SEED="$DEFAULT_SEED"
    fi
    # When booting from disk, skip the custom initrd — the kernel mounts
    # root=/dev/vda1 directly (ext4 and virtio_blk are built-in).
    # Only clear if it was auto-discovered (not explicitly set by user).
    if [[ "${INITRD:-}" == "$DEFAULT_INITRD" ]]; then
        echo "→ Disk boot: skipping custom initrd in favor of root=/dev/vda1"
        INITRD=""
    fi
fi

# ── Build the capavisor ELF ───────────────────────────────────────────────

echo "→ Building capavisor (aarch64, direct-boot, ${PROFILE})..."
cargo build \
    --manifest-path "$WORKSPACE_ROOT/capavisor/Cargo.toml" \
    --target aarch64-unknown-none \
    --features direct-boot \
    $BUILD_FLAGS

ELF="$WORKSPACE_ROOT/target/aarch64-unknown-none/${PROFILE}/capavisor"

if [[ ! -f "$ELF" ]]; then
    echo "ERROR: ELF not found at $ELF" >&2
    exit 1
fi

echo "→ ELF:  $ELF"
echo "→ CPUs: $QEMU_CPUS  RAM: $QEMU_MEM"

# ── Compute memory layout from ELF ────────────────────────────────────────
# Read __image_end from the ELF to know where the capavisor image ends.
# All module addresses are computed relative to this — no hardcoded addresses.

IMAGE_END=$(aarch64-linux-gnu-nm "$ELF" 2>/dev/null \
    | grep '__image_end' | awk '{print $1}' \
    || true)

if [[ -z "$IMAGE_END" ]]; then
    # Fallback: use readelf to find the end of the last LOAD segment.
    IMAGE_END=$(aarch64-linux-gnu-readelf -l "$ELF" 2>/dev/null \
        | awk '/LOAD/{
            split($3, a, "x"); vaddr=strtonum("0x"a[2]);
            split($6, b, "x"); memsz=strtonum("0x"b[2]);
            e=vaddr+memsz; if(e>max) max=e
        } END{printf "%x", max}')
fi

IMAGE_END_DEC=$((16#$IMAGE_END))

# Descriptor blob: 4K page after image end.
DESCRIPTOR_ADDR=$((IMAGE_END_DEC + 0x1000))

# Align all module placement to 2M boundaries after the descriptor.
ALIGN_2M=0x200000
next_aligned() {
    local addr=$1
    echo $(( (addr + ALIGN_2M - 1) & ~(ALIGN_2M - 1) ))
}

# Kernel load address: next 2M boundary after descriptor.
KERNEL_ADDR=$(next_aligned $((DESCRIPTOR_ADDR + 0x1000)))

echo "→ Image end:   0x$(printf '%x' $IMAGE_END_DEC)"
echo "→ Descriptor:  0x$(printf '%x' $DESCRIPTOR_ADDR)"
echo "→ Kernel addr: 0x$(printf '%x' $KERNEL_ADDR)"

# ── Build loader arguments and boot descriptor ───────────────────────────

LOADER_ARGS=""
MODULE_COUNT=0
# Collect module info for descriptor generation: "addr size name"
declare -a MODULE_ENTRIES=()

if [[ -n "${LINUX_IMAGE:-}" ]]; then
    if [[ ! -f "$LINUX_IMAGE" ]]; then
        echo "ERROR: Linux Image not found at $LINUX_IMAGE" >&2
        exit 1
    fi
    KERNEL_SIZE=$(stat -c%s "$LINUX_IMAGE")
    echo "→ Linux Image: $LINUX_IMAGE ($((KERNEL_SIZE / 1024 / 1024)) MiB)"
    echo "  loaded at 0x$(printf '%x' $KERNEL_ADDR)"
    LOADER_ARGS="$LOADER_ARGS -device loader,file=$LINUX_IMAGE,addr=$KERNEL_ADDR"
    MODULE_ENTRIES+=("$KERNEL_ADDR $KERNEL_SIZE dom0-kernel")
    MODULE_COUNT=$((MODULE_COUNT + 1))

    # Initrd: placed after kernel, 2M-aligned.
    if [[ -n "${INITRD:-}" ]]; then
        if [[ ! -f "$INITRD" ]]; then
            echo "ERROR: initrd not found at $INITRD" >&2
            exit 1
        fi
        INITRD_SIZE=$(stat -c%s "$INITRD")
        INITRD_ADDR=$(next_aligned $((KERNEL_ADDR + KERNEL_SIZE)))
        echo "→ Initrd: $INITRD ($((INITRD_SIZE / 1024)) KiB)"
        echo "  loaded at 0x$(printf '%x' $INITRD_ADDR)"
        LOADER_ARGS="$LOADER_ARGS -device loader,file=$INITRD,addr=$INITRD_ADDR"
        MODULE_ENTRIES+=("$INITRD_ADDR $INITRD_SIZE dom0-initrd")
        MODULE_COUNT=$((MODULE_COUNT + 1))
    fi
else
    echo "→ No Linux kernel found. The capavisor will boot standalone."
    echo "  To boot Linux:  cargo fetch-aarch64-kernel && cargo aarch64-direct"
    echo
fi

# ── Generate boot descriptor blob ────────────────────────────────────────
# Format: header (16 bytes) + N entries (48 bytes each).
# This is what the capavisor reads to discover modules.

DESCRIPTOR_FILE=$(mktemp)
trap 'rm -f "$DESCRIPTOR_FILE"' EXIT

python3 -c "
import struct, sys

# Header: magic('TDBS'), version(1), count, pad
magic = 0x54444253
version = 1
count = $MODULE_COUNT
header = struct.pack('<IIII', magic, version, count, 0)

entries = b''
$(for entry in "${MODULE_ENTRIES[@]:-}"; do
    read -r addr size name <<< "$entry"
    echo "entries += struct.pack('<QQ', $addr, $size) + b'$name'.ljust(32, b'\\x00')"
done)

sys.stdout.buffer.write(header + entries)
" > "$DESCRIPTOR_FILE"

DESCRIPTOR_SIZE=$(stat -c%s "$DESCRIPTOR_FILE")
echo "→ Boot descriptor: $DESCRIPTOR_SIZE bytes at 0x$(printf '%x' $DESCRIPTOR_ADDR)"
LOADER_ARGS="$LOADER_ARGS -device loader,file=$DESCRIPTOR_FILE,addr=$DESCRIPTOR_ADDR"

# ── Validate layout — check for overlaps ─────────────────────────────────

echo
validate_no_overlap() {
    local name1=$1 start1=$2 end1=$3 name2=$4 start2=$5 end2=$6
    if [[ $start1 -lt $end2 && $start2 -lt $end1 ]]; then
        echo "ERROR: $name1 [0x$(printf '%x' $start1)..0x$(printf '%x' $end1)] overlaps" >&2
        echo "       $name2 [0x$(printf '%x' $start2)..0x$(printf '%x' $end2)]" >&2
        exit 1
    fi
}

# Collect all regions for overlap checking.
declare -a REGIONS=()
REGIONS+=("hypervisor 0x40100000 $IMAGE_END_DEC")
REGIONS+=("descriptor $DESCRIPTOR_ADDR $((DESCRIPTOR_ADDR + DESCRIPTOR_SIZE))")
for entry in "${MODULE_ENTRIES[@]:-}"; do
    read -r addr size name <<< "$entry"
    REGIONS+=("$name $addr $((addr + size))")
done

# Check all pairs.
for ((i=0; i<${#REGIONS[@]}; i++)); do
    read -r n1 s1 e1 <<< "${REGIONS[$i]}"
    for ((j=i+1; j<${#REGIONS[@]}; j++)); do
        read -r n2 s2 e2 <<< "${REGIONS[$j]}"
        validate_no_overlap "$n1" "$s1" "$e1" "$n2" "$s2" "$e2"
    done
done

echo "→ Layout validated (no overlaps)"

# ── Launch QEMU ───────────────────────────────────────────────────────────
# - virtualization=on: CPU enters at EL2 (required for hypervisor)
# - -kernel: direct ELF load (QEMU reads entry point from ELF header)
# - No firmware/BIOS needed; QEMU provides FDT in X0

DISK_ARGS=()
APPEND_ARGS=()
if [[ -n "$DOM0_DISK" ]]; then
    echo "→ Dom0 disk: $DOM0_DISK"
    DISK_ARGS+=(-drive "id=dom0,file=$DOM0_DISK,format=qcow2,if=none")
    DISK_ARGS+=(-device virtio-blk-pci,drive=dom0)
    if [[ -n "$DOM0_SEED" ]]; then
        echo "→ Seed:      $DOM0_SEED"
        DISK_ARGS+=(-drive "id=seed,file=$DOM0_SEED,format=raw,if=none,readonly=on")
        DISK_ARGS+=(-device virtio-blk-pci,drive=seed)
    fi
    # Boot from disk with serial console.
    BOOTARGS="${BOOTARGS:-console=ttyAMA0 root=/dev/vda1 rw rootwait loglevel=7 systemd.mask=boot-efi.mount systemd.mask=multipathd.service systemd.mask=systemd-networkd-wait-online.service}"
    APPEND_ARGS=(-append "$BOOTARGS")
else
    BOOTARGS="${BOOTARGS:-console=ttyAMA0}"
    APPEND_ARGS=(-append "$BOOTARGS")
fi

echo
exec qemu-system-aarch64 \
    -machine virt,gic-version=3,virtualization=on \
    -cpu cortex-a76 \
    -smp "$QEMU_CPUS" \
    -m "$QEMU_MEM" \
    -kernel "$ELF" \
    -nographic \
    -serial mon:stdio \
    -device virtio-rng-pci \
    $LOADER_ARGS \
    "${DISK_ARGS[@]}" \
    "${APPEND_ARGS[@]}" \
    ${QEMU_EXTRA_ARGS:-}
