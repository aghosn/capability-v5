#!/usr/bin/env bash
# dom0-lib.sh — Helper library for dom0 image version management.
#
# Source this file from any script that needs the dom0 image name or
# Limine boot paths.  Then call dom0_select to load the version config.
#
# Usage:
#   source "$(dirname "$0")/dom0-lib.sh"
#   dom0_select "${DOM0_VERSION:-}"    # picks env var, or default
#
# After dom0_select, these variables are set:
#   DOM0_IMAGE_NAME   — filename (e.g. ubuntu-24.04-server-cloudimg-amd64.img)
#   DOM0_IMAGE_URL    — full download URL
#   DOM0_KERNEL_PATH  — Limine module_path for vmlinuz
#   DOM0_INITRD_PATH  — Limine module_path for initrd.img
#   DOM0_CODENAME     — Ubuntu codename
#   DOM0_RELEASE      — Ubuntu version number
#   DOM0_NOTES        — one-line notes
#   DOM0_VERSION_NICK — selected nickname (e.g. "noble")

_DOM0_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_DOM0_CONF="$_DOM0_LIB_DIR/dom0-versions.conf"

# Source the version registry.
if [[ ! -f "$_DOM0_CONF" ]]; then
    echo "ERROR: dom0-versions.conf not found at $_DOM0_CONF" >&2
    exit 1
fi
# shellcheck source=dom0-versions.conf
source "$_DOM0_CONF"

# dom0_select [nickname]
#   Resolve a version nickname to its config variables.
#   If nickname is empty, uses DOM0_DEFAULT_VERSION from the conf file.
dom0_select() {
    local nick="${1:-$DOM0_DEFAULT_VERSION}"
    nick="${nick,,}"  # lowercase

    # Look up the version fields via indirect variable expansion.
    local var_image="VERSION_${nick}_IMAGE"
    local var_url="VERSION_${nick}_URL"
    local var_kernel="VERSION_${nick}_KERNEL"
    local var_initrd="VERSION_${nick}_INITRD"
    local var_codename="VERSION_${nick}_CODENAME"
    local var_release="VERSION_${nick}_RELEASE"
    local var_notes="VERSION_${nick}_NOTES"

    if [[ -z "${!var_image:-}" ]]; then
        echo "ERROR: unknown dom0 version '$nick'" >&2
        echo "Available versions:" >&2
        dom0_list_versions >&2
        exit 1
    fi

    DOM0_VERSION_NICK="$nick"
    DOM0_IMAGE_NAME="${!var_image}"
    DOM0_IMAGE_URL="${!var_url}"
    DOM0_KERNEL_PATH="${!var_kernel}"
    DOM0_INITRD_PATH="${!var_initrd}"
    DOM0_CODENAME="${!var_codename}"
    DOM0_RELEASE="${!var_release}"
    DOM0_NOTES="${!var_notes:-}"
}

# dom0_list_versions
#   Print all registered version nicknames with their release info.
dom0_list_versions() {
    echo "Registered dom0 versions:"
    # Scan for VERSION_*_CODENAME variables.
    local var
    for var in $(compgen -v | grep '^VERSION_.*_CODENAME$'); do
        local nick="${var#VERSION_}"
        nick="${nick%_CODENAME}"
        local rel_var="VERSION_${nick}_RELEASE"
        local img_var="VERSION_${nick}_IMAGE"
        local note_var="VERSION_${nick}_NOTES"
        local default_mark=""
        [[ "$nick" == "$DOM0_DEFAULT_VERSION" ]] && default_mark=" (default)"
        printf "  %-10s  %s  %s%s\n" "$nick" "${!rel_var}" "${!img_var}" "$default_mark"
    done
}

# dom0_detect_from_guest_dir [guest_dir]
#   Auto-detect which version is present in the guest directory.
#   Prefers DOM0_DEFAULT_VERSION if its image exists, otherwise returns
#   the first matching image found.
dom0_detect_from_guest_dir() {
    local guest_dir="${1:-.}"
    # Check default version first.
    local def_var="VERSION_${DOM0_DEFAULT_VERSION}_IMAGE"
    if [[ -n "${!def_var:-}" && -f "$guest_dir/${!def_var}" ]]; then
        echo "$DOM0_DEFAULT_VERSION"
        return 0
    fi
    # Fall back to first match.
    for var in $(compgen -v | grep '^VERSION_.*_IMAGE$'); do
        local nick="${var#VERSION_}"
        nick="${nick%_IMAGE}"
        if [[ -f "$guest_dir/${!var}" ]]; then
            echo "$nick"
            return 0
        fi
    done
    return 1
}
