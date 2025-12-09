#!/usr/bin/env bash

#=============================================================================
# Silent Legacy YARA Cleanup Script
# Automatically removes old YARA installations from /usr paths
# Called by install.sh - runs silently without user prompts
#=============================================================================

# Define text formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
BOLD='\033[1m'
NORMAL='\033[0m'

# Function for logging with timestamp
log() {
    local LEVEL="$1"
    shift
    local MESSAGE="$*"
    local TIMESTAMP
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "${TIMESTAMP} ${LEVEL} ${MESSAGE}"
}

# Logging helpers
info_message() {
    log "${BLUE}${BOLD}[INFO]${NORMAL}" "$*"
}
warn_message() {
    log "${YELLOW}${BOLD}[WARNING]${NORMAL}" "$*"
}
error_message() {
    log "${RED}${BOLD}[ERROR]${NORMAL}" "$*"
}
success_message() {
    log "${GREEN}${BOLD}[SUCCESS]${NORMAL}" "$*"
}

# Check if we're running in bash; if not, adjust behavior
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

# OS Detection
case "$(uname)" in
Linux)
    OS="linux"
    OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
    WAZUH_CONTROL_BIN_PATH="/var/ossec/bin/wazuh-control"
    ;;
Darwin)
    OS="darwin"
    OSSEC_CONF_PATH="/Library/Ossec/etc/ossec.conf"
    WAZUH_CONTROL_BIN_PATH="/Library/Ossec/bin/wazuh-control"
    ;;
*)
    error_message "Unsupported operating system: $(uname)"
    exit 1
    ;;
esac

# Detect Linux Distribution
if [ "$OS" = "linux" ]; then
    detect_distro() {
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            echo "$ID"
        elif [ -f /etc/redhat-release ]; then
            echo "redhat"
        elif [ -f /etc/debian_version ]; then
            echo "debian"
        else
            echo "unknown"
        fi
    }
    DISTRO=$(detect_distro)
fi

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if sudo is available or if the script is run as root
maybe_sudo() {
    if [ "$(id -u)" -ne 0 ]; then
        if command_exists sudo; then
            sudo "$@"
        else
            "$@"
        fi
    else
        "$@"
    fi
}

# Cross-platform sed function
sed_inplace() {
    if [ "$OS" = "darwin" ]; then
        maybe_sudo sed -i '' "$@" 2>/dev/null || true
    else
        maybe_sudo sed -i "$@" 2>/dev/null || true
    fi
}

# Remove legacy YARA binaries from /usr paths
remove_legacy_yara_binaries() {
    info_message "Removing legacy YARA binaries from /usr paths..."
    local removed_count=0
    
    # Common legacy installation paths
    local legacy_paths=(
        "/usr/bin/yara"
        "/usr/bin/yarac"
        "/usr/local/bin/yara"
        "/usr/local/bin/yarac"
        "/usr/lib/libyara.so"
        "/usr/lib/libyara.so.*"
        "/usr/lib64/libyara.so"
        "/usr/lib64/libyara.so.*"
        "/usr/local/lib/libyara.so"
        "/usr/local/lib/libyara.so.*"
        "/usr/local/lib64/libyara.so"
        "/usr/local/lib64/libyara.so.*"
    )
    
    for path in "${legacy_paths[@]}"; do
        for file in $path; do
            if [ -e "$file" ] || [ -L "$file" ]; then
                info_message "Removing: $file"
                if maybe_sudo rm -f "$file" 2>/dev/null; then
                    removed_count=$((removed_count + 1))
                fi
            fi
        done
    done
    
    if [ $removed_count -gt 0 ]; then
        success_message "Removed $removed_count legacy YARA binary/library file(s)"
    else
        info_message "No legacy YARA binaries found in /usr paths"
    fi
}

# Remove legacy YARA headers
remove_legacy_yara_headers() {
    info_message "Removing legacy YARA header files..."
    local removed_count=0
    
    local header_paths=(
        "/usr/include/yara.h"
        "/usr/include/yara"
        "/usr/local/include/yara.h"
        "/usr/local/include/yara"
    )
    
    for path in "${header_paths[@]}"; do
        if [ -e "$path" ] || [ -L "$path" ]; then
            info_message "Removing: $path"
            if maybe_sudo rm -rf "$path" 2>/dev/null; then
                removed_count=$((removed_count + 1))
            fi
        fi
    done
    
    if [ $removed_count -gt 0 ]; then
        success_message "Removed $removed_count legacy YARA header file(s)/directory(ies)"
    else
        info_message "No legacy YARA headers found"
    fi
}

# Remove legacy pkg-config files
remove_legacy_pkgconfig() {
    info_message "Removing legacy YARA pkg-config files..."
    local removed_count=0
    
    local pkgconfig_paths=(
        "/usr/lib/pkgconfig/yara.pc"
        "/usr/lib64/pkgconfig/yara.pc"
        "/usr/local/lib/pkgconfig/yara.pc"
        "/usr/local/lib64/pkgconfig/yara.pc"
    )
    
    for path in "${pkgconfig_paths[@]}"; do
        if [ -f "$path" ]; then
            info_message "Removing: $path"
            if maybe_sudo rm -f "$path" 2>/dev/null; then
                removed_count=$((removed_count + 1))
            fi
        fi
    done
    
    if [ $removed_count -gt 0 ]; then
        success_message "Removed $removed_count legacy YARA pkg-config file(s)"
    else
        info_message "No legacy YARA pkg-config files found"
    fi
}

# Remove source installation directories silently
remove_legacy_source_dirs() {
    info_message "Removing legacy YARA source directories..."
    local removed_count=0
    
    local source_dirs=(
        "/tmp/yara-*"
        "/opt/yara-*"
    )
    
    for dir_pattern in "${source_dirs[@]}"; do
        for dir in $dir_pattern 2>/dev/null; do
            if [ -d "$dir" ]; then
                info_message "Removing source directory: $dir"
                if maybe_sudo rm -rf "$dir" 2>/dev/null; then
                    removed_count=$((removed_count + 1))
                fi
            fi
        done
    done
    
    if [ $removed_count -gt 0 ]; then
        success_message "Removed $removed_count source directory(ies)"
    else
        info_message "No legacy source directories found"
    fi
}

# Remove YARA rules and scripts from Wazuh
remove_yara_wazuh_components() {
    info_message "Removing YARA components from Wazuh..."
    
    local base_path yara_script_path yara_rules_path
    if [ "$OS" = "darwin" ]; then
        base_path="/Library/Ossec"
        yara_script_path="/Library/Ossec/active-response/bin/yara.sh"
        yara_rules_path="/Library/Ossec/ruleset/yara"
    else
        base_path="/var/ossec"
        yara_script_path="/var/ossec/active-response/bin/yara.sh"
        yara_rules_path="/var/ossec/ruleset/yara"
    fi
    
    # Remove YARA script
    if maybe_sudo test -f "$yara_script_path"; then
        info_message "Removing YARA script: $yara_script_path"
        maybe_sudo rm -f "$yara_script_path" 2>/dev/null || true
        success_message "Removed YARA script"
    fi
    
    # Remove YARA rules directory
    if maybe_sudo test -d "$yara_rules_path"; then
        info_message "Removing YARA rules directory: $yara_rules_path"
        maybe_sudo rm -rf "$yara_rules_path" 2>/dev/null || true
        success_message "Removed YARA rules directory"
    fi
}

# Update dynamic linker cache
update_ldconfig() {
    if [ "$OS" = "linux" ]; then
        info_message "Updating dynamic linker cache..."
        if maybe_sudo ldconfig 2>/dev/null; then
            success_message "Dynamic linker cache updated"
        else
            warn_message "Could not update dynamic linker cache"
        fi
    fi
}

# Restore ossec configuration
restore_ossec_configuration() {
    info_message "Checking OSSEC configuration for YARA-related modifications..."
    
    if maybe_sudo test -f "$OSSEC_CONF_PATH"; then
        if maybe_sudo grep -q "<file_limit>" "$OSSEC_CONF_PATH" 2>/dev/null; then
            info_message "Removing file_limit block from OSSEC configuration"
            sed_inplace "/<file_limit>/,/<\/file_limit>/d" "$OSSEC_CONF_PATH"
            success_message "Removed file_limit block from OSSEC configuration"
        fi
    fi
}

# Main cleanup function
main() {
    info_message "Starting silent legacy YARA cleanup..."
    info_message "Detected OS: ${OS}"
    
    if [ "$OS" = "linux" ]; then
        info_message "Detected Linux distribution: ${DISTRO}"
    fi
    
    # Perform cleanup steps silently
    remove_legacy_yara_binaries
    remove_legacy_yara_headers
    remove_legacy_pkgconfig
    remove_yara_wazuh_components
    restore_ossec_configuration
    update_ldconfig
    remove_legacy_source_dirs
    
    success_message "Legacy YARA cleanup completed successfully!"
    exit 0
}

# Execute main function
main "$@"