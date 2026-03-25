#!/usr/bin/env bash

#=============================================================================
# YARA Uninstallation Script for Linux
# Automatically detects and removes YARA installations from:
# - /opt/yara (legacy installation)
# - /opt/wazuh/yara (modern installation)
# - /usr/local/bin/yara (softlink/wrapper)
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
OS="linux"
OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
WAZUH_CONTROL_BIN_PATH="/var/ossec/bin/wazuh-control"

# Detect Linux Distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/redhat-release ]; then
        echo "redhat"
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    else
        error_message "Unable to detect Linux distribution"
        exit 1
    fi
}
DISTRO=$(detect_distro)

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
            error_message "This script requires root privileges. Please run with sudo or as root."
            exit 1
        fi
    else
        "$@"
    fi
}

# Sed in-place for Linux
sed_inplace() {
    maybe_sudo sed -i "$@" 2>/dev/null || true
}

# Restart Wazuh agent
restart_wazuh_agent() {
    if maybe_sudo "$WAZUH_CONTROL_BIN_PATH" restart >/dev/null 2>&1; then
        success_message "Wazuh agent restarted successfully."
    else
        warn_message "Could not restart Wazuh agent (may not be running)."
    fi
}

# Detect YARA installations
detect_yara_installation() {
    local has_legacy=0
    local has_modern=0
    local has_softlink=0

    if [ -d "/opt/yara" ]; then
        has_legacy=1
    fi

    if [ -d "/opt/wazuh/yara" ]; then
        has_modern=1
    fi

    if [ -L "/usr/local/bin/yara" ] || [ -f "/usr/local/bin/yara" ]; then
        has_softlink=1
    fi

    case "$DISTRO" in
        centos|rhel|redhat|rocky|almalinux|fedora)
            if command_exists rpm && rpm -q yara > /dev/null 2>&1; then
                has_modern=1
            fi
            ;;
        ubuntu|debian)
            if command_exists dpkg && dpkg -s yara > /dev/null 2>&1; then
                has_modern=1
            fi
            ;;
    esac

    echo "${has_legacy},${has_modern},${has_softlink}"
}

# Remove YARA packages installed via package managers
remove_yara_packages() {
    info_message "Removing YARA packages..."

    case "$DISTRO" in
        centos|rhel|redhat|rocky|almalinux|fedora)
            if command_exists rpm && rpm -q yara >/dev/null 2>&1; then
                info_message "Detected RPM-installed YARA package"
                if command_exists dnf; then
                    if maybe_sudo dnf remove -y yara; then
                        success_message "Removed YARA via dnf"
                    fi
                elif command_exists yum; then
                    if maybe_sudo yum remove -y yara; then
                        success_message "Removed YARA via yum"
                    fi
                fi
            else
                info_message "No RPM-installed YARA package found"
            fi
            ;;
        ubuntu|debian)
            if command_exists dpkg && dpkg -s yara >/dev/null 2>&1; then
                info_message "Detected DEB-installed YARA package"
                if maybe_sudo apt-get remove -y yara; then
                    maybe_sudo apt-get autoremove -y
                    success_message "Removed YARA via apt"
                fi
            else
                info_message "No DEB-installed YARA package found"
            fi
            ;;
        *)
            warn_message "Unsupported Linux distribution for package removal: $DISTRO"
            ;;
    esac

    return 0
}

# Remove custom YARA installation from /opt/wazuh/yara
remove_custom_yara_installation() {
    info_message "Removing custom YARA installation..."
    local removed=0

    local yara_install_dir="/opt/wazuh/yara"
    if [ -d "$yara_install_dir" ]; then
        info_message "Removing YARA installation directory: $yara_install_dir"
        if maybe_sudo rm -rf "$yara_install_dir"; then
            success_message "Removed YARA installation directory"
            removed=1
        else
            error_message "Failed to remove YARA installation directory"
        fi
    else
        info_message "YARA installation directory not found: $yara_install_dir"
    fi

    local yara_symlink="/usr/local/bin/yara"
    if [ -L "$yara_symlink" ] || [ -f "$yara_symlink" ]; then
        info_message "Removing YARA symlink/wrapper: $yara_symlink"
        if maybe_sudo rm -f "$yara_symlink"; then
            success_message "Removed YARA symlink/wrapper"
            removed=1
        else
            warn_message "Failed to remove YARA symlink/wrapper"
        fi
    else
        info_message "YARA symlink not found: $yara_symlink"
    fi

    if [ $removed -eq 0 ]; then
        info_message "No custom YARA installation found"
    fi
}

# Remove legacy YARA installation from /opt/yara
remove_legacy_yara_installation() {
    info_message "Removing legacy YARA installation..."
    local removed=0

    local legacy_yara_dir="/opt/yara"
    if [ -d "$legacy_yara_dir" ]; then
        info_message "Removing legacy YARA directory: $legacy_yara_dir"
        if maybe_sudo rm -rf "$legacy_yara_dir"; then
            success_message "Removed legacy YARA directory"
            removed=1
        else
            error_message "Failed to remove legacy YARA directory"
        fi
    else
        info_message "Legacy YARA directory not found: $legacy_yara_dir"
    fi

    if [ $removed -eq 0 ]; then
        info_message "No legacy YARA installation found"
    fi
}

# Remove YARA rules and scripts from Wazuh
remove_yara_wazuh_components() {
    info_message "Removing YARA rules and scripts from Wazuh..."
    local removed=0

    local yara_script_path="/var/ossec/active-response/bin/yara.sh"
    local yara_rules_path="/var/ossec/ruleset/yara"

    if maybe_sudo test -f "$yara_script_path"; then
        info_message "Removing YARA script: $yara_script_path"
        if maybe_sudo rm -f "$yara_script_path"; then
            success_message "Removed YARA script"
            removed=1
        else
            warn_message "Failed to remove YARA script"
        fi
    else
        info_message "YARA script not found: $yara_script_path"
    fi

    if maybe_sudo test -d "$yara_rules_path"; then
        info_message "Removing YARA rules directory: $yara_rules_path"
        if maybe_sudo rm -rf "$yara_rules_path"; then
            success_message "Removed YARA rules directory"
            removed=1
        else
            warn_message "Failed to remove YARA rules directory"
        fi
    else
        info_message "YARA rules directory not found: $yara_rules_path"
    fi

    if [ $removed -eq 0 ]; then
        info_message "No YARA components found in Wazuh directories"
    fi
}

# Restore ossec configuration
restore_ossec_configuration() {
    info_message "Restoring OSSEC configuration..."

    if maybe_sudo test -f "$OSSEC_CONF_PATH"; then
        if maybe_sudo grep -q "<file_limit>" "$OSSEC_CONF_PATH"; then
            info_message "Removing file_limit block from OSSEC configuration"
            sed_inplace "/<file_limit>/,/<\/file_limit>/d" "$OSSEC_CONF_PATH"
            success_message "Removed file_limit block from OSSEC configuration"
        else
            info_message "No file_limit block found in OSSEC configuration"
        fi
    else
        warn_message "OSSEC configuration file not found: $OSSEC_CONF_PATH"
    fi
}

# Validate complete removal
validate_removal() {
    info_message "Validating YARA removal..."
    local found_items=0

    if command_exists yara; then
        local yara_path
        yara_path=$(command -v yara)
        warn_message "YARA command still available at: $yara_path"
        found_items=$((found_items + 1))
    fi

    if [ -d "/opt/yara" ]; then
        warn_message "Legacy YARA directory still exists: /opt/yara"
        found_items=$((found_items + 1))
    fi

    if [ -d "/opt/wazuh/yara" ]; then
        warn_message "YARA installation directory still exists: /opt/wazuh/yara"
        found_items=$((found_items + 1))
    fi

    if [ -L "/usr/local/bin/yara" ] || [ -f "/usr/local/bin/yara" ]; then
        warn_message "YARA binary/symlink still exists: /usr/local/bin/yara"
        found_items=$((found_items + 1))
    fi

    if maybe_sudo test -f "/var/ossec/active-response/bin/yara.sh"; then
        warn_message "YARA script still exists: /var/ossec/active-response/bin/yara.sh"
        found_items=$((found_items + 1))
    fi

    if maybe_sudo test -d "/var/ossec/ruleset/yara"; then
        warn_message "YARA rules directory still exists: /var/ossec/ruleset/yara"
        found_items=$((found_items + 1))
    fi

    if [ $found_items -eq 0 ]; then
        success_message "YARA has been completely removed from the system"
        return 0
    else
        warn_message "Found $found_items YARA component(s) still present"
        warn_message "Manual cleanup may be required for complete removal"
        return 0
    fi
}

# Main uninstallation function
main() {
    info_message "Starting YARA uninstallation..."
    info_message "Detected OS: Linux"
    info_message "Detected Linux distribution: ${DISTRO}"

    local detection_result
    detection_result=$(detect_yara_installation)
    IFS=',' read -r has_legacy has_modern has_softlink <<< "$detection_result"

    if [ "$has_legacy" -eq 1 ] || [ "$has_modern" -eq 1 ] || [ "$has_softlink" -eq 1 ]; then
        echo ""
        info_message "Detected YARA installations:"

        if [ -d "/opt/yara" ]; then
            info_message "  - Legacy installation: /opt/yara"
        fi

        if [ -d "/opt/wazuh/yara" ]; then
            info_message "  - Modern installation: /opt/wazuh/yara"
        fi

        if [ -L "/usr/local/bin/yara" ] || [ -f "/usr/local/bin/yara" ]; then
            info_message "  - Softlink: /usr/local/bin/yara"
        fi

        echo ""
        info_message "Proceeding with automatic uninstallation..."
    else
        info_message "No YARA installations detected"
        success_message "System is already clean"
        return 0
    fi

    remove_yara_packages

    if [ "$has_legacy" -eq 1 ]; then
        remove_legacy_yara_installation
    fi

    if [ "$has_modern" -eq 1 ]; then
        remove_custom_yara_installation
    fi

    remove_yara_wazuh_components
    restore_ossec_configuration
    validate_removal
    restart_wazuh_agent

    echo ""
    success_message "YARA uninstallation process completed!"
    info_message "Your system is now clean and ready for a fresh installation"
}

# Execute main function
main "$@"