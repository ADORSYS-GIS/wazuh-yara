#!/usr/bin/env bash

#=============================================================================
# YARA Uninstallation Script for macOS
# Automatically detects and removes YARA installations from:
# - /opt/yara (legacy installation)
# - /opt/wazuh/yara (modern installation)
# - /usr/local/bin/yara (symlink)
#=============================================================================


# Set shell options based on shell type
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

# OS guard early in the script
if [ "$(uname -s)" != "Darwin" ]; then
    printf "%s\n" "[ERROR] This installation script is intended for macOS systems. Please use the appropriate script for your operating system." >&2
    exit 1
fi

WAZUH_YARA_REPO_REF=${WAZUH_YARA_REPO_REF:-"main"}
WAZUH_YARA_REPO_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/${WAZUH_YARA_REPO_REF}"
OSSEC_CONF_PATH=${OSSEC_CONF_PATH:-"/Library/Ossec/etc/ossec.conf"}
WAZUH_CONTROL_BIN_PATH=${WAZUH_CONTROL_BIN_PATH:-"/Library/Ossec/bin/wazuh-control"}

# Source shared utilities
TMP_DIR=$(mktemp -d)
if ! curl "${WAZUH_YARA_REPO_URL}/scripts/shared/utils.sh" -o "$TMP_DIR/utils.sh"; then
    echo "Failed to download utils.sh"
    exit 1
fi

# Function to calculate SHA256 (cross-platform bootstrap)
calculate_sha256_bootstrap() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# Download checksums and verify utils.sh integrity BEFORE sourcing it
if ! curl "${WAZUH_YARA_REPO_URL}/checksums.sha256" -o "$TMP_DIR/checksums.sha256"; then
    echo "Failed to download checksums.sha256"
    exit 1
fi


EXPECTED_HASH=$(grep "scripts/shared/utils.sh" "$TMP_DIR/checksums.sha256" | awk '{print $1}')
ACTUAL_HASH=$(calculate_sha256_bootstrap "$TMP_DIR/utils.sh")

if [ -z "$EXPECTED_HASH" ] || [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
    echo "Error: Checksum verification failed for utils.sh" >&2
    echo "Expected hash: $EXPECTED_HASH" >&2
    echo "Actual hash: $ACTUAL_HASH" >&2
    exit 1
fi

# Source utils.sh only after verification
. "$TMP_DIR/utils.sh"

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

    if [[ -d "/opt/yara" ]]; then
        has_legacy=1
    fi

    if [[ -d "/opt/wazuh/yara" ]]; then
        has_modern=1
    fi

    if [[ -L "/usr/local/bin/yara" ]] || [[ -f "/usr/local/bin/yara" ]]; then
        has_softlink=1
    fi

    # Check for Homebrew installation
    if command_exists brew && brew list yara >/dev/null 2>&1; then
        has_modern=1
    fi

    echo "${has_legacy},${has_modern},${has_softlink}"
}

# Sed in-place for macOS
sed_inplace() {
    maybe_sudo sed -i '' "$@" 2>/dev/null || true
}

# Remove YARA packages installed via Homebrew
remove_yara_packages() {
    info_message "Removing YARA packages..."

    if command_exists brew && brew list yara >/dev/null 2>&1; then
        info_message "Detected Homebrew-installed YARA"
        brew unpin yara 2>/dev/null || true
        if brew uninstall --force yara; then
            success_message "Removed YARA via Homebrew"
        fi
    else
        info_message "No Homebrew-installed YARA found"
    fi

    return 0
}

# Remove custom YARA installation from /opt/wazuh/yara
remove_custom_yara_installation() {
    info_message "Removing custom YARA installation..."
    local removed=0

    local yara_install_dir="/opt/wazuh/yara"
    if [[ -d "$yara_install_dir" ]]; then
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
    if [[ -L "$yara_symlink" ]] || [[ -f "$yara_symlink" ]]; then
        info_message "Removing YARA symlink: $yara_symlink"
        if maybe_sudo rm -f "$yara_symlink"; then
            success_message "Removed YARA symlink"
            removed=1
        else
            warn_message "Failed to remove YARA symlink"
        fi
    else
        info_message "YARA symlink not found: $yara_symlink"
    fi

    if [[ $removed -eq 0 ]]; then
        info_message "No custom YARA installation found"
    fi
}

# Remove legacy YARA installation from /opt/yara
remove_legacy_yara_installation() {
    info_message "Removing legacy YARA installation..."
    local removed=0

    local legacy_yara_dir="/opt/yara"
    if [[ -d "$legacy_yara_dir" ]]; then
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

    if [[ $removed -eq 0 ]]; then
        info_message "No legacy YARA installation found"
    fi
}

# Remove YARA rules and scripts from Wazuh
remove_yara_wazuh_components() {
    info_message "Removing YARA rules and scripts from Wazuh..."
    local removed=0

    local yara_script_path="/Library/Ossec/active-response/bin/yara.sh"
    local yara_rules_path="/Library/Ossec/ruleset/yara"

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

    if [[ $removed -eq 0 ]]; then
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

    if [[ -d "/opt/yara" ]]; then
        warn_message "Legacy YARA directory still exists: /opt/yara"
        found_items=$((found_items + 1))
    fi

    if [[ -d "/opt/wazuh/yara" ]]; then
        warn_message "YARA installation directory still exists: /opt/wazuh/yara"
        found_items=$((found_items + 1))
    fi

    if [[ -L "/usr/local/bin/yara" ]] || [[ -f "/usr/local/bin/yara" ]]; then
        warn_message "YARA binary/symlink still exists: /usr/local/bin/yara"
        found_items=$((found_items + 1))
    fi

    if maybe_sudo test -f "/Library/Ossec/active-response/bin/yara.sh"; then
        warn_message "YARA script still exists: /Library/Ossec/active-response/bin/yara.sh"
        found_items=$((found_items + 1))
    fi

    if maybe_sudo test -d "/Library/Ossec/ruleset/yara"; then
        warn_message "YARA rules directory still exists: /Library/Ossec/ruleset/yara"
        found_items=$((found_items + 1))
    fi

    if [[ $found_items -eq 0 ]]; then
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
    info_message "Detected OS: macOS"

    local detection_result
    detection_result=$(detect_yara_installation)
    IFS=',' read -r has_legacy has_modern has_softlink <<< "$detection_result"

    if [[ "$has_legacy" -eq 1 ]] || [[ "$has_modern" -eq 1 ]] || [[ "$has_softlink" -eq 1 ]]; then
        echo ""
        info_message "Detected YARA installations:"

        if [[ -d "/opt/yara" ]]; then
            info_message "  - Legacy installation: /opt/yara"
        fi

        if [[ -d "/opt/wazuh/yara" ]]; then
            info_message "  - Modern installation: /opt/wazuh/yara"
        fi

        if [[ -L "/usr/local/bin/yara" ]] || [[ -f "/usr/local/bin/yara" ]]; then
            info_message "  - Symlink: /usr/local/bin/yara"
        fi

        echo ""
        info_message "Proceeding with automatic uninstallation..."
    else
        info_message "No YARA installations detected"
        success_message "System is already clean"
        return 0
    fi

    remove_yara_packages

    if [[ "$has_legacy" -eq 1 ]]; then
        remove_legacy_yara_installation
    fi

    if [[ "$has_modern" -eq 1 ]]; then
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