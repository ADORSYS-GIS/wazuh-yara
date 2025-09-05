#!/bin/sh

# Check if we're running in bash; if not, adjust behavior
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

LOG_LEVEL=${LOG_LEVEL:-INFO}
VERSION="${1:-4.5.4}"

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
info_message() { log "${BLUE}${BOLD}[INFO]${NORMAL}" "$*"; }
warn_message() { log "${YELLOW}${BOLD}[WARNING]${NORMAL}" "$*"; }
error_message() { log "${RED}${BOLD}[ERROR]${NORMAL}" "$*"; }
success_message() { log "${GREEN}${BOLD}[SUCCESS]${NORMAL}" "$*"; }

# Check if sudo is available or if the script is run as root
maybe_sudo() {
    if [ "$(id -u)" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            sudo "$@"
        else
            error_message "This script requires root privileges. Please run with sudo or as root."
            exit 1
        fi
    else
        "$@"
    fi
}

sed_alternative() {
    if command -v gsed >/dev/null 2>&1; then
        maybe_sudo gsed "$@"
    else
        maybe_sudo sed "$@"
    fi
}

# Restart Wazuh agent
restart_wazuh_agent() {
    info_message "Restarting Wazuh agent..."
    if [ -f "/var/ossec/bin/wazuh-control" ]; then
        maybe_sudo /var/ossec/bin/wazuh-control restart && info_message "Wazuh agent restarted successfully." || warn_message "Error occurred during Wazuh agent restart."
    else
        warn_message "Wazuh agent control binary not found. Skipping restart."
    fi
}

# Remove source-installed YARA
remove_source_yara() {
    info_message "Checking for source-installed YARA..."
    local yara_bin="/usr/local/bin/yara"
    local yarac_bin="/usr/local/bin/yarac"
    local yara_lib="/usr/local/lib/libyara*"
    local yara_include="/usr/local/include/yara"
    local yara_man="/usr/local/share/man/man1/yara*"

    if [ -f "$yara_bin" ] || [ -f "$yarac_bin" ] || ls $yara_lib >/dev/null 2>&1; then
        info_message "Removing source-installed YARA components..."
        [ -f "$yara_bin" ] && maybe_sudo rm -f "$yara_bin" && info_message "Removed $yara_bin"
        [ -f "$yarac_bin" ] && maybe_sudo rm -f "$yarac_bin" && info_message "Removed $yarac_bin"
        ls $yara_lib >/dev/null 2>&1 && maybe_sudo rm -f $yara_lib && info_message "Removed YARA libraries from /usr/local/lib"
        [ -d "$yara_include" ] && maybe_sudo rm -rf "$yara_include" && info_message "Removed $yara_include"
        ls $yara_man >/dev/null 2>&1 && maybe_sudo rm -f $yara_man && info_message "Removed YARA man pages"
        maybe_sudo ldconfig && info_message "Updated shared library cache"
        success_message "Source-installed YARA removed"
    else
        info_message "No source-installed YARA found"
    fi
}

# Uninstall YARA based on package manager
uninstall_yara_ubuntu() {
    info_message "Checking for YARA installation..."
    # Check for apt-installed YARA
    if command -v dpkg >/dev/null 2>&1; then
        if dpkg -s yara >/dev/null 2>&1; then
            info_message "Detected apt-installed YARA; uninstalling via apt"
            maybe_sudo apt-get remove -y yara || {
                error_message "Failed to remove apt-installed YARA"
                exit 1
            }
            maybe_sudo apt-get autoremove -y
            success_message "Apt-installed YARA removed"
        else
            info_message "No apt-installed YARA found"
        fi
    fi
    # Check for source-installed YARA
    remove_source_yara
}

# Uninstall YARA based on OS
uninstall_yara() {
    case "$(uname -s)" in
        Linux)
            uninstall_yara_ubuntu
            ;;
        Darwin)
            # Note: macOS logic omitted for brevity, use from previous response if needed
            error_message "macOS uninstallation not implemented in this script"
            exit 1
            ;;
        *)
            error_message "Unsupported operating system."
            exit 1
            ;;
    esac
}

# Remove YARA rules and scripts
remove_yara_components() {
    info_message "Removing YARA rules and scripts..."
    YARA_DIR="/var/ossec/ruleset/yara"
    YARA_SCRIPT="/var/ossec/active-response/bin/yara.sh"
    OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"

    if maybe_sudo [ -d "$YARA_DIR" ]; then
        info_message "Removing YARA directory: $YARA_DIR"
        maybe_sudo rm -rf "$YARA_DIR" || warn_message "Failed to remove YARA directory."
    else
        info_message "YARA directory not found: $YARA_DIR"
    fi

    if maybe_sudo [ -f "$YARA_SCRIPT" ]; then
        info_message "Removing YARA script: $YARA_SCRIPT"
        maybe_sudo rm -f "$YARA_SCRIPT" || warn_message "Failed to remove YARA script."
    else
        info_message "YARA script not found: $YARA_SCRIPT"
    fi
}

# Remove ossec configuration modifications
remove_ossec_configuration() {
    if maybe_sudo [ -f "$OSSEC_CONF_PATH" ]; then
        info_message "Removing OSSEC configuration modifications..."
        # Backup ossec.conf
        local backup_path="$OSSEC_CONF_PATH.bak.$(date +%F_%H-%M-%S)"
        info_message "Backing up $OSSEC_CONF_PATH to $backup_path"
        maybe_sudo cp "$OSSEC_CONF_PATH" "$backup_path" || {
            warn_message "Failed to backup $OSSEC_CONF_PATH"
        }

        # Check and remove added file_limit block
        if maybe_sudo grep -q '<file_limit>' "$OSSEC_CONF_PATH"; then
            sed_alternative -i '/<file_limit>/,/<\/file_limit>/d' "$OSSEC_CONF_PATH" || {
                error_message "Error occurred while removing the file_limit block."
                exit 1
            }
            info_message "Removed file_limit block."
        else
            warn_message "file_limit block not found. Skipping."
        fi

        # Check and remove added directories entry
        if maybe_sudo grep -q '<directories realtime="yes">/home, /root, /bin, /sbin</directories>' "$OSSEC_CONF_PATH"; then
            sed_alternative -i '/<directories realtime="yes">\/home, \/root, \/bin, \/sbin<\/directories>/d' "$OSSEC_CONF_PATH" || {
                error_message "Error occurred while removing directories configuration."
                exit 1
            }
            info_message "Removed directories configuration."
        else
            warn_message "Directories configuration not found. Skipping."
        fi

        # Restore original frequency value if changed
        if maybe_sudo grep -q '<frequency>300</frequency>' "$OSSEC_CONF_PATH"; then
            sed_alternative -i 's/<frequency>300<\/frequency>/<frequency>43200<\/frequency>/g' "$OSSEC_CONF_PATH" || {
                error_message "Error occurred while restoring frequency value."
                exit 1
            }
            info_message "Restored frequency value to default."
        else
            warn_message "Frequency already set to default. Skipping."
        fi

        info_message "Ossec configuration settings removed."
    else
        warn_message "File $OSSEC_CONF_PATH not found. Skipping."
    fi
}

# Main uninstallation steps
info_message "Starting YARA uninstallation process..."
uninstall_yara
remove_yara_components
remove_ossec_configuration
restart_wazuh_agent
success_message "Uninstallation process completed successfully."