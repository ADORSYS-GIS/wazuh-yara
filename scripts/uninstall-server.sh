#!/bin/sh

# Check if we're running in bash; if not, adjust behavior
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

LOG_LEVEL=${LOG_LEVEL:-INFO}
LOGGED_IN_USER=""
VERSION="${1:-4.5.4}"

if [ "$(uname -s)" = "Darwin" ]; then
    LOGGED_IN_USER=$(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ {print $3}')
fi

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

brew_command() {
    if [ -n "$LOGGED_IN_USER" ]; then
        sudo -u "$LOGGED_IN_USER" brew "$@"
    else
        brew "$@"
    fi
}

# Restart Wazuh agent
restart_wazuh_agent() {
    info_message "Restarting Wazuh agent..."
    case "$(uname -s)" in
        Linux)
            if maybe_sudo [ -f "/var/ossec/bin/wazuh-control" ]; then
                maybe_sudo /var/ossec/bin/wazuh-control restart && info_message "Wazuh agent restarted successfully." || warn_message "Error occurred during Wazuh agent restart."
            else
                warn_message "Wazuh agent control binary not found. Skipping restart."
            fi
            ;;
        Darwin)
            if maybe_sudo [ -f "/Library/Ossec/bin/wazuh-control" ]; then
                maybe_sudo /Library/Ossec/bin/wazuh-control restart && info_message "Wazuh agent restarted successfully." || warn_message "Error occurred during Wazuh agent restart."
            else
                warn_message "Wazuh agent control binary not found. Skipping restart."
            fi
            ;;
        *)
            error_message "Unsupported operating system for restarting Wazuh agent."
            exit 1
            ;;
    esac
}

# Remove prebuilt YARA installation (macOS)
remove_prebuilt_yara() {
    local install_dir="/opt/yara"
    if [ -d "$install_dir" ]; then
        info_message "Removing prebuilt YARA installation from ${install_dir}"
        # Remove symlinks
        if [ -L "/usr/local/bin/yara" ]; then
            maybe_sudo rm -f /usr/local/bin/yara
            info_message "Removed yara symlink"
        fi
        if [ -L "/usr/local/bin/yarac" ]; then
            maybe_sudo rm -f /usr/local/bin/yarac
            info_message "Removed yarac symlink"
        fi
        # Remove installation directory
        maybe_sudo rm -rf "$install_dir"
        success_message "Removed prebuilt YARA installation"
    else
        info_message "No prebuilt YARA installation found at ${install_dir}"
    fi
}


# Uninstall YARA for Ubuntu
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
    # Check for prebuilt installation
    remove_prebuilt_yara
}

# Uninstall YARA for RedHat-based systems
uninstall_yara_rhel() {
    info_message "Checking for YARA installation on RedHat-based system..."
    if command -v rpm >/dev/null 2>&1; then
        if rpm -q yara >/dev/null 2>&1; then
            info_message "Detected yum/dnf-installed YARA; uninstalling via yum/dnf"
            if command -v dnf >/dev/null 2>&1; then
                maybe_sudo dnf remove -y yara || {
                    error_message "Failed to remove dnf-installed YARA"
                    exit 1
                }
            else
                maybe_sudo yum remove -y yara || {
                    error_message "Failed to remove yum-installed YARA"
                    exit 1
                }
            fi
            success_message "Yum/dnf-installed YARA removed"
        else
            info_message "No yum/dnf-installed YARA found"
        fi
    fi
}

# Uninstall YARA for macOS
uninstall_yara_macos() {
    info_message "Checking for YARA installation..."
    if command -v yara >/dev/null 2>&1; then
        # Check for Homebrew installation
        if command -v brew >/dev/null 2>&1; then
            if brew_command list yara >/dev/null 2>&1; then
                info_message "Detected Homebrew-installed YARA; uninstalling via brew"
                brew_command unpin yara 2>/dev/null || true
                brew_command uninstall --force yara || {
                    warn_message "Failed to remove Homebrew-installed YARA"
                }
                success_message "Homebrew-installed YARA removed"
            else
                info_message "No Homebrew-installed YARA found"
            fi
        fi
        # Check for prebuilt installation
        remove_prebuilt_yara
    else
        info_message "No YARA installation detected, skipping."
    fi
}

# Uninstall YARA based on OS
uninstall_yara() {
    case "$(uname -s)" in
        Linux)
            # Detect RedHat-based
            if [ -f /etc/os-release ]; then
                . /etc/os-release
                case "$ID" in
                    centos|rhel|redhat|rocky|almalinux|fedora)
                        uninstall_yara_rhel
                        ;;
                    ubuntu|debian)
                        uninstall_yara_ubuntu
                        ;;
                    *)
                        error_message "Unsupported Linux distribution: $ID"
                        exit 1
                        ;;
                esac
            else
                error_message "Cannot determine Linux distribution (missing /etc/os-release)."
                exit 1
            fi
            ;;
        Darwin)
            uninstall_yara_macos
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
    if [ "$(uname -s)" = "Linux" ]; then
        YARA_DIR="/var/ossec/ruleset/yara"
        YARA_SCRIPT="/var/ossec/active-response/bin/yara.sh"
        OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
    elif [ "$(uname -s)" = "Darwin" ]; then
        YARA_DIR="/Library/Ossec/ruleset/yara"
        YARA_SCRIPT="/Library/Ossec/active-response/bin/yara.sh"
        OSSEC_CONF_PATH="/Library/Ossec/etc/ossec.conf"
    else
        error_message "Unsupported OS. Exiting..."
        exit 1
    fi

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

# Main uninstallation steps
info_message "Starting YARA uninstallation process..."
uninstall_yara
remove_yara_components
restart_wazuh_agent
# Validate uninstallation
if command -v yara >/dev/null 2>&1; then
    error_message "YARA is still installed at $(which yara). Uninstallation failed."
    exit 1
fi
success_message "Uninstallation process completed successfully."