#!/bin/sh

# Check if we're running in bash; if not, adjust behavior
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

LOG_LEVEL=${LOG_LEVEL:-INFO}

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

# Stop wazuh agent
stop_wazuh_agent() {
    info_message "Stopping wazuh agent..."
    case "$(uname)" in
        Linux)
            if maybe_sudo /var/ossec/bin/wazuh-control stop >/dev/null 2>&1; then
                info_message "Wazuh agent stopped successfully."
            else
                error_message "Error occurred during Wazuh agent stop."
            fi
            ;;
        Darwin)
            if maybe_sudo /Library/Ossec/bin/wazuh-control stop >/dev/null 2>&1; then
                info_message "Wazuh agent stopped successfully."
            else
                error_message "Error occurred during Wazuh agent stop."
            fi
            ;;
        *)
            error_message "Unsupported operating system for restarting Wazuh agent."
            exit 1
            ;;
    esac
}

# Restart wazuh agent
restart_wazuh_agent() {
    info_message "Restarting wazuh agent..."
    case "$(uname)" in
        Linux)
            if maybe_sudo /var/ossec/bin/wazuh-control restart >/dev/null 2>&1; then
                info_message "Wazuh agent restarted successfully."
            else
                error_message "Error occurred during Wazuh agent restart."
            fi
            ;;
        Darwin)
            if maybe_sudo /Library/Ossec/bin/wazuh-control restart >/dev/null 2>&1; then
                info_message "Wazuh agent restarted successfully."
            else
                error_message "Error occurred during Wazuh agent restart."
            fi
            ;;
        *)
            error_message "Unsupported operating system for restarting Wazuh agent."
            exit 1
            ;;
    esac
}


# Remove YARA and dependencies based on the package manager
uninstall_yara_ubuntu() {
    maybe_sudo apt remove -y yara
    maybe_sudo apt autoremove -y
}

uninstall_yara_alpine() {
    maybe_sudo apk del yara
}

uninstall_yara_centos() {
    maybe_sudo yum remove -y yara
}

uninstall_yara_fedora() {
    maybe_sudo dnf remove -y yara
}

uninstall_yara_suse() {
    maybe_sudo zypper remove -y yara
}

uninstall_yara_arch() {
    maybe_sudo pacman -Rns --noconfirm yara
}

uninstall_yara_macos() {
    brew uninstall yara || info_message "Some components may already be uninstalled."
}

# Remove YARA based on the operating system
uninstall_yara() {
    info_message "Removing YARA..."
    case "$(uname)" in
        Linux)
            if command -v apt >/dev/null 2>&1; then
                uninstall_yara_ubuntu
            elif command -v apk >/dev/null 2>&1; then
                uninstall_yara_alpine
            elif command -v yum >/dev/null 2>&1; then
                uninstall_yara_centos
            elif command -v dnf >/dev/null 2>&1; then
                uninstall_yara_fedora
            elif command -v zypper >/dev/null 2>&1; then
                uninstall_yara_suse
            elif command -v pacman >/dev/null 2>&1; then
                uninstall_yara_arch
            else
                error_message "Unsupported Linux distribution. Exiting..."
                exit 1
            fi
            ;;
        Darwin)
            uninstall_yara_macos
            ;;
        *)
            error_message "Unsupported operating system. Exiting..."
            exit 1
            ;;
    esac
    info_message "Yara successfully removed."
}

# Remove YARA rules and scripts
remove_yara_components() {
    info_message "Removing YARA rules and scripts..."

    if [ "$(uname)" = "Linux" ]; then
        YARA_DIR="/var/ossec/ruleset/yara"
        YARA_SCRIPT="/var/ossec/active-response/bin/yara.sh"
    elif [ "$(uname)" = "Darwin" ]; then
        YARA_DIR="/Library/Ossec/ruleset/yara"
        YARA_SCRIPT="/Library/Ossec/active-response/bin/yara.sh"
    else
        error_message "Unsupported OS. Exiting..."
        exit 1
    fi

    if maybe_sudo [ -d "$YARA_DIR" ]; then
        maybe_sudo rm -rf "$YARA_DIR"
        info_message "Removed YARA directory: $YARA_DIR"
    else
        warn_message "YARA directory not found: $YARA_DIR"
    fi

    if maybe_sudo [ -f "$YARA_SCRIPT" ]; then
        maybe_sudo rm -f "$YARA_SCRIPT"
        info_message "Removed YARA script: $YARA_SCRIPT"
    else
        warn_message "YARA script not found: $YARA_SCRIPT"
    fi
}

# Main uninstallation steps
stop_wazuh_agent
if command -v apt >/dev/null 2>&1; then
    uninstall_yara
else
    info_message "Yara is not installed."
fi
remove_yara_components
restart_wazuh_agent

success_message "Uninstallation process completed successfully."
