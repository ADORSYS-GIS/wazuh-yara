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

# Restart wazuh agent
restart_wazuh_agent() {
    info_message "Restarting wazuh agent..."
    case "$(uname)" in
        Linux)
            if maybe_sudo [ -f "/var/ossec/bin/wazuh-control" ]; then
                maybe_sudo /var/ossec/bin/wazuh-control restart && info_message "Wazuh agent restarted successfully." || warn_message "Error occurred during Wazuh agent restart."
            else
                info_message "Wazuh agent control binary not found. Skipping restart."
            fi
            ;;
        Darwin)
            if maybe_sudo [ -f "/Library/Ossec/bin/wazuh-control" ]; then
                maybe_sudo /Library/Ossec/bin/wazuh-control restart && info_message "Wazuh agent restarted successfully." || warn_message "Error occurred during Wazuh agent restart."
            else
                info_message "Wazuh agent control binary not found. Skipping restart."
            fi
            ;;
        *)
            error_message "Unsupported operating system for restarting Wazuh agent."
            exit 1
            ;;
    esac
}

# Uninstall YARA based on package manager
uninstall_yara() {
    info_message "Removing YARA..."
    if command -v yara >/dev/null 2>&1; then
        case "$(uname)" in
            Linux)
                if command -v apt >/dev/null 2>&1; then
                    maybe_sudo apt purge -y yara && maybe_sudo apt autoremove -y
                elif command -v apk >/dev/null 2>&1; then
                    maybe_sudo apk del yara
                elif command -v yum >/dev/null 2>&1; then
                    maybe_sudo yum remove -y yara
                elif command -v dnf >/dev/null 2>&1; then
                    maybe_sudo dnf remove -y yara
                elif command -v zypper >/dev/null 2>&1; then
                    maybe_sudo zypper remove -y yara
                elif command -v pacman >/dev/null 2>&1; then
                    maybe_sudo pacman -Rns --noconfirm yara
                else
                    error_message "Unsupported Linux distribution."
                    exit 1
                fi
                ;;
            Darwin)
                brew list yara >/dev/null 2>&1 && brew uninstall yara || info_message "Yara is not installed."
                ;;
            *)
                error_message "Unsupported operating system. Exiting..."
                exit 1
                ;;
        esac
        info_message "Yara successfully removed."
    else
        warn_message "Yara is not installed. Skipping uninstallation."
    fi
}

# Remove YARA rules and scripts
remove_yara_components() {
    info_message "Removing YARA rules and scripts..."
    if [ "$(uname)" = "Linux" ]; then
        YARA_DIR="/var/ossec/ruleset/yara"
        YARA_SCRIPT="/var/ossec/active-response/bin/yara.sh"
        OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
    elif [ "$(uname)" = "Darwin" ]; then
        YARA_DIR="/Library/Ossec/ruleset/yara"
        YARA_SCRIPT="/Library/Ossec/active-response/bin/yara.sh"
        OSSEC_CONF_PATH="/Library/Ossec/etc/ossec.conf"
    else
        error_message "Unsupported OS. Exiting..."
        exit 1
    fi

    [ -d "$YARA_DIR" ] && maybe_sudo rm -rf "$YARA_DIR" && info_message "Removed YARA directory: $YARA_DIR" || warn_message "YARA directory not found."
    [ -f "$YARA_SCRIPT" ] && maybe_sudo rm -f "$YARA_SCRIPT" && info_message "Removed YARA script: $YARA_SCRIPT" || warn_message "YARA script not found."
}

# Remove ossec configuration modifications
remove_ossec_configuration() {
    info_message "Removing OSSEC configuration modifications..."
    
    # Check and remove added file_limit block
    if maybe_sudo grep -q '<file_limit>' "$OSSEC_CONF_PATH"; then
        sed_alternative -i '/<!-- Maximum number of files to be monitored -->/,/<\/file_limit>/d' "$OSSEC_CONF_PATH" || {
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
}

# Main uninstallation steps
uninstall_yara
remove_yara_components
remove_ossec_configuration
restart_wazuh_agent

success_message "Uninstallation process completed successfully."
