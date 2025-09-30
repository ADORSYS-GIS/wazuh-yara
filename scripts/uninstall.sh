#!/bin/sh

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

# OS and Distribution Detection
case "$(uname)" in
Linux)
    OS="linux"
    ;;
Darwin)
    OS="darwin"
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

    # Check for unsupported RPM-based distributions
    case "$DISTRO" in
        centos|rhel|redhat|rocky|almalinux|fedora)
            error_message "Unsupported Linux distribution: $DISTRO"
            error_message "This script only supports Ubuntu and Debian distributions"
            exit 1
            ;;
    esac
fi



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

# Remove source-installed YARA (Linux)
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

# Uninstall YARA for Ubuntu/Debian
uninstall_yara_ubuntu() {
    info_message "Checking for YARA installation on Ubuntu/Debian..."
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
    # Check for source-installed YARA
    remove_source_yara
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

# Uninstall YARA based on OS and distribution
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
                uninstall_yara_ubuntu # fallback if cannot detect
            fi
            ;;
        Darwin)
            uninstall_yara_macos
            ;;
        *)
            error_message "Unsupported operating system: $OS"
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
        local directories
        if [ "$(uname -s)" = "Darwin" ]; then
            directories="/Users, /Applications"
        else
            directories="/home, /root, /bin, /sbin"
        fi
        if maybe_sudo grep -q "<directories realtime=\"yes\">$directories</directories>" "$OSSEC_CONF_PATH"; then
            sed_alternative -i "/<directories realtime=\"yes\">$directories<\/directories>/d" "$OSSEC_CONF_PATH" || {
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
info_message "Detected OS: ${OS}"
if [ "$OS" = "linux" ]; then
    info_message "Detected Linux distribution: ${DISTRO}"
fi
uninstall_yara
remove_yara_components
remove_ossec_configuration
restart_wazuh_agent
# Validate uninstallation
if command -v yara >/dev/null 2>&1; then
    error_message "YARA is still installed at $(which yara). Uninstallation failed."
    exit 1
fi
success_message "Uninstallation process completed successfully."