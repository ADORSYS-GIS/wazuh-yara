#!/bin/bash

# Exit on error, undefined variables, and pipeline errors
set -euo pipefail

# Configuration variables
LOG_LEVEL=${LOG_LEVEL:-INFO}
USER="root"
GROUP="wazuh"
YARA_VERSION="${1:-4.5.4}"
YARA_URL="https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz"
YARA_SH_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/yara.sh"
OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
WAZUH_CONTROL_BIN_PATH="/var/ossec/bin/wazuh-control"
YARA_SH_PATH="/var/ossec/active-response/bin/yara.sh"
DOWNLOADS_DIR="/tmp/yara-install"
TAR_DIR="$DOWNLOADS_DIR/yara-${YARA_VERSION}.tar.gz"
EXTRACT_DIR="$DOWNLOADS_DIR/yara-${YARA_VERSION}"
NOTIFY_SEND_VERSION=0.8.3

# Text formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
BOLD='\033[1m'
NORMAL='\033[0m'

# Logging functions
log() {
    local LEVEL="$1"
    shift
    local MESSAGE="$*"
    local TIMESTAMP
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "${TIMESTAMP} ${LEVEL} ${MESSAGE}"
}

info_message() { log "${BLUE}${BOLD}[INFO]${NORMAL}" "$*"; }
warn_message() { log "${YELLOW}${BOLD}[WARNING]${NORMAL}" "$*"; }
error_message() { log "${RED}${BOLD}[ERROR]${NORMAL}" "$*"; }
success_message() { log "${GREEN}${BOLD}[SUCCESS]${NORMAL}" "$*"; }
print_step() { log "${BLUE}${BOLD}[STEP]${NORMAL}" "$1: $2"; }

# Utility functions
command_exists() { command -v "$1" >/dev/null 2>&1; }
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
sed_alternative() { maybe_sudo sed "$@"; }

# Create temporary directory
TMP_DIR=$(mktemp -d)
cleanup() {
    info_message "Cleaning up temporary files..."
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Create downloads directory
mkdir -p "$DOWNLOADS_DIR"

# Ensure user and group exist
ensure_user_group() {
    info_message "Ensuring that the $USER:$GROUP user and group exist..."
    if ! id -u "$USER" >/dev/null 2>&1; then
        info_message "Creating user $USER..."
        maybe_sudo useradd -m "$USER"
    fi
    if ! getent group "$GROUP" >/dev/null 2>&1; then
        info_message "Creating group $GROUP..."
        maybe_sudo groupadd "$GROUP"
    fi
}

# Change ownership
change_owner() {
    local path="$1"
    ensure_user_group
    maybe_sudo chown -R "$USER:$GROUP" "$path"
}

# Restart Wazuh agent
restart_wazuh_agent() {
    if maybe_sudo "$WAZUH_CONTROL_BIN_PATH" restart >/dev/null 2>&1; then
        success_message "Wazuh agent restarted successfully."
    else
        error_message "Error occurred during Wazuh agent restart."
        exit 1
    fi
}

# Remove file_limit block from ossec.conf
remove_file_limit() {
    if maybe_sudo grep -q "<file_limit>" "$OSSEC_CONF_PATH"; then
        sed_alternative -i "/<file_limit>/,/<\/file_limit>/d" "$OSSEC_CONF_PATH" || {
            error_message "Error occurred during removal of file_limit block."
            exit 1
        }
        info_message "File limit block removed successfully."
    else
        info_message "File limit block does not exist."
    fi
}

# Download yara.sh script
download_yara_script() {
    maybe_sudo mkdir -p "$(dirname "$YARA_SH_PATH")"
    maybe_sudo curl -SL --progress-bar "$YARA_SH_URL" -o "$TMP_DIR/yara.sh" || {
        error_message "Failed to download yara.sh script."
        exit 1
    }
    maybe_sudo mv "$TMP_DIR/yara.sh" "$YARA_SH_PATH"
    change_owner "$YARA_SH_PATH"
    maybe_sudo chmod 750 "$YARA_SH_PATH"
    success_message "yara.sh script installed successfully."
}

# Reverse update ossec.conf
reverse_update_ossec_conf() {
    if maybe_sudo grep -q '<directories realtime="yes">/home, /root, /bin, /sbin</directories>' "$OSSEC_CONF_PATH"; then
        info_message "Removing existing YARA configuration..."
        sed_alternative -i '/<directories realtime="yes">\/home, \/root, \/bin, \/sbin<\/directories>/d' "$OSSEC_CONF_PATH" || {
            error_message "Error occurred during removal of directories."
            exit 1
        }
        info_message "YARA configuration removed successfully."
    fi
    remove_file_limit
}

# Install YARA on Ubuntu
install_yara_ubuntu() {
    print_step "1" "Installing YARA v${YARA_VERSION} from source on Ubuntu"
    maybe_sudo apt update -qq
    maybe_sudo apt install -y automake libtool make gcc pkg-config flex bison curl libjansson-dev libmagic-dev libssl-dev
    print_step "2" "Downloading YARA $YARA_VERSION"
    curl -fsSL -o "$TAR_DIR" "$YARA_URL" || {
        error_message "Failed to download YARA source tarball"
        exit 1
    }
    print_step "3" "Extracting source"
    maybe_sudo rm -rf "$EXTRACT_DIR"
    mkdir -p "$EXTRACT_DIR"
    tar -xzf "$TAR_DIR" -C "$DOWNLOADS_DIR" || {
        error_message "Failed to extract YARA tarball"
        exit 1
    }
    print_step "4" "Building & installing"
    pushd "$EXTRACT_DIR" >/dev/null
    maybe_sudo ./bootstrap.sh
    maybe_sudo ./configure --disable-silent-rules --enable-cuckoo --enable-magic --enable-dotnet --enable-macho --enable-dex --with-crypto
    maybe_sudo make
    maybe_sudo make install
    maybe_sudo make check
    maybe_sudo ldconfig
    popd >/dev/null
    success_message "YARA v${YARA_VERSION} installed successfully on Ubuntu."
}

# Install YARA on CentOS
install_yara_centos() {
    print_step "1" "Installing YARA v${YARA_VERSION} from source on CentOS"
    maybe_sudo yum install -y epel-release
    maybe_sudo yum groupinstall -y "Development Tools"
    maybe_sudo yum install -y automake libtool gcc gcc-c++ pkgconfig flex bison curl jansson-devel file-devel openssl-devel
    print_step "2" "Downloading YARA $YARA_VERSION"
    curl -fsSL -o "$TAR_DIR" "$YARA_URL" || {
        error_message "Failed to download YARA source tarball"
        exit 1
    }
    print_step "3" "Extracting source"
    maybe_sudo rm -rf "$EXTRACT_DIR"
    mkdir -p "$EXTRACT_DIR"
    tar -xzf "$TAR_DIR" -C "$DOWNLOADS_DIR" || {
        error_message "Failed to extract YARA tarball"
        exit 1
    }
    print_step "4" "Building & installing"
    pushd "$EXTRACT_DIR" >/dev/null
    maybe_sudo ./bootstrap.sh
    maybe_sudo ./configure --disable-silent-rules --enable-cuckoo --enable-magic --enable-dotnet --enable-macho --enable-dex --with-crypto
    maybe_sudo make
    maybe_sudo make install
    maybe_sudo make check
    maybe_sudo ldconfig
    popd >/dev/null
    success_message "YARA v${YARA_VERSION} installed successfully on CentOS."
}

# Install YARA based on distribution
install_yara() {
    if command_exists apt; then
        install_yara_ubuntu
    elif command_exists yum; then
        install_yara_centos
    else
        error_message "Unsupported Linux distribution. Exiting..."
        exit 1
    fi
}

# Install YARA and tools
install_yara_and_tools() {
    if command_exists yara; then
        current_version=$(yara --version 2>/dev/null || echo "unknown")
        if [ "$current_version" = "$YARA_VERSION" ]; then
            info_message "YARA version $YARA_VERSION is already installed."
        else
            info_message "Different YARA version detected ($current_version). Reinstalling..."
            install_yara
        fi
    else
        info_message "Installing YARA..."
        install_yara
    fi
    maybe_sudo rm -rf "$DOWNLOADS_DIR"
}

# Download YARA rules
download_yara_rules() {
    YARA_RULES_FILE="$TMP_DIR/yara_rules.yar"
    YARA_RULES_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/refs/heads/main/rules/yara_rules.yar"
    maybe_sudo curl -SL --progress-bar "$YARA_RULES_URL" -o "$YARA_RULES_FILE"
    YARA_RULES_DEST_DIR="/var/ossec/ruleset/yara/rules"
    if [ -s "$YARA_RULES_FILE" ]; then
        maybe_sudo mkdir -p "$YARA_RULES_DEST_DIR"
        maybe_sudo mv "$YARA_RULES_FILE" "$YARA_RULES_DEST_DIR/yara_rules.yar"
        change_owner "$YARA_RULES_DEST_DIR"
        success_message "YARA rules installed to $YARA_RULES_DEST_DIR."
    else
        error_message "Failed to download YARA rules."
        exit 1
    fi
}

# Validate installation
validate_installation() {
    VALIDATION_STATUS="TRUE"
    if command_exists yara; then
        actual_version=$(yara --version)
        if [ "$actual_version" = "$YARA_VERSION" ]; then
            success_message "YARA version $YARA_VERSION is installed."
        else
            warn_message "YARA version mismatch. Expected $YARA_VERSION, found $actual_version."
            VALIDATION_STATUS="FALSE"
        fi
    else
        error_message "YARA command is not available."
        VALIDATION_STATUS="FALSE"
    fi
    if [ ! -f "$YARA_RULES_DEST_DIR/yara_rules.yar" ]; then
        warn_message "YARA rules not present at $YARA_RULES_DEST_DIR/yara_rules.yar."
        VALIDATION_STATUS="FALSE"
    else
        success_message "YARA rules exist at $YARA_RULES_DEST_DIR/yara_rules.yar."
    fi
    if [ ! -f "$YARA_SH_PATH" ]; then
        warn_message "YARA active response script not present at $YARA_SH_PATH."
        VALIDATION_STATUS="FALSE"
    else
        success_message "YARA active response script exists at $YARA_SH_PATH."
    fi
    if [ "$VALIDATION_STATUS" = "TRUE" ]; then
        success_message "YARA installation and configuration validated successfully."
    else
        error_message "YARA installation and configuration validation failed."
        exit 1
    fi
}

# Main execution
print_step 1 "Installing YARA and necessary tools..."
install_yara_and_tools
print_step 2 "Downloading YARA rules..."
download_yara_rules
print_step 3 "Downloading yara.sh script..."
download_yara_script
print_step 4 "Updating Wazuh agent configuration file..."
if [ -f "$OSSEC_CONF_PATH" ]; then
    reverse_update_ossec_conf
else
    warn_message "OSSEC configuration file not found at $OSSEC_CONF_PATH."
fi
print_step 5 "Restarting Wazuh agent..."
restart_wazuh_agent
print_step 6 "Validating installation and configuration..."
validate_installation