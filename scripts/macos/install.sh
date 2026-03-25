#!/usr/bin/env bash

#=============================================================================
# Enhanced YARA Installation Script for macOS
# Detects existing YARA installations and performs automatic cleanup
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
print_step() {
    log "${BLUE}${BOLD}[STEP]${NORMAL}" "$1: $2"
}

# Prompt user for installation type
prompt_installation_type() {
    if [[ -n "${INSTALLATION_TYPE:-}" ]]; then
        if [[ "$INSTALLATION_TYPE" == "desktop" ]]; then
            YARA_SOURCE_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/refs/heads/refactor/split-linux-macos-scripts/scripts/macos/yara.sh"
            info_message "Using Desktop/Workstation installation (non-interactive mode)"
            return 0
        elif [[ "$INSTALLATION_TYPE" == "server" ]]; then
            YARA_SOURCE_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/refs/heads/refactor/split-linux-macos-scripts/scripts/macos/yara-server.sh"
            info_message "Using Server installation (non-interactive mode)"
            return 0
        fi
    fi

    echo ""
    info_message "Please select the installation type:"
    echo "  1) Desktop/Workstation (with user notifications)"
    echo "  2) Server (no user notifications, logging only)"
    echo ""
    while true; do
        read -rp "Enter your choice [1-2] (default: 1): " choice
        choice=${choice:-1}
        case "$choice" in
            1)
                INSTALLATION_TYPE="desktop"
                YARA_SOURCE_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/refs/heads/refactor/split-linux-macos-scripts/scripts/macos/yara.sh"
                info_message "Selected: Desktop/Workstation installation"
                return 0
                ;;
            2)
                INSTALLATION_TYPE="server"
                YARA_SOURCE_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/refs/heads/refactor/split-linux-macos-scripts/scripts/macos/yara-server.sh"
                info_message "Selected: Server installation"
                return 0
                ;;
            *)
                warn_message "Invalid choice. Please enter 1 or 2."
                ;;
        esac
    done
}

# Check if we're running in bash; if not, adjust behavior
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

# Configuration
YARA_VERSION="4.5.5"
YARA_VERSION_SET=0
YARA_SCRIPT_NAME="yara.sh"
YARA_RULES_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/rules/yara_rules.yar"

# GitHub Release configuration for packages
GITHUB_RELEASE_BASE_URL="https://github.com/ADORSYS-GIS/wazuh-plugins/releases/download"
MACOS_RELEASE_TAG="yara-v0.5.1"

TMP_DIR=$(mktemp -d)

# OS Detection
OS="darwin"
OSSEC_CONF_PATH="/Library/Ossec/etc/ossec.conf"
LOGGED_IN_USER=$(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ {print $3}')

# Cleanup function
cleanup() {
    info_message "Cleaning up temporary files..."
    rm -rf "$TMP_DIR"

    if [ -d "./yara-install" ]; then
        rm -rf "./yara-install"
    elif [ -n "${HOME:-}" ] && [ -d "$HOME/yara-install" ]; then
        rm -rf "$HOME/yara-install"
    fi
}

# Register cleanup to run on exit
trap cleanup EXIT

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Detect system architecture
detect_architecture() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)
            echo "amd64"
            ;;
        aarch64|arm64)
            echo "arm64"
            ;;
        *)
            error_message "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
}

# Check if version matches 4.5.x pattern
version_is_4_5_x() {
    local version="$1"
    local major minor
    major=$(echo "$version" | cut -d'.' -f1)
    minor=$(echo "$version" | cut -d'.' -f2)

    [ "$major" = "4" ] && [ "$minor" = "5" ]
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

# Sed in-place for macOS
sed_inplace() {
    maybe_sudo sed -i '' "$@" 2>/dev/null || true
}

#=============================================================================
# PRE-INSTALLATION CHECKS
#=============================================================================

# Detect YARA installations
detect_yara_installation() {
    local has_legacy=0
    local has_modern=0
    local has_softlink=0

    exec 3>&1 4>&2
    exec 1>/dev/null 2>/dev/null

    if [ -d "/opt/yara" ]; then
        has_legacy=1
    fi

    if [ -d "/opt/wazuh/yara" ]; then
        has_modern=1
    fi

    if [ -L "/usr/local/bin/yara" ] || [ -f "/usr/local/bin/yara" ]; then
        has_softlink=1
    fi

    exec 1>&3 2>&4
    exec 3>&- 4>&-

    echo "${has_legacy},${has_modern},${has_softlink}"
}

# Download and run uninstallation script from GitHub
run_local_uninstall() {
    local uninstall_script="$TMP_DIR/uninstall.sh"
    local uninstall_url="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/refactor/split-linux-macos-scripts/scripts/macos/uninstall.sh"

    info_message "Downloading uninstall script from GitHub..."

    if ! curl -fsSL "$uninstall_url" -o "$uninstall_script"; then
        error_message "Failed to download uninstall script from $uninstall_url"
        return 1
    fi

    success_message "Uninstall script downloaded successfully"

    info_message "Running uninstallation script..."
    if bash "$uninstall_script"; then
        success_message "Uninstallation completed successfully"
        return 0
    else
        error_message "Uninstallation script failed"
        return 1
    fi
}

# Pre-installation check and automatic cleanup
pre_installation_check() {
    info_message "Performing pre-installation checks..."

    local detection_result
    detection_result=$(detect_yara_installation)

    IFS=',' read -r has_legacy has_modern has_softlink <<< "$detection_result"

    if [ "$has_modern" -eq 1 ]; then
        if [ -f "/opt/wazuh/yara/bin/yara" ]; then
            local current_version
            current_version=$(/opt/wazuh/yara/bin/yara --version 2>/dev/null || echo "")

            if [ -n "$current_version" ] && version_is_4_5_x "$current_version"; then
                success_message "Valid YARA installation found (v${current_version})"
                info_message "Skipping new installation, will proceed to configuration checks..."
                return 2
            fi

            info_message "Existing YARA version ($current_version) does not match target v${YARA_VERSION}"
        fi
    fi

    if [ "$has_legacy" -eq 0 ] && [ "$has_modern" -eq 0 ]; then
        success_message "No existing YARA installation detected"
        success_message "System is ready for fresh installation"
        return 0
    fi

    echo ""
    warn_message "Existing YARA installation(s) detected!"

    if [ -d "/opt/yara" ]; then
        info_message "Found YARA in path: /opt/yara"
    fi

    if [ -d "/opt/wazuh/yara" ]; then
        info_message "Found YARA in path: /opt/wazuh/yara"
    fi

    if [ -L "/usr/local/bin/yara" ] || [ -f "/usr/local/bin/yara" ]; then
        info_message "Found YARA in path: /usr/local/bin/yara"
    fi

    echo ""
    info_message "Running uninstallation script to clean up existing installations..."

    if ! run_local_uninstall; then
        error_message "Failed to remove existing YARA installation(s)"
        exit 1
    fi

    echo ""
    success_message "Pre-installation cleanup completed"
    success_message "System is ready for fresh YARA installation"
    echo ""

    sleep 2

    return 0
}

#=============================================================================
# INSTALLATION FUNCTIONS
#=============================================================================

# Remove file limit from ossec.conf
remove_file_limit() {
    if maybe_sudo grep -q "<file_limit>" "$OSSEC_CONF_PATH" 2>/dev/null; then
        sed_inplace "/<file_limit>/,/<\/file_limit>/d" "$OSSEC_CONF_PATH"
        info_message "The file limit block was removed successfully."
    else
        info_message "The file limit block does not exist. No changes were made."
    fi
}

# Install dependencies via Homebrew or MacPorts
install_dependencies() {
    info_message "Installing dependencies..."
    print_step 1 "Installing dependencies on macOS"

    if command_exists brew; then
        if [ "$(id -u)" -eq 0 ] && [ -n "$LOGGED_IN_USER" ] && [ "$LOGGED_IN_USER" != "loginwindow" ]; then
            sudo -u "$LOGGED_IN_USER" brew install libmagic openssl@3 2>/dev/null || warn_message "Could not install dependencies via Homebrew"
        elif [ "$(id -u)" -ne 0 ]; then
            brew install libmagic openssl@3 2>/dev/null || warn_message "Could not install dependencies via Homebrew"
        else
            warn_message "Cannot install dependencies via Homebrew as root without a logged in user"
        fi
    elif command_exists port; then
        maybe_sudo port install libmagic openssl3 2>/dev/null || warn_message "Could not install dependencies via MacPorts"
    else
        warn_message "Neither Homebrew nor MacPorts found. Please install libmagic and openssl manually."
    fi

    success_message "Dependencies installation attempted successfully"
}

# Download file with error checking
download_file() {
    local url="$1"
    local output="$2"
    local description="$3"

    info_message "Downloading $description..."
    local output_dir
    output_dir=$(dirname "$output")
    if ! maybe_sudo mkdir -p "$output_dir"; then
        error_message "Failed to create directory for $description: $output_dir"
        return 1
    fi

    if curl -fsSL "$url" | maybe_sudo tee "$output" > /dev/null; then
        success_message "$description downloaded successfully"
        return 0
    else
        error_message "Failed to download $description from $url"
        error_message "Please check your network connection and URL validity"
        return 1
    fi
}

# Download YARA DMG for macOS based on architecture
download_yara_macos_dmg() {
    local arch="$1"
    local url="${GITHUB_RELEASE_BASE_URL}/${MACOS_RELEASE_TAG}/yara-v${YARA_VERSION}-macos-${arch}.dmg"

    print_step 1 "Downloading YARA DMG for macOS $arch"
    download_file "$url" "$TMP_DIR/yara.dmg" "YARA DMG" || exit 1
}

# Install YARA from DMG on macOS
install_yara_macos_dmg() {
    local arch="$1"
    info_message "Installing YARA from DMG on macOS ($arch)..."

    local mount_point="/Volumes/YARA_Installer"

    print_step 1 "Mounting YARA DMG"
    if ! maybe_sudo hdiutil attach "$TMP_DIR/yara.dmg" -mountpoint "$mount_point" -quiet; then
        error_message "Failed to mount YARA DMG"
        exit 1
    fi

    print_step 2 "Installing YARA binary"
    maybe_sudo mkdir -p "/opt/wazuh/yara/bin/"

    local yara_binary=""
    if [ -f "$mount_point/yara" ]; then
        yara_binary="$mount_point/yara"
    else
        yara_binary=$(find "$mount_point" -name "yara" -type f -perm +111 2>/dev/null | head -n 1)
    fi

    if [ -z "$yara_binary" ] || [ ! -f "$yara_binary" ]; then
        maybe_sudo hdiutil detach "$mount_point" -quiet
        error_message "Could not find YARA binary in DMG"
        exit 1
    fi

    maybe_sudo cp "$yara_binary" "/opt/wazuh/yara/bin/"
    maybe_sudo hdiutil detach "$mount_point" -quiet

    print_step 3 "Setting permissions"
    maybe_sudo chmod 755 "/opt/wazuh/yara/bin/yara"
    maybe_sudo chown root:wheel "/opt/wazuh/yara/bin/yara" 2>/dev/null || \
    maybe_sudo chown root:staff "/opt/wazuh/yara/bin/yara" 2>/dev/null || \
    maybe_sudo chown root:root "/opt/wazuh/yara/bin/yara"

    maybe_sudo mkdir -p /usr/local/bin
    maybe_sudo ln -sf "/opt/wazuh/yara/bin/yara" /usr/local/bin/yara
    maybe_sudo chmod 755 /usr/local/bin/yara

    if [ -f "/opt/wazuh/yara/bin/yara" ]; then
        info_message "DEBUG: YARA binary verified at /opt/wazuh/yara/bin/yara"
        maybe_sudo ls -l "/opt/wazuh/yara/bin/yara"
    else
        error_message "DEBUG: YARA binary MISSING at /opt/wazuh/yara/bin/yara immediately after install"
        maybe_sudo ls -R "/opt/wazuh/yara/"
    fi

    success_message "YARA installed successfully from DMG on macOS"
}

# Setup YARA directories and components
setup_yara_components() {
    info_message "Setting up YARA components..."

    local yara_script_path="/Library/Ossec/active-response/bin/${YARA_SCRIPT_NAME}"
    local yara_rules_path="/Library/Ossec/ruleset/yara/rules"

    print_step 1 "Creating directories"
    if ! maybe_sudo mkdir -p "/Library/Ossec/active-response/bin/"; then
        error_message "Failed to create directory: /Library/Ossec/active-response/bin/"
        exit 1
    fi

    if ! maybe_sudo mkdir -p "$yara_rules_path/"; then
        error_message "Failed to create directory: $yara_rules_path/"
        exit 1
    fi

    print_step 2 "Downloading and configuring YARA script"
    if ! download_file "$YARA_SOURCE_URL" "$yara_script_path" "YARA script"; then
        error_message "Failed to download YARA script"
        exit 1
    fi

    if [ "$INSTALLATION_TYPE" = "desktop" ]; then
        sed_inplace 's|YARA_PATH="/usr/local/bin"|YARA_PATH="/opt/wazuh/yara/bin"|g' "$yara_script_path"
        sed_inplace 's|YARA_PATH="/opt/yara/bin"|YARA_PATH="/opt/wazuh/yara/bin"|g' "$yara_script_path"
    fi

    print_step 3 "Downloading YARA rules"
    if ! download_file "$YARA_RULES_URL" "$yara_rules_path/yara_rules.yar" "YARA rules"; then
        error_message "Failed to download YARA rules"
        exit 1
    fi

    print_step 4 "Setting permissions"
    if ! maybe_sudo chmod 750 "$yara_script_path"; then
        error_message "Failed to set permissions on $yara_script_path"
        exit 1
    fi

    maybe_sudo chown root:wheel "$yara_script_path" 2>/dev/null || \
    maybe_sudo chown root:staff "$yara_script_path" 2>/dev/null || \
    maybe_sudo chown root:root "$yara_script_path"

    maybe_sudo chown root:wheel "$yara_rules_path/yara_rules.yar" 2>/dev/null || \
    maybe_sudo chown root:staff "$yara_rules_path/yara_rules.yar" 2>/dev/null || \
    maybe_sudo chown root:root "$yara_rules_path/yara_rules.yar"

    maybe_sudo chown root:wheel "$yara_rules_path" 2>/dev/null || \
    maybe_sudo chown root:staff "$yara_rules_path" 2>/dev/null || \
    maybe_sudo chown root:root "$yara_rules_path"

    success_message "YARA components set up successfully"
}

# Validate installation
validate_installation() {
    info_message "Validating YARA installation..."
    local validation_failed=0

    local yara_found=0 actual_version=""

    if command_exists yara; then
        actual_version=$(yara --version 2>&1 || echo "")
        yara_found=1
    elif [ -f "/opt/wazuh/yara/bin/yara" ]; then
        actual_version=$(/opt/wazuh/yara/bin/yara --version 2>&1 || echo "")
        yara_found=1
    fi

    if [ $yara_found -eq 1 ] && [[ "$actual_version" =~ [0-9]+\.[0-9]+\.[0-9]+ ]]; then
        if version_is_4_5_x "$actual_version"; then
            success_message "YARA version $actual_version is installed (4.5.x series)."
        else
            warn_message "YARA version $actual_version is not compatible. Version 4.5.x is required."
            validation_failed=1
        fi
    else
        error_message "YARA command is not available or failed to run."
        error_message "Output was: $actual_version"

        info_message "DEBUG: Checking /opt/wazuh/yara/bin/yara..."
        if [ -f "/opt/wazuh/yara/bin/yara" ]; then
            info_message "DEBUG: File exists."
            info_message "DEBUG: Checking file type:"
            file /opt/wazuh/yara/bin/yara || true
            info_message "DEBUG: Checking shared libraries:"
            otool -L /opt/wazuh/yara/bin/yara || true
        else
            error_message "DEBUG: File does NOT exist."
        fi
        validation_failed=1
    fi

    local yara_rules_path="/Library/Ossec/ruleset/yara/rules/yara_rules.yar"
    local yara_script_path="/Library/Ossec/active-response/bin/${YARA_SCRIPT_NAME}"

    if ! maybe_sudo test -f "$yara_rules_path"; then
        warn_message "YARA rules file not present at $yara_rules_path."
        validation_failed=1
    else
        success_message "YARA rules file exists at $yara_rules_path."
    fi

    if ! maybe_sudo test -f "$yara_script_path"; then
        warn_message "YARA active response script not present at $yara_script_path."
        validation_failed=1
    else
        success_message "YARA active response script exists at $yara_script_path."
    fi

    if [ $validation_failed -eq 0 ]; then
        success_message "YARA installation and configuration validation completed successfully."
    else
        error_message "YARA installation and configuration validation failed."
        exit 1
    fi
}

# Check disk space
check_disk_space() {
    local required_space=102400
    local available_space
    available_space=$(df /tmp | awk 'NR==2 {print $4}')

    if [ "$available_space" -lt "$required_space" ]; then
        error_message "Insufficient disk space. At least 100MB required in /tmp"
        error_message "Available: $((available_space / 1024)) MB"
        exit 1
    fi

    info_message "Sufficient disk space available: $((available_space / 1024)) MB"
}

# Main YARA installation for macOS
yara_macos_installation() {
    info_message "Starting YARA installation for macOS..."

    check_disk_space

    local arch
    arch=$(detect_architecture)
    info_message "Detected macOS architecture: $arch"

    install_dependencies
    download_yara_macos_dmg "$arch"
    install_yara_macos_dmg "$arch"

    setup_yara_components
    remove_file_limit
    validate_installation

    success_message "YARA installation completed successfully!"
    info_message "You can now use YARA with Wazuh for malware detection"
}

# Main function
main() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --type)
                if [[ -n "$2" && "$2" =~ ^(desktop|server)$ ]]; then
                    INSTALLATION_TYPE="$2"
                    shift 2
                else
                    error_message "Invalid installation type. Use 'desktop' or 'server'."
                    exit 1
                fi
                ;;
            --help|-h)
                echo "Usage: $0 [YARA_VERSION] [--type desktop|server]"
                echo "  YARA_VERSION: Version of YARA to install (default: 4.5.5)"
                echo "  --type: Installation type (desktop or server)"
                exit 0
                ;;
            -*)
                error_message "Unknown option: $1"
                exit 1
                ;;
            *)
                if [[ -z "${YARA_VERSION_SET:-}" ]]; then
                    YARA_VERSION="$1"
                    YARA_VERSION_SET=1
                    shift
                else
                    error_message "Unexpected argument: $1"
                    exit 1
                fi
                ;;
        esac
    done

    info_message "Starting YARA installation script v${YARA_VERSION}"
    info_message "Detected OS: macOS"

    if [ ! -d "/Library/Ossec" ]; then
        error_message "Wazuh agent not installed at /Library/Ossec"
        error_message "Please install the Wazuh agent before running this script"
        exit 1
    fi

    prompt_installation_type

    local check_status=0
    pre_installation_check || check_status=$?

    if [ "$check_status" -eq 2 ]; then
        info_message "Verifying existing installation..."
        validate_installation
        success_message "YARA is already installed and configured correctly. Exiting."
        exit 0
    elif [ "$check_status" -ne 0 ]; then
        error_message "Pre-installation checks failed"
        exit 1
    fi
    
    # Proceed with installation
    case "$OS" in
        darwin)
            yara_macos_installation
            ;;
        *)
            error_message "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"