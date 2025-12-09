#!/usr/bin/env bash

#=============================================================================
# Enhanced YARA Installation Script with Pre-Installation Detection
# Detects existing YARA installations and offers automatic cleanup
#=============================================================================

# Check if running as root or with sudo
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root or with sudo privileges."
    echo "Please run: sudo $0"
    exit 1
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

# Check if we're running in bash; if not, adjust behavior
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

# Configuration
YARA_VERSION="${1:-4.5.5}"
YARA_SH_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/yara-integration/scripts/yara.sh"
YARA_RULES_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/rules/yara_rules.yar"

# GitHub Release configuration for packages
GITHUB_RELEASE_BASE_URL="https://github.com/ADORSYS-GIS/wazuh-plugins/releases/download"
LINUX_RELEASE_TAG="yara-v0.3.17"
MACOS_RELEASE_TAG="yara-v0.5.1"

# Cleanup script URLs
CLEANUP_LEGACY_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/yara-integration/scripts/cleanup-legacy.sh"
UNINSTALL_MODERN_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/yara-integration/scripts/uninstall.sh"

TMP_DIR=$(mktemp -d)
LOGGED_IN_USER=""

# OS and Distribution Detection
case "$(uname)" in
Linux)
    OS="linux"
    OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
    WAZUH_CONTROL_BIN_PATH="/var/ossec/bin/wazuh-control"
    YARA_SH_PATH="/var/ossec/active-response/bin/yara.sh"
    ;;
Darwin)
    OS="darwin"
    OSSEC_CONF_PATH="/Library/Ossec/etc/ossec.conf"
    WAZUH_CONTROL_BIN_PATH="/Library/Ossec/bin/wazuh-control"
    YARA_SH_PATH="/Library/Ossec/active-response/bin/yara.sh"
    LOGGED_IN_USER=$(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ {print $3}')
    ;;
*)
    error_message "Unsupported operating system: $(uname)"
    exit 1
    ;;
esac

# Detect Linux Distribution (only on Linux)
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
            error_message "Unable to detect Linux distribution"
            exit 1
        fi
    }
    DISTRO=$(detect_distro)
fi

# Cleanup function
cleanup() {
    info_message "Cleaning up temporary files..."
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Detect system architecture (unified for Linux and macOS)
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

# Cross-platform sed function
sed_inplace() {
    if [ "$OS" = "darwin" ]; then
        if ! maybe_sudo sed -i '' "$@" 2>/dev/null; then
            warn_message "Failed to update file with sed (macOS)"
        fi
    else
        if ! maybe_sudo sed -i "$@" 2>/dev/null; then
            warn_message "Failed to update file with sed (Linux)"
        fi
    fi
}

#=============================================================================
# PRE-INSTALLATION CHECKS
#=============================================================================

# Detect YARA installation type - distinguish between modern and legacy installations
detect_yara_installation() {
    local installation_type=""
    local yara_path=""
    
    info_message "Checking for existing YARA installations..."
    
    # Check if yara command exists
    if command_exists yara; then
        yara_path=$(command -v yara)
        info_message "Found YARA command at: $yara_path"
        
        # Check for modern installation in /opt/wazuh/yara
        if [ -d "/opt/wazuh/yara" ]; then
            installation_type="modern"
            info_message "Found modern YARA installation directory: /opt/wazuh/yara"
        # Check for legacy installation in /opt/yara
        elif [ -d "/opt/yara" ]; then
            installation_type="legacy"
            info_message "Found legacy YARA installation directory: /opt/yara"
        # Check if yara is a symlink pointing to legacy installation
        elif [ -L "$yara_path" ]; then
            local link_target
            link_target=$(readlink "$yara_path")
            if [[ "$link_target" == *"/opt/yara"* ]]; then
                installation_type="legacy"
                info_message "Found legacy YARA installation via symlink: $yara_path -> $link_target"
            elif [[ "$link_target" == *"/opt/wazuh/yara"* ]]; then
                installation_type="modern"
                info_message "Found modern YARA installation via symlink: $yara_path -> $link_target"
            fi
        fi
    fi
    
    # Check for modern installation directory directly
    if [ -z "$installation_type" ] && [ -d "/opt/wazuh/yara" ]; then
        installation_type="modern"
        info_message "Found modern YARA installation directory: /opt/wazuh/yara"
    fi
    
    # Check for legacy installation directory directly
    if [ -z "$installation_type" ] && [ -d "/opt/yara" ]; then
        installation_type="legacy"
        info_message "Found legacy YARA installation directory: /opt/yara"
    fi
    
    # Check if YARA is installed via package manager (modern)
    if [ "$OS" = "linux" ]; then
        case "$DISTRO" in
            centos|rhel|redhat|rocky|almalinux|fedora)
                if command_exists rpm && rpm -q yara >/dev/null 2>&1; then
                    installation_type="modern"
                    info_message "Found YARA installed via RPM package manager"
                fi
                ;;
            ubuntu|debian)
                if command_exists dpkg && dpkg -s yara >/dev/null 2>&1; then
                    installation_type="modern"
                    info_message "Found YARA installed via DEB package manager"
                fi
                ;;
        esac
    fi
    
    echo "$installation_type"
}

# Download and execute legacy cleanup script
run_legacy_cleanup() {
    local cleanup_script="$TMP_DIR/cleanup-legacy.sh"
    
    info_message "Downloading legacy YARA cleanup script..."
    
    if ! curl -fsSL -o "$cleanup_script" "$CLEANUP_LEGACY_URL"; then
        error_message "Failed to download legacy cleanup script"
        error_message "Manual cleanup of legacy installation may be required"
        return 1
    fi
    
    chmod +x "$cleanup_script"
    
    info_message "Running legacy cleanup script..."
    if bash "$cleanup_script"; then
        success_message "Legacy cleanup completed successfully"
        return 0
    else
        error_message "Legacy cleanup script failed"
        return 1
    fi
}

# Download and execute uninstaller - only modern uninstaller
run_uninstaller() {
    local uninstall_script="$TMP_DIR/uninstall-modern.sh"
    
    info_message "Downloading modern YARA uninstaller..."
    
    if ! curl -fsSL -o "$uninstall_script" "$UNINSTALL_MODERN_URL"; then
        error_message "Failed to download uninstaller"
        error_message "Attempting manual cleanup..."
        
        # Fallback: Basic cleanup if download fails
        warn_message "Performing basic cleanup manually..."
        
        if [ -d "/opt/wazuh/yara" ]; then
            info_message "Removing /opt/wazuh/yara..."
            maybe_sudo rm -rf "/opt/wazuh/yara"
        fi
        
        if [ -L "/usr/local/bin/yara" ] || [ -f "/usr/local/bin/yara" ]; then
            info_message "Removing /usr/local/bin/yara..."
            maybe_sudo rm -f "/usr/local/bin/yara"
        fi
        
        success_message "Basic cleanup completed"
        return 0
    fi
    
    chmod +x "$uninstall_script"
    
    info_message "Running uninstaller..."
    if bash "$uninstall_script"; then
        success_message "Uninstaller completed successfully"
        return 0
    else
        warn_message "Uninstaller had issues, but continuing with installation"
        return 0
    fi
}

# Pre-installation check and cleanup - handle both modern and legacy installations
pre_installation_check() {
    info_message "Performing pre-installation checks..."
    
    local installation_type
    installation_type=$(detect_yara_installation)
    
    if [ -z "$installation_type" ]; then
        success_message "No existing YARA installation detected"
        success_message "System is ready for fresh installation"
        return 0
    fi
    
    echo ""
    case "$installation_type" in
        modern)
            warn_message "Existing modern YARA installation detected!"
            warn_message "Installation type: Modern package-based installation"
            warn_message "Location: /opt/wazuh/yara"
            echo ""
            
            info_message "The existing installation will be removed and replaced with the new version"
            read -p "Would you like to remove the existing installation and proceed? [Y/n] " -n 1 -r
            echo ""
            
            if [[ $REPLY =~ ^[Nn]$ ]]; then
                info_message "Installation cancelled by user"
                exit 0
            fi
            
            if ! run_uninstaller; then
                error_message "Failed to remove existing installation"
                error_message "Please manually remove YARA or fix the issues and try again"
                exit 1
            fi
            ;;
        legacy)
            warn_message "Existing legacy YARA installation detected!"
            warn_message "Installation type: Legacy installation"
            warn_message "Location: /opt/yara or linked from /usr/local/bin/yara"
            echo ""
            
            info_message "The existing legacy installation will be removed using the legacy cleanup script"
            read -p "Would you like to remove the existing legacy installation and proceed? [Y/n] " -n 1 -r
            echo ""
            
            if [[ $REPLY =~ ^[Nn]$ ]]; then
                info_message "Installation cancelled by user"
                exit 0
            fi
            
            if ! run_legacy_cleanup; then
                error_message "Failed to remove existing legacy installation"
                error_message "Please manually remove YARA or fix the issues and try again"
                exit 1
            fi
            ;;
    esac
    
    echo ""
    success_message "Pre-installation cleanup completed"
    success_message "System is ready for fresh YARA installation"
    echo ""
    
    # Brief pause to let user see the messages
    sleep 2
}

#=============================================================================
# INSTALLATION FUNCTIONS (from your updated script)
#=============================================================================

# Restart Wazuh agent
restart_wazuh_agent() {
    if maybe_sudo "$WAZUH_CONTROL_BIN_PATH" restart >/dev/null 2>&1; then
        success_message "Wazuh agent restarted successfully."
    else
        error_message "Error occurred during Wazuh agent restart."
    fi
}

# Remove file limit from ossec.conf
remove_file_limit() {
    if maybe_sudo grep -q "<file_limit>" "$OSSEC_CONF_PATH"; then
        sed_inplace "/<file_limit>/,/<\/file_limit>/d" "$OSSEC_CONF_PATH" || {
            error_message "Error occurred during the removal of the file_limit block."
            return 1
        }
        info_message "The file limit block was removed successfully."
    else
        info_message "The file limit block does not exist. No changes were made."
    fi
}

# Install dependencies based on distro
install_dependencies() {
    info_message "Installing dependencies..."
    
    if [ "$OS" = "linux" ]; then
        case "$DISTRO" in
            centos|rhel|redhat|rocky|almalinux|fedora)
                print_step 1 "Installing jq on RPM-based system"
                local pkg_manager=""
                if command_exists dnf; then
                    pkg_manager="dnf"
                elif command_exists yum; then
                    pkg_manager="yum"
                else
                    warn_message "Neither dnf nor yum found, skipping dependency installation"
                    return 0
                fi
                
                maybe_sudo "$pkg_manager" install -y epel-release 2>/dev/null || \
                maybe_sudo "$pkg_manager" install -y oracle-epel-release-el8 2>/dev/null || \
                maybe_sudo "$pkg_manager" install -y oracle-epel-release-el9 2>/dev/null || \
                warn_message "Could not install EPEL repository, continuing without it"
                
                maybe_sudo "$pkg_manager" install -y jq 2>/dev/null || \
                warn_message "Could not install jq, continuing without it"
                ;;
            ubuntu|debian)
                print_step 1 "Installing jq on DEB-based system"
                maybe_sudo apt-get update -qq
                maybe_sudo apt-get install -y jq
                ;;
            *)
                error_message "Unsupported Linux distribution: $DISTRO"
                exit 1
                ;;
        esac
    elif [ "$OS" = "darwin" ]; then
        print_step 1 "Installing jq on macOS"
        if command_exists brew; then
            if [ "$(id -u)" -eq 0 ] && [ -n "$LOGGED_IN_USER" ] && [ "$LOGGED_IN_USER" != "loginwindow" ]; then
                sudo -u "$LOGGED_IN_USER" brew install jq 2>/dev/null || warn_message "Could not install jq via Homebrew"
            elif [ "$(id -u)" -ne 0 ]; then
                brew install jq 2>/dev/null || warn_message "Could not install jq via Homebrew"
            else
                warn_message "Cannot install jq via Homebrew as root without a logged in user"
            fi
        elif command_exists port; then
            maybe_sudo port install jq 2>/dev/null || warn_message "Could not install jq via MacPorts"
        else
            warn_message "Neither Homebrew nor MacPorts found. Please install jq manually."
        fi
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
    
    if curl -fsSL -o "$output" "$url"; then
        success_message "$description downloaded successfully"
        return 0
    else
        error_message "Failed to download $description from $url"
        error_message "Please check your network connection and URL validity"
        return 1
    fi
}

# Download YARA package based on distro and architecture
download_yara_package() {
    local distro="$1"
    local arch="$2"
    local url="" output=""
    
    case "$distro" in
        centos|rhel|redhat|rocky|almalinux|fedora)
            print_step 1 "Downloading YARA RPM package for $arch"
            url="${GITHUB_RELEASE_BASE_URL}/${LINUX_RELEASE_TAG}/yara-v${YARA_VERSION}-linux-${arch}.rpm"
            output="$TMP_DIR/yara.rpm"
            ;;
        ubuntu|debian)
            print_step 1 "Downloading YARA DEB package for $arch"
            url="${GITHUB_RELEASE_BASE_URL}/${LINUX_RELEASE_TAG}/yara-v${YARA_VERSION}-linux-${arch}.deb"
            output="$TMP_DIR/yara.deb"
            ;;
        *)
            error_message "Unsupported Linux distribution: $distro"
            exit 1
            ;;
    esac
    
    download_file "$url" "$output" "YARA package" || exit 1
}

# Download YARA DMG for macOS based on architecture
download_yara_macos_dmg() {
    local arch="$1"
    local url="${GITHUB_RELEASE_BASE_URL}/${MACOS_RELEASE_TAG}/yara-v${YARA_VERSION}-macos-${arch}.dmg"
    
    print_step 1 "Downloading YARA DMG for macOS $arch"
    download_file "$url" "$TMP_DIR/yara.dmg" "YARA DMG" || exit 1
}

# Install YARA package based on distro
install_yara_package() {
    local distro="$1"
    info_message "Installing YARA package for $distro..."
    
    case "$distro" in
        centos|rhel|redhat|rocky|almalinux|fedora)
            print_step 1 "Installing YARA RPM package"
            if command_exists dnf; then
                maybe_sudo dnf install -y "$TMP_DIR/yara.rpm"
            else
                maybe_sudo yum install -y "$TMP_DIR/yara.rpm"
            fi
            ;;
        ubuntu|debian)
            print_step 1 "Installing YARA DEB package"
            maybe_sudo apt-get install -y "$TMP_DIR/yara.deb"
            ;;
        *)
            error_message "Unsupported Linux distribution: $distro"
            exit 1
            ;;
    esac
    
    print_step 2 "Creating wrapper script"
    maybe_sudo mkdir -p /usr/local/bin
    maybe_sudo tee /usr/local/bin/yara > /dev/null << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
export LD_LIBRARY_PATH="/opt/wazuh/yara/lib:${LD_LIBRARY_PATH:-}"
exec "/opt/wazuh/yara/bin/yara.real" "$@"
EOF
    maybe_sudo chmod +x /usr/local/bin/yara
    
    success_message "YARA package installed successfully"
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
    maybe_sudo chmod 750 "/opt/wazuh/yara/bin/yara"
    maybe_sudo chown root:wheel "/opt/wazuh/yara/bin/yara" 2>/dev/null || \
    maybe_sudo chown root:staff "/opt/wazuh/yara/bin/yara" 2>/dev/null || \
    maybe_sudo chown root:root "/opt/wazuh/yara/bin/yara"
    
    maybe_sudo mkdir -p /usr/local/bin
    maybe_sudo ln -sf "/opt/wazuh/yara/bin/yara" /usr/local/bin/yara
    
    success_message "YARA installed successfully from DMG on macOS"
}

# Setup YARA directories and components
setup_yara_components() {
    info_message "Setting up YARA components..."
    
    local base_path yara_script_path yara_rules_path
    if [ "$OS" = "darwin" ]; then
        base_path="/Library/Ossec"
        yara_script_path="/Library/Ossec/active-response/bin/yara.sh"
        yara_rules_path="/Library/Ossec/ruleset/yara/rules"
    else
        base_path="/var/ossec"
        yara_script_path="/var/ossec/active-response/bin/yara.sh"
        yara_rules_path="/var/ossec/ruleset/yara/rules"
    fi
    
    print_step 1 "Creating directories"
    if ! maybe_sudo mkdir -p "$base_path/active-response/bin/"; then
        error_message "Failed to create directory: $base_path/active-response/bin/"
        exit 1
    fi
    
    if ! maybe_sudo mkdir -p "$yara_rules_path/"; then
        error_message "Failed to create directory: $yara_rules_path/"
        exit 1
    fi
    
    print_step 2 "Downloading and configuring YARA script"
    if ! download_file "$YARA_SH_URL" "$yara_script_path" "YARA script"; then
        error_message "Failed to download YARA script"
        exit 1
    fi
    
    sed_inplace 's|YARA_PATH="/usr/local/bin"|YARA_PATH="/opt/wazuh/yara/bin"|g' "$yara_script_path"
    sed_inplace 's|YARA_PATH="/opt/yara/bin"|YARA_PATH="/opt/wazuh/yara/bin"|g' "$yara_script_path"
    
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
    
    if [ "$OS" = "darwin" ]; then
        maybe_sudo chown root:wheel "$yara_script_path" 2>/dev/null || \
        maybe_sudo chown root:staff "$yara_script_path" 2>/dev/null || \
        maybe_sudo chown root:root "$yara_script_path"
    else
        maybe_sudo chown root:wazuh "$yara_script_path" 2>/dev/null || \
        maybe_sudo chown root:root "$yara_script_path"
    fi
    
    success_message "YARA components set up successfully"
}

# Validate installation
validate_installation() {
    info_message "Validating YARA installation..."
    local validation_failed=0
    
    local yara_found=0 actual_version=""
    
    if command_exists yara; then
        actual_version=$(yara --version 2>/dev/null || echo "")
        yara_found=1
    elif [ -f "/opt/wazuh/yara/bin/yara" ]; then
        actual_version=$(/opt/wazuh/yara/bin/yara --version 2>/dev/null || echo "")
        yara_found=1
    fi
    
    if [ $yara_found -eq 1 ] && [ -n "$actual_version" ]; then
        if version_is_4_5_x "$actual_version"; then
            success_message "YARA version $actual_version is installed (4.5.x series)."
        else
            warn_message "YARA version $actual_version is not compatible. Version 4.5.x is required."
            validation_failed=1
        fi
    else
        error_message "YARA command is not available. Please check the installation."
        validation_failed=1
    fi
    
    local yara_rules_path yara_script_path
    if [ "$OS" = "darwin" ]; then
        yara_rules_path="/Library/Ossec/ruleset/yara/rules/yara_rules.yar"
        yara_script_path="/Library/Ossec/active-response/bin/yara.sh"
    else
        yara_rules_path="/var/ossec/ruleset/yara/rules/yara_rules.yar"
        yara_script_path="/var/ossec/active-response/bin/yara.sh"
    fi
    
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

# Main YARA installation for Linux
yara_installation() {
    info_message "Starting YARA installation for Linux..."
    
    check_disk_space
    
    local arch
    arch=$(detect_architecture)
    info_message "Detected Linux distribution: $DISTRO"
    info_message "Detected system architecture: $arch"
    
    case "$DISTRO" in
        centos|rhel|redhat|rocky|almalinux|fedora|ubuntu|debian)
            info_message "Distribution $DISTRO is supported"
            ;;
        *)
            error_message "Unsupported Linux distribution: $DISTRO"
            exit 1
            ;;
    esac
    
    install_dependencies
    download_yara_package "$DISTRO" "$arch"
    install_yara_package "$DISTRO"
    setup_yara_components
    remove_file_limit
    validate_installation
    restart_wazuh_agent
    
    success_message "YARA installation completed successfully!"
    info_message "You can now use YARA with Wazuh for malware detection"
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
    restart_wazuh_agent
    
    success_message "YARA installation completed successfully"
}

# Main function
main() {
    info_message "Starting YARA installation script v${YARA_VERSION}"
    info_message "Detected OS: ${OS}"
    
    # Check if Wazuh agent is installed
    if [ "$OS" = "darwin" ]; then
        if [ ! -d "/Library/Ossec" ]; then
            error_message "Wazuh agent not installed at /Library/Ossec"
            error_message "Please install the Wazuh agent before running this script"
            exit 1
        fi
    else
        if [ ! -d "/var/ossec" ]; then
            error_message "Wazuh agent not installed at /var/ossec"
            error_message "Please install the Wazuh agent before running this script"
            exit 1
        fi
    fi
    
    # Run pre-installation checks and cleanup if needed
    pre_installation_check
    
    # Proceed with installation
    case "$OS" in
        linux)
            yara_installation
            ;;
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
