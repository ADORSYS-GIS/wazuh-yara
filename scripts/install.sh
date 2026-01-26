#!/usr/bin/env bash

#=============================================================================
# Enhanced YARA Installation Script with Pre-Installation Detection
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
    # Check if installation type is already set via environment variable or argument
    if [[ -n "${INSTALLATION_TYPE:-}" ]]; then
        if [[ "$INSTALLATION_TYPE" == "desktop" ]]; then
            YARA_SOURCE_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/yara-integration/scripts/yara.sh"
            info_message "Using Desktop/Workstation installation (non-interactive mode)"
            return 0
        elif [[ "$INSTALLATION_TYPE" == "server" ]]; then
            YARA_SOURCE_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/yara-server.sh"
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
                YARA_SOURCE_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/yara-integration/scripts/yara.sh"
                info_message "Selected: Desktop/Workstation installation"
                return 0
                ;;
            2)
                INSTALLATION_TYPE="server"
                YARA_SOURCE_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/yara-server.sh"
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
# Destination script name is always yara.sh; YARA_SOURCE_URL is set by prompt_installation_type()
YARA_SCRIPT_NAME="yara.sh"
YARA_RULES_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/rules/yara_rules.yar"

# GitHub Release configuration for packages
GITHUB_RELEASE_BASE_URL="https://github.com/ADORSYS-GIS/wazuh-plugins/releases/download"
LINUX_RELEASE_TAG="yara-v0.3.17"
MACOS_RELEASE_TAG="yara-v0.5.1"

TMP_DIR=$(mktemp -d)
LOGGED_IN_USER=""

# OS and Distribution Detection
case "$(uname)" in
Linux)
    OS="linux"
    OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
    WAZUH_CONTROL_BIN_PATH="/var/ossec/bin/wazuh-control"
    ;;
Darwin)
    OS="darwin"
    OSSEC_CONF_PATH="/Library/Ossec/etc/ossec.conf"
    WAZUH_CONTROL_BIN_PATH="/Library/Ossec/bin/wazuh-control"
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
        maybe_sudo sed -i '' "$@" 2>/dev/null || true
    else
        maybe_sudo sed -i "$@" 2>/dev/null || true
    fi
}

#=============================================================================
# PRE-INSTALLATION CHECKS
#=============================================================================

# Detect YARA installations - check for legacy, modern, and softlink
detect_yara_installation() {
    local has_legacy=0
    local has_modern=0
    local has_softlink=0
    
    # Suppress info messages during detection to avoid interference with return values
    exec 3>&1 4>&2  # Save stdout and stderr
    exec 1>/dev/null 2>/dev/null  # Redirect stdout and stderr to /dev/null
    
    # Check for legacy installation in /opt/yara
    if [ -d "/opt/yara" ]; then
        has_legacy=1
    fi
    
    # Check for modern installation in /opt/wazuh/yara
    if [ -d "/opt/wazuh/yara" ]; then
        has_modern=1
    fi
    
    # Check for softlink at /usr/local/bin/yara
    if [ -L "/usr/local/bin/yara" ] || [ -f "/usr/local/bin/yara" ]; then
        has_softlink=1
    fi
    
    # Check if YARA is installed via package manager (modern)
    if [ "$OS" = "linux" ]; then
        case "$DISTRO" in
            centos|rhel|redhat|rocky|almalinux|fedora)
                if command_exists rpm && rpm -q yara >/dev/null 2>&1; then
                    has_modern=1
                fi
                ;;
            ubuntu|debian)
                if command_exists dpkg && dpkg -s yara >/dev/null 2>&1; then
                    has_modern=1
                fi
                ;;
        esac
    fi
    
    # Restore stdout and stderr
    exec 1>&3 2>&4
    exec 3>&- 4>&-
    
    # Return result as "legacy,modern,softlink" format
    echo "${has_legacy},${has_modern},${has_softlink}"
}

# Download and run uninstallation script from GitHub
run_local_uninstall() {
    local uninstall_script="$TMP_DIR/uninstall.sh"
    local uninstall_url="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/yara-integration/scripts/uninstall.sh"
    
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
    
    # Parse the detection result
    IFS=',' read -r has_legacy has_modern has_softlink <<< "$detection_result"
    
    # Check if modern installation has the correct version
    if [ "$has_modern" -eq 1 ]; then
        if [ -f "/opt/wazuh/yara/bin/yara" ]; then
            # Capture output and check version
            local current_version
            current_version=$(/opt/wazuh/yara/bin/yara --version 2>/dev/null || echo "")
            
            if [ -n "$current_version" ] && version_is_4_5_x "$current_version"; then
                success_message "Valid YARA installation found (v${current_version})"
                info_message "Skipping new installation, will proceed to configuration checks..."
                return 2  # Special return code for skipping install
            fi
            
            info_message "Existing YARA version ($current_version) does not match target v${YARA_VERSION}"
        fi
    fi
    
    # If no installations detected, proceed with fresh install
    if [ "$has_legacy" -eq 0 ] && [ "$has_modern" -eq 0 ]; then
        success_message "No existing YARA installation detected"
        success_message "System is ready for fresh installation"
        return 0
    fi
    
    # Display detection results
    echo ""
    warn_message "Existing YARA installation(s) detected!"
    
    # Check for legacy installation in /opt/yara
    if [ -d "/opt/yara" ]; then
        info_message "Found YARA in path: /opt/yara"
    fi
    
    # Check for modern installation in /opt/wazuh/yara
    if [ -d "/opt/wazuh/yara" ]; then
        info_message "Found YARA in path: /opt/wazuh/yara"
    fi
    
    # Check for softlink at /usr/local/bin/yara
    if [ -L "/usr/local/bin/yara" ] || [ -f "/usr/local/bin/yara" ]; then
        info_message "Found YARA in path: /usr/local/bin/yara"
    fi
    
    # Check if YARA is installed via package manager (modern)
    if [ "$OS" = "linux" ]; then
        case "$DISTRO" in
            centos|rhel|redhat|rocky|almalinux|fedora)
                if command_exists rpm && rpm -q yara > /dev/null 2>&1; then
                    info_message "Found YARA installed via RPM package manager"
                fi
                ;;
            ubuntu|debian)
                if command_exists dpkg && dpkg -s yara > /dev/null 2>&1; then
                    info_message "Found YARA installed via DEB package manager"
                fi
                ;;
        esac
    fi
    
    echo ""
    info_message "Running uninstallation script to clean up existing installations..."
    
    # Run the local uninstall script (it will detect and remove everything)
    if ! run_local_uninstall; then
        error_message "Failed to remove existing YARA installation(s)"
        exit 1
    fi
    
    echo ""
    success_message "Pre-installation cleanup completed"
    success_message "System is ready for fresh YARA installation"
    echo ""
    
    # Brief pause to let user see the messages
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
        print_step 1 "Installing dependencies on macOS"
        if command_exists brew; then
            if [ "$(id -u)" -eq 0 ] && [ -n "$LOGGED_IN_USER" ] && [ "$LOGGED_IN_USER" != "loginwindow" ]; then
                sudo -u "$LOGGED_IN_USER" brew install jq libmagic openssl@3 2>/dev/null || warn_message "Could not install dependencies via Homebrew"
            elif [ "$(id -u)" -ne 0 ]; then
                brew install jq libmagic openssl@3 2>/dev/null || warn_message "Could not install dependencies via Homebrew"
            else
                warn_message "Cannot install dependencies via Homebrew as root without a logged in user"
            fi
        elif command_exists port; then
            maybe_sudo port install jq libmagic openssl3 2>/dev/null || warn_message "Could not install dependencies via MacPorts"
        else
            warn_message "Neither Homebrew nor MacPorts found. Please install jq, libmagic, and openssl manually."
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
    
    # Use sudo to download the file to system directories
    if curl -fsSL "$url" | maybe_sudo tee "$output" > /dev/null; then
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
    # Set executable permissions for all users to ensure it can be run without sudo
    maybe_sudo chmod 755 "/opt/wazuh/yara/bin/yara"
    maybe_sudo chown root:wheel "/opt/wazuh/yara/bin/yara" 2>/dev/null || \
    maybe_sudo chown root:staff "/opt/wazuh/yara/bin/yara" 2>/dev/null || \
    maybe_sudo chown root:root "/opt/wazuh/yara/bin/yara"
    
    # Ensure /usr/local/bin exists and create symlink
    maybe_sudo mkdir -p /usr/local/bin
    maybe_sudo ln -sf "/opt/wazuh/yara/bin/yara" /usr/local/bin/yara
    # Also ensure the symlink has proper permissions
    maybe_sudo chmod 755 /usr/local/bin/yara
    
    # DEBUG: Check if file exists right after install
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
    
    local base_path yara_script_path yara_rules_path
    if [ "$OS" = "darwin" ]; then
        base_path="/Library/Ossec"
        yara_script_path="/Library/Ossec/active-response/bin/${YARA_SCRIPT_NAME}"
        yara_rules_path="/Library/Ossec/ruleset/yara/rules"
    else
        base_path="/var/ossec"
        yara_script_path="/var/ossec/active-response/bin/${YARA_SCRIPT_NAME}"
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
    if ! download_file "$YARA_SOURCE_URL" "$yara_script_path" "YARA script"; then
        error_message "Failed to download YARA script"
        exit 1
    fi
    
    # Only apply path replacements for desktop version (yara.sh)
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
    
    if [ "$OS" = "darwin" ]; then
        maybe_sudo chown root:wheel "$yara_script_path" 2>/dev/null || \
        maybe_sudo chown root:staff "$yara_script_path" 2>/dev/null || \
        maybe_sudo chown root:root "$yara_script_path"
        
        # Also set ownership for YARA rules on macOS
        maybe_sudo chown root:wheel "$yara_rules_path/yara_rules.yar" 2>/dev/null || \
        maybe_sudo chown root:staff "$yara_rules_path/yara_rules.yar" 2>/dev/null || \
        maybe_sudo chown root:root "$yara_rules_path/yara_rules.yar"
        
        # FIX: Ensure directory itself has correct group ownership on macOS
        maybe_sudo chown root:wheel "$yara_rules_path" 2>/dev/null || \
        maybe_sudo chown root:staff "$yara_rules_path" 2>/dev/null || \
        maybe_sudo chown root:root "$yara_rules_path"
    else
        maybe_sudo chown root:wazuh "$yara_script_path" 2>/dev/null || \
        maybe_sudo chown root:root "$yara_script_path"
        
        # Also set ownership for YARA rules on Linux (expected to be root:wazuh)
        maybe_sudo chown root:wazuh "$yara_rules_path/yara_rules.yar" 2>/dev/null || \
        maybe_sudo chown root:root "$yara_rules_path/yara_rules.yar"
        
        # FIX: Ensure directory itself has correct group ownership (failed in tests)
        maybe_sudo chown root:wazuh "$yara_rules_path" 2>/dev/null || \
        maybe_sudo chown root:root "$yara_rules_path"
    fi
    
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
        # Capture both stdout and stderr to debug execution failure
        actual_version=$(/opt/wazuh/yara/bin/yara --version 2>&1 || echo "")
        yara_found=1
    fi
    
    # Check if actual_version looks like a version number (contains dots)
    # If not, it might contain an error message
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
            info_message "DEBUG: Trying to run it directly to see error:"
            maybe_sudo /opt/wazuh/yara/bin/yara --version || true
            
            if [ "$OS" = "darwin" ]; then
                info_message "DEBUG: Checking file type:"
                file /opt/wazuh/yara/bin/yara || true
                info_message "DEBUG: Checking shared libraries:"
                otool -L /opt/wazuh/yara/bin/yara || true
            fi
        else
            error_message "DEBUG: File does NOT exist."
        fi
        validation_failed=1
    fi
    
    local yara_rules_path yara_script_path
    if [ "$OS" = "darwin" ]; then
        yara_rules_path="/Library/Ossec/ruleset/yara/rules/yara_rules.yar"
        yara_script_path="/Library/Ossec/active-response/bin/${YARA_SCRIPT_NAME}"
    else
        yara_rules_path="/var/ossec/ruleset/yara/rules/yara_rules.yar"
        yara_script_path="/var/ossec/active-response/bin/${YARA_SCRIPT_NAME}"
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
    
    success_message "YARA installation completed successfully!"
    info_message "You can now use YARA with Wazuh for malware detection"
}

# Main function
main() {
    # Parse command line arguments
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
                # First positional argument is YARA version
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
    
    # Prompt user for installation type (desktop or server) if not set
    prompt_installation_type
    
    # Run pre-installation checks and automatic cleanup
    # Returns 0 for fresh install
    # Returns 2 for skipping install (valid version found)
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