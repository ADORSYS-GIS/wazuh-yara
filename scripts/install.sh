#!/usr/bin/env bash

#=============================================================================
# LOGGING HELPERS
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

# Check if we're running in bash; if not, adjust behavior
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

LOG_LEVEL=${LOG_LEVEL:-INFO}
USER="root"
GROUP="wazuh"

YARA_VERSION="${1:-4.5.4}"
YARA_SH_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/develop/scripts/yara.sh"

# GitHub Release configuration for prebuilt binaries
GITHUB_RELEASE_TAG="v${YARA_VERSION}-adorsys.2.rc1"
GITHUB_RELEASE_BASE_URL="https://github.com/ADORSYS-GIS/wazuh-yara-package/releases/download"

DOWNLOADS_DIR="${HOME}/yara-install"

# shellcheck disable=SC2034
YARA_URL="https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz"
# shellcheck disable=SC2034
TAR_DIR="$DOWNLOADS_DIR/yara-${YARA_VERSION}.tar.gz"
# shellcheck disable=SC2034
EXTRACT_DIR="$DOWNLOADS_DIR/yara-${YARA_VERSION}"

NOTIFY_SEND_VERSION=0.8.3
LOGGED_IN_USER=""


if [ "$(uname -s)" = "Darwin" ]; then
    LOGGED_IN_USER=$(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ {print $3}')
fi

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


# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if version matches 4.5.x pattern
version_is_4_5_x() {
    local version="$1"

    # Extract major and minor version numbers
    local major
    local minor
    major=$(echo "$version" | cut -d'.' -f1)
    minor=$(echo "$version" | cut -d'.' -f2)

    # Check if it's 4.5.x
    if [ "$major" = "4" ] && [ "$minor" = "5" ]; then
        return 0
    else
        return 1
    fi
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

sed_alternative() {
    if command_exists gsed; then
        maybe_sudo gsed "$@"
    else
        maybe_sudo sed "$@"
    fi
}

#Get the logged-in user on macOS
brew_command() {
    sudo -u "$LOGGED_IN_USER" -i brew "$@"
}

# Create a temporary directory and ensure it's cleaned up on exit
TMP_DIR=$(mktemp -d)
cleanup() {
    info_message "Cleaning up temporary files..."
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Create Downloads directory for source builds
mkdir -p "$DOWNLOADS_DIR"

#=============================================================================
# SHARED UTILITY FUNCTIONS
#=============================================================================

# Ensure that the root:wazuh user and group exist, creating them if necessary
ensure_user_group() {
    info_message "Ensuring that the $USER:$GROUP user and group exist..."

    if ! id -u "$USER" >/dev/null 2>&1; then
        info_message "Creating user $USER..."
        if [ "$OS" = "linux" ] && command -v groupadd >/dev/null 2>&1; then
            maybe_sudo useradd -m "$USER"
        elif [ "$(which apk)" = "/sbin/apk" ]; then
            maybe_sudo adduser -D "$USER"
        elif [ "$OS" = "darwin" ]; then
            # macOS
            if ! dscl . -list /Users | grep -q "^$USER$"; then
                info_message "Creating user $USER on macOS..."
                maybe_sudo sysadminctl -addUser "$USER" -fullName "$USER" || {
                    error_message "Failed to create user $USER"
                }
            fi
        else
            error_message "Unsupported OS for creating user."
            exit 1
        fi
    fi

    if ! getent group "$GROUP" >/dev/null 2>&1; then
        info_message "Creating group $GROUP..."
        if [ "$OS" = "linux" ] && command -v groupadd >/dev/null 2>&1; then
            maybe_sudo groupadd "$GROUP"
        elif [ "$(which apk)" = "/sbin/apk" ]; then
            maybe_sudo addgroup "$GROUP"
        elif [ "$OS" = "darwin" ]; then
            # macOS
            if ! dscl . -list /Groups | grep -q "^$GROUP$"; then
                info_message "Creating group $GROUP on macOS..."
                maybe_sudo dscl . -create /Groups/"$GROUP" || {
                    error_message "Failed to create group $GROUP"
                }
            fi
        else
            error_message "Unsupported OS for creating group."
            exit 1
        fi
    fi
}

# Function to change ownership of a file or directory
change_owner() {
    local path="$1"
    ensure_user_group
    maybe_sudo chown -R "$USER:$GROUP" "$path"
}

restart_wazuh_agent() {
    if maybe_sudo "$WAZUH_CONTROL_BIN_PATH" restart >/dev/null 2>&1; then
        info_message "Wazuh agent restarted successfully."
    else
        error_message "Error occurred during Wazuh agent restart."
    fi
}

remove_file_limit() {
    if maybe_sudo grep -q "<file_limit>" "$OSSEC_CONF_PATH"; then
        # Remove the file_limit block
        sed_alternative -i "/<file_limit>/,/<\/file_limit>/d" "$OSSEC_CONF_PATH" || {
            error_message "Error occurred during the removal of the file_limit block."
        }
        info_message "The file limit block was removed successfully."
    else
        info_message "The file limit block does not exist. No changes were made."
    fi
}

#=============================================================================
# YARA REMOVAL FUNCTIONS
#=============================================================================

remove_apt_yara() {
    # only on Debian/Ubuntu
    if command_exists dpkg; then
        if dpkg -s yara >/dev/null 2>&1; then
            info_message "Detected apt-installed YARA; uninstalling via apt"
            maybe_sudo apt remove -y yara || {
                error_message "Failed to remove apt-installed YARA"
            }
            maybe_sudo apt autoremove -y
            success_message "Apt-installed YARA removed"
        fi
    fi
}


remove_brew_yara() {
    # only on macOS/Homebrew
    if command_exists brew; then
        if brew_command list yara >/dev/null 2>&1; then
            info_message "Detected Homebrew version of YARA; uninstalling via brew"
            brew_command unpin yara 2>/dev/null || true
            if brew_command uninstall --force yara; then
                success_message "Homebrew-installed YARA removed"
            else
                warn_message "Homebrew uninstall had issues but continuing anyway"
            fi
        fi
    fi
}

remove_prebuilt_yara() {
    # Remove prebuilt YARA installation from /opt/yara
    local install_dir="/opt/yara"

    if [ -d "$install_dir" ]; then
        info_message "Removing existing prebuilt YARA installation from ${install_dir}"

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
    fi
}

remove_source_yara() {
    # Remove source-built YARA installation (typically installed to /usr/local)
    if command_exists yara; then
        local yara_path
        yara_path=$(which yara 2>/dev/null)

        # Skip if YARA is already our prebuilt installation (symlink to /opt/yara)
        if [ -L "$yara_path" ] && [ "$(readlink -f "$yara_path" 2>/dev/null)" = "/opt/yara/bin/yara" ]; then
            info_message "Detected existing prebuilt YARA installation - skipping source removal"
            return 0
        fi

        # Check if this looks like a source installation
        # Source installations are typically in /usr/local and not symlinks to /opt/yara
        if [ -n "$yara_path" ] && [ "$yara_path" = "/usr/local/bin/yara" ] && [ ! -L "$yara_path" ]; then
            info_message "Detected source-built YARA installation at $yara_path"

            # Common source-built installation paths
            local common_paths=(
                "/usr/local/bin/yara"
                "/usr/local/bin/yarac"
                "/usr/local/lib/libyara.so*"
                "/usr/local/lib/pkgconfig/yara.pc"
                "/usr/local/include/yara.h"
                "/usr/local/include/yara"
            )

            info_message "Removing source-built YARA files from /usr/local"
            for path_pattern in "${common_paths[@]}"; do
                if [ "${path_pattern}" = "${path_pattern%\*}" ]; then
                    # No wildcard - exact path
                    if [ -e "$path_pattern" ] || [ -L "$path_pattern" ]; then
                        maybe_sudo rm -rf "$path_pattern"
                        info_message "Removed $path_pattern"
                    fi
                else
                    # Wildcard pattern - use find
                    local base_path="${path_pattern%\*}"
                    local matches
                    matches=$(find "$(dirname "$base_path")" -name "$(basename "$path_pattern")" 2>/dev/null || true)
                    if [ -n "$matches" ]; then
                        echo "$matches" | while read -r match; do
                            maybe_sudo rm -rf "$match"
                            info_message "Removed $match"
                        done
                    fi
                fi
            done

            # Update library cache
            if command_exists ldconfig; then
                maybe_sudo ldconfig
                info_message "Updated library cache"
            fi

            success_message "Source-built YARA installation removed"
        else
            info_message "No source-built YARA installation detected"
        fi
    fi
}

#=============================================================================
# PREBUILT BINARY INSTALLATION FUNCTIONS
#=============================================================================

check_and_update_bash() {
    if [ "$OS" = "darwin" ]; then
        if command_exists brew; then
            local current_version
            current_version=$(bash --version | head -n1 | cut -d' ' -f4 | cut -d'.' -f1)
            local min_version=4

            if [ "$current_version" -lt "$min_version" ]; then
                info_message "Outdated Bash version detected (${current_version}), installing newer version..."
                brew_command install bash || {
                    error_message "Failed to install newer Bash version"
                    return 1
                }
                success_message "Bash updated successfully"
            else
                info_message "Bash version is up to date (${current_version})"
            fi
        else
            warn_message "Homebrew is not installed. Cannot update Bash version."
        fi
    fi
}

install_notify_send() {
    deb_dir="$TMP_DIR/notify-send-debs"
    mkdir -p "$deb_dir"
    deb_url1="https://launchpad.net/ubuntu/+archive/primary/+files/libnotify4_0.8.3-1_amd64.deb"
    deb_url2="https://launchpad.net/ubuntu/+archive/primary/+files/libnotify-bin_0.8.3-1_amd64.deb"
    deb_file1="$deb_dir/$(basename "$deb_url1")"
    deb_file2="$deb_dir/$(basename "$deb_url2")"
    info_message "Downloading $deb_url1 ..."
    curl -fsSL -o "$deb_file1" "$deb_url1" || {
        error_message "Failed to download $deb_url1"
        exit 1
    }
    info_message "Installing $(basename "$deb_url1") ..."
    maybe_sudo apt install -y "$deb_file1" || {
        error_message "Failed to install $deb_file1"
        exit 1
    }
    info_message "Downloading $deb_url2 ..."
    curl -fsSL -o "$deb_file2" "$deb_url2" || {
        error_message "Failed to download $deb_url2"
        exit 1
    }
    info_message "Installing $(basename "$deb_url2") ..."
    maybe_sudo apt install -y "$deb_file2" || {
        error_message "Failed to install $deb_file2"
        exit 1
    }
    info_message "notify-send and dependencies installed/upgraded to $NOTIFY_SEND_VERSION."
}

# For Ubuntu: Ensure notify-send is at least expected version, else upgrade to it
ensure_notify_send_version() {
    if command_exists notify-send; then
        version=$(notify-send --version 2>&1 | awk '{print $NF}')
        if dpkg --compare-versions "$version" ge "$NOTIFY_SEND_VERSION"; then
            info_message "notify-send version $version is already installed."
        else
            warn_message "notify-send version $version found. Upgrading to $NOTIFY_SEND_VERSION..."
            install_notify_send
        fi
    else
        warn_message "notify-send not found. Installing version $NOTIFY_SEND_VERSION..."
        install_notify_send
    fi
}

ensure_zenity_is_installed() {
    if command_exists zenity; then
        info_message "Zenity is already installed."
    else
        warn_message "Zenity is not installed. Installing it now..."
        maybe_sudo apt install -y zenity || {
            error_message "Failed to install Zenity."
            exit 1
        }
    fi
}

ensure_macos_dependencies() {
    info_message "Ensuring required dependencies are installed..."

    if ! command_exists brew; then
        error_message "Homebrew is required to install dependencies. Please install Homebrew first: https://brew.sh/"
        exit 1
    fi

    local deps=("openssl@3" "pcre2" "libmagic" "jansson" "protobuf-c")
    local missing_deps=()

    # Check which dependencies are missing
    for dep in "${deps[@]}"; do
        if ! brew_command list "$dep" >/dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done

    # Install missing dependencies
    if [ ${#missing_deps[@]} -gt 0 ]; then
        info_message "Installing missing dependencies: ${missing_deps[*]}"
        for dep in "${missing_deps[@]}"; do
            info_message "Installing $dep..."
            if brew_command install "$dep"; then
                success_message "Installed $dep"
            else
                error_message "Failed to install $dep"
                exit 1
            fi
        done
    else
        info_message "All required dependencies are already installed"
    fi
}

install_yara_macos_prebuilt() {
    info_message "Installing YARA v${YARA_VERSION} from prebuilt binaries on macOS"

    # Ensure dependencies are installed
    ensure_macos_dependencies

    # Detect architecture
    local arch
    arch=$(uname -m)
    local binary_arch

    if [ "$arch" = "arm64" ]; then
        binary_arch="arm64"
        info_message "Detected ARM64 architecture"
    elif [ "$arch" = "x86_64" ]; then
        binary_arch="x86_64"
        info_message "Detected x86_64 architecture"
    else
        error_message "Unsupported architecture: $arch"
        exit 1
    fi

    # Construct download URL
    local binary_name="yara-${GITHUB_RELEASE_TAG}-macos-${binary_arch}.tar.gz"
    local download_url="${GITHUB_RELEASE_BASE_URL}/${GITHUB_RELEASE_TAG}/${binary_name}"

    info_message "Download URL: $download_url"

    # Download to temp directory
    local download_path="${TMP_DIR}/${binary_name}"
    print_step "1" "Downloading YARA prebuilt binary for ${binary_arch}"

    if ! curl -fsSL --progress-bar -o "$download_path" "$download_url"; then
        error_message "Failed to download YARA binary from: $download_url"
        error_message "Please check if the release exists and the tag is correct: ${GITHUB_RELEASE_TAG}"
        exit 1
    fi

    success_message "Downloaded YARA binary successfully"

    # Create installation directory
    local install_dir="/opt/yara"
    print_step "2" "Creating installation directory at ${install_dir}"

    if ! maybe_sudo mkdir -p "$install_dir"; then
        error_message "Failed to create installation directory: ${install_dir}"
        exit 1
    fi

    # Extract the tarball
    print_step "3" "Extracting YARA binary to ${install_dir}"

    # First extract to temp to check structure
    local temp_extract="${TMP_DIR}/yara_extract"
    mkdir -p "$temp_extract"

    if ! tar -xzf "$download_path" -C "$temp_extract"; then
        error_message "Failed to extract YARA binary"
        exit 1
    fi

    # Check if there's a nested directory and move contents appropriately
    local extracted_dir
    extracted_dir=$(find "$temp_extract" -maxdepth 1 -mindepth 1 -type d | head -n1)

    if [ -d "$extracted_dir/bin" ]; then
        # Contents are in a subdirectory, move them directly to install_dir
        info_message "Moving extracted contents directly to ${install_dir}"
        # Clear the install directory first to avoid nested structures
        maybe_sudo rm -rf "$install_dir"/*
        # Move the contents of the nested directory directly to install_dir
        maybe_sudo cp -R "$extracted_dir"/* "$install_dir/"
    else
        # Contents are directly extracted, move everything
        maybe_sudo cp -R "$temp_extract"/* "$install_dir/"
    fi

    success_message "Extracted YARA binary successfully"

    # Remove quarantine attributes from all extracted files
    print_step "4" "Removing macOS quarantine attributes"

    # Find all files and remove quarantine attribute
    if maybe_sudo find "$install_dir" -type f -exec xattr -d com.apple.quarantine {} \; 2>/dev/null; then
        success_message "Removed quarantine attributes from YARA files"
    else
        warn_message "No quarantine attributes found or already removed"
    fi

    # Set proper permissions
    print_step "5" "Setting proper permissions"

    maybe_sudo chmod -R 755 "$install_dir"

    # Create symlinks in /usr/local/bin for easier access
    print_step "6" "Creating symlinks for YARA executables"

    maybe_sudo mkdir -p /usr/local/bin

    # Create symlinks for yara and yarac
    if [ -f "$install_dir/bin/yara" ]; then
        maybe_sudo ln -sf "$install_dir/bin/yara" /usr/local/bin/yara
        success_message "Created symlink for yara"
    else
        error_message "yara executable not found in $install_dir/bin/"
        exit 1
    fi

    if [ -f "$install_dir/bin/yarac" ]; then
        maybe_sudo ln -sf "$install_dir/bin/yarac" /usr/local/bin/yarac
        success_message "Created symlink for yarac"
    else
        warn_message "yarac executable not found in $install_dir/bin/ (optional)"
    fi

    success_message "YARA v${YARA_VERSION} installed successfully from prebuilt binaries"
}

install_yara_linux_prebuilt() {
    info_message "Installing YARA v${YARA_VERSION} from prebuilt binaries on Linux"

    # Remove existing installations
    remove_apt_yara
    remove_prebuilt_yara
    remove_source_yara

    # Detect architecture
    local arch
    arch=$(uname -m)
    local binary_arch

    case "$arch" in
        x86_64)
            binary_arch="x86_64"
            info_message "Detected x86_64 architecture"
            ;;
        aarch64|arm64)
            binary_arch="aarch64"
            info_message "Detected ARM64 architecture"
            ;;
        *)
            error_message "Unsupported architecture: $arch"
            return 1
            ;;
    esac

    # Construct download URL based on release asset naming (Ubuntu/Debian only)
    local binary_name
    # Detect Ubuntu version for proper binary selection
    if [ "$DISTRO" = "ubuntu" ] && command_exists lsb_release; then
        ubuntu_version=$(lsb_release -rs 2>/dev/null || echo "")
        if [ "$ubuntu_version" = "22.04" ]; then
            info_message "Detected Ubuntu 22.04 - using Ubuntu 22 prebuilt binaries"
            if [ "$binary_arch" = "x86_64" ]; then
                binary_name="yara-${GITHUB_RELEASE_TAG}-ubuntu22-x86_64.tar.gz"
            else
                # Use Ubuntu 24 ARM binary for Ubuntu 22 ARM as fallback
                binary_name="yara-${GITHUB_RELEASE_TAG}-dirty-ubuntu-aarch64.tar.gz"
            fi
        else
            info_message "Detected Ubuntu ${ubuntu_version:-unknown} - using Ubuntu 24 prebuilt binaries"
            if [ "$binary_arch" = "x86_64" ]; then
                binary_name="yara-${GITHUB_RELEASE_TAG}-ubuntu-x86_64.tar.gz"
            else
                # aarch64
                binary_name="yara-${GITHUB_RELEASE_TAG}-dirty-ubuntu-aarch64.tar.gz"
            fi
        fi
    else
        # Default to Ubuntu 24 binaries for Debian or when version detection fails
        info_message "Using Ubuntu 24 prebuilt binaries for Debian"
        if [ "$binary_arch" = "x86_64" ]; then
            binary_name="yara-${GITHUB_RELEASE_TAG}-ubuntu-x86_64.tar.gz"
        else
            binary_name="yara-${GITHUB_RELEASE_TAG}-dirty-ubuntu-aarch64.tar.gz"
        fi
    fi
    local download_url="${GITHUB_RELEASE_BASE_URL}/${GITHUB_RELEASE_TAG}/${binary_name}"

    info_message "Download URL: $download_url"

    # Download to temp directory
    local download_path="${TMP_DIR}/${binary_name}"
    print_step "1" "Downloading YARA prebuilt binary for ${binary_arch}"

    if ! curl -fsSL --progress-bar -o "$download_path" "$download_url"; then
        error_message "Failed to download YARA binary from: $download_url"
        error_message "Please check if the release exists and the tag is correct: ${GITHUB_RELEASE_TAG}"
        return 1
    fi

    success_message "Downloaded YARA binary successfully"

    # Create installation directory
    local install_dir="/opt/yara"
    print_step "2" "Creating installation directory at ${install_dir}"

    if ! maybe_sudo mkdir -p "$install_dir"; then
        error_message "Failed to create installation directory: ${install_dir}"
        return 1
    fi

    # Extract the tarball
    print_step "3" "Extracting YARA binary to ${install_dir}"

    # First extract to temp to check structure
    local temp_extract="${TMP_DIR}/yara_extract_linux"
    mkdir -p "$temp_extract"

    if ! tar -xzf "$download_path" -C "$temp_extract"; then
        error_message "Failed to extract YARA binary"
        return 1
    fi

    # Check if there's a nested directory and move contents appropriately
    local extracted_dir
    extracted_dir=$(find "$temp_extract" -maxdepth 1 -mindepth 1 -type d | head -n1)

    if [ -d "$extracted_dir/bin" ]; then
        info_message "Moving extracted contents directly to ${install_dir}"
        maybe_sudo rm -rf "$install_dir"/*
        maybe_sudo cp -R "$extracted_dir"/* "$install_dir/"
    else
        maybe_sudo cp -R "$temp_extract"/* "$install_dir/"
    fi

    success_message "Extracted YARA binary successfully"

    # Set proper permissions
    print_step "4" "Setting proper permissions"
    maybe_sudo chmod -R 755 "$install_dir"

    # Create symlinks in /usr/local/bin for easier access
    print_step "5" "Creating symlinks for YARA executables"
    maybe_sudo mkdir -p /usr/local/bin

    if [ -f "$install_dir/bin/yara" ]; then
        maybe_sudo ln -sf "$install_dir/bin/yara" /usr/local/bin/yara
        success_message "Created symlink for yara"
    else
        error_message "yara executable not found in $install_dir/bin/"
        return 1
    fi

    if [ -f "$install_dir/bin/yarac" ]; then
        maybe_sudo ln -sf "$install_dir/bin/yarac" /usr/local/bin/yarac
        success_message "Created symlink for yarac"
    else
        warn_message "yarac executable not found in $install_dir/bin/ (optional)"
    fi

    # Verify installation
    print_step "6" "Verifying YARA installation"
    if command_exists yara; then
        local installed_version
        installed_version=$(yara --version)
        success_message "YARA installed successfully. Version: ${installed_version}"
    else
        error_message "YARA installation verification failed"
        return 1
    fi

    success_message "YARA v${YARA_VERSION} installed successfully from prebuilt binaries"
}

#=============================================================================
# SOURCE BUILD INSTALLATION FUNCTIONS
#=============================================================================


#=============================================================================
# POST-INSTALLATION FUNCTIONS (SHARED)
#=============================================================================

download_yara_script() {
    maybe_sudo mkdir -p "$(dirname "$YARA_SH_PATH")"

    maybe_sudo curl -SL --progress-bar "$YARA_SH_URL" -o "$TMP_DIR/yara.sh" || {
        error_message "Failed to download yara.sh script."
    }

    maybe_sudo mv "$TMP_DIR/yara.sh" "$YARA_SH_PATH"
    (change_owner "$YARA_SH_PATH" && maybe_sudo chmod 750 "$YARA_SH_PATH") || {
        error_message "Error occurred during yara.sh file permissions change."
    }
    info_message "yara.sh script downloaded and installed successfully."
}

reverse_update_ossec_conf() {
    if [ "$OS" = "darwin" ]; then
        # macOS
        if maybe_sudo grep -q '<directories realtime="yes">/Users, /Applications</directories>' "$OSSEC_CONF_PATH"; then
            info_message "Removing new yara configuration for macOS..."
            sed_alternative -i '/<directories realtime="yes">\/Users, \/Applications<\/directories>/d' "$OSSEC_CONF_PATH" || {
                error_message "Error occurred during removal of directories to monitor."
            }
            info_message "New yara configuration removed successfully on macOS."
        fi
    else
        # Linux
        if maybe_sudo grep -q '<directories realtime="yes">/home, /root, /bin, /sbin</directories>' "$OSSEC_CONF_PATH"; then
            info_message "Removing new yara configuration for Linux..."
            sed_alternative -i '/<directories realtime="yes">\/home, \/root, \/bin, \/sbin<\/directories>/d' "$OSSEC_CONF_PATH" || {
                error_message "Error occurred during removal of directories to monitor."
            }
            info_message "New yara configuration removed successfully on Linux."
        fi
    fi

    remove_file_limit
}

download_yara_rules() {
    YARA_RULES_FILE="$TMP_DIR/yara_rules.yar"
    YARA_RULES_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/refs/heads/main/rules/yara_rules.yar"
    maybe_sudo curl -SL --progress-bar "$YARA_RULES_URL" -o "$YARA_RULES_FILE"

    if [ "$OS" = "linux" ]; then
        YARA_RULES_DEST_DIR="/var/ossec/ruleset/yara/rules"
    elif [ "$OS" = "darwin" ]; then
        YARA_RULES_DEST_DIR="/Library/Ossec/ruleset/yara/rules"
    else
        error_message "Unsupported OS. Exiting..."
        exit 1
    fi

    if [ -s "$YARA_RULES_FILE" ]; then
        maybe_sudo mkdir -p "$YARA_RULES_DEST_DIR"
        maybe_sudo mv "$YARA_RULES_FILE" "$YARA_RULES_DEST_DIR/yara_rules.yar"
        change_owner "$YARA_RULES_DEST_DIR"
        info_message "YARA rules moved to $YARA_RULES_DEST_DIR."
    else
        error_message "Error occurred during YARA rules download."
        exit 1
    fi
}

validate_installation() {

    VALIDATION_STATUS="TRUE"

    # Only validate notify-send on Ubuntu/Debian systems where it's required
    if [ "$OS" = "linux" ] && { [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; }; then
        if command_exists notify-send; then
            if [ "$(notify-send --version 2>&1 | awk '{print $NF}')" = "$NOTIFY_SEND_VERSION" ]; then
                success_message "notify-send version $NOTIFY_SEND_VERSION is installed."
            else
                warn_message "notify-send version mismatch. Expected $NOTIFY_SEND_VERSION, but found $(notify-send --version 2>&1 | awk '{print $NF}')."
                VALIDATION_STATUS="FALSE"
            fi
        else
            warn_message "notify-send is not installed. Please install it to use notifications."
            VALIDATION_STATUS="FALSE"
        fi
    fi

    # Check YARA installation - try command first, then direct path
    local yara_found="FALSE"
    local actual_version=""

    if command_exists yara; then
        actual_version=$(yara --version)
        yara_found="TRUE"
    elif [ -f "/opt/yara/bin/yara" ]; then
        actual_version=$(/opt/yara/bin/yara --version)
        yara_found="TRUE"
    fi

    if [ "$yara_found" = "TRUE" ]; then
        if version_is_4_5_x "$actual_version"; then
            success_message "Yara version $actual_version is installed (4.5.x series)."
        else
            warn_message "Yara version $actual_version is not compatible. Version 4.5.x is required."
            VALIDATION_STATUS="FALSE"
        fi
    else
        error_message "Yara command is not available. Please check the installation."
        VALIDATION_STATUS="FALSE"
    fi

    if maybe_sudo [ ! -f "$YARA_RULES_DEST_DIR/yara_rules.yar" ]; then
        warn_message "Yara rules files not present at $YARA_RULES_DEST_DIR/yara_rules.yar."
        VALIDATION_STATUS="FALSE"
    else
        success_message "Yara rules files exists at $YARA_RULES_DEST_DIR/yara_rules.yar."
    fi

    if maybe_sudo [ ! -f "$YARA_SH_PATH" ]; then
        warn_message "Yara active response script not present at $YARA_SH_PATH."
        VALIDATION_STATUS="FALSE"
    else
        success_message "Yara active response script exists at $YARA_SH_PATH."
    fi

    if [ "$VALIDATION_STATUS" = "TRUE" ]; then
        success_message "YARA installation and configuration validation completed successfully."
    else
        error_message "YARA installation and configuration validation failed. Please check the warnings above."
        exit 1
    fi
}

#=============================================================================
# MAIN INSTALLATION FUNCTIONS
#=============================================================================

# Main function for OS with prebuilt binaries (Ubuntu/Debian, macOS)
main_prebuilt_installation() {
    info_message "Starting prebuilt binary installation for ${OS} (${DISTRO:-N/A})"

    # Step 1: Setup and cleanup
    print_step 1 "Setting up environment and checking for existing installations"
    check_and_update_bash

    # Check if YARA is already correctly installed
    if command_exists yara; then
        current_version=$(yara --version 2>/dev/null || echo "unknown")
        info_message "Current YARA version detected: $current_version"

        # Check if it's the version we want and in the right location
        if [ "$current_version" = "$YARA_VERSION" ]; then
            if [ "$OS" = "linux" ] && [ -d "/opt/yara" ]; then
                info_message "YARA prebuilt version $YARA_VERSION is already installed. Skipping installation."
                # Skip to post-installation steps
                print_step 4 "Downloading YARA rules..."
                download_yara_rules
                print_step 5 "Downloading yara.sh script..."
                download_yara_script
                print_step 6 "Updating Wazuh agent configuration..."
                if maybe_sudo [ -f "$OSSEC_CONF_PATH" ]; then
                    reverse_update_ossec_conf
                else
                    warn_message "OSSEC configuration file not found at $OSSEC_CONF_PATH."
                fi
                print_step 7 "Restarting Wazuh agent..."
                restart_wazuh_agent
                print_step 8 "Validating installation..."
                validate_installation
                return 0
            elif [ "$OS" = "darwin" ] && [ -d "/opt/yara" ]; then
                info_message "YARA prebuilt version $YARA_VERSION is already installed. Skipping installation."
                # Skip to post-installation steps (same as above)
                print_step 4 "Downloading YARA rules..."
                download_yara_rules
                print_step 5 "Downloading yara.sh script..."
                download_yara_script
                print_step 6 "Updating Wazuh agent configuration..."
                if maybe_sudo [ -f "$OSSEC_CONF_PATH" ]; then
                    reverse_update_ossec_conf
                else
                    warn_message "OSSEC configuration file not found at $OSSEC_CONF_PATH."
                fi
                print_step 7 "Restarting Wazuh agent..."
                restart_wazuh_agent
                print_step 8 "Validating installation..."
                validate_installation
                return 0
            fi
        fi

        # Different version or wrong installation method, clean up
        info_message "Different YARA version or installation method detected. Cleaning up..."
        if [ "$OS" = "darwin" ]; then
            remove_brew_yara
            remove_prebuilt_yara
        fi
    else
        # No YARA found, clean up any existing installations
        if [ "$OS" = "darwin" ]; then
            remove_brew_yara
            remove_prebuilt_yara
        fi
    fi

    # Step 2: Install platform-specific tools
    print_step 2 "Installing platform-specific tools and dependencies"
    if [ "$OS" = "linux" ]; then
        case "$DISTRO" in
            ubuntu|debian)
                ensure_notify_send_version
                ensure_zenity_is_installed
                ;;
        esac
    fi

    # Step 3: Install YARA from prebuilt binaries
    print_step 3 "Installing YARA v${YARA_VERSION} from prebuilt binaries"
    case "$OS" in
        linux)
            install_yara_linux_prebuilt
            ;;
        darwin)
            install_yara_macos_prebuilt
            ;;
        *)
            error_message "Unsupported operating system for prebuilt installation. Exiting..."
            exit 1
            ;;
    esac

    # Cleanup downloads directory
    if [ -d "$DOWNLOADS_DIR" ]; then
        info_message "Cleaning up downloads directory..."
        maybe_sudo rm -rf "$DOWNLOADS_DIR"
    fi

    # Step 4: Download YARA rules
    print_step 4 "Downloading YARA rules..."
    download_yara_rules

    # Step 5: Download yara.sh script
    print_step 5 "Downloading yara.sh script..."
    download_yara_script

    # Step 6: Update Wazuh agent configuration file
    print_step 6 "Updating Wazuh agent configuration file..."
    if maybe_sudo [ -f "$OSSEC_CONF_PATH" ]; then
        reverse_update_ossec_conf
    else
        warn_message "OSSEC configuration file not found at $OSSEC_CONF_PATH."
    fi

    # Step 7: Restart Wazuh agent
    print_step 7 "Restarting Wazuh agent..."
    restart_wazuh_agent

    # Step 8: Cleanup (handled by trap)
    print_step 8 "Cleaning up temporary files..."
    info_message "Temporary files cleaned up."

    # Step 9: Validate installation and configuration
    print_step 9 "Validating installation and configuration..."
    validate_installation

    success_message "Prebuilt binary installation completed successfully!"
}


#=============================================================================
# MAIN ENTRY POINT
#=============================================================================

# Main entry point function to determine which installation method to use
main() {
    info_message "Starting YARA installation script v${YARA_VERSION}"
    info_message "Detected OS: ${OS}"
    if [ "$OS" = "linux" ]; then
        info_message "Detected Linux distribution: ${DISTRO}"
    fi

    # Route to appropriate installation method based on OS and distribution
    case "$OS" in
        linux)
            case "$DISTRO" in
                ubuntu|debian)
                    info_message "Using prebuilt binary installation for Ubuntu/Debian"
                    main_prebuilt_installation
                    ;;
                *)
                    error_message "Unsupported Linux distribution: $DISTRO"
                    error_message "This script only supports Ubuntu and Debian distributions"
                    exit 1
                    ;;
            esac
            ;;
        darwin)
            info_message "Using prebuilt binary installation for macOS"
            main_prebuilt_installation
            ;;
        *)
            error_message "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
}

#=============================================================================
# SCRIPT EXECUTION
#=============================================================================

# Execute main function
main "$@"