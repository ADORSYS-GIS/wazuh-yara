#!/bin/sh

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
YARA_URL="https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz"
YARA_SH_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/yara.sh"

DOWNLOADS_DIR="${HOME}/yara-install"
TAR_DIR="$DOWNLOADS_DIR/yara-${YARA_VERSION}.tar.gz"
EXTRACT_DIR="$DOWNLOADS_DIR/yara-${YARA_VERSION}"

NOTIFY_SEND_VERSION=0.8.3
LOGGED_IN_USER=""

if [ "$(uname -s)" = "Darwin" ]; then
    LOGGED_IN_USER=$(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ {print $3}')
fi

OS="$(uname -s)"

if [ "$OS" = "Linux" ]; then
    OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
    WAZUH_CONTROL_BIN_PATH="/var/ossec/bin/wazuh-control"
    YARA_SH_PATH="/var/ossec/active-response/bin/yara.sh"
elif [ "$OS" = "Darwin" ]; then
    OSSEC_CONF_PATH="/Library/Ossec/etc/ossec.conf"
    WAZUH_CONTROL_BIN_PATH="/Library/Ossec/bin/wazuh-control"
    YARA_SH_PATH="/Library/Ossec/active-response/bin/yara.sh"
else
    error_message "Unsupported OS. Exiting..."
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

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
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

# Ensure that the root:wazuh user and group exist, creating them if necessary
ensure_user_group() {
    info_message "Ensuring that the $USER:$GROUP user and group exist..."

    if ! id -u "$USER" >/dev/null 2>&1; then
        info_message "Creating user $USER..."
        if [ "$OS" = "Linux" ] && command -v groupadd >/dev/null 2>&1; then
            maybe_sudo useradd -m "$USER"
        elif [ "$(which apk)" = "/sbin/apk" ]; then
            maybe_sudo adduser -D "$USER"
        elif [ "$OS" = "Darwin" ]; then
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
        if [ "$OS" = "Linux" ] && command -v groupadd >/dev/null 2>&1; then
            maybe_sudo groupadd "$GROUP"
        elif [ "$(which apk)" = "/sbin/apk" ]; then
            maybe_sudo addgroup "$GROUP"
        elif [ "$OS" = "Darwin" ]; then
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
    if [ "$OS" = "Darwin" ]; then
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
            info_message "Detected other version of YARA; uninstalling via brew"
            brew_command unpin yara
            brew_command uninstall --force yara || {
                error_message "Failed to remove Homebrew-installed YARA"
            }
            success_message "Homebrew-installed YARA removed"
        fi
    fi
}

check_and_update_bash() {
    if [ "$OS" = "Darwin" ]; then
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

install_yara_ubuntu() {
    info_message "Installing YARA v${YARA_VERSION} from source on Ubuntu" ""

    # Check required tools
    for cmd in curl tar make gcc pkg-config; do
        if ! command_exists "$cmd"; then
            warn_message "$cmd not found; it will be installed as a dependency."
        fi
    done

    print_step "1" "Installing build dependencies"
    maybe_sudo apt update -qq
    maybe_sudo apt install -y automake libtool make gcc pkg-config flex bison curl libjansson-dev libmagic-dev libssl-dev

    print_step "2" "Downloading YARA $YARA_VERSION to $DOWNLOADS_DIR"
    if ! curl -fsSL -o "$TAR_DIR" "$YARA_URL"; then
        error_message "Failed to download YARA source tarball"
        return 1
    fi

    print_step "3" "Extracting source to $DOWNLOADS_DIR"
    maybe_sudo rm -rf "$EXTRACT_DIR"
    mkdir -p "$EXTRACT_DIR"
    if ! tar -xzf "$TAR_DIR" -C "$DOWNLOADS_DIR"; then
        error_message "Failed to extract YARA tarball"
        return 1
    fi

    print_step "4" "Building & installing"
    pushd "$EXTRACT_DIR" >/dev/null 2>&1 || return 1

    info_message "Running bootstrap.sh"
    maybe_sudo ./bootstrap.sh

    info_message "Configuring build"
    maybe_sudo ./configure --disable-silent-rules --enable-cuckoo --enable-magic --enable-dotnet --enable-macho --enable-dex --with-crypto

    info_message "Compiling"
    maybe_sudo make

    info_message "Installing (this may prompt for sudo password)"
    maybe_sudo make install

    info_message "Running test suite"
    maybe_sudo make check

    info_message "Updating shared library cache: sudo ldconfig ..."
    maybe_sudo ldconfig

    popd >/dev/null 2>&1

    success_message "YARA v${YARA_VERSION} installed from source successfully"
}

install_yara_macos() {
    info_message "Installing YARA v${YARA_VERSION} via Homebrew tap on macOS"

    if ! command_exists brew; then
        error_message "Homebrew is not installed. Please install Homebrew first: https://brew.sh/"
        exit 1
    fi

    # Tap the adorsys-gis tools repository
    TAP_NAME="adorsys-gis/tools"
    
    info_message "Tapping $TAP_NAME repository..."
    brew_command tap "$TAP_NAME" "https://github.com/adorsys-gis/homebrew-tools" || {
        error_message "Failed to tap $TAP_NAME repository"
        exit 1
    }

    # Install specific yara version from the tap
    brew_command install "$TAP_NAME/yara@4.5.4" || {
        error_message "Failed to install YARA 4.5.4 from tap"
        exit 1
    }

    success_message "YARA v${YARA_VERSION} installed successfully via local Homebrew tap"
}

install_yara() {
    case "$OS" in
    Linux)
        if command -v apt >/dev/null 2>&1; then
            install_yara_ubuntu
        else
            error_message "Unsupported Linux distribution. Exiting..."
            exit 1
        fi
        ;;
    Darwin)
        install_yara_macos
        ;;
    *)
        error_message "Unsupported operating system. Exiting..."
        exit 1
        ;;
    esac
}

install_yara_and_tools(){
    if [ "$OS" = "Linux" ]; then
        remove_apt_yara
        ensure_notify_send_version
        ensure_zenity_is_installed
    fi
    if command_exists yara; then
        if [ "$(yara --version)" = "$YARA_VERSION" ]; then
            info_message "YARA is already installed. Skipping installation."
        else
            if [ "$OS" = "Darwin" ]; then
                brew_command unpin yara
                remove_brew_yara
            fi
            info_message "Installing YARA..."
            install_yara
        fi
    else
        info_message "Installing YARA..."
        install_yara
    fi
    if [ -d "$DOWNLOADS_DIR" ]; then
        info_message "Cleaning up downloads directory..."
        maybe_sudo rm -rf "$DOWNLOADS_DIR"
    fi
}

download_yara_rules() {
    YARA_RULES_FILE="$TMP_DIR/yara_rules.yar"
    YARA_RULES_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/refs/heads/main/rules/yara_rules.yar"
    maybe_sudo curl -SL --progress-bar "$YARA_RULES_URL" -o "$YARA_RULES_FILE"

    if [ "$OS" = "Linux" ]; then
        YARA_RULES_DEST_DIR="/var/ossec/ruleset/yara/rules"
    elif [ "$OS" = "Darwin" ]; then
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

    if [ "$OS" = "Linux" ]; then
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

    if command_exists yara; then
        if [ "$(yara --version)" = "$YARA_VERSION" ]; then
            success_message "Yara version $YARA_VERSION is installed."
        else
            warn_message "Yara version mismatch. Expected $YARA_VERSION, but found $(yara --version)."
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

#--------------------------------------------#

# Step 1: Install YARA and necessary tools
print_step 1 "Installing YARA and necessary tools..."
# Check and update Bash version if needed
check_and_update_bash
install_yara_and_tools

# Step 2: Download YARA rules
print_step 2 "Downloading YARA rules..."
download_yara_rules

# Step 3: Download yara.sh script
print_step 3 "Downloading yara.sh script..."
download_yara_script

# Step 4: Update Wazuh agent configuration file
print_step 4 "Updating Wazuh agent configuration file..."
if maybe_sudo [ -f "$OSSEC_CONF_PATH" ]; then
    reverse_update_ossec_conf
else
    warn_message "OSSEC configuration file not found at $OSSEC_CONF_PATH."
fi

# Step 5: Restart Wazuh agent
print_step 5 "Restarting Wazuh agent..."
restart_wazuh_agent

# Step 6: Cleanup (handled by trap)
print_step 6 "Cleaning up temporary files..."
info_message "Temporary files cleaned up."

# Step 7: Validate installation and configuration
print_step 7 "Validating installation and configuration..."
validate_installation
