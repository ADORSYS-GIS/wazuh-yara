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

DOWNLOADS_DIR="${HOME}/yara-install"
TAR_DIR="$DOWNLOADS_DIR/yara-${YARA_VERSION}.tar.gz"
EXTRACT_DIR="$DOWNLOADS_DIR/yara-${YARA_VERSION}"

if [ "$(uname)" = "Linux" ]; then
    OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
elif [ "$(uname)" = "Darwin" ]; then
    OSSEC_CONF_PATH="/Library/Ossec/etc/ossec.conf"
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
        if [ "$(uname -s)" = "Linux" ] && command -v groupadd >/dev/null 2>&1; then
            maybe_sudo useradd -m "$USER"
        elif [ "$(which apk)" = "/sbin/apk" ]; then
            maybe_sudo adduser -D "$USER"
        elif [ "$(uname -s)" = "Darwin" ]; then
            # macOS
            if ! dscl . -list /Users | grep -q "^$USER$"; then
                info_message "Creating user $USER on macOS..."
                maybe_sudo sysadminctl -addUser "$USER" -fullName "$USER"
            fi
        else
            error_message "Unsupported OS for creating user."
            exit 1
        fi
    fi

    if ! getent group "$GROUP" >/dev/null 2>&1; then
        info_message "Creating group $GROUP..."
        if [ "$(uname -s)" = "Linux" ] && command -v groupadd >/dev/null 2>&1; then
            maybe_sudo groupadd "$GROUP"
        elif [ "$(which apk)" = "/sbin/apk" ]; then
            maybe_sudo addgroup "$GROUP"
        elif [ "$(uname -s)" = "Darwin" ]; then
            # macOS
            if ! dscl . -list /Groups | grep -q "^$GROUP$"; then
                info_message "Creating group $GROUP on macOS..."
                maybe_sudo dscl . -create /Groups/"$GROUP"
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
    maybe_sudo chown "$USER:$GROUP" "$path"
}

restart_wazuh_agent() {
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

remove_file_limit() {
    if maybe_sudo grep -q "<file_limit>" "$OSSEC_CONF_PATH"; then
        # Remove the file_limit block
        sed_alternative -i "/<file_limit>/,/<\/file_limit>/d" "$OSSEC_CONF_PATH" || {
            error_message "Error occurred during the removal of the file_limit block."
            exit 1
        }
        info_message "The file limit block was removed successfully."
    else
        info_message "The file limit block does not exist. No changes were made."
    fi
}

download_yara_script() {
    YARA_SH_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/yara.sh" # TODO: Update URL if needed
    if [ "$(uname)" = "Linux" ]; then
        YARA_SH_PATH="/var/ossec/active-response/bin/yara.sh"
    elif [ "$(uname)" = "Darwin" ]; then
        YARA_SH_PATH="/Library/Ossec/active-response/bin/yara.sh"
    else
        error_message "Unsupported OS. Exiting..."
        exit 1
    fi

    maybe_sudo mkdir -p "$(dirname "$YARA_SH_PATH")"

    maybe_sudo curl -SL --progress-bar "$YARA_SH_URL" -o "$TMP_DIR/yara.sh" || {
        error_message "Failed to download yara.sh script."
        exit 1
    }

    maybe_sudo mv "$TMP_DIR/yara.sh" "$YARA_SH_PATH"
    (change_owner "$YARA_SH_PATH" && maybe_sudo chmod 750 "$YARA_SH_PATH") || {
        error_message "Error occurred during yara.sh file permissions change."
        exit 1
    }
    info_message "yara.sh script downloaded and installed successfully."
}

reverse_update_ossec_conf() {
    if [ "$(uname)" = "Darwin" ]; then
        # macOS
        if maybe_sudo grep -q '<directories realtime="yes">/Users, /Applications</directories>' "$OSSEC_CONF_PATH"; then
            info_message "Removing new yara configuration for macOS..."
            sed_alternative -i '/<directories realtime="yes">\/Users, \/Applications<\/directories>/d' "$OSSEC_CONF_PATH" || {
                error_message "Error occurred during removal of directories to monitor."
                exit 1
            }
            info_message "New yara configuration removed successfully on macOS."
        fi
    else
        # Linux
        if maybe_sudo grep -q '<directories realtime="yes">/home, /root, /bin, /sbin</directories>' "$OSSEC_CONF_PATH"; then
            info_message "Removing new yara configuration for Linux..."
            sed_alternative -i '/<directories realtime="yes">\/home, \/root, \/bin, \/sbin<\/directories>/d' "$OSSEC_CONF_PATH" || {
                error_message "Error occurred during removal of directories to monitor."
                exit 1
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
            maybe_sudo apt-get remove -y yara || {
                error_message "Failed to remove apt-installed YARA"
                exit 1
            }
            maybe_sudo apt-get autoremove -y
            success_message "Apt-installed YARA removed"
        fi
    fi
}

remove_brew_yara() {
    # only on macOS/Homebrew
    if command_exists brew; then
        if brew list yara >/dev/null 2>&1; then
            info_message "Removing Homebrew-installed YARA package"
            info_message "Detected Homebrew YARA; uninstalling via brew"
            brew uninstall --force yara || {
                error_message "Failed to remove Homebrew-installed YARA"
                exit 1
            }
            success_message "Homebrew-installed YARA removed"
        fi
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
    maybe_sudo apt-get update -qq
    maybe_sudo apt-get install -y automake libtool make gcc pkg-config flex bison curl

    print_step "2" "Downloading YARA $YARA_VERSION to $DOWNLOADS_DIR"
    if ! curl -fsSL -o "$TAR_DIR" "$YARA_URL"; then
        error_message "Failed to download YARA source tarball"
        return 1
    fi

    print_step "3" "Extracting source to $DOWNLOADS_DIR"
    rm -rf "$EXTRACT_DIR"
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
    maybe_sudo ./configure

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
    info_message "Installing YARA v${YARA_VERSION} from source on macOS" ""
    YARA_RB_URL="https://raw.githubusercontent.com/Homebrew/homebrew-core/5239837c0dc157e5ffdfb2de325e942118db9485/Formula/y/yara.rb" #v4.5.4
    YARA_RP_PATH="$DOWNLOADS_DIR/yara.rb"

    curl -SL --progress-bar "$YARA_RB_URL" -o "$YARA_RP_PATH" || {
        error_message "Failed to download yara.rb file"
        exit 1
    }

    brew install --formula "$YARA_RP_PATH"
    brew pin yara

    success_message "YARA v${YARA_VERSION} built and installed from source on macOS successfully"
}


install_yara_tools() {
    case "$(uname)" in
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

#--------------------------------------------#

# Step 1: Install YARA and necessary tools
print_step 1 "Installing YARA and necessary tools..."

if [ "$(uname)" = "Linux" ]; then
    remove_apt_yara
fi

if command_exists yara; then
    if [ "$(yara --version)" == "$YARA_VERSION" ]; then
        info_message "YARA is already installed. Skipping installation."
    else
        info_message "Installing YARA..."
        if [ "$(uname)" = "Darwin" ]; then
            remove_brew_yara
        fi
        install_yara_tools
    fi
else
    info_message "Installing YARA..."
    install_yara_tools
fi

if [ -d "$DOWNLOADS_DIR" ]; then
    info_message "Cleaning up downloads directory..."
    maybe_sudo rm -rf "$DOWNLOADS_DIR"
fi

# Step 2: Download YARA rules
print_step 2 "Downloading YARA rules..."
YARA_RULES_FILE="$TMP_DIR/yara_rules.yar"
download_yara_rules() {
    YARA_RULES_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/refs/heads/main/rules/yara_rules.yar"
    maybe_sudo curl -SL --progress-bar "$YARA_RULES_URL" -o "$YARA_RULES_FILE"

    if [ "$(uname)" = "Linux" ]; then
        YARA_RULES_DEST_DIR="/var/ossec/ruleset/yara/rules"
    elif [ "$(uname)" = "Darwin" ]; then
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
    exit 1
fi

# Step 5: Restart Wazuh agent
print_step 5 "Restarting Wazuh agent..."
restart_wazuh_agent || {
    error_message "Error occurred during Wazuh agent restart."
}
info_message "Wazuh agent restarted successfully."

# Step 6: Validate installation and configuration
validate_installation() {
    if command_exists yara; then
        success_message "Yara is running."
    else
        error_message "Yara is not installed."
    fi

    if maybe_sudo [ ! -f "$YARA_RULES_DEST_DIR/yara_rules.yar" ]; then
        warn_message "Yara rules files not present at $YARA_RULES_DEST_DIR/yara_rules.yar."
    else
        success_message "Yara rules files exists at $YARA_RULES_DEST_DIR/yara_rules.yar."
    fi

    if maybe_sudo [ ! -f "$YARA_SH_PATH" ]; then
        warn_message "Yara active response script not present at $YARA_SH_PATH."
    else
        success_message "Yara active response script exists at $YARA_SH_PATH."
    fi

    success_message "Installation and configuration validated successfully."
}
print_step 6 "Validating installation and configuration..."
validate_installation

# Step 7: Cleanup (handled by trap)
print_step 7 "Cleaning up temporary files..."
info_message "Temporary files cleaned up."
