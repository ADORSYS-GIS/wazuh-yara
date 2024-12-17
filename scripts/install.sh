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

# Create a temporary directory and ensure it's cleaned up on exit
TMP_DIR=$(mktemp -d)
cleanup() {
    info_message "Cleaning up temporary files..."
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

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

check_file_limit() {
    # Determine the OS type
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        SED_CMD="sed -i ''"
    else
        # Linux
        SED_CMD="sed -i"
    fi

    if ! maybe_sudo grep -q "<file_limit>" "$OSSEC_CONF_PATH"; then
        FILE_LIMIT_BLOCK="<!-- Maximum number of files to be monitored -->\n <file_limit>\n  <enabled>no</enabled>\n</file_limit>\n"
        # Add the file_limit block after the <syscheck> line
        maybe_sudo $SED_CMD "/<syscheck>/a\\
$FILE_LIMIT_BLOCK" "$OSSEC_CONF_PATH" || {
            error_message "Error occurred during the addition of the file_limit block."
            exit 1
        }
        info_message "The file limit block was added successfully."
    fi
}


download_yara_script() {
  YARA_SH_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/yara.sh" #TODO: Update URL
  if [ "$(uname)" = "Linux" ]; then
      YARA_SH_PATH="/var/ossec/active-response/bin/yara.sh"
  elif [ "$(uname)" = "Darwin" ]; then
      YARA_SH_PATH="/Library/Ossec/active-response/bin/yara.sh"
  else
      error_message "Unsupported OS. Exiting..."
      exit 1
  fi

  # # Ensure the parent directory for YARA_SH_PATH exists
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

update_ossec_conf() {
    # Determine the OS type
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        SED_CMD="sed -i ''"
    else
        # Linux
        SED_CMD="sed -i"
    fi

    # Check and update configuration file
    if ! maybe_sudo grep -q '<directories realtime="yes">\/home, \/root, \/bin, \/sbin</directories>' "$OSSEC_CONF_PATH"; then
      maybe_sudo $SED_CMD '/<directories>\/etc,\/usr\/bin,\/usr\/sbin<\/directories>/a\
        <directories realtime="yes">\/home, \/root, \/bin, \/sbin</directories>' "$OSSEC_CONF_PATH" || {
            error_message "Error occurred during configuration of directories to monitor."
            exit 1
        }
    fi

    info_message "Wazuh agent configuration file updated successfully."

    maybe_sudo $SED_CMD 's/<frequency>43200<\/frequency>/<frequency>300<\/frequency>/g' "$OSSEC_CONF_PATH" || {
        error_message "Error occurred during frequency update in Wazuh agent configuration file."
        exit 1
    }
    info_message "Frequency in Wazuh agent configuration file updated successfully."

    check_file_limit
}


#--------------------------------------------#

# Step 1: Install YARA and necessary tools
print_step 1 "Installing YARA and necessary tools..."

install_yara_ubuntu() {
    info_message "Installing YARA on Ubuntu/Debian..."
    maybe_sudo apt update
    maybe_sudo apt install -y yara jq curl git
}

install_yara_alpine() {
    info_message "Installing YARA on Alpine Linux..."
    maybe_sudo apk update
    maybe_sudo apk add yara jq curl git
}

install_yara_centos() {
    info_message "Installing YARA on CentOS/RHEL..."
    maybe_sudo yum install -y epel-release
    maybe_sudo yum install -y yara jq curl git
}

install_yara_fedora() {
    info_message "Installing YARA on Fedora..."
    maybe_sudo dnf install -y yara jq curl git
}

install_yara_suse() {
    info_message "Installing YARA on SUSE..."
    maybe_sudo zypper install -y yara jq curl git
}

install_yara_arch() {
    info_message "Installing YARA on Arch Linux..."
    maybe_sudo pacman -Syu --noconfirm yara jq curl git
}

install_yara_busybox() {
    info_message "Installing YARA on BusyBox..."
    error_message "BusyBox does not support direct package management for YARA. Consider cross-compiling or using a pre-built binary."
    exit 1
}

install_yara_macos() {
    info_message "Installing YARA on macOS..."
    brew install yara jq curl git
}

install_yara_tools() {
    case "$(uname)" in
        Linux)
            if command -v apt >/dev/null 2>&1; then
                install_yara_ubuntu
            elif command -v apk >/dev/null 2>&1; then
                install_yara_alpine
            elif command -v yum >/dev/null 2>&1; then
                install_yara_centos
            elif command -v dnf >/dev/null 2>&1; then
                install_yara_fedora
            elif command -v zypper >/dev/null 2>&1; then
                install_yara_suse
            elif command -v pacman >/dev/null 2>&1; then
                install_yara_arch
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

install_yara_tools

# Step 2: Download YARA rules

# Update the URL to the raw file on GitHub
YARA_RULES_FILE="$TMP_DIR/yara_rules.yar"

download_yara_rules() {

    YARA_RULES_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/refs/heads/main/rules/yara_rules.yar"

    info_message "Downloading YARA rules..."
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

# Check if the OSSEC configuration file exists
if maybe_sudo [ -f "$OSSEC_CONF_PATH" ]; then
    # Call the function to update OSSEC configuration
    update_ossec_conf
else
    # Notify the user that the file is missing
    warn_message "OSSEC configuration file not found at $OSSEC_CONF_PATH."
    # Exit the script with a non-zero status
    exit 1
fi

# Step 5: Restart Wazuh agent
print_step 5 "Restarting Wazuh agent..."

restart_wazuh_agent || {
    error_message "Error occurred during Wazuh agent restart."
}
info_message "Wazuh agent restarted successfully."

# Clean up temporary files
print_step 6 "Cleaning up temporary files..."
# The cleanup will be automatically done due to the trap
info_message "Temporary files cleaned up."
