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

custom_sed() {
    local pattern="$1"
    local file="$2"
    local tmp_file="$TMP_DIR/$(basename "$file")"

    if [ "$(uname)" = "Linux" ]; then
        maybe_sudo sed -e -i "$pattern" "$file" > "$tmp_file"
    elif [ "$(uname)" = "Darwin" ]; then
        maybe_sudo sed -e -i '' "$pattern" "$file" > "$tmp_file"
    else
        error_message "Unsupported OS for sed."
        exit 1
    fi

    mv "$tmp_file" "$file"
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
        if [ "$(uname -o)" = "GNU/Linux" ] && command -v groupadd >/dev/null 2>&1; then
            maybe_sudo useradd -m "$USER"
        elif [ "$(which apk)" = "/sbin/apk" ]; then
            maybe_sudo adduser -D "$USER"
        else
            error_message "Unsupported OS for creating user."
            exit 1
        fi
    fi

    if ! getent group "$GROUP" >/dev/null 2>&1; then
        info_message "Creating group $GROUP..."
        if [ "$(uname -o)" = "GNU/Linux" ] && command -v groupadd >/dev/null 2>&1; then
            maybe_sudo groupadd "$GROUP"
        elif [ "$(which apk)" = "/sbin/apk" ]; then
            maybe_sudo addgroup "$GROUP"
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
            maybe_sudo launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist
            maybe_sudo launchctl load /Library/LaunchDaemons/com.wazuh.agent.plist
            ;;
        *)
            error_message "Unsupported operating system for restarting Wazuh agent."
            exit 1
            ;;
    esac
}

check_file_limit() {
    if ! sudo grep -q "<file_limit>" "$OSSEC_CONF_PATH"; then
        FILE_LIMIT_BLOCK="<!-- Maximum number of files to be monitored -->\n <file_limit>\n  <enabled>no</enabled>\n</file_limit>\n"
        # Add the file_limit block after the <disabled>no</disabled> line
        maybe_sudo sed -i "/<syscheck>/a $FILE_LIMIT_BLOCK" "$OSSEC_CONF_PATH" || {
            error_message "Error occurred during the addition of the file_limit block."
            exit 1
        }
        info_message "The file limit block was added successfully"
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

  # Ensure the parent directory for YARA_SH_PATH exists
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
    if [ "$(uname)" = "Linux" ]; then
        OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
    elif [ "$(uname)" = "Darwin" ]; then
        OSSEC_CONF_PATH="/Library/Ossec/etc/ossec.conf"
    else
        error_message "Unsupported OS. Exiting..."
        exit 1
    fi

    if ! sudo grep -q '<directories realtime="yes">\/home, \/root, \/bin, \/sbin</directories>' "$OSSEC_CONF_PATH"; then
      custom_sed '/<directories>\/etc,\/usr\/bin,\/usr\/sbin<\/directories>/a\
        <directories realtime="yes">\/home, \/root, \/bin, \/sbin</directories>' "$OSSEC_CONF_PATH" || {
            error_message "Error occurred during configuration of directories to monitor."
            exit 1
        }
    fi

    info_message "Wazuh agent configuration file updated successfully."

    custom_sed 's/<frequency>43200<\/frequency>/<frequency>300<\/frequency>/g' "$OSSEC_CONF_PATH" || {
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
print_step 2 "Downloading YARA rules..."

YARA_RULES_URL="https://valhalla.nextron-systems.com/api/v1/get"
YARA_RULES_FILE="$TMP_DIR/yara_rules.yar"
API_KEY="1111111111111111111111111111111111111111111111111111111111111111"
YARA_RULES_DEST_DIR="/var/ossec/ruleset/yara/rules"

download_yara_rules() {
    info_message "Downloading YARA rules..."
    maybe_sudo curl -SL --progress-bar "$YARA_RULES_URL" \
        -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
        -H 'Accept-Language: en-US,en;q=0.5' \
        --compressed \
        -H 'Referer: https://valhalla.nextron-systems.com/' \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -H 'DNT: 1' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' \
        --data "demo=demo&apikey=$API_KEY&format=text" \
        -o "$YARA_RULES_FILE"

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
update_ossec_conf

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
