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

# Function to handle logging
log() {
    local LEVEL="$1"
    shift
    local MESSAGE="$*"
    local TIMESTAMP="$(date +"%Y-%m-%d %H:%M:%S")"

    if [ "$LEVEL" = "ERROR" ] || { [ "$LEVEL" = "WARNING" ] && [ "$LOG_LEVEL" != "ERROR" ]; } || { [ "$LEVEL" = "INFO" ] && [ "$LOG_LEVEL" = "INFO" ]; }; then
        echo "$TIMESTAMP [$LEVEL] $MESSAGE"
    fi
}

# Function to print steps
print_step() {
    local step="$1"
    local message="$2"
    log INFO "------ Step $step : $message ------"
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
        log ERROR "Unsupported OS for sed."
        exit 1
    fi

    mv "$tmp_file" "$file"
}

# Create a temporary directory and ensure it's cleaned up on exit
TMP_DIR=$(mktemp -d)
cleanup() {
    log INFO "Cleaning up temporary files..."
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Check if sudo is available or if the script is run as root
maybe_sudo() {
    if [ "$(id -u)" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            sudo "$@"
        else
            log ERROR "This script requires root privileges. Please run with sudo or as root."
            exit 1
        fi
    else
        "$@"
    fi
}

# Ensure that the root:wazuh user and group exist, creating them if necessary
ensure_user_group() {
    log INFO "Ensuring that the $USER:$GROUP user and group exist..."

    if ! id -u "$USER" >/dev/null 2>&1; then
        log INFO "Creating user $USER..."
        if [ "$(uname -o)" = "GNU/Linux" ] && command -v groupadd >/dev/null 2>&1; then
            maybe_sudo useradd -m "$USER"
        elif [ "$(which apk)" = "/sbin/apk" ]; then
            maybe_sudo adduser -D "$USER"
        else
            log ERROR "Unsupported OS for creating user."
            exit 1
        fi
    fi

    if ! getent group "$GROUP" >/dev/null 2>&1; then
        log INFO "Creating group $GROUP..."
        if [ "$(uname -o)" = "GNU/Linux" ] && command -v groupadd >/dev/null 2>&1; then
            maybe_sudo groupadd "$GROUP"
        elif [ "$(which apk)" = "/sbin/apk" ]; then
            maybe_sudo addgroup "$GROUP"
        else
            log ERROR "Unsupported OS for creating group."
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
                log INFO "Wazuh agent restarted successfully."
            else
                log ERROR "Error occurred during Wazuh agent restart."
            fi
            ;;
        Darwin)
            maybe_sudo launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist
            maybe_sudo launchctl load /Library/LaunchDaemons/com.wazuh.agent.plist
            ;;
        *)
            log ERROR "Unsupported operating system for restarting Wazuh agent."
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
        log INFO "The file limit block was added successfully"
    fi
}

#--------------------------------------------#

# Step 1: Install YARA and necessary tools
print_step 1 "Installing YARA and necessary tools..."

install_yara_ubuntu() {
    log INFO "Installing YARA on Ubuntu/Debian..."
    maybe_sudo apt update
    maybe_sudo apt install -y yara jq curl git
}

install_yara_alpine() {
    log INFO "Installing YARA on Alpine Linux..."
    maybe_sudo apk update
    maybe_sudo apk add yara jq curl git
}

install_yara_centos() {
    log INFO "Installing YARA on CentOS/RHEL..."
    maybe_sudo yum install -y epel-release
    maybe_sudo yum install -y yara jq curl git
}

install_yara_fedora() {
    log INFO "Installing YARA on Fedora..."
    maybe_sudo dnf install -y yara jq curl git
}

install_yara_suse() {
    log INFO "Installing YARA on SUSE..."
    maybe_sudo zypper install -y yara jq curl git
}

install_yara_arch() {
    log INFO "Installing YARA on Arch Linux..."
    maybe_sudo pacman -Syu --noconfirm yara jq curl git
}

install_yara_busybox() {
    log INFO "Installing YARA on BusyBox..."
    log ERROR "BusyBox does not support direct package management for YARA. Consider cross-compiling or using a pre-built binary."
    exit 1
}

install_yara_macos() {
    log INFO "Installing YARA on macOS..."
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
                log ERROR "Unsupported Linux distribution. Exiting..."
                exit 1
            fi
            ;;
        Darwin)
            install_yara_macos
            ;;
        *)
            log ERROR "Unsupported operating system. Exiting..."
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
    log INFO "Downloading YARA rules..."
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
        log INFO "YARA rules moved to $YARA_RULES_DEST_DIR."
    else
        log ERROR "Error occurred during YARA rules download."
        exit 1
    fi
}

download_yara_rules

# Step 3: Download yara.sh script
print_step 3 "Downloading yara.sh script..."

YARA_SH_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/yara.sh" #TODO: Update URL
if [ "$(uname)" = "Linux" ]; then
    YARA_SH_PATH="/var/ossec/active-response/bin/yara.sh"
    OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
elif [ "$(uname)" = "Darwin" ]; then
    YARA_SH_PATH="/Library/Ossec/active-response/bin/yara.sh"
    OSSEC_CONF_PATH="/Library/Ossec/etc/ossec.conf"
else
    log ERROR "Unsupported OS. Exiting..."
    exit 1
fi

# Ensure the parent directory for YARA_SH_PATH exists
maybe_sudo mkdir -p "$(dirname "$YARA_SH_PATH")"

maybe_sudo curl -SL --progress-bar "$YARA_SH_URL" -o "$TMP_DIR/yara.sh" || {
    log ERROR "Failed to download yara.sh script."
    exit 1
}

maybe_sudo mv "$TMP_DIR/yara.sh" "$YARA_SH_PATH"
(change_owner "$YARA_SH_PATH" && maybe_sudo chmod 750 "$YARA_SH_PATH") || {
    log ERROR "Error occurred during yara.sh file permissions change."
    exit 1
}
log INFO "yara.sh script downloaded and installed successfully."

# Step 4: Update Wazuh agent configuration file
print_step 4 "Updating Wazuh agent configuration file..."
custom_sed '/<directories>\/etc,\/usr\/bin,\/usr\/sbin<\/directories>/a\
    <directories realtime="yes">/tmp/yara/malware</directories>' "$OSSEC_CONF_PATH" || {
        log ERROR "Error occurred during Wazuh agent configuration file update."
        exit 1
    }
log INFO "Wazuh agent configuration file updated successfully."

# Step 5: Update frequency in Wazuh agent configuration file
print_step 5 "Updating frequency in Wazuh agent configuration file..."
custom_sed 's/<frequency>43200<\/frequency>/<frequency>300<\/frequency>/g' "$OSSEC_CONF_PATH" || {
    log ERROR "Error occurred during frequency update in Wazuh agent configuration file."
    exit 1
}
log INFO "Frequency in Wazuh agent configuration file updated successfully."

check_file_limit

# Step 6: Restart Wazuh agent
print_step 6 "Restarting Wazuh agent..."

restart_wazuh_agent || {
    log ERROR "Error occurred during Wazuh agent restart."
}
log INFO "Wazuh agent restarted successfully."

# Clean up temporary files
print_step 7 "Cleaning up temporary files..."
# The cleanup will be automatically done due to the trap
log INFO "Temporary files cleaned up."
