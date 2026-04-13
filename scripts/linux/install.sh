#!/usr/bin/env bash

# Set shell options based on shell type
if [[ -n "${BASH_VERSION:-}" ]]; then
    set -euo pipefail
else
    set -eu
fi

# OS guard early in the script
if [[ "$(uname -s)" != "Linux" ]]; then
    printf "%s\n" "[ERROR] This installation script is intended for Linux systems. Please use the appropriate script for your operating system." >&2
    exit 1
fi

# Variables
YARA_VERSION=${YARA_VERSION:-"4.5.5"}
YARA_VERSION_SET=0
YARA_SCRIPT_NAME="yara.sh"
WAZUH_YARA_REPO_REF=${WAZUH_YARA_REPO_REF:-"main"}
WAZUH_YARA_REPO_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/${WAZUH_YARA_REPO_REF}"
YARA_RULES_URL="${WAZUH_YARA_REPO_URL}/rules/yara_rules.yar"

# GitHub Release configuration for packages
GITHUB_RELEASE_BASE_URL="https://github.com/ADORSYS-GIS/wazuh-plugins/releases/download"
LINUX_RELEASE_TAG="yara-v0.3.17"

# OS and Distribution Detection
OSSEC_CONF_PATH=${OSSEC_CONF_PATH:-"/var/ossec/etc/ossec.conf"}

#=============================================================================
# Enhanced YARA Installation Script for Linux
# Detects existing YARA installations and performs automatic cleanup
#=============================================================================

# Source shared utilities
TMP_DIR=$(mktemp -d)
if ! curl "${WAZUH_YARA_REPO_URL}/scripts/shared/utils.sh" -o "$TMP_DIR/utils.sh"; then
    echo "Failed to download utils.sh"
    exit 1
fi

# Function to calculate SHA256 (cross-platform bootstrap)
calculate_sha256_bootstrap() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    else
        shasum -a 256 "$file" | awk '{print $1}'
    fi
    return 0
}

# Download checksums and verify utils.sh integrity BEFORE sourcing it
if ! curl "${WAZUH_YARA_REPO_URL}/checksums.sha256" -o "$TMP_DIR/checksums.sha256"; then
    echo "Failed to download checksums.sha256"
    exit 1
fi


EXPECTED_HASH=$(grep "scripts/shared/utils.sh" "$TMP_DIR/checksums.sha256" | awk '{print $1}' || printf "%s\n" "[ERROR] Failed to get expected hash for utils.sh" >&2)
ACTUAL_HASH=$(calculate_sha256_bootstrap "$TMP_DIR/utils.sh")

if [[ -z "$EXPECTED_HASH" ]] || [[ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]]; then
    echo "Error: Checksum verification failed for utils.sh" >&2
    echo "Expected hash: $EXPECTED_HASH" >&2
    echo "Actual hash: $ACTUAL_HASH" >&2
    exit 1
fi

# shellcheck disable=SC1091
. "$TMP_DIR/utils.sh"

# Prompt user for installation type
prompt_installation_type() {
    # Check if installation type is already set via environment variable or argument
    if [[ -n "${INSTALLATION_TYPE:-}" ]]; then
        if [[ "$INSTALLATION_TYPE" == "desktop" ]]; then
            YARA_SOURCE_URL="${WAZUH_YARA_REPO_URL}/scripts/linux/yara.sh"
            info_message "Using Desktop/Workstation installation (interactive mode)"
            return 0
        elif [[ "$INSTALLATION_TYPE" == "server" ]]; then
            YARA_SOURCE_URL="${WAZUH_YARA_REPO_URL}/scripts/linux/yara-server.sh"
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
                YARA_SOURCE_URL="${WAZUH_YARA_REPO_URL}/scripts/linux/yara.sh"
                info_message "Selected: Desktop/Workstation installation"
                return 0
                ;;
            2)
                INSTALLATION_TYPE="server"
                YARA_SOURCE_URL="${WAZUH_YARA_REPO_URL}/scripts/linux/yara-server.sh"
                info_message "Selected: Server installation"
                return 0
                ;;
            *)
                warn_message "Invalid choice. Please enter 1 or 2."
                ;;
        esac
    done
}

# Detect Linux Distribution
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        echo "$ID"
    elif [[ -f /etc/redhat-release ]]; then
        echo "redhat"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    else
        error_exit "Unable to detect Linux distribution"
    fi
}
DISTRO=$(detect_distro)

# Cleanup function
cleanup() {
    info_message "Cleaning up temporary files..."
    rm -rf "$TMP_DIR"

    if [[ -d "./yara-install" ]]; then
        rm -rf "./yara-install"
    elif [[ -n "${HOME:-}" ]] && [[ -d "$HOME/yara-install" ]]; then
        rm -rf "$HOME/yara-install"
    fi
    return 0
}

# Register cleanup to run on exit
trap cleanup EXIT

# Check if version matches 4.5.x pattern
version_is_4_5_x() {
    local version="$1"
    local major minor
    major=$(echo "$version" | cut -d'.' -f1)
    minor=$(echo "$version" | cut -d'.' -f2)

    [[ "$major" = "4" ]] && [[ "$minor" = "5" ]]
    return $?
}

#=============================================================================
# PRE-INSTALLATION CHECKS
#=============================================================================

# Detect YARA installations - check for legacy, modern, and softlink
detect_yara_installation() {
    local has_legacy=0
    local has_modern=0
    local has_softlink=0

    exec 3>&1 4>&2
    exec 1>/dev/null 2>/dev/null

    if [[ -d "$YARA_LEGACY_PATH" ]]; then
        has_legacy=1
    fi

    if [[ -d "$YARA_MODERN_PATH" ]]; then
        has_modern=1
    fi

    if [[ -L "$YARA_BIN_PATH" ]] || [[ -f "$YARA_BIN_PATH" ]]; then
        has_softlink=1
    fi

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
        *)
            error_exit "Unable to detect Linux distribution"
            ;;
    esac

    exec 1>&3 2>&4
    exec 3>&- 4>&-

    echo "${has_legacy},${has_modern},${has_softlink}"
    return 0
}

# Download and run uninstallation script from GitHub
run_local_uninstall() {
    local uninstall_script="$TMP_DIR/uninstall.sh"
    local uninstall_url="${WAZUH_YARA_REPO_URL}/scripts/linux/uninstall.sh"

    info_message "Downloading uninstall script from GitHub..."

    if ! download_and_verify_file "$uninstall_url" "$uninstall_script" "scripts/linux/uninstall.sh" "Yara Uninstall Script" "${WAZUH_YARA_REPO_URL}/checksums.sha256"; then
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

    if [[ "$has_modern" -eq 1 ]] && [[ -f "$YARA_MODERN_BIN_PATH" ]]; then
        local current_version
        current_version=$("$YARA_MODERN_BIN_PATH" --version 2>/dev/null || echo "")

        if [[ -n "$current_version" ]] && version_is_4_5_x "$current_version"; then
            success_message "Valid YARA installation found (v${current_version})"
            info_message "Skipping new installation, will proceed to configuration checks..."
            return 2
        fi

        info_message "Existing YARA version ($current_version) does not match target v${YARA_VERSION}"
    fi

    if [[ "$has_legacy" -eq 0 ]] && [[ "$has_modern" -eq 0 ]]; then
        success_message "No existing YARA installation detected"
        success_message "System is ready for fresh installation"
        return 0
    fi

    echo ""
    warn_message "Existing YARA installation(s) detected!"

    if [[ -d "$YARA_LEGACY_PATH" ]]; then
        info_message "Found YARA in path: $YARA_LEGACY_PATH"
    fi

    if [[ -d "$YARA_MODERN_PATH" ]]; then
        info_message "Found YARA in path: $YARA_MODERN_PATH"
    fi

    if [[ -L "$YARA_BIN_PATH" ]] || [[ -f "$YARA_BIN_PATH" ]]; then
        info_message "Found YARA in path: $YARA_BIN_PATH"
    fi

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
        *)
            error_exit "Unsupported Linux distribution: $DISTRO"
            ;;
    esac

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

# sed in-place for Linux
sed_inplace() {
    if command_exists gsed; then
        maybe_sudo sed -i "$@" 2>/dev/null || true
    fi
    return 0
}

# Remove file limit from ossec.conf
remove_file_limit() {
    if maybe_sudo grep -q "<file_limit>" "$OSSEC_CONF_PATH" 2>/dev/null; then
        sed_inplace "/<file_limit>/,/<\/file_limit>/d" "$OSSEC_CONF_PATH"
        info_message "The file limit block was removed successfully."
    else
        info_message "The file limit block does not exist. No changes were made."
    fi
    return 0
}

# Install dependencies
install_dependencies() {
    info_message "Installing dependencies..."

    case "$DISTRO" in
        centos|rhel|redhat|rocky|almalinux|fedora)
            print_step 1 "Installing dependencies on RPM-based system"
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
            print_step 1 "Updating package lists on DEB-based system"
            maybe_sudo apt-get update -qq

            maybe_sudo apt-get install -y jq 2>/dev/null || \
            warn_message "Could not install jq, continuing without it"
            ;;
        *)
            error_exit "Unsupported Linux distribution: $DISTRO"
            ;;
    esac

    success_message "Dependencies installation attempted successfully"
    return 0
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
            error_exit "Unsupported Linux distribution: $distro"
            ;;
    esac

    download_file "$url" "$output" "YARA package" || exit 1
    return 0
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
            error_exit "Unsupported Linux distribution: $distro"
            ;;
    esac

    print_step 2 "Creating wrapper script"
    maybe_sudo mkdir -p /usr/local/bin
    maybe_sudo tee "$YARA_BIN_PATH" > /dev/null << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
export LD_LIBRARY_PATH="$YARA_MODERN_PATH/lib:${LD_LIBRARY_PATH:-}"
exec "$YARA_MODERN_BIN_PATH" "$@"
EOF
    maybe_sudo chmod +x "$YARA_BIN_PATH"


    success_message "YARA package installed successfully"
    return 0
}

# Setup YARA directories and components
setup_yara_components() {
    info_message "Setting up YARA components..."

    local yara_script_path="/var/ossec/active-response/bin/${YARA_SCRIPT_NAME}"
    local yara_rules_path="/var/ossec/ruleset/yara/rules"

    print_step 1 "Creating directories"
    if ! maybe_sudo mkdir -p "/var/ossec/active-response/bin/"; then
        error_message "Failed to create directory: /var/ossec/active-response/bin/"
        exit 1
    fi

    if ! maybe_sudo mkdir -p "$yara_rules_path/"; then
        error_message "Failed to create directory: $yara_rules_path/"
        exit 1
    fi

    local yara_script_pattern="scripts/linux/yara.sh"
    [[ "$INSTALLATION_TYPE" == "server" ]] && yara_script_pattern="scripts/linux/yara-server.sh"

    print_step 2 "Downloading and configuring YARA script"
    if ! download_and_verify_file "$YARA_SOURCE_URL" "$yara_script_path" "$yara_script_pattern" "YARA script" "${WAZUH_YARA_REPO_URL}/checksums.sha256"; then
        error_message "Failed to download YARA script"
        exit 1
    fi

    if [[ "$INSTALLATION_TYPE" = "desktop" ]]; then
        sed_inplace 's|YARA_PATH="/usr/local/bin"|YARA_PATH="/opt/wazuh/yara/bin"|g' "$yara_script_path"
        sed_inplace 's|YARA_PATH="/opt/yara/bin"|YARA_PATH="/opt/wazuh/yara/bin"|g' "$yara_script_path"
    fi

    print_step 3 "Downloading YARA rules"
    if ! download_and_verify_file "$YARA_RULES_URL" "$yara_rules_path/yara_rules.yar" "rules/yara_rules.yar" "YARA rules" "${WAZUH_YARA_REPO_URL}/checksums.sha256"; then
        error_message "Failed to download YARA rules"
        exit 1
    fi

    print_step 4 "Setting permissions"
    if ! maybe_sudo chmod 750 "$yara_script_path"; then
        error_message "Failed to set permissions on $yara_script_path"
        exit 1
    fi

    maybe_sudo chown root:wazuh "$yara_script_path" 2>/dev/null || \
    maybe_sudo chown root:root "$yara_script_path"

    maybe_sudo chown root:wazuh "$yara_rules_path/yara_rules.yar" 2>/dev/null || \
    maybe_sudo chown root:root "$yara_rules_path/yara_rules.yar"

    maybe_sudo chown root:wazuh "$yara_rules_path" 2>/dev/null || \
    maybe_sudo chown root:root "$yara_rules_path"

    success_message "YARA components set up successfully"
    return 0
}

# Validate installation
validate_installation() {
    info_message "Validating YARA installation..."
    local validation_failed=0

    local yara_found=0 actual_version=""

    if command_exists yara; then
        actual_version=$(yara --version 2>&1 || echo "")
        yara_found=1
    elif [[ -f "$YARA_MODERN_BIN_PATH" ]]; then
        actual_version=$("$YARA_MODERN_BIN_PATH" --version 2>&1 || echo "")
        yara_found=1
    fi

    if [[ $yara_found -eq 1 ]] && [[ "$actual_version" =~ [0-9]+\.[0-9]+\.[0-9]+ ]]; then
        if version_is_4_5_x "$actual_version"; then
            success_message "YARA version $actual_version is installed (4.5.x series)."
        else
            warn_message "YARA version $actual_version is not compatible. Version 4.5.x is required."
            validation_failed=1
        fi
    else
        error_message "YARA command is not available or failed to run."
        error_message "Output was: $actual_version"

        info_message "DEBUG: Checking $YARA_MODERN_BIN_PATH..."
        if [[ -f "$YARA_MODERN_BIN_PATH" ]]; then
            info_message "DEBUG: File exists."
            info_message "DEBUG: Trying to run it directly to see error:"
            maybe_sudo "$YARA_MODERN_BIN_PATH" --version || true
        else
            error_message "DEBUG: File does NOT exist."
        fi
        validation_failed=1
    fi

    local yara_rules_path="/var/ossec/ruleset/yara/rules/yara_rules.yar"
    local yara_script_path="/var/ossec/active-response/bin/${YARA_SCRIPT_NAME}"

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

    if [[ $validation_failed -eq 0 ]]; then
        success_message "YARA installation and configuration validation completed successfully."
    else
        error_message "YARA installation and configuration validation failed."
        exit 1
    fi
    return 0
}

# Main YARA installation for Linux
yara_installation() {
    info_message "Starting YARA installation for Linux..."

    check_disk_space /tmp 102400

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
    return 0
}

# Main function
main() {
    local args=("$@")
    
    while [[ ${#args[@]} -gt 0 ]]; do
        case "${args[0]}" in
            --type)
                if [[ -n "${args[1]}" && "${args[1]}" =~ ^(desktop|server)$ ]]; then
                    INSTALLATION_TYPE="${args[1]}"
                    args=("${args[@]:2}")
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
                error_exit "Unknown option: ${args[0]}"
                ;;
            *)
                if [[ -z "${YARA_VERSION_SET:-}" ]]; then
                    YARA_VERSION="${args[0]}"
                    YARA_VERSION_SET=1
                    args=("${args[@]:1}")
                else
                    error_exit "Unexpected argument: ${args[0]}"
                fi
                ;;
        esac
    done

    info_message "Starting YARA installation script v${YARA_VERSION}"
    info_message "Detected OS: Linux"

    if [[ ! -d "/var/ossec" ]]; then
        error_message "Wazuh agent not installed at /var/ossec"
        error_message "Please install the Wazuh agent before running this script"
        exit 1
    fi

    prompt_installation_type

    local check_status=0
    pre_installation_check || check_status=$?

    if [[ "$check_status" -eq 2 ]]; then
        info_message "Verifying existing installation..."
        validate_installation
        success_message "YARA is already installed and configured correctly. Exiting."
        exit 0
    elif [[ "$check_status" -ne 0 ]]; then
        error_message "Pre-installation checks failed"
        exit 1
    fi

    # Proceed with installation
    yara_installation
    return 0
}

# Execute main function
main "$@"