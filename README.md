# Wazuh Yara
[![Run Pytest](https://github.com/ADORSYS-GIS/wazuh-yara/actions/workflows/yara-test.yml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-yara/actions/workflows/yara-test.yml)

---

## Overview
**Wazuh Yara** integrates YARA rules with Wazuh to improve malware detection and file integrity monitoring on Linux and macOS. For Windows, the solution leverages Windows Defender integration to provide native malware detection and log monitoring, ensuring a unified security approach across platforms.

By leveraging YARA’s rule-based detection capabilities on Linux and macOS, Wazuh Yara enables real-time, targeted malware detection and response. On Windows, the provided integration script configures Wazuh to monitor Windows Defender logs for threat events, automating response and visibility.

---

## Features
- **File Integrity Monitoring (FIM):** Monitors specified directories and files for modifications, automatically triggering YARA scans on all supported platforms.
- **Malware Detection:**
  - **Linux/macOS:** Detects and classifies malware by applying YARA rules to files and directories using the `yara-server.sh` scanning engine.
  - **Windows:** Uses YARA-based active response via `yara.bat` to scan files and detect malware.
- **Active Response:**
  - **Linux/macOS:** Automatically responds to detected threats based on YARA rule matches, logging results to active response logs.
  - **Windows:** Provides desktop notifications via BurntToast and logs scan results to active response logs.
- **Cross-Platform Support:** Unified approach for Ubuntu, macOS, and Windows endpoints using consistent YARA-based detection.
- **Automated Testing:** Comprehensive test suite and CI workflow for installation and configuration validation (Linux/macOS).
- **Checksum Verification:** All scripts and rules are verified using SHA256 checksums during installation for security and integrity.

---

## Supported Operating Systems
- **Ubuntu (22.04+, 24.04+)** - YARA integration with active response
- **macOS (Monterey, Ventura, Sonoma, Sequoia)** - YARA integration with active response
- **Windows 10/11** - YARA integration with desktop notifications

---

## Getting Started

### Prerequisites
- Wazuh Agent installed on endpoints
- `curl` (Linux/macOS) or `PowerShell` (Windows)
- Sufficient privileges to install system packages and modify configuration files
- **Bash 4.0+** (Linux/macOS) - required for YARA scanning scripts

### Installation

#### Linux (Ubuntu)

**Desktop (non-interactive)**
```bash
curl -fsSL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/linux/install.sh | sudo env INSTALLATION_TYPE=desktop bash
```

**Server (non-interactive)**
```bash
curl -fsSL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/linux/install.sh | sudo env INSTALLATION_TYPE=server bash
```

**Alternative (flags, interactive equivalent)**
```bash
curl -fsSL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/linux/install.sh | sudo bash -s -- --type desktop
curl -fsSL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/linux/install.sh | sudo bash -s -- --type server
```

**Notes**
- Setting `INSTALLATION_TYPE` runs the installer in non-interactive mode with the selected flow.
- `sudo` is recommended to ensure correct ownership and service restart.

#### macOS

**Desktop (non-interactive)**
```bash
curl -fsSL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/macos/install.sh | sudo env INSTALLATION_TYPE=desktop bash
```

**Server (non-interactive)**
```bash
curl -fsSL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/macos/install.sh | sudo env INSTALLATION_TYPE=server bash
```

**Alternative (flags, interactive equivalent)**
```bash
curl -fsSL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/macos/install.sh | sudo bash -s -- --type desktop
curl -fsSL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/macos/install.sh | sudo bash -s -- --type server
```

**Notes**
- macOS requires Bash 4.0+ (install via Homebrew: `brew install bash`)
- Full disk access may be required for YARA scanning operations

#### Windows (YARA Integration)
```powershell
iex (iwr -UseBasicParsing "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/windows/install.ps1")
```

**Uninstall (Windows)**
```powershell
iex (iwr -UseBasicParsing "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/windows/uninstall.ps1")
```

**Notes**
- Administrator privileges required
- Installs YARA binaries and configures Wazuh agent active response
- Downloads and configures YARA rules for malware detection

---

## Usage Guide

### Linux/macOS (YARA Integration)

#### Script Structure
The integration uses a two-script architecture:
- **`yara.sh`** - Client-side active response script that triggers scans when files are modified
- **`yara-server.sh`** - Server-side script that performs the actual YARA scanning

#### Configuration

1. **YARA Rules Location:**
   - Linux: `/var/ossec/ruleset/yara/rules/yara_rules.yar`
   - macOS: `/Library/Ossec/ruleset/yara/rules/yara_rules.yar`
   
2. **File Integrity Monitoring:**
   - Configure the Wazuh FIM module in `/var/ossec/etc/ossec.conf` (Linux) or `/Library/Ossec/etc/ossec.conf` (macOS)
   - Monitor directories by adding `<directories>` tags under `<syscheck>`
   - Each file change triggers the `yara.sh` active response script

3. **Active Response Workflow:**
   - FIM detects file modification
   - `yara.sh` is triggered as an active response
   - Script calls `yara-server.sh` to perform the scan
   - Results are logged to `/var/ossec/logs/active-responses.log` (Linux) or `/Library/Ossec/logs/active-responses.log` (macOS)

4. **Log Monitoring:**
   - Monitor active response logs for YARA scan results
   - Wazuh rules can be configured to generate alerts based on YARA matches

### Windows (YARA Integration)

#### Script Structure
The Windows integration uses:
- **`install.ps1`** - Installation script that sets up YARA and configures Wazuh
- **`uninstall.ps1`** - Removal script to clean up YARA installation
- **`yara.bat`** - Active response batch script that executes YARA scans

#### Configuration

1. **Installation:**
   - Run `install.ps1` as Administrator
   - Downloads YARA binaries (version 4.5.2) from official releases
   - Installs to `C:\Program Files (x86)\ossec-agent\active-response\bin\yara\`
   - Copies YARA rules to the installation directory

2. **Active Response Setup:**
   - `yara.bat` is configured as a Wazuh active response command
   - Scans files detected by FIM using YARA rules
   - Logs results to `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log`

3. **Wazuh Configuration:**
   - Modifies `ossec.conf` to monitor `C:\Users\<username>\Downloads`
   - Adds `<file_limit>` with `enabled=no` to prevent file limit issues
   - Sets frequency to 21600 seconds (6 hours)

4. **Notifications:**
   - Uses BurntToast PowerShell module for desktop notifications
   - Notifications include malware name and file path
   - Falls back to event log if notification fails

5. **Uninstallation:**
   - Run `uninstall.ps1` as Administrator
   - Removes YARA binaries and configuration
   - Cleans up Wazuh agent modifications
   - Restarts Wazuh service

---

## Automated Testing & CI

- The repository includes a GitHub Actions workflow that automatically runs the test suite on every push, pull request, and release tag.
- The test suite verifies:
  - User and group creation
  - Configuration file presence
  - YARA and notify-send installation and version
  - Script and rules file permissions
  - Wazuh agent service status
- See [YARA Tests README](scripts/tests/README.md) for details and manual test instructions.
- See the [GitHub Actions Workflow](https://github.com/ADORSYS-GIS/wazuh-yara/actions/workflows/yara-test.yml) for CI details.

---

## Contributing

Contributions are welcome! Please open issues or pull requests for bug fixes, improvements, or new features. All contributions should:
- Pass the automated test suite (see CI badge above)
- Follow the code style and documentation guidelines
- Include clear commit messages and PR descriptions

---

## References
- [Wazuh](https://wazuh.com/)
- [YARA](https://virustotal.github.io/yara/)
- [Windows Defender](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-endpoint)
- [GitHub Actions](https://github.com/features/actions)

---