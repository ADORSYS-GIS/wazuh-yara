# Wazuh Yara
[![Run Pytest](https://github.com/ADORSYS-GIS/wazuh-yara/actions/workflows/yara-test.yml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-yara/actions/workflows/yara-test.yml)

---

## Overview
**Wazuh Yara** integrates YARA rules with Wazuh to improve malware detection and file integrity monitoring on Linux and macOS. For Windows, the solution leverages Windows Defender integration to provide native malware detection and log monitoring, ensuring a unified security approach across platforms.

By leveraging YARA’s rule-based detection capabilities on Linux and macOS, Wazuh Yara enables real-time, targeted malware detection and response. On Windows, the provided integration script configures Wazuh to monitor Windows Defender logs for threat events, automating response and visibility.

---

## Features
- **File Integrity Monitoring (FIM):** Monitors specified directories and files for modifications, automatically triggering YARA scans (Linux/macOS) or Defender log monitoring (Windows).
- **Malware Detection:**
  - **Linux/macOS:** Detects and classifies malware by applying YARA rules to files and directories.
  - **Windows:** Monitors Windows Defender events for malware detection and response.
- **Active Response:**
  - **Linux/macOS:** Automatically responds to detected threats based on YARA rule matches, including the ability to delete flagged files.
  - **Windows:** Leverages Windows Defender default capabilities.
- **Cross-Platform Support:** Unified approach for Ubuntu, macOS, and Windows endpoints.
- **Automated Testing:** Comprehensive test suite and CI workflow for installation and configuration validation (Linux/macOS).

---

## Supported Operating Systems
- **Ubuntu (22.04+, 24.04+)** (YARA integration)
- **macOS (Monterey, Ventura, Sonoma, Sequoia)** (YARA integration)
- **Windows 10/11** (Windows Defender integration)

---

## Getting Started

### Prerequisites
- Wazuh Agent installed on endpoints
- `curl` (Linux/macOS) or `PowerShell` (Windows)
- Sufficient privileges to install system packages and modify configuration files

### Installation

#### Linux (Ubuntu) / macOS
```bash
curl -SL --progress-bar https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/install.sh | bash
```

#### Windows (Defender Integration)
```powershell
iex (iwr -UseBasicParsing "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/refs/heads/main/scripts/win-defender-integration.ps1")
```

---

## Usage Guide

### Linux/macOS (YARA)
1. **Configure YARA Rules:**
   - Place your YARA rules in the Wazuh agent’s designated rules directory to activate them during scans.
2. **Set Up File Integrity Monitoring:**
   - Configure the Wazuh FIM module to monitor directories you want to secure. Each change within these directories will trigger a YARA scan.
3. **Deploy Active Response:**
   - Use the provided `yara.sh` script to automatically initiate responses upon threat detection.

### Windows (Defender Integration)
1. **Run the Integration Script:**
   - Execute `win-defender-integration.ps1` as Administrator to configure Wazuh to monitor Windows Defender logs and automate response.
2. **Monitor Defender Events:**
   - Wazuh will now collect and respond to Defender-detected threats via the agent.

---

## Automated Testing & CI

- The repository includes a GitHub Actions workflow that automatically runs the test suite on every push, pull request, and release tag (Linux/macOS).
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