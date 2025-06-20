# Wazuh Yara
[![Run Pytest](https://github.com/ADORSYS-GIS/wazuh-yara/actions/workflows/yara-test.yml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-yara/actions/workflows/yara-test.yml)

---

## Overview
**Wazuh Yara** integrates YARA rules with Wazuh to improve malware detection and file integrity monitoring. This integration empowers Wazuh to detect, classify, and respond to malware threats and file integrity changes across endpoints.

By leveraging YARA’s rule-based detection capabilities, Wazuh Yara allows for real-time, targeted malware detection and response. It automates threat mitigation by actively monitoring for suspicious file changes and applying YARA rules, which can identify malware artifacts and, when necessary, remove them to safeguard endpoint integrity.

---

## Features
- **File Integrity Monitoring (FIM):** Constantly monitors specified directories and files for modifications, automatically triggering YARA scans when changes are detected.
- **Malware Detection:** Detects and classifies malware by applying YARA rules to assess files and directories, identifying potential threats based on known malware signatures.
- **Active Response:** Automatically responds to detected threats based on YARA rule matches, including the ability to delete flagged files to prevent further spread or damage.
- **Cross-Platform Support:** Works on Ubuntu, macOS, and Windows (with platform-specific scripts).
- **Automated Testing:** Includes a comprehensive test suite and CI workflow for installation and configuration validation.

---

## Supported Operating Systems
- **Ubuntu (22.04+, 24.04+)**
- **macOS (Monterey, Ventura, Sonoma, Sequoia)**
- **Windows 10/11**

---

## Getting Started

### Prerequisites
- Wazuh Agent installed on endpoints
- `curl` (Linux/macOS) or `PowerShell` (Windows)
- Sufficient privileges to install system packages and modify configuration files

### Installation

#### Linux (Ubuntu) / macOs
```bash
curl -SL --progress-bar https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/install.sh | bash
```
#### Windows
```powershell
iex (iwr -UseBasicParsing "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/refs/heads/main/scripts/install.ps1")
```

---

## Usage Guide

1. **Configure YARA Rules:**
   - Place your YARA rules in the Wazuh agent’s designated rules directory to activate them during scans.
2. **Set Up File Integrity Monitoring:**
   - Configure the Wazuh FIM module to monitor directories you want to secure. Each change within these directories will trigger a YARA scan.
3. **Deploy Active Response:**
   - Use the provided `yara.sh` script to automatically initiate responses upon threat detection.

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
- [GitHub Actions](https://github.com/features/actions)

---