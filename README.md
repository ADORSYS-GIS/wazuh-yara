# Wazuh Yara
[![Run Pytest](https://github.com/ADORSYS-GIS/wazuh-yara/actions/workflows/yara-test.yml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-yara/actions/workflows/yara-test.yml)


## Overview
**Wazuh Yara** integrates YARA rules with Wazuh to improve malware detection and file integrity monitoring. This integration empowers Wazuh to detect, classify, and respond to malware threats and file integrity changes across endpoints.

By leveraging YARA’s rule-based detection capabilities, Wazuh Yara allows for real-time, targeted malware detection and response. It automates threat mitigation by actively monitoring for suspicious file changes and applying YARA rules, which can identify malware artifacts and, when necessary, remove them to safeguard endpoint integrity.

## Features
- **File Integrity Monitoring (FIM)**: Constantly monitors specified directories and files for modifications, automatically triggering YARA scans when changes are detected.

- **Malware Detection**: Detects and classifies malware by applying YARA rules to assess files and directories, identifying potential threats based on known malware signatures.

- **Active Response**:  Automatically responds to detected threats based on YARA rule matches, including the ability to delete flagged files to prevent further spread or damage.

## Supported Operating Systems
- **Ubuntu**
- **macOS**
- **Windows**

## Usage Guide
- **Configure YARA Rules:** Place your YARA rules in the Wazuh agent’s designated rules directory to activate them during scans.

- **Set Up File Integrity Monitoring:** Configure the Wazuh FIM module to monitor directories you want to secure. Each change within these directories will trigger a YARA scan.

- **Deploy Active Response:** Use the provided `yara.sh` script to automatically initiate responses upon threat detection.


## Getting Started
### Prerequisites
- Wazuh Agent installed on endpoints
### Installation

#### Linux
Install using this command:
   ```bash
   curl -SL --progress-bar https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/install.sh | sh
   ```

#### Windows
Install using this command:
   ```powershell
   iex (iwr -UseBasicParsing "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/refs/heads/main/scripts/install.ps1")
   ```

## YARA Tests

To ensure the correct installation and configuration of YARA and Wazuh, we have implemented a set of automated tests. These tests verify the presence and proper configuration of essential components such as users, groups, configuration files, and installed packages.

For a detailed description of these tests and how to execute them, please refer to the [YARA Tests README](scripts/tests/README.md).

## GitHub Actions

The repository includes a GitHub Actions workflow that automatically runs the tests on every push or pull request. This helps maintain the integrity of the system by validating the setup continuously.

For more information on the test workflow, see the [GitHub Actions Workflow](https://github.com/ADORSYS-GIS/wazuh-yara/actions/workflows/yara-test.yml).

## YARA Tests

To ensure the correct installation and configuration of YARA and Wazuh, we have implemented a set of automated tests. These tests verify the presence and proper configuration of essential components such as users, groups, configuration files, and installed packages.

For a detailed description of these tests and how to execute them, please refer to the [YARA Tests README](scripts/tests/README.md).

## GitHub Actions

The repository includes a GitHub Actions workflow that automatically runs the tests on every push or pull request. This helps maintain the integrity of the system by validating the setup continuously.

For more information on the test workflow, see the [GitHub Actions Workflow](https://github.com/ADORSYS-GIS/wazuh-yara/actions/workflows/yara-test.yml).