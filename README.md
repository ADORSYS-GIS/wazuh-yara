# Wazuh Yara
[![Run Pytest](https://github.com/ADORSYS-GIS/wazuh-yara/actions/workflows/yara-test.yml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-yara/actions/workflows/yara-test.yml)


## Overview
**Wazuh Yara** is a project aimed at integrating YARA rules with Wazuh for enhanced malware detection and file integrity monitoring.

## Features
- **File Integrity Monitoring (FIM)**: Monitors directories and files for changes and triggers YARA scans.
- **Malware Detection**: Uses YARA rules to detect and classify malware artifacts on endpoints.
- **Active Response**: Automatically deletes detected threats based on YARA rule matches.

## Supported Operating Systems
- **Ubuntu**
- **macOS**

## Usage
1. Configures the YARA rules in the wazuh agent `rules` directory.
2. Set up the Wazuh FIM module to monitor desired directories.
3. Deploy the `yara.sh` script for active response.

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