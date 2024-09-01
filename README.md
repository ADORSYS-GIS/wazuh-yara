# Wazuh Yara

[![Test YARA Script](https://github.com/ADORSYS-GIS/wazuh-yara/actions/workflows/test-script.yml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-yara/actions/workflows/test-script.yml)


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
Install using this command:
   ```bash
   curl -SL --progress-bar https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/install.sh | sh
   ```
