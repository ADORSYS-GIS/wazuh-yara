# Installation and Setup Guide

This guide covers how to install, verify, and uninstall Wazuh Yara on Linux,
macOS, and Windows using the scripts in this repository.

## Prerequisites

Before installing, make sure you have:

- A running **Wazuh agent** installed on the endpoint (required - the installer
  aborts if Wazuh is not present).
- **Root / administrator privileges** (`sudo` on Linux/macOS, an Administrator
  PowerShell on Windows).
- An active internet connection to download the YARA package, rules, and
  supporting files.
- `curl` (Linux/macOS) or PowerShell (Windows).
- **Bash 4.0+** on Linux/macOS for the YARA scanning scripts.

---

## 1. Linux Installation

The installer is tested on **Ubuntu (22.04+, 24.04+)** and also supports other
DEB/RPM-based distributions (Debian, CentOS/RHEL/Rocky/AlmaLinux, Fedora). It
downloads a pre-built YARA package, installs dependencies, configures the Wazuh
agent, and validates the result.

### Run the Installer

Two installation types are available:

- **Desktop / Workstation** - installs `yara.sh` with user notifications.
- **Server** - installs `yara-server.sh` (logging only, no notifications).

**Desktop (non-interactive):**

```bash
curl -fsSL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/linux/install.sh | sudo env INSTALLATION_TYPE=desktop bash
```

**Server (non-interactive):**

```bash
curl -fsSL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/linux/install.sh | sudo env INSTALLATION_TYPE=server bash
```

**Alternative (flags, interactive equivalent):**

```bash
curl -fsSL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/linux/install.sh | sudo bash -s -- --type desktop
curl -fsSL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/linux/install.sh | sudo bash -s -- --type server
```

The installer can also be run directly from a local checkout:

```bash
sudo env INSTALLATION_TYPE=server bash scripts/linux/install.sh
```

### What the Linux installer does

1. Verifies the operating system is Linux and that Wazuh is installed.
2. Verifies the downloaded `utils.sh` and installer files against SHA256
   checksums.
3. Prompts for (or reads) the installation type.
4. Detects any existing YARA installation and, if incompatible, automatically
   runs the uninstaller first.
5. Installs dependencies (`jq`, and for desktop `notify-send`/`zenity`).
6. Downloads and installs the YARA DEB/RPM package and creates a wrapper at
   `/usr/local/bin/yara`.
7. Installs `yara.sh` / `yara-server.sh` to
   `/var/ossec/active-response/bin/` and copies the rules to
   `/var/ossec/ruleset/yara/rules/yara_rules.yar`.
8. Removes the `<file_limit>` block from `ossec.conf`.
9. Validates the installation (YARA version 4.5.x, rules and script present).

### Notes

- Setting `INSTALLATION_TYPE` runs the installer non-interactively with the
  selected flow.
- `sudo` is recommended to ensure correct ownership and service restart.
- YARA is installed to `/opt/wazuh/yara`, with a wrapper at
  `/usr/local/bin/yara`.

### Verify the Linux Installation

```bash
yara --version
ls -l /var/ossec/active-response/bin/yara.sh
ls -l /var/ossec/ruleset/yara/rules/yara_rules.yar
```

### Uninstall on Linux

Run the uninstall script (also invoked automatically by the installer when an
incompatible installation is found):

```bash
curl -fsSL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/linux/uninstall.sh | sudo bash
# or from a checkout:
sudo bash scripts/linux/uninstall.sh
```

It removes YARA packages, the `/opt/wazuh/yara` (modern) and `/opt/yara`
(legacy) directories, the `/usr/local/bin/yara` wrapper, the active response
script and rules, the `<file_limit>` config block, and restarts the Wazuh agent.

---

## 2. macOS Installation

The installer supports macOS on both Intel (amd64) and Apple Silicon (arm64).
It is tested on macOS Monterey, Ventura, Sonoma, and Sequoia.

### Prerequisites for macOS

- [Homebrew](https://brew.sh) or [MacPorts](https://www.macports.org) for
  dependency installation.
- Bash 4.0+ (install via Homebrew: `brew install bash`).
- Terminal with administrator permissions.

### Run the Installer

```bash
curl -fsSL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/macos/install.sh | sudo env INSTALLATION_TYPE=desktop bash
```

Server mode: replace `INSTALLATION_TYPE=desktop` with
`INSTALLATION_TYPE=server`. A flags-based form is also supported:

```bash
curl -fsSL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/macos/install.sh | sudo bash -s -- --type server
```

### What the macOS installer does

1. Verifies the operating system is macOS and that Wazuh is installed.
2. Verifies `utils.sh` against its SHA256 checksum.
3. Installs dependencies (`jq`, `libmagic`, `openssl`) via Homebrew or
   MacPorts.
4. Downloads the YARA DMG for the detected architecture and installs the binary
   into `/opt/wazuh/yara/bin/`.
5. Installs `yara.sh` / `yara-server.sh` to
   `/Library/Ossec/active-response/bin/` and copies the rules to
   `/Library/Ossec/ruleset/yara/rules/yara_rules.yar`.
6. Removes the `<file_limit>` block from `ossec.conf`.
7. Validates the installation.

### Notes

- macOS requires **Bash 4.0+**; the scripts automatically re-exec with a newer
  Bash if one is available (`/opt/homebrew/bin/bash` or `/usr/local/bin/bash`).
- **Full disk access** may be required for YARA scanning operations on some
  directories.

### Verify the macOS Installation

```bash
yara --version
ls -l /Library/Ossec/active-response/bin/yara.sh
ls -l /Library/Ossec/ruleset/yara/rules/yara_rules.yar
```

### Uninstall on macOS

```bash
curl -fsSL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/macos/uninstall.sh | sudo bash
# or from a checkout:
sudo bash scripts/macos/uninstall.sh
```

---

## 3. Windows Installation

The Windows installer sets up YARA and configures the Wazuh agent for the YARA
active response and Windows Defender integration. It is tested on **Windows
10/11**.

### Run the Installer

Open **PowerShell as Administrator** and run:

```powershell
iex (iwr -UseBasicParsing "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/windows/install.ps1")
```

### What the Windows installer does

1. Verifies the process is running with Administrator privileges.
2. Downloads and extracts the YARA Windows binary (version `4.5.2` by default)
   into `C:\Program Files (x86)\ossec-agent\active-response\bin\yara\`.
3. Downloads the YARA rules (`yara_rules.yar`) and the `yara.bat` active
   response script, verifying them against SHA256 checksums.
4. Adds the YARA directory to the system `PATH`.
5. Updates `ossec.conf`:
   - Adds `C:\Users\<username>\Downloads` to `syscheck` directories with
     `realtime=yes`.
   - Adds a `<file_limit>` with `enabled=no`.
   - Sets the FIM `frequency` to `21600` seconds (6 hours).
6. Restarts the Wazuh service (`WazuhSvc`).

### Windows Defender Integration

To stream Windows Defender threat events into Wazuh, run the optional
integration script as Administrator:

```powershell
iex (iwr -UseBasicParsing "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/windows/win-defender-integration.ps1")
```

This script:

1. Uninstalls the YARA active response components (YARA binary, `yara.bat`,
   rules, and `ossec.conf` modifications).
2. Adds a `localfile` entry monitoring the
   `Microsoft-Windows-Windows Defender/Operational` event channel.
3. Restarts the Wazuh service if changes were made.

### Notes

- **Administrator privileges are required.**
- The installer installs YARA binaries and configures the Wazuh agent active
  response, and downloads and configures YARA rules for malware detection.

### Verify the Windows Installation

```powershell
yara --version
Test-Path "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\yara64.exe"
Test-Path "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar"
```

### Uninstall on Windows

```powershell
iex (iwr -UseBasicParsing "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/windows/uninstall.ps1")
```

The uninstaller removes the YARA directory and `yara.bat`, removes the YARA
directory from the system `PATH`, removes the `ossec.conf` modifications
(Downloads directory, `file_limit`), and restarts the Wazuh service.

---

## See also

- [Architecture Overview](../architecture/overview.md)
- [Usage Guide](../operations/usage.md)
- [YARA Rules Reference](../reference/rules.md)
