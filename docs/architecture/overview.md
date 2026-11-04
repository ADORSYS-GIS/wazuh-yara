# Architecture Overview

This document explains how YARA integrates with the Wazuh agent to detect malware
across Linux, macOS, and Windows, and how detections are surfaced to the user and
forwarded to your Wazuh manager.

## How It Works

**Wazuh Yara** combines YARA's rule-based malware detection with Wazuh File
Integrity Monitoring (FIM). When a monitored file changes on an endpoint, Wazuh
triggers an active response that scans the file with YARA rules. If malware is
detected, the result is written to the active response log (and, on desktop
installations, shown to the user via a native notification).

The detection engine differs by platform:

- **Linux / macOS** run the two-script architecture: a client-side active
  response script (`yara.sh`) that triggers scans and a server-side scanning
  script (`yara-server.sh`) that performs the actual YARA scan.
- **Windows** uses a native `yara.bat` active response together with a Windows
  Defender integration that streams Defender threat events into Wazuh.

### Event Flow (Linux / macOS)

```
   File change on monitored directory
              │
              ▼
   ┌──────────────────────────────┐
   │   Wazuh FIM (syscheck)       │  Detects modification, raises alert
   └──────────────┬───────────────┘
                  │ Triggers active response
                  ▼
   ┌──────────────────────────────┐
   │   yara.sh (active response)  │  Reads alert JSON, resolves file path
   └──────────────┬───────────────┘
                  │ Waits for file to be stable, then scans
                  ▼
   ┌──────────────────────────────┐
   │   yara-server.sh / yara      │  Runs YARA against ruleset
   └──────────────┬───────────────┘
                  │ Match found?
                  ▼
   ┌──────────────────────────────┐
   │   active-responses.log       │  wazuh-yara: INFO - Scan result ...
   └──────────────────────────────┘
```

### Event Flow (Windows)

```
   File change in monitored directory (e.g. Downloads)
              │
              ▼
   ┌────────────────────────────────────────┐
   │   Wazuh FIM (syscheck)                 │  Detects modification
   └────────────────┬───────────────────────┘
                    │ Triggers active response
                    ▼
   ┌────────────────────────────────────────┐
   │   yara.bat (active response)           │  Scans file with yara64.exe
   └────────────────┬───────────────────────┘
                    │ Match found?
                    ▼
   ┌────────────────────────────────────────┐
   │   BurntToast desktop notification      │  Includes malware name + file path
   └────────────────────────────────────────┘

   Windows Defender integration (win-defender-integration.ps1):
   Wazuh agent monitors the "Microsoft-Windows-Windows Defender/Operational"
   event channel and forwards Defender threat events to the Wazuh manager.
```

## Step by Step Event Flow

1. **File Integrity Monitoring (FIM):** The Wazuh agent's `syscheck` module
   monitors the configured directories. On a modification it produces an alert
   carrying the changed file path under `alert.syscheck.path`.
2. **Active Response trigger:** Wazuh runs the YARA active response script
   (`yara.sh` on Linux/macOS, `yara.bat` on Windows) and passes the alert as
   JSON on stdin.
3. **Path extraction:** The script parses `parameters.alert.syscheck.path` from
   the JSON input and validates that the file exists.
4. **File stabilisation:** The script waits until the file size stops changing
   so that the file is fully written before scanning.
5. **YARA scan:** The script runs `yara -w -r <rules> <file>` against the YARA
   ruleset (`yara_rules.yar`). `-w` disables warnings and `-r` scans recursively.
6. **Result handling:**
   - **Server mode:** every matching rule line is written to
     `active-responses.log` as `wazuh-yara: INFO - Scan result: <rule> <file>`.
   - **Desktop mode (Linux/macOS):** the user is shown a critical notification
     with options to **Delete All**, **Ignore All**, or **Dismiss**. Delete
     removes the files; Ignore adds the path to the FIM ignore list in
     `ossec.conf` and restarts the agent.
   - **Windows:** a BurntToast toast notification is sent to the logged-in user
     session, falling back to the event log if no interactive session exists.
7. **Log monitoring:** The Wazuh agent monitors `active-responses.log` so that
   YARA scan results can be turned into alerts in the Wazuh manager.

## Key Scripts

| Platform   | Script                         | Role                                       |
| :--------- | :----------------------------- | :----------------------------------------- |
| Linux      | `scripts/linux/yara.sh`        | Desktop active response (with notifications) |
| Linux      | `scripts/linux/yara-server.sh` | Server active response (logging only)      |
| macOS      | `scripts/macos/yara.sh`        | Desktop active response (with notifications) |
| macOS      | `scripts/macos/yara-server.sh` | Server active response (logging only)      |
| Windows    | `scripts/windows/yara.bat`     | Windows active response + BurntToast       |
| Windows    | `scripts/windows/win-defender-integration.ps1` | Windows Defender log monitoring  |

## Standard File Paths

| Component              | Linux                              | macOS                              | Windows                                                |
| :--------------------- | :--------------------------------- | :--------------------------------- | :----------------------------------------------------- |
| **YARA binary**        | `/opt/wazuh/yara/bin/yara`         | `/opt/wazuh/yara/bin/yara`         | `C:\Program Files (x86)\ossec-agent\active-response\bin\yara\yara64.exe` |
| **YARA rules**         | `/var/ossec/ruleset/yara/rules/yara_rules.yar` | `/Library/Ossec/ruleset/yara/rules/yara_rules.yar` | `C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar` |
| **Active response script** | `/var/ossec/active-response/bin/yara.sh` | `/Library/Ossec/active-response/bin/yara.sh` | `C:\Program Files (x86)\ossec-agent\active-response\bin\yara.bat` |
| **Wazuh config**       | `/var/ossec/etc/ossec.conf`        | `/Library/Ossec/etc/ossec.conf`    | `C:\Program Files (x86)\ossec-agent\ossec.conf`        |
| **Active response log**| `/var/ossec/logs/active-responses.log` | `/Library/Ossec/logs/active-responses.log` | `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log` |

## Notification Behaviour

- **Linux desktop:** `notify-send` (via `libnotify`) is used, upgraded to
  `>= 0.8.3` if needed, with a confirmation dialog via `zenity`.
- **macOS desktop:** notifications and confirmation dialogs use `osascript`
  (AppleScript / `display dialog` and `display notification`).
- **Windows:** notifications use the **BurntToast** PowerShell module, delivered
  through a temporary scheduled task running in the interactive user session.

## See also

- [Installation & Setup](../operations/installation.md)
- [Usage Guide](../operations/usage.md)
- [YARA Rules Reference](../reference/rules.md)
