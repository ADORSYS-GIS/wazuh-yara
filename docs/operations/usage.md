# Usage Guide

This guide explains how to use Wazuh Yara after installation: the script
structure, where the YARA rules live, how to configure File Integrity Monitoring
(FIM), the active response workflow, log monitoring, Windows Defender
integration, and notifications.

## Script Structure

### Linux / macOS

The Linux/macOS integration installs a single active response script into
`/var/ossec/active-response/bin/yara.sh`. The exact script is chosen at install
time by the `INSTALLATION_TYPE` (desktop or server); the two are mutually
exclusive deployment flavors, not a pipeline where one calls the other:

- **`yara.sh`** (desktop) - interactive active response script that triggers
  scans when files are modified and shows user notifications with actions
  (Delete / Ignore / Dismiss).
- **`yara-server.sh`** (server) - headless active response script that performs
  the YARA scan and logs results without user interaction.

Both scripts independently run the YARA CLI binary directly against the ruleset.

### Windows

The Windows integration uses:

- **`install.ps1`** - installation script that sets up YARA and configures Wazuh.
- **`uninstall.ps1`** - removal script that cleans up the YARA installation.
- **`yara.bat`** - the active response batch script that executes YARA scans and
  sends BurntToast notifications.
- **`win-defender-integration.ps1`** - optional script that configures Wazuh to
  monitor Windows Defender logs.

## YARA Rules Location

The rules file (`yara_rules.yar`) is installed to:

| Platform | Path |
| :------- | :--- |
| Linux    | `/var/ossec/ruleset/yara/rules/yara_rules.yar` |
| macOS    | `/Library/Ossec/ruleset/yara/rules/yara_rules.yar` |
| Windows  | `C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar` |

The active response scripts reference this path directly, so the rules are
applied automatically on every scan.

## File Integrity Monitoring (FIM) Configuration

To have YARA scan files, configure the Wazuh FIM module in `ossec.conf`
(`/var/ossec/etc/ossec.conf` on Linux, `/Library/Ossec/etc/ossec.conf` on
macOS). Add the directories you want to monitor under the `<syscheck>` section:

```xml
<syscheck>
  <directories check_all="yes">/home/user/Downloads</directories>
  <directories check_all="yes">/tmp</directories>
</syscheck>
```

Each file change detected by FIM triggers the YARA active response script.

On Windows, the installer adds `C:\Users\<username>\Downloads` with
`realtime="yes"` automatically.

### Ignoring Files

From a desktop notification you can choose **Ignore All** for detected files.
This adds the file path to the FIM ignore list in `ossec.conf`:

```xml
<syscheck>
  <ignore>/path/to/file</ignore>
</syscheck>
```

and restarts the Wazuh agent so the change takes effect.

## Active Response Workflow

When a monitored file changes, the following happens:

1. FIM detects the modification and produces an alert containing the file path.
2. Wazuh runs the active response script and passes the alert JSON on stdin.
3. The script reads `parameters.alert.syscheck.path`, waits for the file to be
   fully written, and runs YARA against the rules.
4. Matching rules are logged; on desktop installs a notification is shown.

## Log Monitoring

Scan results are written to the active response log:

| Platform | Log path |
| :------- | :------- |
| Linux    | `/var/ossec/logs/active-responses.log` |
| macOS    | `/Library/Ossec/logs/active-responses.log` |
| Windows  | `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log` |

Result lines look like:

```
wazuh-yara: INFO - Scan result: ELASTIC_Windows_Trojan_Lumma_693A5234 /path/to/file
```

The Wazuh agent monitors this log, so you can create Wazuh rules that raise
alerts whenever a `wazuh-yara` scan result appears. The log also records
DEBUG/WARNING/ERROR lines that are useful when troubleshooting.

## Windows Defender Integration

On Windows, run `win-defender-integration.ps1` as Administrator to monitor
Windows Defender threat events. It adds a `localfile` entry to `ossec.conf`:

```xml
<localfile>
  <location>Microsoft-Windows-Windows Defender/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

This forwards Windows Defender detections into Wazuh so they appear alongside
YARA active response results.

## Notifications

- **Linux (desktop):** uses `notify-send` (upgraded to `>= 0.8.3` if needed)
  with a `zenity` confirmation dialog. The notification offers **Delete All**,
  **Ignore All**, and **Dismiss** actions.
- **macOS (desktop):** uses AppleScript (`osascript`) dialogs with the same
  actions.
- **Windows:** uses the **BurntToast** PowerShell module to show a toast
  notification containing the malware name and file path. If no interactive
  user session is found, it falls back to logging rather than notifying.

Deleting files removes them from disk; ignoring files adds them to the FIM
ignore list so they are not re-scanned.

## See also

- [Architecture Overview](../architecture/overview.md)
- [Installation & Setup](../operations/installation.md)
- [YARA Rules Reference](../reference/rules.md)
