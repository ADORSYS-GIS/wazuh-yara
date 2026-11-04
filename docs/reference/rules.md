# YARA Rules Reference

This document is a reference for the YARA ruleset shipped with this project and
for the standard configuration paths used at runtime.

## The Rules File

The detection logic is contained in a single rules file:

```
rules/yara_rules.yar
```

This is a **YARA-Forge "core"** package (version 0.9.0) generated on
2025-03-23. It aggregates high-quality, community-vetted YARA rules from
multiple public repositories. The embedded header reports **7,382 rules** after
filtering by age, quality, score, and importance thresholds. Rules are attributed
per source repository and carry their original license (for example, the Elastic
rule set is licensed under the Elastic License 2.0).

Example rules present in the file include detections for:

- Windows ransomware (e.g. WannaCry, Magniber)
- Windows trojans and stealers (e.g. Lumma, BlackShades, SnakeKeylogger, OskiStealer)
- Linux trojans, exploit kits, and cryptominers (e.g. Swrort, Pulse, Miancha)
- macOS trojans and backdoors (e.g. AppleJeus)
- Known CVEs (e.g. CVE-2009-2698, CVE-2018-10561, CVE-2017-100011)

Each rule declares metadata such as the threat name, author, source repository,
score, quality, severity, target OS, and a unique rule ID, which appear in scan
output alongside the matching rule name.

## Where the Rules Are Installed

The rules file is copied to the platform-specific path during installation:

| Platform | Installed path |
| :------- | :------------- |
| Linux    | `/var/ossec/ruleset/yara/rules/yara_rules.yar` |
| macOS    | `/Library/Ossec/ruleset/yara/rules/yara_rules.yar` |
| Windows  | `C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar` |

On Linux and macOS the file and its directory are owned by `root:wazuh`; the
active response script and rules are given mode `750`. All downloaded scripts
and rules are verified against the repository's `checksums.sha256` during
installation.

## Updating the Rules

The rules file is treated like any other artifact in this repository: it is
downloaded and checksum-verified on install. To ship updated detections, replace
the contents of `rules/yara_rules.yar` (ideally re-generating it from a current
YARA-Forge core package) and update `checksums.sha256` so installers pick up the
new rules. The `yara-ci.yml` workflow regenerates `checksums.sha256`
automatically on pushes to `main`/`develop`.

After updating the rules on an endpoint, no agent restart is strictly required
for future scans, because the active response scripts read the rules file at
scan time.

## Runtime Configuration Paths

| Component              | Linux                              | macOS                              | Windows                                                |
| :--------------------- | :--------------------------------- | :--------------------------------- | :----------------------------------------------------- |
| **YARA rules**         | `/var/ossec/ruleset/yara/rules/yara_rules.yar` | `/Library/Ossec/ruleset/yara/rules/yara_rules.yar` | `C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar` |
| **YARA binary**        | `/opt/wazuh/yara/bin/yara`         | `/opt/wazuh/yara/bin/yara`         | `...\bin\yara\yara64.exe`                              |
| **Active response script** | `/var/ossec/active-response/bin/yara.sh` | `/Library/Ossec/active-response/bin/yara.sh` | `...\bin\yara.bat`                                     |
| **Wazuh config**       | `/var/ossec/etc/ossec.conf`        | `/Library/Ossec/etc/ossec.conf`    | `C:\Program Files (x86)\ossec-agent\ossec.conf`        |
| **Active response log**| `/var/ossec/logs/active-responses.log` | `/Library/Ossec/logs/active-responses.log` | `...\active-response\active-responses.log`             |

## See also

- [Architecture Overview](../architecture/overview.md)
- [Usage Guide](../operations/usage.md)
- [Installation & Setup](../operations/installation.md)
