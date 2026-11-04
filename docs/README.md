# wazuh-yara Documentation

The `wazuh-yara` project ships YARA rules and the supporting scripts that
install, scan, and integrate them with the Wazuh agent across Linux, macOS, and
Windows.

## SDLC map

This repository follows the organization documentation standard. The table below
shows the active documentation for each phase:

| Phase      | Folder            | Contents                                                      |
| :--------- | :---------------- | :------------------------------------------------------------ |
| Design     | `architecture/`   | System overview, YARA + Wazuh event flow, and component map   |
| Decision   | `adr/`            | Architecture Decision Records                                 |
| Build      | `development/`    | CI/CD workflows and the automated test suite                  |
| Operate    | `operations/`     | Installation, setup, and usage guides                         |
| Reference  | `reference/`      | YARA rules and configuration reference                        |

## Quick links

| Area                      | Link                                            | Description                                                     |
| :------------------------ | :---------------------------------------------- | :-------------------------------------------------------------- |
| Architecture Overview     | [overview.md](architecture/overview.md)         | How YARA integrates with Wazuh across all platforms             |
| Installation Guide        | [installation.md](operations/installation.md)   | Setup instructions for Linux, macOS, and Windows                |
| Usage Guide               | [usage.md](operations/usage.md)                 | FIM config, active response, and notifications                  |
| CI/CD Overview            | [ci.md](development/ci.md)                      | GitHub Actions workflows and the test suite                     |
| YARA Rules Reference      | [rules.md](reference/rules.md)                  | The YARA ruleset and configuration paths                        |
| Decision Records          | [adr/README.md](adr/README.md)                  | Index of architectural decisions                                |
