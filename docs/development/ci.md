# CI/CD Overview

This document describes the continuous integration, continuous delivery, and
automated testing for the `wazuh-yara` repository.

## Workflows

The repository ships three GitHub Actions workflows under `.github/workflows/`.

### `yara-ci.yml` (YARA CI)

The main CI workflow. It triggers on pushes and pull requests to `main` and
`develop` (and on version tags `v*`), limited to changes under `scripts/`,
`rules/`, and `.github/workflows/`.

It runs three jobs:

- **`update-changelog-and-checksums`** - regenerates `checksums.sha256` for all
  scripts and rules, regenerates the full `CHANGELOG.md` using `git-cliff`, and
  (on push) commits and pushes the result.
- **`run-pytest-linux`** - on `ubuntu-latest`, installs the Wazuh agent, runs
  `scripts/linux/install.sh` (server mode), and executes the pytest/testinfra
  suite against `scripts/tests/yara.py`.
- **`run-pytest-macos`** - on `macos-latest`, the same flow using the macOS
  installer.
- **`release`** - on version tags (`refs/tags/v*`), and only after the test jobs
  pass, generates release notes with `git-cliff`, marks the release as a
  pre-release if the tag contains `rc`, and creates a GitHub Release attaching
  `checksums.sha256`.

### `sast.yml` (Static Application Security Testing)

Runs on pushes and pull requests to `main` (plus manual dispatch). It reuses
reusable workflows from `ADORSYS-GIS/adorsys-ci-cd-templates`:

- **`sbom`** - generates a Software Bill of Materials (see ADR-0001).
- **`sast-python`** - static analysis for Python (Python 3.12).
- **`sast-shell`** - static analysis for shell scripts.
- **`sast-powershell`** - static analysis for PowerShell scripts.

### `sonarqube.yml` (SonarQube)

Runs on pushes and pull requests to `main` and `develop` (plus manual dispatch).

- **`test`** - installs `bats` and `kcov`, runs the Bats test suite with
  coverage via `./tests/run-coverage.sh`, and uploads the coverage report.
- **`scan`** - after tests pass, invokes the SonarQube scan for project key
  `wazuh-yara`, feeding in the coverage report and excluding test and coverage
  paths.

## Automated Test Suite

The automated test suite lives under `scripts/tests/` and is described in
[`scripts/tests/README.md`](../../scripts/tests/README.md).

### Prerequisites

- Python 3.9+
- `pytest`
- `pytest-testinfra`
- A Wazuh agent and YARA installed on the test system

```bash
pip install pytest pytest-testinfra
```

### Running the tests

```bash
pytest -vv scripts/tests/yara.py
```

The tests are cross-platform (Linux/macOS) and skip OS-specific checks as
appropriate. They assume the install script has been run and the system is in
the expected post-install state.

### What is tested

| Test                          | What it checks                                    |
| :---------------------------- | :------------------------------------------------ |
| `test_user_exists`            | `root` user exists                                |
| `test_group_exists`           | `wazuh` group exists                              |
| `test_ossec_conf_exists`      | Wazuh configuration file exists at the correct path |
| `test_yara_installed_from_source` | YARA binary is present and version is `4.5.x` |
| `test_notify_send_version`    | `notify-send` is present and version is `0.8.3` (Linux only) |
| `test_yara_script_downloaded` | YARA active response script exists, owned `root:wazuh`, mode `750` |
| `test_yara_script_permissions`| YARA script permissions/ownership                 |
| `test_yara_rules_file_exists` | YARA rules file exists and is a regular file      |
| `test_yara_rules_file_permissions` | YARA rules file/directory permissions/ownership |
| `test_wazuh_agent_restarted`  | `wazuh-agent` service is running and enabled      |

## Release Process

Releases are triggered by pushing a `v*` tag. The `release` job waits for the
Linux and macOS test jobs (and the changelog/checksums job) to pass, then:

1. Generates release notes from `CHANGELOG.md` via `git-cliff`.
2. Marks the release as a pre-release if the tag contains `rc`.
3. Publishes a GitHub Release with the `checksums.sha256` file attached.

## See also

- [scripts/tests/README.md](../../scripts/tests/README.md) - test suite details.
- [ADR-0001](../adr/0001-generate-sbom-in-ci.md) - SBOM generation decision.
