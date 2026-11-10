# ADR-0003: Enable Secret Scanning and Gitleaks in CI

> We enable GitHub native Secret scanning and Push protection on this public repository and add a Gitleaks job that scans the full git history to CI through the shared adorsys-ci-cd-templates workflow.

## Metadata

| Field             | Value                                                |
| :---------------- | :--------------------------------------------------- |
| **Document ID**   | ADR-0003                                             |
| **Status**        | `Accepted`                                           |
| **Date**          | 2026-11-09                                           |
| **Deciders**      | Wazuh maintainers                                    |
| **Governs**       | `.github/workflows/sast.yml` (the `secret-scan` job) |
| **Amends**        | N/A                                                  |
| **Amended by**    | N/A                                                  |
| **Supersedes**    | N/A                                                  |
| **Superseded by** | N/A                                                  |

## Context

The `wazuh-yara` repository is public and maintains YARA scanning, rule synchronization, and active response integration scripts for Wazuh agents across Linux, macOS, and Windows. Any credential committed to it is exposed to the internet immediately. Audit requirement SSDLC-DEV-04 requires secrets scanning on repositories and pipelines, and GAP-WZ-SEC-02 (a plaintext cluster key committed in another Wazuh repository) shows the consequence of scanning being off.

The repository already runs the shared security scanners from [adorsys-ci-cd-templates](https://github.com/ADORSYS-GIS/adorsys-ci-cd-templates) through `.github/workflows/sast.yml`.

The deciding forces are:

- Block secrets before they reach Git using GitHub native tooling, which is free on public repositories.
- Scan the full commit history, not only the diff of a push or pull request, so secrets that were committed and later removed are still detected.
- Reuse the shared secret scanning workflow instead of maintaining a repository-local copy.

## Decision

1. Enable GitHub Secret scanning and Push protection in the repository security settings, free on public repositories.
2. Add a `secret-scan` job to `.github/workflows/sast.yml` that calls the shared `adorsys-ci-cd-templates/.github/workflows/secret-scan.yml` workflow, pinned to a commit SHA, scanning the full git history (`--log-opts=--all`) on push and pull request.
3. Pass `NOTIFY_WEBHOOK_URL` to route findings to the alerting channel. Results always remain available in the `gitleaks-report` SARIF artifact and the Gitleaks step log.

## Options considered

| Option                                                             | Verdict  | Why (one line)                                                                     |
| :----------------------------------------------------------------- | :------- | :--------------------------------------------------------------------------------- |
| GitHub native Secret scanning and Push protection only, no CI scan | Rejected | Misses secrets already in history and non-provider patterns.                       |
| Repository-local Gitleaks workflow                                 | Rejected | Duplicates the shared workflow and drifts from other Wazuh repositories.           |
| Native Secret scanning plus shared Gitleaks CI (adopted)           | Adopted  | Blocks at push time and scans history in CI, consistent across Wazuh repositories. |

## Consequences

**Not part of this decision:** Secret scanning on private repositories (requires GitHub Advanced Security), rewriting history for historical findings, and local pre-commit hooks (this repository has no pre-commit setup). Existing findings are triaged separately.

### Impact

**Benefits**

- Credentials are blocked at push time by native Push protection.
- Full history is scanned on every push and pull request, so removed secrets are still found.
- Scanning is consistent across Wazuh repositories through the shared workflow.

**Costs**

- A historical finding fails the scan on the protected `main` branch until it is triaged or the history is cleaned.

### Done when

- [ ] Secret scanning and Push protection enabled in the repository security settings (requires repository admin).
- [x] `secret-scan` job present in `.github/workflows/sast.yml`, pinned to a commit SHA of the shared workflow.
- [x] ADR-0003 is documented and indexed in `docs/adr/README.md`.

### Revisit when

- The shared `secret-scan.yml` workflow changes.
- The organization gains GitHub Advanced Security, enabling native scanning on private repositories.

## Rollback

Disable Secret scanning and Push protection in the repository security settings and remove the `secret-scan` job from `.github/workflows/sast.yml`.

## Evidence

| Claim                                           | Where                                                                           |
| :---------------------------------------------- | :------------------------------------------------------------------------------ |
| Shared secret scanning workflow                 | `ADORSYS-GIS/adorsys-ci-cd-templates/.github/workflows/secret-scan.yml`         |
| Audit requirement and risk reference            | Epic [ADORSYS-GIS/wazuh#2376](https://github.com/ADORSYS-GIS/wazuh/issues/2376) |
| The `secret-scan` job calls the shared workflow | `.github/workflows/sast.yml` in this repo                                       |

## References

- [GitHub Secret scanning documentation](https://docs.github.com/en/code-security/secret-scanning)
- [adorsys-ci-cd-templates](https://github.com/ADORSYS-GIS/adorsys-ci-cd-templates)
- [ADR template](https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/template.md)
- [ADR writing guide](https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/GUIDE.md)

## Solution implementation

| Kind  | Tracking                                                                                                 | Status            | What it covers                                   |
| :---- | :------------------------------------------------------------------------------------------------------- | :---------------- | :----------------------------------------------- |
| Epic  | [ADORSYS-GIS/wazuh#2376](https://github.com/ADORSYS-GIS/wazuh/issues/2376)                               | Open              | Enable secret scanning across Wazuh repositories |
| Issue | [ADORSYS-GIS/wazuh-yara#109](https://github.com/ADORSYS-GIS/wazuh-yara/issues/109)                       | Open              | Child issue for this decision                    |
| PR    | [ADORSYS-GIS/adorsys-ci-cd-templates#76](https://github.com/ADORSYS-GIS/adorsys-ci-cd-templates/pull/76) | Merged 2026-11-09 | Adds the shared `secret-scan.yml` workflow       |
| PR    | [ADORSYS-GIS/wazuh-yara#118](https://github.com/ADORSYS-GIS/wazuh-yara/pull/118)                         | Open              | Adds the `secret-scan` job and ADR-0003          |
