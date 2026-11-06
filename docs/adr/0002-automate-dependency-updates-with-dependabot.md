# ADR-0002: Automate Dependency Updates with Dependabot

> We introduce GitHub Dependabot configuration to automate GitHub Actions workflow updates on a weekly schedule with pull request limits and cool-down buffers.

## Metadata

| Field             | Value                                              |
| :---------------- | :------------------------------------------------- |
| **Document ID**   | ADR-0002                                           |
| **Status**        | `Accepted`                                         |
| **Date**          | 2026-11-06                                         |
| **Deciders**      | Wazuh maintainers                                  |
| **Governs**       | `.github/dependabot.yml`                           |
| **Amends**        | N/A                                                |
| **Amended by**    | N/A                                                |
| **Supersedes**    | N/A                                                |
| **Superseded by** | N/A                                                |

## Context

The `wazuh-yara` repository maintains YARA scanning, rule synchronization, and active response integration scripts for Wazuh agents across Linux, macOS, and Windows. While core detection logic is implemented in shell and PowerShell scripts, CI/CD automation in `.github/workflows/` (SAST, SonarQube, and test execution) relies on third-party GitHub Actions (`actions/checkout`, `SonarSource/sonarqube-scan-action`, etc.).

Previously, GitHub Actions action version updates were handled manually. This introduces operational and security risks:
- GitHub Actions runners regularly deprecate older runtimes (e.g. Node.js 16/20 deprecations), causing CI pipelines to fail if actions are not kept updated.
- Security updates and bug fixes published by action maintainers are delayed until manual reviews happen.
- Org-wide standardization under Epic ADORSYS-GIS/wazuh#2354 establishes automated dependency management across all active repositories using Dependabot, modeled after `wazuh-cert-oauth2`.

The deciding forces are:
- Keep CI/CD action references secure and compatible with GitHub-hosted runners.
- Automate routine maintenance without overwhelming maintainer review capacity.
- Standardize configuration across organizational repositories.

## Decision

We will configure GitHub Dependabot in `.github/dependabot.yml` for the `github-actions` ecosystem:

1. **Ecosystem Configuration**:
   - `github-actions`: Scans `.github/workflows` on a `weekly` schedule on Mondays at `08:00` UTC.

2. **Workload and Throttling Limits**:
   - `open-pull-requests-limit: 10`: Restricts active open pull requests per ecosystem to prevent review congestion.
   - `cooldown.default-days: 7`: Implements a 7-day cool-down buffer before opening non-critical update PRs, allowing upstream patches to stabilize.

## Options considered

| Option                                              | Verdict  | Why (one line)                                                                    |
| :-------------------------------------------------- | :------- | :-------------------------------------------------------------------------------- |
| Manual workflow action updates (status quo)         | Rejected | Inefficient and prone to missed runner deprecations or security advisories.       |
| Daily action update scanning                        | Rejected | Generates unnecessary noise for CI workflow actions that update infrequently.     |
| Weekly Dependabot scanning with cooldown (Adopted)  | Adopted  | Balances prompt security updates with minimal notification noise and stability.   |

## Consequences

**Not part of this decision:** Automatic merging of Dependabot PRs. All action updates must pass existing CI checks and undergo review.

### Impact

**Benefits**

- Workflow actions stay current and avoid runner runtime deprecation breakage.
- Security vulnerabilities and outdated actions are remediated continuously.
- Weekly scheduling on Mondays avoids daily workflow noise.
- Cool-down buffers prevent churn from rapid upstream patch releases.

**Costs**

- Maintainers will periodically review and merge Dependabot pull requests.
- CI runner usage increases due to automated checks on Dependabot PR branches.

**Risks**

- Upstream breaking changes in minor or patch releases (mitigated by CI checks and human review requirement).

### Done when

- [x] `.github/dependabot.yml` exists with valid configuration for `github-actions`.
- [x] Schedule, PR limits, and cool-down parameters conform to the organizational convention.
- [x] ADR-0002 is documented and registered in `docs/adr/README.md`.

### Revisit when

- Team review capacity requires adjusting `open-pull-requests-limit` or schedule intervals.
- Additional package ecosystems or sub-directories are introduced.

## Rollback

To roll back, remove or revert `.github/dependabot.yml`. Dependabot will cease opening new PRs.

## Evidence

| Claim                                                                 | Where                                                          |
| :-------------------------------------------------------------------- | :------------------------------------------------------------- |
| Organization reference convention                                     | `ADORSYS-GIS/wazuh-cert-oauth2/.github/dependabot.yml`         |
| Sub-issue scope definition                                            | `ADORSYS-GIS/wazuh-yara#107`                                   |
| Organization epic tracking                                            | `ADORSYS-GIS/wazuh#2354`                                       |

## References

- [GitHub Dependabot Configuration Options](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file)
- [ADR template](https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/template.md)
- [ADR writing guide](https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/GUIDE.md)

## Solution implementation

| Kind   | Tracking                                                                                   | Status | What it covers                                 |
| :----- | :----------------------------------------------------------------------------------------- | :----- | :--------------------------------------------- |
| Issue  | [ADORSYS-GIS/wazuh-yara#107](https://github.com/ADORSYS-GIS/wazuh-yara/issues/107)         | Closed | Add dependabot configuration to wazuh-yara     |
| PR     | [ADORSYS-GIS/wazuh-yara#108](https://github.com/ADORSYS-GIS/wazuh-yara/pull/108)           | Merged | Adds .github/dependabot.yml and ADR-0002       |
