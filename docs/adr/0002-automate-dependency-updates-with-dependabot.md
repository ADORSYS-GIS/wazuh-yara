# ADR-0002: Automate Dependency Updates with Dependabot

- Status: Accepted
- Date: 2026-11-06
- Authors: @chojuninengu
- Deciders: Wazuh Security Operations Team
- Consulted: @t-desmond
- Informed: Wazuh Security Operations Team
- Relations:
  - Extends: ADR-0001 (Generate CycloneDX SBOM in CI)
  - Implements: [ADORSYS-GIS/wazuh-yara#107](https://github.com/ADORSYS-GIS/wazuh-yara/issues/107)
  - Part of: [ADORSYS-GIS/wazuh#2354](https://github.com/ADORSYS-GIS/wazuh/issues/2354)

## Context

The `wazuh-yara` repository maintains YARA scanning and integration scripts for Linux, macOS, and Windows agents. Workflows in `.github/workflows/` (such as SAST, SonarQube, and CI testing) rely on GitHub Actions steps maintained by third parties and the GitHub community.

Manually monitoring and updating GitHub Action versions is inefficient and can result in pin drift, missing security fixes, and unpatched runner deprecations. Automated dependency updates are required to ensure continuous compliance and reduce supply chain risk across the Wazuh infrastructure.

## Decision

Enable and configure GitHub Dependabot for `wazuh-yara` via `.github/dependabot.yml` tracking the `github-actions` ecosystem.

Configuration standard (aligned with organizational baseline established in `wazuh-cert-oauth2`):
- Ecosystem: `github-actions`
- Schedule interval: Weekly on Mondays at 08:00 UTC
- Open pull requests limit: 10
- Cooldown period: 7 days

## Options Considered

### Option 1: GitHub Dependabot (Selected)
- Native GitHub integration with zero external infrastructure requirements.
- Standardized across organization repositories (`wazuh-cert-oauth2`, `wazuh-agent`, etc.).
- Granular control over schedules, directories, PR limits, and cooldown periods.

### Option 2: Renovate Bot
- Highly configurable but requires external application permissions and hosting maintenance.
- Overly complex for repositories primarily using GitHub Actions workflows.

### Option 3: Manual Version Bumping
- High operational overhead and prone to delayed vulnerability remediation.

## Consequences

### Positive
- Automatic pull requests for GitHub Actions version bumps and security advisories.
- Reduced manual maintenance overhead.
- Predictable weekly review cadences on Mondays at 08:00 UTC.

### Negative / Trade-offs
- PR review volume will increase periodically when new action versions are published.
- Mitigated by setting `open-pull-requests-limit: 10` and `cooldown.default-days: 7`.

## Rollout / Rollback Plan

- Rollout: Merge `.github/dependabot.yml` into `main`. Dependabot will automatically activate and open update PRs according to schedule.
- Rollback: Revert the commit introducing `.github/dependabot.yml`.
