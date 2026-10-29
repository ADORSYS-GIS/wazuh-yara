# ADR-0001: Generate CycloneDX SBOM in CI

> We generate the SBOM in CI with Trivy because the GitHub Dependency Graph alone misses dependencies for this project.

## Metadata

| Field             | Value                                         |
| :---------------- | :-------------------------------------------- |
| **Document ID**   | ADR-0001                                      |
| **Status**        | `Proposed`                                    |
| **Date**          | 2026-10-28                                    |
| **Deciders**      | SIEM Security Engineering Team                |
| **Governs**       | `.github/workflows/sast.yml` (the `sbom` job) |
| **Amends**        | N/A                                           |
| **Amended by**    | N/A                                           |
| **Supersedes**    | N/A                                           |
| **Superseded by** | N/A                                           |

## Context

This project ships YARA rules and the supporting scripts that install, scan, and integrate them with the Wazuh agent across Linux, macOS, and Windows. It is written in Bash and Python, with YARA rule files under `rules/` and more scripts under `scripts/`. It needs an accurate inventory of what it delivers so the supply chain can be audited.

We first enabled the GitHub Dependency Graph because it is free and needs no setup. It produced a minimal SBOM for this repository. It only covers the package ecosystems GitHub parses, and it only reads committed manifests. Python `requirements` files are partially covered, but the YARA rules and the shell scripts that form the bulk of what we ship do not appear in the graph at all.

The dependency graph is therefore not a reliable source for what this project actually ships.

The deciding forces were: the SBOM must reflect what we deliver, it must be reproducible in CI, and it should not depend on GitHub parsing our manifests correctly.

## Decision

We will generate a CycloneDX SBOM in CI with Trivy, using the shared `sbom.yml` workflow from [adorsys-ci-cd-templates](https://github.com/ADORSYS-GIS/adorsys-ci-cd-templates). The `sbom` job in `.github/workflows/sast.yml` calls that workflow with a filesystem scan, `format: cyclonedx`, and uploads `sbom.json` as the `sbom` workflow artifact.

The GitHub Dependency Graph stays enabled as a baseline and for Dependabot alerts, but the CI-generated SBOM is the source of truth.

The shared workflow reference is pinned to a commit SHA, like the other reusable workflows in this repo, so a change in the templates cannot break our pipeline silently.

## Options considered

| Option                                                  | Verdict  | Why (one line)                                                                |
| :------------------------------------------------------ | :------- | :---------------------------------------------------------------------------- |
| GitHub Dependency Graph only                            | Rejected | It misses the YARA rules and shell scripts that make up most of what we ship. |
| Shared `sbom.yml` workflow from adorsys-ci-cd-templates | Adopted  | One workflow reused across all Wazuh projects keeps results consistent.       |
| A dedicated SBOM workflow in this repo                  | Rejected | It would duplicate the shared workflow and drift from the other projects.     |

## Consequences

**Not part of this decision:** the GitHub Dependency Graph stays enabled, and image-level SBOM scanning is not covered here, only the filesystem scan.

### Impact

**Benefits**

- The SBOM reflects the repository contents as scanned by Trivy, including dependencies the dependency graph cannot see.
- The SBOM is produced on every push to the default branch and on pull requests.
- The same workflow is reused across all Wazuh projects, so results are consistent.
- The artifact can be imported into CycloneDX tooling or DefectDojo.

**Costs**

- Adds one job to the SAST workflow on every run.
- The reusable workflow reference must be kept pinned and reviewed when the shared workflow changes.

**Risks**

- The SBOM is a snapshot of the repository at scan time, not of a built artifact.
- If the shared workflow changes behavior, the pinned reference may need a bump, or the SBOM content could change unexpectedly.

### Accepted limits

- The SBOM covers repository contents, not built binaries or container images.
- The `sbom` artifact expires after the workflow retention period.

### Done when

- [ ] The `sbom` job runs in the SAST workflow on push to the default branch and on pull requests.
- [ ] The run uploads `sbom.json` as the `sbom` artifact.
- [ ] The shared workflow reference is pinned to a commit SHA, not `@main`.

### Revisit when

- The shared `sbom.yml` workflow changes.
- The project starts building container images or binaries that should appear in the SBOM.

## Rollback

Nothing to roll back.

## Evidence

| Claim                                                           | Where                                                            |
| :-------------------------------------------------------------- | :--------------------------------------------------------------- |
| The `sbom` job calls the shared workflow with a filesystem scan | `.github/workflows/sast.yml` in this repo                        |
| The shared workflow generates a CycloneDX SBOM with Trivy       | `ADORSYS-GIS/adorsys-ci-cd-templates/.github/workflows/sbom.yml` |
| The shared workflow is referenced by commit SHA                 | `.github/workflows/sast.yml` in this repo                        |
| The SAST workflow (including the `sbom` job) passes             | ![SAST workflow status](https://github.com/ADORSYS-GIS/wazuh-yara/actions/workflows/sast.yml/badge.svg) |

## References

- [adorsys-ci-cd-templates](https://github.com/ADORSYS-GIS/adorsys-ci-cd-templates)
- [ADR template](https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/template.md)
- [ADR writing guide](https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/GUIDE.md)

## Solution implementation

| Kind  | Tracking                                                                        | Status | What it covers                   |
| :---- | :------------------------------------------------------------------------------ | :----- | :------------------------------- |
| Issue | [ADORSYS-GIS/wazuh-yara#99](https://github.com/ADORSYS-GIS/wazuh-yara/issues/99) | Open   | Requests SBOM generation in CI   |
| PR    | [ADORSYS-GIS/wazuh-yara#104](https://github.com/ADORSYS-GIS/wazuh-yara/pull/104) | Open   | Adds the `sbom` job and this ADR |
