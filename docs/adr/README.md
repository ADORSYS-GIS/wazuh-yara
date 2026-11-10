# Architecture Decision Records

Every architectural decision is recorded here as a numbered ADR: one file per
decision. The canonical writing guidance is the central ADR guide:
<https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/GUIDE.md>
(read it before writing an ADR). The canonical template is:
<https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/template.md>.

## Index

| ID                                                              | Title                                       | Status     | Date       | Relations | Formerly |
| :-------------------------------------------------------------- | :------------------------------------------ | :--------- | :--------- | :-------- | :------- |
| [ADR-0001](0001-generate-sbom-in-ci.md)                         | Generate CycloneDX SBOM in CI               | `Accepted` | 2026-10-28 | N/A       | N/A      |
| [ADR-0002](0002-automate-dependency-updates-with-dependabot.md) | Automate Dependency Updates with Dependabot | `Accepted` | 2026-11-06 | N/A       | N/A      |
| [ADR-0003](0003-enable-secret-scanning-and-gitleaks.md)         | Enable Secret Scanning and Gitleaks in CI   | `Accepted` | 2026-11-09 | N/A       | N/A      |

---

## Centralized Specifications

For comprehensive scanner details, rule profiles, and global SIEM security policies, refer to the master specifications:

- [Wazuh SAST Integration Guide (`wazuh-playbook`)](https://github.com/ADORSYS-GIS/wazuh-playbook/blob/main/SOC-Documentation/sast-integration.md)
- [SonarQube Scan Exclusions Guide (`wazuh-playbook`)](https://github.com/ADORSYS-GIS/wazuh-playbook/blob/main/SOC-Documentation/sonarqube-scan-exclusions.md)
