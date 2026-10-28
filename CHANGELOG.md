# Changelog

All notable changes to this repo are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Releases are tagged
`vX.Y.Z`.

## [0.1.0] - 2026-10-28

### Added
- Plugin marketplace `cloud-security-skills` with two plugins: `aws-attack-paths` (new)
  and `fedramp-cloud-compliance` (installed from its own repository).
- `aws-attack-paths` skill: workflow for mapping an AWS technique to detection,
  prevention, response and NIST 800-53 Rev5 IDs, and a catalog of eleven techniques
  checked against AWS documentation and MITRE ATT&CK.
- CI: ruff, structure tests, Gitleaks, Checkov, Trivy, zizmor and CodeQL.
