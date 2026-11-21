# Changelog

All notable changes to this repo are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Releases are tagged
`vX.Y.Z`.

## [Unreleased]

### Fixed
- `aws-attack-paths` catalog, rechecked against AWS documentation on 2026-11-20:
  - OIDC (entry 5): STS now validates GitHub claim keys such as `repository_id` and
    `job_workflow_ref` in commercial Regions; the sub-template workaround is kept as the
    GovCloud fallback. RCP guidance covers `sts:AssumeRoleWithWebIdentity`, and CloudTrail
    no longer claimed to show every token claim.
  - Leaked keys (entries 1-2): Bedrock/SES deny matches `FederatedUser` as well as `User`;
    containment also denies re-enabling credentials; added GuardDuty
    `CredentialAccess:IAMUser/CompromisedCredentials`.
  - IMDS (entry 4): SCPs don't bind Auto Scaling launches, so added account IMDS defaults,
    declarative policies, `autoscaling:LaunchTemplateVersionSpecified`, EC2.170,
    AutoScaling.3, and replacing the instance profile on response.
  - LLMjacking (entry 6): model access page retirement, data-event invocation APIs,
    per-Region invocation logging, and how to revoke short-term Bedrock API keys.
  - Logging tampering (entry 8): more tamper APIs, custom EventBridge rule, CloudTrail
    delegated administrator.
  - S3 ransomware (entry 9): T1485.001, an out-of-org KMS key SCP to test, and the data
    events gap scoped to your own detections.
  - Outside sharing (entry 10): `BoolIfExists` for RAM, EBS associated KMS keys and
    `CopySnapshot` paths, block public access and RCP limits, RDS.1.
- `aws-attack-paths` ground rules: RCP exemptions.

## [0.1.0] - 2026-10-28

### Added
- Plugin marketplace `cloud-security-skills` with two plugins: `aws-attack-paths` (new)
  and `fedramp-cloud-compliance` (installed from its own repository).
- `aws-attack-paths` skill: workflow for mapping an AWS technique to detection,
  prevention, response and NIST 800-53 Rev5 IDs, and a catalog of eleven techniques
  checked against AWS documentation and MITRE ATT&CK.
- CI: ruff, structure tests, Gitleaks, Checkov, Trivy, zizmor and CodeQL.
