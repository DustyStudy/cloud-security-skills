# Cloud Security Skills

[![CI](https://github.com/DustyStudy/cloud-security-skills/actions/workflows/ci.yml/badge.svg)](https://github.com/DustyStudy/cloud-security-skills/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

A Claude Code plugin marketplace of [Agent Skills](https://docs.claude.com/en/docs/agents-and-tools/agent-skills/overview)
for AWS cloud security and FedRAMP work.

| Plugin | What it does |
|---|---|
| [`aws-attack-paths`](plugins/aws-attack-paths/skills/aws-attack-paths/SKILL.md) | Takes an AWS attack technique, a GuardDuty finding or a threat report and maps it to the detections, preventive controls (SCPs, RCPs, permissions boundaries, IAM conditions) and response that cover it, with NIST SP 800-53 Rev5 IDs and the gaps that remain. Its [technique catalog](plugins/aws-attack-paths/skills/aws-attack-paths/references/techniques.md) covers eleven techniques, from leaked access keys to S3 ransomware, each linked to MITRE ATT&CK and to a tested implementation where one exists. |
| [`fedramp-cloud-compliance`](https://github.com/DustyStudy/fedramp-cloud-compliance-skill) | FedRAMP 2026 (20x and Rev5) on AWS, Azure and Google Cloud: control and KSI mapping, Terraform review, and documentation. Maintained in its own repository; this marketplace installs it from there. |

## Install

```bash
claude plugin marketplace add DustyStudy/cloud-security-skills
claude plugin install aws-attack-paths@cloud-security-skills
claude plugin install fedramp-cloud-compliance@cloud-security-skills
```

Or, inside Claude Code: `/plugin marketplace add DustyStudy/cloud-security-skills`, then
`/plugin` to pick the plugins.

## How the skills behave

- **Defensive only.** Techniques are described at the level of API calls and conditions,
  which is what detections and policies are written against. The skills don't write
  exploit code.
- **Facts that drift are dated.** GuardDuty finding types, Security Hub control IDs and IAM
  condition keys were checked against AWS documentation on the date in each reference
  file's header, and the skill tells the user to confirm them before deploying.
- **Nothing is deployed.** The skills produce policies, Terraform and `terraform plan`
  commands for a person to review and run.

## Reference implementations

The technique catalog links tested code in
[aws-org-guardrails](https://github.com/DustyStudy/aws-org-guardrails),
[aws-remediation-orchestrator](https://github.com/DustyStudy/aws-remediation-orchestrator),
[fedramp-terraform-library](https://github.com/DustyStudy/fedramp-terraform-library) and
[prowler-aws-template](https://github.com/DustyStudy/prowler-aws-template).

## Development

```bash
pip install ruff==0.16.9 pytest==9.1.1
ruff check .
python -m pytest tests -q
claude plugin validate .
```

The tests check the manifests, skill frontmatter, relative links, and that every catalog
entry has all of its fields, an ATT&CK link and well-formed NIST IDs.

## License

[MIT](./LICENSE)
