---
name: aws-attack-paths
description: Maps AWS attack techniques to the detections, preventive controls and response that cover them, with NIST SP 800-53 Rev5 IDs. Use when the user asks how to detect, prevent or respond to an AWS technique (leaked access keys, extra credentials on an IAM user, IAM privilege escalation, instance metadata credential theft, OIDC or cross-account trust abuse, LLMjacking, cryptomining, logging tampering, S3 ransomware, sharing data to outside accounts, CI/CD supply chain), asks what a GuardDuty finding means and what to do about it, or wants a threat report or advisory turned into AWS controls. Defensive only; not for writing exploits.
---

# AWS attack paths

Turn an AWS attack technique into the controls that cover it: how it shows up, how to
detect it, how to prevent it, how to respond, and the evidence and NIST IDs that go with
each control. The audience runs multi-account AWS Organizations, often under FedRAMP.

## Ground rules

1. **Defensive only.** Explain a technique at the level of API calls and conditions, which
   is what detections and policies are written against. Don't write working exploit code,
   attack tooling, or step-by-step instructions for using a technique against an
   environment the user doesn't own.
2. **Check facts that drift.** GuardDuty finding types, Security Hub control IDs, IAM
   condition keys, and which services RCPs support all change. The catalog was checked
   against AWS documentation on the date in its header. Before a user deploys a policy or
   detection, point them to the AWS page for each finding type, control or key used, and
   say so if you could not confirm it.
3. **Partition-aware, least privilege.** Build ARNs from `data.aws_partition.current.partition`
   (Terraform) or `${AWS::Partition}`; never hard-code `arn:aws:`. In GovCloud use only
   `us-gov-west-1` and `us-gov-east-1`. Wildcards need a stated reason.
4. **Preventive controls can break workloads.** For every SCP or RCP, state who it would
   deny besides the attacker, exempt break-glass and security-pipeline roles, and default
   anything that could deny existing workloads to off. SCPs don't apply to the management
   account or to service-linked roles, and an SCP document is limited to 5,120 characters.
5. **Never deploy.** Give Terraform and `terraform plan` commands for the user to run and
   review; never apply, and never run mutating AWS CLI calls.
6. **Say what isn't covered.** Every answer ends with the gaps: the variants the controls
   miss, logs that must be turned on first (data events, Bedrock invocation logging), and
   detections that need tuning before they page anyone.

## Workflow

1. **Name the technique.** Map the user's description, finding or report to a MITRE ATT&CK
   technique ID and to an entry in [references/techniques.md](references/techniques.md).
   If no entry fits, work it out with the same fields and say it is not in the catalog.
2. **Trace the path.** List the API calls the attacker makes, in order, and which
   principal makes them. This is what the detections and policies hang on.
3. **Detect.** GuardDuty finding types, CloudTrail event names (say which are data events
   that must be enabled), Security Hub controls, and Config rules. Note where a custom
   EventBridge rule or metric filter is needed because no managed finding exists.
4. **Prevent.** SCPs, RCPs, permissions boundaries, IAM conditions, and account settings.
   Give the policy statement, its blast radius, and its exemptions.
5. **Respond.** The containment step (revoke sessions, deactivate credentials, isolate),
   what evidence to preserve first, and how to recover.
6. **Map to NIST.** Give the 800-53 Rev5 control IDs for each control. If the
   `fedramp-cloud-compliance` skill is installed, confirm IDs and FedRAMP class baselines
   with its `fedramp.py lookup`.
7. **List gaps**, per ground rule 6.

## Output

Lead with a one-line summary of the technique and the strongest single control. Then a
table:

| Layer | Control | Where | NIST |
|---|---|---|---|
| Detect | GuardDuty `<finding type>` | Organization-wide GuardDuty | SI-4, AU-6 |
| Prevent | SCP statement denying `<actions>` unless `<condition>` | OU `<name>`, exempting break-glass | AC-3, AC-6 |
| Respond | Revoke role sessions | Runbook or automated playbook | IR-4 |

Then the policy or detection code, the rollout and rollback notes, and the gaps.

## Reference implementations

The catalog links working, tested examples in these public repositories. Point users to
them as patterns to adapt, not as a drop-in deployment:

- [aws-org-guardrails](https://github.com/DustyStudy/aws-org-guardrails): SCP bundles
  (core, security services, data and compute, region), a permissions boundary, AI/ML
  guardrails, and an AI agent IAM auditor.
- [aws-remediation-orchestrator](https://github.com/DustyStudy/aws-remediation-orchestrator):
  approval-gated response playbooks driven by GuardDuty and Security Hub findings.
- [fedramp-terraform-library](https://github.com/DustyStudy/fedramp-terraform-library):
  organization CloudTrail, GuardDuty and Security Hub modules, plus detective auditors
  for trust policies, Identity Center access, RDS access and stale accounts.
- [prowler-aws-template](https://github.com/DustyStudy/prowler-aws-template): scheduled
  organization-wide Prowler scans from GitHub Actions over OIDC.

## Related skills

- `fedramp-cloud-compliance`: exact FedRAMP rule, KSI and control text, and Terraform
  review against FedRAMP.
- `security-audit`: vulnerability review of application or infrastructure code.
