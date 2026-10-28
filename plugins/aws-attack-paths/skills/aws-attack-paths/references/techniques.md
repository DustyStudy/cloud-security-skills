# AWS technique catalog

Checked on 2026-10-28: GuardDuty finding types, Security Hub control IDs, RCP service
coverage and S3 SSE-C behavior against AWS documentation; IAM action and condition key
names against the reference repositories' policies, which pass IAM Access Analyzer policy
validation. All of these change; confirm each one on the linked AWS page before deploying.

Each entry has the same fields: **Path** (the API calls, in order), **Detect**, **Prevent**,
**Respond**, **NIST** (800-53 Rev5), **Example** (a tested implementation, where one exists)
and **Gaps**.

Primary references:

- GuardDuty finding types: <https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html>
- Security Hub CSPM controls: <https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html>
- AWS CIRT Threat Technique Catalog: <https://aws-samples.github.io/threat-technique-catalog-for-aws/>
- MITRE ATT&CK Cloud (IaaS): <https://attack.mitre.org/matrices/enterprise/cloud/iaas/>

## 1. Leaked long-term access keys used from outside

ATT&CK [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Valid Accounts: Cloud
Accounts.

- **Path:** an IAM user's access key leaks (committed to code, infostealer, exposed web
  file). The attacker calls `sts:GetCallerIdentity`, enumerates (`iam:List*`,
  `ses:GetSendQuota`, `bedrock:ListFoundationModels`), then abuses whatever the user can
  reach.
- **Detect:** GuardDuty `UnauthorizedAccess:IAMUser/MaliciousIPCaller`,
  `Discovery:IAMUser/AnomalousBehavior`, `InitialAccess:IAMUser/AnomalousBehavior`, and the
  Extended Threat Detection attack sequence `AttackSequence:IAM/CompromisedCredentials`;
  Security Hub IAM.3 (keys rotated every 90 days or less) and IAM.22 (credentials unused for
  45 days removed); an AWS Health event or an `AWSCompromisedKeyQuarantine` managed policy
  (V2 and V3 versions exist) appearing on the user, which AWS does when it finds a key
  exposed publicly.
- **Prevent:** no long-term keys. SCP denying `iam:CreateUser`, `iam:CreateAccessKey` and
  `iam:CreateLoginProfile` outside break-glass; workloads use roles, people use IAM
  Identity Center. Where IAM users must stay, deny high-abuse services to them with
  `aws:PrincipalType` = `User` (SES, Bedrock).
- **Respond:** deactivate (don't delete) every access key and service-specific credential
  on the user, and attach an inline deny on `aws:TokenIssueTime` before now to the user too:
  deactivating a key doesn't end temporary credentials already issued from it
  (`GetSessionToken`, `GetFederationToken`). Revoke sessions on any role the key assumed.
  Check `iam:ListAccessKeys` and `iam:ListServiceSpecificCredentials` for credentials the
  attacker added, then review CloudTrail for the key's activity.
- **NIST:** IA-2, IA-5, AC-2, AC-2(3), AC-6, SI-4, IR-4.
- **Example:** aws-org-guardrails `core` bundle (IAM user and key creation, SES to IAM
  users); aws-remediation-orchestrator `DisableCompromisedCredentials` and
  `DeactivateStaleAccessKeys`.
- **Gaps:** keys that already exist keep working until rotated or removed; the SCP does not
  bind the management account.

## 2. Extra credentials added to a compromised IAM user

ATT&CK [T1098.001](https://attack.mitre.org/techniques/T1098/001/) Additional Cloud
Credentials.

- **Path:** with one stolen key, the attacker calls `iam:CreateAccessKey` (second key),
  `iam:CreateLoginProfile` or `iam:UpdateLoginProfile` (console password), or
  `iam:CreateServiceSpecificCredential` (Bedrock API key, CodeCommit Git credential,
  Keyspaces password), so revoking the first key doesn't end access.
- **Detect:** GuardDuty `Persistence:IAMUser/AnomalousBehavior`; CloudTrail
  `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile`,
  `CreateServiceSpecificCredential` from an IAM user (alert on any, since people shouldn't
  be doing it).
- **Prevent:** SCP denying those four actions except for break-glass.
- **Respond:** contain as in entry 1 (deactivate keys and service-specific credentials, deny
  sessions issued before now). Export the user's policies, group memberships, credential
  report and login profile as evidence before removing the login profile; delete the user
  only after the investigation is closed.
- **NIST:** AC-2, AC-2(4), IA-5, AU-6, IR-4.
- **Example:** aws-org-guardrails `core` bundle (service-specific credentials statement,
  off by default); aws-remediation-orchestrator `DisableCompromisedCredentials`.
- **Gaps:** containment that only deactivates access keys misses service-specific
  credentials and console passwords.

## 3. Privilege escalation through IAM

ATT&CK [T1098.003](https://attack.mitre.org/techniques/T1098/003/) Additional Cloud Roles.

- **Path:** a principal with one write action on IAM grants itself more:
  `iam:AttachUserPolicy`/`AttachRolePolicy`, `iam:PutUserPolicy`/`PutRolePolicy`,
  `iam:CreatePolicyVersion` with `--set-as-default`, `iam:SetDefaultPolicyVersion`,
  `iam:AddUserToGroup`, `iam:UpdateAssumeRolePolicy`, `iam:PassRole` combined with a
  compute service (`ec2:RunInstances`, `lambda:CreateFunction`), or
  `sso:CreateAccountAssignment` in IAM Identity Center.
- **Detect:** GuardDuty `PrivilegeEscalation:IAMUser/AnomalousBehavior`; CloudTrail
  `AttachRolePolicy` or `AttachUserPolicy` with `AdministratorAccess`, and
  `UpdateAssumeRolePolicy` adding an outside principal; IAM Access Analyzer external access
  findings.
- **Prevent:** a permissions boundary on every role that application teams and pipelines
  create (they can only create roles carrying the same boundary, can't edit or remove it,
  and can only pass roles under a delegated path); SCP protecting security and
  `OrganizationAccountAccessRole` roles; no permission set grants IAM or `sso:` write
  actions on `*`.
- **Respond:** detach the added policy, restore the trust policy, revoke the principal's
  sessions, and look for new users, roles and keys created in the same window.
- **NIST:** AC-6, AC-6(1), AC-6(5), AC-2(7), CM-5, AU-6.
- **Example:** aws-org-guardrails `permission-boundary` and `core` bundle (protected
  roles); fedramp-terraform-library `identity-center-access-auditor` (escalation actions on
  wildcard resources).
- **Gaps:** a boundary isn't attached retroactively: principals created before it was
  required need it added, and a principal that can edit its own boundary (for example one
  holding `iam:*` without an SCP protecting the boundary) can remove it.

## 4. Instance role credentials stolen through the metadata service

ATT&CK [T1552.005](https://attack.mitre.org/techniques/T1552/005/) Cloud Instance Metadata
API.

- **Path:** code running on the instance (a web app with server-side request forgery, a
  compromised package, a container) reads the role's credentials from the instance metadata
  service and uses them elsewhere.
- **Detect:** GuardDuty
  `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` and
  `.InsideAWS` (credentials used from another AWS account); Security Hub EC2.8 (IMDSv2
  required).
- **Prevent:** require IMDSv2 at launch (`ec2:MetadataHttpTokens` = `required`), deny
  changing metadata options afterwards, and set the hop limit to 1 where containers on
  bridge networks shouldn't reach the instance role
  (`ec2:MetadataHttpPutResponseHopLimit`). Network perimeter conditions
  (`aws:SourceVpc`, `aws:SourceVpce`, `aws:VpcSourceIp`) on sensitive resources make
  stolen credentials useless off the network.
- **Respond:** revoke the role's active sessions (an inline deny on
  `aws:TokenIssueTime` before now, which is what the console's "Revoke active sessions"
  adds as `AWSRevokeOlderSessions`), then isolate the instance after snapshotting its
  volumes.
- **NIST:** AC-3, AC-4, SC-7, SI-4, IR-4.
- **Example:** aws-org-guardrails `data-and-compute` bundle (IMDSv2, hop limit, metadata
  options); aws-remediation-orchestrator `RevokeRoleSessions` and
  `IsolateCompromisedInstance`.
- **Gaps:** IMDSv2 does not stop code running on the host itself; the hop-limit statement
  doesn't cover launches by Auto Scaling or EKS managed node groups; ECS task credentials
  come from a different endpoint.

## 5. Over-trusting OIDC and cross-account role trust

ATT&CK [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Cloud Accounts and
[T1195.002](https://attack.mitre.org/techniques/T1195/002/) Compromise Software Supply
Chain.

- **Path:** a role trusts the GitHub OIDC provider with no `sub` condition, a wildcard
  `sub`, or a whole branch, so any repository or any workflow file on that branch can
  assume it; or a role trusts a whole outside account (`:root`) instead of a named role, or
  trusts a third party without `sts:ExternalId`; or a role trusted by an AWS service lacks
  `aws:SourceAccount` or `aws:SourceArn` (confused deputy).
- **Detect:** CloudTrail `AssumeRoleWithWebIdentity` from an unexpected repository or
  workflow (the claims are in the event); IAM Access Analyzer external access findings;
  a scheduled audit of trust policies.
- **Prevent:** pin `token.actions.githubusercontent.com:sub` to one repository and
  environment or branch, and require `aud` = `sts.amazonaws.com`. IAM supports only the
  `amr`, `aud`, `email`, `oaud` and `sub` keys for GitHub, so a condition on another claim
  such as `job_workflow_ref` never matches and blocks the role entirely. To admit only one
  workflow file, customize the repository's OIDC subject template on GitHub to include
  `job_workflow_ref`, then match the new `sub` value. Trust named roles rather than whole
  accounts, require `sts:ExternalId` for third parties, and add
  `aws:SourceAccount`/`aws:SourceArn` to service-principal trusts; RCP limiting
  `sts:AssumeRole` to principals in the organization plus named partners.
- **Respond:** tighten the trust policy, revoke the role's sessions, and review what the
  role did since the trust was loosened.
- **NIST:** AC-3, AC-17, IA-2, IA-8, SA-9, SR-3.
- **Example:** fedramp-terraform-library `trust-policy-auditor` (missing or wildcard `sub`
  and `aud`, cross-account and `"*"` trust).
- **Gaps:** a trust pinned to `main` still admits every workflow file merged to `main`;
  branch protection and review are part of the control.

## 6. LLMjacking: stolen credentials used to run AI models

ATT&CK [T1496.004](https://attack.mitre.org/techniques/T1496/004/) Cloud Service
Hijacking.

- **Path:** stolen credentials call `bedrock:ListFoundationModels` and
  `bedrock:GetFoundationModelAvailability`, request model access, then invoke models at the
  victim's cost (`bedrock:InvokeModel`, which also authorizes the Converse API, and
  `bedrock:InvokeModelWithResponseStream`), often after
  `bedrock:GetModelInvocationLoggingConfiguration` to check whether prompts are logged, or
  `bedrock:DeleteModelInvocationLoggingConfiguration` to stop it.
- **Detect:** GuardDuty `DefenseEvasion:IAMUser/BedrockLoggingDisabled`; with GuardDuty AI
  Protection, `Impact:IAMUser/AnomalousModelInvocation` and `Impact:IAMUser/CostHarvesting`;
  CloudTrail Bedrock calls from IAM users or unexpected roles; a Cost Anomaly Detection
  monitor on Bedrock; model invocation logging turned on and protected.
- **Prevent:** SCP denying Bedrock to IAM users; an allowlist of foundation models; SCP
  denying both `bedrock:DeleteModelInvocationLoggingConfiguration` and
  `bedrock:PutModelInvocationLoggingConfiguration` (which can turn off payload logging or
  redirect it) to everyone but the logging administrator, plus guardrail deletion; Bedrock
  only from roles that need it.
- **Respond:** deactivate the credential (including Bedrock API keys), check model access
  agreements made during the incident, and review invocation logs.
- **NIST:** AC-3, AC-6, AU-2, AU-12, SI-4.
- **Example:** aws-org-guardrails `ai-ml-guardrails` (Bedrock to IAM users, model
  allowlist, invocation logging, guardrail deletion), `bedrock-cost-guardrails` and
  `bedrock-logging-enforcement`.
- **Gaps:** roles that legitimately call Bedrock can still be abused; without invocation
  logging the prompts are not recorded; the reference SCP denies only the delete call, so
  the logging configuration can still be overwritten (a scheduled enforcement check
  restores it after the fact, it doesn't prevent the change).

## 7. Cryptomining on hijacked compute

ATT&CK [T1496.001](https://attack.mitre.org/techniques/T1496/001/) Compute Hijacking, often
after [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing
Application.

- **Path:** an internet-facing service (an exposed AI server, a database, an unpatched web
  app) is exploited and runs a miner; or stolen credentials launch large instances in
  unused Regions.
- **Detect:** GuardDuty `CryptoCurrency:EC2/BitcoinTool.B!DNS`,
  `CryptoCurrency:EC2/BitcoinTool.B`; with Runtime Monitoring,
  `CryptoCurrency:Runtime/BitcoinTool.B!DNS` and `Impact:Runtime/CryptoMinerExecuted`;
  Security Hub EC2.18 and EC2.19 (security groups open to the internet); Cost Anomaly
  Detection; service quota changes.
- **Prevent:** region restriction SCP; no `0.0.0.0/0` ingress on management, database or
  AI server ports; patching and vulnerability scanning (Amazon Inspector).
- **Respond:** isolate the instance after snapshotting it, revoke its role's sessions, and
  close the ingress rule.
- **NIST:** CM-7, SC-7, SI-2, SI-4, RA-5, IR-4.
- **Example:** aws-org-guardrails `region-restriction` bundle;
  aws-remediation-orchestrator `RevokeOpenSshRdpIngress` and `IsolateCompromisedInstance`.
- **Gaps:** a region restriction must carve out global services; miners on containers
  need Runtime Monitoring, not only VPC flow and DNS analysis.

## 8. Logging and security service tampering

ATT&CK [T1562.008](https://attack.mitre.org/techniques/T1562/008/) Disable or Modify Cloud
Logs.

- **Path:** `cloudtrail:StopLogging`, `DeleteTrail`, `UpdateTrail` or `PutEventSelectors`;
  `guardduty:DeleteDetector`, `UpdateDetector` or `CreateFilter` (an auto-archive
  suppression rule); `config:StopConfigurationRecorder`; `securityhub:DisableSecurityHub`.
- **Detect:** GuardDuty `Stealth:IAMUser/CloudTrailLoggingDisabled` and
  `DefenseEvasion:IAMUser/AnomalousBehavior`; Security Hub CloudTrail.1 and GuardDuty.1;
  CIS metric filters for CloudTrail and Config changes.
- **Prevent:** an organization trail (members can't stop it); SCP denying those actions
  outside the security pipeline; delegated administrator for GuardDuty and Security Hub in a
  security account.
- **Respond:** restore the service, then treat the gap as an incident: whoever did it had
  admin rights.
- **NIST:** AU-6, AU-9, AU-12, SI-4, CM-5.
- **Example:** aws-org-guardrails `security-services` bundle; fedramp-terraform-library
  `org-cloudtrail`, `guardduty-org`, `security-hub-org` and `logging-monitoring`.
- **Gaps:** an organization trail can still be changed from the management account.

## 9. S3 ransomware and destruction

ATT&CK [T1486](https://attack.mitre.org/techniques/T1486/) Data Encrypted for Impact and
[T1485](https://attack.mitre.org/techniques/T1485/) Data Destruction.

- **Path:** stolen credentials rewrite objects (`PutObject`, `CopyObject`) using
  server-side encryption with a customer-provided key (SSE-C) that only the attacker holds,
  or with a KMS key in the attacker's account, then delete originals or add a lifecycle
  rule (`PutBucketLifecycleConfiguration`) to expire them. Since April 2026, S3 blocks SSE-C
  writes by default on new buckets and on existing buckets in accounts with no SSE-C
  objects, so the attacker may first re-enable it with `PutBucketEncryption`
  (`BlockedEncryptionTypes` set to `NONE`).
- **Detect:** GuardDuty `Impact:S3/AnomalousBehavior.Write`,
  `Impact:S3/AnomalousBehavior.Delete` and `Impact:S3/AnomalousBehavior.Permission`, and
  the attack sequence `AttackSequence:S3/CompromisedData` (these need S3 Protection, which
  uses CloudTrail S3 data events); CloudTrail management events for `PutBucketEncryption`,
  lifecycle and bucket policy changes.
- **Prevent:** keep SSE-C blocked on every bucket that doesn't need it, and deny
  `s3:PutEncryptionConfiguration` outside the pipeline that manages buckets; RCP denying S3
  access to principals outside the organization; versioning plus Object Lock or AWS Backup
  vault lock for data that must survive; MFA delete where practical.
- **Respond:** revoke the credentials, remove attacker lifecycle rules, and restore from
  versions or backups; don't pay for keys you can't verify.
- **NIST:** CP-9, CP-10, SC-28, AC-3, SI-4, IR-4.
- **Example:** none in the reference repositories yet.
- **Gaps:** S3 data events cost money and are often off; versioning alone doesn't help if
  the attacker can delete versions.

## 10. Sharing data to an outside account

ATT&CK [T1537](https://attack.mitre.org/techniques/T1537/) Transfer Data to Cloud Account.

- **Path:** `ec2:ModifySnapshotAttribute` (EBS snapshot), `ModifyImageAttribute` (AMI),
  `rds:ModifyDBSnapshotAttribute`, `ram:CreateResourceShare` or `AssociateResourceShare`
  with an outside principal, or a bucket policy granting an outside account.
- **Detect:** CloudTrail for those events with an account outside the organization in the
  request; IAM Access Analyzer external access findings; Security Hub EC2.1 and EC2.182
  (public EBS snapshots).
- **Prevent:** SCP denying new RAM shares that allow principals outside the organization
  (`ram:RequestedAllowsExternalPrincipals` on `CreateResourceShare` and
  `UpdateResourceShare`) and denying `AssociateResourceShare` on shares that already allow
  them (`ram:AllowsExternalPrincipals`), plus a review of shares created before the SCP;
  EBS snapshot and AMI block public access; RCP
  with `aws:PrincipalOrgID` on S3 and KMS.
- **Respond:** remove the share or permission and check whether the outside account copied
  the resource before removal (the copy is out of reach).
- **NIST:** AC-3, AC-4, AC-21, SC-7, SI-4.
- **Example:** aws-org-guardrails `data-and-compute` bundle (external RAM shares);
  fedramp-terraform-library `trust-policy-auditor` (RAM shares and open resource policies).
- **Gaps:** an unencrypted snapshot is readable as soon as it is shared. Snapshots
  encrypted with an AWS managed key can't be shared at all, and one encrypted with a
  customer managed key is useless to the outside account unless the key policy or a grant
  also lets it use the key, so watch KMS key policy and `CreateGrant` changes too.

## 11. Supply chain into the pipeline

ATT&CK [T1195.001](https://attack.mitre.org/techniques/T1195/001/) Compromise Software
Dependencies and Development Tools and [T1195.002](https://attack.mitre.org/techniques/T1195/002/)
Compromise Software Supply Chain.

- **Path:** a backdoored package, container image, GitHub Action or Terraform provider runs
  in CI or on a workload and steals the credentials around it (OIDC role sessions, instance
  roles, secrets).
- **Detect:** CloudTrail activity by the pipeline role outside its normal pattern; GuardDuty
  credential exfiltration findings for instance roles; dependency and image scanning.
- **Prevent:** pin Actions to full commit SHAs and packages by hash, keep Terraform lock
  files and a provider allowlist, give pipeline roles least privilege with pinned OIDC
  trust (entry 5), and audit workflows (for example with zizmor).
- **Respond:** revoke the pipeline role's sessions, rotate any secrets the job could read,
  and rebuild from known-good versions.
- **NIST:** SR-3, SR-11, SA-10, CM-14, SI-7, AC-6.
- **Example:** fedramp-terraform-library provider-source allowlist test; aws-org-guardrails
  IMDS hop-limit statement.
- **Gaps:** pinning stops silent upgrades, not a compromised version you chose to pin.
