# AWS technique catalog

Checked on 2026-11-20: GuardDuty finding types, Security Hub control IDs, RCP service
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
- **Detect:** GuardDuty `CredentialAccess:IAMUser/CompromisedCredentials` (Amazon threat
  intelligence flagged the key), `UnauthorizedAccess:IAMUser/MaliciousIPCaller`,
  `Discovery:IAMUser/AnomalousBehavior`, `InitialAccess:IAMUser/AnomalousBehavior`, and the
  Extended Threat Detection attack sequence `AttackSequence:IAM/CompromisedCredentials`;
  Security Hub IAM.3 (keys rotated every 90 days or less) and IAM.22 (credentials unused for
  45 days removed); an AWS Health event or an `AWSCompromisedKeyQuarantine` managed policy
  (V2 and V3 versions exist) appearing on the user, which AWS does when it finds a key
  exposed publicly.
- **Prevent:** no long-term keys. SCP denying `iam:CreateUser`, `iam:CreateAccessKey` and
  `iam:CreateLoginProfile` outside break-glass; workloads use roles, people use IAM
  Identity Center. Where IAM users must stay, deny high-abuse services to them with
  `aws:PrincipalType` in [`User`, `FederatedUser`] (SES, Bedrock): a `GetFederationToken`
  session made with the key has type `FederatedUser` and slips past a `User`-only match (or
  deny `sts:GetFederationToken` outright).
- **Respond:** deactivate (don't delete) every access key and service-specific credential
  on the user, and attach an inline deny on `aws:TokenIssueTime` before now to the user too:
  deactivating a key doesn't end temporary credentials already issued from it
  (`GetSessionToken`, `GetFederationToken`). The same inline policy denies
  `iam:UpdateAccessKey`, `iam:UpdateServiceSpecificCredential` and
  `iam:ResetServiceSpecificCredential`, so a credential you missed can't re-enable or re-key
  the ones you deactivated. Revoke sessions on any role the key assumed.
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
- **Prevent:** SCP denying those four actions except for break-glass, plus
  `iam:UpdateAccessKey`, `iam:UpdateServiceSpecificCredential` and
  `iam:ResetServiceSpecificCredential` for IAM users themselves (`aws:PrincipalType` =
  `User`), so a stolen credential can't re-enable a deactivated one (this also stops users
  managing their own keys).
- **Respond:** contain as in entry 1 (deactivate keys and service-specific credentials, deny
  sessions issued before now and the calls that re-enable credentials). Export the user's
  policies, group memberships, credential report and login profile as evidence before
  removing the login profile; delete the user only after the investigation is closed.
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
  required on instances), EC2.170 (launch templates) and AutoScaling.3 (launch
  configurations).
- **Prevent:** require IMDSv2 at launch (`ec2:MetadataHttpTokens` = `required`), deny
  changing metadata options afterwards, and set the hop limit to 1 where containers on
  bridge networks shouldn't reach the instance role
  (`ec2:MetadataHttpPutResponseHopLimit`). Because SCPs miss Auto Scaling launches (see
  Gaps), also set the account IMDS defaults per Region
  (`ec2:ModifyInstanceMetadataDefaults`, `--http-tokens required`, plus account-level IMDSv2
  enforcement) or the same settings in an EC2 declarative policy, and require `autoscaling:LaunchTemplateVersionSpecified` so groups
  can't follow `$Latest`/`$Default`. Network perimeter conditions
  (`aws:SourceVpc`, `aws:SourceVpce`, `aws:VpcSourceIp`) on sensitive resources make
  stolen credentials useless off the network.
- **Respond:** revoke the role's active sessions (an inline deny on
  `aws:TokenIssueTime` before now, which is what the console's "Revoke active sessions"
  adds as `AWSRevokeOlderSessions`). That doesn't stop a running instance pulling fresh
  credentials from IMDS, so also disassociate or replace its instance profile
  (`ec2:DisassociateIamInstanceProfile`, `ReplaceIamInstanceProfileAssociation`), then
  isolate the instance after snapshotting its volumes.
- **NIST:** AC-3, AC-4, SC-7, SI-4, IR-4.
- **Example:** aws-org-guardrails `data-and-compute` bundle (IMDSv2, hop limit, metadata
  options); aws-remediation-orchestrator `RevokeRoleSessions` and
  `IsolateCompromisedInstance`.
- **Gaps:** IMDSv2 does not stop code running on the host itself. Neither the IMDSv2 nor the
  hop-limit SCP statement binds instances that Auto Scaling (including EKS managed node
  groups) launches after the group is created or updated: those launches use its
  service-linked role, which SCPs don't bind. Account defaults don't change existing
  instances. ECS task credentials come from a different endpoint.

## 5. Over-trusting OIDC and cross-account role trust

ATT&CK [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Cloud Accounts and
[T1195.002](https://attack.mitre.org/techniques/T1195/002/) Compromise Software Supply
Chain.

- **Path:** a role trusts the GitHub OIDC provider with no `sub` condition, a wildcard
  `sub`, or a whole branch, so any repository or any workflow file on that branch can
  assume it; or a role trusts a whole outside account (`:root`) instead of a named role, or
  trusts a third party without `sts:ExternalId`; or a role trusted by an AWS service lacks
  `aws:SourceAccount` or `aws:SourceArn` (confused deputy).
- **Detect:** CloudTrail `AssumeRoleWithWebIdentity` from an unexpected repository (the
  event's `userIdentity` carries the provider, `aud` and `sub`; don't expect
  `job_workflow_ref`, `workflow` or `actor` in it, so an unexpected workflow on an allowed
  branch can't be spotted from CloudTrail alone; check a sample event); IAM Access
  Analyzer external access findings; a scheduled audit of trust policies.
- **Prevent:** require `aud` = `sts.amazonaws.com` and pin the repository by its immutable
  IDs, `token.actions.githubusercontent.com:repository_id` and `repository_owner_id`
  (names can be renamed and re-registered), plus `sub` or `ref`/`environment` for the
  branch or environment; add `job_workflow_ref` to admit one workflow file. Since early
  2026 STS validates GitHub's `actor`, `actor_id`, `job_workflow_ref`, `repository`,
  `repository_id`, `repository_owner_id`, `workflow`, `ref`, `environment` and
  `enterprise_id` claims in trust policies and RCPs, in commercial Regions. GovCloud
  support is unconfirmed: test there first, since a condition on an unsupported key never
  matches and locks the role out, and fall back to customizing the repository's OIDC
  subject template on GitHub to include `job_workflow_ref`, then matching the new `sub`.
  Trust named roles rather than whole accounts, require `sts:ExternalId` for third
  parties, and add `aws:SourceAccount`/`aws:SourceArn` to service-principal trusts. RCP
  limiting `sts:AssumeRole` to principals in the organization plus named partners, and
  `sts:AssumeRoleWithWebIdentity` from GitHub to your `repository_owner_id` (scope it with
  `...IfExists` or a `Null` check so other OIDC providers such as EKS aren't denied; test
  first). RCPs never cover roles in the management account or service-linked roles.
- **Respond:** tighten the trust policy, revoke the role's sessions, and review what the
  role did since the trust was loosened.
- **NIST:** AC-3, AC-17, IA-2, IA-8, SA-9, SR-3.
- **Example:** fedramp-terraform-library `trust-policy-auditor` (missing or wildcard `sub`
  and `aud`, cross-account and `"*"` trust).
- **Gaps:** a trust pinned to `main` without `job_workflow_ref` still admits every
  workflow file merged to `main`; branch protection and review are part of the control.

## 6. LLMjacking: stolen credentials used to run AI models

ATT&CK [T1496.004](https://attack.mitre.org/techniques/T1496/004/) Cloud Service
Hijacking.

- **Path:** stolen credentials call `bedrock:ListFoundationModels` and
  `bedrock:GetFoundationModelAvailability`, then invoke models at the victim's cost
  (`bedrock:InvokeModel`, which also authorizes the Converse API, and
  `bedrock:InvokeModelWithResponseStream`), often after
  `bedrock:GetModelInvocationLoggingConfiguration` to check whether prompts are logged, or
  `bedrock:DeleteModelInvocationLoggingConfiguration` to stop it. Since October 2025
  serverless models are enabled by default (the model access page and
  `PutFoundationModelEntitlement` are retired); Anthropic models need a one-time use-case
  form (`bedrock:PutUseCaseForModelAccess`) and Marketplace-offered models an
  `aws-marketplace:Subscribe` on first call, which the attacker can make.
- **Detect:** GuardDuty `DefenseEvasion:IAMUser/BedrockLoggingDisabled`; with GuardDuty AI
  Protection, `Impact:IAMUser/AnomalousModelInvocation` (default severity Low, so route it
  by type, not severity) and `Impact:IAMUser/CostHarvesting`; CloudTrail Bedrock calls from
  IAM users or unexpected roles (`InvokeModel`, `InvokeModelWithResponseStream`, `Converse`
  and `ConverseStream` are management events, but `StartAsyncInvoke` and
  `InvokeModelWithBidirectionalStream` are data events that must be turned on); a Cost
  Anomaly Detection monitor on Bedrock; model invocation logging turned on and protected.
- **Prevent:** SCP denying Bedrock to IAM users; an allowlist of foundation models; SCP
  denying both `bedrock:DeleteModelInvocationLoggingConfiguration` and
  `bedrock:PutModelInvocationLoggingConfiguration` (which can turn off payload logging or
  redirect it) to everyone but the logging administrator, plus guardrail deletion; Bedrock
  only from roles that need it. Invocation logging is set per Region, so pair it with a
  Region-restriction SCP or turn it on in every Region Bedrock can be called in.
- **Respond:** deactivate the credential. Long-term Bedrock API keys can be set inactive
  (`iam:UpdateServiceSpecificCredential`); short-term keys are presigned and can't be
  revoked one by one, so revoke the issuing identity's sessions. Check CloudTrail for
  `PutUseCaseForModelAccess`, `CreateFoundationModelAgreement` and
  `aws-marketplace:Subscribe` during the incident, and review invocation logs.
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
  `guardduty:DeleteDetector`, `UpdateDetector`, `CreateFilter` (an auto-archive
  suppression rule), `CreateIPSet` or `UpdateIPSet` (GuardDuty raises no findings for
  addresses on a trusted IP list) or `DisassociateFromAdministratorAccount`;
  `config:StopConfigurationRecorder`, `DeleteConfigurationRecorder` or
  `DeleteDeliveryChannel`; `securityhub:DisableSecurityHub`, `BatchDisableStandards` or
  `CreateAutomationRule` (to suppress findings); `ec2:DeleteFlowLogs`.
- **Detect:** GuardDuty `Stealth:IAMUser/CloudTrailLoggingDisabled` and
  `DefenseEvasion:IAMUser/AnomalousBehavior`; Security Hub CloudTrail.1 and GuardDuty.1;
  CIS metric filters for CloudTrail and Config changes. GuardDuty has no dedicated finding
  for GuardDuty, Security Hub or Config being disabled, so add a custom EventBridge rule on
  the calls above.
- **Prevent:** an organization trail (members can't stop it); SCP denying those actions
  outside the security pipeline; delegated administrator for GuardDuty and Security Hub in a
  security account.
- **Respond:** restore the service, then treat the gap as an incident: whoever did it had
  admin rights.
- **NIST:** AU-6, AU-9, AU-12, SI-4, CM-5.
- **Example:** aws-org-guardrails `security-services` bundle; fedramp-terraform-library
  `org-cloudtrail`, `guardduty-org`, `security-hub-org` and `logging-monitoring`.
- **Gaps:** an organization trail can still be changed from the management account and
  from the CloudTrail delegated administrator account.

## 9. S3 ransomware and destruction

ATT&CK [T1486](https://attack.mitre.org/techniques/T1486/) Data Encrypted for Impact and
[T1485](https://attack.mitre.org/techniques/T1485/) Data Destruction, including
[T1485.001](https://attack.mitre.org/techniques/T1485/001/) Lifecycle-Triggered Deletion.

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
  vault lock for data that must survive; MFA delete where practical. For the
  attacker-account KMS key variant, test an SCP denying `kms:GenerateDataKey*`,
  `kms:Encrypt` and `kms:ReEncrypt*` on keys whose `aws:ResourceOrgID` isn't your
  organization; it also blocks partner and AWS-owned keys you rely on, so list exemptions
  first.
- **Respond:** revoke the credentials, remove attacker lifecycle rules, and restore from
  versions or backups; don't pay for keys you can't verify.
- **NIST:** CP-9, CP-10, SC-28, AC-3, SI-4, IR-4.
- **Example:** none in the reference repositories yet.
- **Gaps:** GuardDuty S3 Protection reads S3 data events itself, but your own CloudTrail or
  SIEM detections on object writes (for example SSE-C `PutObject`) need trail data events,
  which cost money and are often off; versioning alone doesn't help if the attacker can
  delete versions.

## 10. Sharing data to an outside account

ATT&CK [T1537](https://attack.mitre.org/techniques/T1537/) Transfer Data to Cloud Account.

- **Path:** `ec2:ModifySnapshotAttribute` (EBS snapshot), `ModifyImageAttribute` (AMI),
  `rds:ModifyDBSnapshotAttribute`, `ram:CreateResourceShare` or `AssociateResourceShare`
  with an outside principal, or a bucket policy granting an outside account.
- **Detect:** CloudTrail for those events with an account outside the organization in the
  request, plus `AssociateKmsKeyId` (an EBS associated KMS key that makes a snapshot
  shareable) and `CopySnapshot` re-encrypting under a customer managed key; IAM Access
  Analyzer external access findings; Security Hub EC2.1 and EC2.182 (public EBS
  snapshots) and RDS.1 (public RDS snapshots).
- **Prevent:** SCP denying new RAM shares that allow principals outside the organization
  (`ram:RequestedAllowsExternalPrincipals` with `BoolIfExists` on `CreateResourceShare`,
  since an omitted `allowExternalPrincipals` defaults to true, and `Bool` on
  `UpdateResourceShare`) and denying `AssociateResourceShare` on shares that already allow
  them (`ram:AllowsExternalPrincipals`), plus a review of shares created before the SCP;
  EBS snapshot and AMI block public access (stops public sharing only, not sharing to a
  named outside account); RCP with `aws:PrincipalOrgID` on S3 and KMS (RCPs don't cover
  the `ec2:` and `rds:` snapshot and AMI actions, or AWS managed KMS keys).
- **Respond:** remove the share or permission and check whether the outside account copied
  the resource before removal (the copy is out of reach).
- **NIST:** AC-3, AC-4, AC-21, SC-7, SI-4.
- **Example:** aws-org-guardrails `data-and-compute` bundle (external RAM shares);
  fedramp-terraform-library `trust-policy-auditor` (RAM shares and open resource policies).
- **Gaps:** an unencrypted snapshot is readable as soon as it is shared. An encrypted one is
  useless to the outside account until it can use a key: the encrypting customer managed
  key (key policy or `CreateGrant`), an associated KMS key (which also makes snapshots
  encrypted with an AWS managed key shareable), or a key the snapshot was re-encrypted
  under with `CopySnapshot`. Watch all three.

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
