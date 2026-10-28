# Security Policy

## What "security" means for this repo

This repo holds Agent Skills (Markdown and manifests), not a running service.
"Security issue" here means:

- guidance that would lead a user to a weaker control than it claims, such as a
  wrong condition key, a policy that doesn't deny what it says, or a detection
  that can't fire;
- a skill that would help someone attack an environment they don't own;
- content that tries to instruct the agent (prompt injection).

## Reporting a vulnerability

Please **do not open a public GitHub issue** for a security finding. Use GitHub's
private reporting instead: **Security** tab → **Report a vulnerability**. Include the
file and line, what it says versus what it should say, and a primary source (AWS
documentation or MITRE ATT&CK).

## Response expectations

This is a personally maintained public repo with no SLA. Expect an acknowledgment
within a few days, and a fix prioritized ahead of new content once confirmed.

## Supported scope

Only the latest release and `main` are supported.
