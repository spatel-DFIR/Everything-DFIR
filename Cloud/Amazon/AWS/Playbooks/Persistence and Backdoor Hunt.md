# Playbook — Persistence & Backdoor Hunt

You've contained the obvious compromise — now the hard question: **did they leave a way back in?** AWS offers many persistence footholds, several "self-healing." This playbook is the systematic sweep to find and remove *all* of them, so eradication actually sticks.

> **Tier 2 (cross-service).** Touches IAM, STS, Lambda, EventBridge/CloudWatch, Organizations, EC2. Read **IAM for DFIR**, **CloudWatch for DFIR**, **Lambda for DFIR**.

## Contents

- [Why This Playbook Exists](#why-this-playbook-exists)
- [Trigger / When to Run It](#trigger--when-to-run-it)
- [The Persistence Surfaces — Full Checklist](#the-persistence-surfaces--full-checklist)
- [Step-by-Step Hunt](#step-by-step-hunt)
- [Decision Points](#decision-points)
- [Eradicate](#eradicate)
- [Verify It Stuck](#verify-it-stuck)
- [Red Flags](#red-flags)
- [References](#references)

## Why This Playbook Exists

> 🔴 **The #1 IR failure in AWS: rotating the leaked key but missing the second access key, the backdoor role trust, or the EventBridge→Lambda that recreates access every hour.** The attacker walks right back in. This playbook prevents that by hunting *every* surface, not just the entry point.

## Trigger / When to Run It

- After **any** confirmed credential/identity compromise (always).
- When a resource keeps reappearing after you delete it (self-healing persistence).
- During a compromise assessment / threat hunt with no specific alert.

## The Persistence Surfaces — Full Checklist

| # | Surface | What to look for |
|---|---------|------------------|
| 1 | **Extra access keys** | A 2nd active `AKIA` on a user (esp. service accounts) |
| 2 | **New IAM users** | Users created in/after the incident window |
| 3 | **Console login profiles** | `CreateLoginProfile` on a user that never logged in |
| 4 | **Inline/attached policies** | Backdoor `Action:*` grants |
| 5 | **Role trust policies** | An added external/`*` trusted principal |
| 6 | **New roles** | Attacker-created assumable roles |
| 7 | **Identity providers** | Rogue SAML/OIDC `Create*Provider` |
| 8 | **Lambda + EventBridge** | Scheduled rule → function that re-creates creds |
| 9 | **EC2 key pairs / user-data** | Added SSH keys; boot-time backdoors |
| 10 | **Login/SSO changes** | New Identity Center users/assignments; IdP-side |
| 11 | **Org-level** | New member accounts; weakened SCPs; delegated admins |
| 12 | **Compute carrying creds** | Rogue instances/functions with powerful roles |
| 13 | **Resource policies** | S3/KMS/SQS/Secrets granting external accounts |
| 14 | **Cognito** | Guest identity pool / broadened roles |
| 15 | **SSM persistence** | State Manager **associations** (scheduled re-run of a doc) or attacker-created/edited **SSM documents** (→ Systems Manager (SSM)) |

## Step-by-Step Hunt

**1. Credential report — the fast win.**

```bash
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d > cred.csv
# Read: users with 2 active keys, new user_creation_time, recent access_key rotation, mfa_active=false
```

**2. Full authorization snapshot + diff.**

```bash
aws iam get-account-authorization-details > iam_now.json
# diff against a known-good baseline: new users/roles/policies/attachments/trusts
```

**3. Timeline the persistence APIs** (Athena/Lake over the window):

```sql
SELECT eventtime, useridentity.arn, eventname, requestparameters
FROM cloudtrail_logs
WHERE eventname IN ('CreateUser','CreateAccessKey','CreateLoginProfile','AttachUserPolicy',
  'PutUserPolicy','CreateRole','UpdateAssumeRolePolicy','CreateSAMLProvider',
  'CreateOpenIDConnectProvider','PutRolePolicy','CreatePolicyVersion','AddUserToGroup')
  AND eventtime > '2026-07-01' ORDER BY eventtime;
```

**4. Self-healing hunt (EventBridge + Lambda):**

```bash
aws events list-rules --query 'Rules[?ScheduleExpression].{Name:Name,Sched:ScheduleExpression}'
# for each suspect rule: list-targets-by-rule → inspect the target Lambda's code + role
```

**5. Compute + resource policies:** rogue instances/functions with broad roles; S3/KMS/Secrets/SQS resource policies granting external accounts; Cognito guest access.

**6. Org + SSO:** new accounts, detached/weakened SCPs, new delegated admins (→ Organizations); new Identity Center users/assignments + the upstream IdP (→ IAM Identity Center).

## Decision Points

| Question | If yes → |
|----------|----------|
| Resource reappears after deletion? | There's a self-healing loop (EventBridge/Lambda) — find it before deleting again |
| Second key on a service account? | Backdoor — remove it |
| Trust policy has a principal you don't recognize? | Backdoor federation/role — fix trust |
| New IdP present? | Rogue federation — delete it |
| Management account touched? | Escalate to org-wide (→ Organizations playbook territory) |

## Eradicate

Remove **every** item found: extra keys, rogue users, login profiles, backdoor policies/versions, fixed trust policies, deleted rogue roles/IdPs, killed EventBridge+Lambda loops, removed EC2 keypairs/user-data backdoors, reverted resource policies, disabled Cognito guest access, cleaned SSO/Org changes.

## Verify It Stuck

- Re-run the credential report + auth diff — clean vs baseline.
- Watch CloudTrail for 24–72h for the same identity/IP reappearing or a resource re-creating itself.
- Confirm no EventBridge/Lambda re-grant loop remains.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| Second active key on an account | Key-add persistence |
| `CreateLoginProfile` on a service user | Interactive backdoor |
| Trust policy with an external/`*` principal | Assume-role backdoor |
| `Create*Provider` you don't recognize | Rogue federation |
| EventBridge schedule → Lambda → IAM writes | Self-healing persistence |
| Resource created after you deleted it | Active re-grant loop |
| New member account / weakened SCP | Org-level persistence |

## References

- Related notes: **IAM for DFIR**, **CloudWatch for DFIR** (EventBridge), **Lambda for DFIR**, **Organizations for DFIR**, **IAM Identity Center for DFIR**, **Systems Manager (SSM) for DFIR** (State Manager associations / malicious documents), **Secrets Manager for DFIR** (resource-policy grants)
- MITRE ATT&CK: Account Manipulation (T1098), Event Triggered Execution (T1546), Create Account (T1136) — https://attack.mitre.org/techniques/T1098/
