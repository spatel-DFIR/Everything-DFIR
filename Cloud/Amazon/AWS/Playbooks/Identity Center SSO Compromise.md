# Playbook — IAM Identity Center (SSO) Compromise

In an SSO-first org, humans reach every AWS account through **IAM Identity Center** backed by an IdP (Okta/Entra/etc.). Compromise the SSO layer or the IdP, and the attacker gets **broad, multi-account access wearing a legitimate face**. This playbook works an SSO/identity compromise.

> **Tier 2 (cross-service).** Touches IAM Identity Center, STS, CloudTrail, and the upstream IdP. Read **IAM Identity Center for DFIR** and **STS for DFIR**.

## Contents

- [Attack Chain](#attack-chain)
- [Trigger / How You Find Out](#trigger--how-you-find-out)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Role Back to Human — the Core Move](#role-back-to-human--the-core-move)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Attack Chain

```
IdP compromise (phishing / MFA fatigue / token theft) OR SSO-admin compromise
   → SSO portal login from new IP/device → assume a permission-set role
   → appears in target accounts as AWSReservedSSO_<set>_<hash>
   → escalate: add self to admin group / widen a permission set / self-assign admin in an account
   → act across many accounts with one identity
```

## Trigger / How You Find Out

| Source | What you see |
|--------|--------------|
| **IdP alerts** | Impossible travel, new MFA factor, risky sign-in |
| **CloudTrail** | Activity by `AWSReservedSSO_…` roles from a new IP/geo |
| **Identity Center CloudTrail** | `CreateAccountAssignment`, `AttachManagedPolicyToPermissionSet`, new SSO users |
| **GuardDuty** | Anomalous console/API activity by the SSO role |

## Hypothesis

An attacker is using SSO access — via a stolen session, a compromised IdP account, or SSO-admin rights. Confirm the human behind it, determine whether the SSO layer or IdP itself is compromised, and cut off both.

## Step-by-Step Investigation

**1. Find the SSO role activity.** In target accounts, identify `AWSReservedSSO_<set>_<hash>` sessions acting suspiciously; note the `roleSessionName` (usually the user's email).

**2. Pivot to Identity Center logs.** Find the portal sign-in for that user at that time — IP, device, session (→ IAM Identity Center for DFIR).

**3. Pivot to the IdP.** In Okta/Entra, confirm the authentication: device, MFA method/factor, geo, impossible travel, and any IdP-side alert. **This is where you learn if the IdP itself is owned.**

**4. Hunt SSO-admin tampering** (usually in the mgmt/delegated-admin account):

```sql
SELECT eventtime, useridentity.arn, eventname, requestparameters
FROM cloudtrail_logs
WHERE eventsource IN ('sso.amazonaws.com','identitystore.amazonaws.com')
  AND eventname IN ('CreateAccountAssignment','AttachManagedPolicyToPermissionSet',
    'PutInlinePolicyToPermissionSet','AddMemberToGroup','CreateUser')
  AND eventtime > '2026-07-01' ORDER BY eventtime;
```

**5. Scope multi-account reach.** SSO spans accounts — check the org trail for the identity's activity in *every* account it could reach.

## Role Back to Human — the Core Move

| Rung | Log |
|------|-----|
| 1. The action | CloudTrail in the target account — the `AWSReservedSSO_` role |
| 2. The SSO sign-in | Identity Center logs — which user, IP, session |
| 3. The authentication | The **upstream IdP** — the real person, device, MFA, compromise |

> 🔴 Stop at rung 1 and you blame a role. You must reach the IdP to know *who* and *whether the front door is owned*.

## Decision Points

| Question | If yes → |
|----------|----------|
| Is the IdP itself compromised? | Fixing AWS alone won't contain — coordinate with IdP owners NOW |
| SSO-admin tampering (assignments/sets)? | Broad, deliberate escalation — treat as high severity |
| `roleSessionName` doesn't match a real sign-in? | Session forged by an SSO-admin attacker |
| New IAM users/keys in an SSO-only org? | Off-path persistence — hunt it |
| Multiple accounts touched? | Org-wide scope |

## Contain

- **Kill the SSO session**: Identity Center → Users → **Delete active sessions** for the user.
- **Disable the user** in the identity source (the external IdP if federated).
- **Revoke** the assumed permission-set role sessions in affected accounts.
- If the **IdP is compromised**: force IdP password reset + MFA re-enrollment, revoke IdP tokens, and treat it as an IdP incident too.

## Eradicate

- Remove attacker SSO tampering: rogue account assignments, group memberships, widened permission-set policies, rogue SSO users.
- Remove any AWS-side persistence created in-session (users/keys/roles — → Persistence Hunt).
- Fix the IdP: revoke rogue OAuth apps, remove attacker MFA factors, audit directory sync.

## Recover

- Enforce **phishing-resistant MFA (FIDO2)** at the IdP; shorten SSO session duration.
- Least-privilege permission sets; separate, tightly-assigned admin sets.
- Preserve: Identity Center sign-in logs, target-account CloudTrail, and IdP logs.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| SSO login from new country/ASN/device | Stolen session or IdP compromise |
| `roleSessionName` with no matching sign-in | Forged session (SSO-admin attacker) |
| `CreateAccountAssignment` granting self access | Self-assigned account access |
| Permission set gaining `AdministratorAccess` | Everyone with it just got admin |
| New IAM user/`AKIA` in an SSO-only org | Off-path persistence |
| IdP: new MFA factor / OAuth app / sync change | Front-door compromise |

## References

- Related notes: **IAM Identity Center for DFIR**, **STS for DFIR**, **Persistence and Backdoor Hunt**, **Organizations for DFIR**
- Logging Identity Center with CloudTrail — https://docs.aws.amazon.com/singlesignon/latest/userguide/logging-using-cloudtrail.html
- MITRE ATT&CK: Valid Accounts – Cloud (T1078.004), Modify Authentication Process (T1556) — https://attack.mitre.org/techniques/T1078/004/
