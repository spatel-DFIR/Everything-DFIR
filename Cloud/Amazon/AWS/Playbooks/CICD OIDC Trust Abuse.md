# Playbook — CI/CD OIDC Trust Abuse

Modern pipelines (GitHub Actions, GitLab, etc.) authenticate to AWS **without stored keys** by federating via **OIDC** and calling `AssumeRoleWithWebIdentity`. Powerful and keyless — but a **loose trust policy** lets *someone else's* pipeline assume your role. This is a current, rising attack path.

> **Tier 2 (cross-service).** Touches STS, IAM, CloudTrail. Read **STS for DFIR** and **01 IAM & Identities** (federation).

## Contents

- [Attack Chain](#attack-chain)
- [Trigger / How You Find Out](#trigger--how-you-find-out)
- [Hypothesis](#hypothesis)
- [The Trust-Policy Weakness](#the-trust-policy-weakness)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Attack Chain

```
CI role trusts an OIDC provider (e.g. token.actions.githubusercontent.com)
   but the trust CONDITION is too loose (missing/loose `sub`, or `aud` only)
   → attacker's fork / another repo / another org gets an OIDC token
   → AssumeRoleWithWebIdentity → your CI role's ASIA creds
   → acts as your pipeline: deploy, read secrets, push malicious artifacts, pivot
```

A second variant: the **pipeline itself is compromised** (malicious dependency / poisoned workflow) and abuses its *legitimate* role.

## Trigger / How You Find Out

| Source | What you see |
|--------|--------------|
| **CloudTrail** | `AssumeRoleWithWebIdentity` with an unexpected `sub` / repo / branch |
| **Unexpected deploys** | Infra/artifact changes outside your pipeline runs |
| **GuardDuty** | Role activity from anomalous IPs, or secrets access |
| **Supply-chain alert** | A dependency/workflow flagged as malicious |

## Hypothesis

An attacker assumed a CI role via OIDC — either by abusing a loose trust policy from an external identity, or by compromising the pipeline that legitimately holds the role. Confirm which, scope the role's actions, and tighten the trust.

## The Trust-Policy Weakness

The role's trust policy should pin **provider + audience + subject** to *your* repo/branch/environment. Weaknesses:

| Weakness | Effect |
|----------|--------|
| No `sub` condition (only `aud`) | 🔴 **Any** repo on that OIDC provider can assume the role |
| Wildcard `sub` (`repo:org/*`) too broad | Any repo in the org (incl. forks with write) |
| Missing `aud` (`sts.amazonaws.com`) check | Token-audience confusion |
| Trusting the wrong OIDC thumbprint/provider | Rogue provider |

Read it:

```bash
aws iam get-role --role-name <ci-role> --query 'Role.AssumeRolePolicyDocument'
# check Condition.StringEquals/StringLike: token.actions.githubusercontent.com:sub and :aud
```

## Step-by-Step Investigation

**1. Pull the web-identity assumes.**

```sql
-- Athena/Lake
SELECT eventtime, sourceipaddress,
       json_extract_scalar(requestparameters,'$.roleArn') AS role,
       json_extract_scalar(useridentity,'$.username') AS sub
FROM cloudtrail_logs
WHERE eventname = 'AssumeRoleWithWebIdentity' AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**2. Check the `sub` / repo.** Does each assume's subject match **your** repo/branch/environment? An unexpected `sub` (foreign repo, a fork, another org) = trust abuse. Correlate the source IP (GitHub-hosted runner ranges vs random).

**3. External abuse vs pipeline compromise.**
- **External:** `sub` is a repo/org that isn't yours → loose trust policy exploited.
- **Pipeline compromise:** `sub` *is* yours, but the assume happened at an odd time / from an odd IP / did unusual things → your workflow or a dependency was poisoned.

**4. Scope the session.** Follow the `ASIA` from the assume: what did the CI role do? Deploys, secret reads (`GetSecretValue`), artifact pushes, further `AssumeRole`, IAM changes.

**5. Blast radius = the CI role's policy.** CI roles are often over-permissioned ("deploy everything") — enumerate what it could reach.

## Decision Points

| Question | If yes → |
|----------|----------|
| Is the `sub` foreign to your org? | Loose trust exploited — tighten the condition now |
| Is the `sub` yours but behavior anomalous? | Pipeline/dependency compromise — investigate the repo/workflow |
| Did the role read secrets? | Rotate all of them |
| Did it deploy artifacts? | Assume artifacts are tainted — rebuild from trusted source |
| Over-permissioned role? | Scope it down as part of the fix |

## Contain

- **Tighten the trust policy immediately** to pin `sub` to your exact repo/branch/environment (and `aud = sts.amazonaws.com`), or temporarily detach the OIDC trust.
- Revoke the CI role's active sessions.
- If pipeline-compromise: disable the affected workflow / rotate the pipeline's own secrets.

## Eradicate

- Fix the trust condition (least-privilege `sub`).
- Rotate every secret the role could read.
- Rebuild/redeploy any artifacts pushed during the window from a trusted state.
- Remove any persistence the session created in AWS (→ Persistence Hunt).
- For pipeline compromise: remove the malicious dependency/workflow change; audit the repo's history.

## Recover

- Least-privilege the CI role (deploy only what it needs).
- Add branch/environment protection; require reviews on workflow changes.
- Preserve: the `AssumeRoleWithWebIdentity` events + the session timeline.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| `AssumeRoleWithWebIdentity` with a foreign `sub`/repo | Loose OIDC trust abused |
| CI role assume from a non-runner IP / odd time | Pipeline or trust compromise |
| Trust policy with `aud` but no `sub` condition | Any repo can assume it |
| CI role reading secrets / doing IAM changes | Over-reach / abuse |
| Unexpected deploys outside pipeline runs | Someone else holds the role |

## References

- Related notes: **STS for DFIR**, **IAM for DFIR**, **01 IAM & Identities**, **Persistence and Backdoor Hunt**
- Configuring OIDC for GitHub Actions in AWS — https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services
- IAM OIDC identity providers — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html
- MITRE ATT&CK: Valid Accounts – Cloud (T1078.004), Trusted Relationship (T1199) — https://attack.mitre.org/techniques/T1199/
