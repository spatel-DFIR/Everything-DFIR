# STS for DFIR

STS is where you **reconstruct movement**. When an attacker pivots from a stolen key into a role, or from one account into another, the `AssumeRole` events are the breadcrumbs. This note is about following them.

New to the service? Read **What is STS** and **01 - IAM & Identities** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate — Reconstructing the Pivot](#investigate--reconstructing-the-pivot)
- [Reading an STS Event](#reading-an-sts-event)
- [The Orphan-Session Problem](#the-orphan-session-problem)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

STS answers **"how did they move, into what, and can I cut the session off?"** Killing the original key does nothing to a live `ASIA` session — you have to *see* the session to *revoke* it.

## Evidence It Produces

| Evidence | What it gives you | Where |
|----------|-------------------|-------|
| `AssumeRole*` events | Who assumed what, when, from where, MFA or not | CloudTrail `sts.amazonaws.com` |
| `GetCallerIdentity` events | "whoami" recon calls | CloudTrail |
| The session's own actions | Everything the `ASIA` session did downstream | CloudTrail (filter by the `ASIA` key) |
| `sessionContext` on every event | Ties any action back to its role + MFA status | Inside `userIdentity` |

## Collect It

STS has little live state — the evidence is in **CloudTrail**. Pull the assume events and the session's downstream actions.

```bash
# Every role assumption in the window (Event history, mgmt events)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole --max-results 50

# Everything a specific temporary session did
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=ASIA... --max-results 50
```

> **Console:** CloudTrail → Event history → Event name = `AssumeRole` / `GetCallerIdentity`; or filter by the `ASIA` **Access key ID** to see a session's actions.

## Investigate — Reconstructing the Pivot

Walk the chain in order — this is the core skill:

| Step | What you find | Field |
|------|---------------|-------|
| 1. Origin | The first identity (leaked user/key, SSO login) | `userIdentity` on the earliest event |
| 2. The assume | The `AssumeRole` call itself | `eventName=AssumeRole`, `requestParameters.roleArn` |
| 3. The session | The `ASIA` key it minted | `responseElements.credentials.accessKeyId` |
| 4. The actions | What the session did next | Filter later events by that `ASIA` |
| 5. Further hops | Any `AssumeRole` *from* the session | Repeat — chains can be several deep |
| 6. Attribution | Tie the whole chain to a human | `sourceIdentity` (if enforced) survives every hop |

**Split human from workload:** legit STS is dominated by workloads (EC2/Lambda assuming their roles on a schedule). Filter those out by looking for:

- **Unusual assumers** — a *user* assuming a role they never touch.
- **Unusual source IPs / geos / ASNs** — a workload role suddenly assumed from a residential IP or foreign country.
- **`mfaAuthenticated: false`** on a human-facing or sensitive role.
- **Odd `roleSessionName`** — tool names, hostnames, or attacker labels.

## Reading an STS Event

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `userIdentity` | Who asked to assume | A user/key you're already tracking |
| `requestParameters.roleArn` | **What role they became** | Admin / cross-account roles |
| `requestParameters.roleSessionName` | Caller-chosen session label | Tool names; blends-in labels |
| `responseElements.credentials.accessKeyId` | The `ASIA` session key | Pivot key for the next step |
| `sourceIPAddress` + `userAgent` | From where / with what | New IP/geo; scripted tooling |
| `sessionContext.attributes.mfaAuthenticated` | Was MFA satisfied | `false` on sensitive roles |
| `resources[].accountId` vs caller account | Cross-account assume | Movement between accounts |
| `sourceIdentity` | Tamper-resistant human attribution | Best field if your org sets it |

## The Orphan-Session Problem

The most common STS confusion on a real case:

> **You see an `ASIA…` session doing damage, but you can't find the `AssumeRole` that created it.**

Causes and fixes:

| Cause | Fix |
|-------|-----|
| The assume logged to a **region you're not looking at** | Check **all** regions, especially `us-east-1` (global STS endpoint) |
| The assume happened **before your log window** | Widen the time range; pull from S3/Lake, not just 90-day history |
| The session was minted in **another account** (cross-account role) | Check the org trail / the trusting account's logs |
| The trail **excludes** STS or global events | Confirm the trail is multi-region + includes management events |

> 🔴 An orphan `ASIA` session is not a dead end — it's a signpost saying *your visibility has a hole*. Find and close the hole; the origin is on the other side of it.

## Hunt at Scale

**In-platform — Athena / Lake (SQL):**

```sql
-- Sensitive-role assumptions without MFA
SELECT eventtime, useridentity.arn AS who,
       json_extract_scalar(requestparameters,'$.roleArn') AS role_assumed,
       sourceipaddress,
       json_extract_scalar(useridentity, '$.sessioncontext.attributes.mfaauthenticated') AS mfa
FROM cloudtrail_logs
WHERE eventname = 'AssumeRole' AND eventtime > '2026-07-01'
  AND json_extract_scalar(requestparameters,'$.roleArn') LIKE '%admin%'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):**

```text
metadata.log_type = "AWS_CLOUDTRAIL"
metadata.product_event_type = "AssumeRole"
```

## Respond

| Goal | Action |
|------|--------|
| Kill all live sessions for a role | IAM → Role → **Revoke active sessions** (inline deny by `aws:TokenIssueTime`) |
| Cut a specific in-flight session | Attach a deny policy conditioned on the session's issue time/ARN |
| Stop new assumptions | Tighten (or temporarily lock) the role's **trust policy** |
| Kill the source of the sessions | Deactivate the originating `AKIA` key / disable the user / fix the OIDC trust |

> 🔴 **You cannot "delete" a temporary credential.** The only ways to stop it are to **revoke the role's sessions** (time-based deny) or wait for expiry. Deactivating the parent key stops *new* assumes but not the session already in flight — do both.

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enforce `sourceIdentity`** on assume-role policies | Attribution survives role chaining |
| **Short session durations** on sensitive roles | Smaller window for a stolen session |
| **`aws:MultiFactorAuthPresent` condition** in trust policies | No MFA → no assume into sensitive roles |
| **Scope OIDC/SAML trust tightly** (repo/subject/audience conditions) | Blocks foreign-CI / rogue-IdP abuse |
| **Regional STS endpoints + activation controls** | Reduces global-endpoint logging blind spots |
| **Restrict `iam:PassRole`** to only the roles a service truly needs | Cuts the PassRole→compute privesc |
| **Alert** on cross-account assumes and MFA-false sensitive-role assumes | Real-time pivot detection |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `ASIA…` session activity with no discoverable `AssumeRole` | Session minted outside your logging scope — widen it |
| `AssumeRole` into admin with `mfaAuthenticated: false` | Privilege escalation / MFA bypass |
| A *user* assuming a role they never use, from a new IP/geo | Stolen creds pivoting |
| Cross-account `AssumeRole` you didn't expect | Lateral movement between accounts |
| `AssumeRoleWithWebIdentity` from an unexpected OIDC subject | Over-broad trust policy abused (foreign CI) |
| `GetCallerIdentity` from a new IP, then enumeration | Attacker "whoami" after landing a cred |
| Deep role chains (assume → assume → assume) | Obfuscated pivoting |
| Odd `roleSessionName` (tool names, hostnames) | Attacker tooling fingerprint |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What STS is + session anatomy | **STS → What is STS** |
| Reading identity types (AKIA vs ASIA) | **AWS → 01 IAM & Identities** |
| The roles/trust policies assumed | **AWS → Identity & Access → IAM** |
| SSO permission-set sessions | **AWS → Identity & Access → IAM Identity Center** |
| Instance role theft via IMDS | **AWS → Playbooks → IMDS SSRF to Role Theft** |
| The audit trail | **AWS → Logging & Monitoring → CloudTrail** |

## Resources

- STS API reference — https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html
- Revoking IAM role temporary credentials — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html
- Monitoring & controlling actions with `sourceIdentity` — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html
- MITRE ATT&CK: Use Alternate Authentication Material (T1550) — https://attack.mitre.org/techniques/T1550/
