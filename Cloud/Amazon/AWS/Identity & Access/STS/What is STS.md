# What is STS?

**STS (Security Token Service)** mints **temporary credentials**. When anyone "assumes a role," STS is what hands them the short-lived `ASIA…` key, secret, and session token they use from then on.

STS is the **engine of movement** in AWS. Nearly every pivot — user → role, EC2 → role, SSO → role, one account → another — runs through an STS call. This note is the concept; **STS for DFIR** is the hunt.

## Contents

- [How It Works](#how-it-works)
- [The STS Operations](#the-sts-operations)
- [Global vs Regional Endpoints — A Logging Trap](#global-vs-regional-endpoints--a-logging-trap)
- [How to Identify STS in Evidence](#how-to-identify-sts-in-evidence)
- [What a Session Looks Like](#what-a-session-looks-like)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
Caller (user / EC2 / SSO / another account)
      │  "I want to be role X"
      ▼
STS  ── checks role X's TRUST POLICY ──►  allowed?
      │  yes
      ▼
Returns TEMPORARY creds:  AccessKeyId (ASIA…) + SecretAccessKey + SessionToken + Expiration
      │
      ▼
Caller now acts AS role X until the creds expire (15 min – 12 hrs, up to 36h for GetSessionToken)
```

Key facts:

- The creds are **short-lived** and **carry a session token** (`x-amz-security-token`).
- Authorization to assume is decided by the **role's trust policy**, not the caller's own policy alone.
- STS itself is **free** and its events appear in CloudTrail under `sts.amazonaws.com`.

## The STS Operations

| Operation | Who calls it | What it mints | 🔴 Watch |
|-----------|--------------|---------------|----------|
| **`AssumeRole`** | A user/role/service assuming another role | Session for that role | The workhorse pivot; role chaining |
| **`AssumeRoleWithSAML`** | Enterprise SAML SSO | Session from a SAML assertion | New IdP or unexpected subject |
| **`AssumeRoleWithWebIdentity`** | OIDC (GitHub Actions, EKS IRSA, mobile) | Session from an OIDC token | 🔴 over-broad OIDC trust abuse |
| **`GetSessionToken`** | A user upgrading to an MFA-backed session | Temp session for the *same* user | Rare from attackers; MFA-gating |
| **`GetFederationToken`** | A user minting a federated session | `FederatedUser` session | Unusual; can broaden reach |
| **`GetCallerIdentity`** | Anyone: "who am I?" | Nothing — just identity | 🔴 The #1 first move after landing a stolen cred |

> 🔴 **`GetCallerIdentity`** is the attacker's "whoami." It's harmless by itself and used by legit tooling, but a `GetCallerIdentity` from a new IP immediately followed by enumeration is a classic **first-action-after-compromise** signature.
>
> 🔴 The "~36 hrs max" figure for `GetSessionToken` applies to **IAM users**. **Root-user** credentials obtained via `GetSessionToken` are capped at **1 hour**, no matter what duration is requested.

## Global vs Regional Endpoints — A Logging Trap

STS can be called two ways, and it changes **where the event logs**:

| Endpoint | Example host | Event logs to |
|----------|--------------|---------------|
| **Global** | `sts.amazonaws.com` | **`us-east-1`** |
| **Regional** | `sts.eu-west-1.amazonaws.com` | that region (`eu-west-1`) |

> 🔴 **The trap:** if your CloudTrail is single-region and misses `us-east-1`, or misses the region an attacker chose, you can **see an `ASIA` session acting but never see the `AssumeRole` that created it.** A temporary session with no discoverable origin means *widen your logging scope* — check `us-east-1` and every region. This is one of the most common "the logs don't add up" moments in AWS IR.

## How to Identify STS in Evidence

**In CloudTrail:** `eventSource = "sts.amazonaws.com"`, `eventName` = one of the operations above.

**ARNs a session produces:**

| Thing | ARN shape |
|-------|-----------|
| Assumed-role session | `arn:aws:sts::123456789012:assumed-role/<role>/<session-name>` |
| Federated session | `arn:aws:sts::123456789012:federated-user/<name>` |

**The key prefix:** every STS-minted key starts with **`ASIA`** (vs `AKIA` for long-term). See **01 - IAM & Identities**.

## What a Session Looks Like

The `AssumeRole` event and the session it mints:

```jsonc
// The AssumeRole call
{
  "eventSource": "sts.amazonaws.com",
  "eventName": "AssumeRole",
  "userIdentity": { "type": "IAMUser", "userName": "ci-deploy" },      // who asked
  "requestParameters": {
    "roleArn": "arn:aws:iam::123456789012:role/prod-admin",            // 🔴 what they became
    "roleSessionName": "deploy-42" },
  "responseElements": { "credentials": {
      "accessKeyId": "ASIAXXXX",                                       // the session key
      "expiration": "Jul 9, 2026 8:02:11 PM" } }
}
```

Every later action by that session carries `accessKeyId: "ASIAXXXX"` and `sessionContext.sessionIssuer.arn = …:role/prod-admin`. **That's how you tie a session's actions back to the role and the human.**

> **`roleSessionName`** is attacker-chosen on `AssumeRole` — sometimes it's a giveaway (a tool name, a username), sometimes deliberately blends in. **`sourceIdentity`**, if your org enforces it, is *not* freely settable and propagates through role chains — the best field for attribution.

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| STS `AssumeRole` | Token request / on-behalf-of flow | `generateAccessToken` (SA impersonation) |
| `AssumeRoleWithWebIdentity` | Federated credential (workload identity) | Workload Identity Federation |
| `AssumeRoleWithSAML` | SAML token issuance | Workforce Identity Federation |
| `ASIA…` temp creds | OAuth access token | Short-lived SA token |
| `GetCallerIdentity` | `az account show` / token introspection | `gcloud auth ... whoami` |

## Common Use Cases

Your "normal" for STS:

- **Workloads assuming roles** — EC2/Lambda/ECS use instance/execution roles constantly (high-volume, benign).
- **SSO logins** — every Identity Center sign-in is an `AssumeRole` into a permission-set role.
- **Cross-account access** — a central account assuming roles in member accounts.
- **CI/CD** — pipelines `AssumeRoleWithWebIdentity` via OIDC.
- **Break-glass / MFA step-up** — `GetSessionToken` for an MFA-backed session.

> Because legit `AssumeRole` volume is *huge*, don't alert on it blindly. Alert on **unusual assumers, unusual roles, unusual source IPs/geos, and MFA-false on sensitive roles** — see **STS for DFIR**.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Temporary credentials** | Short-lived `ASIA` key + secret + session token |
| **Session token** | The `x-amz-security-token` that accompanies temp creds |
| **AssumeRole** | The call that mints a session for a role |
| **Role session name** | Caller-chosen label on the session |
| **sourceIdentity** | Tamper-resistant attribution string that survives chaining |
| **Session duration** | 15 min–12 hrs (role) / up to 36 hrs (`GetSessionToken`) |
| **Trust policy** | The role-side rule deciding who may assume it |
| **Role chaining** | A session assuming another role (multi-hop) |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Hunting STS abuse in a case | **STS → STS for DFIR** |
| Reading identity types & the AKIA→ASIA pivot | **AWS → 01 IAM & Identities** |
| The roles/trust policies being assumed | **AWS → Identity & Access → IAM** |
| SSO permission-set sessions | **AWS → Identity & Access → IAM Identity Center** |
| Where these events are recorded | **AWS → Logging & Monitoring → CloudTrail** |

## Resources

- STS API reference — https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html
- Temporary security credentials — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html
- Managing STS in a Region (global vs regional endpoints) — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html
- Monitoring `sourceIdentity` — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html
