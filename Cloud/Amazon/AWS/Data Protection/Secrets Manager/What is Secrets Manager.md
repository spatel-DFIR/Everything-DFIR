# What is Secrets Manager

**AWS Secrets Manager** is the managed store for **secrets** — database passwords, API keys, OAuth tokens, third-party credentials — that applications fetch at runtime instead of hard-coding. Values are encrypted with **KMS** and retrieved by API.

Why an analyst cares: this is a **credential jackpot**. One `GetSecretValue` (or a `BatchGetSecretValue`) can hand an attacker the keys to your databases and SaaS integrations. Every secret read is a lead to *downstream* compromise, and the retrieval itself is logged in CloudTrail.

## Contents

- [How It Works](#how-it-works)
- [Secrets Manager vs SSM Parameter Store](#secrets-manager-vs-ssm-parameter-store)
- [How Access Is Decided](#how-access-is-decided)
- [How to Identify It](#how-to-identify-it)
- [Common Operations](#common-operations)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

| Concept | What it is | Why the analyst cares |
|---------|-----------|-----------------------|
| **Secret** | A named object holding a `SecretString` (usually JSON) or `SecretBinary`, encrypted with a KMS key | The value is the prize; reading it = the downstream creds are burned. |
| **Version + staging labels** | Every value is a version; `AWSCURRENT` = live, `AWSPREVIOUS` = last, `AWSPENDING` = mid-rotation | An attacker can read `AWSPREVIOUS` to get an *old but maybe still valid* credential. |
| **Rotation** | An optional Lambda rotates the secret on a schedule (built-in for RDS) | 🔴 The rotation Lambda is a persistence/interception target. |
| **Resource policy** | A policy attached to the secret (like a KMS key policy) | 🔴 Can grant **another account** read access — cross-account theft. |
| **Replication** | A secret can be copied to other regions | 🔴 `ReplicateSecretToRegions` can be an exfil/stash move. |
| **KMS backing** | The secret is envelope-encrypted with a KMS key | Reading it triggers a KMS `Decrypt` — a second breadcrumb (→ KMS). |

## Secrets Manager vs SSM Parameter Store

Both store secrets; you'll investigate both. Know the difference:

| | Secrets Manager | SSM Parameter Store (`SecureString`) |
|-|-----------------|--------------------------------------|
| **Built for** | Secrets, with rotation | Config + secrets, simpler |
| **Rotation** | ✅ Native (Lambda) | ❌ Manual |
| **Cross-region replication** | ✅ | ❌ |
| **Retrieval API** | `GetSecretValue` / `BatchGetSecretValue` | `GetParameter(s)` / `GetParametersByPath` |
| **Cost** | Per secret + per call | Free tier (standard) |
| **KMS-encrypted** | ✅ | ✅ (`SecureString`) |

> On a case, hunt **both** — attackers harvest from whichever the org used. See **SSM → Parameter Store**.

## How Access Is Decided

Two layers, and either can be the abused one:

- **IAM identity policy** — what a principal is allowed to do (`secretsmanager:GetSecretValue` on which secret ARNs).
- **Resource policy on the secret** — can *additionally* grant access, including to **another account**. 🔴 `PutResourcePolicy` adding an external principal = cross-account secret theft that an IAM-only review misses.
- The **KMS key policy** on the wrapping key must also allow the caller to `Decrypt` — so a secret read leaves a KMS trail too.

## How to Identify It

| Thing | Shape / example |
|------|-----------------|
| **Secret ARN** | `arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/password-a1b2c3` (random 6-char suffix) |
| **Secret name** | `prod/db/password` (often path-like) |
| **Version ID** | a UUID; labelled `AWSCURRENT` / `AWSPREVIOUS` / `AWSPENDING` |
| **Rotation Lambda** | a function named `SecretsManager…` with permission on the secret |
| **Value** | `SecretString` (JSON) or `SecretBinary` — **never** in CloudTrail |

## Common Operations

🔴 = high-value on a case. **W** = write, **R** = read.

| Operation | R/W | What it does | Flag |
|-----------|-----|--------------|------|
| `GetSecretValue` | R | Retrieves a secret's value | 🔴 credential theft — the core event |
| `BatchGetSecretValue` | R | Retrieves **many** secrets in one call | 🔴 bulk harvest |
| `ListSecrets` | R | Enumerates secret names/ARNs | Recon before harvesting |
| `DescribeSecret` | R | Metadata (not value): rotation, policy, KMS key | Recon / targeting |
| `PutResourcePolicy` | W | Sets the secret's resource policy | 🔴 add external account → cross-account theft |
| `PutSecretValue` / `UpdateSecret` | W | Writes a new value | Tampering / planting attacker creds |
| `ReplicateSecretToRegions` | W | Copies the secret to other regions | 🔴 exfil/stash |
| `DeleteSecret` | W | Deletes (with a recovery window) | 🔴 destruction |
| `RestoreSecret` | W | Cancels a pending deletion | Recovery — or attacker restoring |
| `RotateSecret` / `CancelRotateSecret` | W | Trigger/stop rotation | Disrupting rotation to keep a stolen cred valid |

> **What CloudTrail gives you:** the *fact* of a `GetSecretValue` (who, when, which secret ARN, from where) — but **never the secret value**. That's enough to scope: any secret read by a suspect principal is burned and must be rotated.

## Cross-Provider Equivalent

| Concept | AWS | Azure | Google Cloud |
|---------|-----|-------|--------------|
| Secret store | **Secrets Manager** | **Key Vault (secrets)** | **Secret Manager** |
| Read a secret | **`GetSecretValue`** | `SecretGet` (Key Vault) | `AccessSecretVersion` |
| Resource-level policy | **Secret resource policy** | Key Vault access policy / RBAC | IAM on the secret |
| Native rotation | **✅ (Lambda)** | ✅ (Key Vault + Functions) | Rotation schedules |
| Alt. store | **SSM Parameter Store** | **App Configuration** | Runtime config |

## Common Use Cases

- **App runtime secrets** — a service fetches its DB password at boot via its IAM role, rather than baking it into an image.
- **RDS/Aurora credential rotation** — Secrets Manager rotates database creds automatically.
- **Third-party API keys / tokens** — Stripe, Datadog, GitHub, etc.
- **Cross-account sharing** — a secret shared (deliberately) via resource policy to a partner account.

> "Normal" retrieval is a **specific app role** reading a **specific secret** on a predictable cadence (boot, rotation). A human principal, or a role reading *many* secrets it never touched, or a read from a new IP — those are the anomalies.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Secret** | The stored, KMS-encrypted credential object |
| **Version / staging label** | `AWSCURRENT` (live), `AWSPREVIOUS`, `AWSPENDING` |
| **Rotation** | Scheduled automatic replacement of the secret value |
| **Resource policy** | Policy on the secret; can grant cross-account access |
| **Replication** | Copying a secret to additional regions |
| **Recovery window** | The 7–30 day delay before `DeleteSecret` finalizes |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Reading `GetSecretValue` events + the harvest/theft patterns | **Secrets Manager for DFIR** |
| The KMS key that wraps the secret (second breadcrumb) | **AWS → Data Protection → KMS** |
| The other secret store to also sweep | **AWS → Compute → Systems Manager (SSM)** (Parameter Store) |
| Who read it, and revoking their session | **AWS → 01 IAM & Identities** · **STS** |
| A leaked-key chain that ends in secret theft | **AWS → Playbooks → Leaked Access Key** |
| The audit log recording every read | **AWS → Logging & Monitoring → CloudTrail** |
| The same service in Azure/GCP | **Azure → Key Vault** · **Cloud → 06 Service Equivalents** |

## Resources

- What is Secrets Manager — https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html
- Retrieving secrets (`GetSecretValue`) — https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets.html
- Resource-based policies — https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-based-policies.html
- Rotation — https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html
- Logging with CloudTrail — https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring-cloudtrail.html
