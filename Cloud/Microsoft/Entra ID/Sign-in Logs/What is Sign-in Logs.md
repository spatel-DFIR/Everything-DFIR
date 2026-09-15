# What is Entra Sign-in Logs?

Entra **sign-in logs** are the record of **every authentication** in the tenant — every time an identity proves who it is to get a token. They answer *who signed in, from where, into what, and whether MFA and Conditional Access were satisfied.*

Think of them as the **front-door CCTV** for the whole Microsoft cloud. Because one sign-in issues a token that opens both M365 and Azure, this is where most investigations begin.

## Contents

- [How It Works](#how-it-works)
- [The Four Sign-in Logs](#the-four-sign-in-logs)
- [Where the Logs Live and How You Query Each](#where-the-logs-live-and-how-you-query-each)
- [How to Identify a Sign-in Event](#how-to-identify-a-sign-in-event)
- [Common Sign-in Fields You Will Read](#common-sign-in-fields-you-will-read)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

Every time an identity authenticates to Entra, it gets a **token** and Entra writes a **sign-in event**. The event captures the identity, the app it signed into, the source, the auth method, and the Conditional Access outcome.

The pipeline:

| Step | What happens |
|------|--------------|
| 1. Auth attempt | A user, app, or resource tries to authenticate |
| 2. Policy evaluation | Conditional Access + MFA + risk are evaluated |
| 3. Decision | Success (token issued) or failure (with an error code) |
| 4. Event | Entra records the sign-in with all the detail |
| 5. Retention | Kept ~30 days in Entra; longer only if exported |

Two facts to remember on a live case:

- Retention is **short** (~30 days, or 7 on some SKUs). Beyond that you need a **Log Analytics / Sentinel** export.
- Sign-ins are split into **four separate logs** (below). Looking at only the interactive one misses token replay and app abuse.

## The Four Sign-in Logs

🔴 The single most important structural fact about Entra sign-ins — there are **four**, and attackers hide in the ones nobody watches:

| Log | Records | Log Analytics table | Why you care |
|-----|---------|---------------------|--------------|
| **Interactive user** | A human typing a password / doing MFA | `SigninLogs` | The obvious sign-ins |
| **Non-interactive user** | Silent re-auth with an existing/refresh token | `AADNonInteractiveUserSignInLogs` | 🔴 **Token replay** hides here |
| **Service principal** | An app signing in with a secret/cert (no user) | `AADServicePrincipalSignInLogs` | 🔴 App-only attacks; no MFA |
| **Managed identity** | An Azure resource getting a token | `AADManagedIdentitySignInLogs` | 🔴 Managed-identity/IMDS abuse |

> **Always check all four.** A token-theft or rogue-app case that looks quiet in the interactive log is often loud in the non-interactive or service-principal log.

## Where the Logs Live and How You Query Each

| Destination | What it is | Look-back | How you query it | Best for |
|-------------|-----------|-----------|------------------|----------|
| **Entra portal** | The built-in sign-in blade | ~30 days | Filters + column picker | The fast first look |
| **Microsoft Graph** | `auditLogs/signIns` API | ~30 days | Graph queries / PowerShell | Scripted pulls, automation |
| **Log Analytics / Sentinel** | Exported copy, queryable with KQL | Your retention (often 90 days–2 yrs) | **KQL** | Long look-back, hunting, correlation |

> **Rule of thumb:** *recent, quick* → Entra portal. *Scripted / repeatable* → Graph. *Older / hunt / join across logs* → KQL in Log Analytics or Sentinel.

## How to Identify a Sign-in Event

- **Entra portal:** Entra ID → **Monitoring → Sign-in logs** → four tabs (User / Non-interactive / SP / Managed identity).
- **Graph:** `GET https://graph.microsoft.com/v1.0/auditLogs/signIns`.
- **KQL:** tables `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs`.
- **A sign-in event** always carries: an identity, an `appId`/`appDisplayName`, an `ipAddress`, an `authenticationDetails`, a `conditionalAccessStatus`, and a `status.errorCode`.

## Common Sign-in Fields You Will Read

| Field | Tells you | 🔴 Watch for |
|-------|-----------|-------------|
| `userPrincipalName` / `userType` | Who, member vs guest | `#EXT#` guest |
| `appDisplayName` / `appId` | Which app | Unexpected app; legacy clients |
| `ipAddress` + `location` | From where | New geo / ASN / impossible travel |
| `clientAppUsed` | Modern vs legacy auth | `IMAP`/`POP`/`SMTP`/"Other clients" = MFA bypass |
| `authenticationRequirement` | MFA required? | `singleFactorAuthentication` on sensitive access |
| `authenticationDetails` | MFA method + result | "satisfied by claim in token" = possible replay |
| `conditionalAccessStatus` | CA outcome | `failure` / `notApplied` where it should apply |
| `status.errorCode` | Success `0` or failure reason | `50126` spray · `53003` CA block · `50053` lockout |
| `riskLevelDuringSignIn` / `riskState` | Identity Protection verdict | `high` / `atRisk` |
| `deviceDetail` | Managed/compliant device? | Unknown/unmanaged device on sensitive access |
| `resourceDisplayName` | What was accessed | `Microsoft Graph`/`Azure Resource Manager` from odd tooling |

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| Entra sign-in logs | CloudTrail `ConsoleLogin` + STS events | Cloud Audit Logs (login) / Login audit |
| Non-interactive / token re-auth | (token use in CloudTrail) | Token grants |
| Service-principal sign-in | Service/role assumption events | Service-account auth |
| Conditional Access result | (no direct equal) | Context-Aware Access |

## Common Use Cases

Your "normal" baseline:

- **Access troubleshooting** — why a sign-in failed / was blocked.
- **Security monitoring** — risky sign-ins, impossible travel, legacy auth.
- **Conditional Access tuning** — what a policy would/did block.
- **App inventory** — which apps identities actually use.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Interactive sign-in** | A human authenticating directly |
| **Non-interactive sign-in** | Silent re-auth using an existing token |
| **Service principal sign-in** | An app authenticating as itself |
| **Managed identity sign-in** | An Azure resource getting a token |
| **Conditional Access (CA)** | Policy engine gating sign-ins |
| **Legacy auth** | Old protocols (IMAP/POP/SMTP) that bypass MFA |
| **Risk level** | Identity Protection's real-time verdict |
| **Error code** | The numeric reason a sign-in succeeded/failed |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating sign-ins in a case | **Sign-in Logs → Sign-in Logs for DFIR** |
| Identity types + tokens | **Microsoft → 01 Entra ID & Identities** |
| The policy that gates sign-ins | **Entra → Conditional Access & MFA** |
| Directory changes (roles/apps/consent) | **Entra → Audit Logs** |
| Risk detections behind a risky sign-in | **Entra → Identity Protection** |

## Resources

- Sign-in logs concept + schema — https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-ins
- Sign-in error codes — https://learn.microsoft.com/entra/identity-platform/reference-error-codes
- Non-interactive & service-principal sign-ins — https://learn.microsoft.com/entra/identity/monitoring-health/concept-all-sign-ins
- Stream logs to Log Analytics/Sentinel — https://learn.microsoft.com/entra/identity/monitoring-health/howto-integrate-activity-logs-with-azure-monitor-logs
