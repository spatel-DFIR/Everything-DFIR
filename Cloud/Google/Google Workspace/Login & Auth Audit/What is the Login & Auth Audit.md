# What is the Login & Auth Audit?

The **Login audit log** records every **authentication** event for Workspace accounts — successful sign-ins, failures, 2-Step Verification challenges, logouts, and Google's own **suspicious-login** and **leaked-password** detections.

It answers the first question of almost every Google case: **who signed in, from where, and was it really them?** Because one Google account opens both Workspace and GCP, the takeover you find here is the root of the whole intrusion.

## Contents

- [How It Works](#how-it-works)
- [How to Identify It in Evidence](#how-to-identify-it-in-evidence)
- [The Login Events](#the-login-events)
- [Login Types — How They Authenticated](#login-types--how-they-authenticated)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
User authenticates (password / 2SV / SAML SSO / OAuth reauth)
   → event written to the Login audit log
   → readable in: Admin console → Reporting → Audit and investigation → Login events
                  Reports API (Admin SDK) applicationName=login
                  (optional) BigQuery export / Cloud Logging
```

- Each event has an **actor** (the account), an **IP**, a **login type** (`google_password`, `saml`, `reauth`…), and challenge/2SV detail.
- 🔴 Google adds its own verdicts: **`suspicious_login`** (ML-flagged anomaly) and **`account_disabled_password_leak`** (credential found in a breach).
- Service accounts do **not** appear here — they don't sign into Workspace. SA activity is in **Cloud Audit Logs** (see 01).

## How to Identify It in Evidence

- **Console:** Admin console → **Reporting → Audit and investigation → Login events** (filter by user, event, IP, date).
- **API:** Admin SDK Reports API, `applicationName=login`.
- **Event shape:** `actor.email`, `ipAddress`, `events[].name` (`login_success`…), `parameters` (`login_type`, `is_suspicious`, `login_challenge_method`).
- **Security dashboard / Security Investigation Tool** surface suspicious logins for hunting.

## The Login Events

| Event | Means | Watch? |
|-------|-------|--------|
| `login_success` | A successful sign-in | Baseline; 🔴 from new IP/geo |
| `login_failure` | A failed sign-in | 🔴 bursts = spray/brute force |
| `login_verification` | A 2SV challenge was issued | Context for MFA |
| `login_challenge` | An identity challenge (risk-based) | 🔴 repeated challenges |
| `suspicious_login` | Google flagged the login as anomalous | 🔴 investigate |
| `suspicious_login_less_secure_app` | Anomalous login via legacy/less-secure app | 🔴 legacy-auth risk |
| `account_disabled_password_leak` | Password found leaked → account auto-disabled | 🔴 credential compromise |
| `account_disabled_hijacked` | Google auto-disabled a hijacked account | 🔴 confirmed takeover |
| `logout` | Sign-out | Session boundary |
| `2sv_enroll` / `2sv_disable` | 2-Step Verification changed | 🔴 disable = persistence/evasion |

## Login Types — How They Authenticated

The `login_type` parameter tells you the **method** — and legacy methods are the MFA-bypass risk:

| `login_type` | Means | 🔴 Note |
|--------------|-------|---------|
| `google_password` | Password (+ any 2SV) at Google | Normal |
| `saml` | Federated SSO from your IdP | Pivot to the IdP logs for the real auth |
| `reauth` | Re-authentication for a sensitive action | Context |
| `exchange` | Legacy ActiveSync / mail-protocol auth | 🔴 can **bypass 2SV** |
| `unknown` | Unclassified | Investigate |

> 🔴 **Legacy / less-secure app access** (IMAP, POP, ActiveSync) can authenticate with just a password — bypassing 2-Step Verification. A `suspicious_login_less_secure_app` or `exchange` login on an account that should use modern auth is a classic attacker channel. Disable less-secure-app access org-wide.

## Cross-Provider Equivalent

| Google Workspace | AWS | Microsoft |
|------------------|-----|-----------|
| Login audit log | CloudTrail `ConsoleLogin` | Entra sign-in logs |
| `suspicious_login` | GuardDuty console/anomaly finding | Identity Protection risky sign-in |
| 2-Step Verification | MFA | MFA / Conditional Access |
| Legacy/less-secure app | — | Legacy auth (IMAP/POP/SMTP) |
| SAML login | `AssumeRoleWithSAML` | Federated SAML sign-in |

## Common Use Cases

Your "normal" baseline:

- **Daily sign-ins** from known corporate IPs/geos and managed devices.
- **SSO** via an enterprise IdP (Okta, Ping, Entra) — most enterprises federate Workspace.
- **Mobile sync** from enrolled devices.
- **2SV challenges** for new devices / risky context.

> 🔴 A mature org enforces 2SV and blocks less-secure apps. So a **password-only login, a legacy-protocol login, or a login from a brand-new ASN/country** stands out immediately.

## Key Terminology

| Term | Meaning |
|------|---------|
| **2-Step Verification (2SV)** | Google's MFA |
| **Suspicious login** | Google's ML-flagged anomalous sign-in |
| **Less-secure app** | Legacy app using password-only auth |
| **Login type** | The authentication method (`google_password`, `saml`…) |
| **Login challenge** | A risk-based identity verification |
| **Security dashboard / SIT** | Admin hunting/investigation surfaces |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating a takeover in a case | **Login & Auth Audit → for DFIR** |
| Who the identity is | **Google → 01 Google Identities** |
| What the account did after signing in (Workspace) | **Workspace → Admin Audit Log** · **Gmail** · **Drive & Docs Audit** |
| What it did in GCP | **GCP → Cloud Audit Logs** |
| A full account takeover | **Workspace → Playbooks → Account Takeover** |

## Resources

- Login audit log — https://support.google.com/a/answer/4580120
- Reports API events (login) — https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list/login-event-names
- Suspicious login / security alerts — https://support.google.com/a/answer/7102416
- 2-Step Verification — https://support.google.com/a/answer/175197
