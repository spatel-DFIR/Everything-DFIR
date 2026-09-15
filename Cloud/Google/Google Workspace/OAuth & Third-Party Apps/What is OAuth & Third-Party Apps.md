# What is OAuth & Third-Party Apps?

Workspace lets users **authorize third-party apps** to access their data (mail, Drive, calendar) via **OAuth**. That consent is a credential: an app granted `gmail.readonly` holds a **refresh token** that reads the user's mail **without a password and without tripping MFA** — until the grant is revoked.

This is the surface behind the **illicit OAuth grant** attack, and it's also where **domain-wide delegation** (a service account's Workspace-wide key) is configured. The **Token audit log** is your evidence.

## Contents

- [How It Works](#how-it-works)
- [Why Attackers Love OAuth Grants](#why-attackers-love-oauth-grants)
- [The Scopes That Matter](#the-scopes-that-matter)
- [App Access Control — The Admin Levers](#app-access-control--the-admin-levers)
- [Domain-Wide Delegation Lives Here](#domain-wide-delegation-lives-here)
- [How to Identify OAuth Evidence](#how-to-identify-oauth-evidence)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
User clicks "Allow" on an app's consent screen (or admin grants domain-wide)
   → app receives a REFRESH TOKEN for the granted OAuth scopes
   → app calls Gmail/Drive/Directory APIs as the user, silently, until revoked
   → each grant is recorded in the Token audit log (event: authorize)
```

- The grant is **per-user** (user consent) or **domain-wide** (admin-configured delegation).
- A refresh token is **long-lived** — the app keeps working across password resets. 🔴 Revoking the **grant** (not resetting the password) is what cuts it.
- OAuth apps appear in **Admin console → Security → API controls → "Apps with access to Workspace data."**

## Why Attackers Love OAuth Grants

| Property | Why it helps the attacker |
|----------|---------------------------|
| **No password / no MFA** | The token *is* the access; MFA already satisfied at consent |
| **Survives password reset** | Refresh token persists — classic persistence |
| **Looks like a normal app** | Blends into the many legit SaaS integrations |
| **User-grantable** | Unless restricted, any user can consent — one phish click = access |

> 🔴 The **illicit consent grant**: a phishing link leads to a real Google consent screen for an attacker-controlled app requesting `gmail.readonly` + `drive.readonly`. The victim clicks Allow; the attacker's app now reads their mail and files with a refresh token. No credentials stolen. See **Workspace → Playbooks → Illicit OAuth Grant**.

## The Scopes That Matter

🔴 Scopes that grant broad data access are the ones to scrutinize on any grant:

| Scope | Grants | 🔴 |
|-------|--------|----|
| `https://mail.google.com/` | Full mailbox (read/send/delete) | Total mail control |
| `gmail.readonly` / `gmail.modify` | Read / modify mail | Mail theft / rule injection |
| `drive` / `drive.readonly` | All Drive files | File exfil |
| `admin.directory.*` | Directory read/write | Recon / user manipulation |
| `cloud-platform` | GCP APIs | Bridge into GCP |
| `calendar` / `contacts` | Calendar / contacts | Recon / social-engineering data |

## App Access Control — The Admin Levers

Admin console → **Security → API controls → App access control**. Each third-party app is:

| State | Meaning |
|-------|---------|
| **Trusted** | Full access to permitted scopes |
| **Limited** | Only limited scopes |
| **Blocked** | Cannot access Workspace data |
| **Unconfigured** | Governed by the default (allow/block unconfigured apps) |

> 🔴 Set the default to **block unconfigured apps** and restrict which scopes users can consent to. An org that allows any app + any user consent is one phish away from an illicit grant.

## Domain-Wide Delegation Lives Here

Admin console → **Security → API controls → Domain-wide delegation** lists **service accounts (by OAuth client ID) authorized to impersonate users** for specific scopes. 🔴 This is the GCP↔Workspace bridge from **01 - Google Identities**: an SA here can read *any* user's mail/Drive. A **new client ID** in this list is a top-tier alert (audit event `AUTHORIZE_API_CLIENT_ACCESS`).

## How to Identify OAuth Evidence

- **Token audit log:** Admin console → **Reporting → Audit → Token log events**; Reports API `applicationName=token`.
- **Event shape:** `actor.email`, `event.name` (`authorize`/`revoke`/`activity`), `client_id`, `app_name`, `scope`.
- **Current grants:** Admin console → **Security → API controls → Apps with access to Workspace data** (and per-user *Connected applications*).
- **DWD list:** Security → API controls → **Domain-wide delegation**.

## Cross-Provider Equivalent

| Google Workspace | AWS | Microsoft |
|------------------|-----|-----------|
| OAuth grant (Token log `authorize`) | — | Enterprise-app consent / OAuth2PermissionGrant |
| Illicit OAuth grant | — | Illicit consent grant |
| Domain-wide delegation | — | App-only Graph permissions (`Mail.Read` app) |
| App access control | — | App consent policies / admin consent |
| Refresh token (app) | — | Refresh token |

## Key Terminology

| Term | Meaning |
|------|---------|
| **OAuth scope** | The permission an app requests (e.g. `gmail.readonly`) |
| **Refresh token** | Long-lived token letting an app keep accessing data |
| **Token audit log** | The log of OAuth authorizations/revocations |
| **App access control** | Admin allow/limit/block of third-party apps |
| **Domain-wide delegation (DWD)** | An SA authorized to impersonate users |
| **Connected app** | A third-party app a user has authorized |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating OAuth abuse in a case | **OAuth & Third-Party Apps → for DFIR** |
| Service accounts + DWD (the identity side) | **Google → 01 Google Identities** |
| The admin event that authorizes a DWD client | **Workspace → Admin Audit Log** |
| Illicit-grant intrusion | **Workspace → Playbooks → Illicit OAuth Grant** |
| Mail/Drive data an app can reach | **Workspace → Gmail** · **Drive & Docs Audit** |

## Resources

- Token audit log — https://support.google.com/a/answer/6124308
- Control which third-party apps access Workspace — https://support.google.com/a/answer/7281227
- Domain-wide delegation — https://support.google.com/a/answer/162106
- OAuth 2.0 scopes for Google APIs — https://developers.google.com/identity/protocols/oauth2/scopes
