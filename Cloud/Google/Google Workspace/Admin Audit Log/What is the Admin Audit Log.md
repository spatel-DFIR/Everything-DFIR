# What is the Admin Audit Log?

The **Admin audit log** records every change made in the **Admin console** (`admin.google.com`) — creating users, granting admin roles, changing security settings, authorizing API clients. It is the Workspace equivalent of watching the directory's control plane.

If the Login audit answers "who signed in?", the Admin audit answers **"who changed the org?"** Almost every Workspace persistence and privilege move — a new admin, a disabled 2-Step Verification requirement, a domain-wide-delegation grant — lands here.

## Contents

- [How It Works](#how-it-works)
- [How to Identify It in Evidence](#how-to-identify-it-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

Workspace keeps a **separate audit log per application** (admin, login, drive, token, groups…). The **Admin** log captures administrative actions taken in the console or via the **Admin SDK**.

```
Admin acts (console or Admin SDK / gcloud identity)
   → event written to the Admin audit log
   → readable in: Admin console → Reporting → Audit and investigation → Admin log events
                  Reports API (Admin SDK) applicationName=admin
                  (optional) exported to BigQuery / shared to Cloud Logging
```

- Every event has an **actor** (which admin), an **event name** (`GRANT_ADMIN_PRIVILEGE`), and **parameters** (the target user, the role, the old/new value).
- **Super Admins** can do anything here; delegated admin roles are scoped.
- 🔴 The Admin log is where you see the **two-admin-worlds** crown jewel move: granting Super Admin, or authorizing an API client for **domain-wide delegation**.

## How to Identify It in Evidence

- **Console:** Admin console → **Reporting → Audit and investigation → Admin log events** (filter by event, actor, date).
- **API:** Admin SDK **Reports API**, `activities.list` with `applicationName=admin`.
- **Event shape:** `actor.email`, `id.time`, `events[].name`, `events[].parameters[]` (e.g. `USER_EMAIL`, `ROLE_NAME`, `NEW_VALUE`).
- **Export:** if configured, Workspace logs land in **BigQuery** (`admin` table) or are shared to **Cloud Logging**.

## Common Operations You Will See

🔴 marks the events that create admins, weaken security, or open the Workspace↔GCP bridge — the attacker's toolkit.

| Event name | What it does | Watch? |
|-----------|--------------|--------|
| `CREATE_USER` / `DELETE_USER` | Add/remove a user | 🔴 backdoor identity |
| `GRANT_ADMIN_PRIVILEGE` / `GRANT_DELEGATED_ADMIN_PRIVILEGE` | Make someone an admin | 🔴 privilege escalation |
| `ASSIGN_ROLE` / `CREATE_ROLE` / `UPDATE_ROLE` | Role management | 🔴 custom admin role with broad scopes |
| `AUTHORIZE_API_CLIENT_ACCESS` | Authorize an API client (**domain-wide delegation**) | 🔴 SA gets a Workspace-wide key |
| `CHANGE_PASSWORD` / `RESET_PASSWORD` | Change a user's password | 🔴 account takeover of another user |
| `TOGGLE_2SV` / `UNENROLL_USER_FROM_STRONG_AUTHENTICATION` | Change 2-Step Verification | 🔴 removing MFA to persist |
| `ENFORCE_STRONG_AUTHENTICATION` (disabled) | Turn off org-wide MFA enforcement | 🔴 weakens everyone |
| `CHANGE_EMAIL_SETTING` / auto-forwarding, routing | Mail flow / routing changes | 🔴 org-level mail exfil |
| `ADD_APPLICATION` / `CHANGE_APPLICATION_SETTING` | Marketplace app / app config | 🔴 rogue app enabled |
| `CREATE_GROUP` / `ADD_GROUP_MEMBER` | Group changes | 🔴 add self to a privileged group |
| `TRUSTED_DOMAINS` / SSO profile changes | Federation / SSO config | 🔴 federation backdoor |

## Cross-Provider Equivalent

| Google Workspace | AWS | Microsoft |
|------------------|-----|-----------|
| Admin audit log | CloudTrail (IAM/Organizations events) | Entra audit log |
| `GRANT_ADMIN_PRIVILEGE` | `AttachUserPolicy` (admin) | `Add member to role` (Global Admin) |
| `AUTHORIZE_API_CLIENT_ACCESS` (DWD) | (no direct equal) | Admin consent to app-only Graph perms |
| `TOGGLE_2SV` | `DeactivateMFADevice` | `Disable strong auth` |
| Super Admin | Root / Org management account | Global Administrator |

## Common Use Cases

Your "normal" baseline:

- **Provisioning** — onboarding/offboarding users, groups, org units.
- **Security config** — enforcing 2SV, setting Context-Aware Access, session controls.
- **App management** — enabling Workspace Marketplace apps; authorizing API clients for integrations.
- **Delegated administration** — help-desk/user-management admins doing scoped tasks.

> 🔴 In a mature org, **Super-Admin actions are rare and few people hold the role.** A *new* Super Admin, a *new* API client authorization, or a 2SV toggle outside a change window is unusual by itself — a strong signal.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Admin console** | `admin.google.com` — where Workspace/identity is managed |
| **Super Admin** | The most powerful Workspace role |
| **Delegated admin role** | A scoped admin role (help desk, user management…) |
| **Reports API** | Admin SDK API that returns audit activities |
| **Domain-wide delegation** | Authorizing an SA/API client to impersonate users (see 01) |
| **2-Step Verification (2SV)** | Google's MFA |
| **Org unit (OU)** | A subtree of users for scoped policy |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating admin abuse in a case | **Admin Audit Log → for DFIR** |
| Who the identities/admins are | **Google → 01 Google Identities** |
| The sign-in behind an admin action | **Workspace → Login & Auth Audit** |
| The two admin worlds (Workspace vs GCP) | **Google → 00 Overview & Terminology** |
| OAuth / API client grants in depth | **Workspace → OAuth & Third-Party Apps** |

## Resources

- Admin audit log — https://support.google.com/a/answer/4579579
- Reports API (admin activities) — https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list
- Administrator roles — https://support.google.com/a/answer/2405986
- Manage domain-wide delegation — https://support.google.com/a/answer/162106
