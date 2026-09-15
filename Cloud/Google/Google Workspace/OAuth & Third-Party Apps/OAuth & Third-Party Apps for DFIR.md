# OAuth & Third-Party Apps for DFIR

OAuth cases are about **tokens that outlive passwords**: find the rogue grant, see what data it could reach, revoke it (not just reset the user), and close the consent path.

New to it? Read **What is OAuth & Third-Party Apps** first. This note is the *how*.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Reading a Token Record](#reading-a-token-record)
- [Triaging a Suspicious App](#triaging-a-suspicious-app)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Retention | Best for |
|--------|--------------|-----------|----------|
| **Token audit log** | Authorize/revoke/activity per app | ~6 months | The grants |
| **Reports API** (`applicationName=token`) | Same, scriptable | ~6 months | Bulk pulls |
| **Apps with access to Workspace data** | Current grants + scopes + user counts | Live | Rogue-app hunt |
| **Domain-wide delegation list** | SAs authorized to impersonate users | Live | 🔴 The bridge |
| **BigQuery export** | Token events, SQL | Your retention | Hunting |

## Collect It

**Console:** Admin console → **Reporting → Audit → Token log events** → filter by app / scope / user.

**API (Admin SDK Reports):**

```bash
# All OAuth authorizations in a window
GET .../activity/users/all/applications/token?eventName=authorize \
  &startTime=2026-06-01T00:00:00Z

# Grants for a specific (suspicious) client_id
  ...&filters=client_id==<CLIENT_ID>
```

**Current state:** Admin console → **Security → API controls → Apps with access to Workspace data** (review scopes + how many users) and **Domain-wide delegation** (client IDs + scopes).

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Identify the app | `client_id` + `app_name` from the Token log |
| 2. Read the scopes | 🔴 Broad mail/Drive/directory scopes = high risk |
| 3. Scope the blast radius | How many users authorized it? Which data can it reach? |
| 4. Judge legitimacy | Unknown developer, odd name, recent first-seen, phishing lure? |
| 5. Tie to the intrusion | Did the grant follow a suspicious login / phishing campaign? |

## Reading a Token Record

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `actor.email` | Who consented | Many users → campaign |
| `event.name` | `authorize` / `revoke` / `activity` | New `authorize` |
| `client_id` | Which app | Unknown / attacker-controlled |
| `app_name` | Display name | Lookalike / generic |
| `scope` | What it can do | 🔴 `mail.google.com`, `drive`, `admin.directory` |

## Triaging a Suspicious App

| Signal | Weight |
|--------|--------|
| Requests **full mailbox** (`https://mail.google.com/`) or all-Drive scope | 🔴 High |
| **New/unknown** developer or client ID, first seen recently | 🔴 High |
| Consented by **many users in a short window** | 🔴 Campaign |
| Grant **right after** a phishing email / suspicious login | 🔴 High |
| Name mimics a known SaaS ("Google Security", "Docs Viewer") | 🔴 High |

## Hunt at Scale

**BigQuery (Token logs) — new authorizations to broad scopes:**

```sql
SELECT time_usec, actor.email, p_app.value AS app, p_scope.value AS scope
FROM `contoso.workspace_logs.token`,
     UNNEST(event.parameter) p_app, UNNEST(event.parameter) p_scope
WHERE event.name='authorize'
  AND p_app.name='app_name' AND p_scope.name='scope'
  AND p_scope.value LIKE '%mail.google.com%';
```

**One app, many users (mass-consent campaign):**

```sql
SELECT p.value AS client_id, COUNT(DISTINCT actor.email) AS users
FROM `contoso.workspace_logs.token`, UNNEST(event.parameter) p
WHERE event.name='authorize' AND p.name='client_id'
GROUP BY client_id HAVING users > 5 ORDER BY users DESC;
```

> **At the very end — SecOps UDM (optional):** land OAuth `authorize` events to correlate a rogue `client_id` across users/tenants. Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Kill the rogue app | **Block the app** (API controls) and **revoke its tokens** for all users |
| Per-user cleanup | Remove the app from each user's *Connected applications* |
| Kill a DWD backdoor | Remove the client ID from **Domain-wide delegation** |
| Contain the user | Reset password + sign out (tokens) if the account was also phished |
| Preserve | Export Token log for the window; record client ID + scopes |

```bash
# Revoke a rogue app's tokens across the domain (Admin SDK / GAM)
gam all users deprovision  # per-user token revoke; or block via API controls console
```

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Block unconfigured apps** by default | No silent third-party access |
| **Restrict user consent** to trusted apps / limited scopes | One phish click can't grant mail access |
| **Review the DWD list** quarterly; remove unused client IDs | Closes the Workspace↔GCP bridge |
| **Alert** on new grants to broad scopes + mass-consent bursts | Catch illicit grants early |
| **App allowlisting** for high-risk scopes (`mail`, `drive`, `directory`) | Limits blast radius |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| New grant of `https://mail.google.com/` or all-Drive to an unknown app | Illicit consent — mail/file theft |
| One `client_id` consented by many users quickly | Mass-consent phishing campaign |
| New client ID in **Domain-wide delegation** | SA granted a Workspace-wide key |
| App grant right after a suspicious login | Attacker persistence via token |
| App requesting `admin.directory` / `cloud-platform` | Recon / GCP bridge |
| App name mimicking a Google/SaaS product | Social-engineering lure |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The OAuth model + scopes + DWD | **OAuth & Third-Party Apps → What is** |
| SAs + domain-wide delegation (identity side) | **Google → 01 Google Identities** |
| The admin event authorizing a DWD client | **Workspace → Admin Audit Log** |
| Illicit-grant intrusion end to end | **Workspace → Playbooks → Illicit OAuth Grant** |
| The data an app can read | **Workspace → Gmail** · **Drive & Docs Audit** |

## Resources

- Token audit log — https://support.google.com/a/answer/6124308
- Manage third-party app access — https://support.google.com/a/answer/7281227
- Revoke access to third-party apps — https://support.google.com/a/answer/9050643
- Domain-wide delegation — https://support.google.com/a/answer/162106
- MITRE ATT&CK: T1528 Steal Application Access Token / T1550.001 Application Access Token — https://attack.mitre.org/techniques/T1528/
