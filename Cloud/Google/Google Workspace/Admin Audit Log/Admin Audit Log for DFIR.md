# Admin Audit Log for DFIR

The Admin audit log is where you find **who changed the org** — new admins, disabled MFA, authorized API clients, mail-routing changes. In almost every Workspace intrusion it holds the persistence and privilege-escalation events.

New to it? Read **What is the Admin Audit Log** first. This note is the *how*.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Reading an Admin Record](#reading-an-admin-record)
- [What to Look For, by Phase](#what-to-look-for-by-phase)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Retention | Best for |
|--------|--------------|-----------|----------|
| **Admin console → Audit and investigation** | All admin events | ~6 months | Fast first look |
| **Reports API** (`applicationName=admin`) | Same, scriptable | ~6 months | Bulk pulls / automation |
| **BigQuery export** (if enabled) | Same, SQL | Your retention | Hunting + long retention |
| **Security Investigation Tool** (Enterprise) | Cross-log search + actions | — | Correlate + remediate |

**In SecOps (optional):** lands as Workspace activity; actor → `principal.user.email_addresses`, event → `metadata.product_event_type`.

## Collect It

**Console:** Admin console → **Reporting → Audit and investigation → Admin log events** → filter by event/actor/date → **Export** (to Sheets/BigQuery).

**API (Admin SDK Reports):**

```bash
# All admin events by an actor in a window
GET https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin \
  ?actorEmail=admin@contoso.com&startTime=2026-06-01T00:00:00Z&endTime=2026-07-11T00:00:00Z

# Target the high-value events (eventName filter)
  ...&eventName=GRANT_ADMIN_PRIVILEGE
  ...&eventName=AUTHORIZE_API_CLIENT_ACCESS
```

> Practitioners often use **GAM/GAMADV** (`gam report admin`) as a fast CLI over the Reports API. Console + Reports API are the primary/native path.

**ALFA (analysis layer, on top of a Reports API pull):** GAM gets the raw records out; **ALFA** (FOR509's standard open-source Workspace forensic tool) is what you point at them afterward. `alfa acquire` pulls Reports API activity itself (so it can stand in for the GAM/API pull above), but its real value is analysis: it loads events into an `A.activities`/`A.events` object model you can filter, pivot, and re-query in Python instead of hand-parsing JSON. It ships **subchains** — pre-built queries that map raw admin/login/token events onto MITRE ATT&CK kill-chain stages — and a curated **"activities of interest"** list that flags the same high-value events this file's phase table calls out (`GRANT_ADMIN_PRIVILEGE`, `AUTHORIZE_API_CLIENT_ACCESS`, 2SV toggles) without you having to hand-write the filter each time. Treat it as the post-acquisition analysis step, not a replacement for the GAM/Reports API collection above — acquire with GAM or `alfa acquire`, then analyze with ALFA once you have events across multiple logs (admin + login + token) and need to correlate them into a single kill-chain view.

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Confirm coverage | Admin logging is always on; note retention + whether a BigQuery export exists for older events |
| 2. Scope the actor | Full admin timeline for the suspect admin; note IP + which events |
| 3. Classify each event | Bucket into phases (table below) |
| 4. Tie to a sign-in | Cross the actor's IP with the **Login audit** for the session behind the change |
| 5. Split human vs API | Console action (browser) vs Admin-SDK call (a script/SA) |

## Reading an Admin Record

| Field | Answers | Notes |
|-------|---------|-------|
| `actor.email` | **Who** | The admin who acted (or an API caller) |
| `id.time` | **When** | Event timestamp |
| `events[].name` | **What** | `GRANT_ADMIN_PRIVILEGE`, `AUTHORIZE_API_CLIENT_ACCESS`… |
| `events[].parameters` | **The detail** | Target user, role name, old/new value, client ID + scopes |
| `ipAddress` | **From where** | Correlate with the Login audit |

> The gold is in `parameters`: the **target user**, the **role granted**, the **API client ID + scopes** for a DWD grant. Always expand it.

## What to Look For, by Phase

| Phase | Telltale events |
|-------|-----------------|
| **Privilege escalation** | `GRANT_ADMIN_PRIVILEGE`, `ASSIGN_ROLE` (privileged), `ADD_GROUP_MEMBER` to an admin group |
| **Persistence** | `CREATE_USER` (backdoor), `AUTHORIZE_API_CLIENT_ACCESS` (DWD), `CREATE_ROLE` with broad scopes |
| **Defense evasion** | `TOGGLE_2SV`/`UNENROLL_USER_FROM_STRONG_AUTHENTICATION`, disabling `ENFORCE_STRONG_AUTHENTICATION`, disabling logging/alerts |
| **Account takeover** | `RESET_PASSWORD`/`CHANGE_PASSWORD` on another user; recovery email/phone change |
| **Exfil setup** | Org-level auto-forwarding / mail routing; external sharing enabled; trusted-domain change |
| **Federation backdoor** | SSO/SAML profile change; new trusted domain |

🔴 A `RESET_PASSWORD` on an executive + a `TOGGLE_2SV` to off, minutes apart, is a takeover-of-another-user in progress.

## Hunt at Scale

**BigQuery (Workspace logs export) — new admin grants:**

```sql
SELECT time_usec, actor.email, event.name, event.parameter
FROM `contoso.workspace_logs.activity`
WHERE event.name IN ('GRANT_ADMIN_PRIVILEGE','GRANT_DELEGATED_ADMIN_PRIVILEGE')
ORDER BY time_usec DESC;
```

**Domain-wide delegation authorized (the Workspace↔GCP bridge):**

```sql
SELECT time_usec, actor.email, param
FROM `contoso.workspace_logs.activity`, UNNEST(event.parameter) AS param
WHERE event.name = 'AUTHORIZE_API_CLIENT_ACCESS';   -- inspect client_id + scopes
```

**2SV weakened:**

```sql
SELECT time_usec, actor.email, event.name
FROM `contoso.workspace_logs.activity`
WHERE event.name IN ('TOGGLE_2SV','UNENROLL_USER_FROM_STRONG_AUTHENTICATION','ENFORCE_STRONG_AUTHENTICATION');
```

> **At the very end — SecOps UDM (optional):** land admin-privilege and DWD-grant events to answer "did this admin/IP appear elsewhere?" Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Reverse a rogue admin grant | Remove the admin role; review what they touched |
| Kill a DWD backdoor | Remove the authorized API client (Admin console → Security → API controls → Domain-wide delegation) |
| Re-secure a reset account | Reset password + sign out everywhere + re-enroll 2SV |
| Re-enable protections | Turn 2SV enforcement back on; restore mail-routing settings |
| Preserve | Export the Admin log for the window (and any BigQuery copy) |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enforce 2SV** (phishing-resistant for admins) org-wide | Kills spray/phish takeover of admins |
| **Minimize Super Admins**; use scoped roles + PIM-style just-in-time | Small blast radius |
| **Export logs to BigQuery** (long retention) | Beats the ~6-month limit + enables hunting |
| **Alert** on `GRANT_ADMIN_PRIVILEGE`, `AUTHORIZE_API_CLIENT_ACCESS`, 2SV changes | Catch privesc/persistence early |
| **Restrict API-client authorization** + review DWD list quarterly | Closes the Workspace↔GCP bridge |
| **Require admin approval for Marketplace apps** | No rogue app self-install |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| New `GRANT_ADMIN_PRIVILEGE` (esp. to a fresh/low-profile account) | Privilege escalation |
| `AUTHORIZE_API_CLIENT_ACCESS` (new DWD client) | SA granted a Workspace-wide mailbox/Drive key |
| `TOGGLE_2SV` off / MFA enforcement disabled | Defense evasion / persistence |
| `RESET_PASSWORD` on an exec/admin by an unexpected actor | Account takeover |
| Org-level auto-forwarding / mail routing added | Silent org-wide mail exfil |
| New trusted domain / SSO profile change | Federation backdoor |
| Admin action from a new IP/geo/ASN | Compromised admin session |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What the Admin log is + events | **Admin Audit Log → What is** |
| Who the admin/identity is | **Google → 01 Google Identities** |
| The sign-in behind the change | **Workspace → Login & Auth Audit** |
| DWD / OAuth client abuse | **Workspace → OAuth & Third-Party Apps** |
| GCP-side privilege escalation | **GCP → Cloud IAM** |
| A privileged-role takeover end to end | **Workspace → Playbooks → Account Takeover** |

## Resources

- Admin audit log — https://support.google.com/a/answer/4579579
- Reports API events (admin) — https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list/admin-event-names
- Export Workspace logs to BigQuery — https://support.google.com/a/answer/9079365
- Security best practices — https://support.google.com/a/answer/7587183
- MITRE ATT&CK: T1098 Account Manipulation / T1136 Create Account — https://attack.mitre.org/techniques/T1098/
