# Playbook — Illicit OAuth Grant

An attacker phishes a user into **authorizing a malicious OAuth app** with mail/Drive scopes. No password is stolen and MFA is never tripped — the app holds a **refresh token** and reads the victim's mail and files until the grant is revoked. This playbook finds the rogue app, scopes who consented, revokes it everywhere, and closes the consent path.

> **Tier 2 (cross-service).** Spans Login audit + Token log + Gmail/Drive. Read **Workspace → OAuth & Third-Party Apps** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Scope the Campaign](#scope-the-campaign)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **Token audit log** | New `authorize` to an unknown app with `mail`/`drive` scopes |
| **Alert Center** | Suspicious OAuth app / phishing alert |
| **User report** | "I clicked a Google permission screen from an email" |
| **Data exposure** | Mail/files accessed with no matching login |

## Hypothesis

A malicious app was consented by one or more users and is reading data via a refresh token. Identify the app (`client_id`), enumerate every user who consented, determine what it accessed, revoke it, and block the consent path.

## Step-by-Step Investigation

**1. Identify the app.** From the Token log: `client_id`, `app_name`, and the **scopes** granted.

```bash
GET .../activity/users/all/applications/token?eventName=authorize   # find the grant(s)
```

**2. Read the scopes.** 🔴 `https://mail.google.com/`, `gmail.readonly/modify`, `drive`, `admin.directory`, `cloud-platform` = high-impact.

**3. Tie to a lure.** Did the grant follow a phishing email (Gmail/SIT search for the sending domain/URL)?

**4. Determine access.** Token log `activity` events + Gmail/Drive audit for reads by the app during the exposure window.

## Scope the Campaign

| Question | Evidence |
|----------|----------|
| How many users consented? | Token log grouped by `client_id` |
| What data could it reach? | The union of scopes × those users' mailboxes/Drives |
| Is it in domain-wide delegation? | 🔴 Check the DWD list — if so, it can read *everyone* |
| Still active? | Recent `activity` events for the app |

## Decision Points

| Question | If yes → |
|----------|----------|
| Broad scopes (`mail`/`drive`/`directory`)? | Treat as data breach for affected users |
| Many users / DWD? | Campaign / tenant-wide — escalate |
| Also a suspicious login? | The account was phished too — run **Account Takeover** |
| App requests `cloud-platform`? | Check GCP access — possible bridge |

## Contain

- **Block the app** (Admin console → Security → API controls → app → **Block**).
- **Revoke its tokens** for every affected user (SIT bulk **Revoke OAuth tokens**, or per-user Connected applications).
- If in **Domain-wide delegation**, remove the client ID immediately.

## Eradicate

- Confirm no residual grants of the same `client_id` remain across users.
- Purge the phishing message from all mailboxes (SIT **Delete**).
- Reset credentials for any user who was *also* phished (not just the OAuth grant).
- Hunt for a second/backup app the attacker may have consented.

## Recover

- Set default to **block unconfigured apps**; restrict user consent to trusted apps + limited scopes.
- Alert on new grants to high-risk scopes + mass-consent bursts.
- Notify affected users; treat exposed mailboxes/files per data-breach policy.
- Preserve: Token log grants, scopes, the phishing lure, and any access evidence.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| New grant of `mail.google.com`/all-Drive to an unknown app | Illicit consent |
| One `client_id` consented by many users fast | Mass-consent phishing |
| Rogue client ID in domain-wide delegation | Tenant-wide silent access |
| App name mimicking a Google/SaaS product | Social-engineering lure |
| App `activity` reading mail/files with no user login | Token-based access |

## References

- Related notes: **OAuth & Third-Party Apps**, **Gmail for DFIR**, **Login & Auth Audit**, **Account Takeover**
- Revoke third-party app access — https://support.google.com/a/answer/9050643
- Control third-party app access — https://support.google.com/a/answer/7281227
- MITRE ATT&CK: T1528 Steal Application Access Token — https://attack.mitre.org/techniques/T1528/
