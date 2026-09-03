# Playbook — Account Takeover

An attacker gains control of a Workspace account — via **phishing, password spray, session-cookie/token theft (AiTM), or a leaked password**. Because one Google account opens both Workspace and GCP, a takeover is the root of most Google intrusions. This playbook establishes the entry, finds the persistence, cuts the session (tokens outlive passwords), and hunts for spread.

> **Tier 2 (cross-service).** Spans Login audit + Token log + Admin/Gmail/Drive. Read **Workspace → Login & Auth Audit** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Find the Persistence](#find-the-persistence)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **Alert Center** | Suspicious login / leaked password / gov-backed attack |
| **Login audit** | New ASN/country; legacy login; impossible travel |
| **User report** | "I entered my password on a page from an email" |
| **Downstream** | Mail rules / OAuth grant / Drive exfil with no known change |

## Hypothesis

An attacker controls the account and may have established persistence (tokens, OAuth grants, mail rules, MFA changes). Establish the entry method, cut every session/token, remove persistence, and determine what the account touched across Workspace and GCP.

## Step-by-Step Investigation

**1. Find the entry.** Login audit: the first bad sign-in — new IP/ASN, legacy/less-secure (`exchange`, IMAP/POP), `suspicious_login`, or impossible travel. Was it **password** (spray/phish) or a **token/cookie** (AiTM — a login that skips the 2SV challenge)?

**2. Establish the takeover window.** Everything after the first bad login is suspect.

**3. Check MFA & recovery.** Was 2SV disabled, a new method added, or the recovery email/phone changed? (Admin audit + user security page.)

**4. Follow the activity.** From the session IP, pivot into Admin/Gmail/Drive audit and — if the account has GCP access — **Cloud Audit Logs**.

## Find the Persistence

🔴 Cut all of these, not just the password:

| Persistence | Where |
|-------------|-------|
| **Refresh tokens / active sessions** | Reset password + "Sign out" everywhere |
| **OAuth app grants** | Connected applications / Token log |
| **Mail filters / forwarding / delegation** | Gmail settings (`gam show filters/forwards/delegates`) |
| **2SV method added / recovery contact changed** | User security page + Admin audit |
| **New app passwords** | User security page |
| **GCP footholds** (if the account had cloud access) | SA keys created, IAM grants — Cloud Audit Logs |

## Decision Points

| Question | If yes → |
|----------|----------|
| Token/cookie theft (AiTM), not password? | Revoking sessions is essential — password reset alone won't cut it |
| Admin account? | Check Admin audit for role/DWD grants (escalation); treat as tenant-level |
| Has GCP access? | Pivot to Cloud Audit Logs — run **Service Account Key Abuse** if SA keys were made |
| Many accounts hit? | Campaign — run **Password Spray**-style sweep across the org |

## Contain

```
1. Reset password AND "Sign out" everywhere        (Admin console → Users → user)  ← revokes tokens
2. Re-enroll 2SV; remove attacker-added methods; fix recovery email/phone
3. Revoke OAuth app grants (Connected applications / SIT bulk revoke)
4. Remove mail filters/forwarding/delegates the attacker set
```

## Eradicate

- Confirm no lingering sessions, OAuth grants, or mail persistence remain.
- If GCP access existed: delete any SA keys created, revoke impersonation grants, review IAM changes.
- Block the source IP range / disable less-secure apps if that was the channel.
- Hunt the same IP/ASN and lure across the org for other victims.

## Recover

- Re-enable with fresh creds + **phishing-resistant 2SV** (security keys).
- Enforce 2SV org-wide; disable legacy/less-secure apps; enable Context-Aware Access.
- Alert on suspicious logins, new OAuth grants, mail-rule changes.
- Preserve: login timeline, persistence snapshot, and downstream activity.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| Login skipping 2SV / MFA "already satisfied" from a new device | Token/cookie theft (AiTM) |
| Legacy/less-secure login | 2SV bypass |
| 2SV disabled / recovery contact changed | Persistence / recovery hijack |
| New OAuth grant or mail rule after the login | Attacker persistence |
| SA keys / IAM grants by the account (GCP) | Bridge into infrastructure |
| Burst of logins across many users from one IP | Spray campaign |

## References

- Related notes: **Login & Auth Audit**, **OAuth & Third-Party Apps**, **Gmail for DFIR**, **Service Account Key Abuse** (GCP)
- Respond to a compromised account — https://support.google.com/a/answer/2984349
- Security checklist for admins — https://support.google.com/a/answer/7587183
- MITRE ATT&CK: T1078 Valid Accounts / T1110 Brute Force / T1539 Steal Web Session Cookie — https://attack.mitre.org/techniques/T1078/
