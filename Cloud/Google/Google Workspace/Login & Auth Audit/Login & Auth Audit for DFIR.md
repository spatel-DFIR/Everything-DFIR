# Login & Auth Audit for DFIR

The Login audit is the **anchor of the first hour**. It tells you the takeover sign-in — the new IP, the missing 2SV, the legacy-protocol login, the suspicious-login verdict — that starts almost every Google intrusion.

New to it? Read **What is the Login & Auth Audit** first. This note is the *how*.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Reading a Login Record](#reading-a-login-record)
- [Spotting the Takeover Sign-in](#spotting-the-takeover-sign-in)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Retention | Best for |
|--------|--------------|-----------|----------|
| **Admin console → Audit → Login** | All login events | ~6 months | Fast first look |
| **Reports API** (`applicationName=login`) | Same, scriptable | ~6 months | Bulk pulls |
| **BigQuery export** (if enabled) | Same, SQL | Your retention | Hunting + long retention |
| **Security Investigation Tool** | Cross-log + bulk actions (suspend, sign-out) | — | Correlate + remediate |

**In SecOps (optional):** actor → `principal.user.email_addresses`, IP → `principal.ip`, verdict → security result fields.

## Collect It

**Console:** Admin console → **Reporting → Audit and investigation → Login events** → filter (user, IP, event) → **Export**.

**API (Admin SDK Reports):**

```bash
# All logins for a user in a window
GET .../activity/users/alice@contoso.com/applications/login \
  ?startTime=2026-06-01T00:00:00Z&endTime=2026-07-11T00:00:00Z

# Just the suspicious ones, org-wide
GET .../activity/users/all/applications/login?eventName=suspicious_login
```

> Also pull the account's **current auth posture**: is 2SV enrolled? Are recovery email/phone changed? (Admin console → Users → security.) A disabled 2SV or swapped recovery contact is persistence.

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Confirm coverage | Login logging is always on; note retention + any BigQuery export |
| 2. Build the sign-in timeline | Every login for the user; note IP, geo, ASN, login type, 2SV result |
| 3. Find the anomaly | New ASN/country; legacy/less-secure login; `suspicious_login`; impossible travel |
| 4. Establish the takeover moment | The first bad login → everything after it is suspect |
| 5. Pivot to activity | From that session's IP, follow into Admin/Gmail/Drive and Cloud Audit Logs |

## Reading a Login Record

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `actor.email` | **Who** | The account |
| `ipAddress` | **From where** | New ASN/country; Tor/VPN/hosting |
| `events[].name` | **What** | `login_success` / `failure` / `suspicious_login` |
| `login_type` | **How** | 🔴 `exchange` / less-secure = MFA-bypassing |
| `is_suspicious` | Google's verdict | 🔴 `true` |
| `login_challenge_method` | 2SV method used | 🔴 none, on a sensitive account |

## Spotting the Takeover Sign-in

| Signal | Why it matters |
|--------|----------------|
| **New country/ASN** then immediate activity | Geo anomaly → takeover |
| **Impossible travel** (two far-apart logins in minutes) | Two actors on one account |
| **Legacy/less-secure login** (`exchange`, IMAP/POP) | 🔴 Password-only, **2SV bypassed** |
| **`suspicious_login`** verdict | Google's ML flagged it |
| **2SV disabled** just before/after a login | Persistence — attacker removing MFA |
| **Recovery email/phone changed** | Account-recovery hijack |
| **`account_disabled_password_leak`** | Credentials were in a breach |

> 🔴 If the user **federates via an IdP** (`login_type=saml`), the *real* authentication happened at the IdP — a Google `login_success` may hide a compromised IdP session. Pivot to the IdP (Okta/Ping/Entra) sign-in logs.

## Hunt at Scale

**BigQuery — suspicious logins:**

```sql
SELECT time_usec, actor.email, network.ip_address, event.name
FROM `contoso.workspace_logs.activity`
WHERE event.name = 'suspicious_login'
ORDER BY time_usec DESC;
```

**Password spray (many users, many failures, few IPs):**

```sql
SELECT network.ip_address, COUNT(DISTINCT actor.email) AS users, COUNT(*) AS attempts
FROM `contoso.workspace_logs.activity`
WHERE event.name = 'login_failure'
GROUP BY network.ip_address
HAVING users > 20
ORDER BY users DESC;
```

**Legacy / less-secure logins:**

```sql
SELECT time_usec, actor.email, network.ip_address
FROM `contoso.workspace_logs.activity`, UNNEST(event.parameter) p
WHERE event.name = 'login_success' AND p.name='login_type' AND p.value IN ('exchange');
```

> **At the very end — SecOps UDM (optional):** land suspicious-login + spray events to answer "did this IP hit other users/tenants?" Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Cut the session | **Reset password + "Sign out" everywhere** (revokes tokens) — Admin console → Users → (user) |
| Restore MFA | Re-enroll 2SV; fix swapped recovery email/phone |
| Kill lingering access | Remove **OAuth app grants** (attacker refresh tokens) — see OAuth note |
| Block the channel | Disable less-secure-app access; block the source IP range if hostile |
| Preserve | Export the login timeline + any BigQuery copy |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enforce 2SV** (phishing-resistant keys for admins/execs) | Stops phish/spray takeover |
| **Disable less-secure apps / legacy protocols** | Removes the 2SV-bypass channel |
| **Context-Aware Access** (device/geo conditions) | Blocks logins from untrusted context |
| **Turn on suspicious-login + leaked-password alerts** | Early detection |
| **Export login logs → BigQuery** | Beats ~6-month retention + enables hunting |
| **Enrolled-devices only** for mobile/sync | Kills rogue-device access |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `suspicious_login` / `is_suspicious=true` | Google flagged an anomaly |
| Legacy/less-secure (`exchange`, IMAP/POP) login | 2SV bypass |
| New ASN/country then admin or Drive activity | Takeover in progress |
| Impossible travel | Two actors, one account |
| `2sv_disable` / recovery contact change | Persistence / recovery hijack |
| Burst of `login_failure` across many users | Password spray |
| `account_disabled_password_leak`/`_hijacked` | Confirmed credential compromise |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What the login events mean | **Login & Auth Audit → What is** |
| Who the identity is | **Google → 01 Google Identities** |
| Admin changes made in the session | **Workspace → Admin Audit Log** |
| Mail / Drive actions after takeover | **Workspace → Gmail** · **Drive & Docs Audit** |
| Attacker OAuth persistence | **Workspace → OAuth & Third-Party Apps** |
| A full takeover | **Workspace → Playbooks → Account Takeover** |

## Resources

- Login audit log — https://support.google.com/a/answer/4580120
- Investigate suspicious activity — https://support.google.com/a/answer/7102416
- Context-Aware Access — https://support.google.com/a/answer/9275380
- 2-Step Verification enforcement — https://support.google.com/a/answer/9176657
- MITRE ATT&CK: T1078 Valid Accounts / T1110 Brute Force — https://attack.mitre.org/techniques/T1078/
