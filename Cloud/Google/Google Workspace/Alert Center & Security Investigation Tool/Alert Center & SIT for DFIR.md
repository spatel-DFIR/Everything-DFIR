# Alert Center & SIT for DFIR

The Alert Center is often where a Workspace case **starts**; the Security Investigation Tool is how you **scope and contain** it — cross-log hunting plus one-click bulk remediation.

New to it? Read **What is Alert Center & the SIT** first. This note is the *how*.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Investigation Tool vs Reports API](#investigation-tool-vs-reports-api)
- [Triage an Alert](#triage-an-alert)
- [Hunt with the Investigation Tool](#hunt-with-the-investigation-tool)
- [Bulk Containment Actions](#bulk-containment-actions)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Best for |
|--------|--------------|----------|
| **Alert Center** | Google + rule alerts, with linked evidence | Triage entry point |
| **Alert Center API** | Alerts programmatically | SOAR/automation |
| **Investigation Tool** | Cross-log query results | Scoping + hunting |
| **SIT action log** | Who ran which bulk action | Chain of custody |

## Triage an Alert

| Step | Do this |
|------|---------|
| 1. Read the alert | Type, affected users, timestamp, linked evidence |
| 2. Confirm scope | One user or many? One IP/app/sender? |
| 3. Pivot to the source log | Suspicious login → Login audit; phishing → Gmail; DLP → Drive |
| 4. Decide severity | Gov-backed / leaked-password / admin-targeted = escalate |
| 5. Contain | Use the SIT bulk actions (below) |

## Hunt with the Investigation Tool

Pick a **data source**, add conditions, run, then act. Common hunts:

| Hunt | Data source + condition |
|------|-------------------------|
| **Phishing spread** | Gmail messages · `from` = attacker sender / subject / attachment hash |
| **Who clicked / got the mail** | Gmail log events · message-ID → recipients |
| **Mass download** | Drive log events · `event = download`, group by actor |
| **Rogue app grants** | OAuth token log · `event = authorize`, `client_id =` suspect |
| **Takeover logins** | User/Login log events · `is_suspicious = true` / new IP |

> 🔴 The workflow that wins: **find the phishing sender in Gmail messages → select all → Delete from every mailbox → then suspend anyone who replied/clicked and revoke tokens.** One console, minutes.

## Bulk Containment Actions

| Action | Effect |
|--------|--------|
| **Delete message** (Gmail) | Purge phishing from all mailboxes |
| **Suspend user** | Freeze a compromised account |
| **Reset password / sign out** | Kill sessions/tokens in bulk |
| **Revoke OAuth tokens** | Cut app persistence |
| **Mark phishing/spam** | Reclassify delivered mail |

## Respond

| Goal | Action |
|------|--------|
| Purge a phishing campaign | SIT → find by sender/subject → **Delete** across mailboxes |
| Contain compromised users | SIT → **Suspend** + **Sign out** in bulk |
| Kill app persistence | SIT → **Revoke tokens** for the rogue app |
| Preserve | Export SIT results + note the action log (who did what) |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Turn on all relevant Alert Center rules** + route to a queue | Nothing missed |
| **Activity rules** (auto-actions on conditions) | Faster containment |
| **Grant SIT access** to responders (least privilege) | Response capability without over-granting |
| **Integrate Alert Center API → SIEM/SOAR** | Central triage + automation |
| **Enable underlying logs** (Drive/Gmail/BigQuery) | The SIT can only search what's logged |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Government-backed attack alert | State-actor targeting |
| Leaked-password alert on an admin/exec | Imminent takeover |
| Phishing alert with many recipients | Active campaign |
| Suspicious-login cluster from one IP/ASN | Spray / takeover wave |
| DLP alert on bulk external sharing | Exfil |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The tools + what alerts exist | **Alert Center & SIT → What is** |
| The login behind a suspicious-login alert | **Workspace → Login & Auth Audit** |
| Purging phishing / mail hunts | **Workspace → Gmail** |
| Rogue OAuth apps | **Workspace → OAuth & Third-Party Apps** |
| GCP-side detection | **GCP → Security Command Center** |

## Resources

- Alert Center — https://support.google.com/a/answer/9105393
- Investigation Tool: take action — https://support.google.com/a/answer/9300653
- Activity rules — https://support.google.com/a/answer/9275024
- Alert Center API — https://developers.google.com/admin-sdk/alertcenter
- MITRE ATT&CK Cloud (Google Workspace) — https://attack.mitre.org/matrices/enterprise/cloud/
