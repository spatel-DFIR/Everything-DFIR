# What is Alert Center & the Security Investigation Tool?

Workspace's built-in detection and response lives in three places: the **Alert Center** (Google's alerts — suspicious logins, leaked passwords, phishing, government-backed attacks), the **Security dashboard** (posture views), and the **Security Investigation Tool (SIT)** (cross-log search + bulk remediation). Together they are the Workspace equivalent of a managed detection console.

## Contents

- [How It Works](#how-it-works)
- [Alert Center — What It Surfaces](#alert-center--what-it-surfaces)
- [The Security Investigation Tool](#the-security-investigation-tool)
- [How to Identify It in Evidence](#how-to-identify-it-in-evidence)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
Google detections + admin rules
   ├── Alert Center     → alerts (suspicious login, leaked password, phishing, gov-backed attack, DLP…)
   ├── Security dashboard → aggregate posture (spam, sharing, OAuth, device trends)
   └── Investigation Tool → search across Gmail/Drive/Devices/Users + BULK ACTIONS
```

- The **Alert Center** is the triage inbox — each alert links to the evidence and (often) a suggested action.
- The **SIT** is the hunting + response console: query conditions across logs, then **act in bulk** (delete a phishing message from all mailboxes, suspend users, revoke tokens).
- Availability varies by edition (SIT needs Enterprise Plus / Education Plus / frontline).

## Alert Center — What It Surfaces

| Alert | Means | 🔴 |
|-------|-------|----|
| **Suspicious login** | Anomalous sign-in | Takeover |
| **Leaked password** | Credential found in a breach | Reset now |
| **Government-backed attack** | Google believes a state actor targeted a user | High-priority |
| **Phishing / malware (Gmail)** | Malicious mail delivered | Purge + hunt |
| **Suspicious device activity** | Compromised/abnormal device | Device IR |
| **Data loss prevention (DLP)** | Sensitive-data rule triggered | Exfil |
| **User-reported phishing** | A user reported a message | Investigate + purge |
| **AppSheet / third-party app** | Risky app activity | Rogue app |

## The Security Investigation Tool

The SIT queries **data sources** (Gmail log events, Gmail messages, Drive log events, Device log events, User log events, OAuth token log) with conditions, then lets you **take action on the results**:

| Action | Use |
|--------|-----|
| **Delete / restore message** | Purge phishing from every mailbox |
| **Mark as phishing/spam** | Reclassify delivered mail |
| **Suspend user** | Contain a compromised account |
| **Reset password / sign out** | Cut sessions in bulk |
| **Revoke OAuth tokens** | Kill app persistence |

> 🔴 The SIT's power is **cross-log correlation + one-click bulk remediation** — e.g. search all mailboxes for the phishing sender, then delete the message everywhere and suspend anyone who clicked. It's the fastest containment path in Workspace.

## How to Identify It in Evidence

- **Alert Center:** Admin console → **Security → Alert center**; **Alert Center API** for programmatic pull.
- **Security dashboard:** Admin console → **Security → Dashboard**.
- **SIT:** Admin console → **Security → Investigation tool** (searches + audited actions).
- SIT/alert actions are themselves **audited** (who ran what).

## Cross-Provider Equivalent

| Google Workspace | AWS | Microsoft |
|------------------|-----|-----------|
| Alert Center | GuardDuty / Security Hub findings | Defender alerts / XDR |
| Security dashboard | Security Hub summary | Secure Score / Defender dashboard |
| Security Investigation Tool | Detective + response | Defender Advanced Hunting + actions |
| Government-backed attack alert | — | Nation-state notification |

## Common Use Cases

Your "normal" baseline: analysts triage the Alert Center daily; the SIT is used to hunt a reported phish and purge it; the dashboard tracks sharing/OAuth/spam trends. On a case, the Alert Center is often *where the incident starts*, and the SIT is *how you scope and contain* it.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Alert Center** | Workspace's alert triage inbox |
| **Security dashboard** | Aggregate security posture views |
| **Security Investigation Tool (SIT)** | Cross-log search + bulk remediation |
| **Data source** | A log the SIT can query (Gmail, Drive, Devices…) |
| **Government-backed attack alert** | Google's state-actor targeting warning |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Using these tools in a case | **Alert Center & SIT → for DFIR** |
| The login alerts' source | **Workspace → Login & Auth Audit** |
| Purging phishing / mail hunts | **Workspace → Gmail** |
| Rogue OAuth apps | **Workspace → OAuth & Third-Party Apps** |
| GCP-side detection | **GCP → Security Command Center** |

## Resources

- Alert Center — https://support.google.com/a/answer/9105393
- Security Investigation Tool — https://support.google.com/a/answer/7575955
- Security dashboard — https://support.google.com/a/answer/7492330
- Alert Center API — https://developers.google.com/admin-sdk/alertcenter
