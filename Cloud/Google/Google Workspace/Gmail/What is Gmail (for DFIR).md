# What is Gmail (for DFIR)?

**Gmail** is Workspace's email service — and the #1 target of Workspace attacks: business email compromise, mail exfil via forwarding/filters, and payment fraud. Investigating it means knowing **two evidence sources** (delivery logs vs. content) and one crucial gap: **mailbox persistence (filters, forwarding, delegation) is not in the audit log — you pull it from the account's Gmail settings.**

## Contents

- [How It Works](#how-it-works)
- [The Two Evidence Sources](#the-two-evidence-sources)
- [Mailbox Persistence Lives in Settings, Not Logs](#mailbox-persistence-lives-in-settings-not-logs)
- [How to Identify Gmail Evidence](#how-to-identify-gmail-evidence)
- [Common Attacker Actions](#common-attacker-actions)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

A user's mailbox has **content** (messages), **settings** (filters, forwarding, delegation, signatures), and it generates **delivery events** as mail flows. Each is investigated differently:

```
Mailbox
├── Content        → Security Investigation Tool (content search) / eDiscovery (Vault)
├── Settings       → Gmail API (users.settings.*) — filters, forwarding, delegates
└── Delivery flow  → Email Log Search + Gmail logs in BigQuery
```

- **Filters and forwarding are per-user Gmail settings.** A compromised user (or an attacker with delegated/DWD access) sets them to hide and exfil mail.
- 🔴 The classic BEC persistence — a filter that forwards finance mail out and deletes the copy — leaves **little to no audit-log trace**; you find it by **reading the settings**.

## The Two Evidence Sources

| Source | What it gives you | Where |
|--------|-------------------|-------|
| **Email Log Search (ELS)** | Message metadata + delivery: sender, recipient, subject, message-ID, delivery status, post-delivery actions | Admin console → Reporting → Email Log Search |
| **Gmail logs in BigQuery** | Richer, queryable message events (delivery, spam, encryption) | Admin console → enable Gmail logs → BigQuery |
| **Security Investigation Tool (SIT)** | Search **content**, and bulk-act (delete, quarantine) | Admin console → Security → Investigation tool |
| **Vault (eDiscovery)** | Hold + export mailbox content for legal | vault.google.com |

## Mailbox Persistence Lives in Settings, Not Logs

🔴 This is the single most important Gmail-DFIR fact. To find attacker persistence, **read the mailbox's settings via the Gmail API** (the Google equivalent of `Get-InboxRule`):

```bash
# Filters (the "inbox rules")
GET https://gmail.googleapis.com/gmail/v1/users/{user}/settings/filters

# Forwarding addresses + whether auto-forwarding is ON
GET .../settings/forwardingAddresses
GET .../settings/autoForwarding

# Mailbox delegation (someone else can read this mailbox)
GET .../settings/delegates

# "Send mail as" aliases (spoof-from setup)
GET .../settings/sendAs
```

> Practitioners commonly use **GAM/GAMADV** (`gam user <u> show filters forwards delegates sendas`) as a fast CLI over these same APIs. Either way: **you cannot rely on the audit log for filters/forwarding** — go to the settings.

## How to Identify Gmail Evidence

- **ELS:** Admin console → **Reporting → Email Log Search** (search by sender/recipient/subject/message-ID).
- **Gmail logs:** enable in Admin console → routed to **BigQuery** (`gmail_logs` dataset).
- **Settings/persistence:** **Gmail API** `users.settings.*` (filters, forwarding, delegates, sendAs).
- **Content:** **Security Investigation Tool** or **Vault**.

## Common Attacker Actions

| Action | Where you find it | 🔴 |
|--------|-------------------|----|
| Filter that forwards + deletes finance mail | Gmail API `settings/filters` | BEC persistence |
| Auto-forwarding to an external address | `settings/autoForwarding` + `forwardingAddresses` | Silent exfil |
| Mailbox delegation to attacker account | `settings/delegates` | Persistent read access |
| `sendAs` alias impersonating an exec | `settings/sendAs` | Spoofed fraud mail |
| Fraudulent sends / replies | ELS + SIT content | Payment fraud |
| Mass deletion (cover tracks) | SIT / Vault | Anti-forensics |

## Cross-Provider Equivalent

| Google Workspace | AWS | Microsoft |
|------------------|-----|-----------|
| Gmail | (WorkMail / SES) | Exchange Online |
| Gmail filter + forwarding | — | Inbox rule + forwarding |
| Email Log Search | — | Message trace |
| Mailbox delegation | — | `Add-MailboxPermission` |
| Vault (eDiscovery) | — | Purview eDiscovery / litigation hold |
| Security Investigation Tool | — | Defender / Content search |

## Common Use Cases

Your "normal" baseline: everyday mail; **legitimate filters** (foldering newsletters); **legit forwarding** (a shared/role mailbox); **delegation** (an exec's assistant). The job is to separate benign settings from attacker persistence — check *who* set it and *when*, against the takeover timeline.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Filter** | A Gmail rule (the "inbox rule") — condition → action |
| **Auto-forwarding** | Sending a copy of incoming mail elsewhere |
| **Delegation** | Granting another account access to a mailbox |
| **sendAs** | An alias you can send mail "from" |
| **Email Log Search (ELS)** | Message-delivery metadata search |
| **Security Investigation Tool (SIT)** | Content search + bulk remediation |
| **Vault** | Workspace eDiscovery / legal hold |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating a Gmail compromise | **Gmail → Gmail for DFIR** |
| The takeover sign-in | **Workspace → Login & Auth Audit** |
| Who the identity is | **Google → 01 Google Identities** |
| BEC end to end | **Workspace → Playbooks → BEC and Mail Forwarding** |
| An app reading all mail | **Workspace → OAuth & Third-Party Apps** |

## Resources

- Email Log Search — https://support.google.com/a/answer/2604578
- Gmail logs in BigQuery — https://support.google.com/a/answer/7233312
- Gmail API settings (filters/forwarding/delegates) — https://developers.google.com/gmail/api/reference/rest/v1/users.settings
- Security Investigation Tool — https://support.google.com/a/answer/7575955
