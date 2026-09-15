# Gmail for DFIR

Gmail investigations are BEC investigations: find the takeover, find the **mailbox persistence** (filters/forwarding/delegation) that the audit log won't show you, quantify the fraud, and lock it down.

New to it? Read **What is Gmail (for DFIR)** first. This note is the *how*.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Finding Mailbox Persistence](#finding-mailbox-persistence)
- [Quantify the Exposure](#quantify-the-exposure)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Retention | Best for |
|--------|--------------|-----------|----------|
| **Email Log Search** | Delivery metadata (who→who, subject, status) | 30 days | The sends/receives |
| **Gmail logs (BigQuery)** | Richer message events | Your retention | Hunting |
| **Gmail API `settings.*`** | Filters, forwarding, delegates, sendAs | Live state | 🔴 Persistence |
| **Security Investigation Tool / Vault** | Content search + hold/export | — / hold | Prove reads + preserve |

## Collect It

**1. Snapshot mailbox persistence (do this the moment you suspect compromise):**

```bash
# The Google "Get-InboxRule": pull filters, forwarding, delegates, sendAs
gam user victim@contoso.com show filters
gam user victim@contoso.com show forwards
gam user victim@contoso.com show delegates
gam user victim@contoso.com show sendas
# (equivalently: Gmail API users.settings.filters/forwardingAddresses/autoForwarding/delegates/sendAs)
```

**2. Pull the delivery trail (Email Log Search):** Admin console → **Reporting → Email Log Search** → by sender `victim@contoso.com` and date window → note external recipients + subjects.

**3. Preserve content:** put the mailbox on **Vault hold** before anything is deleted.

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Anchor the takeover | Cross the **Login audit** for the first bad sign-in / token |
| 2. Snapshot persistence | Filters, forwarding, delegates, sendAs (above) — *the audit log won't show these* |
| 3. Find the sends | ELS / SIT: fraudulent or external sends from the mailbox |
| 4. Map contacts | Every external recipient of fraud mail — to warn out of band |
| 5. Prove reads | SIT content search / Vault — which threads (invoices, banking) were opened |

## Finding Mailbox Persistence

🔴 The BEC signature — a filter that quietly moves and forwards finance mail:

| Setting | What malicious looks like |
|---------|---------------------------|
| **Filter** | Matches `invoice`/`payment`/`wire` → forward to external + mark read + archive/delete |
| **Auto-forwarding** | ON, to an external/lookalike domain |
| **Delegate** | An attacker (or lookalike) account granted mailbox access |
| **sendAs** | An alias set to send as the CEO/CFO |

> Compare *every* setting against "was this here before the takeover?" A benign-looking forward set **the same hour** as the suspicious login is the attacker's.

## Quantify the Exposure

| Question | Evidence |
|----------|----------|
| What was forwarded/sent, to whom? | ELS + filter target + sendAs |
| Were payment details changed in replies? | SIT / Vault content |
| Which internal threads were read? | SIT content search (limited without content logging) |
| Did money move? | Coordinate with finance/bank immediately |

## Hunt at Scale

**BigQuery (Gmail logs) — external forwarding volume by user:**

```sql
SELECT message_info.source.address AS sender,
       message_info.destination.address AS recipient, COUNT(*) c
FROM `contoso.gmail_logs.daily_YYYYMMDD`
WHERE message_info.destination.address NOT LIKE '%@contoso.com'
GROUP BY sender, recipient
HAVING c > 50
ORDER BY c DESC;
```

> **Filters/forwarding settings are per-mailbox, not in BigQuery.** For a tenant-wide sweep, script the **Gmail API** across users (`gam all users show forwards filters`) and flag external targets. This is the highest-value BEC hunt.

> **At the very end — SecOps UDM (optional):** land external-forward + fraud-send events to correlate the attacker's external domains across users. Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Cut the identity | Reset password + **sign out everywhere** (Login note) |
| Kill mail persistence | Delete malicious **filters**, turn **off forwarding**, remove **delegates**/`sendAs` |
| Stop the fraud | Warn contacted parties **out of band**; recall/mark fraud mail via SIT |
| Preserve | Vault hold + export the mailbox and ELS window |
| Remove app access | Revoke OAuth grants the attacker may hold |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Disable automatic external forwarding** org-wide | Kills the #1 BEC exfil channel |
| **Enforce phishing-resistant 2SV** | Stops the takeover upstream |
| **Alert on new external forwarding / filters** (SIT rules) | Catch persistence early |
| **Restrict mailbox delegation / sendAs** | No stealth read/spoof |
| **Enable Gmail logs → BigQuery** | Hunting + retention |
| **Disable less-secure apps** | Removes 2SV-bypass access to mail |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Filter forwarding finance mail + deleting the copy | BEC persistence |
| Auto-forwarding to an external/lookalike domain | Silent exfil |
| New mailbox delegate / `sendAs` alias | Stealth access / spoofing |
| External sends of wire/bank-change requests | Payment fraud |
| Mass deletion of sent items | Track-covering |
| Settings changed the same hour as a suspicious login | Attacker persistence |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The evidence sources + settings APIs | **Gmail → What is Gmail (for DFIR)** |
| The takeover sign-in | **Workspace → Login & Auth Audit** |
| BEC end to end | **Workspace → Playbooks → BEC and Mail Forwarding** |
| An app reading all mailboxes | **Workspace → OAuth & Third-Party Apps** · **Google → 01 (domain-wide delegation)** |
| Account takeover | **Workspace → Playbooks → Account Takeover** |

## Resources

- Email Log Search — https://support.google.com/a/answer/2604578
- Gmail API settings — https://developers.google.com/gmail/api/reference/rest/v1/users.settings
- Disable automatic forwarding — https://support.google.com/a/answer/2491924
- Security Investigation Tool — https://support.google.com/a/answer/7575955
- MITRE ATT&CK: T1114 Email Collection / T1564.008 Email Hiding Rules — https://attack.mitre.org/techniques/T1114/
