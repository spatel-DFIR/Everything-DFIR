# Playbook — Business Email Compromise (BEC)

The most common — and most expensive — M365 incident. An attacker takes over a mailbox (via phish, token theft, or spray), then **hides in it**: reads finance/vendor mail, sets rules to conceal their replies, and sends **fraudulent payment/wire requests** from a trusted identity. This playbook reconstructs the takeover, finds the persistence, quantifies the fraud, and locks it down.

> **Tier 2 (cross-service).** Spans Entra sign-ins + Exchange + UAL. Read **M365 → Exchange Online** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Quantify the Fraud](#quantify-the-fraud)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **User/finance report** | A vendor/customer got a fake invoice or wire-change from us |
| **Identity Protection** | Risky sign-in / anomalous token on the mailbox owner |
| **UAL** | New inbox rule + external sends from a new IP |
| **Defender** | Suspicious inbox-rule / BEC alert |

## Hypothesis

An attacker controls the mailbox and is committing payment fraud while hiding replies. Establish the initial access, the persistence (rules/forwarding), the fraudulent sends, and every party contacted.

## Step-by-Step Investigation

**1. Find the takeover sign-in.** New IP/ASN/country; token replay (MFA "by claim"); legacy auth. Cross **Entra sign-in logs** with the mailbox owner.

**2. Snapshot mailbox persistence** — the moment you're sure it's compromised:

```powershell
Get-InboxRule -Mailbox victim@contoso.com | Select Name,Enabled,ForwardTo,MoveToFolder,DeleteMessage,MarkAsRead
Get-Mailbox victim@contoso.com | fl ForwardingSmtpAddress,ForwardingAddress
Get-MailboxPermission victim@contoso.com | ? { $_.User -notlike "NT AUTHORITY*" }
```

**3. Find the fraudulent sends.**

```powershell
Search-UnifiedAuditLog -StartDate .. -EndDate .. -UserIds victim@contoso.com -Operations "Send","SendAs","SendOnBehalf"
Get-MessageTraceV2 -SenderAddress victim@contoso.com -StartDate .. -EndDate ..
```

**4. Map who was contacted.** Message trace → every external recipient of the fraud mail (vendors/customers to warn).

**5. Prove reads (if E5).** `MailItemsAccessed` — which threads (invoices, banking) the attacker read.

## Quantify the Fraud

| Question | Evidence |
|----------|----------|
| What fraud mail was sent, to whom? | Message trace + `Send`/`SendAs` |
| Were payment details changed? | Read the sent items / replies (eDiscovery) |
| Did money move? | Coordinate with finance/bank immediately |
| Which internal threads were read? | `MailItemsAccessed` (E5) |
| Is the rule hiding replies? | The rule moving vendor mail to a hidden folder |

## Decision Points

| Question | If yes → |
|----------|----------|
| Money in motion? | 🔴 **Immediate** finance + bank recall; law enforcement |
| Token theft (not password)? | Run **Token Theft and AiTM**; revoke tokens |
| Multiple mailboxes hit? | Campaign — hunt the rule pattern/IP tenant-wide |
| Admin mailbox? | Check for role/app changes (escalation) |

## Contain

```powershell
Revoke-MgUserSignInSession -UserId victim@contoso.com    # kill the session (tokens!)
Update-MgUser -UserId victim@contoso.com -AccountEnabled:$false
Remove-InboxRule -Mailbox victim@contoso.com -Identity "<rule>"
Set-Mailbox victim@contoso.com -ForwardingSmtpAddress $null -ForwardingAddress $null
```
Warn the contacted vendors/customers **out of band** (the mailbox is untrusted).

## Eradicate

- Remove all malicious rules, forwarding, and delegated permissions.
- Reset password **after** token revocation; re-register MFA.
- Remove any consented apps / added MFA methods the attacker planted.
- Check for a malicious **transport rule** at the org level.

## Recover

- Re-enable with fresh creds + phishing-resistant MFA.
- **Disable external auto-forwarding** tenant-wide; alert on new inbox rules.
- Notify affected parties + follow fraud/legal/regulatory process.
- Preserve: sign-ins, rules, sends, message trace, and (if possible) the fraud mail content on hold.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| Inbox rule hiding vendor/finance replies | BEC concealment |
| External forwarding set | Silent exfil |
| `SendAs`/`Send` fraud mail from a new IP | Payment fraud |
| Wire/bank-detail change in sent mail | Active fraud |
| Token replay on the mailbox owner | AiTM takeover |

## References

- Related notes: **Exchange Online**, **Sign-in Logs**, **Token Theft and AiTM**, **Unified Audit Log**
- Respond to a compromised email account — https://learn.microsoft.com/microsoft-365/security/office-365-security/responding-to-a-compromised-email-account
- BEC guidance — https://learn.microsoft.com/defender-office-365/attack-simulation-training-insights
- MITRE ATT&CK: T1114 Email Collection / T1534 Internal Spearphishing — https://attack.mitre.org/techniques/T1114/
