# Playbook — Malicious Inbox Rules and Forwarding

The quiet persistence behind most mailbox compromises. After getting in, an attacker sets **inbox rules** (auto-delete/move/mark-read to hide replies) and **auto-forwarding** (copy mail to an external address). These outlast a password reset and silently exfiltrate mail. This playbook finds every rule and forward, ties them to the intrusion, and removes them.

> **Tier 2 (cross-service).** Exchange + UAL + Entra sign-ins. Read **M365 → Exchange Online** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [The Rule/Forward Types to Find](#the-ruleforward-types-to-find)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **Defender** | Suspicious inbox-manipulation-rule alert |
| **UAL** | `New-InboxRule` / `Set-Mailbox` forwarding from a new IP |
| **User report** | "I'm missing emails / a rule I didn't make" |
| **Identity Protection** | `mcasSuspiciousInboxManipulationRules` |

## Hypothesis

An attacker planted rules/forwarding to hide activity and exfiltrate mail. Enumerate every rule and forward (inbox, mailbox, and org-wide transport), attribute them, and remove them.

## Step-by-Step Investigation

**1. Enumerate all three layers** (inbox rule, mailbox forward, transport rule):

```powershell
Get-InboxRule -Mailbox victim@contoso.com | fl Name,Enabled,ForwardTo,RedirectTo,MoveToFolder,DeleteMessage,MarkAsRead,StopProcessingRules
Get-Mailbox victim@contoso.com | fl ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward
Get-TransportRule | ? { $_.BlindCopyTo -or $_.RedirectMessageTo }    # org-wide interception
```

**2. Attribute each rule.** UAL `New-InboxRule` events carry `ClientIP` + time → tie to the compromising sign-in.

```powershell
Search-UnifiedAuditLog -StartDate .. -EndDate .. -Operations "New-InboxRule","Set-InboxRule","UpdateInboxRules","Set-Mailbox"
```

**3. Read the rule logic.** What does it hide (finance/vendor/security mail)? Where does it send? Rules that **delete** or move to *Deleted Items / RSS / Conversation History / Archive* + **mark read** are classic concealment.

**4. Find the destination.** External forward address = the exfil endpoint (and often a lead on the actor).

## The Rule/Forward Types to Find

| Type | Malicious shape |
|------|-----------------|
| **Hide/conceal rule** | Move matching mail to a rarely-seen folder + mark read + delete |
| **External forward rule** | `ForwardTo`/`RedirectTo` an outside address |
| **Mailbox forwarding** | `ForwardingSmtpAddress` to external, `DeliverToMailboxAndForward` sometimes false (silent) |
| **Transport rule** | 🔴 Org-wide BCC/redirect of all mail |
| **Keyword rule** | Triggers on "invoice", "payment", "wire", "password" |

## Decision Points

| Question | If yes → |
|----------|----------|
| External destination? | Confirmed exfil — treat mail as leaked |
| Transport (org-wide) rule? | All-org interception — highest priority |
| Rule keyed on finance terms? | BEC — run the **BEC** playbook |
| Rule survived a prior reset? | Persistence worked — token/session wasn't cut |

## Contain

```powershell
Remove-InboxRule -Mailbox victim@contoso.com -Identity "<rule>"
Set-Mailbox victim@contoso.com -ForwardingSmtpAddress $null -ForwardingAddress $null
Disable-TransportRule -Identity "<badRule>"
Revoke-MgUserSignInSession -UserId victim@contoso.com
```

## Eradicate

- Remove every malicious rule/forward across all three layers.
- Cut the identity (revoke tokens + disable + reset) so no new rules can be set.
- Sweep other mailboxes for the same rule pattern/destination.

## Recover

- **Disable external auto-forwarding** tenant-wide.
- Alert on `New-InboxRule` / `Set-Mailbox` forwarding / `New-TransportRule`.
- Preserve: the rule definitions, their creation events + IPs, and forwarding destinations.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| Rule deleting/hiding + marking read | Concealment |
| External `ForwardTo`/`ForwardingSmtpAddress` | Mail exfil |
| Transport rule BCC/redirect external | Org-wide interception |
| Rule keyed on finance terms | BEC |
| Rule created from a new IP right after a risky sign-in | Attacker persistence |

## References

- Related notes: **Exchange Online**, **Unified Audit Log**, **Business Email Compromise**, **Sign-in Logs**
- Control external forwarding — https://learn.microsoft.com/defender-office-365/outbound-spam-policies-external-email-forwarding
- Mail flow rules — https://learn.microsoft.com/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules
- MITRE ATT&CK: T1564.008 Email Hiding Rules / T1114.003 Email Forwarding Rule — https://attack.mitre.org/techniques/T1114/003/
