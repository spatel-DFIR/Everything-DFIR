# What is Exchange Online?

**Exchange Online (EXO)** is Microsoft 365's **email service** — mailboxes, calendars, contacts, and the rules that move mail around. It is the **#1 target** in M365 compromises: attackers read a mailbox for intel, set rules to hide their tracks, forward mail out, and send fraud from a trusted name.

This note is the mental model + evidence map for EXO. For the log itself, see **M365 → Unified Audit Log**.

## Contents

- [How It Works](#how-it-works)
- [The Attacker's Toolkit in a Mailbox](#the-attackers-toolkit-in-a-mailbox)
- [Inbox Rules vs Transport Rules vs Forwarding](#inbox-rules-vs-transport-rules-vs-forwarding)
- [Mailbox Permissions and Delegation](#mailbox-permissions-and-delegation)
- [The Evidence Exchange Produces](#the-evidence-exchange-produces)
- [How to Identify Exchange Activity](#how-to-identify-exchange-activity)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

Users reach their mailbox via Outlook, OWA (browser), or mobile — all authenticating through **Entra**. Admins manage EXO via the **Exchange admin center** or **Exchange Online PowerShell**. Every meaningful action can be audited into the **UAL** and per-mailbox audit log.

The three things attackers do in a mailbox:

1. **Read** — collect intel (`MailItemsAccessed`, searches).
2. **Persist / hide** — inbox rules, forwarding, delegate permissions.
3. **Send** — fraud/impersonation from a trusted identity (`Send`, `SendAs`).

## The Attacker's Toolkit in a Mailbox

| Technique | What it does | Log signal |
|-----------|--------------|-----------|
| **Malicious inbox rule** | Auto-move/delete/mark-read to hide replies (invoice fraud) | `New-InboxRule` / `UpdateInboxRules` |
| **Auto-forwarding** | Copy all mail to an external address | `Set-Mailbox` (ForwardingSmtpAddress) |
| **Mailbox delegation** | Grant themselves access to another mailbox | `Add-MailboxPermission`, `Add-RecipientPermission` |
| **Mail reading** | Bulk-read for reconnaissance | `MailItemsAccessed` (E5) |
| **Impersonation send** | Send as the victim / on behalf | `Send`, `SendAs`, `SendOnBehalf` |
| **Evidence deletion** | Delete their own phishing/replies | `HardDelete`, `MoveToDeletedItems` |

## Inbox Rules vs Transport Rules vs Forwarding

Three different "move my mail" mechanisms — know which you're looking at:

| Mechanism | Scope | Set by | Log |
|-----------|-------|--------|-----|
| **Inbox rule** | One mailbox | User/attacker | `New-InboxRule` (UAL) |
| **Transport (mail flow) rule** | 🔴 **Org-wide** | Admin | `New-TransportRule` (UAL admin) |
| **Mailbox forwarding** | One mailbox | User/admin | `Set-Mailbox` ForwardingSmtpAddress |

> 🔴 A malicious **transport rule** is worse than an inbox rule — it can silently BCC *all* org mail to an attacker. Check both.

## Mailbox Permissions and Delegation

| Permission | Grants |
|-----------|--------|
| **FullAccess** | Open and read the whole mailbox |
| **SendAs** | Send as the mailbox (impersonation) |
| **SendOnBehalf** | Send on behalf of |
| **Folder-level** | Access to specific folders |

🔴 An attacker granting **their** account FullAccess/SendAs on an exec's mailbox is both access and persistence — and survives the victim's password reset.

## The Evidence Exchange Produces

| Evidence | Where | Needs |
|----------|-------|-------|
| Mailbox actions (rules, sends, perms) | UAL / mailbox audit log | Auditing on |
| **Which items were read** | UAL `MailItemsAccessed` | 🔴 E5 / advanced audit |
| Message delivery path | **Message trace** (`Get-MessageTraceV2`) | On by default (short retention) |
| Rules/forwarding current state | `Get-InboxRule`, `Get-Mailbox` | Admin access |
| Mailbox content | eDiscovery / content search | Hold/permissions |

## How to Identify Exchange Activity

- **UAL:** RecordTypes `ExchangeItem`, `ExchangeItemGroup`, `ExchangeAdmin`; workload `Exchange`.
- **PowerShell:** Exchange Online module (`Get-InboxRule`, `Get-Mailbox`, `Search-MailboxAuditLog`, `Get-MessageTraceV2`).
- **KQL:** `OfficeActivity | where Workload == "Exchange"`.

## Common Operations You Will See

| Operation | 🔴 Watch |
|-----------|---------|
| `New-InboxRule` / `UpdateInboxRules` | Hide/forward rules |
| `Set-Mailbox` (forwarding) | External forward |
| `Add-MailboxPermission` / `Add-RecipientPermission` | Delegation persistence |
| `MailItemsAccessed` | Bulk reads |
| `Send` / `SendAs` / `SendOnBehalf` | Impersonation |
| `New-TransportRule` | Org-wide mail interception |
| `HardDelete` / `MoveToDeletedItems` | Track-covering |

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| Exchange Online | WorkMail (rough) | Gmail |
| Inbox rule | — | Gmail filter |
| Auto-forwarding | — | Gmail forwarding |
| MailItemsAccessed | — | Gmail audit |

## Common Use Cases

Your "normal" baseline:

- Corporate email + calendars.
- Shared/resource mailboxes with delegation.
- Legitimate forwarding (usually *internal*; external forwarding is rare and suspicious).

## Key Terminology

| Term | Meaning |
|------|---------|
| **Mailbox** | A user's email store |
| **Inbox rule** | Per-mailbox auto-action on mail |
| **Transport rule** | Org-wide mail-flow rule |
| **Forwarding** | Auto-copy mail elsewhere |
| **FullAccess / SendAs** | Mailbox delegation permissions |
| **MailItemsAccessed** | The "mail was read" audit event |
| **Message trace** | Delivery-path log |
| **BEC** | Business Email Compromise |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating a mailbox compromise | **Exchange Online → for DFIR** |
| The master M365 log | **M365 → Unified Audit Log** |
| The sign-in behind the access | **Entra → Sign-in Logs** |
| The BEC scenario | **Exchange Online → Playbooks → Business Email Compromise** |
| Rules & forwarding scenario | **Exchange Online → Playbooks → Malicious Inbox Rules and Forwarding** |

## Resources

- Exchange Online overview — https://learn.microsoft.com/exchange/exchange-online
- Mailbox auditing — https://learn.microsoft.com/purview/audit-mailboxes
- Inbox rules — https://learn.microsoft.com/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules
- Message trace (Get-MessageTraceV2) — https://learn.microsoft.com/powershell/module/exchange/get-messagetracev2
