# Exchange Online for DFIR

Exchange is where most M365 compromises pay off — read the mail, hide the tracks, forward the data, send the fraud. This note is how you **investigate a mailbox, find the rules/forwarding/delegation, prove what was read, and clean it up.**

New to the service? Read **What is Exchange Online** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Proving What Was Read](#proving-what-was-read)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Notes |
|--------|--------------|-------|
| **UAL** (`ExchangeItem*`) | Rules, sends, perms, reads | Longest look-back |
| **Mailbox audit log** | Per-mailbox actions | `Search-MailboxAuditLog` |
| **Message trace** | Delivery path of specific mail | Short retention — pull early |
| **Current config** | Rules, forwarding, permissions now | `Get-InboxRule`, `Get-Mailbox` |

## Collect It

**Snapshot the mailbox's current state (rules + forwarding + delegation):**

```powershell
Get-InboxRule -Mailbox alice@contoso.com | Select Name, Enabled, ForwardTo, RedirectTo, MoveToFolder, DeleteMessage, MarkAsRead
Get-Mailbox alice@contoso.com | fl ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward
Get-MailboxPermission alice@contoso.com | ? { $_.User -notlike "NT AUTHORITY*" }
Get-RecipientPermission alice@contoso.com   # SendAs
```

> **Console:** Exchange admin center → **Recipients → Mailboxes** → the mailbox → **Mail flow / Delegation**; and Outlook web → **Rules**.

**Pull the audit history:**

```powershell
Search-UnifiedAuditLog -StartDate .. -EndDate .. -UserIds alice@contoso.com \
  -Operations "New-InboxRule","Set-InboxRule","Set-Mailbox","Add-MailboxPermission","Send","SendAs","MailItemsAccessed"
```

**Message trace (do this early — short retention):**

```powershell
Get-MessageTraceV2 -SenderAddress alice@contoso.com -StartDate .. -EndDate ..
```

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Snapshot config | Rules, forwarding, delegation — capture before you change anything |
| 2. Find the persistence | Hide/forward rules, external forwarding, self-granted permissions |
| 3. Tie to the intrusion | The rule/forward's creation time + `ClientIP` → the compromising sign-in |
| 4. Prove reads/sends | `MailItemsAccessed` (reads), `Send`/`SendAs` (fraud), message trace (where mail went) |
| 5. Check org-wide | Any malicious **transport rule** BCCing all mail? |

## Proving What Was Read

| If you had… | You can determine |
|-------------|-------------------|
| **Advanced audit** (`MailItemsAccessed`) | Which mail items/folders were accessed, by whom, from where 🎯 |
| Only basic auditing | Rules/sends but **not reads** — 🔴 assume the mailbox was read |
| Message trace | Where specific messages were delivered/forwarded |

🔴 `MailItemsAccessed` with `MailAccessType: Bind` lists specific items; a "throttled" flag means volume was high enough that Microsoft stopped itemizing — treat as bulk access.

### Delete State — What's Actually Recoverable

Not all `*Deleted` operations mean the same thing. Before you write off deleted mail as gone, check which delete state it's in:

| Delete state | What happened | Recoverable? |
|---------------|----------------|---------------|
| `MoveToDeletedItems` | Item moved to the mailbox's **Deleted Items** folder | ✅ Fully recoverable — it's just sitting in a visible folder |
| `SoftDelete` | Item removed from Deleted Items into **Recoverable Items / dumpster** | ✅ Recoverable via `Restore-RecoverableItems`, until the retention window (default 14 days, up to 30) expires |
| `HardDelete` | Item purged from Recoverable Items | 🔴 Only recoverable if a **litigation hold** or in-place hold was active on the mailbox at time of deletion — otherwise it's gone |

🔴 Check hold status (`Get-Mailbox <mailbox> | fl LitigationHoldEnabled,InPlaceHolds`) **before** telling anyone evidence is unrecoverable — a hard-deleted item under hold is still pullable from the hold's preserved copy via Content Search/eDiscovery.

## Hunt at Scale

**External forwarding across the tenant:**

```kql
OfficeActivity
| where Operation == "Set-Mailbox" and Parameters has_any ("ForwardingSmtpAddress","ForwardingAddress")
| project TimeGenerated, UserId, ClientIP, Parameters
```

**Suspicious inbox rules (delete/forward/move-to-hidden):**

```kql
OfficeActivity
| where Operation in ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| where Parameters has_any ("ForwardTo","RedirectTo","DeleteMessage","Deleted Items","RSS","Archive","Conversation History")
| project TimeGenerated, UserId, ClientIP, Parameters
```

**Org-wide transport rules added:**

```kql
OfficeActivity
| where Operation == "New-TransportRule"
| project TimeGenerated, UserId, ClientIP, Parameters
```

## Respond

| Goal | Action |
|------|--------|
| Cut the identity | Revoke tokens + disable |
| Remove mail persistence | Delete malicious inbox rules; clear forwarding; remove rogue delegation |
| Kill org-wide interception | Disable/delete the malicious transport rule |
| Block the channel | Disable external auto-forwarding tenant-wide |
| Preserve | eDiscovery/litigation hold on affected mailboxes before cleanup |

```powershell
Remove-InboxRule -Mailbox alice@contoso.com -Identity "<ruleName>"
Set-Mailbox alice@contoso.com -ForwardingSmtpAddress $null -ForwardingAddress $null
```

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Disable external auto-forwarding** (outbound anti-spam / remote domains) | Kills the #1 BEC channel |
| **Enable advanced auditing** (`MailItemsAccessed`) | Prove reads |
| **Alert** on new inbox rules / forwarding / transport rules | Catch BEC early |
| **Block legacy auth + require MFA** | Stops the account compromise upstream |
| **Restrict who can add mailbox permissions** | Limits delegation persistence |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Inbox rule forwarding/deleting/hiding finance mail | BEC persistence |
| `Set-Mailbox` external forwarding | Silent exfil |
| Self-granted FullAccess/SendAs on an exec mailbox | Access + persistence |
| `New-TransportRule` BCCing external | Org-wide interception |
| `MailItemsAccessed` bulk/throttled from a new IP | Mailbox read at scale |
| Mass `HardDelete` after suspicious sends | Track-covering fraud |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What EXO is + the toolkit | **Exchange Online → What is** |
| The master M365 log | **M365 → Unified Audit Log** |
| The compromising sign-in | **Entra → Sign-in Logs** |
| BEC end to end | **Exchange Online → Playbooks → Business Email Compromise** |
| Rules/forwarding scenario | **Exchange Online → Playbooks → Malicious Inbox Rules and Forwarding** |

## Resources

- Mailbox auditing — https://learn.microsoft.com/purview/audit-mailboxes
- Responding to a compromised email account — https://learn.microsoft.com/microsoft-365/security/office-365-security/responding-to-a-compromised-email-account
- Control automatic external email forwarding — https://learn.microsoft.com/defender-office-365/outbound-spam-policies-external-email-forwarding
- MITRE ATT&CK: T1114 Email Collection / T1564.008 Email Hiding Rules — https://attack.mitre.org/techniques/T1564/008/
