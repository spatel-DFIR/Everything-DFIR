# Unified Audit Log for DFIR

The UAL is the **first place you look** in almost every M365 investigation. It tells you what an identity did across email, files, Teams, and the directory.

New to the service? Read **What is the Unified Audit Log** first. This note is the *how*.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Reading a UAL Record](#reading-a-ual-record)
- [What to Look For, by Phase](#what-to-look-for-by-phase)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Retention | Best for |
|--------|--------------|-----------|----------|
| **Purview Audit** | All M365 workloads | 180 d–1 yr | Fast first look |
| **`Search-UnifiedAuditLog`** | Same, scriptable | 180 d–1 yr | Bulk pulls |
| **`OfficeActivity`** (Sentinel) | Exported copy, KQL | Your retention | Hunting + long retention |

**In SecOps (optional):** lands as Office 365 activity; actor → `principal.user.userid`, op → `metadata.product_event_type`, IP → `principal.ip`.

## Collect It

**Step 1 — Confirm auditing was on** (do this first):

```powershell
Get-AdminAuditLogConfig | fl UnifiedAuditLogIngestionEnabled
Get-Mailbox <upn> | fl AuditEnabled, AuditOwner    # per-mailbox: is MailItemsAccessed captured?
```

**Step 2 — Pull the identity's activity.**

```powershell
Search-UnifiedAuditLog -StartDate 2026-06-01 -EndDate 2026-07-11 \
  -UserIds alice@contoso.com -ResultSize 5000 -SessionCommand ReturnLargeSet |
  Export-Csv alice_ual.csv -NoTypeInformation
```

> **Console:** Purview → **Audit** → set date range + user + activities → **Search** → **Export**.

**Step 3 — Target the high-value operations.**

```powershell
Search-UnifiedAuditLog -StartDate .. -EndDate .. \
  -Operations "New-InboxRule","Set-Mailbox","Add-MailboxPermission","MailItemsAccessed","FileDownloaded","AnonymousLinkCreated"
```

> **For bulk/large pulls, consider the Microsoft Extractor Suite instead.** Raw `Search-UnifiedAuditLog` above works for a single identity over a short window, but it's a thin wrapper you have to page yourself — `-SessionCommand ReturnLargeSet` still throttles, and multi-user/multi-week pulls silently drop records if you don't manage the paging loop and retry-on-429 logic by hand. **Microsoft Extractor Suite** (the community-maintained PowerShell toolkit that succeeded Hawk) wraps that same UAL/Graph/Entra API surface with pagination and rate-limit handling built in, so bulk extraction across many mailboxes or a full retention window comes back complete instead of truncated. Main cmdlets: `Get-UALAll`/`Get-UALGraph` for UAL extraction, `Get-Sessions`/`Get-RiskyUsers`/`Get-RiskyDetections` for Entra ID risk data, and `Get-MailboxAuditLog`/`Get-MessageTraceLog`/`Get-Devices` for the Exchange/Graph-adjacent pulls this file already discusses. Use raw `Search-UnifiedAuditLog` for quick, scoped, single-identity checks; reach for Extractor Suite when the pull is tenant-wide, multi-week, or otherwise large enough that manual paging risks silent data loss.

## Investigate on the Platform

The flow — five steps:

| Step | Do this |
|------|---------|
| 1. Confirm coverage | Auditing on? Mailbox auditing on? Note blind spots (no `MailItemsAccessed` = can't prove reads) |
| 2. Scope the identity | Full timeline for the user/app; note `ClientIP` and workloads touched |
| 3. Classify each op | Bucket into phases (table below) |
| 4. Follow across workloads | A phished user often: reads mail → makes a rule → downloads files → shares out |
| 5. Split human vs app | `UserId` a UPN (person) vs an app/SP (automation or rogue app) |

## Reading a UAL Record

| Field | Answers | Notes |
|-------|---------|-------|
| `UserId` | **Who** | UPN, or an app/SP identity |
| `Operation` + `Workload` | **What / where** | The action + the M365 service |
| `ClientIP` | **From where** | Correlate with sign-in logs' IP/ASN |
| `AuditData` | **The detail** | Nested JSON — the rule text, the file name, the mailbox |
| `ResultStatus` | **Did it work** | Succeeded / failed |

> The gold is inside `AuditData`: the **inbox-rule parameters**, the **forwarding address**, the **file path**, the **sharing target**. Always expand it.

## What to Look For, by Phase

| Phase | Telltale operations |
|-------|---------------------|
| **Initial access** | `UserLoggedIn` from a new IP; `Add-MailboxPermission` on a shared mailbox |
| **Collection / recon** | `MailItemsAccessed` at volume; `Search` in mailboxes; file browsing |
| **Persistence** | `New-InboxRule` (hide/forward); `Set-Mailbox` forwarding; `Consent to application` |
| **Exfil** | `FileDownloaded`/`FileSyncDownloadedFull` at volume; `AnonymousLinkCreated`; external sharing |
| **Impact / fraud** | `Send`/`SendAs` (invoice fraud); mass `MoveToDeletedItems`/`HardDelete` (cover tracks) |

🔴 An inbox rule that moves finance mail to **RSS/Archive/a hidden folder** and marks it read is the classic BEC tell.

## Hunt at Scale

KQL over `OfficeActivity`:

**New inbox rules (BEC):**

```kql
OfficeActivity
| where Operation in ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| project TimeGenerated, UserId, ClientIP, Parameters=OfficeObjectId, Detail=Operation
```

**External auto-forwarding set:**

```kql
OfficeActivity
| where Operation == "Set-Mailbox"
| where Parameters has "ForwardingSmtpAddress" or Parameters has "ForwardingAddress"
| project TimeGenerated, UserId, ClientIP, Parameters
```

**Mass file download by one user:**

```kql
OfficeActivity
| where Operation in ("FileDownloaded","FileSyncDownloadedFull")
| summarize Files=count() by UserId, ClientIP, bin(TimeGenerated, 1h)
| where Files > 100
```

**Anonymous sharing links created:**

```kql
OfficeActivity
| where Operation == "AnonymousLinkCreated"
| project TimeGenerated, UserId, ClientIP, OfficeObjectId
```

> **At the very end — SecOps UDM (optional):** land inbox-rule / download events to answer "did this actor/IP appear elsewhere?" Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Cut the identity | Revoke tokens + disable (see 02 checklist) |
| Kill mail persistence | Remove malicious inbox rules + forwarding |
| Stop exfil | Revoke sharing links; suspend external sharing if needed |
| Preserve | Export the UAL for the window + put affected mailboxes on **litigation/eDiscovery hold** |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enable unified + advanced auditing** (`MailItemsAccessed`) | No exfil blind spot |
| **Export UAL → Sentinel** (long retention) | Beats the 180-day limit + enables hunting |
| **Disable external auto-forwarding** (Exchange remote domains / anti-spam) | Kills the #1 BEC channel |
| **Restrict anonymous/external sharing** | Limits data exposure |
| **Alert** on new inbox rules, forwarding, mass downloads | Catch BEC/exfil early |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `New-InboxRule` hiding/forwarding mail | BEC persistence |
| `Set-Mailbox` external forwarding | Silent mail exfil |
| `MailItemsAccessed` from a new IP at volume | Mailbox being read |
| `FileDownloaded` at volume | Data exfil |
| `AnonymousLinkCreated` on sensitive sites | Public data exposure |
| Mass `HardDelete`/`MoveToDeletedItems` | Track-covering |
| Activity by an app/SP nobody installed | Rogue app |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What the UAL is + operations | **Unified Audit Log → What is** |
| Who the identity/app is | **Microsoft → 01 Entra ID & Identities** |
| The sign-in behind the activity | **Entra → Sign-in Logs** |
| Mailbox-specific investigation | **M365 → Exchange Online** |
| File exfil | **M365 → SharePoint & OneDrive** |
| BEC end to end | **M365 → Exchange Online → Playbooks → Business Email Compromise** |

## Resources

- Search the audit log — https://learn.microsoft.com/purview/audit-log-search
- Audit log activities reference — https://learn.microsoft.com/purview/audit-log-activities
- Advanced audit — https://learn.microsoft.com/purview/audit-solutions-overview
- MITRE ATT&CK: T1114 Email Collection / T1530 Data from Cloud Storage — https://attack.mitre.org/techniques/T1114/
