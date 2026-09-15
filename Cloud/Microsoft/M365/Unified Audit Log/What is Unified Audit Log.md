# What is the Unified Audit Log?

The **Unified Audit Log (UAL)** is Microsoft 365's **master audit log** — one searchable stream of activity across **Exchange Online, SharePoint, OneDrive, Teams, Entra, Power Platform**, and more. It answers *who did what in M365* — read a mailbox item, changed a sharing link, created an inbox rule, downloaded files.

Think of it as **CloudTrail for M365**: one place, one schema-ish record, almost every SaaS-side attacker step shows up here.

## Contents

- [How It Works](#how-it-works)
- [Is It Even On?](#is-it-even-on)
- [Where the Log Lives and How You Query It](#where-the-log-lives-and-how-you-query-it)
- [Record Types and Operations](#record-types-and-operations)
- [The Mailbox-Auditing Catch](#the-mailbox-auditing-catch)
- [How to Identify a UAL Record](#how-to-identify-a-ual-record)
- [The Operations That Matter Most](#the-operations-that-matter-most)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

Every audited action across M365 workloads is written as a **UAL record** — a JSON blob with a common envelope (who, when, what, where) plus workload-specific detail in an `AuditData` field.

| Field | Contains |
|-------|----------|
| `CreationTime` | When |
| `UserId` | Who (UPN, or an app/SP) |
| `Operation` | The action (`New-InboxRule`, `FileDownloaded`, `MailItemsAccessed`) |
| `Workload` | Exchange / SharePoint / OneDrive / Teams / AzureActiveDirectory |
| `ClientIP` | Source IP |
| `AuditData` | The full workload-specific detail (nested JSON) |

Two facts for a live case:

- **Ingestion lag** — records can take minutes to ~24h to appear. Don't conclude "nothing happened" from a too-fresh search.
- **Retention** — **180 days** (E3) or **1 year** (E5); custom policies can extend. 🔴 Often the **longest native look-back** you have for identity+M365.

## Is It Even On?

🔴 The first question, always. If auditing was off, the evidence was never created.

```powershell
# Is unified audit logging enabled tenant-wide?
Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled
```

> **Console:** Purview → **Audit** → if you see a "Start recording user and admin activity" banner, it was **off**. On by default for new tenants since 2019, but verify — and check **per-mailbox** auditing too (below).

## Where the Log Lives and How You Query It

| Method | What it is | Look-back | Best for |
|--------|-----------|-----------|----------|
| **Purview Audit portal** | The GUI audit search | 180 d–1 yr | Fast first look, exports |
| **`Search-UnifiedAuditLog`** (Exchange Online PowerShell) | Scriptable search | 180 d–1 yr | Repeatable pulls, large exports |
| **Microsoft Graph** (`security/auditLog`) | API access | Same | Automation |
| **Log Analytics / Sentinel** (`OfficeActivity`) | Exported copy, KQL | Your retention | Hunting + correlation + long retention |

> **Rule of thumb:** quick look → Purview portal. Scripted/bulk → `Search-UnifiedAuditLog` (page with `-SessionId`/`-SessionCommand ReturnLargeSet`). Hunt/correlate/keep-forever → `OfficeActivity` in Sentinel.

## Record Types and Operations

The UAL is huge; you filter by **RecordType** + **Operations**:

| RecordType (examples) | Workload |
|-----------------------|----------|
| `ExchangeItem`, `ExchangeItemGroup`, `ExchangeAdmin` | Exchange Online |
| `SharePointFileOperation`, `SharePointSharingOperation` | SharePoint |
| `OneDrive` | OneDrive |
| `MicrosoftTeams` | Teams |
| `AzureActiveDirectory`, `AzureActiveDirectoryStsLogon` | Entra events (also here) |
| `MicrosoftFlow`, `PowerAppsApp` | Power Platform |

## The Mailbox-Auditing Catch

🔴 The gotcha that ruins BEC investigations: **`MailItemsAccessed`** (which mailbox items were *read*) depends on **mailbox auditing** being enabled and the right license.

- **Mailbox audit logging** is on by default for most, but **`MailItemsAccessed`** (the "was my mail actually read?" event) requires **E5 / Advanced Auditing**.
- Without it, you can see rules and sends but **not reads** — the exfiltration blind spot.

> **Verify per mailbox:** `Get-Mailbox <upn> | fl AuditEnabled, AuditOwner`. Turn on advanced auditing *before* you need it.

## How to Identify a UAL Record

- **Portal:** Purview → **Audit** → search by user/activity/date.
- **PowerShell:** `Search-UnifiedAuditLog -StartDate .. -EndDate .. -Operations .. -UserIds ..`.
- **KQL:** table `OfficeActivity`.
- Every record: `CreationTime`, `UserId`, `Operation`, `Workload`, `ClientIP`, `AuditData` (JSON).

## The Operations That Matter Most

| Operation | Workload | 🔴 Why |
|-----------|----------|--------|
| `New-InboxRule` / `Set-InboxRule` | Exchange | Hiding/forwarding mail (BEC) |
| `Set-Mailbox` (ForwardingSmtpAddress) | Exchange | External auto-forward |
| `Add-MailboxPermission` / `Add-RecipientPermission` | Exchange | Delegate access to a mailbox |
| `MailItemsAccessed` | Exchange | 🔴 Which items were read (E5) |
| `Send` / `SendAs` / `SendOnBehalf` | Exchange | Impersonation / fraud mail |
| `FileDownloaded` / `FileSyncDownloadedFull` | SharePoint/OneDrive | Mass exfil |
| `AnonymousLinkCreated` / `SharingInvitationCreated` | SharePoint/OneDrive | Data exposure |
| `Add member to role` / `Consent to application` | AzureActiveDirectory | Escalation / rogue app |
| `MemberAdded` (Teams) | Teams | External access to a team |

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| Unified Audit Log | CloudTrail (+ data events) | Workspace audit logs (Admin/Drive/Gmail) |
| `MailItemsAccessed` | S3 data events (per-object) | Gmail audit |
| `FileDownloaded` | S3 `GetObject` data event | Drive audit |

## Common Use Cases

Your "normal" baseline:

- **Compromise investigation** — the go-to M365 evidence.
- **Insider / exfil** — file downloads, sharing.
- **Compliance / eDiscovery** — a record of activity.

## Key Terminology

| Term | Meaning |
|------|---------|
| **UAL** | Unified Audit Log — the M365 master log |
| **RecordType** | The workload category of a record |
| **Operation** | The specific action |
| **AuditData** | The nested workload-specific detail |
| **Mailbox auditing** | Per-mailbox logging (needed for reads) |
| **MailItemsAccessed** | The "mail was read" event (E5) |
| **OfficeActivity** | The Sentinel/Log Analytics table for UAL |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating with the UAL | **Unified Audit Log → for DFIR** |
| Who the identity/app is | **Microsoft → 01 Entra ID & Identities** |
| Mailbox specifics | **M365 → Exchange Online** |
| File exfil specifics | **M365 → SharePoint & OneDrive** |
| Long-retention / eDiscovery | **M365 → Purview & eDiscovery** |

## Resources

- Search the audit log — https://learn.microsoft.com/purview/audit-log-search
- Audited activities — https://learn.microsoft.com/purview/audit-log-activities
- Advanced audit / MailItemsAccessed — https://learn.microsoft.com/purview/audit-solutions-overview
- Search-UnifiedAuditLog — https://learn.microsoft.com/powershell/module/exchange/search-unifiedauditlog
