# What is SharePoint & OneDrive?

**SharePoint Online (SPO)** and **OneDrive for Business (ODB)** are M365's **file platforms**. SharePoint hosts shared **sites** (team/department document libraries, intranet); OneDrive is each user's **personal** cloud drive. Under the hood they're the same engine — so their forensics are nearly identical.

They're the M365 **data crown jewels** and a prime **exfiltration** target: mass downloads, anonymous sharing links, and external guest access.

## Contents

- [How It Works](#how-it-works)
- [SharePoint vs OneDrive](#sharepoint-vs-onedrive)
- [Sharing — The Main Exposure Path](#sharing--the-main-exposure-path)
- [The Evidence They Produce](#the-evidence-they-produce)
- [How to Identify File Activity](#how-to-identify-file-activity)
- [Numeric UAL RecordType Values](#numeric-ual-recordtype-values)
- [The Operations That Matter Most](#the-operations-that-matter-most)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

Files live in **document libraries** on **sites** (SPO) or personal drives (ODB). Access is by permissions + **sharing links**. Every meaningful file action — view, download, share, sync, delete — can be audited into the **UAL**.

The two things attackers do here:

1. **Exfiltrate** — download or sync at volume; share out via links.
2. **Expose** — create anonymous/"anyone" links, add external guests.

## SharePoint vs OneDrive

| | **SharePoint Online** | **OneDrive for Business** |
|-|------------------------|----------------------------|
| Purpose | Shared team/org files | One user's personal files |
| Scope | Sites + libraries | Per-user drive |
| Owner | Team/site owners | The individual |
| 🔴 Risk | Broad blast radius (whole team's data) | Personal exfil, but often has synced corporate docs |
| UAL RecordType | `SharePointFileOperation`, `SharePointSharingOperation` | `OneDrive` |

## Sharing — The Main Exposure Path

How a file gets exposed — know the link types:

| Link type | Who can access | 🔴 Risk |
|-----------|----------------|---------|
| **Anyone / Anonymous** | Anyone with the URL, no sign-in | 🔴 Public exposure — the "leaky link" |
| **People in your org** | Any authenticated tenant user | Internal over-sharing |
| **Specific people** | Named users (incl. external guests) | Guest access — watch external |
| **Existing access** | No new grant | Low risk |

> 🔴 **`AnonymousLinkCreated`** on a sensitive site is the SharePoint equivalent of a public S3 bucket. **`SharingInvitationCreated`** to an external domain is data leaving to a guest.

## The Evidence They Produce

| Evidence | UAL Operation | Notes |
|----------|---------------|-------|
| File viewed | `FileAccessed` | Read |
| File downloaded | `FileDownloaded` | 🔴 Exfil |
| Bulk sync download | `FileSyncDownloadedFull` | 🔴 Whole library pulled |
| Sharing link created | `AnonymousLinkCreated`, `SharingLinkCreated` | Exposure |
| External invite | `SharingInvitationCreated` | Guest access |
| File deleted | `FileDeleted` / `FileRecycled` | Impact / cleanup |
| Permission change | `SharingSet`, `SiteCollectionAdminAdded` | Access grant |

## How to Identify File Activity

- **UAL:** RecordTypes `SharePointFileOperation`, `SharePointSharingOperation`, `OneDrive`.
- **Portal:** SharePoint admin center (sites/sharing); Purview Audit for activity.
- **KQL:** `OfficeActivity | where Workload in ("SharePoint","OneDrive")`.
- **PnP/Graph:** enumerate sites, permissions, sharing links.

## Numeric UAL RecordType Values

🔴 The named RecordTypes above (`SharePointFileOperation`, etc.) are what you see in the Purview UI and in `Search-UnifiedAuditLog` output — but raw/bulk JSON UAL exports (Management Activity API, SIEM pulls) surface `RecordType` as an **integer**, not a friendly name. Map them:

| RecordType (int) | Name | Meaning |
|-------------------|------|---------|
| 4 | `SharePoint` | General site-level/admin operation (site creation, admin actions) |
| 6 | `SharePointFileOperation` | File-level activity — view, download, upload, delete, move |
| 14 | `SharePointSharingOperation` | Sharing links, invitations, permission grants |
| 36 | `SharePointListOperation` | List/library-schema create, update, delete |
| 54 | `SharePointListItemOperation` | List-item-level activity (add/edit/delete individual items) |
| 55 | `SharePointContentTypeOperation` | Content-type create/modify/delete |
| 56 | `SharePointFieldOperation` | Field/column create/modify/delete |

If you're parsing raw UAL JSON and only have the integer, use this table to know which workload operation you're looking at before you go hunting for the matching `Operation` name.

> 🔴 The integers for `SharePointFileOperation` (6) and `SharePointSharingOperation` (14) are the two you'll hit constantly and are worth memorizing; treat the rest as a lookup table, not something to memorize — always cross-check against the current `AuditLogRecordType` enum in Microsoft's Office 365 Management Activity API schema docs if precision matters for a report.

## The Operations That Matter Most

| Operation | 🔴 Watch |
|-----------|---------|
| `FileDownloaded` / `FileSyncDownloadedFull` | Mass exfil |
| `FileAccessed` (at volume) | Bulk reconnaissance |
| `AnonymousLinkCreated` | Public exposure |
| `SharingInvitationCreated` (external) | Data to a guest |
| `SiteCollectionAdminAdded` | Site takeover |
| `FileDeleted` / mass recycle | Destruction |

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| SharePoint / OneDrive | S3 (rough) | Google Drive |
| Anonymous link | S3 public object | Drive "anyone with link" |
| `FileDownloaded` | S3 `GetObject` data event | Drive `download` audit |
| External sharing invite | Cross-account grant | Drive external share |

## Common Use Cases

Your "normal" baseline:

- Team collaboration on documents.
- Intranet / knowledge bases.
- Personal work files (OneDrive), often synced to endpoints.
- *Some* external sharing with partners (baseline it — anonymous links usually aren't normal).

## Key Terminology

| Term | Meaning |
|------|---------|
| **Site / site collection** | A SharePoint container of libraries |
| **Document library** | A file store within a site |
| **OneDrive** | A user's personal drive |
| **Sharing link** | A URL granting access (anonymous/org/specific) |
| **Anonymous link** | "Anyone with the link" — no sign-in |
| **External sharing** | Access granted to guests/outside the tenant |
| **FileSyncDownloadedFull** | Bulk sync-client download |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating file exfil | **SharePoint & OneDrive → for DFIR** |
| The master M365 log | **M365 → Unified Audit Log** |
| The sign-in behind the access | **Entra → Sign-in Logs** |
| Mass-download scenario | **SharePoint & OneDrive → Playbooks → Mass Download Exfiltration** |
| Data classification / DLP | **M365 → Purview & eDiscovery** |

## Resources

- SharePoint auditing — https://learn.microsoft.com/purview/audit-log-activities#sharepoint-activities
- External sharing overview — https://learn.microsoft.com/sharepoint/external-sharing-overview
- Manage sharing settings — https://learn.microsoft.com/sharepoint/turn-external-sharing-on-or-off
