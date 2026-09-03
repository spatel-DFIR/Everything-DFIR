# What is the Drive Audit?

The **Drive audit log** records what happens to files in **Google Drive** and shared drives — views, downloads, edits, deletes, and (critically) **sharing changes** that expose data externally or publicly. It is the evidence behind data-exfiltration and leaky-link cases.

If Gmail is the #1 BEC target, Drive is the #1 **data-theft** surface: a departing insider mass-downloads, or a compromised account shares the crown-jewels folder "anyone with the link."

## Contents

- [How It Works](#how-it-works)
- [How to Identify Drive Evidence](#how-to-identify-drive-evidence)
- [The Sharing Model — Where Exposure Happens](#the-sharing-model--where-exposure-happens)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
User acts on a file (view / download / edit / share / delete)
   → event written to the Drive audit log   (Enterprise / Business Plus editions)
   → readable in: Admin console → Reporting → Audit and investigation → Drive log events
                  Reports API (applicationName=drive)
                  (optional) BigQuery export
```

- Each event has an **actor**, a **document** (title, ID, owner), and a **visibility/access** change where relevant.
- 🔴 **Sharing events** are the ones that leak data: a change from *private* to *anyone with the link* or *public on the web* exposes a file to the internet.
- **Shared drives** (team drives) have their own membership; adding an external member is a bulk-exposure event.

## How to Identify Drive Evidence

- **Console:** Admin console → **Reporting → Audit and investigation → Drive log events**.
- **API:** Admin SDK Reports, `applicationName=drive`.
- **Current sharing state:** the **Drive API** (`files.list`, `permissions.list`) enumerates who can access a file *now*.
- **Event shape:** `actor.email`, `doc_id`, `doc_title`, `visibility`, `event.name` (`download`, `change_document_visibility`…), `target_user` (share recipient).

## The Sharing Model — Where Exposure Happens

| Visibility | Meaning | 🔴 Risk |
|-----------|---------|---------|
| **Private** | Only explicitly shared people | Baseline |
| **People with the link** | Anyone holding the URL | 🔴 Link can be forwarded/leaked |
| **Shared externally** | Someone outside the domain | 🔴 Data left the org |
| **Public on the web** | Indexable by anyone | 🔴 Full public exposure |

> 🔴 A `change_document_visibility` to **public_on_the_web** or **people_with_link**, or a `change_user_access` granting an **external** address, on a sensitive doc/folder = the leak moment. Establish *when* and *who*.

## Common Operations You Will See

| Event | What it does | Watch? |
|-------|--------------|--------|
| `download` | File downloaded | 🔴 at volume = exfil |
| `view` / `edit` | Access to content | Baseline; volume matters |
| `change_document_visibility` | Change public/link visibility | 🔴 exposure |
| `change_user_access` | Grant/remove a user's access | 🔴 external grantee |
| `change_document_access_scope` | Change scope (domain/anyone) | 🔴 broaden |
| `add_to_shared_drive` / membership change | Shared-drive access | 🔴 external member = bulk exposure |
| `copy` / `print` | Alternate exfil paths | 🔴 evasion of download alerts |
| `delete` / `trash` | Removal | 🔴 destruction / cover tracks |

## Cross-Provider Equivalent

| Google Workspace | AWS | Microsoft |
|------------------|-----|-----------|
| Drive audit log | S3 data events (loosely) | SharePoint/OneDrive audit (UAL) |
| `change_document_visibility` public | S3 public ACL/policy | Anonymous sharing link |
| Shared drive | — | SharePoint site / Team |
| `download` at volume | S3 `GetObject` volume | `FileDownloaded` volume |
| Drive API permissions | S3 bucket policy/ACL | Sharing permissions |

## Common Use Cases

Your "normal" baseline: everyday collaboration; **legit external sharing** with partners; **shared drives** per team. The job is to separate normal collaboration from exfil — check *volume*, *sensitivity*, *external recipients*, and whether it aligns with a takeover or a departing employee.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Visibility** | Who can access a file (private / link / external / public) |
| **Shared drive** | A team-owned drive (formerly Team Drive) |
| **Access scope** | The breadth of a share (domain / anyone) |
| **Drive audit log** | The per-app log of Drive activity |
| **DLP** | Data-loss-prevention rules on Drive content |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating Drive exfil in a case | **Drive & Docs Audit → for DFIR** |
| The takeover / insider identity | **Workspace → Login & Auth Audit** · **Google → 01 Google Identities** |
| Mass-download exfil end to end | **Workspace → Playbooks → Mass Drive Exfiltration** |
| An app with Drive scopes reading files | **Workspace → OAuth & Third-Party Apps** |

## Resources

- Drive audit log — https://support.google.com/a/answer/4579696
- Reports API events (drive) — https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list/drive-event-names
- Drive API permissions — https://developers.google.com/drive/api/reference/rest/v3/permissions
- Sharing settings — https://support.google.com/a/answer/60781
