# Email Forensics

**Scope boundary (read this first):** this note has three layers, and they don't get equal depth on purpose. **Layer 1 — local Outlook artifacts sitting on this Windows host (OST/PST/NST files, autocomplete cache, deleted-item recovery)** is this note's core job and gets full host-forensics depth, matching the rest of this module. **Layer 2 — on-premises Exchange Server (the EDB/STM database, `eseutil`, mailbox export/import cmdlets)** gets real but somewhat lighter coverage, since it's server-side but still a classic on-host/on-prem artifact an analyst may have to touch directly. **Layer 3 — Microsoft 365 (Exchange Online, UAL, Extractor Suite) and Google Workspace (Gmail, Vault)** is deliberately brief and cross-linked, not re-derived — that depth already lives in `Cloud/Microsoft/M365/Exchange Online/` and `Cloud/Google/Google Workspace/Gmail/`. This mirrors the same boundary note 13 (Cloud Storage Artifacts) draws for OneDrive/Google Drive/Box/Dropbox: **Windows/ owns the "evidence on disk" lens, Cloud/ owns the "server-side API/admin-log" lens**, and this note is where email specifically crosses that line.

Email is one of the highest-value evidence sources in almost every engagement — BEC, phishing-delivery, insider data theft, and harassment/HR cases all turn on what's provable from a mailbox. The catch is that "the mailbox" can mean up to four different things depending on where the investigation lands: a local OST/PST cache on a laptop, an on-prem Exchange Server database, an M365 cloud mailbox, or a Google Workspace mailbox — and each has a completely different collection path.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [OST vs. PST vs. NST](#ost-vs-pst-vs-nst)
- [Underlying File Format](#underlying-file-format)
- [Deleted Item Recovery Within OST/PST](#deleted-item-recovery-within-ostpst)
- [Attachment Recovery](#attachment-recovery)
- [Local Artifacts Beyond the OST/PST File](#local-artifacts-beyond-the-ostpst-file)
- [On-Premises Exchange Server: EDB/STM/ESE](#on-premises-exchange-server-edbstmese)
- [Mailbox Export/Import: New-MailboxExportRequest, ExMerge, Compliance Search](#mailbox-exportimport-new-mailboxexportrequest-exmerge-compliance-search)
- [M365: UAL + Extractor Suite (Deferred)](#m365-ual--extractor-suite-deferred)
- [Google Workspace Vault (Deferred)](#google-workspace-vault-deferred)
- [Webmail & Mobile-Mail Collection](#webmail--mobile-mail-collection)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage across the three layers this note covers. **Layer 1 (local OST/PST/NST) is pure native PowerShell** — these are proprietary binary formats, so the cmdlets below only locate/hash/enumerate, they don't parse message content. **Layer 2 (on-prem Exchange) requires the Exchange Management Shell** — `Get-MailboxExportRequest` is an on-prem Exchange cmdlet, not part of base Windows PowerShell, and it does not exist against Exchange Online. **Layer 3 (M365) requires the `ExchangeOnlineManagement` module, installed and authenticated** — `Search-UnifiedAuditLog` is not built into base PowerShell either; full query depth lives in `Cloud/Microsoft/M365/Exchange Online/`.

```powershell
# Locate OST/PST/NST under both the legacy and modern default paths - confirm which convention is actually populated on this host
Get-ChildItem -Path "$env:LocalAppData\Microsoft\Outlook","$env:UserProfile\Documents\Outlook Files" -Include *.ost,*.pst,*.nst -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime, CreationTime

# Full-volume sweep - a PST is portable, so it may have been manually relocated anywhere on disk (or off it)
Get-ChildItem -Path C:\ -Include *.ost,*.pst,*.nst -Recurse -Force -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime

# Hash every located mail-store file before touching/copying it - chain of custody on a proprietary binary container
Get-ChildItem -Path "$env:LocalAppData\Microsoft\Outlook","$env:UserProfile\Documents\Outlook Files" -Include *.ost,*.pst -Recurse -ErrorAction SilentlyContinue |
    Get-FileHash -Algorithm SHA256 | Select-Object Path, Hash

# Legacy autocomplete/nickname cache file - direct, low-effort relationship-mapping artifact; absence doesn't rule out a newer, non-.NK2 storage mechanism
Get-ChildItem -Path "$env:AppData\Microsoft\Outlook" -Filter *.nk2 -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime

# On-prem Exchange only - requires Exchange Management Shell run against the Exchange server, not base Windows PowerShell, and has no Exchange Online equivalent
Get-MailboxExportRequest | Select-Object Name, Mailbox, Status, CreatedTime

# M365 only - requires Install-Module ExchangeOnlineManagement and Connect-ExchangeOnline first; see Cloud/ for full UAL depth
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -RecordType ExchangeItem -Operations MailItemsAccessed,SoftDelete,HardDelete |
    Select-Object CreationDate, UserIds, Operations, AuditData
```

## OST vs. PST vs. NST

Getting these three file types straight is foundational — they look similar (same file-format family, similar extensions) but represent forensically different things.

| Format | What it is | Portable/standalone? | Typical trigger |
|---|---|---|---|
| **PST** (Personal Storage Table) | The original Outlook local-storage format — a self-contained file holding a full local copy of mail, calendar, contacts, and (per the FOR500 index) group-chat data | **Yes** — a PST is a durable, exportable local copy, not tied to a live server connection. A PST found on disk can be examined in isolation, with nothing else needed | Historically the default for POP3/IMAP accounts, or any manually created "Personal Folders" / archive set |
| **OST** (Offline Storage Table) | The modern default for Exchange/M365 accounts running in **Cached Exchange Mode** — a **local cache** of the server-side mailbox | **No** — an OST is structurally tied to the specific mailbox it caches and generally cannot be opened standalone against a different mailbox without special recovery tooling | Any Exchange/M365 account added to Outlook with Cached Exchange Mode on (the modern default) |
| **NST** (Notes Storage Table) | A lesser-known local file backing Outlook's "Notes" module (a sticky-notes-style feature) | Narrower artifact than OST/PST — I don't have high confidence in how prevalent or forensically central NST evidence still is in current Outlook deployments; treat it as worth checking when Notes content is specifically relevant to the case, not as a routine first-priority pull | Present alongside an Exchange/M365 profile that has ever used the Notes feature |

🔴 **The OST vs. PST distinction is the single most important thing to get right in this section.** A PST is a portable archive an analyst can pick up and examine anywhere. An OST is a live cache — and that cache-vs-archive distinction has a direct forensic payoff: **an OST on disk can reveal recent mailbox content even after server-side retention has purged it.** This is the exact same "local cache outlived server retention" pattern established in note 13 for OneDrive/Google Drive/Box/Dropbox sync databases — a client-side cache surviving past what the server-side record still shows. Don't skip pulling the OST just because the case looks server-side/M365-centric; it may hold mail the server no longer does.

**Default locations — hedge on exact current path.** Microsoft has shifted the default OST/PST storage location across Outlook versions, and I don't have full confidence in which convention applies to a given build without confirming against the target host:

| Convention | Path |
|---|---|
| Legacy / commonly cited default | `%UserProfile%\Documents\Outlook Files\` |
| Modern / more recent default | `%LocalAppData%\Microsoft\Outlook\` |

Confirm which one is actually populated on the host in front of you rather than assuming — it's also entirely possible for a user to have manually relocated a PST anywhere on disk (or onto removable/network storage), so a filesystem-wide search for `*.ost`/`*.pst`/`*.nst` extensions is worth running regardless of which default path you check first.

### PowerShell

To confirm which default-path convention is actually populated on this host before assuming either one:

```powershell
Test-Path "$env:LocalAppData\Microsoft\Outlook"
Test-Path "$env:UserProfile\Documents\Outlook Files"
```

To break out what was found by extension, so OST/PST/NST counts are visible at a glance:

```powershell
Get-ChildItem -Path "$env:LocalAppData\Microsoft\Outlook","$env:UserProfile\Documents\Outlook Files" -Recurse -ErrorAction SilentlyContinue |
    Group-Object Extension | Select-Object Name, Count
```

## Underlying File Format

Both OST and PST use a Microsoft proprietary structured-storage-style compound file format — a structured binary container, not a simple flat text or delimited file. This is conceptually the same idea as the ESE-based structured storage underlying `WebCacheV01.dat`/`spartan.edb` covered in the Internet Explorer & Legacy Edge note (note 14 subfolder): a purpose-built internal filesystem-within-a-file, organized into internal "streams"/objects rather than into rows a generic parser can read off the bat.

**Practical consequence:** generic file-carving or plain-text string search across an OST/PST *can* work for basic string-recovery (email addresses, keywords, fragments of message bodies frequently show up as recoverable plaintext strings even in a damaged or partially-recovered container), but **full-fidelity parsing — individual emails reconstructed with correct headers, folder structure, and attachments intact — requires PST/OST-aware tooling** (see Tooling below). Don't rely on a raw strings pass as a substitute for proper parsing when the case needs message-level fidelity (exact sender/recipient, exact send time, exact folder location).

### PowerShell

For a raw plaintext strings pass across the container, useful only for quick lead-generation (recoverable email addresses/fragments), not a substitute for OST/PST-aware parsing:

```powershell
Select-String -Path "C:\Evidence\user.ost" -Pattern '[\w\.-]+@[\w\.-]+\.\w+' -Encoding Unicode | Select-Object -First 50
```

## Deleted Item Recovery Within OST/PST

Two distinct recovery tiers exist inside an OST/PST, and it's worth keeping them separate when briefing a case:

| Tier | What it is | Recoverable? |
|---|---|---|
| **Deleted Items folder** | Outlook's own visible "Deleted Items" folder — a normal folder *within* the OST/PST structure, functionally the email-world analogue of the Windows Recycle Bin (note 08, Deleted Items and File Existence) | Fully recoverable — it's just sitting in a visible folder, open Outlook (or a parsing tool) and look |
| **Purged from Deleted Items** | Items removed even from the Deleted Items folder | May still be recoverable from the file's own **unallocated internal space** — the compound-file container doesn't necessarily zero out a deleted item's storage the instant it's removed from the folder index, similar in spirit to SQLite's deleted-row-recovery concept (rows marked free but not immediately overwritten) |

The second tier is meaningfully less certain than the first — whether a purged item is actually recoverable depends on how much subsequent write activity has occurred in the file since the purge (new mail arriving, other items being added, can overwrite the freed space). Treat "purged from Deleted Items" as a lead worth attempting with dedicated recovery/carving tooling rather than a guaranteed win, and cross-reference note 08 for the general Recycle Bin/deleted-item evidentiary pattern this parallels.

## Attachment Recovery

Attachments embedded within an OST/PST's compound-file structure can sometimes be recovered even when the parent email itself is damaged or only partially recoverable — the attachment is its own internal stream/object within the container, and dedicated PST/OST parsing tools generally handle attachment extraction as a first-class feature (see Tooling), not an afterthought.

**Fallback when the container itself is corrupted:** a generic file-carving pass across the raw OST/PST, carving for known file-header magic-byte signatures, can recover embedded attachments even when neither Outlook nor a PST-parsing tool can open the file at all:

| Signature | Recovers |
|---|---|
| `PK\x03\x04` | Embedded ZIP-based formats — modern Office documents (.docx/.xlsx/.pptx are ZIP containers), plain .zip attachments |
| `%PDF` | PDF attachments |
| (standard signature table) | Any other file-carving signature relevant to the case — same general-carving methodology covered under NTFS file-header carving in NTFS/07 |

This is the same carving methodology NTFS/07 (File Deletion Mechanics) already covers for file-header-based recovery generally — applied here to attachment content buried inside a damaged compound-file container instead of unallocated disk clusters.

## Local Artifacts Beyond the OST/PST File

Two categories worth checking beyond the mail store itself:

**MRU/registry artifacts specific to Outlook** — beyond what note 07 (File and Folder Opening) already covers generically for MRU/recent-file behavior across applications, I don't have confident knowledge of Outlook-specific registry artifacts materially beyond that general coverage. Rather than speculate, treat note 07's generic MRU/opened-file coverage as the operative reference here and check it first; if a case turns up an Outlook-specific registry artifact worth documenting, it belongs as an addition to that note rather than duplicated here.

**Autocomplete/nickname cache** — Outlook maintains a cache of frequently- and recently-emailed contacts that powers the auto-suggest behavior when composing a new message's To/Cc line. Historically this lived in a standalone **`.NK2`** file (legacy Outlook versions); more recent Outlook builds have moved this into a different internal mechanism (commonly referenced as an autocomplete stream stored within the mailbox/profile itself rather than a standalone file) — I don't have full confidence in the exact current storage mechanism across the newest Outlook builds, so confirm against the version in front of you rather than assuming `.NK2` is still how it's stored.

🔴 Whatever the exact current storage mechanism, the forensic value is the same: **the autocomplete/nickname cache is a direct, low-effort relationship-mapping artifact.** It surfaces who the mailbox owner has actually emailed, independent of what's currently in Sent Items (an entry can persist after the corresponding sent mail is deleted) — useful for quickly establishing whether communication occurred with an unexpected or suspicious external contact without needing to parse the full mail store.

### PowerShell

To locate and hash any legacy `.NK2` file for chain of custody before further handling; a miss here doesn't rule out a newer, non-file-based autocomplete cache (see note 07 for the general MRU pattern this sits alongside):

```powershell
Get-ChildItem -Path "$env:AppData\Microsoft\Outlook" -Filter *.nk2 -Recurse -ErrorAction SilentlyContinue |
    Get-FileHash -Algorithm SHA256 | Select-Object Path, Hash
```

## On-Premises Exchange Server: EDB/STM/ESE

Distinct from Exchange **Online**/M365 (Cloud/'s territory, Layer 3 below) — this section covers the **on-premises Exchange Server product**, which an analyst may still encounter directly in a legacy environment or a hybrid on-prem/M365 tenant, even in an otherwise cloud-centric investigation.

On-prem Exchange Server stores mailbox data in an **EDB** (Exchange Database) file — an **ESE**-based database, the same underlying Extensible Storage Engine that backs `WebCacheV01.dat`/`spartan.edb` (Internet Explorer & Legacy Edge note) and `NTDS.dit` (Active Directory). Cross-reference those notes for the general shape of ESE internals rather than re-deriving them here.

**The EDB/STM split — a version boundary worth getting right, stated with appropriate hedge:** older Exchange versions held mailbox content across **two** files — the EDB (MAPI-formatted content) plus a companion **STM** (Streaming Media file, holding MIME-formatted internet-mail-format content separately). My understanding is Microsoft deprecated this split starting around **Exchange Server 2007**, consolidating all mailbox content into a single unified EDB from that point forward — but confirm the exact version boundary against current Microsoft documentation before asserting it in a report, since I'm not fully certain of the precise cutoff.

| Artifact | Older Exchange (pre-2007-era split) | Exchange 2007+ |
|---|---|---|
| MAPI-formatted content | EDB | Unified EDB |
| MIME/internet-mail-formatted content | Separate STM file | Unified EDB (STM folded in) |

**Tools:**

| Tool | Use | Note |
|---|---|---|
| **`eseutil`** | Exchange-specific ESE database utility — repair/recovery of a dirty/inconsistent EDB, integrity checks, defragmentation | I believe this is the Exchange-branded counterpart to the more general `esentutl.exe` covered in the Internet Explorer & Legacy Edge note (both operate against ESE databases), but I'm not fully certain whether they're literally the same binary under two names or genuinely distinct utilities with overlapping purpose — confirm before asserting equivalence in a report |
| **`New-MailboxExportRequest`** / legacy **ExMerge** | Extracting individual mailbox content from a live/attached on-prem Exchange database — see next section | |

### PowerShell

To enumerate mailbox databases and their EDB file paths/sizes; **requires the Exchange Management Shell run on or against the Exchange server** — this is Exchange's own PowerShell snap-in, not base Windows PowerShell, and it isn't present on a generic host:

```powershell
Get-MailboxDatabase -Status | Select-Object Name, EdbFilePath, DatabaseSize, Mounted
```

## Mailbox Export/Import: New-MailboxExportRequest, ExMerge, Compliance Search

These are the practical collection mechanisms an analyst actually invokes to pull mailbox content out of on-prem Exchange (and, for the last one, out of M365) — named explicitly because the FOR500 index calls them out as a distinct, testable topic.

| Mechanism | What it does | Era / status |
|---|---|---|
| **`New-MailboxExportRequest`** | Modern on-prem Exchange PowerShell cmdlet — exports a mailbox (or a filtered subset of it) to a PST file. **This is the direction DFIR typically needs** — pulling mailbox content out for preservation/analysis | Current, PowerShell-based |
| **`New-MailboxImportRequest`** | The inverse — imports a PST's content into a mailbox | Current, PowerShell-based; less commonly the DFIR-relevant direction, but named in the FOR500 index alongside the export cmdlet |
| **ExMerge** | Older GUI/CLI tool that performed the same export/merge job, predecessor to the modern PowerShell cmdlets | Largely superseded, but may still appear in older environments or in documentation/runbooks that haven't been updated |
| **Compliance Search** | A Microsoft Purview/M365 Compliance-center feature for searching across mailboxes at scale (eDiscovery-style) | **Genuinely M365/cloud-side** — this is the bridge point where this note defers to Cloud/'s coverage. Compliance Search operates against Exchange Online mailboxes through the Purview compliance portal, not against an on-prem EDB directly; for its full mechanics (search syntax, holds, export), see the Exchange Online notes cross-linked below rather than expecting depth on it here |

🔴 Execution of `New-MailboxExportRequest`/ExMerge on an Exchange server outside a documented IT/legal-hold process is worth flagging on its own — see Red Flags below and cross-reference note 06 (Prefetch/ShimCache/Amcache) for execution-evidence of these tools having run on the server itself.

### PowerShell

To pull the full statistics once an export request has been flagged (Hunt Evil above lists them) — destination path, status detail, duration — to establish exactly what was exported and where it landed; **Exchange Management Shell only, on-prem Exchange, no Exchange Online equivalent**:

```powershell
Get-MailboxExportRequest | Get-MailboxExportRequestStatistics | Select-Object Name, SourceAlias, FilePath, StatusDetail, OverallDuration
```

## M365: UAL + Extractor Suite (Deferred)

**This section is deliberately brief.** Full mechanics — UAL schema, `MailItemsAccessed`, inbox-rule/forwarding hunting, message trace, delete-state recoverability — live in `Cloud/Microsoft/M365/Exchange Online/Exchange Online for DFIR.md` and `What is Exchange Online.md`. Read those for depth; this note's job is only to name that this evidence source exists and point there, exactly like note 13's pattern for cloud-storage sync clients.

The **Unified Audit Log (UAL)** is the M365-wide audit trail, queryable via `Search-UnifiedAuditLog` or the Purview compliance portal, and it's the primary evidence source for mailbox activity once a mailbox has moved to Exchange Online (or the investigation needs to correlate Exchange with SharePoint/OneDrive/Azure AD activity in the same tenant).

The **Microsoft 365 Extractor Suite** is a known DFIR-community PowerShell-based tool for pulling M365 audit/UAL data (and related M365 forensic artifacts) in bulk, outside of manually paging through `Search-UnifiedAuditLog` results — I have moderate but not full confidence in its exact current feature set and maintenance status, so verify against the tool's current documentation/repository before relying on a specific capability claim. For the actual field-level UAL Event ID/schema depth this tool is pulling, forward-reference the Cloud/ Exchange Online note above.

### PowerShell

For setup only; `Search-UnifiedAuditLog` is not part of base PowerShell, it ships in the `ExchangeOnlineManagement` module and requires an authenticated session against the tenant. Full query syntax/schema depth is deliberately not re-derived here — see `Cloud/Microsoft/M365/Exchange Online/` for that:

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Connect-ExchangeOnline -UserPrincipalName analyst@tenant.onmicrosoft.com
```

## Google Workspace Vault (Deferred)

Same brief, deferred treatment as the M365 section above. **Vault** is Google Workspace's e-discovery / legal-hold / audit tool, covering Gmail and other Workspace content — it supports placing a hold on a mailbox (preserving content even past a user's own deletion) and exporting content for legal/investigative purposes.

Full Gmail-specific investigation mechanics — the settings-vs-audit-log split, filters/forwarding/delegation as the mailbox-persistence evidence class, Email Log Search, Security Investigation Tool — live in `Cloud/Google/Google Workspace/Gmail/Gmail for DFIR.md` and `What is Gmail (for DFIR).md`. This note doesn't re-derive that; go there for depth.

## Webmail & Mobile-Mail Collection

**Webmail** (Outlook Web Access/OWA, the Gmail web interface, and equivalents) accessed through a browser on this host leaves the exact browser-artifact trail the note 14 Chromium/Firefox notes already cover in full — History (with the OWA/Gmail URL and, depending on transition type, evidence of deliberate navigation), Cookies (session tokens — see the Chromium note's session-hijacking cross-reference to MITRE ATT&CK T1539), and IndexedDB/Local Storage (some webmail clients cache message content client-side for offline/performance reasons, landing in the same LevelDB-based storage the Chromium note covers). This note doesn't re-derive any of that — a webmail session viewed in Chrome or Edge on this host produces exactly the History/Cookies/IndexedDB evidence those notes already document; go there.

**Mobile-mail collection** — email synced to a phone (native mail app, Outlook mobile, Gmail app) — is **out of scope for this Windows-host-focused module.** This note's job is what's forensically recoverable from a Windows host; mobile device forensics (extraction methods, mobile-specific mail-app artifact locations, MDM-based collection) is a genuinely separate discipline with its own tooling and isn't attempted here. Note the scope boundary explicitly rather than trying to fake depth on it.

## Tooling

| Tool | Use |
|---|---|
| **libpff** | Open-source library for parsing PFF-family formats (OST/PST) — the community-standard foundation a lot of open-source PST/OST tooling is built on |
| **readpst** (part of libpff's ecosystem) | Open-source command-line PST/OST-to-mbox/individual-message extraction — a practical free option for bulk extraction when a commercial suite isn't available |
| **Autopsy / FTK / X-Ways / AXIOM** | Commercial/semi-commercial forensic suites — all generically relevant across this module (per the FOR500 index's tool-mapping convention) and all include OST/PST parsing (message-level reconstruction, attachment extraction, deleted-item recovery) as a standard feature |
| **Kernel/Stellar-style commercial PST-repair tools** | Commercial PST/OST repair-and-recovery products exist in this space (Kernel and Stellar are names commonly associated with this niche), but I don't have high enough confidence in current product names/capabilities to cite a specific SKU — verify what's current before relying on a named product in a report |
| **`eseutil`** | Exchange-specific ESE repair/recovery utility for a dirty on-prem EDB — see On-Premises Exchange Server above |
| **Eric Zimmerman's tools** | Honest gap, consistent with this module's other tooling sections: EZ's suite (Registry Explorer, MFTECmd, JLECmd, PECmd, LECmd, RECmd) is registry/EVTX/filesystem-focused — I'm not aware of an EZ tool dedicated to OST/PST parsing. Don't expect coverage here that doesn't exist |
| **Microsoft 365 Extractor Suite** | M365 UAL/audit bulk-extraction tool — see M365 section above |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Mass email deletion or bulk mailbox export activity in a short window preceding a resignation/departure | Classic insider-exfiltration pattern — the email-world parallel to note 13's cloud-storage-sync red flags for the same HR-timing signature |
| OST content revealing mailbox activity no longer present server-side | The "local cache outlived server retention" pattern — retention purge vs. local cache mismatch, corroborate timeline gaps between the local OST and server-side UAL/audit evidence |
| Autocomplete/nickname cache revealing communication with an unexpected or suspicious external contact | Direct, low-effort relationship-mapping signal — worth checking early in insider-threat or BEC-adjacent cases |
| Evidence of `New-MailboxExportRequest`/ExMerge execution on an Exchange server outside a documented IT/legal-hold process | Suggests bulk mailbox export occurred outside normal process — cross-reference note 06 (Prefetch/ShimCache/Amcache) for execution evidence of these tools having run |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Exchange Online mailbox investigation — UAL, inbox rules, forwarding, MailItemsAccessed, delete-state recoverability | `Cloud/Microsoft/M365/Exchange Online/Exchange Online for DFIR.md` + `What is Exchange Online.md` |
| Gmail/Workspace mailbox investigation — settings-vs-audit-log split, filters/forwarding/delegation, ELS, SIT | `Cloud/Google/Google Workspace/Gmail/Gmail for DFIR.md` + `What is Gmail (for DFIR).md` |
| The email-world analogue of the Windows Recycle Bin (Deleted Items folder) | Deleted Items and File Existence (note 08) |
| The "local cache/database entry outlives what the server currently shows" evidentiary pattern, applied to sync clients | Cloud Storage Artifacts (Local Evidence) (note 13) |
| Browser artifact trail for webmail sessions (History, Cookies, IndexedDB) | Web Browser Forensics — Chromium and Firefox notes (note 14 subfolder) |
| Execution evidence for export/collection tools run on a host or server | Evidence of Program Execution — Prefetch, ShimCache, Amcache (note 06 subfolder) |
| Generic MRU/recent-item artifacts beyond Outlook-specific ones | File and Folder Opening (User Activity) (note 07) |
| ESE database internals shared with EDB (WebCacheV01.dat, spartan.edb, NTDS.dit) | Internet Explorer & Legacy Edge (note 14 subfolder) |
| NTFS file-header carving methodology, applied here to attachment recovery from a damaged container | NTFS/07 - File Deletion Mechanics |

## Resources

- `SANS FOR500 Index _final.xlsx` (bundled in this folder) — coverage checklist confirming this note's expanded email-forensics scope (OST/PST/NST, EDB/STM, export cmdlets, UAL/Extractor Suite, Vault, webmail) — cross-referenced for gaps, not a prose source
- libpff — https://github.com/libyal/libpff
- readpst — part of the libpff project's tooling ecosystem
- Microsoft Learn: `eseutil` reference — check Microsoft Learn directly for the current stable URL, documentation has been reorganized across Exchange releases
- Microsoft Learn: `New-MailboxExportRequest` / `New-MailboxImportRequest` reference — check Microsoft Learn directly for the current stable URL
- MITRE ATT&CK T1114 (Email Collection) — https://attack.mitre.org/techniques/T1114/
