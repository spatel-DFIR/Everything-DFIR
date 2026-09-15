# OneDrive

**Scope boundary (read this first):** this note covers only what's forensically recoverable from **the local Windows host** — filesystem, registry, local databases, client-side logs — when the OneDrive Desktop sync client has been installed and used. It does **not** cover OneDrive/SharePoint server-side audit logs, sharing/permissions APIs, Microsoft Graph activity, or M365 admin-console investigation — that's `Cloud/Microsoft/M365/SharePoint & OneDrive/SharePoint & OneDrive for DFIR.md`'s job. Per the module's structure decision (PLANNING.md §3, R3): **Windows/ owns the "evidence on disk" lens, Cloud/ owns the "server-side API/admin-log" lens** for the same service. Use both together — this note tells you what touched *this host*; the Cloud/ note tells you what the account did *in the cloud*, including from other devices this note can't see.

OneDrive is the highest-value cloud-storage sync client to know cold on Windows because it ships **built into the OS** from Windows 10 onward and is very frequently present — and configured with a business/M365 account — on corporate-issued machines whether or not the organization intended to allow it as a sanctioned data channel. That ubiquity cuts both ways: it's a legitimate productivity tool, and it's also one of the most common **insider-exfiltration channels** investigators encounter, because moving a file into a synced folder looks identical, from the file-copy operation's perspective, to moving it anywhere else on disk.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Sync Root & Folder Structure](#sync-root--folder-structure)
- [Known Folder Move (KFM)](#known-folder-move-kfm)
- [The Local Sync Database](#the-local-sync-database)
- [Registry Artifacts](#registry-artifacts)
- [Files On-Demand: Placeholders vs. Hydrated Files](#files-on-demand-placeholders-vs-hydrated-files)
- [Client-Side Logs](#client-side-logs)
- [Browser-Adjacent Evidence](#browser-adjacent-evidence)
- [Red Flags](#red-flags)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage against the registry and sync-root filesystem before any SQLite tool or ODL log converter comes out — no third-party modules required. PowerShell can enumerate account/tenant registry keys, sync-root folders, and file-attribute/reparse-point state natively; it cannot query the sync database's internal schema (no built-in SQLite cmdlet) or decode `.odl`/`.odlgz` logs — both require the tooling covered later in this note.

```powershell
# Every configured account/tenant slot on this host - Personal, Business1, Business2, ...
Get-ChildItem 'HKCU:\Software\Microsoft\OneDrive\Accounts' -ErrorAction SilentlyContinue |
    ForEach-Object { Get-ItemProperty $_.PSPath | Select-Object @{N='AccountSlot';E={$_.PSChildName}}, UserFolder, UserEmail, CID }

# Personal + Business account slots both present = classic exfiltration-vector configuration (see Red Flags)
$slots = (Get-ChildItem 'HKCU:\Software\Microsoft\OneDrive\Accounts' -ErrorAction SilentlyContinue).PSChildName
if (($slots -contains 'Personal') -and ($slots -match '^Business')) { "Personal + Business sync both configured: $slots" }

# Which sync root folders actually exist on disk, and their <Organization Name> strings
Get-ChildItem $env:USERPROFILE -Directory -Filter 'OneDrive*' | Select-Object Name, CreationTime, LastWriteTime

# Files added/modified anywhere under a sync root in the last 7 days - a fast exfil/staging-window lead
Get-ChildItem "$env:USERPROFILE\OneDrive*" -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object LastWriteTime -gt (Get-Date).AddDays(-7) |
    Sort-Object LastWriteTime -Descending | Select-Object -First 50 FullName, LastWriteTime, Length

# Reparse-point (Files On-Demand placeholder) count vs. fully hydrated file count in the sync tree
Get-ChildItem "$env:USERPROFILE\OneDrive*" -Recurse -File -ErrorAction SilentlyContinue |
    Group-Object { [bool]($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
    Select-Object @{N='IsPlaceholder';E={$_.Name}}, Count

# Client-side log folder recency - a proxy for last confirmed client activity when the sync DB is ambiguous
Get-ChildItem "$env:LocalAppData\Microsoft\OneDrive\logs" -Recurse -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 10 FullName, LastWriteTime

# Is Desktop/Documents actually a KFM reparse point into the OneDrive tree, or an ordinary local folder?
(Get-Item "$env:USERPROFILE\Desktop").Attributes -band [IO.FileAttributes]::ReparsePoint
```

## Sync Root & Folder Structure

| Account type | Default sync root |
|---|---|
| Personal (consumer Microsoft account) | `%UserProfile%\OneDrive` |
| Business / M365 (Entra ID-joined or configured tenant account) | `%UserProfile%\OneDrive - <Organization Name>` |
| Additional business accounts (multiple tenants on one host) | `%UserProfile%\OneDrive - <Organization Name>` repeated per tenant, each its own root |

🔴 **The `<Organization Name>` string in the folder path is itself informative.** It's populated from the tenant's display name at the time the account was configured, so a bare directory listing of a user profile — even without touching the registry or any sync database — can reveal which M365 tenant(s) a machine has been connected to. Useful for quickly scoping which organizations have (or had) a sync relationship with a host during triage, before deeper artifacts are pulled.

The presence of **both** a `OneDrive` (personal) folder and a `OneDrive - <Org>` (business) folder on the same profile means a personal consumer account and a corporate account are syncing side by side on the same machine — see Red Flags below, this is a classic exfiltration-vector configuration on a machine that should only have business sync enabled.

### PowerShell

Enumerate every sync-root folder on the profile and its `<Organization Name>` suffix:

```powershell
Get-ChildItem $env:USERPROFILE -Directory -Filter 'OneDrive*' | Select-Object Name, CreationTime, LastWriteTime
```

Flag personal and business roots coexisting on the same profile — the folder-structure equivalent of the registry check in Hunt Evil:

```powershell
$roots = Get-ChildItem $env:USERPROFILE -Directory -Filter 'OneDrive*' | Select-Object -ExpandProperty Name
if (($roots -contains 'OneDrive') -and ($roots -match '^OneDrive - ')) { "Personal + Business sync roots both present: $roots" }
```

Sweep an estate for hosts with a personal OneDrive root present — a policy-violation indicator worth aggregating across many machines at once:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    if (Test-Path "$env:USERPROFILE\OneDrive") { [PSCustomObject]@{ ComputerName = $env:COMPUTERNAME; PersonalRootPresent = $true } }
} | Export-Csv C:\hunt\onedrive_personal_root_sweep.csv -NoTypeInformation
```

## Known Folder Move (KFM)

Known Folder Move is a policy-driven OneDrive feature (configurable via GPO/Intune, but also user-initiated) that **redirects the Desktop, Documents, and Pictures folders into the OneDrive sync root**, so that `%UserProfile%\Desktop` and `%UserProfile%\Documents` stop being ordinary local folders and become symlinked/junction-redirected paths pointing inside `%UserProfile%\OneDrive - <Org>\Desktop`, etc.

This is forensically significant for one reason: **it silently changes where "local user activity" artifacts actually live.** Everything note 07 (File and Folder Opening) and note 08 (Deleted Items) describe as living under the Desktop or Documents folder may, on a KFM-enabled host, actually be inside the cloud-synced tree — meaning those files are simultaneously local evidence *and* subject to the sync database's own retention/versioning behavior described below, and potentially subject to cloud-side recovery (Cloud/'s domain) even after local deletion. Before concluding a file is "gone" because it's absent from `%UserProfile%\Documents`, confirm whether KFM is active — check `HKCU\Software\Microsoft\OneDrive\Accounts\<Account>\` for KFM-related values, or simply check whether `Desktop`/`Documents` resolve as reparse points into the OneDrive tree via `dir` or `fsutil reparsepoint query`.

### PowerShell

Confirm whether Desktop/Documents/Pictures are ordinary folders or KFM reparse points into the sync tree:

```powershell
'Desktop', 'Documents', 'Pictures' | ForEach-Object {
    $item = Get-Item "$env:USERPROFILE\$_" -ErrorAction SilentlyContinue
    [PSCustomObject]@{ Folder = $_; IsReparsePoint = [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint); Target = $item.Target }
}
```

Determine where a redirected folder actually resolves to, so note 07/08 artifacts under that name are recognized as cloud-synced rather than purely local:

```powershell
Get-Item "$env:USERPROFILE\Desktop" | Select-Object FullName, LinkType, Target
```

## The Local Sync Database

This is the forensic core of the note: a local cache database the OneDrive sync client maintains to track every file it has synced, independent of the file's current presence on disk.

**Where it lives:**

| Account type | Path |
|---|---|
| Personal | `%LocalAppData%\Microsoft\OneDrive\settings\Personal\` |
| Business (first account) | `%LocalAppData%\Microsoft\OneDrive\settings\Business1\` |
| Additional business accounts | `Business2`, `Business3`, etc. — one numbered folder per additional connected tenant |

**Hedge, stated plainly:** Microsoft has changed the OneDrive sync engine's local database format multiple times across client versions, and the exact current filename and schema is not something I can assert with confidence — do not treat a specific filename below as guaranteed to match the client version on your target host. What's consistently true across the versions I'm aware of:

- Older/legacy OneDrive builds stored sync state in binary `.dat` files (e.g. per-account metadata files, sometimes GUID-named) under this `settings` path.
- More recent OneDrive builds use a **SQLite-based cache database** in the same general `settings\<Personal|Business1>\` location — historically referenced in community research as something like `ObjectsCache.db` or a similarly-named cache file, but confirm the actual filename present on the version you're examining rather than assuming a name in advance; simply enumerate the `settings\<Personal|Business1>\` folder and identify which files are SQLite-format (`file` command or a hex/magic-byte check, or just try opening each in DB Browser for SQLite) versus legacy binary `.dat`.

**What this database proves, regardless of exact schema:** a per-file record for every item the client has seen and synced — filename, file size, local-side and cloud-side modification timestamps, current sync status, and typically a cloud "resource ID" / item ID that ties the entry back to the file's identity in Microsoft Graph (useful for pivoting into the Cloud/ side of the investigation with an unambiguous file identifier rather than a filename that could collide).

🔴 **The database entry can outlive the local file.** If a file is deleted from the sync folder — by the user, by an attacker cleaning up, or simply superseded by a later sync — the sync database's record of that file having existed and been synced does not necessarily disappear with it. This makes the sync database a "file was here" artifact in the same evidentiary family as the Recycle Bin or `$LogFile` (see note 08, Deleted Items and File Existence) — a way to establish a file's past presence on the host independent of whether it's still there today. Don't over-claim: exact retention behavior for stale entries varies by client version and hasn't been independently verified here, but the general pattern — cache entries surviving past local file deletion, at least for some retention window — is consistent with how sync-client caches of this kind typically behave.

### PowerShell

Enumerate the `settings\<Personal|Business1>\` folder without assuming a filename, since PowerShell has no built-in SQLite cmdlet to query the database contents directly:

```powershell
Get-ChildItem "$env:LocalAppData\Microsoft\OneDrive\settings" -Recurse -File |
    Select-Object FullName, Length, LastWriteTime
```

Distinguish SQLite-format files from legacy binary `.dat` files by magic-byte check ("SQLite format 3" header), so the right file gets handed to DB Browser for SQLite rather than guessed at:

```powershell
Get-ChildItem "$env:LocalAppData\Microsoft\OneDrive\settings" -Recurse -File | ForEach-Object {
    $header = [System.Text.Encoding]::ASCII.GetString((Get-Content $_.FullName -AsByteStream -TotalCount 16 -ErrorAction SilentlyContinue))
    [PSCustomObject]@{ FullName = $_.FullName; IsSQLite = $header -like 'SQLite format 3*' }
}
```

## Registry Artifacts

`HKCU\Software\Microsoft\OneDrive\Accounts\<Personal|Business1|...>` (the `SyncEngines`/`Accounts` structure varies somewhat by client version — enumerate the subkeys under `HKCU\Software\Microsoft\OneDrive` rather than assuming exact key names) tracks each configured sync account on the host:

| Value (typical) | Meaning |
|---|---|
| `UserFolder` | The local sync root path for this account — corroborates/confirms the folder-structure evidence above |
| `UserEmail` | The email address of the connected account — direct account attribution |
| Service/endpoint-related values | Which OneDrive service endpoint (consumer vs. commercial/M365) the account authenticates against |
| `CID` | **Client ID** — a persistent identifier tied to the specific Microsoft account, not to the local Windows profile |
| Business-tenant values (Business accounts only) | Tenant-related identifiers when the account is an M365/business connection |

🔴 **`CID` is worth remembering specifically:** because it's tied to the cloud account rather than the local profile, it survives a re-image or a profile migration and lets you attribute local sync activity to a specific cloud account even after the host itself has been rebuilt — useful for tying an older forensic image's sync activity to the same account seen on a later image of the same (or a different) machine. A `CID` value that **changes** on a host between two points in time, where previously it was stable, means a different account was connected to that sync engine slot — see Red Flags.

See Registry Forensics Fundamentals (note 04) for `NTUSER.DAT`/hive-access mechanics generally — these are ordinary `HKCU` values, no special hive-loading considerations beyond the standard live-vs-offline distinction.

### PowerShell

Enumerate whichever account subkeys actually exist under `HKCU\Software\Microsoft\OneDrive`, rather than assuming `Personal` or `Business1` names:

```powershell
Get-ChildItem 'HKCU:\Software\Microsoft\OneDrive' -Recurse -ErrorAction SilentlyContinue | Select-Object PSPath, PSChildName
```

Sweep an estate for `CID` values, then group to spot the same `CID` appearing on multiple machines (account shared/reused across hosts) or flag hosts where it's absent entirely:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
$results = Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-ChildItem 'HKCU:\Software\Microsoft\OneDrive\Accounts' -ErrorAction SilentlyContinue |
        ForEach-Object { Get-ItemProperty $_.PSPath | Select-Object @{N='ComputerName'; E={ $env:COMPUTERNAME }}, @{N='AccountSlot'; E={ $_.PSChildName }}, UserEmail, CID }
}
$results | Group-Object CID | Where-Object Count -gt 1 | Select-Object Name, Count
$results | Export-Csv C:\hunt\onedrive_cid_sweep.csv -NoTypeInformation
```

## Files On-Demand: Placeholders vs. Hydrated Files

**OS-version floor: Windows 10 version 1709 (Fall Creators Update) and later.** Files On-Demand is the feature that lets a file *appear* present in File Explorer without its actual content having ever been downloaded to disk — the file exists as a **placeholder**, an NTFS reparse point that Explorer renders with a full name, icon, and metadata, but which contains effectively none of the file's actual bytes until the user (or a process) opens it and triggers hydration.

| State | What's actually on disk | How it looks in Explorer |
|---|---|---|
| **Placeholder (cloud-only / dehydrated)** | Reparse point only — near-zero local content | Identical file listing to a real file; cloud icon overlay if the user looks closely |
| **Partially hydrated** | Some content cached locally (can happen with partial reads) | Same as above |
| **Fully hydrated (locally available)** | Complete file content on disk | Same listing, "always available" icon overlay |

🔴 **This is the single most important pitfall in this note.** A directory listing, a Shell Bag entry, a Jump List reference, or any other artifact that merely shows a file's *name* present under the OneDrive tree does **not** prove the file's content was ever actually present or accessible on that host. Under Files On-Demand, a placeholder can sit in a folder indefinitely, fully visible to every listing-based artifact, without a single byte of the target file ever having been downloaded. Before asserting "this file was on this host" based on a filename showing up in a directory or an artifact that only records names/paths, confirm hydration state.

**How to check hydration state:**

| Method | What it shows |
|---|---|
| `attrib` (on a Files On-Demand-aware system) | Cloud-file attribute flags in the output — a `U` (unpinned/dehydrated, cloud-only placeholder) vs. `P` (pinned, always keep on this device, fully hydrated) style indicator distinguishing placeholder from hydrated state. Confirm the exact flag characters against the OS build you're working on rather than assuming — Microsoft has adjusted `attrib`'s cloud-file flag display across Windows 10/11 builds. |
| `fsutil reparsepoint query <path>` | Confirms whether the file is a reparse point at all (placeholder) versus an ordinary file (hydrated, no reparse tag) |
| File size on disk vs. reported size | A placeholder typically reports its real logical size in Explorer/`dir` but occupies little to no actual allocated disk space — a size/allocation mismatch is a quick tell |

### PowerShell

Perform a reparse-point attribute check per file — the same underlying signal `fsutil reparsepoint query` reports — scriptable across a whole tree:

```powershell
Get-ChildItem "$env:USERPROFILE\OneDrive*" -Recurse -File -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, @{N='IsPlaceholder'; E={ [bool]($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }}
```

Before asserting "this file was accessed on this host" from a filename showing up in Shell Bags, Jump Lists, or RecentDocs (note 07), confirm the file wasn't sitting there as an un-hydrated placeholder:

```powershell
$path = "$env:USERPROFILE\OneDrive - Contoso\Finance\Q4-Report.xlsx"
$item = Get-Item $path -ErrorAction SilentlyContinue
if ($item) { [PSCustomObject]@{ FullName = $item.FullName; IsPlaceholder = [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint); ReportedSize = $item.Length } }
```

## Client-Side Logs

`%LocalAppData%\Microsoft\OneDrive\logs\<Personal|Business1>\` holds the OneDrive client's own operational logs, in a proprietary `.odl` / compressed `.odlgz` format — not human-readable as-is.

Microsoft has historically provided ways to convert these into readable text (a converter has existed under names referenced informally as `ODLViewer` or similar in community discussion); I don't have high confidence in the exact current tool name or whether it remains actively maintained/distributed, so verify tooling availability at investigation time rather than assuming a specific utility is on hand. Whatever the current tool, the payoff is the same: these logs record sync errors, connection/authentication events, and individual file-operation history at a level of verbosity well beyond what the sync database alone captures — worth pulling when the sync database shows *that* something happened but not *why* (e.g., repeated sync failures, throttling, conflict-resolution events).

### PowerShell

Inventory the raw `.odl` and `.odlgz` log files present — since PowerShell cannot decode their proprietary format directly, this is only a triage/collection step ahead of a dedicated converter:

```powershell
Get-ChildItem "$env:LocalAppData\Microsoft\OneDrive\logs" -Recurse -Include '*.odl', '*.odlgz' -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime
```

Bundle the current account's log folder to a case-share for offline conversion, preserving relative paths and timestamps rather than hand-copying files one at a time:

```powershell
Compress-Archive -Path "$env:LocalAppData\Microsoft\OneDrive\logs\*" -DestinationPath "C:\hunt\$env:COMPUTERNAME`_onedrive_logs.zip"
```

## Browser-Adjacent Evidence

Accessing OneDrive/SharePoint through a web browser (rather than the Desktop sync client) leaves its own separate trail — browser history, cache, and IndexedDB/LevelDB storage referencing `onedrive.live.com` / `*.sharepoint.com`. That's real evidence but belongs to the future `14 - Web Browser Forensics/` subfolder's depth, not here — this note is scoped to the Desktop sync client's on-disk footprint.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Mass file deletions visible in the sync database with no corresponding legitimate bulk-delete/reorg business justification | Consistent with anti-forensic cleanup or a bulk-exfil-then-delete pattern; corroborate with the Cloud/ note's server-side delete/download UAL entries for the same account |
| Sync database entries for files that were never actually hydrated on this host (Files On-Demand placeholder-only) being read as "the file was on this host" | The single biggest pitfall in this note — a name/metadata entry is not proof of local content access; confirm hydration state before asserting local presence |
| `CID` (or other account-identifying registry value) changes on a previously-stable sync engine slot | A different cloud account was connected — a classic pattern for an insider swapping in a personal account on a corporate machine, or an attacker repurposing an existing sync configuration |
| Personal OneDrive (`OneDrive` folder, `Personal` settings subfolder) present on a machine that should only have business/M365 sync configured | Policy-violation and exfiltration-vector signal on its own — a personal account sync relationship gives a user (or attacker with access to the user's session) a ready-made channel to move corporate files to a Microsoft consumer account outside organizational control |
| Large volume of recent file additions to the sync folder immediately preceding a resignation/termination date | Classic insider-exfiltration narrative — tie the sync database's file-add timestamps to HR-provided dates and corroborate against the Cloud/ note's `FileSyncDownloadedFull`/upload-side UAL evidence |
| KFM active but not accounted for in the investigation | User-activity artifacts (note 07/08) assumed to be purely local may actually sit inside the cloud-synced tree, with different retention/recovery properties than a genuinely local file |

## Tooling

| Tool | Use |
|---|---|
| **DB Browser for SQLite** | Generic fallback for opening whichever file in the `settings\<Personal|Business1>\` folder turns out to be SQLite-format on the client version you're examining — the safest choice given the schema/filename uncertainty noted above |
| **`fsutil reparsepoint query`** | Confirms placeholder (reparse point) vs. hydrated state for a given file under Files On-Demand |
| **`attrib`** | Quick cloud-file attribute flags (pinned/unpinned) for hydration state at a glance; confirm exact flag meaning against the build in use |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of `HKCU\Software\Microsoft\OneDrive\...` — see Registry Forensics Fundamentals (note 04) for hive-access mechanics |
| **RegRipper** | Plugin-based quick extraction of OneDrive registry keys for rapid triage |
| **A dedicated OneDrive sync-database parser** | I'm not confident there is currently a well-maintained, purpose-built free/open community parser for this artifact comparable to Eric Zimmerman's suite for registry/EVTX artifacts — OneDrive's local database format has changed enough across client versions that community tooling here has historically been less mature and more version-fragile. Verify what's current before relying on a named tool; DB Browser for SQLite is the dependable fallback. |
| **KAPE** | I believe KAPE has (or has had) a OneDrive-related collection target, but I'm not fully certain of its current name/scope — confirm against your KAPE target list rather than assuming, and at minimum hand-target the paths in this note if no matching target exists |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Server-side/M365-admin-log evidence for the same account — audit logs, sharing events, Graph API access, download/exfil confirmation from the cloud side | **SharePoint & OneDrive for DFIR** (`Cloud/Microsoft/M365/SharePoint & OneDrive/SharePoint & OneDrive for DFIR.md`) — this note owns local disk evidence, that note owns everything server-side for the same account |
| Registry hive structure, `NTUSER.DAT` access mechanics used to read the keys in this note | Registry Forensics Fundamentals (note 04) |
| User-activity artifacts (Shell Bags, RecentDocs, LNK files, Jump Lists) that may now live inside a KFM-redirected, cloud-synced folder | File and Folder Opening (User Activity) (note 07) |
| The "database/artifact entry outlives the file" evidentiary pattern, applied to Recycle Bin and other deleted-item artifacts | Deleted Items and File Existence (note 08) |
| Compare/contrast with other Desktop sync clients' local artifacts | Google Drive for Desktop, Box Drive, Dropbox (this subfolder — not yet written) |

## Resources

- Microsoft Learn's OneDrive sync engine / Files On-Demand documentation (general reference — check Microsoft Learn directly for the current stable URL rather than relying on a specific link cited here, as Microsoft has reorganized this documentation across releases)
- MITRE ATT&CK T1567.002 (Exfiltration to Cloud Storage) — https://attack.mitre.org/techniques/T1567/002/
