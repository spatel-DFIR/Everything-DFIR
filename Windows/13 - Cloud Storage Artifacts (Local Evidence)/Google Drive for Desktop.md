# Google Drive for Desktop

**Scope boundary (read this first):** this note covers only what's forensically recoverable from **the local Windows host** — filesystem, registry, local databases, client-side logs — when Google's desktop sync client has been installed and used. It does **not** cover Google Workspace's Drive Audit API, admin-console sharing/permission investigation, or Drive activity events visible only server-side — that's `Cloud/Google/Google Workspace/Drive & Docs Audit/Drive Audit for DFIR.md`'s job. Per the module's structure decision (PLANNING.md §3, R3): **Windows/ owns the "evidence on disk" lens, Cloud/ owns the "server-side API/admin-log" lens** for the same service. Use both together — this note tells you what touched *this host*; the Cloud/ note tells you what the account did *in Drive*, including from other devices or the web UI this note can't see.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Client History & Naming Disambiguation](#client-history--naming-disambiguation)
- [Sync Root & Folder Structure](#sync-root--folder-structure)
- [The Local Cache: DriveFS](#the-local-cache-drivefs)
- [Registry Artifacts](#registry-artifacts)
- [Client-Side Logs](#client-side-logs)
- [Mirror vs. Stream Mode: The Central Forensic Distinction](#mirror-vs-stream-mode-the-central-forensic-distinction)
- [Browser-Adjacent Evidence](#browser-adjacent-evidence)
- [Red Flags](#red-flags)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage before reaching for DB Browser for SQLite or a registry tool — no third-party modules required. PowerShell can enumerate the DriveFS folders/cache, read the registry, and identify SQLite-format files by magic bytes, but it **cannot query inside a SQLite database natively** — that last step still needs DB Browser for SQLite or a scripting module (see Tooling).

```powershell
# Does the DriveFS local cache exist at all, and how recently was it touched - confirms client presence/activity
Get-Item "$env:LocalAppData\Google\DriveFS" -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime

# Per-account subfolders under DriveFS - more than one is a multi-account correlation lead worth chasing
Get-ChildItem "$env:LocalAppData\Google\DriveFS" -Directory -ErrorAction SilentlyContinue |
    Select-Object Name, CreationTime, LastWriteTime

# Raw dump of every value under HKCU\Software\Google\DriveFS - schema isn't fixed across client versions, so enumerate rather than assume specific value names
Get-ChildItem 'HKCU:\Software\Google\DriveFS' -Recurse -ErrorAction SilentlyContinue | Get-ItemProperty

# Is the client running right now (live host only) - StartTime brackets when this session's sync activity began
Get-Process -Name GoogleDriveFS -ErrorAction SilentlyContinue | Select-Object Id, StartTime, Path

# Confirm the default Mirror-mode path actually exists before concluding "no Drive" - root is user-relocatable, don't trust absence alone
Test-Path "$env:UserProfile\Google Drive"

# Files modified in the Mirror-mode sync root in the last 3 days - exfil-window triage; swap path if registry shows a relocated root
Get-ChildItem "$env:UserProfile\Google Drive" -Recurse -ErrorAction SilentlyContinue |
    Where-Object LastWriteTime -gt (Get-Date).AddDays(-3) | Select-Object FullName, LastWriteTime, Length

# Magic-byte check for SQLite-format files inside the DriveFS cache - filenames aren't reliable across client versions, the header is
Get-ChildItem "$env:LocalAppData\Google\DriveFS" -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    $header = Get-Content $_.FullName -Encoding Byte -TotalCount 16 -ErrorAction SilentlyContinue
    if ($header -and [System.Text.Encoding]::ASCII.GetString($header) -like 'SQLite format 3*') { $_.FullName }
}
```

## Client History & Naming Disambiguation

Google has rebranded and re-architected its desktop sync client more times than most competitors, and an analyst can genuinely encounter any of the following depending on the host's age and how recently it was updated. **Get the version identification right before trusting any artifact location below** — paths and formats have shifted across this history, and a stale client on an old image may not match current documentation at all.

| Era / name | Rough character | Notes |
|---|---|---|
| **"Google Drive"** (classic sync client, discontinued ~2018) | Full local mirror only — no cloud-first mode | Oldest variant; may still be found on legacy/never-updated hosts or in older forensic images |
| **"Backup and Sync"** (consumer-focused, discontinued 2021) | Added photo/folder backup on top of classic Drive sync | Consumer-oriented successor; also had a sibling enterprise product ("Drive File Stream") for Workspace accounts during the same era |
| **"Google Drive for Desktop"** (current, unified client) | Merged the consumer and enterprise lines into one client supporting both **Mirror** and **Stream** modes | What you should expect on any actively-maintained Windows 10/11 host today |

🔴 **Do not assume "Google Drive for Desktop" branding means Mirror-mode behavior, and don't assume an old-looking folder name means an old client.** Because Google has reused similar folder/product names across eras, and because Mirror vs. Stream is a *configuration choice within* the current unified client rather than a version distinction, confirm both the installed client version and its configured mode before drawing conclusions from path names alone.

## Sync Root & Folder Structure

| Mode | Default location | Forensic complication |
|---|---|---|
| **Mirror mode** | `%UserProfile%\Google Drive` (default) | **Google Drive for Desktop allows the user to relocate the sync root to an arbitrary path at setup or later** — unlike OneDrive's comparatively fixed `%UserProfile%\OneDrive...` convention. Do not assume the default path; confirm the actual configured root via the registry (below) before concluding Drive isn't in use just because the default folder is absent. |
| **Stream mode** | Virtual drive letter, typically `G:\` by default | The drive letter itself is also user-configurable. The mount is backed by a local cache, not a full mirror — see Mirror vs. Stream below. |

Because the sync root isn't guaranteed to sit at a predictable path, a quick directory-listing pass of the user profile is **not sufficient** to rule out Google Drive usage on a host — confirm via `HKCU\Software\Google\DriveFS` (or the profile's local cache under `%LocalAppData%`) rather than relying on folder presence alone.

### PowerShell

Check the default Mirror-mode path and the presence of a Stream-mode virtual drive before falling back to the registry for a relocated root:

```powershell
Test-Path "$env:UserProfile\Google Drive"
Get-PSDrive -PSProvider FileSystem | Select-Object Name, Root, Used, Free
```

Pull whatever path and root-shaped values exist under the DriveFS key so a relocated Mirror-mode root doesn't get missed by only checking the default location:

```powershell
Get-ChildItem 'HKCU:\Software\Google\DriveFS' -Recurse -ErrorAction SilentlyContinue | Get-ItemProperty | ForEach-Object {
    $_.PSObject.Properties | Where-Object { $_.Name -match 'path|root|dir' -and $_.Name -notmatch '^PS' }
}
```

## The Local Cache: DriveFS

This is the forensic core of the note. `%LocalAppData%\Google\DriveFS\` holds the current unified client's local state, organized into a per-account subfolder structure (numbered and/or GUID-named, depending on client version) — one subfolder per connected Google account on the host.

**Hedge, stated plainly:** Google has changed DriveFS's internal database/cache naming and layout across client versions, and I do not have high confidence in a specific current filename to hand you — do not treat any name below as guaranteed present on your target host's client version. What I can say with reasonable confidence:

- Within each per-account subfolder, DriveFS maintains **SQLite database(s)** tracking synced-file metadata: filename, cloud file ID, local cache/hydration status, and modification timestamps for files the client has seen. Community research has at various points referenced names in the neighborhood of `sync_config.db` and separate content-cache directories, but I'd rather you enumerate the actual per-account folder and identify SQLite-format files directly (magic-byte/`file` check, or attempt to open each in DB Browser for SQLite) than rely on a filename I can't verify against the version in front of you.
- Alongside the metadata database(s), DriveFS maintains a **local content cache** — actual file bytes (full or partial) for files the client has downloaded or accessed, used to serve both Mirror-mode's full local copies and Stream-mode's on-demand hydration.

**What the metadata database proves:** the same evidentiary role as OneDrive's local sync database (see note 08, Deleted Items and File Existence, for the general "database entry outlives file" pattern) — a record of every file the client has seen and synced, including its cloud file ID and sync status, that can persist after the file itself has been deleted locally or removed from the sync folder. Treat it as a "file was here" artifact, not proof the file is still recoverable from disk.

🔴 **Stream mode's content cache means "cloud-first" is not the same as "nothing touches disk."** Even in Stream mode, DriveFS caches partial or full content locally for files the user has recently opened, so local disk analysis — file carving, unallocated-space review, cache-directory inspection — can recover actual file content the analyst might otherwise assume never left Google's servers. This is a common misconception worth correcting explicitly; see Red Flags and the Mirror vs. Stream section below.

### PowerShell

Enumerate every per-account subfolder and get a full recursive file listing of the cache, since filenames and layout aren't stable across client versions:

```powershell
Get-ChildItem "$env:LocalAppData\Google\DriveFS" -Directory -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime

Get-ChildItem "$env:LocalAppData\Google\DriveFS" -Recurse -File -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime
```

Identify SQLite-format files by magic bytes rather than by name — PowerShell can spot the file, it cannot query inside it, so that gap is the Tooling section's job — and separately size the content-cache footprint per account to gauge how much local content actually exists:

```powershell
Get-ChildItem "$env:LocalAppData\Google\DriveFS" -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    $header = Get-Content $_.FullName -Encoding Byte -TotalCount 16 -ErrorAction SilentlyContinue
    if ($header -and [System.Text.Encoding]::ASCII.GetString($header) -like 'SQLite format 3*') {
        [PSCustomObject]@{ Path = $_.FullName; SizeBytes = $_.Length; LastWriteTime = $_.LastWriteTime }
    }
}

Get-ChildItem "$env:LocalAppData\Google\DriveFS" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $size = (Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    [PSCustomObject]@{ AccountFolder = $_.Name; CacheSizeMB = [math]::Round($size / 1MB, 2) }
}
```

Sweep an estate for hosts running DriveFS and pull the per-host cache footprint in one pass for scoping how many machines a compromised or exfiltrating account touched:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    $path = "$env:LocalAppData\Google\DriveFS"
    if (Test-Path $path) {
        $accounts = Get-ChildItem $path -Directory -ErrorAction SilentlyContinue
        [PSCustomObject]@{ ComputerName = $env:COMPUTERNAME; AccountFolders = $accounts.Count; LastWriteTime = (Get-Item $path).LastWriteTime }
    }
} | Export-Csv C:\hunt\drivefs_cache_sweep.csv -NoTypeInformation
```

## Registry Artifacts

`HKCU\Software\Google\DriveFS` (exact subkey/value names are not something I can assert with full confidence across client versions — enumerate the subkeys present rather than assuming a fixed schema) is expected to track:

| Value (typical, not guaranteed) | Meaning |
|---|---|
| Configured account identifier(s) | Which Google account(s) — personal or Workspace — are connected on this host |
| Account email | Direct account attribution |
| Sync root path | The *actual* configured Mirror-mode root — critical given that the path isn't fixed by default (see above) |
| Mode indicator (Mirror vs. Stream) | Which mode the client is running in for a given account, relevant to how much local content to expect |

See Registry Forensics Fundamentals (note 04) for general `HKCU`/hive-access mechanics — these are ordinary user-hive values, no special live-vs-offline considerations beyond the standard ones covered there.

### PowerShell

Enumerate every subkey under `DriveFS` rather than assuming fixed value names, then pull each subkey's full property set:

```powershell
Get-ChildItem 'HKCU:\Software\Google\DriveFS' -Recurse -ErrorAction SilentlyContinue

Get-ChildItem 'HKCU:\Software\Google\DriveFS' -Recurse -ErrorAction SilentlyContinue | Get-ItemProperty
```

Pull only the properties whose name looks account, path, or mode-shaped, so a long uncertain-schema dump doesn't bury the values this note actually keys on:

```powershell
Get-ChildItem 'HKCU:\Software\Google\DriveFS' -Recurse -ErrorAction SilentlyContinue | Get-ItemProperty | ForEach-Object {
    $_.PSObject.Properties | Where-Object { $_.Name -match 'account|email|mode|stream|mirror' -and $_.Name -notmatch '^PS' }
}
```

Sweep loaded user hives on a live host for a personal (non-Workspace-domain) account configured where only a business account should be present:

```powershell
Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-.*[^_Classes]$' } | ForEach-Object {
    $key = "Registry::$($_.PSChildName)\Software\Google\DriveFS"
    if (Test-Path $key) { Get-ChildItem $key -Recurse -ErrorAction SilentlyContinue | Get-ItemProperty }
}
```

## Client-Side Logs

`%LocalAppData%\Google\DriveFS\Logs\` (path given with moderate, not full, confidence — verify against the client version present) is expected to hold Google Drive for Desktop's own diagnostic logs.

A point of contrast worth noting if accurate for the version you're examining: Google's client logs have generally leaned toward **plaintext or JSON-per-line formats** rather than a proprietary binary format — a difference from OneDrive's `.odl`/`.odlgz` logs (note the OneDrive note's own hedging on that format), which would make DriveFS logs more directly readable with a text editor or basic JSON tooling without needing a dedicated converter. I don't have full confidence this holds across every client version, so confirm format on the actual files recovered before assuming they're plaintext.

### PowerShell

List the log directory and read the most recently modified log on the assumption (verify per version) that entries are plaintext or JSON-per-line rather than binary:

```powershell
Get-ChildItem "$env:LocalAppData\Google\DriveFS\Logs" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending

Get-Content (Get-ChildItem "$env:LocalAppData\Google\DriveFS\Logs" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName -Tail 200
```

Attempt a line-by-line JSON parse and fall back to raw text on failure since format consistency across client versions isn't guaranteed, then grep for account-identifier or error-level lines across every log file in the directory:

```powershell
Get-ChildItem "$env:LocalAppData\Google\DriveFS\Logs" -File -ErrorAction SilentlyContinue | ForEach-Object {
    Get-Content $_.FullName | ForEach-Object {
        try { $_ | ConvertFrom-Json -ErrorAction Stop } catch { $_ }
    }
}

Select-String -Path "$env:LocalAppData\Google\DriveFS\Logs\*" -Pattern 'error|fail|@gmail\.com|@.*\.(com|org|net)' -ErrorAction SilentlyContinue
```

## Mirror vs. Stream Mode: The Central Forensic Distinction

This is the single most important interpretive concept in this note — get it wrong and every other artifact here gets misread.

| | **Mirror mode** | **Stream mode** |
|---|---|---|
| What's on disk | Full local copies of every synced file, under the configured sync root | Files appear in the mount (e.g. `G:\`) but are virtual/cloud-first — local presence is **not guaranteed** even when the file shows up in a directory listing |
| Local cache role | Cache/database is metadata alongside real files | Cache is often the *only* local copy of a file's content that exists, and only for recently-accessed files |
| Analyst implication | Straightforward file-recovery target — treat like any other local file | **Do not assume a listed file has recoverable content on this host.** A directory listing, Shell Bag entry, or LNK reference showing a filename under the Stream mount proves the client saw the name — not that content ever touched this disk. Confirm via the DriveFS local content cache before asserting local file presence. |

This is the direct structural analogue of OneDrive's Files On-Demand placeholder pitfall (see OneDrive.md's "Files On-Demand: Placeholders vs. Hydrated Files" section) — same underlying trap (name visible ≠ content present), different vendor implementation. Any investigator already comfortable reasoning about OneDrive placeholders should apply the same skepticism here before concluding a Stream-mode file was actually accessible on the host.

### PowerShell

Confirm which mode is actually in play before trusting a directory listing — a Stream-mode mount shows up as a filesystem volume, not just a folder, which is the quick way to tell it apart from a relocated Mirror-mode root:

```powershell
Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystemType, Size, SizeRemaining
```

A directory listing under the Stream mount proves the client saw the filename, not that content exists on disk; `Length` on a virtual or reparse entry is not reliable proof of hydration either, so treat the listing as a name-only lead and confirm against the local content cache before asserting local presence:

```powershell
Get-ChildItem "G:\" -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime, Attributes
```

For a given filename seen in a Stream-mode listing, search the DriveFS content cache for a matching blob so a "name-only" lead can be upgraded to "content confirmed local" or ruled out:

```powershell
$targetName = 'confidential-report.xlsx'
Get-ChildItem "$env:LocalAppData\Google\DriveFS" -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "*$targetName*" -or $_.LastWriteTime -gt (Get-Date).AddDays(-3) } |
    Select-Object FullName, Length, LastWriteTime
```

## Browser-Adjacent Evidence

Accessing Drive through a web browser (drive.google.com) rather than the desktop client leaves its own separate trail — browser history, cache, and IndexedDB/LevelDB storage referencing `drive.google.com` / `docs.google.com`. That's real evidence but belongs to the future `14 - Web Browser Forensics/` subfolder's depth, not here — this note is scoped to the desktop sync client's on-disk footprint.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Mass file additions/deletions in the DriveFS metadata database or local cache immediately preceding a resignation/termination date | Classic insider-exfiltration narrative — tie file-add/delete timestamps to HR-provided dates and corroborate against the Cloud/ note's server-side Drive Audit evidence for the same account |
| A personal Google account configured for sync (`HKCU\Software\Google\DriveFS` shows a consumer account) on a corporate machine that should only have a Workspace/business account present | Policy-violation and exfiltration-vector signal — mirrors OneDrive's personal-vs-business account red flag; gives a user a ready-made channel to move corporate files to a personal Google account outside organizational control |
| Stream-mode files assumed to have "never touched disk" because they're cloud-first | The core misconception this note exists to correct — check the local content cache directly; partial or full file content for recently-accessed files may well be recoverable |
| Sync root relocated to an unusual, hidden, or non-default path | Because Drive for Desktop allows relocation (unlike OneDrive's fixed convention), a malicious insider or attacker could deliberately move the sync root somewhere an analyst doing a quick directory-listing pass would miss — always confirm the actual configured root via registry rather than trusting a default-path assumption |

## Tooling

| Tool | Use |
|---|---|
| **DB Browser for SQLite** | Generic fallback for opening whichever file under the per-account DriveFS folder turns out to be SQLite-format on the client version you're examining — the same safe-default approach as the OneDrive note, given the naming uncertainty above |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of `HKCU\Software\Google\DriveFS` — see Registry Forensics Fundamentals (note 04) for hive-access mechanics |
| **RegRipper** | Plugin-based quick extraction of registry keys for rapid triage, if a Google Drive-specific plugin is available on the version you're running — confirm rather than assume |
| **A dedicated Google Drive for Desktop / DriveFS parser** | I am not confident there is currently a well-maintained, purpose-built free/open community parser for this artifact family comparable to Eric Zimmerman's suite for registry/EVTX artifacts. DriveFS's local database format and naming have changed enough across Google's multiple client rebrands that I'd treat community tooling here as less mature and more version-fragile than the OneDrive equivalent — verify what's current before relying on a named tool, and fall back to DB Browser for SQLite plus manual enumeration |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Server-side/Workspace-admin-log evidence for the same account — Drive Audit API events, sharing/permission changes, download/exfil confirmation from the cloud side | **Drive Audit for DFIR** (`Cloud/Google/Google Workspace/Drive & Docs Audit/Drive Audit for DFIR.md`) — this note owns local disk evidence, that note owns everything server-side for the same account |
| Registry hive structure, `NTUSER.DAT` access mechanics used to read the keys in this note | Registry Forensics Fundamentals (note 04) |
| The "database/artifact entry outlives the file" evidentiary pattern, applied more broadly | Deleted Items and File Existence (note 08) |
| User-activity artifacts (Shell Bags, RecentDocs, LNK files) that may reference names inside a Stream-mode mount without content ever having been local | File and Folder Opening (User Activity) (note 07) |
| Compare Mirror/Stream mode against OneDrive's Files On-Demand for the equivalent cloud-first-file pitfall | **OneDrive** (this subfolder) |
| Compare/contrast with other Desktop sync clients' local artifacts | Box Drive, Dropbox (this subfolder — not yet written) |

## Resources

- Google's own Drive for Desktop help/support documentation (general reference — check Google's current support site directly rather than relying on a specific URL cited here, as Google has reorganized this documentation across the client's multiple rebrands)
- MITRE ATT&CK T1567.002 (Exfiltration to Cloud Storage) — https://attack.mitre.org/techniques/T1567/002/
