# Box Drive

**Scope boundary (read this first):** this note covers only what's forensically recoverable from **the local Windows host** — filesystem, registry, local cache/log files — when Box's desktop sync client (Box Drive) has been installed and used. It does **not** cover Box's admin console, the Box Events API, shared-link/collaboration audit investigation, or any server-side activity log — that's `Cloud/`'s job per the module's structure decision (PLANNING.md §3, R3): **Windows/ owns the "evidence on disk" lens, Cloud/ owns the "server-side API/admin-log" lens** for the same service. As of this writing there is **no `Cloud/` counterpart note for Box** in this repo yet (unlike OneDrive and Google Drive, which both have one) — see Correlate With below. This note stands alone for now; when a Box server-side note exists, link it the same way OneDrive.md and the Google Drive note link theirs.

**The architectural distinction that shapes this entire note:** Box Drive is **stream-only by design**. Unlike OneDrive and Google Drive — both of which historically offered (and, for OneDrive, still effectively default toward via Files On-Demand) a "keep everything mirrored locally" mode as an option alongside on-demand streaming — Box Drive has never offered a full-local-mirror mode as its current product. It mounts as a virtual drive showing the complete Box folder/file tree, but file **content** is pulled to local disk only when a file is actually opened. There is no baseline "if it's in the sync folder, it's on disk" assumption to fall back on with Box Drive the way there arguably still loosely is with a freshly-provisioned OneDrive or Google Drive install before On-Demand/Stream settings are touched. With Box Drive, **local presence of file content is always conditional** — this is the single fact that should shape how you read every other artifact in this note.

**History, hedged:** Box previously shipped a different, more traditional client called **Box Sync**, which did behave more like a classic full-mirror sync client (files fully downloaded into a local folder by default, closer to old-style OneDrive/Dropbox behavior). Box has been moving customers off Box Sync toward Box Drive for years and my understanding is Box Sync is deprecated/retired as a supported product — but I don't have current confidence in Box's exact end-of-life/support-lifecycle date for Box Sync, so if you encounter Box Sync (rather than Box Drive) on a host during an engagement, treat it as its own artifact set with more classic full-mirror assumptions, verify current lifecycle/support status independently, and don't assume everything in this note (written for Box Drive) transfers directly.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Mount Point & Local Cache Root](#mount-point--local-cache-root)
- [The Local Cache/Database](#the-local-cachedatabase)
- [Registry Artifacts](#registry-artifacts)
- [Client-Side Logs](#client-side-logs)
- [The Core Forensic Pitfall: Stream-Only Means No Mirror Fallback](#the-core-forensic-pitfall-stream-only-means-no-mirror-fallback)
- [Browser-Adjacent Evidence](#browser-adjacent-evidence)
- [Red Flags](#red-flags)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage across the virtual mount, `%LocalAppData%\Box\Box Drive\`, and `HKCU\Software\Box` — no third-party modules required. Remember the note's core pitfall while reading these: PowerShell can enumerate the surrounding filesystem/registry/process evidence, but a directory listing of the mounted virtual drive itself proves nothing about local hydration — see The Core Forensic Pitfall below for why.

```powershell
# Does a Box Drive client footprint even exist on this host, and how recently was it touched
Get-ChildItem 'C:\Users\*\AppData\Local\Box\Box Drive' -Directory -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime

# Is the Box Drive client actually running right now, and from what binary path
Get-Process -Name 'Box' -ErrorAction SilentlyContinue | Select-Object Id, Path, StartTime

# Every mounted filesystem drive letter present - Box Drive's mount point is configurable per-user/policy, don't assume Z: without checking here
Get-PSDrive -PSProvider FileSystem | Select-Object Name, Root, Description

# HKCU\Software\Box present at all - fast account/install-attribution check before touching any cache file
Get-ChildItem 'HKCU:\Software\Box' -ErrorAction SilentlyContinue

# Every file under the local cache root, unfiltered - the "go look" starting point this note's hedge insists on, since no confirmed DB filename exists
Get-ChildItem 'C:\Users\*\AppData\Local\Box\Box Drive' -Recurse -File -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime, Extension

# Candidate client-side log files touched in the last 24 hours - the "why", not just "that", when the cache alone doesn't explain an event
Get-ChildItem 'C:\Users\*\AppData\Local\Box\Box Drive\logs' -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object LastWriteTime -gt (Get-Date).AddHours(-24) | Select-Object FullName, LastWriteTime

# Directory listing of the mounted virtual drive itself - proves NOTHING about local content, every file the account can see shows regardless of hydration
Get-ChildItem 'Z:\' -Recurse -File -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime
```

## Mount Point & Local Cache Root

Box Drive presents itself to the user as a **virtual drive** — commonly `Z:\`, though the exact letter is configurable by the user or by admin policy and should never be assumed without checking the host in front of you. Under that virtual drive letter, Explorer shows the full Box folder/file tree the account has access to, including files whose content has never touched local disk.

The virtual presentation is backed by a real, physical local cache on the actual filesystem. That cache root is typically located under:

```
%LocalAppData%\Box\Box Drive\
```

**Hedge, stated plainly and up front:** I do not have confident, current knowledge of Box Drive's exact subfolder layout or cache-file naming beneath this root. Box Drive's internal cache format is meaningfully less documented in public DFIR community research than OneDrive's or Google Drive's equivalents — this is a genuine, acknowledged gap in what's publicly known and validated, not an oversight in this note. Treat `%LocalAppData%\Box\Box Drive\` as your starting point for **live enumeration on the actual system under investigation**, not as a memorized path you can cite with certainty in a report without having verified it against the specific host and client version. Expect to need to browse the folder yourself, identify file types by magic bytes/`file`, and document what you actually find — this is one of the notes in this subfolder where "go look" is genuinely the correct methodology, more so than for OneDrive or Google Drive.

### PowerShell

Confirm the cache root exists on this profile and pull its top-level timestamps and attributes before browsing further:

```powershell
Get-Item 'C:\Users\<user>\AppData\Local\Box\Box Drive' -ErrorAction SilentlyContinue |
    Select-Object FullName, CreationTime, LastWriteTime, Attributes
```

Group everything under the cache root by extension since no confirmed filename or format exists to search for by name — this is the live-discovery starting point the hedge above calls for:

```powershell
Get-ChildItem 'C:\Users\<user>\AppData\Local\Box\Box Drive' -Recurse -File -ErrorAction SilentlyContinue |
    Group-Object Extension | Sort-Object Count -Descending | Select-Object Name, Count
```

Sweep an estate for hosts where a Box Drive cache root exists at all before deciding whether deeper per-host analysis is worth the time:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        CachePresent = Test-Path "$env:LocalAppData\Box\Box Drive"
    }
} | Export-Csv C:\hunt\box_drive_footprint.csv -NoTypeInformation
```

## The Local Cache/Database

By analogy with every other sync client covered in this subfolder, Box Drive almost certainly maintains some local database or cache-index tracking:

- which files/folders have actually had their content pulled to local disk (i.e., which placeholders are hydrated),
- metadata for the **full virtual tree** — including files never opened, whose names/sizes/timestamps are needed to render the drive letter's listing at all, and
- sync/upload status for local changes being pushed back to Box's servers.

**Hedge, stated more heavily than for OneDrive or Google Drive:** I cannot name a specific filename, format, or schema for this database with confidence. I don't know whether it's SQLite, a proprietary binary format, or something else, and I'm not aware of mature, widely-cited public DFIR research pinning this down the way there is for OneDrive's or Google Drive's local databases. This is a genuine current gap in publicly available research on Box Drive's forensic footprint, not a detail being glossed over here — say so plainly to whoever's reading this note rather than inventing a plausible-sounding filename. **The correct operational takeaway is: expect to do live discovery on a real system.** Acquire a test host with Box Drive installed, open some files, leave others untouched, and diff the cache folder before/after to identify candidate database files empirically, before an engagement where this evidence matters — don't assume you can walk into a case cold on this artifact the way you could with OneDrive's `settings\<Personal|Business1>\` folder.

### PowerShell

Capture a full baseline of the cache root's contents on a test host as the starting point for the before/after diff the prose above calls for:

```powershell
Get-ChildItem 'C:\Users\<user>\AppData\Local\Box\Box Drive' -Recurse -File -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime | Export-Csv C:\hunt\box_cache_baseline_before.csv -NoTypeInformation
```

Diff a before/after baseline pair to empirically identify which files change when a file is opened (hydrated) versus left untouched — this is how you find the candidate database file this note can't name with confidence:

```powershell
$before = Import-Csv C:\hunt\box_cache_baseline_before.csv
$after  = Import-Csv C:\hunt\box_cache_baseline_after.csv
Compare-Object $before $after -Property FullName, Length -PassThru | Select-Object FullName, Length, SideIndicator
```

## Registry Artifacts

Expect Box Drive to record its per-user configuration somewhere under a key resembling:

```
HKCU\Software\Box\Box Drive
```

**Hedge:** I'm not confident of the exact subkey structure or value names — this is drawn from the general pattern every desktop sync client follows (a per-user `HKCU` key recording the configured account, drive-letter assignment, and sync status), not from verified knowledge of Box Drive's specific schema. On a real host, enumerate `HKCU\Software\Box\` fully rather than searching for named values in advance. Plausible categories to expect, by analogy with OneDrive/Google Drive's equivalent keys, but unverified for exact naming:

| Expected category | Likely purpose (unverified naming) |
|---|---|
| Account identifier / email | Attribution of the sync relationship to a specific Box account |
| Drive-letter assignment | Confirms which letter the virtual drive was mounted as at last configuration |
| Sync/connection status | Whether the client was actively connected/authenticated |

See Registry Forensics Fundamentals (note 04) for `NTUSER.DAT`/hive-access mechanics generally — assuming Box Drive uses ordinary `HKCU` values (a reasonable assumption, but again unverified in specific), no special hive-loading considerations beyond the standard live-vs-offline distinction apply.

### PowerShell

Pull the values directly under the expected `Box Drive` subkey:

```powershell
Get-ItemProperty 'HKCU:\Software\Box\Box Drive' -ErrorAction SilentlyContinue | Format-List *
```

Since the exact subkey structure isn't confirmed, walk every subkey under `HKCU\Software\Box` and dump its values for manual review rather than guessing names in advance:

```powershell
Get-ChildItem 'HKCU:\Software\Box' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
} | Format-List *
```

Cross-host sweep to confirm which hosts in an estate have Box Drive's per-user key present at all, ahead of a targeted account-attribution pull:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Test-Path 'HKCU:\Software\Box\Box Drive'
} | Select-Object PSComputerName, RunspaceId
```

## Client-Side Logs

Box Drive likely maintains its own client-side diagnostic/operational logs, plausibly under a path resembling:

```
%LocalAppData%\Box\Box Drive\logs\
```

**Hedge:** both the exact path and the log format (plain text, structured/JSON, proprietary binary) are unverified here — treat this as a reasonable starting guess based on where the other sync clients in this subfolder keep their logs, not a confirmed location. If present, expect the general category of content every sync client's logs record: connection/authentication events, sync errors, and individual file-operation history — useful for the same reason OneDrive's `.odl` logs are useful, when the cache/database shows *that* something happened but not *why*. Verify the actual path and format on the specific client version present at investigation time rather than citing this path in a report without having confirmed it.

### PowerShell

Enumerate whatever's under the expected logs path, newest first:

```powershell
Get-ChildItem 'C:\Users\<user>\AppData\Local\Box\Box Drive\logs' -Recurse -File -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime | Sort-Object LastWriteTime -Descending
```

If the logs turn out to be plaintext (unconfirmed for this client per the hedge above), grep them for the connection, auth, and error keywords that fill the "why" gap the cache or database alone can't answer:

```powershell
Get-ChildItem 'C:\Users\<user>\AppData\Local\Box\Box Drive\logs' -Recurse -File -ErrorAction SilentlyContinue |
    Select-String -Pattern 'error|fail|auth|disconnect' | Select-Object Path, LineNumber, Line
```

## The Core Forensic Pitfall: Stream-Only Means No Mirror Fallback

🔴 **This is the single most important interpretive point in this note, and it applies with more force here than in either sibling note.** Because Box Drive has no full-mirror mode to fall back on, **the presence of a file's name in the mounted virtual drive's directory listing proves nothing about whether that file's content was ever pulled to local disk.** Every file the account has access to appears in the listing — opened or not, ever — because the virtual tree is rendered from cloud metadata regardless of local hydration state.

This is conceptually the same pitfall as OneDrive's Files On-Demand placeholder problem (see OneDrive.md, "Files On-Demand: Placeholders vs. Hydrated Files") and Google Drive's Stream-mode equivalent (see Google Drive for Desktop.md's equivalent section) — but where those clients' pitfalls apply to a *subset* of files under a *configurable* setting, Box Drive's pitfall applies to **every file, all the time, by default**, because there is no alternate full-mirror configuration to compare against. Never assume a OneDrive-style "well, if Files On-Demand were off, this would prove local content" escape hatch exists for Box Drive — it doesn't.

Practical consequence: before asserting a file's content was ever present or accessible on a Box Drive host, you need positive local evidence of hydration (find the cached content itself, or a database/log record specifically indicating the file was opened) — a directory listing, a Shell Bag entry, or a Jump List reference showing the filename alone is not sufficient, exactly as with the other two clients' equivalent pitfalls, but here with zero exceptions available.

## Browser-Adjacent Evidence

Accessing Box through a web browser (`app.box.com`) rather than the Box Drive client leaves its own separate trail in browser history, cache, and IndexedDB/LevelDB storage — that's real evidence but belongs to the future `14 - Web Browser Forensics/` subfolder's depth, not here.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Mass file access (and therefore local-cache hydration/population) immediately preceding a resignation/termination date | Classic insider-exfiltration narrative — files being opened (and thus pulled to local disk) at volume shortly before departure is the same pattern flagged in OneDrive.md and the Google Drive note, corroborate against HR-provided dates |
| A personal/non-corporate Box account configured on a corporate machine | Same policy-violation/exfiltration-vector pattern as a personal OneDrive or Google account on a business host — a ready-made channel to move corporate files to an account outside organizational control |
| Concluding "these files were never touched locally" purely because a superficial file-recovery pass didn't turn up cached content | **The specific caution unique to this note's emphasis:** because Box Drive is stream-only with no mirror-mode baseline, the absence of recovered local content proves *less* here than it would for OneDrive or Google Drive, where a full-mirror configuration might otherwise have guaranteed local presence. Don't over-conclude from absence of evidence — confirm you've actually located and checked whatever the local cache/database artifact turns out to be (per the heavy hedge above) before ruling out local access, rather than treating a quick pass as exhaustive |

## Tooling

| Tool | Use |
|---|---|
| **DB Browser for SQLite** | Generic fallback **if** whatever cache/database file you find under `%LocalAppData%\Box\Box Drive\` turns out to be SQLite-format — unverified whether Box Drive actually uses SQLite for its local cache, so confirm format (magic bytes) before assuming this tool applies |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of `HKCU\Software\Box\Box Drive` — see Registry Forensics Fundamentals (note 04) for hive-access mechanics |
| **RegRipper** | Plugin-based registry extraction — check whether a Box-specific plugin exists at investigation time; if not, a generic key-dump approach against `HKCU\Software\Box\` still works |
| **A dedicated Box-Drive-specific forensic parser** | **I am not aware of a purpose-built, actively-maintained parser for Box Drive's local cache** comparable to what exists (with its own caveats) for OneDrive or Google Drive. Say this plainly rather than naming an unverified tool — this reflects a genuine, current gap in public Box Drive DFIR tooling, not incomplete research for this note. Expect to fall back on generic tools (hex viewers, `file`/magic-byte identification, DB Browser for SQLite if applicable) plus manual, host-specific validation |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Server-side/admin-console evidence for the same Box account — Events API, sharing/collaboration audit, download/exfil confirmation from the cloud side | **Not yet covered in this repo** — no `Cloud/` Box note currently exists (unlike OneDrive and Google Drive, which both have one). This note stands alone for now; add the cross-link here once a Cloud/ Box note is written |
| Registry hive structure, `NTUSER.DAT` access mechanics used to read the keys in this note | Registry Forensics Fundamentals (note 04) |
| User-activity artifacts (Shell Bags, RecentDocs, LNK files, Jump Lists) that might reference files under the Box Drive mount point | File and Folder Opening (User Activity) (note 07) |
| Establishing whether a file's content ever actually existed locally, independent of directory-listing presence | Deleted Items and File Existence (note 08) |
| Compare/contrast stream-only architecture against another client that *does* offer a configurable on-demand mode | OneDrive.md ("Files On-Demand: Placeholders vs. Hydrated Files") and Google Drive for Desktop.md's equivalent Stream-mode section — same core pitfall, different vendor implementation and different default-mode guarantees |
| Compare/contrast with the fourth sync client in this subfolder | Dropbox.md (this subfolder — not yet written) |

## Resources

- Box's own Box Drive support/admin documentation (generic reference — check Box's current support site directly for the current article rather than relying on a specific link cited here, as Box has reorganized this documentation across releases)
- MITRE ATT&CK T1567.002 (Exfiltration to Cloud Storage) — https://attack.mitre.org/techniques/T1567/002/
