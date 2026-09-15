# Deleted Items and File Existence

Deleting a file in Windows rarely means what a user thinks it means, and it means even less to the operating system than most examiners assume. "Delete" triggers a cascade of independent caches — some file-based, some database-based — that were never designed to work together but collectively leave a trail an analyst can walk backward. A Recycle Bin entry can prove a file existed after its content is gone. A thumbnail can prove an image existed after both the file *and* the Recycle Bin entry are gone. A search-index row can prove a filename existed after the thumbnail is gone too. None of these artifacts were built for forensics; each was built to solve its own narrow problem (undo-delete, fast folder previews, fast keyword search) and each happens to retain its own independent proof of past file existence, on its own schedule, with its own decay point.

That's this note's organizing idea — a **chain of survivability**: when a file disappears, it doesn't disappear from every artifact at once. Different caches outlive the file (and each other) by different margins, and stacking them is often how "the file is gone but I can still prove it was here" gets answered. This note covers the four artifacts that make up that chain at the application layer. For the filesystem-layer theory underneath all of them — orphan $MFT records, copy-on-write/Volume Shadow Copies, carving strategies, SSD/TRIM's hard recovery ceiling — see **NTFS/07 - File Deletion Mechanics**, which this note assumes and does not re-explain.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Recycle Bin](#recycle-bin)
- [Thumbs.db](#thumbsdb)
- [Thumbcache](#thumbcache)
- [Windows Search Database (Windows.edb)](#windows-search-database-windowsedb)
- [String vs Indexed Searching, Revisited](#string-vs-indexed-searching-revisited)
- [The Chain of Survivability](#the-chain-of-survivability)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage across the Recycle Bin, Windows Search Database, and Thumbcache before any parser (RECmd, a Windows Search DB tool, Thumbcache Viewer) comes out — no third-party modules required.

```powershell
# Every $I/$R file across all user SIDs in the Recycle Bin - the baseline inventory before anything else
Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force -Include '$I*','$R*' -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, CreationTime, LastWriteTime

# Orphaned half of a pair - grouping by the shared identifier+extension after the $I/$R prefix
# surfaces items where only one half of the pairing survived
Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force -Include '$I*','$R*' -ErrorAction SilentlyContinue |
    Group-Object { $_.Name.Substring(2) } | Where-Object Count -eq 1 |
    Select-Object @{N='OrphanedFile'; E={ $_.Group.Name }}

# Deleted items sorted by recency across every SID - fastest way to see what left the system last
Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force -Include '$I*' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 25 FullName, LastWriteTime

# $Recycle.Bin SID subfolders with no resolvable local profile - deleted/orphaned account, or a foreign SID (see note 05)
Get-ChildItem 'C:\$Recycle.Bin' -Force -Directory -ErrorAction SilentlyContinue |
    Where-Object { -not (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($_.Name)" -ErrorAction SilentlyContinue) }

# Windows.edb existence, size, and last-write - a quick triage signal for how current/stale the search index is
Get-Item 'C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb' -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime

# Thumbcache file set present for the current user, sized - a thin or missing set on an aged host is itself a finding
Get-ChildItem "$env:USERPROFILE\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db" -ErrorAction SilentlyContinue |
    Select-Object Name, Length, LastWriteTime
```

## Recycle Bin

The Recycle Bin is a hidden system folder that intercepts ordinary (non-`Shift+Delete`, non-CLI) deletions and holds them in a recoverable staging area until the user empties it. Its on-disk structure changed completely between XP and Vista, and the version in scope changes which files an examiner should go looking for.

| | Windows XP | Windows Vista / 7 and later |
|---|---|---|
| **Location** | `C:\Recycler\<SID>\` | `C:\$Recycle.Bin\<SID>\` |
| **Structure** | One shared **`INFO2`** database per user SID folder | One **pair of files per deleted item** |
| **Metadata (name/path/time)** | Stored inside `INFO2` itself — original filename and deletion time for every item in that user's bin, all in one file | Stored in a dedicated **`$I######`** file — one per deleted item, holding the original filename, full original path, and deletion date/time |
| **Content** | The deleted file itself, renamed to a `D`-prefixed placeholder, sitting alongside the shared `INFO2` | Stored in a dedicated **`$R######`** file — one per deleted item, the actual deleted file's bytes renamed under this identifier |

The Vista+ design's practical payoff is that metadata and content are **decoupled into two separate files that share only a matching numeric identifier**. That decoupling is the whole reason this artifact is worth understanding in depth rather than treating as "check the Recycle Bin":

- If `$R######` has been overwritten or the bin was emptied and the content is gone, the paired `$I######` can still independently prove **that** a specific file existed, its original full path, its size, and precisely when it was deleted — even with zero recoverable content.
- Less commonly, an `$I` record can be lost (corruption, partial overwrite) while `$R` content is still recoverable via carving/index-based $MFT recovery (NTFS/07) — the pairing is not a hard guarantee both halves survive or die together, just that they're normally created together.
- Recall from NTFS/02: the deleted file's own `$MFT`/`$STANDARD_INFORMATION` timestamps **do not change on deletion** — "when was this deleted" lives nowhere on the file's own record. The `$I######` file is the actual source of that fact, which is exactly why losing it (while keeping `$R`) still costs you the deletion timestamp even if the content survives.

Each `<SID>` subfolder is a per-user Recycle Bin. Resolving that SID to an actual username uses the same SAM/`ProfileList` material covered in **Users, Groups & Authentication** (note 05) — a `$Recycle.Bin` subfolder for a SID with no resolvable profile is itself worth a second look (a deleted/orphaned account, or a SID copied in from another system image).

🔴 A Recycle Bin folder — `$Recycle.Bin` or `Recycler` — surviving on disk after the corresponding user profile has been deleted is a standalone artifact worth checking on its own: recycled items can outlive the profile that created them.

### PowerShell

To list every SID subfolder and its `$I`/`$R` contents, no filtering applied yet:

```powershell
Get-ChildItem 'C:\$Recycle.Bin' -Force -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    Get-ChildItem $_.FullName -Force -ErrorAction SilentlyContinue | Select-Object Directory, Name, Length, CreationTime, LastWriteTime
}
```

This note documents that `$I######` holds the original filename, full path, and deletion timestamp, but it does not specify the exact byte offsets of that binary header (version field, path-length field, FILETIME offset). Decoding those fields precisely requires a dedicated parser — **RECmd/RBCmd** (Eric Zimmerman) or Recycle Bin Explorer — not hand-rolled PowerShell byte math; inventing an offset here would be a guess, not a fact. What PowerShell *can* do natively, with zero binary parsing, is confirm presence/absence of the pairing and fall back on the `$I` file's own file-system timestamps as an approximation of deletion time:

```powershell
Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force -Filter '$I*' -ErrorAction SilentlyContinue |
    Select-Object FullName, CreationTime, LastWriteTime,
        @{N='PairedRExists'; E={ Test-Path (Join-Path $_.DirectoryName ('$R' + $_.Name.Substring(2))) }}
```

To resolve each SID subfolder to a username (or confirm it doesn't resolve at all) via the same `ProfileList` material as note 05:

```powershell
Get-ChildItem 'C:\$Recycle.Bin' -Force -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $profile = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($_.Name)" -ErrorAction SilentlyContinue
    [PSCustomObject]@{ SID = $_.Name; ProfilePath = $profile.ProfileImagePath; Resolved = [bool]$profile }
}
```

To sweep an estate for Recycle Bin contents across every host and export for timeline pivoting:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force -Include '$I*' -ErrorAction SilentlyContinue |
        Select-Object @{N='ComputerName'; E={ $env:COMPUTERNAME }}, FullName, CreationTime, LastWriteTime
} | Export-Csv C:\hunt\recyclebin_sweep.csv -NoTypeInformation
```

## Thumbs.db

`Thumbs.db` is a hidden, per-folder database file Windows creates the moment a folder's contents are viewed in thumbnail view — it caches small preview images so Explorer doesn't have to re-decode the full picture every time that folder is reopened.

- **Version dependence matters here.** `Thumbs.db` is historically an XP-era artifact — Vista and later moved thumbnail caching to the centralized Thumbcache below by default, and modern Windows normally does **not** create per-folder `Thumbs.db` files for local folders. It can still appear on modern Windows, though, in specific circumstances — most notably folders accessed over a **UNC/network path** or certain non-standard view configurations — so its absence on a modern host is normal, but its presence is still worth collecting, not dismissing as "legacy."
- **Content, and an XP-only enhancement.** Every `Thumbs.db` entry carries a thumbnail image of the original picture. On **Windows XP specifically**, entries additionally carry the original file's **last-modification time** and **original filename** — fields that later versions dropped from the format entirely. On non-XP builds where `Thumbs.db` does appear, treat it as thumbnail-image evidence only; don't expect the filename/timestamp fields to be there.
- **Forensic value.** Because the thumbnail lives inside `Thumbs.db` independent of the source image, a `Thumbs.db` file can catalog a folder's **past contents** — proving specific images existed in that folder — even after every original image has been deleted and the folder itself shows empty.

## Thumbcache

Thumbcache is the centralized, per-user successor to `Thumbs.db`, introduced in **Windows Vista** and standard ever since. Instead of one database scattered per folder, each user gets one set of size-tiered database files under a single profile path:

| | |
|---|---|
| **Location** | `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer\` |
| **File naming** | `thumbcache_<size>.db` — commonly seen tiers include `thumbcache_32.db`, `thumbcache_96.db`, `thumbcache_256.db`, `thumbcache_1024.db`, and an `sr` (screenshot/live-tile-adjacent) variant on some builds; exact tier set and pixel sizes have shifted across Windows releases, so treat this list as representative, not exhaustive, and enumerate whatever tier files are actually present on the build in scope |
| **Scope** | Per-user (unlike `Thumbs.db`'s per-folder scope) — one Thumbcache set covers every folder that user has browsed in thumbnail view, system-wide |

Same core forensic value as `Thumbs.db` — a thumbnail can outlive the source image and prove a folder's past contents — but centralized per-user rather than scattered per-folder, which means a single Thumbcache set can be a much richer, single-stop record of everything a user has ever previewed, across every folder they've opened.

### PowerShell

To enumerate whatever tier files actually exist across every local profile, not just the current user, since the tier set varies by build:

```powershell
Get-ChildItem 'C:\Users\*\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db' -Force -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime
```

🔴 `Get-ChildItem` only surfaces which tier files exist, their size, and when they were last written — it cannot open the database or extract individual thumbnail images/Thumbnail Cache IDs; that requires Thumbcache Viewer (see Tooling below).

**The Thumbnail Cache ID cross-reference.** Each Thumbcache entry carries an internal identifier (the Thumbnail Cache ID) that has no filename or path attached to it directly — a thumbnail image with no idea what it's a thumbnail *of*. That ID can be cross-referenced against the **Windows Search Database** (next section), which independently maps the same ID back to the original filename, full path, and additional file metadata. This is the single most powerful move in this note: a Thumbcache image that looks like nothing on its own can be identified by name and location once matched against `Windows.edb` — recovering evidence of a specific deleted file that neither artifact alone could name.

## Windows Search Database (Windows.edb)

`Windows.edb` is the backing database behind Windows Search/indexed search — a single file that indexes metadata (and for many file types, extracted content) for **900+ file types** across the indexed scope, including email. It is an **Extensible Storage Engine (ESE)** database, the same underlying database technology behind SRUM's `SRUDB.dat` (see **SRUM**, note 06 series, for the ESE-format parallel and the shared repair/export tooling that follows from it).

| | Windows XP | Windows 7 and later |
|---|---|---|
| **Database path** | `C:\Documents and Settings\All Users\Application Data\Microsoft\Search\Data\Applications\Windows\Windows.edb` | `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb` |
| **Gather Logs path** | — | `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\GatherLogs\SystemIndex\` |

- **Gather Logs (`.gthr` files)** hold a **rolling ~24-hour candidate list** of files queued up for indexing — files Windows Search has noticed and intends to index, whether or not the main `Windows.edb` index has actually caught up to them yet. Treat Gather Logs as a secondary, shorter-window signal answering "what files existed and were about to be indexed" — useful when the file in question was deleted before the indexer got to it, or when `Windows.edb` itself is corrupted/stale and Gather Logs is the more current record.
- 🔴 **Windows 11 changed the search-database structure** in ways not fully verified for this note — treat the exact current format/location on a Windows 11 host as something to confirm against the specific build in scope rather than assuming the Win7+ path/behavior above carries forward unchanged.

### PowerShell

To check the Gather Logs folder as the shorter-window supplementary signal alongside the Hunt Evil check on `Windows.edb` itself:

```powershell
Get-ChildItem 'C:\ProgramData\Microsoft\Search\Data\Applications\Windows\GatherLogs\SystemIndex\' -ErrorAction SilentlyContinue |
    Select-Object Name, Length, LastWriteTime
```

`Windows.edb` is normally locked open by the Search service, the same limitation SRUM's `SRUDB.dat` has (note 06 series). Rather than fighting the live lock, enumerate Volume Shadow Copies and pull a prior snapshot of the file out of the shadow device path — a native technique, no third-party tool required:

```powershell
# Enumerate available shadow copies to pick a snapshot predating the point of interest
Get-CimInstance Win32_ShadowCopy | Select-Object ID, InstallDate, VolumeName

# Copy Windows.edb out of a specific shadow copy's device path (swap in the shadow copy ID from above)
$shadow = '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1'
Copy-Item "$shadow\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" C:\hunt\Windows.edb.bak
```

🔴 The extracted copy is still an ESE database — run it through `esentutl` (Tooling below) for a consistency check before handing it to a Windows Search DB parser.

## String vs Indexed Searching, Revisited

`Windows.edb`'s entire purpose is to make keyword search fast by trading completeness for speed — see **NTFS/07 - File Deletion Mechanics** for the full string-vs-indexed tradeoff. The short version relevant here: an indexed hit in `Windows.edb` is fast but only as current and as broad as the last index pass, while a slow bit-for-bit string search still catches what indexing missed (unallocated space, unindexed file types, files created after the last index update).

## The Chain of Survivability

The unifying point of this note: a deleted file doesn't vanish from every artifact simultaneously. Each cache below survives independently, for a different reason, and for a different span — which is exactly why stacking them recovers proof of existence that no single artifact could provide alone.

| Artifact | Survives deletion of… | Survives for roughly… | Cross-references |
|---|---|---|---|
| **Recycle Bin ($I/$R)** | The file's own $MFT record content | Until the bin is emptied (or `$R`/`$I` is individually overwritten) | $MFT/NTFS timestamps (NTFS/02) for the file's pre-deletion history; SAM/`ProfileList` (note 05) for SID → username |
| **Thumbs.db** | The original image file, per folder | Indefinitely once written — survives the source image and can outlive the folder's other contents | Nothing built-in; XP entries self-contain filename + last-modified time |
| **Thumbcache** | The original image file *and* the emptied Recycle Bin | Indefinitely once written — centralized per-user, independent of any single folder or the bin | **Windows Search Database** via Thumbnail Cache ID, to recover filename/path/metadata |
| **Windows.edb (Search Database)** | The original file, its Recycle Bin entry, and its thumbnail cache entry, all at once | Until the index entry is evicted/rebuilt/repaired | Gather Logs (`.gthr`) as a shorter-window supplementary signal; Thumbcache via Thumbnail Cache ID (reverse direction) |

Framed simply: **even when a file is truly gone — off disk, out of the Recycle Bin, unrecoverable by carving — multiple independent caches may still prove it existed.** No single artifact in this chain was designed with the others in mind; that independence is precisely what makes stacking them so effective.

## Tooling

| Tool | Use |
|---|---|
| **RECmd** (Eric Zimmerman) | Parses Recycle Bin `$I`/`$R` pairs (Vista+) and `INFO2` (XP) |
| **esentutl** (built-in Windows utility) | Repairs, defragments, and exports ESE-format databases — usable directly against `Windows.edb` when the index needs recovery or offline export |
| **A dedicated Windows Search DB analysis tool** | Purpose-built parsers exist for extracting and correlating `Windows.edb` entries (including the Thumbnail-Cache-ID cross-reference described above) — verify the current best-of-breed tool name for the version in scope rather than assuming a specific one, as this space has changed hands across releases |
| **Thumbcache Viewer** (community tool) | Extracts and displays individual thumbnail images out of `thumbcache_*.db` files, including the Thumbnail Cache ID needed for the `Windows.edb` cross-reference |
| **Autopsy / FTK / X-Ways / AXIOM** | General forensic suites with built-in Recycle Bin and Thumbcache parsing modules — see NTFS/07 for their broader carving/recovery role |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `$I######` present with no matching `$R######` (or vice versa) | The pairing isn't guaranteed to survive together — confirm which half you actually have before claiming full recovery; metadata-only or content-only results are each still independently useful |
| `$Recycle.Bin\<SID>` folder with no resolvable profile for that SID | Deleted/orphaned account, or a SID carried over from a different system image — cross-check note 05 |
| `Thumbs.db` present on a modern (post-XP) local folder with no UNC/network-path explanation | Worth explaining — not itself malicious, but an unusual finding for the OS version in scope |
| Thumbcache entry with no corresponding `Windows.edb` index row | The filename/path cross-reference will fail — the thumbnail image is still evidence of a picture's existence, just not by name, without another correlating source |
| `Windows.edb` referencing a file that no longer exists anywhere else on disk, in the Recycle Bin, or in Thumbcache | The index itself may be the last surviving proof of that file's past existence — don't discard it as "stale," treat it as the terminal link in the survivability chain |
| Analyst statement that a deleted file is "completely unrecoverable" without checking Recycle Bin, Thumbs.db/Thumbcache, and `Windows.edb` in turn | Premature — this note's whole point is that these four caches fail independently; check all of them before concluding total loss |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Orphan $MFT records, copy-on-write/VSS, carving strategy, and SSD/TRIM's hard recovery ceiling underneath all of the above | **NTFS/07 - File Deletion Mechanics** |
| Mapping a Recycle Bin SID subfolder to an actual username | **Users, Groups & Authentication** (note 05) |
| Shellbags, Recent Files/MRU, and other artifacts proving a file or folder was *opened* rather than deleted | **File and Folder Opening (User Activity)** |
| Whether a deleted file arrived via a USB device in the first place | **Removable Device (USB) Forensics** |
| ESE-format parallel and shared repair/export tooling (`esentutl`) | **SRUM** (note 06 series) |

## Resources

- SANS FOR500 poster, "Deleted Items and File Existence" panel — coverage checklist for paths/fields, rewritten in this note's own words
- SANS FOR500 course syllabus (public) — Recycle Bin / Thumbs.db / Thumbcache / Windows Search Database coverage checklist
- Eric Zimmerman's tools (RECmd) — https://ericzimmerman.github.io/
- Microsoft Learn — `esentutl` reference: https://learn.microsoft.com/windows-server/administration/windows-commands/esentutl
