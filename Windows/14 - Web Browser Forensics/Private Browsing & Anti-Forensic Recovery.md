# Private Browsing & Anti-Forensic Recovery

The three preceding notes in this subfolder (**Chromium (Chrome & Edge).md**, **Firefox.md**, **Internet Explorer & Legacy Edge.md**) each document a specific browser's on-disk artifact model in depth — exact SQLite tables, ESE containers, registry keys, file paths. This note is different in kind: it's a **synthesis/bridge note**. It does not re-teach any of those schemas. Its job is to answer the question an analyst actually asks mid-incident when the normal artifact trail from those three notes comes up thin: *"the user says they used private browsing, or the history is suspiciously empty/short — where else can this evidence possibly be?"* — plus the second, related question this repo's PLANNING.md scopes into the same note: *"the SQLite/ESE file I need is deleted or corrupted — can I get anything back?"*

Everything below assumes familiarity with the artifact names introduced in the three sibling notes (`History`/`Cookies`/`Web Data`, `places.sqlite`, `WebCacheV01.dat`/`spartan.edb`) — they're referenced here, not re-derived.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [What Private Browsing Actually Does NOT Do](#what-private-browsing-actually-does-not-do)
- [Where Private-Browsing Evidence Can Still Surface](#where-private-browsing-evidence-can-still-surface)
  - [DNS Cache](#dns-cache)
  - [Memory (RAM) — The Richest Source](#memory-ram--the-richest-source)
  - [Pagefile / Hiberfil / Swapfile Carving](#pagefile--hiberfil--swapfile-carving)
  - [Network-Level Logs](#network-level-logs)
  - [Extension Data](#extension-data)
  - [Thumbnail/Preview Caches](#thumbnailpreview-caches)
- [SQLite Recovery Across All Browsers](#sqlite-recovery-across-all-browsers)
- [ESE Recovery (IE / Legacy Edge)](#ese-recovery-ie--legacy-edge)
- [The Anti-Forensic Angle — Deliberate Evidence Destruction](#the-anti-forensic-angle--deliberate-evidence-destruction)
- [Red Flags](#red-flags)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage for the recovery avenues this note covers — memory/pagefile carving candidacy, SQLite/ESE sidecar presence, and the meta-artifacts private browsing can't suppress. None of this carves unallocated space or memory itself (see the note below the block); it's the fast pre-checks that tell you whether a deeper memory-forensics or file-carving pass is worth running at all.

```powershell
# Is a private/incognito-capable browser currently running - live session in memory right now is the richest target
Get-Process -Name chrome, msedge, firefox, iexplore -ErrorAction SilentlyContinue | Select-Object Name, Id, StartTime, Path

# Pagefile/swapfile presence and size - confirms a carving target exists before reaching for a memory-forensics tool
Get-CimInstance Win32_PageFileUsage | Select-Object Name, AllocatedBaseSize, CurrentUsage

# Hibernation enabled (hiberfil.sys present) - a full physical-memory snapshot on disk, independent of browser privacy mode
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name HibernateEnabled -ErrorAction SilentlyContinue

# DNS resolver cache - still populated during a private session regardless of browsing mode, cheap corroboration when history is empty
Get-DnsClientCache | Select-Object Entry, Data, TimeToLive

# WAL/journal/-shm sidecar files sitting next to browser databases - recent transactions not yet checkpointed into the main file
Get-ChildItem "$env:LOCALAPPDATA","$env:APPDATA" -Recurse -Include *-wal,*-journal,*-shm,*.log -ErrorAction SilentlyContinue |
    Where-Object { $_.Directory.FullName -match '(Chrome|Edge|Firefox|Mozilla|Microsoft\\Windows\\WebCache)' } |
    Select-Object FullName, LastWriteTime, Length

# Privacy-cleaner execution evidence in Prefetch - the meta-artifact that outlives whatever it successfully cleaned up
Get-ChildItem "$env:SystemRoot\Prefetch" -Filter *.pf | Where-Object Name -match 'CCLEANER|BLEACHBIT|PRIVAZER' | Select-Object Name, LastWriteTime

# Extensions with "run in incognito" enabled (Chromium Secure Preferences) - can hold a fuller record than the browser's own history
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\*\Secure Preferences","$env:LOCALAPPDATA\Microsoft\Edge\User Data\*\Secure Preferences" -ErrorAction SilentlyContinue |
    ForEach-Object { (Get-Content $_ -Raw | ConvertFrom-Json).extensions.settings.PSObject.Properties |
        Where-Object { $_.Value.incognito_content_settings -or $_.Value.newAllowFileAccess } | Select-Object Name }
```

PowerShell cannot carve unallocated disk space, parse memory dumps, or query SQLite/ESE page internals natively — everything above is presence/triage, not recovery. The actual carving/parsing work (memory strings, page-signature carving, `sqlite3 .recover`, `esentutl /r`) is covered in [Tooling](#tooling) below.

## What Private Browsing Actually Does NOT Do

Chrome/Edge "Incognito," Firefox "Private Browsing," and IE/Legacy Edge "InPrivate" are all, mechanically, the same idea: the browser stops **writing new rows** to the on-disk `History`/`places.sqlite`/`WebCacheV01.dat` artifacts documented in the three sibling notes for the duration of that session, and it typically discards session-scoped state (cookies, Local Storage/session data created during the session) when the private window closes. That's it. That's the entire guarantee.

🔴 **The framing every analyst needs going into this note: private browsing raises the bar for what's recoverable — it does not make browsing forensically invisible.** Specifically, private browsing does **not**:

- **Prevent network-level logging.** The ISP, a corporate proxy/firewall, a DNS resolver — none of them know or care that the browser tab was in private mode. Every one of those still sees and can log the traffic exactly as it would for a normal window.
- **Stop enabled extensions from seeing the session.** If a browser extension has been granted permission to run in private/incognito windows (a per-extension, user-configurable setting in Chromium — see [Extension Data](#extension-data) below), that extension observes the session just as normally as it would outside private mode.
- **Prevent the OS from ever touching disk.** Private mode is a *browser-application-layer* promise, not an OS-layer one. Windows' own memory manager can still page browser process memory out to `pagefile.sys`/`swapfile.sys` under memory pressure, entirely independent of — and unknown to — whatever the browser's private-mode logic intended. A browser process crash during a private session can still produce a crash dump containing in-memory browsing data.
- **Prevent artifacts generated by the ACT of navigating, even when the specific URL isn't logged by the browser.** DNS resolution still happens and still populates the OS DNS cache. Depending on configuration, `Prefetch`/ShimCache/Amcache (note 06) can still record that the *browser process itself* ran during the relevant window — not what URL was visited, but that the browser was active, which is still a timeline anchor.

The through-line for the rest of this note: **private browsing protects against the browser's own deliberate writes to its own artifact files. It does nothing about the OS's independent, browser-unaware memory-management writes, nothing about anything happening off-host, and nothing about anything a still-enabled third party (extension, network device) chooses to record.** Every recovery avenue below exploits one of those gaps.

## Where Private-Browsing Evidence Can Still Surface

### DNS Cache

A private session still has to resolve hostnames to IP addresses like any other session — DNS resolution is an OS-level service the browser calls into, not something private mode suppresses. On a live system, `ipconfig /displaydns` dumps the current resolver cache, which can retain recently resolved hostnames regardless of which browser (or which browsing mode) triggered the resolution, until TTL expiry or reboot clears them. This is a fast, zero-cost first check during live response (see note 16, Live Response and Volatile Data) — cheap to pull, and it doesn't prove *what page* was visited, only that a hostname was resolved on this host in a recent window, which is still useful corroboration when the browser's own history is empty.

For DNS cache analysis using PowerShell:

Full resolver-cache dump, PowerShell's native equivalent of `ipconfig /displaydns`:

```powershell
Get-DnsClientCache | Format-List *
```

A/AAAA records only, sorted by remaining TTL descending (the most recently resolved entries have the most TTL left):

```powershell
Get-DnsClientCache | Where-Object Type -in 1, 28 | Sort-Object TimeToLive -Descending | Select-Object Entry, Type, TimeToLive, Data
```

Pull the resolver cache across a set of hosts in one pass:

```powershell
Invoke-Command -ComputerName (Get-Content C:\hunt\hosts.txt) -ScriptBlock { Get-DnsClientCache } |
    Export-Csv C:\hunt\dns_cache_sweep.csv -NoTypeInformation
```

### Memory (RAM) — The Richest Source

This is the single most valuable recovery avenue when private browsing is suspected, and the reason is structural, not incidental: the browser has to hold the page content, the URL, and often form-field data **in memory** in order to render and interact with it at all — private mode doesn't change that, it only changes whether that data later gets *written back out* to a database file. So for the duration a private-browsing tab or window is open (and often for some time after it closes, until the OS reuses that physical memory page for something else), the evidence private mode "hid" from the disk-based artifact trail is sitting in RAM in a form no different from any other tab's data.

Practically, this means: if private browsing is suspected or reported and a live-response opportunity exists, **memory acquisition should be prioritized disproportionately** relative to a normal browser-history investigation — it may be the *only* place the activity is recoverable at all. Once acquired, an analyst can string-search or carve a memory image for HTTP/HTTPS URL patterns, HTML tag fragments, or page-title text, and in some cases Chromium's separate incognito-profile process/memory context can itself be identifiable as a distinct region worth targeting — though I don't have high confidence in the exact current process-isolation internals well enough to assert a specific memory signature here; treat "incognito runs in a genuinely separate process context" as a lead worth pursuing with current memory-forensics tooling rather than a guaranteed offset or marker.

This note's job stops at explaining *why* memory becomes the primary target — full memory acquisition mechanics (live imaging methods, tool selection) and full memory *analysis* mechanics (process/string/artifact carving with tools like Volatility) belong to the forward-referenced **Memory Forensics** notes (note 17, `Memory Acquisition Fundamentals.md` and `Memory Analysis (Processes, Injection, Rootkits).md`) — not yet written as of this note, but this is the note that will own that depth.

For memory acquisition, note that PowerShell has no native memory-acquisition or memory-parsing capability — it cannot dump a process's address space or carve a `.dmp`/raw memory image itself. Its role here is limited to identifying *which* process to prioritize before handing off to a real acquisition tool:

```powershell
# Candidate PIDs and working-set size for a live memory-acquisition tool to target first
Get-Process -Name chrome, msedge, firefox, iexplore -ErrorAction SilentlyContinue |
    Select-Object Name, Id, @{N='WorkingSetMB'; E={ [math]::Round($_.WorkingSet64 / 1MB, 1) }}, StartTime
```

### Pagefile / Hiberfil / Swapfile Carving

The same logic as live memory capture applies to the **paged-out or hibernated version** of that memory, and this is a genuinely non-obvious point worth stating as plainly as possible:

🔴 **Private browsing protects against the browser's OWN deliberate writes to its OWN database files — it does not, and structurally cannot, protect against the OS's own independent memory-management writes.** When Windows pages out memory under pressure, it doesn't ask the browser's permission or consult the browser's privacy mode — it just writes whatever's in that physical page to `pagefile.sys` (or `swapfile.sys` on modern builds) because the memory manager needed to free that page for something else. If a private-browsing session's in-memory page/form/URL data happened to occupy a page that got swapped, it's now sitting on disk in `pagefile.sys` in exactly the same recoverable form it would be in a live memory capture — private mode never had any say in that decision, because paging is a kernel-level activity the browser doesn't control or get notified of. `hiberfil.sys` (produced on hibernation, effectively a full physical-memory snapshot written to disk) carries the same property for anything resident in memory at the moment of hibernation.

This is exactly why pagefile/hiberfil/swapfile carving is a real, working technique against private browsing at all — even after the live system has been powered off entirely, the file *on disk* can still hold fragments of the very browsing session the browser itself never wrote anywhere. The carving/string-search techniques are the same in principle as for a live memory image; the future Memory Forensics notes (note 17) own the acquisition and parsing mechanics for `pagefile.sys`/`hiberfil.sys`/`swapfile.sys` specifically — this note's contribution is the "why this even works against private mode" reasoning above.

For pagefile/hiberfil/swapfile analysis, note that PowerShell cannot carve `pagefile.sys`/`hiberfil.sys`/`swapfile.sys` — they're locked by the kernel while the system is live and require offline carving tools regardless. Native PowerShell use here is limited to confirming a carving target exists and sizing it before committing to acquisition:

```powershell
# Confirm presence/size of each carving target; -Force is required, these are hidden system files
Get-ChildItem C:\ -Force -Include pagefile.sys, hiberfil.sys, swapfile.sys -ErrorAction SilentlyContinue |
    Select-Object Name, @{N='SizeGB'; E={ [math]::Round($_.Length / 1GB, 2) }}, LastWriteTime
```

### Network-Level Logs

Outside the host entirely, but worth naming plainly as the most *reliable* source when host-based recovery comes up empty: DNS server logs, proxy/firewall logs, and NetFlow/network-traffic logs were never subject to the browser's private-mode write-suppression in the first place — that suppression is purely a browser-application-layer behavior, and none of these logging systems are part of the browser at all. If the organization has egress logging or DNS logging in place, it is frequently a cleaner and more complete source for "what did this host reach out to during the private-browsing window" than anything recoverable from the host itself. Full network-log analysis is out of this repo's host-forensics scope — this note names it as an avenue, not a how-to.

### Extension Data

If a browser extension was installed and the user (or an attacker with browser-configuration access) enabled it to **"Allow in InPrivate"/"Run in Incognito"** — a genuinely per-extension, user-configurable setting in Chromium — that extension continues to run and observe the private session normally. Critically, **the extension's own storage is not automatically subject to private mode's session-clearing behavior the same way the browser's own history/cookies are.** An extension's `Local Storage`/IndexedDB data, keyed under its own extension ID (see the Chromium note's Extensions section for where that data lives on disk), can persist across private-session close the same way it would for a normal session, because that persistence is the extension's own code and storage model, not the browser core's private-mode logic. This is a lesser-known but genuinely useful artifact source: a compromised or monitoring-capable extension enabled for private-mode use can end up holding a more complete record of a "private" session than the browser itself ever did.

For extension data analysis using PowerShell:

Enumerate installed Chromium extension IDs/names/versions from each profile's manifest, without touching the incognito flag itself (that's in Hunt Evil above):

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\*\Extensions\*\*\manifest.json",
              "$env:LOCALAPPDATA\Microsoft\Edge\User Data\*\Extensions\*\*\manifest.json" -ErrorAction SilentlyContinue |
    ForEach-Object { $m = Get-Content $_ -Raw | ConvertFrom-Json; [PSCustomObject]@{ Path = $_.FullName; Name = $m.name; Version = $m.version } }
```

An extension's own Local Storage/IndexedDB files, keyed under its extension ID, worth collecting when that extension was incognito-enabled:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\*\Local Extension Settings\*" -Directory -ErrorAction SilentlyContinue |
    Select-Object Name, FullName, LastWriteTime
```

### Thumbnail/Preview Caches

Windows' own thumbnail cache (`Thumbcache`, covered in note 08 — Deleted Items and File Existence) can retain a rendered preview of an image or page element viewed during a private session **if the OS generated a thumbnail for some reason unrelated to the browser's privacy mode** — most commonly, a file (an image, a PDF) downloaded during a private session and saved to disk. Once that file is saved, it's an ordinary file on an ordinary filesystem; Windows Explorer generating a thumbnail for it has nothing to do with which browser mode originally fetched it. This is a good concrete illustration of this note's core framing principle: **private browsing only protects the browser's own artifact trail, not everything downstream that subsequently interacts with a file the private session happened to produce.** Once evidence crosses out of the browser's own database/cache model and into the general filesystem, it's governed by the same rules as anything else on that filesystem — see note 08 for `Thumbcache`/`IconCache` mechanics generally.

For thumbnail/preview cache analysis using PowerShell:

List the thumbnail-cache database files themselves (parsing their internal entries requires a dedicated tool, per note 08 — this just confirms presence/size/recency):

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\Explorer" -Filter thumbcache_*.db | Select-Object Name, Length, LastWriteTime
```

## SQLite Recovery Across All Browsers

Everything in this section applies to Chromium's and Firefox's SQLite-based artifacts (`History`, `Cookies`, `Web Data`, `Login Data`, `places.sqlite`, `cookies.sqlite`, `formhistory.sqlite`, and the SQLite-backed Local Storage files covered in the two sibling notes) uniformly — the recovery techniques are properties of the SQLite file format itself, not of any particular browser's schema.

**Deleted rows are not immediately gone.** SQLite, like NTFS itself (see NTFS/07's `$MFT`/orphan-file/carving concepts — the same underlying "deletion just deallocates, it doesn't zero" principle applies one layer up inside the database file), doesn't overwrite a deleted row's bytes at the moment of deletion. When a user clears browsing history through the browser's own UI, SQLite typically marks the corresponding pages/rows as free/unallocated within the `.sqlite` file rather than immediately scrubbing their contents — those bytes persist until a subsequent write operation happens to reuse that page. Practically: **a "cleared" History file can still be carved for deleted-row remnants**, and the fact that a user or attacker cleared history via the browser's own UI does not by itself guarantee the underlying data is unrecoverable.

🔴 **Always collect the WAL and rollback-journal sidecar files alongside the main database — this is a common, avoidable analyst mistake.** SQLite databases operating in write-ahead-log mode maintain a `-wal` file (and sometimes a `-shm` shared-memory index file) sitting alongside the main `.sqlite`/database file; databases using the older rollback-journal mode instead produce a `-journal` file during active transactions. Either sidecar can contain **very recent transactions — committed or even uncommitted — that have not yet been merged (checkpointed) back into the main database file.** An analyst who collects only `History` and leaves `History-wal` behind can miss the most recent activity in the case entirely, since it may exist only in the WAL at the moment of collection. Treat "grab the main file plus every same-named sidecar" as a non-negotiable collection step for every SQLite artifact in this subfolder.

Recovery/carving techniques and tooling, roughly in order of how intact the file needs to be:

| Technique | When to use | Notes |
|---|---|---|
| **`sqlite3` CLI `.recover` command** | Corrupted or partially-damaged `.sqlite` file that won't open normally | Modern SQLite's own command-line shell includes a built-in best-effort recovery mode that walks the file and reconstructs as much recoverable data as possible into a new, clean database — a strong first move on a corrupted browser database before reaching for anything more manual |
| **WAL/journal sidecar inspection** | Any live or freshly-collected profile | Not really "recovery" so much as "don't skip it" — open `-wal`/`-journal` files alongside the main database (some tools merge them automatically on open; verify yours does, or checkpoint manually) |
| **Unallocated-page/freelist carving within an otherwise-intact file** | An intact, openable `.sqlite` file where the browser's own UI was used to clear history and you suspect deleted rows remain in freed pages | A more advanced, page-level (not whole-file-level) technique — targets SQLite's internal freelist and unallocated page space for row remnants that haven't yet been overwritten by new activity |
| **Known-signature carving against unallocated disk space / a disk image** | The `.sqlite` file itself is deleted entirely, not just corrupted or cleared | Generic file-carving via SQLite's own page-header signatures, run against unallocated space the same way any other file-carving exercise would run — I don't have a specific named tool to confidently recommend for this exact use case beyond generic forensic carving suites; treat "SQLite page-signature carving is a known technique category" as the reliable takeaway rather than asserting a specific product does it best |

For SQLite recovery using PowerShell, note that PowerShell cannot open, query, or run `.recover` against a SQLite database — no native cmdlet understands the SQLite page format, so the `sqlite3` CLI in Tooling below is still required for the actual recovery. Native PowerShell use here is collection and integrity-preservation ahead of that step:

Confirm every sidecar is actually present before collection (the WAL/journal-omission mistake called out above):

```powershell
Get-ChildItem "$env:LOCALAPPDATA" -Recurse -Include History, Cookies, 'Web Data', places.sqlite -ErrorAction SilentlyContinue |
    ForEach-Object { Get-ChildItem "$($_.FullName)*" -Force }
```

Hash the main file and every sidecar together before handing off to `sqlite3 .recover`, so the recovery attempt doesn't get blamed for an integrity gap that predates it:

```powershell
Get-ChildItem "$env:LOCALAPPDATA" -Recurse -Include History, History-wal, History-journal, Cookies, Cookies-wal -ErrorAction SilentlyContinue |
    Get-FileHash -Algorithm SHA256 | Select-Object Path, Hash | Export-Csv C:\hunt\browser_db_hashes.csv -NoTypeInformation
```

## ESE Recovery (IE / Legacy Edge)

The IE & Legacy Edge note already establishes the core mechanics of `esentutl.exe` — that's not re-derived here. What matters for this note specifically: `esentutl /r` (repair a dirty-shutdown/inconsistent-state database into a consistent one) and `esentutl /p` (a more aggressive repair mode, generally reached for when `/r` isn't sufficient) can recover a `WebCacheV01.dat` or `spartan.edb` that's sitting in an inconsistent state — whether from an abrupt process termination, a crash, or a straightforward attempt at anti-forensic file tampering that left the database mid-transaction.

The same "check the sidecar files" principle from SQLite's WAL/journal applies here too, with a different mechanism underneath: ESE maintains its own internal versioning-store and **transaction-log files** (`.log` files sitting alongside the `.edb`) that can hold recent, not-yet-checkpointed transactions the same way a SQLite WAL does. Collecting only the `.edb`/`.dat` file and leaving its `.log` files behind risks the identical mistake as leaving a SQLite `-wal` file uncollected — same principle, different database engine.

For ESE recovery using PowerShell, note that PowerShell cannot read ESE's internal page/versioning-store structures — `esentutl.exe` (a native Windows binary, not a PowerShell cmdlet) is still required for both repair and any structured read. PowerShell's role is confirming what's present and, if repair is actually warranted, invoking that binary as a documented response action.

Confirm the `.dat`/`.edb` file and its transaction-log sidecars are all present:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\WebCache" -Include WebCacheV01.dat, '*.log' -Recurse -ErrorAction SilentlyContinue |
    Select-Object Name, Length, LastWriteTime
```

Repair a dirty-shutdown `WebCacheV01.dat` via `esentutl /r`; this is a destructive, in-place operation on the working copy, so it belongs on a **copy** of the evidence, never the original:

```powershell
# Evidence-first: work only on a copy
Copy-Item "$env:LOCALAPPDATA\Microsoft\Windows\WebCache\WebCacheV01.dat" C:\hunt\WebCacheV01_copy.dat
Copy-Item "$env:LOCALAPPDATA\Microsoft\Windows\WebCache\*.log" C:\hunt\ -Force

# Repair the copy - esentutl is a native Windows binary, invoked here from PowerShell, not a cmdlet itself
Start-Process esentutl.exe -ArgumentList '/r','WebCacheV01','/l','C:\hunt' -WorkingDirectory C:\hunt -Wait -NoNewWindow
```

## The Anti-Forensic/Evidence-Destruction Angle

This section is deliberately brief — full depth on Volume Shadow Copy analysis, `$LogFile`/`$UsnJrnl`-based deletion recovery, and timestomping detection belongs to the forward-referenced **note 19 (Anti-Forensics and Evidence Destruction)**, not yet written as of this note. What belongs here is the browser-specific slice of that broader topic.

An attacker or user deliberately trying to destroy browser evidence generally has three escalating options, and each leaves a different recoverability profile:

1. **Clear history via the browser's own UI.** The weakest destruction method from a forensic standpoint — it leaves exactly the recoverable-deleted-row trail described in [SQLite Recovery Across All Browsers](#sqlite-recovery-across-all-browsers) above (and the ESE equivalent for IE/Legacy Edge).
2. **Delete the profile folder entirely.** A much more thorough act — removes `History`/`Cookies`/`Web Data`/`places.sqlite`/etc. as files, not just as rows within them. Even here, file-level carving and NTFS journal-based recovery (`$LogFile`/`$UsnJrnl`, per NTFS/05, NTFS/06, and 19 - Anti-Forensics and Evidence Destruction) can sometimes recover fragments of the deleted files themselves, depending on how much subsequent disk activity has occurred since deletion.
3. **Use a dedicated privacy-cleaner tool** (CCleaner and similar tools exist in this category — naming CCleaner specifically as a commonly-encountered example, though I don't have confident, current knowledge of exactly which overwrite/secure-deletion techniques any specific version of CCleaner or a comparable tool implements against these exact files, so treat "these tools specifically target overwriting the artifact files this subfolder covers" as the general category behavior rather than a verified claim about any one product's internals). The forensically interesting angle here isn't the cleanup itself — it's that **the tool's own execution is a meta-artifact.** A privacy-cleaner tool has to run as a process on the host to do its job, which means its own execution can surface in the evidence-of-execution artifact family (Prefetch/ShimCache/Amcache — note 06) independent of whatever it successfully cleaned up. Finding CCleaner-or-similar execution evidence shortly before or after a suspected incident window is itself a red flag worth flagging explicitly (see Red Flags below), even when the browser artifacts it targeted are genuinely gone.

For anti-forensic/evidence-destruction analysis using PowerShell:

A Windows user profile still registered in `ProfileList` whose `ProfileImagePath` no longer resolves to a real folder points at deliberate deletion of the profile (and everything under it, including the browser folders) rather than an in-browser history clear — method 2's disk-level footprint:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction SilentlyContinue |
    Where-Object { $_.ProfileImagePath -and -not (Test-Path $_.ProfileImagePath) } |
    Select-Object ProfileImagePath, PSChildName
```

MITRE ATT&CK **T1070 (Indicator Removal)** is the attacker-technique umbrella this whole section sits under — see Resources.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Privacy-cleaner tool execution evidence (Prefetch/ShimCache/Amcache showing CCleaner or a similar tool ran shortly before/after a suspected incident window) | Meta-artifact evidence of deliberate cleanup intent — the tool's own execution can outlive whatever it successfully destroyed, per note 06 |
| History database shows a suspicious **gap** in visit timestamps rather than a fully empty/cleared history | Sometimes *more* suspicious than a fully cleared history — a targeted gap suggests deliberate, selective removal of specific activity rather than routine, wholesale privacy-clearing habit |
| Memory or pagefile artifacts recover URLs/page content with **no corresponding on-disk History entry** for that activity | Direct evidence private browsing (or equivalent write-suppression) was used for that specific browsing session — the disk-based trail from the sibling notes will never show this activity by design |
| WAL/journal (SQLite) or `.log` (ESE) sidecar files present with content not yet reflected/checkpointed into the main database file | Recent activity an analyst who only pulls the main `.sqlite`/`.dat`/`.edb` file will silently miss entirely |

## Tooling

| Tool | Use |
|---|---|
| **`sqlite3` CLI** (`.recover` command) | Best-effort recovery of a corrupted/damaged SQLite browser database — covered in detail above |
| **`esentutl.exe`** (built into Windows) | ESE repair (`/r`, `/p`) for a dirty-shutdown or corrupted `WebCacheV01.dat`/`spartan.edb` — full mechanics live in the IE & Legacy Edge note, this note only adds the "why it matters for anti-forensic recovery specifically" framing |
| **`strings` / `grep` / `findstr`** | Generic first-pass triage — string-searching a memory image, pagefile, or hiberfil for URL patterns (`http://`, `https://`), HTML fragments, or known page-title text, ahead of a more structured memory-forensics pass |
| **Memory-forensics toolchain (Volatility, etc.)** | Full acquisition and structured analysis of RAM/pagefile/hiberfil content — this note deliberately does not re-derive that toolchain; see the forward-referenced Memory Forensics notes (note 17) for full depth |
| **`ipconfig /displaydns`** | Live-response DNS-cache dump — fast, zero-cost first check when private browsing is suspected |
| **CCleaner / privacy-tool awareness** | Not a forensic tool — named here as something to *recognize the execution evidence of*, per the anti-forensics section above, not something to run |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Chromium's exact `History`/`Cookies`/`Web Data` schema, transition types, and Extensions storage model referenced throughout this note | Chromium (Chrome & Edge).md (this subfolder) |
| Firefox's exact `places.sqlite`/`cookies.sqlite`/`formhistory.sqlite` schema and PRTime epoch referenced throughout this note | Firefox.md (this subfolder) |
| IE/Legacy Edge's ESE artifact model (`WebCacheV01.dat`, `spartan.edb`) and the full `esentutl.exe` mechanics this note builds on | Internet Explorer & Legacy Edge.md (this subfolder) |
| `$MFT`/orphan-file/journal-based deletion-recovery concepts this note's SQLite-recovery reasoning parallels | NTFS/07 - File Deletion Mechanics |
| Evidence-of-execution artifacts (Prefetch/ShimCache/Amcache) — both for "the browser process still ran even in private mode" and "privacy-cleaner execution evidence" points | Evidence of Program Execution family (note 06) |
| Windows Thumbnail Cache and general deleted-item recovery mechanics | Deleted Items and File Existence (note 08) |
| Full memory acquisition and structured memory-analysis mechanics (RAM, pagefile, hiberfil carving in depth) | Memory Forensics family (note 17, forward reference — not yet written; this note is a lighter bridge to it, not a replacement) |
| Full anti-forensics/evidence-destruction depth (Volume Shadow Copy analysis, `$LogFile`/`$UsnJrnl` recovery, timestomping detection) | Anti-Forensics and Evidence Destruction (note 19, forward reference — not yet written; this note's anti-forensics section is deliberately brief and defers fully to that note) |

## Resources

- SQLite documentation — Write-Ahead Logging (WAL) mode and the `.recover` command, generic engine-behavior reference — https://www.sqlite.org/wal.html
- Microsoft Learn — ESE (`esent.dll`)/`esentutl.exe` documentation, same generic reference already cited in the IE & Legacy Edge note
- MITRE ATT&CK T1070 (Indicator Removal) — https://attack.mitre.org/techniques/T1070/
- SANS FOR500 poster/index, browser-artifacts panel and its private-browsing-recovery expansion — used as a coverage checklist for this note's scope (memory/pagefile recovery, SQLite/ESE recovery techniques), rewritten in this note's own words, no verbatim reproduction
- `SANS FOR500 Index _final.xlsx` — coverage checklist confirming this note's scope as the "richer browser section" expansion referenced in this repo's PLANNING.md
