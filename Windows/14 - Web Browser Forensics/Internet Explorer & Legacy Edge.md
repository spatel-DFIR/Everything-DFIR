# Internet Explorer & Legacy Edge

This note covers two related-but-distinct Microsoft browser lineages, both now legacy: classic **Internet Explorer** (IE, through IE11) and the original, non-Chromium **"Spartan"/Legacy Edge (EdgeHTML)** — Windows 10's default browser from 2015 until Microsoft rebuilt Edge on Chromium in January 2020. Neither is under active development, and Microsoft retired the standalone IE11 desktop application in June 2022 — but both still turn up constantly in real casework: older forensic images (Windows 7/8/8.1, early Windows 10) routinely carry IE artifacts, some regulated/legacy enterprise environments still run IE11 or Legacy Edge deliberately, and — critically — a fully modern, Chromium-only system can still generate IE's artifact format today via **IE mode** inside Chromium Edge (see below). An analyst who assumes "this system only ever ran modern Edge, so I can skip this note" can miss evidence sitting right on disk.

**Scope boundary:** the Chromium-based Edge (79+, 2020-present) — the "Edge" almost every current Windows 10/11 install ships with by default — is a completely different artifact set (SQLite + LevelDB, Chrome-compatible schema) and is covered in **Chromium (Chrome & Edge).md** (this subfolder), not here. Nothing in that note applies to the artifacts below, and nothing here applies to Chromium Edge except where IE mode bridges the two (see [IE Mode: A Bridge Back to This Note](#ie-mode-a-bridge-back-to-this-note)).

🔴 **The single most important framing point in this note: IE and Legacy Edge do not use SQLite.** Every artifact this repo's other browser notes describe — Chromium's `History`/`Cookies`/`Web Data`, Firefox's `places.sqlite` — is a SQLite database you can open with any generic SQLite browser. IE and Legacy Edge instead store their unified activity history in **ESE (Extensible Storage Engine)** — the same underlying database engine that backs Active Directory's `NTDS.dit` and Exchange Server's `.edb` mailbox stores (see note 05b and note 15 for those relatives). ESE and SQLite are unrelated file formats with unrelated tooling ecosystems. An analyst who shows up to this artifact with only DB Browser for SQLite in their kit will not get a "this file looks corrupt" error and a workaround — the tool will simply fail to recognize the file at all. You need ESE-aware tooling (`esentutl.exe`, ESEDatabaseView, or a purpose-built parser) for everything in this note's ESE-backed sections. This is worth internalizing before touching anything below.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Version & Storage-Format Timeline](#version--storage-format-timeline)
- [WebCacheV01.dat — IE's Unified ESE Store](#webcachev01dat--ies-unified-ese-store)
- [The Pre-ESE Era — index.dat](#the-pre-ese-era--indexdat)
- [TypedURLs Registry Key](#typedurls-registry-key)
- [Legacy Edge (EdgeHTML) — spartan.edb](#legacy-edge-edgehtml--spartanedb)
- [Legacy Edge's DOMStore](#legacy-edges-domstore)
- [IE Mode: A Bridge Back to This Note](#ie-mode-a-bridge-back-to-this-note)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage against IE/Legacy Edge artifacts — no third-party tool required. PowerShell has no native ESE cursor/query cmdlet, so these commands locate, enumerate, and hash the ESE containers (`WebCacheV01.dat`, `spartan.edb`) rather than reading records inside them — see Tooling for the ESE-aware viewers needed for that next step.

```powershell
# Locate every WebCacheV*.dat across all user profiles - confirms IE11 use and catches the filename-version hedge
Get-ChildItem 'C:\Users\*\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat' -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime

# Locate spartan.edb under the sandboxed Packages tree - Legacy Edge use, independent of WebCacheV01.dat
Get-ChildItem 'C:\Users\*\AppData\Local\Packages\Microsoft.MicrosoftEdge_*\AC\MicrosoftEdge\User\Default\DataStore\Data' -Recurse -Filter 'spartan.edb' -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime

# Both ESE stores active in the same recent window - confirms IE11 and Legacy Edge were both in use, don't assume only one was "the browser"
$webcache = Get-ChildItem 'C:\Users\*\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat' -ErrorAction SilentlyContinue
$spartan  = Get-ChildItem 'C:\Users\*\AppData\Local\Packages\Microsoft.MicrosoftEdge_*\AC\MicrosoftEdge\User\Default\DataStore\Data' -Recurse -Filter 'spartan.edb' -ErrorAction SilentlyContinue
$webcache + $spartan | Sort-Object LastWriteTime -Descending | Select-Object FullName, LastWriteTime

# TypedURLs across every mounted NTUSER.DAT-backed profile hive - deliberate, user-initiated navigation
Get-ItemProperty 'HKCU:\Software\Microsoft\Internet Explorer\TypedURLs' -ErrorAction SilentlyContinue

# Legacy DOMStore presence under the Packages tree - lesser-documented artifact, worth flagging as a lead
Get-ChildItem 'C:\Users\*\AppData\Local\Packages\Microsoft.MicrosoftEdge_*' -Recurse -Filter 'DOMStore' -Directory -ErrorAction SilentlyContinue |
    Select-Object FullName

# Pre-ESE index.dat leftovers - flags an older-format image or artifacts surviving from a pre-Win8 OS upgrade
Get-ChildItem 'C:\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\index.dat', 'C:\Users\*\AppData\Local\Microsoft\Windows\History\History.IE5\index.dat' -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime

# Hash every located ESE store for chain-of-custody before any esentutl /r repair touches the file
Get-ChildItem 'C:\Users\*\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat' -ErrorAction SilentlyContinue |
    Get-FileHash -Algorithm SHA256 | Select-Object Path, Hash
```

## Version & Storage-Format Timeline

Getting the lineage and the OS-version boundaries right matters more in this note than in most, because "which artifact format am I looking at" is itself the first triage question — get it wrong and you'll point the wrong tool at the wrong file.

| Era | Browser | Approx. OS floor/ceiling (hedge on exact builds) | Default-browser status | Underlying storage |
|---|---|---|---|---|
| IE5–IE9 | Internet Explorer | Windows XP through roughly Windows 7 (pre-SP1/early SP1 era for the older format) | Default browser on WinXP/Vista/7 | **`index.dat`** — multiple flat files scattered across per-artifact-type folders (see below) |
| IE10–IE11 | Internet Explorer | Roughly Windows 8 onward through Windows 10 (and installable/available on Windows 7 for IE11 specifically) | Default on Win8/8.1; still present and usable well into Windows 10 even after Edge's introduction, for legacy compatibility | **`WebCacheV01.dat`** (ESE) — consolidated history/cache/cookies/downloads store, replacing `index.dat` |
| "Spartan"/Legacy Edge (EdgeHTML) | Microsoft Edge (original) | Windows 10, 2015 (initial Win10 RTM) through the 2020 Chromium rebuild | Default browser on Windows 10 from launch until Chromium Edge rollout | **`spartan.edb`** (ESE) — Legacy Edge's own, separate ESE database; not the same file as `WebCacheV01.dat` despite both being ESE and both being Microsoft browsers |
| Chromium Edge | Microsoft Edge (79+) | 2020-present | Default on modern Windows 10/11 | SQLite + LevelDB — **covered in Chromium (Chrome & Edge).md, not this note** |

🔴 **IE11 didn't disappear the moment Edge launched.** Windows 10 shipped with both Legacy Edge *and* IE11 side by side for years specifically because enterprise intranet sites and legacy web apps often only worked correctly in IE's rendering engine. Microsoft didn't retire the standalone IE11 desktop application until June 2022. Practically: on any Windows 10 image from 2015–2022, don't assume "Edge was the browser" — check for both `WebCacheV01.dat` (IE11 use) and `spartan.edb` (Legacy Edge use) independently, they can both be actively populated on the same host across the same time window.

🔴 **Hedge explicitly:** the exact build-number cutover points above (particularly the `index.dat` → `WebCacheV01.dat` transition, which is generally associated with IE10/Windows 8 but had some presence earlier depending on update level) are approximate. If a precise cutover build matters to your case, verify against the specific OS build and IE version in front of you rather than relying on the era boundaries above — the two-format distinction itself (older per-folder `index.dat` vs. newer consolidated `WebCacheV01.dat`) is the reliable takeaway, the exact version number where it flips is the part worth double-checking.

## WebCacheV01.dat — IE's Unified ESE Store

| | |
|---|---|
| **Location** | `%LocalAppData%\Microsoft\Windows\WebCache\WebCacheV01.dat` |
| **Format** | ESE (Extensible Storage Engine) — same engine as `NTDS.dit`/Exchange `.edb`, unrelated to SQLite |
| **Filename** | Hedge: `WebCacheV01.dat` has been the common filename historically, but the exact version number embedded in the filename (`V01`, potentially others across IE/OS builds) can differ — treat the pattern as `WebCacheV*.dat` (per this repo's own PLANNING sourcing) rather than assuming `V01` is universal |

**The consolidation is itself the notable architectural point.** Where Chromium and Firefox split history, cache, cookies, and downloads across several *separate* files (`History`, `Cookies`, `Web Data`, `Cache\`, `places.sqlite`, etc. — see the sibling notes in this subfolder), IE folds **History, Cookies, Cache (Temporary Internet Files), and Download history all into one single ESE database container.** Internally, ESE organizes this data into what are generically called "containers" (ESE's rough conceptual analog to tables in a SQL database, though the internal model and naming differ from relational tables) — a container-per-artifact-type layout, generically including containers along the lines of `History`, `Content` (the cache), `Cookies`, and `iedownload` (download history). Exact internal container names, counts, and layout have varied across IE10/IE11 and across Windows 8/8.1/10 builds, so treat the names above as descriptive/generic rather than a guaranteed literal schema to expect byte-for-byte on every build — confirm the actual container list with an ESE-aware viewer (see Tooling) against the specific file in hand rather than assuming this note's names are exhaustive.

🔴 **`WebCacheV01.dat` is locked while in use — but it's a different lock, needing a different toolchain, than the SQLite files elsewhere in this subfolder.** Like Chromium's `History` or Firefox's `places.sqlite`, this file is held open by the OS/IE process during normal use, so a plain live copy will fail or return an inconsistent snapshot. The critical difference: recovering/copying a locked or "dirty shutdown" ESE database is an **ESE-specific operation**, not a SQLite one. `esentutl.exe` (built into Windows) is the tool for this — `esentutl /r` repairs/replays a dirty-shutdown ESE database into a consistent state, and `esentutl` with VSS-aware copy options (`/y` plus `/vss`) can pull a live-locked ESE file off a running system the way you'd otherwise need a shadow-copy-based approach for a locked SQLite file. An analyst reaching for DB Browser for SQLite here gets nothing — it doesn't understand the file format at all, not even enough to report a lock error. Know you're in ESE-land before you start.

### PowerShell

PowerShell has no native ESE cursor, so "basic" here is file-level: confirm existence, size, and last-write time as a pre-triage step before invoking an ESE-aware tool:

```powershell
Get-Item 'C:\Users\<user>\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat' | Select-Object FullName, Length, LastWriteTime, Attributes
```

sweep an estate for `WebCacheV*.dat` presence/size across hosts via PSRemoting, and export for pivoting before running `esentutl` locally on each hit:

```powershell
Invoke-Command -ComputerName (Get-Content C:\hunt\hosts.txt) -ScriptBlock {
    Get-ChildItem 'C:\Users\*\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat' -ErrorAction SilentlyContinue |
        Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, FullName, Length, LastWriteTime
} | Export-Csv C:\hunt\webcache_sweep.csv -NoTypeInformation
```

not applicable here in the persistence/removal sense this repo uses elsewhere (this is a read-only evidentiary artifact, not an attacker-controlled config); the only "action" is evidence preservation before repair — hash the file, then let `esentutl /r` run against a copy, never the original:

```powershell
Get-FileHash 'C:\Users\<user>\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat' -Algorithm SHA256
```

## The Pre-ESE Era — index.dat

Before IE10's consolidated `WebCacheV01.dat`, older IE versions (roughly IE5 through the IE9/pre-Windows-8 era) stored history, cookies, and cache metadata in **`index.dat`** — an older, simpler, non-ESE flat-file format, with **one `index.dat` file per artifact type per location**, scattered across several per-user folders rather than unified into a single database:

| Era | Typical `index.dat` locations (approximate, varies by OS/profile config) |
|---|---|
| Older IE (pre-IE10/pre-Win8) | `History\index.dat`, `Cookies\index.dat`, `Temporary Internet Files\index.dat` — each under the user's profile, in the corresponding History/Cookies/Temporary Internet Files subfolders |

This is the format you'll encounter on **older evidence** — Windows XP/Vista/early-Windows-7-era images, or any system that never moved past IE9. Treat it as the artifact family's predecessor: same evidentiary questions (what did the user visit, what cookies were set, what was cached) as `WebCacheV01.dat` answers on newer systems, but a structurally simpler, non-ESE format that older-generation IE forensic tools (and some still-current ones — see Tooling) target specifically. Don't assume a modern ESE-focused toolchain will open an `index.dat` file, and don't assume an `index.dat`-focused legacy tool will open `WebCacheV01.dat` — confirm which era's format you're actually looking at before picking a tool.

### PowerShell

enumerate every `index.dat` under a profile's History/Cookies/Temporary Internet Files folders; like `WebCacheV01.dat`, PowerShell has no native reader for the flat-file internal format, this is file-level triage only:

```powershell
Get-ChildItem 'C:\Users\<user>\AppData\Local\Microsoft\Windows\History', 'C:\Users\<user>\AppData\Local\Microsoft\Windows\Temporary Internet Files', 'C:\Users\<user>\Cookies' -Recurse -Filter 'index.dat' -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime
```

## TypedURLs Registry Key

Independent of both `index.dat` and `WebCacheV01.dat`, IE (across essentially all versions covered by this note) records URLs the user **manually typed** into the address bar in the registry:

| | |
|---|---|
| **Key** | `HKCU\Software\Microsoft\Internet Explorer\TypedURLs` |
| **Values** | `url1`, `url2`, `url3`, ... — most-recent-first, a capped MRU list |
| **Forensic weight** | Same interpretive value as Chromium's `TYPED` transition type or Firefox's typed-navigation visit flag (see the sibling notes) — a URL appearing here is strong evidence of **deliberate, user-initiated navigation**, not an incidental click-through or redirect |

Because this lives in the registry rather than in the ESE store, it survives independently — it's readable from an offline `NTUSER.DAT` hive with the same mechanics covered in note 04 (Registry Forensics Fundamentals), and it's worth pulling even when `WebCacheV01.dat` is missing, corrupted, or unrecoverable. Cross-reference note 04 for hive-parsing mechanics generally, and note that a companion `TypedURLsTime` value (recording per-entry last-typed timestamps) has existed on some IE/Windows versions — verify its presence on the specific build in front of you rather than assuming it's always populated.

### PowerShell

pull `url1`...`urlN` in stored (most-recent-first) order alongside the companion `TypedURLsTime` value where present, since raw `Get-ItemProperty` output interleaves them with PSPath/PSProvider noise:

```powershell
$key = Get-Item 'HKCU:\Software\Microsoft\Internet Explorer\TypedURLs'
$times = Get-Item 'HKCU:\Software\Microsoft\Internet Explorer\TypedURLsTime' -ErrorAction SilentlyContinue
$key.GetValueNames() | Sort-Object { [int]($_ -replace 'url','') } | ForEach-Object {
    [PSCustomObject]@{ Entry = $_; Url = $key.GetValue($_); LastTyped = if ($times) { $times.GetValue($_) } }
}
```

pull `TypedURLs` from every local user's offline `NTUSER.DAT` (for profiles not currently logged on, where `HKCU:` won't reach them) by mounting each hive under a temporary key:

```powershell
Get-ChildItem 'C:\Users' -Directory | ForEach-Object {
    $hive = Join-Path $_.FullName 'NTUSER.DAT'
    if (Test-Path $hive) {
        reg load "HKU\temp_$($_.Name)" $hive | Out-Null
        Get-ItemProperty "Registry::HKEY_USERS\temp_$($_.Name)\Software\Microsoft\Internet Explorer\TypedURLs" -ErrorAction SilentlyContinue
        reg unload "HKU\temp_$($_.Name)" | Out-Null
    }
}
```

## Legacy Edge (EdgeHTML) — spartan.edb

Legacy Edge — codenamed "Spartan" during development, built on the **EdgeHTML** rendering engine — was a ground-up rewrite from IE, not an evolution of it, and that shows in its storage: Legacy Edge uses **its own separate ESE database**, `spartan.edb`, structurally similar in spirit to `WebCacheV01.dat` (same ESE engine, same "unify history/cookies/cache/downloads into one container-based store" philosophy) but a **wholly different file, in a wholly different location, with its own internal layout** — the two are not interchangeable and one does not supersede or replace the other on a system where both were used.

**Location** (hedge on the exact full path — it's long and version/package-dependent, but the structure below is the key point):

```
%LocalAppData%\Packages\Microsoft.MicrosoftEdge_<PackageFamilyName>\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\<GUID>\DBStore\spartan.edb
```

🔴 **The `Packages\Microsoft.MicrosoftEdge_...` path structure is itself a distinctive forensic marker.** Legacy Edge was distributed and sandboxed as a **UWP/Windows Store-style packaged app** — a genuinely different application model from IE (a traditional Win32 desktop app) and from every other browser covered in this subfolder, all of which live under the conventional `%LocalAppData%\<Vendor>\<Product>\...` convention. Legacy Edge's artifacts instead live inside the AppContainer-sandboxed `Packages\` tree that Windows uses for Store/UWP apps generally — the same broad packaging model as other Modern/UWP apps introduced starting with Windows 8 (see note 01 for that OS-version context). If you're searching a disk image for "the Edge folder" using IE/Chrome-style path conventions as your mental model, you will walk right past it — search under `Packages\Microsoft.MicrosoftEdge_` instead.

`spartan.edb` holds history, cookies, and related activity data in ESE format, structurally analogous to `WebCacheV01.dat` — the same `esentutl`-based repair/recovery approach and the same "you need ESE tooling, not SQLite tooling" caveat apply here without modification.

### PowerShell

resolve the actual `PackageFamilyName` under a profile first (the GUID/version-qualified path segment varies per install), then confirm `spartan.edb`'s presence and timestamps against it:

```powershell
Get-ChildItem 'C:\Users\<user>\AppData\Local\Packages' -Directory -Filter 'Microsoft.MicrosoftEdge_*' |
    Get-ChildItem -Recurse -Filter 'spartan.edb' -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime
```

## Legacy Edge's DOMStore

Legacy Edge's equivalent of HTML5 **Local Storage** (the client-side key-value persistence mechanism modern web apps use — see the Chromium note's LevelDB-based treatment of the same concept for Chrome/Chromium Edge) is stored as **DOMStore** files, living under the same sandboxed `Packages\Microsoft.MicrosoftEdge_...` structure as `spartan.edb` above.

Honest hedge: DOMStore is a comparatively lesser-documented artifact in public DFIR literature relative to `spartan.edb` and `WebCacheV01.dat`, and this note isn't confident enough to assert DOMStore's exact on-disk file format (whether it's XML-structured, a binary format, or something else) without verifying against a specific sample. Treat DOMStore's presence under a `Packages\Microsoft.MicrosoftEdge_...\DOMStore\` (or similarly named) path as a lead worth pursuing with a current forensic reference or a purpose-built parser at the time of the exam, rather than something this note can characterize field-by-field the way it does for `WebCacheV01.dat`'s containers above. The FOR500 index (this note's sourcing reference) also lists a few adjacent, similarly lesser-documented Legacy Edge artifacts worth being aware of even though this note doesn't go deep on them individually — **WebNotes** (tied to Edge's page-annotation/web-note feature) and `.vcrd`-extension files — flag both as leads to research against the specific build in scope rather than artifacts this note can characterize confidently today.

### PowerShell

once a `DOMStore` folder is located (see Hunt Evil), list its actual contents and per-origin timestamps — the format itself isn't natively parseable, so this is inventory, not content extraction:

```powershell
Get-ChildItem 'C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftEdge_*' -Recurse -Filter 'DOMStore' -Directory -ErrorAction SilentlyContinue |
    Get-ChildItem -Recurse -File | Select-Object FullName, Length, LastWriteTime
```

## IE Mode: A Bridge Back to This Note

Chromium Edge (2020+) ships a feature called **IE mode** — rendering specific pages (typically legacy intranet sites configured via an enterprise site list) using IE's actual legacy rendering engine, embedded inside the modern Chromium Edge shell, rather than Chromium's own engine.

🔴 **This is a genuinely useful, non-obvious forensic point: IE mode use can still generate this note's ESE-based artifacts, even on a system whose only installed/visible browser is modern Chromium Edge.** A host that looks, at a glance, like pure Chromium-Edge territory (nothing in Chromium's `History`/`Cookies` explains a particular page) may still have relevant activity sitting in `WebCacheV01.dat` or the `TypedURLs` registry key because the page in question was rendered in IE mode. Don't conclude "this system never used legacy IE artifacts" purely from the absence of a standalone IE11/Legacy Edge installation — check for `WebCacheV01.dat` activity independent of which browser icon the user actually clicked.

This also has a real offensive/adversarial angle worth flagging explicitly: IE mode's older rendering engine has historically carried a weaker, less-hardened security posture than Chromium's own engine, and forcing a target page into IE mode (via a crafted enterprise site-list entry, or social-engineering a user into manually invoking it) has been used as a technique to render phishing or exploit content under a less-scrutinized, less-patched rendering path than the browser's default modern engine would provide. Treat unexplained IE mode activity — especially IE mode rendering of an external/internet-facing page rather than the intranet content it's meant for — as worth investigating context for: it's sometimes a legitimate legacy-compatibility need, and sometimes a deliberate attempt to exploit IE mode's weaker rendering behavior.

### PowerShell

check whether IE mode is enabled via Group Policy and where the enterprise site-list XML is configured from; a site list pointing somewhere unexpected (or IE mode force-enabled with no corresponding legacy-intranet justification) is the policy-side half of this section's red flag:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'InternetExplorerIntegrationLevel', 'InternetExplorerIntegrationSiteList' -ErrorAction SilentlyContinue
```

## Tooling

This note's tooling is architecturally distinct from every other note in this subfolder — nothing here is a SQLite tool.

| Tool | Use |
|---|---|
| **`esentutl.exe`** (built into Windows) | **The foundational ESE tool — the ESE-world equivalent of "copy the SQLite file before opening it."** `esentutl /r` repairs/recovers a dirty-shutdown ESE database (`WebCacheV01.dat` or `spartan.edb`) into a consistent, openable state. `esentutl` with VSS-aware copy options (`/y` + `/vss`) can extract a live, locked ESE file off a running system. Reach for this first on any ESE artifact in this note, before any GUI viewer |
| **NirSoft `ESEDatabaseView`** | Generic ESE database viewer — opens the raw container/table structure of `WebCacheV01.dat` or `spartan.edb` directly, the closest ESE-world equivalent to DB Browser for SQLite. Useful fallback for any ESE file regardless of which specific browser produced it |
| **NirSoft `IECacheView`** | Purpose-built viewer for IE's cache (Temporary Internet Files), reading from `WebCacheV01.dat` (modern IE) or `index.dat` (legacy IE) as appropriate — NirSoft has long-standing, mature tooling here given how long IE was the dominant browser |
| **NirSoft `IEHistoryView`** | Purpose-built viewer for IE browsing history, same modern-vs-legacy format awareness as `IECacheView` |
| **NirSoft `IECookiesView`** | Purpose-built viewer for IE cookies |
| **libesedb** (open-source, part of the libyal project) | Generic open-source ESE parsing library — the fallback for raw ESE access when no GUI tool covers a specific artifact or when scripting bulk extraction is preferable to a one-off GUI session |
| **RegRipper** / **Registry Explorer** (Eric Zimmerman) | For `TypedURLs` and other registry-resident IE artifacts — standard hive-parsing tools already established elsewhere in this repo (note 04, note 06/10) |
| **Honest gap** | This note isn't confident there is a dedicated Eric Zimmerman tool specifically targeting `WebCacheV01.dat`/`spartan.edb` parsing the way EZ's suite covers Prefetch/ShimCache/registry/EVTX elsewhere in this repo — EZ's suite is not known (to this note's authoring confidence) to include an ESE-browser-specific parser. Don't expect EZ coverage here that may not exist; verify against the current EZ tool list before assuming a gap in your kit |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `TypedURLs` entries pointing to a known-bad or unexpected domain | Deliberate, user-initiated navigation — same interpretive weight as Chromium's `TYPED` transition or Firefox's typed-navigation flag |
| IE mode activity on a modern Chromium-Edge-only system, especially rendering external/internet content rather than expected intranet sites | Could be legitimate legacy-compat need, or a deliberate attempt to render phishing/exploit content under IE mode's older, potentially less-hardened rendering engine |
| `index.dat`, `WebCacheV01.dat`, or `spartan.edb` showing active/recent entries on a system where the "known" primary browser is Chrome or modern Edge | Suggests either legitimate legacy-compatibility use (an old intranet app, IE11 kept around deliberately) or an attempt to operate under a browser family less familiar to — and less monitored by — the analyst/organization's usual tooling |
| `spartan.edb` and `WebCacheV01.dat` both showing activity in the same time window on one host | Confirms both IE11 and Legacy Edge were in active use concurrently — don't assume only one was "the browser" on any Windows 10-era image |
| ESE artifact (`WebCacheV01.dat`/`spartan.edb`) in a dirty-shutdown state at collection | May indicate an abrupt process termination or system crash near the time of interest — worth correlating with other crash/shutdown artifacts before assuming benign cause |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Chromium Edge's separate, SQLite/LevelDB-based artifact set, and the mechanics of how IE mode inside Chromium Edge can still generate this note's ESE artifacts | Chromium (Chrome & Edge).md (this subfolder) |
| Registry hive structure and offline hive-parsing mechanics generally — relevant both to `TypedURLs` directly and conceptually, since ESE and registry hives are both "structured binary databases needing dedicated parsers" rather than generic text/flat files | Registry Forensics Fundamentals (note 04) |
| Which OS version maps to which browser era — confirming whether a given image should even be expected to carry `index.dat`, `WebCacheV01.dat`, or `spartan.edb` before you go looking | Windows OS Fundamentals & Versions (note 01) |
| ESE as a database engine generally, its Active Directory and Exchange relatives | Active Directory & Domain Forensic Artifacts (note 05b — `NTDS.dit`), Email Forensics (note 15 — Exchange `.edb`/`.stm`) |
| Firefox's parallel-but-different artifact model | Firefox.md (this subfolder, forward reference) |
| Recovering browser artifacts from memory, unallocated space, or after deletion — applies to ESE-based artifacts as much as SQLite ones | Private Browsing & Anti-Forensic Recovery.md (this subfolder, forward reference) |
| Electron-embedded browser engines that aren't a general-purpose browser | Electron Apps (Teams, Discord, WebView2).md (this subfolder, forward reference) |

## Resources

- SANS FOR500 poster/index, browser-artifacts coverage — used as a coverage checklist for this note's artifact list (`WebCacheV*.dat`, `spartan.edb`, DOMStore, WebNotes, `.vcrd`), rewritten in this note's own words, no verbatim reproduction
- `SANS FOR500 Index _final.xlsx` — confirms this note's scope, including the IE-mode/privacy-setting callout and the ESE/SQLite carving distinction
- Microsoft Learn — ESE (`esent.dll`)/`esentutl.exe` documentation, generic reference for ESE repair/recovery syntax
- NirSoft utilities page — https://www.nirsoft.net/ (`ESEDatabaseView`, `IECacheView`, `IEHistoryView`, `IECookiesView`)
- libesedb (libyal project) — https://github.com/libyal/libesedb
