# Chromium (Chrome & Edge)

Google Chrome and Microsoft Edge (version 79 and later) are, under the hood, **the same browser**. Edge dropped its own EdgeHTML rendering engine in January 2020 and rebuilt itself on Chromium — the open-source engine Chrome is built on — which means the two browsers share almost identical profile layouts, identical SQLite schemas, and identical LevelDB-based storage mechanisms for the artifacts covered below. This is the single most useful fact in this note: learn Chrome's artifact model once, and Edge falls out almost for free. Where the two genuinely diverge, it's called out explicitly; everywhere else, assume parity.

This is deliberately the longest note in this subfolder. Chromium's user-activity evidence is spread across roughly half a dozen distinct SQLite databases plus two LevelDB-based key-value stores, each with its own set of forensically relevant tables and columns — there's no way to compress that into a short reference without losing the field-level detail that makes this note useful mid-incident.

**Scope boundary:** this note covers Chrome and Chromium-based Edge (79+) only. The pre-2020, non-Chromium **EdgeHTML** Edge (`spartan.edb`, its own DOMStore/cache model) is a completely different artifact set and is covered separately in **Internet Explorer & Legacy Edge.md** (this subfolder, not yet written) alongside classic Internet Explorer. Firefox's parallel-but-different artifact model (places.sqlite, different transition semantics, different encryption story) is covered in **Firefox.md** (this subfolder, not yet written) — this note calls out useful compare/contrast points as they come up. Recovering browser artifacts from memory, unallocated space, or after a private-browsing session is covered in **Private Browsing & Anti-Forensic Recovery.md** (this subfolder, not yet written). Electron-based apps (Teams, Discord, VS Code, and other apps that embed Chromium via WebView2/CEF but aren't "a browser" in the user-facing sense) get their own note, **Electron Apps (Teams, Discord, WebView2).md** (this subfolder, not yet written), since their artifact locations and forensic value diverge enough from a general-purpose browser to deserve separate treatment.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Profile Directory Structure](#profile-directory-structure)
- [History — The Core Artifact](#history--the-core-artifact)
- [Transition Types](#transition-types)
- [Cache](#cache)
- [Cookies](#cookies)
- [HTML5 Storage — LevelDB (Local Storage, Session Storage, IndexedDB)](#html5-storage--leveldb-local-storage-session-storage-indexeddb)
- [Autocomplete & Form Data](#autocomplete--form-data)
- [Passwords & DPAPI](#passwords--dpapi)
- [Sync](#sync)
- [Profiles & the Snapshots Folder](#profiles--the-snapshots-folder)
- [Downloads](#downloads)
- [Extensions](#extensions)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage across profiles and hosts — no third-party tool required. PowerShell has **no built-in SQLite provider**, so these commands enumerate, date-stamp, and hash the artifact files rather than querying inside them; opening `History`/`Cookies`/`Login Data`/`Web Data` at the row level still requires a SQLite-aware tool (see Tooling below).

```powershell
# Every Chrome/Edge profile on the box, across every Windows user account - the multi-profile under-collection trap this note warns about
Get-ChildItem "$env:SystemDrive\Users\*\AppData\Local\Google\Chrome\User Data\Profile*","$env:SystemDrive\Users\*\AppData\Local\Google\Chrome\User Data\Default","$env:SystemDrive\Users\*\AppData\Local\Microsoft\Edge\User Data\Profile*","$env:SystemDrive\Users\*\AppData\Local\Microsoft\Edge\User Data\Default" -Directory -ErrorAction SilentlyContinue

# History/Cookies/Login Data/Web Data presence and last-write time per profile - recency triage without opening the SQLite file
Get-ChildItem "$env:SystemDrive\Users\*\AppData\Local\*\*\User Data\*" -Include History,Cookies,'Login Data','Web Data' -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime, Length

# Chrome/Edge running right now - explains a locked-file read failure and flags a live-response window to close the browser first
Get-Process chrome,msedge -ErrorAction SilentlyContinue | Select-Object Name, Id, Path, StartTime

# Installed extensions and their permissions straight from Preferences JSON - no registry equivalent exists, Chromium extensions aren't tracked in the Run-key/Services sense
Get-ChildItem "$env:SystemDrive\Users\*\AppData\Local\*\*\User Data\*\Preferences" -ErrorAction SilentlyContinue | ForEach-Object {
    (Get-Content $_ -Raw | ConvertFrom-Json).extensions.settings.PSObject.Properties |
        Select-Object @{N='Profile';E={$_.Value.path}}, Name, @{N='Permissions';E={$_.Value.manifest.permissions -join ','}}
}

# .crdownload files on disk right now - a download actively in progress or interrupted at time of collection
Get-ChildItem "$env:SystemDrive\Users\*\Downloads" -Filter *.crdownload -Recurse -ErrorAction SilentlyContinue

# Files landed in Downloads in the last 24 hours - cheap cross-reference against History's downloads table without querying SQLite
Get-ChildItem "$env:SystemDrive\Users\*\Downloads" -File -Recurse -ErrorAction SilentlyContinue | Where-Object LastWriteTime -gt (Get-Date).AddDays(-1)

# Cross-host sweep for a running Chrome/Edge process across an estate - fast triage before pulling profiles from every box
Invoke-Command -ComputerName (Get-Content C:\hunt\hosts.txt) -ScriptBlock { Get-Process chrome,msedge -ErrorAction SilentlyContinue }
```

## Profile Directory Structure

| Browser | Profile root |
|---|---|
| **Chrome** | `%LocalAppData%\Google\Chrome\User Data\<Profile>\` |
| **Edge (Chromium, 79+)** | `%LocalAppData%\Microsoft\Edge\User Data\<Profile>\` |

`<Profile>` is `Default` for the first/primary profile, then `Profile 1`, `Profile 2`, etc. for each additional profile the user has created (Chrome and Edge both support multiple, fully independent profiles — think of each as a separate person using the browser, even if it's the same Windows user account).

🔴 **Every profile is a fully separate artifact set.** `History`, `Cookies`, `Web Data`, `Login Data`, `Local Storage`, `Extensions` — all of it — exists once per profile, independently. An analyst who only pulls `Default` on a machine with `Profile 1` and `Profile 2` in active use has silently missed two-thirds of the browser evidence on that host. Always enumerate `User Data\` for every `Profile *` folder (and check `Local State`, below, which lists configured profiles by name) before concluding a browser shows no relevant activity.

| File/folder (profile root) | Role |
|---|---|
| `Local State` (one level up, in `User Data\` itself, not per-profile) | JSON file listing all configured profiles, their display names, and some browser-wide settings — the fastest way to confirm how many profiles exist on a host without walking the filesystem manually |
| `Preferences` / `Secure Preferences` | Per-profile JSON settings files — extensions list, homepage, default search engine, sync status, and much more (see Extensions and Sync below) |

**Chrome vs. Chromium-Edge parity table** — because the two share an engine, nearly every artifact in this note applies to both with only the root path swapped:

| Artifact | Chrome filename | Edge (Chromium) filename | Same schema? |
|---|---|---|---|
| History | `History` | `History` | Yes |
| Cookies | `Cookies` | `Cookies` | Yes |
| Autofill/Autocomplete | `Web Data` | `Web Data` | Yes |
| Passwords | `Login Data` | `Login Data` | Yes |
| Local Storage | `Local Storage\leveldb\` | `Local Storage\leveldb\` | Yes (LevelDB) |
| IndexedDB | `IndexedDB\` | `IndexedDB\` | Yes (LevelDB) |
| Cache | `Cache\` (or `Cache_Data\` depending on build) | `Cache\` (or `Cache_Data\`) | Yes (Simple Cache format, see below) |
| Extensions | `Extensions\<ext-id>\<version>\` | `Extensions\<ext-id>\<version>\` | Yes (Chrome Web Store IDs; Edge also supports its own Add-ons store, same folder structure) |

Given that near-total parity, this note writes artifact paths once under the shared filename and expects the reader to substitute `Google\Chrome` ↔ `Microsoft\Edge` in the root path as needed — restating both roots for every single artifact would roughly double this note's length for zero added information.

## History — The Core Artifact

The `History` file (no extension — it's a SQLite database, confirm with a magic-byte check or DB Browser for SQLite if the lack of extension throws you) is the single richest artifact in a Chromium profile. Four tables matter most:

| Table | Key columns | What it holds |
|---|---|---|
| `urls` | `url`, `title`, `visit_count`, `last_visit_time` | One row per distinct URL ever visited — the page title as it existed at last visit, a running visit count, and the most recent visit timestamp |
| `visits` | `url` (FK to `urls.id`), `visit_time`, `transition`, `from_visit` | One row **per visit event** — every individual navigation to a URL, not deduplicated like `urls`. `transition` is where navigation-type evidence lives (see below). `from_visit` chains a visit back to the visit that led to it, letting you reconstruct navigation sequences |
| `downloads` | `target_path`, `tab_url`, `start_time`, `danger_type`, `state` | Download history — see the Downloads section below, this table is shared between "history" and "downloads" conceptually |
| `keyword_search_terms` | `term`, `url_id` | The **literal search query text** the user typed into the omnibox for a recognized search engine — often overlooked, and directly recovers what the user searched for even when the resulting search-engine results page URL itself doesn't cleanly expose the query string |

🔴 **Timestamp format pitfall.** `urls.last_visit_time` and `visits.visit_time` are stored in the **WebKit/Chrome epoch**: microseconds since **1601-01-01 00:00:00 UTC**. This is neither Unix epoch (seconds since 1970-01-01) nor Windows FILETIME (100-nanosecond intervals since 1601-01-01, used everywhere else in this repo's Windows notes) — it's a third, Chromium-specific convention that happens to share FILETIME's epoch year but not its unit. Converting by treating a Chrome timestamp as FILETIME (or vice versa) silently produces a wrong-by-orders-of-magnitude timestamp with no error thrown — a classic, easy-to-miss conversion mistake. Every tool in the Tooling section below handles this conversion automatically; if you're ever querying the raw SQLite database by hand, convert explicitly rather than trusting a spreadsheet formula you haven't verified against a known-good timestamp.

🔴 **The `History` file is locked while Chrome/Edge is running.** SQLite holds an exclusive lock on the file for the duration of the browser process, so attempting to open `History` directly off a live system with the browser still running will fail or return stale/incomplete data. Either close the browser first (not always viable mid-response), work from a byte-level copy of the file (most forensic imaging and most DB-browser/forensic tools do this copy-first automatically), or use a tool built for exactly this case. Don't assume a locked-file error means "no history exists" — it usually means the opposite.

### PowerShell

Confirm the file exists, hash it, and take a locked-file-safe copy for a SQLite-aware tool to open later — PowerShell has no native SQLite provider, so it can locate, copy, and hash `History` but can't query the `urls`, `visits`, and `downloads` tables inside it:

```powershell
Get-ChildItem "$env:LocalAppData\Google\Chrome\User Data\*\History" -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime, @{N='SHA256';E={(Get-FileHash $_.FullName).Hash}}

Copy-Item "$env:LocalAppData\Google\Chrome\User Data\Default\History" "C:\hunt\History_$(Get-Date -f yyyyMMddHHmmss).sqlite"
```

Convert the WebKit/Chrome epoch format as a reusable function for any raw microseconds-since-1601 value pulled out of History or Cookies by a SQLite-aware tool:

```powershell
function Convert-ChromeTime ([long]$WebKitMicroseconds) {
    [datetime]'1601-01-01Z' + [timespan]::FromTicks($WebKitMicroseconds * 10)
}
# Convert-ChromeTime 13350000000000000
```

## Transition Types

The `visits.transition` column encodes **how** the user arrived at a URL, not just that they arrived — and this is one of the most forensically important distinctions Chromium's history model offers, because it separates deliberate navigation from incidental navigation.

| Core transition type | Meaning | Forensic weight |
|---|---|---|
| `LINK` | User clicked a hyperlink to get here | Weak intent signal — could be one click among many in a chain the user didn't consciously choose the destination of |
| `TYPED` | User typed the URL (or a search term resolving to it) directly into the address bar | **Strong intent signal** — the user knew this destination and deliberately navigated to it, the browser equivalent of `TypedPaths` in note 07 |
| `AUTO_BOOKMARK` | Navigated via a bookmark the user had saved | Moderate intent signal — confirms the user had previously bookmarked the site, at minimum |
| `FORM_SUBMIT` | Reached via submitting an HTML form (e.g. a login page, a search box on a site) | Corroborates active interaction with a page, not just passive viewing |
| `RELOAD` | Page reload — not a new navigation destination | Low standalone value, but a burst of `RELOAD` events on one URL can indicate a user waiting on a slow-loading page (e.g. a C2 panel or exfil upload completing) |

| Qualifier flag (combines with a core type) | Meaning |
|---|---|
| `CLIENT_REDIRECT` | Page itself (via JavaScript/meta-refresh) redirected the browser — the user didn't choose the final URL, the page did |
| `SERVER_REDIRECT` | An HTTP redirect (3xx response) sent the browser onward — again, not a user choice |
| `FORWARD_BACK` | Reached via the browser's Forward/Back navigation buttons, not a fresh navigation |

**Why this matters in practice:** a `TYPED` transition to a phishing domain is strong evidence the victim was tricked into deliberately typing (or pasting) a malicious URL — a materially different narrative than a `LINK` transition with a `CLIENT_REDIRECT` qualifier, which more plausibly describes the user clicking a legitimate-looking link that silently bounced them somewhere else without their knowledge. When building a phishing or drive-by timeline, always check the transition type and qualifier flags before asserting the user "went to" a malicious site — the transition tells you whether that was a choice or something done to them.

### PowerShell

The `visits.transition` field is a packed 32-bit value where the low byte is the core type and the qualifier flags live in the high bits. Decode a raw value pulled from a SQLite-aware tool's output into something readable:

```powershell
function Convert-ChromeTransition ([int]$Transition) {
    $core = @{0='LINK';1='TYPED';2='AUTO_BOOKMARK';3='AUTO_SUBFRAME';4='MANUAL_SUBFRAME';5='GENERATED';6='START_PAGE';7='FORM_SUBMIT';8='RELOAD'}[$Transition -band 0xFF]
    $qualifiers = [System.Collections.Generic.List[string]]::new()
    if ($Transition -band 0x00800000) { $qualifiers.Add('CLIENT_REDIRECT') }
    if ($Transition -band 0x01000000) { $qualifiers.Add('SERVER_REDIRECT') }
    if ($Transition -band 0x02000000) { $qualifiers.Add('FORWARD_BACK') }
    [PSCustomObject]@{ Core = $core; Qualifiers = ($qualifiers -join ',') }
}
# Convert-ChromeTransition 805306370
```

## Cache

Chrome's disk cache — cached page resources, images, scripts — lives under `Cache\` (older builds sometimes use `Cache_Data\`) inside the profile, or in some configurations a browser-wide cache directory outside the profile folder. Since roughly Chrome 32, this uses the **Simple Cache** format: an index file plus a set of numbered data-block files, storing cached entries as raw blocks rather than as a SQLite database or discrete per-resource files.

Simple Cache is **not human-parseable by casual inspection** the way a SQLite table is — there's no straightforward "open it in DB Browser and read rows" path. Manually reconstructing cached content and its metadata (fetch time, response headers, originating URL) from the raw index/data-block files is realistically a job for a purpose-built parser, not manual review — see Hindsight in Tooling, which is the standard way to extract cache metadata and content alongside the rest of a Chromium profile's evidence in one pass.

### PowerShell

PowerShell can't parse Simple Cache's index and data-block format, but a quick size, count, and recency check tells you whether cache activity is present at all before handing the folder to Hindsight:

```powershell
Get-ChildItem "$env:LocalAppData\Google\Chrome\User Data\Default\Cache" -Recurse -File -ErrorAction SilentlyContinue |
    Measure-Object -Property Length -Sum | Select-Object Count, @{N='TotalMB';E={[math]::Round($_.Sum/1MB,1)}}
```

## Cookies

`Cookies` (SQLite) holds the `cookies` table:

| Column | Meaning |
|---|---|
| `host_key` | The domain the cookie belongs to |
| `name` | Cookie name |
| `value` | Plaintext value — **populated only for cookies the browser hasn't encrypted** |
| `encrypted_value` | DPAPI-encrypted blob — **populated for most modern cookies**, since Chrome encrypts cookie values by default on Windows |
| `expires_utc` | Expiration timestamp — same WebKit/Chrome epoch pitfall as History, see above |

🔴 **Expect `value` to be empty and `encrypted_value` to hold the real data on a modern Chrome/Edge profile.** This mirrors the password-storage story in the Passwords & DPAPI section below almost exactly: cookie values are DPAPI-encrypted, tied to the Windows user profile that created them, and decryption generally requires the same DPAPI-unwrap approach used for saved passwords — see that section for the account-binding mechanics, they apply here without modification. A raw SQLite dump of `Cookies` that shows `value` columns full of blank strings is not evidence the cookies are empty; it's evidence they're encrypted and you're looking at the wrong column.

Session-hijacking investigations (stolen/replayed authentication cookies) live squarely in this table — see MITRE ATT&CK T1539 in Resources.

### PowerShell

Confirm `Cookies` exists and take a locked-file-safe copy — same lock caveat as `History`, and same "no native SQLite provider" limitation — a SQLite-aware tool still has to open the `cookies` table itself:

```powershell
Get-ChildItem "$env:LocalAppData\Google\Chrome\User Data\*\Cookies" -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime, Length
```

Decrypt a DPAPI-protected blob in the current user's own security context (this only works if you're running as the account that created the cookie, and does not account for the post-2024 App-Bound Encryption layer flagged above — verify the build before trusting a failed or garbage result as "not DPAPI"):

```powershell
Add-Type -AssemblyName System.Security
$blob = [byte[]](Get-Content C:\hunt\encrypted_value.bin -Encoding Byte -Raw)  # extracted separately via a SQLite-aware tool
[System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($blob, $null, 'CurrentUser'))
```

## HTML5 Storage — LevelDB (Local Storage, Session Storage, IndexedDB)

Modern web applications increasingly keep client-side state in mechanisms that predate or bypass traditional cookies entirely — Local Storage, Session Storage, and IndexedDB. All three are stored under the profile folder, but critically, **none of them are SQLite** — they're built on **LevelDB**, Google's embedded key-value store, a completely different on-disk format from every artifact covered so far in this note.

| Storage type | Location | Typical use | Persistence |
|---|---|---|---|
| **Local Storage** | `Local Storage\leveldb\` | Small key-value pairs a site stores client-side (settings, tokens, flags) | Persists across browser restarts, until explicitly cleared |
| **Session Storage** | `Session Storage\leveldb\` | Same idea as Local Storage but scoped to a single tab/session | Cleared when the tab closes |
| **IndexedDB** | `IndexedDB\<origin>\` (also LevelDB-based internally) | A much higher-capacity, structured client-side database — used by web apps that need to store meaningfully large amounts of data locally (offline mail clients, PWAs, and — worth flagging specifically — some phishing/malicious pages use IndexedDB to stage captured credentials or exfiltration data client-side before transmission) | Persists like Local Storage, larger capacity ceiling |

This is exactly why **Hindsight** carries so much weight in this note's Tooling section: it's one of the few widely-used free tools that parses LevelDB-based Chromium artifacts (Local Storage, IndexedDB) **alongside** the SQLite-based ones (History, Cookies, Web Data) in a single pass and correlates them into one timeline — without it, LevelDB parsing is a meaningfully harder, more manual undertaking than opening a SQLite file.

### PowerShell

PowerShell has no LevelDB reader either, so enumerate origins and last-write recency as a presence or triage check before handing off to Hindsight:

```powershell
Get-ChildItem "$env:LocalAppData\Google\Chrome\User Data\Default\IndexedDB" -Directory -ErrorAction SilentlyContinue |
    Select-Object Name, LastWriteTime
```

## Autocomplete & Form Data

`Web Data` (SQLite) holds several tables worth checking individually:

| Table | Columns | What it reveals |
|---|---|---|
| `autofill` | field `name`, `value` | Form field values the user has typed anywhere on the web — this reaches well beyond the dedicated password manager, and can surface typed usernames, search terms, addresses, and other free-text entries even for sites the user never explicitly "saved" credentials for |
| `credit_cards` | payment-card metadata (masked/tokenized in most builds, but confirm on the version in front of you) | Chrome's built-in payment-info autofill, when the user has enabled it — sensitive by nature, flag and handle per your engagement's data-handling requirements regardless of exactly how much raw card data is actually stored locally |
| `keywords` | search-engine name, URL template, keyword shortcut | Every custom search engine the user (or something acting as the user) has added. This is itself a compromise indicator worth checking proactively — a malicious extension or a policy pushed by an attacker with admin access can silently add or change the **default** search engine to hijack omnibox queries, redirecting search traffic through an attacker-controlled endpoint |

### PowerShell

Confirm `Web Data` exists per profile before handing it to a SQLite-aware tool for the `autofill`, `credit_cards`, and `keywords` tables:

```powershell
Get-ChildItem "$env:LocalAppData\Google\Chrome\User Data\*\Web Data" -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime, Length
```

## Passwords & DPAPI

`Login Data` (SQLite) holds the `logins` table: `origin_url`, `username_value`, and `password_value`.

`password_value` is **not plaintext** — it's a **DPAPI-encrypted blob**. Windows Data Protection API ties the encryption key to the specific Windows user account that created it (technically, to that account's master key material, itself protected by the user's logon credentials). The practical consequence: **decrypting a saved password generally requires operating in the security context of that specific Windows user** — either running the decryption while logged in/impersonating as that user, or having recovered that user's DPAPI master key material separately (e.g. from a memory capture, or via an offline DPAPI-key-recovery technique against the SAM/domain credentials). You cannot simply copy `Login Data` off the disk and decrypt it in a vacuum on an unrelated system — this is the single most common point of confusion analysts hit with this artifact, and it's worth stating plainly up front rather than assuming it's obvious.

🔴 **Post-2024 Chrome (Windows) adds App-Bound Encryption on top of DPAPI.** Starting with Chrome 127 (mid-2024), Chrome introduced an additional encryption layer for sensitive data including saved passwords and cookies, binding decryption to the Chrome application itself (via a Windows service running as SYSTEM) rather than to the user account alone under plain DPAPI. This is intended specifically to defeat commodity infostealer malware that simply calls the DPAPI unwrap API as the logged-in user. I'm not fully confident in the exact current mechanics, rollout status across Chrome/Edge versions, or how completely App-Bound Encryption has superseded plain per-account DPAPI for every affected data type as of this note's writing — treat this as an evolving mitigation to verify against the specific Chrome/Edge build in front of you, rather than something to assume is either fully present or fully absent. Confirm the browser's build number and check current vendor documentation before asserting which encryption model applies to a given `Login Data`/`Cookies` extraction.

No dedicated DPAPI mechanics note exists yet in this repo's numbered sequence — if note 05 (Users, Groups & Authentication) later covers DPAPI/credential-material internals in depth, cross-reference it there; until then, treat the account-binding property explained above as the operative fact for this note's purposes.

### PowerShell

Confirm `Login Data` exists per profile (same "locate, hash, copy, not query" limitation as every other SQLite artifact in this note):

```powershell
Get-ChildItem "$env:LocalAppData\Google\Chrome\User Data\*\Login Data" -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime, Length
```

The same `ProtectedData]::Unprotect` DPAPI-decrypt pattern shown under Cookies above applies to `password_value` byte-for-byte identically — same current-user-context requirement, same App-Bound Encryption caveat on post-2024 builds. Not repeated here to avoid duplicating the exact command; see the Cookies section's Interpret block.

## Sync

When a user signs into a Google account (Chrome) or Microsoft account/Entra ID account (Edge) and enables Sync, the browser's local artifacts stop being a purely single-device record. The signed-in account's email address is recoverable locally from the profile's `Preferences`/`Sync Data` state, giving direct account attribution for whichever account is driving sync on this profile.

🔴 **Synced history/bookmarks can appear on a host the user never actually browsed on.** This is the browser-artifact parallel to the cloud-storage-sync pitfall covered in note 13 (OneDrive's "sync database entry can predate/postdate local file presence"): if Sync is enabled, entries in `History`, bookmarks, and potentially other synced data types can reflect activity that occurred **on a different device entirely**, pulled down to this host purely because the same account was signed in here. Before asserting "the user visited this site on this host at this time" from a synced profile, corroborate with a locally-generated artifact that can't have arrived via sync (e.g. Cache content, a Prefetch/ShimCache entry for a downloaded file, or the LNK/RecentDocs trail for a file that was actually saved to this machine) — history rows alone, on a synced profile, don't prove local origin.

### PowerShell

Pull the signed-in Sync account email straight out of `Preferences` JSON, confirming account attribution without opening any SQLite file. Note that `account_info` has shifted shape across Chrome versions (an array of accounts in some builds, a single object in others) — dump the raw property rather than trusting one fixed path, and verify against the actual `Preferences` file from the build under examination:

```powershell
Get-ChildItem "$env:LocalAppData\Google\Chrome\User Data\*\Preferences" -ErrorAction SilentlyContinue | ForEach-Object {
    $prefs = Get-Content $_ -Raw | ConvertFrom-Json
    [PSCustomObject]@{ Profile = $_.Directory.Name; AccountInfo = ($prefs.account_info | ConvertTo-Json -Compress -Depth 3); SyncEnabled = [bool]$prefs.sync }
}
```

## Profiles & the Snapshots Folder

Multi-profile enumeration matters enough to restate: every `Profile N` folder under `User Data\` is a fully independent artifact set (see Profile Directory Structure above) — this bears repeating specifically in the profiles context because it's the single most common way an analyst under-collects Chromium evidence.

Chrome/Chromium also maintains a `Snapshots\` folder under the profile, used in connection with session-restore/crash-recovery behavior (recovering open tabs after an unexpected browser exit). I don't have high confidence in the exact current contents, format, or retention behavior of this folder across recent Chrome versions — this is an area that has evolved release to release and is less documented than the core SQLite/LevelDB artifacts above. Treat its presence as a lead worth checking (it may hint at what was open at time of crash/close) rather than a fully characterized artifact you can rely on without verifying against the specific build under examination.

### PowerShell

Enumerate every profile's `Snapshots\` folder contents and timestamps as a lead, given the format itself isn't well-characterized enough here to interpret further:

```powershell
Get-ChildItem "$env:LocalAppData\Google\Chrome\User Data\*\Snapshots" -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime, Length
```

## Downloads

Download history is stored in the `downloads` table inside `History` (see the History section above — this is the same file, not a separate database). Rather than re-deriving the table structure, here's what to pull from it specifically:

| Column | Forensic value |
|---|---|
| `target_path` | Where the file was saved on disk — ties the download event to a filesystem artifact you can cross-check against note 06/08 |
| `tab_url` | The **referring page** — often the actual phishing page, malicious ad, or compromised site that initiated the download, distinct from the direct download URL itself |
| `danger_type` | Chrome's own Safe Browsing verdict at the moment of download — a value indicating Chrome itself flagged the file as dangerous is direct evidence the browser warned the user and (per the Red Flags table below) the user may have proceeded anyway |
| `state` | Download completion state (complete, interrupted, cancelled) |

**Live-response tell:** a partially-downloaded file with a `.crdownload` (Chrome) extension sitting on disk indicates an **in-progress or interrupted download** at the moment of collection — useful corroboration if you're trying to establish whether a download was actively happening at a specific point during incident response.

### PowerShell

hash every file sitting in a user's Downloads folder and export for offline comparison against a known-bad hash set, correlating the filesystem side of this table with threat-intel without needing to query `downloads.target_path` directly:

```powershell
Get-ChildItem "$env:SystemDrive\Users\*\Downloads" -File -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName, CreationTime, LastWriteTime, @{N='SHA256';E={(Get-FileHash $_.FullName).Hash}} |
    Export-Csv C:\hunt\downloads_hashes.csv -NoTypeInformation
```

## Extensions

`Extensions\<extension-id>\<version>\` under the profile holds one subfolder per installed extension, versioned. The `Preferences`/`Secure Preferences` JSON files in the profile root list installed extensions alongside the permissions each was granted at install time.

This matters beyond simple inventory: a malicious or compromised browser extension is a genuine **persistence and data-exfiltration vector** in its own right — broad extension permissions (`<all_urls>`, `webRequest`, access to cookies/tabs) give an extension DOM-level visibility into every page the user visits and network-request-level interception capability, without needing any separate malware on the host at all. This is a cross-cutting observation worth connecting explicitly to the Persistence Mechanisms family (note 10): a malicious extension behaves like a persistence mechanism in effect (it survives browser restarts, runs automatically, and often the user never consciously re-approved it after an update silently expanded its permissions) even though it doesn't fit neatly into any of that family's five specific notes (Autostart Keys, Services, Scheduled Tasks, WMI Event Consumers, DLL Hijacking) — it's a browser-native persistence primitive that sits outside the OS-level mechanisms those notes cover.

### PowerShell

filter the extension inventory (see Hunt Evil above for the full enumeration) down to the specific permission combination this note flags as the malicious-extension pattern:

```powershell
Get-ChildItem "$env:LocalAppData\*\*\User Data\*\Preferences" -ErrorAction SilentlyContinue | ForEach-Object {
    $profile = $_.Directory.Name
    (Get-Content $_ -Raw | ConvertFrom-Json).extensions.settings.PSObject.Properties | ForEach-Object {
        $perms = $_.Value.manifest.permissions
        if ($perms -match '<all_urls>' -and ($perms -match 'webRequest|cookies|tabs')) {
            [PSCustomObject]@{ Profile = $profile; ExtensionId = $_.Name; Name = $_.Value.manifest.name; Permissions = ($perms -join ',') }
        }
    }
}
```

response action, distinct from the read-only commands above: **capture the extension folder and its `Preferences` entry as evidence before removal.** Chrome/Edge have no native cmdlet to uninstall an extension; disabling it via policy or removing its `Extensions\<id>\` folder while the browser is closed is the practical native-tooling option, and either should happen only after evidence capture:

```powershell
# Evidence-first: preserve the extension's on-disk files and its Preferences manifest entry before touching anything
Copy-Item "$env:LocalAppData\Google\Chrome\User Data\Default\Extensions\<extension-id>" "C:\hunt\ext_<extension-id>_before_removal" -Recurse
(Get-Content "$env:LocalAppData\Google\Chrome\User Data\Default\Preferences" -Raw) | Out-File C:\hunt\Preferences_before_removal.json

# Removal - browser must be closed first (same file-lock constraint as History/Cookies); this deletes the extension's payload but does not itself edit Preferences
Stop-Process -Name chrome -Force -ErrorAction SilentlyContinue
Remove-Item "$env:LocalAppData\Google\Chrome\User Data\Default\Extensions\<extension-id>" -Recurse -Force
```

## Tooling

| Tool | Use |
|---|---|
| **Hindsight** (obelisk) | **The most important named tool in this note.** Purpose-built Chromium forensics parser — reads History, Cookies, Local Storage, IndexedDB, and Cache metadata together and correlates them into a single unified timeline, handling the WebKit epoch conversion and LevelDB parsing automatically. This is required reading/tooling for any serious Chromium browser examination; treat it as the default starting point rather than manually querying each SQLite file in isolation |
| **DB Browser for SQLite** | Generic manual inspection of `History`, `Cookies`, `Web Data`, `Login Data` — useful for targeted spot-checks or verifying Hindsight's output against the raw table, especially given the file-lock caveat above (always work from a copy) |
| **NirSoft ChromeHistoryView** | Lightweight, single-purpose GUI viewer for Chrome/Chromium history — fast triage tool, still in real-world DFIR use for a quick look without standing up a full parsing pipeline |
| **NirSoft ChromePass** | Lightweight GUI tool for recovering saved Chrome/Chromium passwords — operates within the same DPAPI account-binding constraint described above (must run in the right account context) |
| **KAPE** | Has Chromium/browser-artifact collection targets — confirm the exact target name against your current KAPE target list, but at minimum it's built to collect the profile paths in this note as a triage-time first step, ahead of deeper parsing |
| **Eric Zimmerman's tools** | Honest gap: EZ's suite (Registry Explorer, MFTECmd, JLECmd, PECmd, LECmd, etc.) is registry/EVTX/filesystem-focused, as established throughout this repo's other notes — there is no EZ tool dedicated to Chromium browser artifacts. Don't expect coverage here that doesn't exist |
| **Generic SQLite CLI** (`sqlite3`) | Fallback for any of the SQLite-format databases above when no GUI tool is available — remember to work from a copy given the live-lock caveat, and to convert WebKit-epoch timestamps manually if querying raw |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `TYPED` transition to a known-bad or newly-registered domain | Strong evidence of deliberate, user-initiated navigation to the site — a materially stronger phishing/social-engineering narrative than a `LINK`/`CLIENT_REDIRECT` arrival at the same URL |
| Extension with broad permissions (`<all_urls>`, `webRequest`, tab/cookie access) that the user doesn't recognize installing, or that silently gained permissions after an update | Classic malicious-extension pattern — DOM and network visibility across every page the user visits, functioning as a browser-native persistence and exfiltration mechanism |
| History/bookmarks entries on a synced profile with no corroborating locally-generated artifact (Cache, Prefetch, saved file) | Sync can pull in activity from a different device entirely — don't assert local browsing without independent local corroboration |
| `Login Data`/`Cookies` DPAPI-encrypted blobs recovered and matched to an account known to be compromised | Confirms the scope of credential exposure tied to that specific Windows account — pair with the account-binding explanation above when briefing non-technical stakeholders on why decryption isn't trivial off-host |
| `keywords` table shows a default search engine the user didn't knowingly configure | Search-engine hijack — attacker or malicious extension redirecting omnibox queries through a controlled endpoint |
| `downloads.danger_type` shows Chrome flagged a file as dangerous, but `state` shows it completed anyway | User (or an automated process) proceeded past Chrome's own Safe Browsing warning — directly relevant to establishing user awareness/intent in a malware-delivery timeline |
| `.crdownload` temp file present on disk at time of collection | Download was actively in progress or was interrupted — useful to pin down exact timing during live response |

## Correlate With

| To go deeper on… | Open |
|---|---|
| DPAPI account-binding mechanics and broader Windows credential material, if covered there | Users, Groups & Authentication (note 05) |
| The "sync can pull in off-host activity" pitfall, same evidentiary pattern applied to file-sync clients | OneDrive.md (note 13) — same class of pitfall, different artifact family |
| Firefox's equivalent history/cookie/password model — places.sqlite, different transition semantics, different encryption approach | Firefox.md (this subfolder, not yet written) |
| Pre-Chromium (EdgeHTML) Edge and classic Internet Explorer's completely different artifact set (`spartan.edb`, WebCacheV*.dat, DOMStore) | Internet Explorer & Legacy Edge.md (this subfolder, not yet written) |
| Recovering Chromium artifacts from memory, unallocated space, or a private/Incognito session | Private Browsing & Anti-Forensic Recovery.md (this subfolder, not yet written) |
| Chromium-embedded desktop apps (Teams, Discord, WebView2) that aren't general-purpose browsers but share the same underlying engine | Electron Apps (Teams, Discord, WebView2).md (this subfolder, not yet written) |
| Malicious extensions as a persistence mechanism, conceptually alongside OS-level persistence techniques | Persistence Mechanisms family (note 10) |
| Webmail activity reached through a browser, once that note exists | Email Forensics (note 15, forward reference — not yet written) |

## Resources

- Hindsight (obelisk) — https://github.com/obsidianforensics/hindsight
- NirSoft ChromeHistoryView — https://www.nirsoft.net/utils/chrome_history_view.html
- NirSoft ChromePass — https://www.nirsoft.net/utils/chromepass.html
- SANS FOR500 poster, browser-artifacts panel — coverage checklist for path/table facts, rewritten in this note's own words
- `SANS FOR500 Index _final.xlsx` — coverage checklist confirming the expanded browser scope (transition types, HTML5 storage/Hindsight, sync internals, Snapshots folder, DPAPI) this note builds out
- MITRE ATT&CK T1539 (Steal Web Session Cookie) — https://attack.mitre.org/techniques/T1539/
- MITRE ATT&CK T1176 (Browser Extensions) — https://attack.mitre.org/techniques/T1176/
