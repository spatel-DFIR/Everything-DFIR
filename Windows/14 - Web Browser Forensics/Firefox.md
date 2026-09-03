# Firefox

Firefox is built on **Gecko**, Mozilla's own rendering/browser engine — not Chromium. That single fact drives most of the differences in this note. Firefox still leans heavily on SQLite for its core artifacts (so the "open it in DB Browser for SQLite" workflow from the Chromium note largely still applies), but the schema, file layout, and — critically — the encryption model are genuinely different, not just renamed. Where Chromium spreads user activity across half a dozen purpose-specific files (`History`, `Cookies`, `Web Data`, `Login Data`), Firefox consolidates browsing history and bookmarks into a single unified database (`places.sqlite`) and keeps most other artifact categories in their own dedicated SQLite files rather than combining them the way Chromium's `Web Data` does.

This note assumes you've read (or will read) **Chromium (Chrome & Edge).md** in this subfolder — rather than re-deriving every concept from scratch, it calls out explicit contrast points against that note wherever Firefox's architecture diverges in a way that matters forensically (timestamp epoch, password encryption model, and history/bookmark consolidation are the three biggest).

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Profile Directory Structure](#profile-directory-structure)
- [The Places Database — History, Visits & Bookmarks](#the-places-database--history-visits--bookmarks)
- [Downloads](#downloads)
- [Cookies](#cookies)
- [Cache](#cache)
- [HTML5 Storage](#html5-storage)
- [Autocomplete & Form History](#autocomplete--form-history)
- [Passwords & NSS](#passwords--nss)
- [Sync](#sync)
- [Extensions/Add-ons](#extensionsadd-ons)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage against a live Firefox install — no third-party tool required. PowerShell has no native SQLite query cmdlet, so these locate, enumerate, hash, and stage the SQLite-format artifacts (`places.sqlite`, `cookies.sqlite`, `formhistory.sqlite`) rather than querying inside them — see Tooling below for the third-party query step.

```powershell
# Resolve every profile from profiles.ini rather than guessing the randomized folder prefix
Get-Content "$env:APPDATA\Mozilla\Firefox\profiles.ini" | Select-String '^(Name|IsRelative|Path|Default)='

# All profile folders across every local user, sorted by last-write - a proxy for which profile is actually active
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue |
    Select-Object Name, LastWriteTime | Sort-Object LastWriteTime -Descending

# .part files - an in-progress or interrupted download at time of collection, Firefox's analog to Chromium's .crdownload
Get-ChildItem "$env:USERPROFILE\Downloads" -Filter '*.part' -ErrorAction SilentlyContinue

# logins.json + key4.db recovered together - the trivially-decryptable-if-no-Primary-Password credential pair
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Recurse -Include 'logins.json','key4.db' -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime

# Recently modified cookies.sqlite - narrows the window for session-cookie theft/replay off a plaintext value column
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Filter 'cookies.sqlite' -Recurse -ErrorAction SilentlyContinue |
    Where-Object LastWriteTime -gt (Get-Date).AddDays(-7)

# Hash the core artifacts before any further handling, for chain-of-custody and later diffing
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Recurse -Include 'places.sqlite','cookies.sqlite','formhistory.sqlite','logins.json' -ErrorAction SilentlyContinue |
    Get-FileHash -Algorithm SHA256

# extensions.json across every profile on the host, for a fast unrecognized-add-on sweep
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Filter 'extensions.json' -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object { (Get-Content $_.FullName -Raw | ConvertFrom-Json).addons | Select-Object id, version, active }

# Cross-host sweep - locate every Firefox profile root across an estate in one pass
Invoke-Command -ComputerName (Get-Content C:\hunt\hosts.txt) -ScriptBlock {
    Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue |
        Select-Object @{N='ComputerName'; E={ $env:COMPUTERNAME }}, Name, LastWriteTime
}
```

## Profile Directory Structure

| Path | Role |
|---|---|
| `%AppData%\Mozilla\Firefox\Profiles\<random>.<profile-name>\` | Roaming profile root — where `places.sqlite`, `cookies.sqlite`, `logins.json`, `formhistory.sqlite`, and most other durable artifacts in this note live |
| `%LocalAppData%\Mozilla\Firefox\Profiles\<random>.<profile-name>\` | Local (non-roaming) profile path — historically used for cache-only data (`cache2\`, see Cache below). I'm not fully confident of the exact current Roaming/Local split for every data type across recent Firefox versions — Mozilla has adjusted what lives where more than once, so confirm against the specific build in front of you rather than assuming the split below is exhaustive |
| `%AppData%\Mozilla\Firefox\profiles.ini` | **Master index** — the file that maps profile names to their actual folder paths |

🔴 **Read `profiles.ini` first, before enumerating anything else.** This is a genuine first-step difference from Chromium. Chrome/Edge profiles use predictable, simple names (`Default`, `Profile 1`, `Profile 2`) that you can enumerate just by listing the `User Data\` folder. Firefox profile folders use a **randomized prefix** (`xxxxxxxx.default-release`, `xxxxxxxx.default`, `xxxxxxxx.dev-edition-default`, or an arbitrary custom name if the user created one manually) — the random 8-character prefix is unique per install and not guessable or predictable from the folder listing alone. `profiles.ini` is the authoritative index: it lists every profile Firefox knows about, whether each is the default, and its relative or absolute path. An analyst who skips `profiles.ini` and just globs `Profiles\*` will usually still find the folders (the random-prefix naming doesn't hide them), but `profiles.ini` is still the fast, authoritative way to confirm profile names, which one is default, and whether any profile path has been relocated outside the standard directory — don't skip it as a first step.

| File/folder (profile root) | Role |
|---|---|
| `profiles.ini` (one level up, in `%AppData%\Mozilla\Firefox\`, not per-profile) | Master profile index — profile names, default flag, relative/absolute path to each profile folder |
| `prefs.js` | Per-profile preferences (JSON-like `pref()` call format, not strict JSON) — browser settings, some extension state |
| `extensions.json` | Installed extensions/add-ons list — see Extensions/Add-ons below |

Unlike Chromium's near-total Chrome/Edge parity table, there's no second "flavor" of Firefox to cross-reference here — this note covers desktop Firefox (Windows) as a single artifact model.

### PowerShell

read `profiles.ini` directly (it's plain INI text, not JSON or SQLite) and list `prefs.js`/`extensions.json` per resolved profile:

```powershell
Get-Content "$env:APPDATA\Mozilla\Firefox\profiles.ini"

Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory | ForEach-Object {
    Get-ChildItem $_.FullName -Filter 'prefs.js' -ErrorAction SilentlyContinue
}
```

## The Places Database — History, Visits & Bookmarks

`places.sqlite` is Firefox's core artifact and the direct analog to Chromium's `History` file — but architecturally broader. Where Chromium keeps bookmarks in a completely separate JSON file (`Bookmarks`), **Firefox stores browsing history and bookmarks in the same database.** This is a genuine structural difference worth internalizing before you start querying: a `moz_bookmarks` row and a `moz_places` row for the same URL live side by side in one file, not two.

| Table | Key columns | What it holds |
|---|---|---|
| `moz_places` | `url`, `title`, `visit_count`, `last_visit_date` | One row per distinct URL — analogous to Chromium's `urls` table |
| `moz_historyvisits` | `place_id` (FK to `moz_places`), `visit_date`, `visit_type`, `from_visit` | One row **per visit event**, analogous to Chromium's `visits` table. `visit_type` is Firefox's equivalent of Chromium's string-based `transition` column, but encoded as a **numeric** value (see table below) rather than a named constant |
| `moz_bookmarks` | `fk` (FK to `moz_places.id`), `title`, `dateAdded`, `lastModified`, `parent` | Bookmarks — **stored in the same database as history**, unlike Chromium's separate `Bookmarks` JSON file. `parent` chains into Firefox's bookmark-folder hierarchy |
| `moz_keywords` | keyword text, associated `place_id` | Keyword shortcuts for bookmarked URLs (e.g. typing a short keyword in the address bar to jump to a saved bookmark) — I'm reasonably but not fully confident of the exact current column set, confirm against the schema in front of you |
| `moz_annos` | annotation `content`, `type`, tied to a `place_id` | A generic key-value annotation mechanism Firefox has historically used to attach extra metadata to places entries — see Downloads below for its most forensically relevant historical use |

🔴 **Timestamp format: `moz_places.last_visit_date` and `moz_historyvisits.visit_date` use PRTime — microseconds since the Unix epoch (1970-01-01 00:00:00 UTC).** This is a **different convention from Chromium's WebKit/Chrome epoch** (microseconds since 1601-01-01, covered in the Chromium note) — same unit (microseconds), different epoch year. This is exactly the kind of pitfall that bites cross-browser timeline work: pull a Firefox `visit_date` and a Chrome `visit_time` into the same spreadsheet and apply one conversion formula to both, and one of the two will be silently wrong by the ~11,644,473,600-second gap between 1601 and 1970 — with no error thrown, just a timestamp that's off by decades. When building a super-timeline spanning both browser families on one host, verify each source's epoch explicitly before merging; don't assume a "microseconds" timestamp column means the same thing browser to browser.

| `moz_historyvisits.visit_type` value | Meaning |
|---|---|
| 1 | Link — followed a hyperlink |
| 2 | Typed — user typed the URL directly (Firefox's `TYPED`-equivalent strong-intent signal) |
| 3 | Bookmark — navigated via a bookmark |
| 4 | Embed — embedded content load, not a direct user navigation |
| 5 | Redirect (permanent) |
| 6 | Redirect (temporary) |
| 7 | Download |
| 8 | Framed link — link followed within a frame/iframe |

I'm not fully confident every one of the eight numeric mappings above is exactly correct for every Firefox version — the concept (a numeric `visit_type` column functioning as Firefox's analog to Chromium's named transition types, with `2 = typed` as the highest-value forensic signal) is the reliable takeaway; verify the exact table against the schema/version in front of you before treating any single value as certain in a report. The interpretive logic from the Chromium note's Transition Types section — `typed` navigation to a bad domain is meaningfully stronger evidence than a `link`/redirect chain arriving at the same URL — carries over unchanged.

🔴 **`places.sqlite` is locked while Firefox is running** — the same file-lock caveat as Chromium's `History` file. Work from a byte-level copy, or use a tool built to handle a locked SQLite file, rather than assuming a failed open means no history exists.

### PowerShell

locate and stage `places.sqlite`; PowerShell has no native SQLite query cmdlet, so this gets you the file itself, not the rows inside it (see Tooling below for the query step):

```powershell
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Filter 'places.sqlite' -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime
```

convert a raw PRTime value (microseconds since 1970-01-01) pulled from `moz_places.last_visit_date` or `moz_historyvisits.visit_date` via SQLite tooling into a readable UTC timestamp — the conversion the Timestamp format callout above is warning you to get right:

```powershell
$prtime = 1700000000000000  # example raw value from moz_historyvisits.visit_date
[DateTimeOffset]::FromUnixTimeMilliseconds([math]::Floor($prtime / 1000)).UtcDateTime
```

## Downloads

Older Firefox versions stored download metadata as **annotations in the `moz_annos` table**, tied back to the download's URL entry in `moz_places` — conceptually, the download record lived as extra metadata bolted onto a places row rather than in its own dedicated downloads table. More recent Firefox versions have moved away from this in favor of a different internal mechanism for tracking downloads (I don't have high confidence in the exact current table/mechanism across the most recent Firefox releases — this has changed across versions and is worth confirming against the specific build under examination rather than assuming the `moz_annos` model still applies).

**Live-response tell, parallel to Chromium's `.crdownload`:** an in-progress Firefox download leaves a `.part` temp-file extension on disk. A `.part` file present at time of collection indicates an actively-in-progress or interrupted download, same evidentiary use as Chromium's `.crdownload`.

## Cookies

`cookies.sqlite` — a dedicated, separate SQLite database (Firefox keeps cookies in their own file, same conceptual separation as Chromium's dedicated `Cookies` file). The `moz_cookies` table holds `host`, `name`, `value`, and `expiry`.

🔴 **Firefox has historically stored cookie values in plaintext in `moz_cookies.value`**, without applying the DPAPI-style OS-level encryption Chromium applies to its `encrypted_value` column by default on Windows. This is a meaningful forensic-ease difference: pulling readable session-cookie values off a Firefox profile has historically been more straightforward than the Chromium equivalent, which usually requires the DPAPI-unwrap step covered in the Chromium note's Cookies/Passwords sections. I'm not fully confident this remains true for every current Firefox release — Mozilla could have changed this — so confirm plaintext-vs-encrypted against the actual `value` column contents on the version you're examining rather than assuming it's guaranteed, but treat plaintext storage as the historical default worth checking for first.

## Cache

Firefox's disk cache lives under `%LocalAppData%\Mozilla\Firefox\Profiles\<profile>\cache2\`, using **Firefox's own cache format** — an index file plus per-entry cache files, conceptually similar in spirit to Chromium's Simple Cache (not a SQLite database, not casually human-readable) but a **completely different on-disk format**, not interchangeable with either Chromium's Simple Cache or any of Firefox's own SQLite artifacts.

Honest gap: unlike Chromium, where Hindsight has become the broadly dominant single tool for pulling cache metadata into the same pass as history/cookies/LevelDB artifacts, I'm not aware of an equally dominant, equally broadly-adopted single tool that does the same breadth for Firefox. NirSoft's MozillaCacheView (see Tooling) handles cache2 specifically, but there isn't a Firefox-equivalent to Hindsight's full-suite correlation — treat Firefox cache and full-artifact-suite parsing as more fragmented across several narrower tools rather than one unified pipeline.

### PowerShell

enumerate `cache2` entry files and their timestamps; the format isn't human-readable without MozillaCacheView, but presence/volume/recency is visible natively:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles" -Recurse -Filter 'cache2' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    Get-ChildItem $_.FullName -Recurse -File | Measure-Object -Property Length -Sum |
        Select-Object @{N='Profile'; E={ $_.Directory }}, Count, Sum
}
```

## HTML5 Storage

Modern Firefox stores Local Storage under `storage/default/<origin>/` within the profile, using **SQLite-based `.sqlite` files** per origin. This is a genuine architectural contrast with Chromium: Chromium's Local Storage is **LevelDB**-based (see the Chromium note's HTML5 Storage section), while Firefox moved to a **SQLite-backed** implementation for Local Storage in modern versions — meaning Firefox's Local Storage is actually easier to inspect directly (DB Browser for SQLite opens it natively) than Chromium's, which requires LevelDB-aware tooling. I'm not fully confident of the exact schema or the precise Firefox version boundary where this SQLite-backed model was introduced/finalized — confirm against the build in front of you if the exact `storage/default/<origin>/` layout or schema matters to your findings, but treat "SQLite, not LevelDB" as the reliable high-level contrast point against Chromium.

### PowerShell

list the origins that have Local Storage on disk; the `storage/default/<origin>` folder names are themselves forensically useful (which sites a user actually has persistent client-side state for), independent of opening the per-origin SQLite files:

```powershell
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Recurse -Directory -Filter 'default' -ErrorAction SilentlyContinue |
    Where-Object { $_.Parent.Name -eq 'storage' } |
    Get-ChildItem -Directory | Select-Object Name, LastWriteTime
```

## Autocomplete & Form History

`formhistory.sqlite` — a **separate, dedicated database**, unlike Chromium's `Web Data`, which combines autofill, saved payment info, and search keywords into one file. The `moz_formhistory` table holds `fieldname`, `value`, `timesUsed`, `firstUsed`, and `lastUsed` — form field values the user has typed across sites, the same broad-reach caveat from the Chromium note's Autocomplete section applies: this reaches well beyond a dedicated password manager and can surface typed usernames, search terms, and other free-text entries for sites the user never explicitly saved credentials for.

## Passwords & NSS

Firefox's password storage is architecturally the most consequential difference in this note. Saved credentials live in `logins.json` in modern Firefox (older versions used a `signons.sqlite` database instead — if you're working an older profile or an artifact recovered from an older install, check for `signons.sqlite` rather than assuming `logins.json` is present). Either way, the stored username/password pairs are **encrypted**, not plaintext.

Encryption is handled by Firefox's own **NSS (Network Security Services)** crypto library, using a per-profile master key stored in `key4.db` (or the legacy `key3.db` format in older profiles). This is a fundamentally different trust model from Chromium's DPAPI-bound passwords:

🔴 **Firefox password decryption does not require the original Windows user's account context.** Chromium's `password_value` is DPAPI-encrypted and tied to the specific Windows account (and that account's master key material) that created it — decrypting it generally requires operating in that account's security context (see the Chromium note's Passwords & DPAPI section). Firefox's `key4.db` is different: **if the user has not set a Firefox Master Password (now called a Primary Password in current Firefox terminology)**, the key material in `key4.db` is sufficient on its own to decrypt `logins.json` — on *any* system, not just the original host, and without needing the original Windows user's credentials or account context at all. Copy `logins.json` and `key4.db` off the profile together, and they can be decrypted anywhere. This is a materially easier extraction path than Chromium's DPAPI model and a real difference worth flagging plainly in any comparison between the two browsers' credential exposure risk.

If the user **has** set a Primary Password, that password itself becomes a real barrier — it's required to unlock the NSS key material, and without it (or a successful crack/recovery of it), `logins.json` doesn't decrypt even with `key4.db` in hand. Always check whether a Primary Password is configured (visible in Firefox's own settings, and inferable from whether NSS decryption attempts fail without a passphrase) before assuming trivial extraction.

### PowerShell

`logins.json` is plain JSON, not SQLite, so PowerShell reads it natively; the `hostname` field is stored in the clear even though `encryptedUsername`/`encryptedPassword` are not — enough to scope which sites had saved credentials without decrypting anything:

```powershell
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Filter 'logins.json' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    (Get-Content $_.FullName -Raw | ConvertFrom-Json).logins | Select-Object hostname, timeCreated, timeLastUsed
}
```

evidence-first: hash and export both `logins.json` and `key4.db` together (they decrypt as a pair) before any credential-exposure containment step, such as forcing a password reset on the affected accounts:

```powershell
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Recurse -Include 'logins.json','key4.db' -ErrorAction SilentlyContinue |
    ForEach-Object { Get-FileHash $_.FullName -Algorithm SHA256 } |
    Export-Csv C:\hunt\firefox_credential_evidence.csv -NoTypeInformation
```

## Sync

Firefox Sync uses a **Mozilla Account** (not a Google or Microsoft/Entra ID account) as the anchor identity — the signed-in account is recoverable from local profile state, giving direct account attribution similar to the Chromium note's Sync section.

The same off-host-activity pitfall from the Chromium note applies here without modification: synced history/bookmark entries can reflect activity that happened on a **different device entirely**, pulled down to this host purely because the same Mozilla Account was signed in here. Don't assert local browsing occurred from a `moz_places`/`moz_historyvisits` row on a synced profile without independent, locally-generated corroboration (Cache content, a downloaded-file's Prefetch/filesystem trail, etc.) — see the Chromium note's Sync section for the full reasoning, which carries over unchanged.

## Extensions/Add-ons

`extensions.json` (profile root) lists installed extensions/add-ons; the `extensions/` folder under the profile holds the extension packages themselves. The same persistence/exfiltration-vector framing from the Chromium note's Extensions section applies here without modification — a malicious or over-permissioned Firefox extension is a browser-native persistence mechanism that survives restarts and can carry broad DOM/network visibility, conceptually outside the OS-level Persistence Mechanisms family (note 10) but worth cross-referencing there the same way the Chromium note does.

### PowerShell

sweep an estate for outlier extension IDs (present on only a handful of hosts), the same baseline-diff logic used for services and scheduled tasks elsewhere in this repo:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
$results = Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Filter 'extensions.json' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        (Get-Content $_.FullName -Raw | ConvertFrom-Json).addons |
            Select-Object @{N='ComputerName'; E={ $env:COMPUTERNAME }}, id, version
    }
}
$results | Group-Object id | Where-Object Count -lt ($computers.Count * 0.5) | Select-Object Name, Count
```

## Tooling

| Tool | Use |
|---|---|
| **DB Browser for SQLite** | Works directly against most Firefox SQLite artifacts — `places.sqlite`, `cookies.sqlite`, `formhistory.sqlite`, and the SQLite-based Local Storage files — with no DPAPI-style barrier for any of these except the master-password-protected password case. This is a meaningfully lower-friction starting point than Chromium's equivalent workflow for most artifact categories in this note |
| **NirSoft PasswordFox** | Long-standing NirSoft tool purpose-built for recovering saved Firefox passwords — operates within the NSS/`key4.db` constraints described above (works freely absent a Primary Password, needs the passphrase otherwise) |
| **NirSoft MozillaCacheView** | Purpose-built parser for Firefox's `cache2` format — the closest tool to a dedicated Firefox cache viewer, though narrower in scope than Hindsight's all-in-one Chromium correlation |
| **NirSoft MozillaHistoryView** | Lightweight GUI viewer for `places.sqlite` history — fast triage tool, Firefox's rough parallel to ChromeHistoryView |
| **KAPE** | Has Firefox collection targets — confirm the exact target name against your current KAPE target list, but it's built to collect the profile paths in this note (via `profiles.ini` resolution) as a triage-time first step |
| **Eric Zimmerman's tools** | Same honest gap as the Chromium note: EZ's suite is registry/EVTX/filesystem-focused, with no tool dedicated to Firefox's SQLite artifacts specifically |
| **Generic SQLite CLI** (`sqlite3`) | Fallback for any of the SQLite-format databases above — remember to work from a copy given the file-lock caveat, and to apply PRTime (not WebKit epoch) when converting timestamps by hand |

Honest overall gap, worth stating plainly: there isn't a single dominant Firefox-equivalent to Hindsight's breadth. Firefox artifact parsing is more fragmented across several narrower, artifact-specific tools (PasswordFox for passwords, MozillaCacheView for cache, MozillaHistoryView for history) rather than one unified correlation pipeline — plan a Firefox examination as several targeted tool passes rather than expecting a single "run this one tool" workflow.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Cross-browser timeline mixing Firefox `visit_date` (PRTime, epoch 1970) with Chromium `visit_time` (WebKit epoch, 1601) under one conversion formula | Silently produces a decades-wrong timestamp for one of the two browsers with no error thrown — verify each source's epoch explicitly before merging into a super-timeline |
| `key4.db` + `logins.json` recovered together from a profile with **no Primary Password set** | Trivially decryptable on any system, no original-Windows-account context required — a materially easier credential-exposure path than Chromium's DPAPI model, worth flagging distinctly when scoping credential compromise |
| `moz_historyvisits.visit_type` = 2 (typed) navigation to a known-bad or newly-registered domain | Strong evidence of deliberate, user-initiated navigation — same weight as Chromium's `TYPED` transition, same phishing/social-engineering narrative implications |
| History/bookmark entries on a Sync-enabled profile with no corroborating locally-generated artifact | Firefox Sync can pull in activity from a different device entirely tied to the same Mozilla Account — don't assert local browsing without independent local corroboration |
| Unrecognized or newly-permissioned entries in `extensions.json` | Malicious/compromised extension acting as a browser-native persistence and data-exfiltration mechanism |

## Correlate With

| To go deeper on… | Open |
|---|---|
| The PRTime vs WebKit-epoch timestamp contrast in full, including Chromium's side of the conversion pitfall | Chromium (Chrome & Edge).md (this subfolder) — Timestamp format pitfall callout |
| The DPAPI-bound vs NSS/`key4.db` password-encryption architectural contrast in full, including Chromium's account-binding mechanics | Chromium (Chrome & Edge).md (this subfolder) — Passwords & DPAPI section |
| Pre-Chromium (EdgeHTML) Edge and classic Internet Explorer's completely different artifact set | Internet Explorer & Legacy Edge.md (this subfolder, not yet written) |
| Recovering Firefox artifacts from memory, unallocated space, or a Private Browsing session | Private Browsing & Anti-Forensic Recovery.md (this subfolder, not yet written) |
| Chromium-embedded desktop apps that aren't general-purpose browsers but share an underlying engine | Electron Apps (Teams, Discord, WebView2).md (this subfolder, not yet written) |
| Malicious extensions as a persistence mechanism, conceptually alongside OS-level persistence techniques | Persistence Mechanisms family (note 10) |
| Webmail activity reached through a browser, once that note exists | Email Forensics (note 15, forward reference — not yet written) |

## Resources

- NirSoft PasswordFox — https://www.nirsoft.net/utils/passwordfox.html
- NirSoft MozillaCacheView — https://www.nirsoft.net/utils/mozilla_cache_viewer.html
- NirSoft MozillaHistoryView — https://www.nirsoft.net/utils/mozilla_history_view.html
- NirSoft utilities index — https://www.nirsoft.net/
- SANS FOR500 poster, browser-artifacts panel — coverage checklist for path/table facts, rewritten in this note's own words; Firefox is noticeably thinner in the poster/index than Chrome, so several facts in this note (visit_type numeric mapping, current downloads mechanism, exact storage/default schema) are flagged with explicit confidence hedges above rather than asserted from that source
- `SANS FOR500 Index _final.xlsx` — coverage checklist, same caveat as above
- MITRE ATT&CK T1539 (Steal Web Session Cookie) — https://attack.mitre.org/techniques/T1539/
- MITRE ATT&CK T1176 (Browser Extensions) — https://attack.mitre.org/techniques/T1176/
