# Timeline Analysis

No single artifact in this module tells the whole story on its own. A Prefetch entry proves an executable ran from a specific path; an EVTX record proves a logon or a service install happened; a registry LastWrite time proves *something* under that key changed. Each is a fragment — and, per the "presence ≠ execution" caveat that runs through the Evidence of Program Execution notes, some fragments actively mislead if read in isolation (ShimCache proves existence, not execution; Amcache is an inventory snapshot, not a run log). A **super-timeline** is what turns dozens of these fragments — NTFS MACE timestamps, registry LastWrite times, EVTX event timestamps, Prefetch run times, browser visit times, and more — into one sorted, cross-source chronology. The value isn't any single row; it's what emerges when independent sources land within seconds of each other and corroborate one coherent story, or when one source's timestamp doesn't fit where it lands relative to everyone else's.

This note is a **synthesis note**: it does not re-derive how any individual artifact's timestamp works — that depth already lives in the NTFS/ folder (00-07), Event Log Analysis (11), each Evidence of Program Execution note (06), each Persistence Mechanisms note (10), and the Chromium/Firefox browser notes (14). What this note owns is the **methodology of building, normalizing, filtering, and reading a merged timeline** across all of them.

> 🔴 The hardest part of a Windows super-timeline is rarely finding the data — it's **normalizing wildly different timestamp encodings and timezones into one common frame before merging**. Get that step wrong and the resulting timeline doesn't just have gaps, it actively lies: an effect can appear to precede its cause, purely from an unconverted epoch or an unlabeled local-time value.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Why Build a Super-Timeline](#why-build-a-super-timeline)
- [The Timestamp-Format Tower of Babel](#the-timestamp-format-tower-of-babel)
- [Timezone Normalization](#timezone-normalization)
- [Building the Super-Timeline](#building-the-super-timeline)
  - [Plaso / log2timeline](#plaso--log2timeline)
  - [Timesketch](#timesketch)
  - [The "Poor Man's Super-Timeline" — Merged EZ-Tool CSVs](#the-poor-mans-super-timeline--merged-ez-tool-csvs)
- [Filtering and Reducing Noise](#filtering-and-reducing-noise)
- [Interpreting a Super-Timeline](#interpreting-a-super-timeline)
  - [Corroboration Patterns](#corroboration-patterns)
  - [Inconsistency as Evidence of Tampering](#inconsistency-as-evidence-of-tampering)
- [Red Flags](#red-flags)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native PowerShell can build a lightweight, single-host timestamp timeline for fast triage or a spot-check — it reads filesystem MACE properties and EVTX records natively via `Get-ChildItem`/`Get-WinEvent`, but it merges nowhere near as many sources as a real super-timeline tool (Plaso/log2timeline, see Tooling). Treat the below as pre-Plaso triage or a quick sanity check on a narrow window, not a replacement for the real pipeline.

```powershell
# Filesystem MACE timeline for one tree, newest LastWriteTime first - the native equivalent of a single-source super-timeline slice
Get-ChildItem -Path 'C:\Users' -Recurse -File -ErrorAction SilentlyContinue |
    Select-Object FullName, CreationTime, LastWriteTime, LastAccessTime |
    Sort-Object LastWriteTime -Descending

# Bound that same tree to a suspected incident window - the first filtering pass every timeline workflow starts with
$start = Get-Date '2026-07-18 00:00:00'; $end = Get-Date '2026-07-19 00:00:00'
Get-ChildItem -Path 'C:\Users' -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -ge $start -and $_.LastWriteTime -le $end } |
    Select-Object FullName, CreationTime, LastWriteTime, LastAccessTime

# EVTX entries for the exact same window, System + Security in one pull - the second source to eyeball alongside the filesystem slice above
Get-WinEvent -FilterHashtable @{LogName='System','Security'; StartTime=$start; EndTime=$end} -ErrorAction SilentlyContinue |
    Sort-Object TimeCreated | Select-Object TimeCreated, Id, LogName, Message

# Files whose CreationTime lands after LastWriteTime - a cheap, native heuristic (not the $SI/$FN comparison in NTFS/02, which needs MFT parsing)
Get-ChildItem -Path 'C:\Windows\System32' -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.CreationTime -gt $_.LastWriteTime } |
    Select-Object FullName, CreationTime, LastWriteTime

# Confirm the host's configured timezone before merging any local-time-displayed value into a UTC timeline
Get-TimeZone

# Manual FILETIME (100ns since 1601 UTC) -> DateTime conversion for a raw registry/EVTX integer pulled by hand
[DateTime]::FromFileTimeUtc(133678900000000000)

# Export a directory's MACE timestamps to CSV in a shape ready to merge alongside EZ-tool exports into a poor-man's super-timeline
Get-ChildItem -Path 'C:\Users\victim\Downloads' -Recurse -File -ErrorAction SilentlyContinue |
    Select-Object FullName, CreationTime, LastWriteTime, LastAccessTime |
    Export-Csv C:\hunt\fs_timeline_slice.csv -NoTypeInformation
```

## Why Build a Super-Timeline

An investigation built one artifact at a time answers "what does this artifact show" — an investigation built on a super-timeline answers "what actually happened, in what order." The distinction matters because single-source conclusions are exactly where Windows forensics has the most traps:

- ShimCache shows a file *existed*, not that it ran (Evidence of Program Execution: ShimCache).
- A 4688 process-creation event with command-line auditing disabled shows *that* something ran, not what it was told to do (Event Log Analysis).
- A registry key's LastWrite time reflects the *most recent* write to that key — it can't tell you a value was added yesterday if the key was touched again today (Registry Forensics Fundamentals).
- A Prefetch file's own filesystem timestamps can be timestomped independently of the embedded run-time array inside the `.pf` payload (Evidence of Program Execution: Prefetch).

None of these caveats disappear inside a super-timeline — but **corroboration across independent sources is powerful evidence in a way no single source can be**. When a suspicious binary's Prefetch creation time, an EVTX 4688 process-creation event, a new Run-key registry LastWrite, and a fresh MFT $STANDARD_INFORMATION creation timestamp all cluster within the same few seconds, that convergence is far stronger than any one of those four facts standing alone — each source has different blind spots and different ways of being fooled, and it's very hard for an attacker (or an innocent explanation) to fake convergence across all of them simultaneously. Building the super-timeline is the mechanism for making that convergence visible in the first place.

## The Timestamp-Format Tower of Babel

This is the note's most important cross-cutting technical content. Before any two sources can be merged into one sorted timeline, every timestamp has to be converted to a single common encoding (almost always a normal UTC datetime). The Windows ecosystem alone uses at least five genuinely different timestamp conventions, and several of them look deceptively similar to each other.

| Format | Epoch | Unit | Typical source artifacts | Conversion gotcha |
|---|---|---|---|---|
| **Windows FILETIME** | 1601-01-01 00:00:00 UTC | 100-nanosecond intervals | NTFS $SI/$FN MACE timestamps (03), most registry key LastWrite times (04), EVTX record timestamps (11), Prefetch embedded run-time array (06) | The dominant format across this module — most native Windows structures use it directly |
| **WebKit / Chrome epoch** | **1601-01-01 00:00:00 UTC** (same epoch year as FILETIME) | Microseconds | Chromium `History.urls.last_visit_time`/`visits.visit_time`, `Cookies.expires_utc` (14 — Chromium) | 🔴 Shares FILETIME's epoch but uses a **different unit** (microseconds vs 100ns intervals) — treating a WebKit timestamp as FILETIME, or vice versa, silently produces a wrong-by-orders-of-magnitude result with no error thrown. This is the single easiest Windows-timestamp conversion mistake to make precisely *because* the epoch matches |
| **PRTime** | **1970-01-01 00:00:00 UTC** (Unix epoch) | Microseconds | Firefox `places.sqlite` — `moz_places.last_visit_date`, `moz_historyvisits.visit_date` (14 — Firefox) | Same unit as WebKit epoch (microseconds) but a **completely different epoch** — the ~11,644,473,600-second gap between 1601 and 1970 means applying one conversion formula to both a Chrome and a Firefox timestamp produces a value that's off by decades for one of them, with no error thrown |
| **Unix epoch / POSIX time** | 1970-01-01 00:00:00 UTC | Seconds | Various Unix-derived tool output, some log formats, some third-party/cross-platform application logs found on a Windows host (e.g. a Linux-origin agent's local log) | Easy to confuse with PRTime at a glance since both start from 1970 — check the unit (seconds vs microseconds) before converting, not just the epoch |
| **DOS/FAT timestamp** | Local time, no fixed absolute epoch (packed date/time fields) | 2-second granularity | Legacy — exFAT/FAT32 volumes, some older interpreted metadata fields an analyst may still encounter on removable media or older images | Historical gotcha, hedge on current relevance: this format is **local-time-based rather than UTC-based**, and its 2-second granularity means it can never resolve sub-2-second ordering the way FILETIME can — worth naming because it still turns up on older USB media/legacy filesystems even on an otherwise modern case |

The practical rule this table exists to support: **never trust a raw integer timestamp column without confirming both its epoch and its unit.** "Microseconds since an epoch" is not a self-describing format — Chrome and Firefox both use microseconds, and get it catastrophically wrong from opposite epochs. Every reputable parsing tool named in this note (Plaso, Hindsight, EvtxECmd, MFTECmd, PECmd, RECmd) handles these conversions automatically and correctly — the danger zone is specifically manual/spreadsheet-based conversion of a raw SQLite or registry value, which is exactly the scenario the Chromium and Firefox notes both flag independently.

### PowerShell

manual conversion formulas for each format in the table above, for the rare case a raw value has to be checked by hand rather than trusted to a parser (which is still the safer default per the caution above):

```powershell
# FILETIME (100ns intervals since 1601-01-01 UTC) -> UTC DateTime
[DateTime]::FromFileTimeUtc(132980000000000000)

# WebKit/Chrome epoch (microseconds since 1601-01-01 UTC) -> UTC DateTime - same epoch as FILETIME, convert via the 100ns intermediate, not directly
$webkitMicroseconds = 13383014400000000
[DateTime]::FromFileTimeUtc($webkitMicroseconds * 10)

# PRTime / Firefox (microseconds since 1970-01-01 UTC) -> UTC DateTime - different epoch than WebKit despite the matching unit
$prtimeMicroseconds = 1700000000000000
[DateTimeOffset]::FromUnixTimeMilliseconds($prtimeMicroseconds / 1000).UtcDateTime

# Unix epoch seconds -> UTC DateTime
[DateTimeOffset]::FromUnixTimeSeconds(1700000000).UtcDateTime
```

## Timezone Normalization

A separate problem from format, and just as common a source of a broken timeline: **most low-level Windows timestamps (everything FILETIME-based) are stored internally in UTC**, but many GUI tools **display** them converted to the local system's configured timezone by default — Windows Explorer's Properties dialog and Event Viewer's default column view both do this silently. An analyst who copies a "created" or "time generated" value straight off a GUI screen without noting whether it was displayed in UTC or local time — and without recording which timezone/DST offset was in effect at the time of capture — has captured an ambiguous value that cannot be safely merged with another source recorded in UTC.

**Workflow that avoids this**: fix one canonical timezone for the entire merged timeline — almost always **UTC** — and normalize every individual source into that canonical zone *before* merging, never after. Convert back to local time only at the very end, for a human-readable report or exhibit, and only with the specific timezone/DST context clearly labeled. Merging first and normalizing later is how a super-timeline silently misorders events; normalizing first and merging second is the workflow that keeps ordering trustworthy throughout.

The host's own configured timezone — itself sometimes forensically relevant (e.g. confirming what local time an attacker who changed it was trying to establish, or ruling out a timezone misconfiguration as the explanation for an apparent ordering anomaly) — is recoverable from `HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation`. Cross-reference Windows OS Fundamentals & Versions (01) if system configuration artifacts are covered there in more depth; this note only needs the key as the place to confirm which zone a given host's local-time-displayed timestamps were relative to.

### PowerShell

confirm the host's active timezone before normalizing any local-time-displayed value:

```powershell
Get-TimeZone

# Raw registry read of the same configuration, for the exact bias/DST values behind Get-TimeZone's summary
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation'
```

convert a local-time value to UTC before merging it against any FILETIME-based source:

```powershell
(Get-Date '2026-07-18 14:30:00').ToUniversalTime()
```

## Building the Super-Timeline

### Plaso / log2timeline

**Plaso** (`log2timeline`) is the dominant open-source super-timeline framework, and it works in two distinct stages:

1. **`log2timeline.py`** — the extraction stage. It runs dozens of format-specific **parsers** against a mounted image, a live collection, or a directory of gathered artifacts, and writes every event it finds into an intermediate storage file. Plaso has dedicated parsers for many of the exact artifact types already covered in depth elsewhere in this module: NTFS $MFT records, the registry (NTUSER.DAT/SAM/SYSTEM/SOFTWARE hives), EVTX, Prefetch, and browser history among others — meaning the extraction stage is where all of this module's individually-covered artifacts get pulled into one common event stream for the first time.
2. **`psort.py`** — the filter/sort/export stage. It reads the intermediate storage file, applies any time-window or field filters requested, sorts everything chronologically, and exports the result — typically to CSV (the classic "l2tcsv" format) or another structured output for downstream tooling.

This two-stage design is deliberate: extraction is the slow, exhaustive part (worth doing once, broadly), while filtering/sorting/exporting is cheap enough to re-run repeatedly against the same intermediate storage as the investigation's questions narrow.

### Timesketch

**Timesketch** is a web-based, collaborative timeline analysis and visualization platform, commonly paired directly with Plaso output. Once a Plaso storage file is imported into a Timesketch "sketch," a team can search, tag, star, and annotate individual events together rather than everyone working from their own private copy of a multi-million-row CSV. It's most valuable on larger or longer-duration investigations where more than one analyst needs to work the same merged timeline concurrently and build a shared narrative around specific confirmed-malicious events.

### The "Poor Man's Super-Timeline" — Merged EZ-Tool CSVs

Running the full Plaso pipeline isn't always necessary. Many of the individual Eric Zimmerman tools already covered throughout this module — **MFTECmd** ($MFT/$LogFile/$UsnJrnl), **EvtxECmd** (EVTX), **PECmd** (Prefetch), **RECmd** (registry) — can each independently output CSV in a format compatible with the broader Plaso-timeline ecosystem's conventions. That means an analyst can build a lighter-weight, semi-manual super-timeline by:

1. Running the relevant EZ tools against the collected artifacts individually (exactly as each tool's own note already describes).
2. Merging their CSV outputs into one combined file (a spreadsheet tool, a quick script, or a purpose-built merge utility).
3. Sorting the combined result chronologically, having already normalized each source's timestamps to one timezone per the section above.

**Eric Zimmerman's Timeline Explorer** is the GUI tool built for exactly this review step — it opens large CSV-based timelines (whether Plaso's own output or a manually merged set of EZ-tool CSVs) and supports fast filtering, column pivoting, and highlighting across millions of rows, making it genuinely usable as an interactive review layer for either workflow.

This EZ-tool-CSV-merge approach is a real, practical alternative to the full Plaso pipeline — faster to stand up when only a handful of artifact types matter to the current question, at the cost of losing Plaso's much broader out-of-the-box parser coverage (browser artifacts, many third-party log formats, and anything without a dedicated EZ tool). Treat it as the right choice for a narrowly-scoped question and Plaso as the right choice when the investigation needs the widest possible artifact coverage in one pass.

### PowerShell

merge already-exported CSVs and sort chronologically, the "quick script" step 2 above refers to. Each EZ tool uses its own timestamp column name (`RunTime`, `TimeCreated`, `LastWriteTimestamp`, etc.) — normalize to one common column name before merging, or the sort silently operates on the wrong field for some rows:

```powershell
Get-ChildItem 'C:\hunt\csv\*.csv' | ForEach-Object { Import-Csv $_.FullName } |
    Sort-Object { [DateTime]$_.Timestamp } |
    Export-Csv C:\hunt\merged_timeline.csv -NoTypeInformation
```

## Filtering and Reducing Noise

A full super-timeline across a modern, actively-used Windows system can easily reach **millions of events** — every file MACE change, every registry write, every EVTX record, all sorted into one file. Reading that file line by line is not a workflow; the goal is iterative reduction, not exhaustive reading:

| Technique | How it works | When to use it |
|---|---|---|
| **Time-window filtering** | Bound the timeline to the suspected incident window plus a reasonable buffer before and after (hours to days, depending on how confident the initial window estimate is) | Always the first cut — `psort.py`'s date filtering (or an equivalent filter on merged EZ CSVs) turns a million-row file into something actually reviewable |
| **Artifact-type filtering** | Temporarily exclude known-noisy sources — routine Windows Update file-timestamp churn, antivirus definition updates, and similar high-volume, low-signal background activity | Once the time window is set but the remaining volume is still dominated by background system noise unrelated to the investigative question |
| **Keyword/IOC filtering** | Search the merged timeline for specific filenames, IP addresses, hashes, or other indicators already identified as relevant from other analysis (a Prefetch hit, a suspicious EVTX event, a known-bad domain) | Once at least one concrete IOC exists — this is how a super-timeline earns its keep, letting the analyst pivot from "what happened around IOC X" straight to every other artifact that references it |

Frame this as **iterative**: start broad within a reasonable window, review what's there, and narrow further based on what that first pass surfaces — rather than attempting to read every event from the outset. Each round of filtering should be driven by something the previous round found, not by a fixed checklist applied blind.

### PowerShell

time-window filtering on an already-merged CSV, the same first cut `psort.py`'s date filtering performs:

```powershell
Import-Csv C:\hunt\merged_timeline.csv |
    Where-Object { [DateTime]$_.Timestamp -ge $start -and [DateTime]$_.Timestamp -le $end }
```

keyword/IOC filtering across every column, once at least one concrete indicator is in hand:

```powershell
Import-Csv C:\hunt\merged_timeline.csv | Where-Object { $_.PSObject.Properties.Value -match 'evil\.exe' }
```

## Interpreting a Super-Timeline

### Corroboration Patterns

The payoff of building a super-timeline is seeing what no single source shows alone. A representative example worth internalizing: a Prefetch entry showing a suspicious executable ran (Evidence of Program Execution, 06), corroborated within seconds by an EVTX 4688 process-creation event (Event Log Analysis, 11), a new or modified Run-key registry LastWrite time (Persistence Mechanisms → Autostart Keys, 10), and a newly-created file's MFT $STANDARD_INFORMATION creation timestamp (NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes) — all clustering within a tight time window. No single one of those four facts proves a coordinated malicious action on its own; a Prefetch hit alone could be an isolated legitimate run, a Run-key write alone could be routine software installing itself. **All four landing within the same narrow window is what elevates the finding from "notable" to "confirmed" for the purposes of a report** — this is the corroboration pattern a super-timeline is specifically built to surface, and it's worth actively looking for it around every significant event, not just noting it when it happens to appear.

### PowerShell

native spot-check for this exact corroboration pattern on a live host: pull Prefetch and 4688 activity for the same narrow window in one pass, without standing up Plaso:

```powershell
$center = Get-Date '2026-07-18 09:14:00'; $window = 5
Get-ChildItem 'C:\Windows\Prefetch\*.pf' |
    Where-Object { $_.LastWriteTime -ge $center.AddMinutes(-$window) -and $_.LastWriteTime -le $center.AddMinutes($window) } |
    Select-Object Name, LastWriteTime

Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$center.AddMinutes(-$window); EndTime=$center.AddMinutes($window)} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, @{N='NewProcessName'; E={$_.Properties[5].Value}}
```

### Inconsistency as Evidence of Tampering

The inverse pattern is just as valuable: a timestamp that doesn't fit where it lands relative to its neighbors in the merged timeline is itself evidence — of timestomping, log manipulation, or clock skew. NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes already covers the core detection technique in depth: comparing a file's $STANDARD_INFORMATION creation time (the value most common timestomping tools overwrite, since it's what Explorer and most GUI tools display) against its $FILE_NAME attribute timestamp (touched only on namespace events — creation, rename, move — and largely untouched by ordinary timestomping tools). A super-timeline is exactly where this $SI/$FN mismatch becomes visible in context: a file whose $SI creation time places it months before the incident, but whose $FN creation time (and its position among every other artifact clustered around the actual incident window) says otherwise, is a textbook timestomp catch. Full timestomping-detection depth — including $LogFile/$UsnJrnl corroboration and Volume Shadow Copy comparison — belongs to the forthcoming **Anti-Forensics and Evidence Destruction (19)** note; this note's job is flagging that a super-timeline is where that kind of inconsistency first becomes visible, not re-deriving the full detection methodology.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Prefetch + EVTX 4688 + registry LastWrite + MFT $SI creation all clustering within a tight window around the same executable | Strong corroborated evidence of a coordinated action — a **positive** finding pattern worth calling out explicitly, not just a caution |
| A single artifact's timestamp inconsistent with its neighbors in the merged timeline (e.g. a file's position in the incident cluster contradicted by its own $SI creation time) | Possible timestomping — cross-reference the $SI/$FN comparison technique (NTFS/02) and the forthcoming full detection depth in Anti-Forensics and Evidence Destruction (19) |
| An apparently-impossible sequence in the merged timeline — an effect appearing to precede its cause | Almost always a timezone- or epoch-conversion bug in the analyst's own timeline-building process (an unconverted WebKit/FILETIME mixup, an unlabeled local-time value merged against UTC) rather than a genuine anomaly — re-check normalization before concluding something more exotic happened |
| A raw "microseconds since epoch" column merged without confirming which epoch (1601 vs 1970) | Silently produces a decades-wrong timestamp for that source, with no error thrown — the exact WebKit-epoch-vs-PRTime trap both browser notes (14) flag independently |

## Tooling

| Tool | Role |
|---|---|
| **Plaso / log2timeline** | The dominant open-source super-timeline framework — `log2timeline.py` extracts via dozens of format-specific parsers into an intermediate storage file, `psort.py` filters/sorts/exports to CSV or another structured format |
| **Timesketch** | Web-based collaborative timeline analysis/visualization, typically paired with Plaso output — search/tag/annotate a shared timeline across a team |
| **Timeline Explorer** (Eric Zimmerman) | GUI viewer for large CSV-based timelines — filtering, column pivoting, and highlighting across millions of rows; works equally well against Plaso's own CSV export or a manually merged set of EZ-tool CSVs |
| **MFTECmd / EvtxECmd / PECmd / RECmd** (Eric Zimmerman) | Each independently outputs CSV in a Plaso-timeline-compatible format — the building blocks of the "poor man's super-timeline" merge workflow when the full Plaso pipeline isn't warranted |
| **Generic spreadsheet/CSV tools** | Sufficient for smaller-scale manual correlation once a timeline is already narrowed to a small event set — not a substitute for Plaso/Timeline Explorer at full merged-timeline scale |

## Correlate With

| To go deeper on… | Open |
|---|---|
| The filesystem-timestamp foundation (MACE/MACB rules, $SI vs $FN) this note builds on | NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes |
| $MFT/$LogFile/$UsnJrnl structural depth | NTFS/ folder (00, 05, 06) |
| EVTX timestamp mechanics, record structure, and log-clearing/time-change tampering detection | Event Log Analysis (11) |
| Individual execution-evidence artifacts as timeline sources (Prefetch, ShimCache, Amcache, BAM/DAM, UserAssist, Jump Lists, SRUM) and their precision/retention tradeoffs | Evidence of Program Execution (06) |
| Registry LastWrite times as timeline sources across each persistence mechanism | Persistence Mechanisms (10) — Autostart Keys, Services, Scheduled Tasks, WMI Event Consumers, DLL Hijacking |
| The WebKit-epoch vs PRTime timestamp-format contrast this note resolves at the multi-source level | Web Browser Forensics (14) — Chromium (Chrome & Edge).md, Firefox.md |
| Full timestomping-detection depth ($LogFile/$UsnJrnl recovery, Volume Shadow Copy comparison, clock-skew propagation) | Anti-Forensics and Evidence Destruction (19, forthcoming) |
| How a built super-timeline feeds into broader hunting and case-narrative construction | Threat Hunting Methodology and Intelligence (20, forthcoming) |

## Resources

- SANS FOR508 poster/index (Section 4: Timeline Analysis) — used as a coverage checklist only, per this repo's sourcing convention; no verbatim reproduction
- Plaso / log2timeline — https://plaso.readthedocs.io / https://github.com/log2timeline/plaso
- Timesketch — https://github.com/google/timesketch
- Eric Zimmerman's tools (MFTECmd, EvtxECmd, PECmd, RECmd, Timeline Explorer) — https://ericzimmerman.github.io/
- Hindsight (Chromium timeline parser, referenced in Web Browser Forensics 14 for its own epoch-handling) — cross-reference only, full tooling depth lives in that note
