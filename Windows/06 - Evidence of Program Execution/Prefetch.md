# Prefetch

Prefetch is the first stop in the "Evidence of Program Execution" family — eight artifacts, spread across the registry and filesystem, that each answer some version of "did this program run?" with a different (and sometimes contradictory) level of confidence. This note opens the family with a full side-by-side comparison of all eight, then goes deep on Prefetch itself: what it is, exactly where it lives, what's inside a `.pf` file field by field, and the pitfalls that trip up analysts who treat "a Prefetch file exists" as an unqualified fact of execution.

> 🔴 **No single artifact in this family is sufficient on its own.** Prefetch proves a specific path ran at least once but goes stale after ~128–1024 entries and can be disabled or wiped. ShimCache proves a file merely existed on disk, not that it ran. Amcache and BAM/DAM each add a different angle (hash/first-seen vs. per-user last-run). Real casework triangulates two or three of these against each other — that's the entire reason this note leads with the comparison table below rather than burying it at the end.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [The Evidence of Execution Family](#the-evidence-of-execution-family)
- [What Prefetch Is](#what-prefetch-is)
- [Where It Lives](#where-it-lives)
- [What's Inside a .pf File](#whats-inside-a-pf-file)
- [How to Interpret It](#how-to-interpret-it)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage against `C:\Windows\Prefetch\` before any parser (PECmd) comes out — no third-party modules required. PowerShell can only read the filesystem/registry side of Prefetch (names, hashes-in-filename, timestamps); the embedded 8-entry run-timestamp array and run counter live inside the binary `.pf` payload and require PECmd, covered in Tooling below.

```powershell
# How many .pf files exist, and where - a suspiciously low count for an aged host is itself a finding
Get-ChildItem C:\Windows\Prefetch\*.pf | Measure-Object | Select-Object -ExpandProperty Count

# Same exe name, multiple hashes = that binary ran from more than one path - classic masquerading lead
Get-ChildItem C:\Windows\Prefetch\*.pf |
    ForEach-Object { [PSCustomObject]@{ ExeName = ($_.BaseName -split '-')[0]; Hash = ($_.BaseName -split '-')[1] } } |
    Group-Object ExeName | Where-Object Count -gt 1 | Select-Object Name, Count

# Is Prefetch even enabled, and at what level - confirm before concluding "it never ran"
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name EnablePrefetcher

# Oldest and newest .pf on the host by last-run (file last-modified) - brackets the host's execution window
Get-ChildItem C:\Windows\Prefetch\*.pf | Sort-Object LastWriteTime | Select-Object -First 1 -Last 1 Name, CreationTime, LastWriteTime

# Every captured path-hash variant for one exe name of interest - swap in the binary you're chasing
Get-ChildItem C:\Windows\Prefetch\ -Filter 'RUNDLL32.EXE-*.pf' | Select-Object Name, CreationTime, LastWriteTime

# .pf whose file-system creation/last-modified pair is older than the Prefetch directory's own oldest
# entries would be impossible - flags a timestomped .pf worth cross-checking against $MFT
Get-ChildItem C:\Windows\Prefetch\*.pf | Where-Object { $_.CreationTime -gt $_.LastWriteTime }
```

## The Evidence of Execution Family

Eight artifacts, one question each: did this program run, and how sure can I be? This table is the anchor reference for the whole `06 - Evidence of Program Execution/` subfolder — every sibling note (ShimCache, Amcache, BAM/DAM, UserAssist, Jump Lists, SRUM, Task Bar Feature Usage) links back here in its own Correlate With section rather than re-deriving the comparison.

| Artifact | What it actually proves | Timestamp precision | Run-count / history data | Retention window | Presence = execution? |
|---|---|---|---|---|---|
| **Prefetch** | The named executable ran **from that specific path** at least once | Creation ≈ first run, last-modified ≈ last run, both ±~10 sec | Embedded array of the last 8 run timestamps (Win8+); only the single last-run time pre-Win8; total run counter | Rolling by file count, not age — 128 files max (XP/Win7), 1024 (Win8+); oldest evicted as new ones are created | **Yes** — one of the few artifacts in this family where presence is genuine execution evidence, but only for that exact path |
| **ShimCache (AppCompatCache)** | The file **existed on disk** (path, size, `$STANDARD_INFORMATION` last-modified time) as of the last time the cache was built | No execution timestamp at all — only the file's own last-modified time is carried | None — a single snapshot entry per path, no run count, no history | Entries only flush to the registry at shutdown/reboot; list is capped (~1024 typical) and rebuilt each boot, LRU-evicted | **No** — this is the textbook "presence ≠ execution" artifact; a Vista/Win7-era execution flag existed but is unreliable/removed on Win8+ |
| **Amcache.hve** | An executable **was inventoried** by the Application Compatibility subsystem — install/first-seen path, SHA-1, PE compile timestamp | Key last-write time ≈ first-seen/inventory time; PE compile timestamp is attacker-controllable | No run counter; some Windows 10 builds' `Program`/`InventoryApplicationFile` structure captures execution-adjacent detail, but this varies by build | Persists across reboots (unlike ShimCache) until the key is pruned or the hive is rebuilt | **Partial** — stronger than ShimCache (hash + compile time available) but still fundamentally an inventory, not a run log; version-dependent |
| **BAM / DAM** | The named executable **last ran at this specific time**, attributed to a specific user SID | Single last-run timestamp per path per SID, high precision (registry key value, not ±10 sec) | None — only ever the most recent run, no history array | Persists as long as the registry key/value exists, no fixed cap | **Yes** for that single most-recent execution, but tells you nothing about earlier runs |
| **UserAssist** | A **GUI-launched** program (double-clicked, Start-menu, taskbar) ran, with run count and last-run time | Last-run timestamp precise to the second; ROT13-encoded value names | Run count **and** last-execution time; Win7+ adds focus count/focus duration | Persists in `NTUSER.DAT` until the value is manually cleared or the profile is deleted | **Yes**, but scoped to shell-initiated GUI launches only — silently misses command-line, scheduled-task, and service-launched execution |
| **Jump Lists** | A specific **file was opened with** a specific application — execution is implied, not the primary claim | Creation ≈ first access, last-modified ≈ most recent access of that file | Per-entry access count/order embedded in the `.customDestinations-ms`/`.automaticDestinations-ms` structure | Persists per user until the app/file pair ages out of the list or the app is uninstalled | **Indirect** — this artifact is really "evidence of file opening," included here because it corroborates which app touched which file |
| **SRUM** | An application **consumed CPU/network resources** over a sampled interval, per user | Sampled roughly hourly — coarse compared to Prefetch/BAM, but survives long after those are gone | Cumulative bytes sent/received and foreground/background CPU time per app per interval, not a simple run counter | Rolling ~30–60 days in `SRUDB.dat`, independent of reboot | **Yes**, at hourly granularity — valuable specifically *because* its retention outlives Prefetch/ShimCache/UserAssist |
| **Task Bar Feature Usage / CapabilityAccessManager** | An app was **pinned/launched from the taskbar**, or accessed a sensitive capability (mic/camera/location) | Feature Usage has no timestamps at all (counters only); CapabilityAccessManager has `LastUsedTimeStart`/`LastUsedTimeStop` | Feature Usage: launch/pin/unpin counters only. CapabilityAccessManager: per-session start/stop times | Feature Usage persists in `NTUSER.DAT` indefinitely; CapabilityAccessManager keyed per app, persists until cleared | **Partial** — Feature Usage confirms a launch happened but not when; CapabilityAccessManager gives real timestamps but only for sensitive-capability access |

The pattern to internalize: **precision and history depth trade off against retention.** Prefetch and BAM/DAM give you tight timestamps but a shallow or capped history; SRUM gives you weeks of coverage at the cost of hourly-bucket precision. When one artifact has been cleared or disabled, reach for the next row down this table rather than concluding the program never ran.

## What Prefetch Is

Windows' Memory Manager watches which files and directories a process touches during its first ~10 seconds of launch (or, for the boot itself, the first ~30 seconds after login begins) and records that access pattern to disk. On the next launch of the same executable, Windows uses that recorded pattern to pre-load the relevant code and data pages into memory ahead of time, cutting perceived launch latency. That monitoring data — one file per traced executable/process — is what lands in `C:\Windows\Prefetch\` as a `.pf` file.

From a DFIR standpoint the caching mechanism itself is irrelevant; what matters is the byproduct: **a `.pf` file is durable evidence that a specific executable, at a specific path, launched at least once on this host.**

## Where It Lives

| Detail | Value |
|---|---|
| Directory | `C:\Windows\Prefetch\` |
| Naming format | `(EXENAME)-(HASH).pf` — e.g. `NOTEPAD.EXE-3524DBAF.pf` |
| The hash | A hash derived from the **full path** the executable was launched from (plus, on some builds, command-line arguments/working directory) — **not** just the filename |
| Governing registry value | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher` |

🔴 **Same exe name, different path, different hash — and that's a feature, not noise.** Because the hash is path-derived, `svchost.exe` launched from `C:\Windows\System32\` and a same-named binary launched from `C:\Users\Public\svchost.exe` produce **two separate `.pf` files** with two different hashes. Seeing multiple `.pf` files for one executable name is itself an investigative lead — it means that name was executed from more than one location, which is exactly the masquerading pattern covered in Windows OS Fundamentals & Versions (01).

**Version limits and the `EnablePrefetcher` value:**

| OS | Max `.pf` files | `EnablePrefetcher` default |
|---|---|---|
| Windows XP / Windows 7 | 128 | `3` (boot + application launch) |
| Windows 8 and later (client) | 1024 | `3` |
| Windows Server (most releases) | 1024 (where enabled) | Historically `0` (disabled by default) — Prefetch is oriented at desktop launch-latency, and Server SKUs traditionally didn't prioritize it |

`EnablePrefetcher` values:

| Value | Meaning |
|---|---|
| `0` | Prefetching disabled entirely — no new `.pf` files are created |
| `1` | Application-launch prefetching only |
| `2` | Boot prefetching only |
| `3` | Both application-launch and boot prefetching enabled (typical client default) |

🔴 **`EnablePrefetcher = 0` is not automatically suspicious — context decides.** On a Windows Server box, `0` (or the whole feature being off) is often just the platform's historical default and proves nothing. On a **client** workstation where you'd expect Prefetch data and instead find the value flipped to `0`, or a `Prefetch` directory that's suspiciously thin for the host's age, treat it as a possible anti-forensic move and say so explicitly rather than silently noting an absence.

### PowerShell

List the directory and pull the file-system dates every analyst starts with; `Get-ChildItem` never opens the binary payload, so this is metadata only:

```powershell
Get-ChildItem C:\Windows\Prefetch\*.pf | Select-Object Name, CreationTime, LastWriteTime, Length
```

Parse the `EXENAME-HASH.pf` naming convention into its two components so exe name and path-hash can be filtered/grouped independently:

```powershell
Get-ChildItem C:\Windows\Prefetch\*.pf | ForEach-Object {
    $exe, $hash = $_.BaseName -split '-'
    [PSCustomObject]@{ ExeName = $exe; Hash = $hash; FirstRun = $_.CreationTime; LastRun = $_.LastWriteTime }
}
```

## What's Inside a .pf File

Each `.pf` file is a structured binary record (parsed, not hand-read) containing:

| Field | Meaning | Interpretation notes |
|---|---|---|
| File creation date (of the `.pf` itself) | Approximates the **first** execution of that exe from that path | Accurate to roughly ±10 seconds |
| File last-modified date (of the `.pf` itself) | Approximates the **most recent** execution | Also ±10 seconds; this is the timestamp analysts lean on most |
| Embedded last-run timestamp array | The last **8** execution times, stored inside the `.pf` payload (Windows 8 and later) | Pre-Win8, only a single last-run timestamp is embedded — the file-system dates above are your only fallback for earlier runs on those OSes |
| Run count | A cumulative counter of how many times that exe/path pair has launched | Increments on every launch since the `.pf` was created — a large count with a recent last-run date on a binary the user swears they never touched is worth a second look |
| Referenced files/directories/volumes | A list of file and directory handles the process touched near launch — DLLs loaded, config files read, and (notably) any files pulled from removable media or network shares during that startup window | This is the field most useful for reconstructing *what else* an executable interacted with immediately after launch, including staging files an attacker dropped alongside the binary |

## How to Interpret It

- **Prefetch proves execution from a specific path, not universal execution.** A missing `.pf` for `evil.exe` run from `C:\Temp\` tells you nothing about whether the *same file* was also run from `C:\Users\bob\Downloads\` — each path gets its own entry.
- **It does not prove every launch.** The embedded timestamp array only holds 8 entries (or 1, pre-Win8) — a frequently-launched legitimate tool will show only its most recent handful of runs, not a complete history. For long-window "was this ever run" questions, use run count as corroboration, not the timestamp array alone.
- **It depends entirely on `EnablePrefetcher` being non-zero.** No Prefetch data exists at all on a host where the feature was disabled — confirm the registry value before concluding an executable never ran.
- 🔴 **Deleting the `.pf` file is a known, simple anti-forensic move.** Prefetch files are ordinary files in an ordinary directory — no special permissions or API needed to remove one. A conspicuously **missing** `.pf` file for an executable you'd otherwise expect evidence for — especially when ShimCache or Amcache elsewhere on the same host still shows that file existed — is a stronger red flag than the file simply never having existed in the first place.
- **File-system metadata on the `.pf` itself can also be manipulated.** Timestomping the `.pf` file's own creation/modified dates undermines the "approximate first/last run" logic above — cross-check against `$MFT` records and the embedded internal timestamp array, which is a separate, harder-to-reach data structure than the surrounding file-system metadata.

### PowerShell

Group by exe name to rank every masquerading candidate by how many distinct paths it ran from, then sort the full set by last-run recency:

```powershell
Get-ChildItem C:\Windows\Prefetch\*.pf |
    ForEach-Object { [PSCustomObject]@{ ExeName = ($_.BaseName -split '-')[0]; Hash = ($_.BaseName -split '-')[1]; LastRun = $_.LastWriteTime } } |
    Group-Object ExeName | Sort-Object Count -Descending |
    Select-Object Name, Count, @{N='Hashes'; E={ $_.Group.Hash -join ', ' }}
```

🔴 **This is filename/timestamp correlation only** — it tells you a name ran from multiple paths and roughly when, not the run count or full 8-entry history embedded in the `.pf` payload. Confirm with PECmd before drawing conclusions that depend on exact run counts.

To sweep an estate for a specific filename of interest (e.g. a tool named in a threat-intel report) and export for timeline pivoting:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-ChildItem C:\Windows\Prefetch\ -Filter 'PSEXEC.EXE-*.pf' -ErrorAction SilentlyContinue |
        Select-Object @{N='ComputerName'; E={ $env:COMPUTERNAME }}, Name, CreationTime, LastWriteTime
} | Export-Csv C:\hunt\prefetch_sweep.csv -NoTypeInformation
```

Deletion of a `.pf` is itself the anti-forensic move covered in Red Flags below, not a legitimate response action; there is nothing here to remediate on a real host. The only valid use of `Remove-Item` against this directory is generating known-clean test data in a lab:

```powershell
# Lab/testing only - do NOT run against a live evidence host; a missing .pf is itself evidence (see Red Flags)
Remove-Item 'C:\Windows\Prefetch\TESTBINARY.EXE-DEADBEEF.pf' -WhatIf
```

## Tooling

| Tool | Form | What it gives you |
|---|---|---|
| **PECmd** (Eric Zimmerman suite) | CLI | The primary Prefetch parser used throughout this repo's convention (matches RECmd/MFTECmd/JLECmd elsewhere) — parses one `.pf` or an entire `Prefetch\` directory, outputs run count, creation/last-run/all embedded run timestamps, and the full list of referenced files and volumes, in CSV or JSON for pivoting in a timeline tool |
| **KAPE** | Collection + parsing pipeline | Targets/modules exist to both collect `C:\Windows\Prefetch\*.pf` from a live or imaged host and run PECmd against the results automatically as part of a triage pass |
| **WinPrefetchView** (NirSoft) | GUI | Fast interactive alternative for eyeballing a handful of `.pf` files without scripting; less suited to bulk/automated processing than PECmd |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Multiple `.pf` files for the same executable name, different hashes | The binary ran from more than one path — check every referenced path, not just the expected one |
| `.pf` file missing for an executable that ShimCache/Amcache/Event Log shows existed and ran | Possible deliberate deletion of the `.pf` — a known, low-effort anti-forensic step |
| `EnablePrefetcher = 0` on a client workstation | Prefetching disabled — either intentional tampering or a system/GPO misconfiguration; investigate the "why," don't assume it's benign |
| Run count high but last-run timestamp very recent and inconsistent with user-reported usage | Possible automated/scripted repeated execution (e.g., a persistence mechanism re-launching a payload) |
| `.pf` file-system timestamps (creation/modified) inconsistent with the embedded internal run-timestamp array | Possible timestomping of the `.pf` file itself — trust the embedded array over surrounding file metadata when they disagree |
| Referenced-files list shows loads from removable media or a network share the host shouldn't be touching | Corroborates lateral movement or removable-device staging — cross-check against Removable Device (USB) Forensics (09) |

## Correlate With

- **ShimCache (AppCompatCache)** — corroborate path-specific Prefetch evidence against ShimCache's broader-but-weaker "file existed" signal; useful when Prefetch is missing or disabled.
- **Amcache** — cross-check SHA-1/compile-timestamp/install-path detail against Prefetch's path-and-run-count view of the same binary.
- **BAM/DAM** — confirm the single most-recent execution time and user attribution when Prefetch's embedded 8-entry history has already rolled past the run you care about.
- **UserAssist** — corroborate GUI-initiated launches specifically; useful for distinguishing a shell double-click from a script/service launch that Prefetch alone can't tell apart.
- **Jump Lists** — cross-reference which files a launched application actually opened around the same time window.
- **SRUM** — extend the investigation window well past Prefetch's rolling 128/1024-file cap, at the cost of hourly-bucket precision.
- **Task Bar Feature Usage** — corroborate whether a launch was taskbar-initiated, and whether it touched a sensitive capability (mic/camera/location) around the same time.
- **Persistence Mechanisms** — a `.pf` file with a surprisingly high run count and no matching user activity often points back to an autostart/scheduled-task/service entry keeping a binary alive.
- **Timeline Analysis** — Prefetch's creation/last-modified pair and embedded run-time array are prime super-timeline anchors; plot them against Event Log and file-system timestamps rather than reading them in isolation.

## Resources

- SANS FOR500 "Windows Artifact Analysis: Evidence of..." poster, "Application Execution" panel — `Windows/SANS_DFPS_FOR500_v4.18_09-24.pdf` (bundled in this repo)
- SANS FOR508 "Hunt Evil" poster — `Windows/SANS_DFPS_FOR508_v4.11_0624.pdf` (bundled in this repo)
- Eric Zimmerman's tools (PECmd) — https://ericzimmerman.github.io/
- NirSoft WinPrefetchView — https://www.nirsoft.net/utils/win_prefetch_view.html
- Microsoft Learn — Windows Prefetch behavior overview: https://learn.microsoft.com/windows-server/administration/performance-tuning/hardware/
