# Task Bar Feature Usage & CapabilityAccessManager

These are two small, unrelated-by-function registry artifacts that this repo groups into one note for a practical reason: both are compact, single-key, Windows 10 1903+-only usage-tracking mechanisms — short enough that neither needed its own file, but each carrying a genuinely distinct forensic signal worth knowing cold. **Task Bar Feature Usage** tells you how a user interacted with the taskbar (launches, focus-switches) but never *when*. **CapabilityAccessManager** tells you exactly *when* an application accessed a sensitive device capability — microphone, camera, location — down to session start/stop times. Put side by side, they're a useful lesson in how two artifacts that look similar on paper (both registry, both "usage counters") can sit at opposite ends of the timestamp-precision spectrum covered in the family comparison table in `Prefetch.md` (same folder).

Neither artifact exists before Windows 10 version 1903 — there is no XP/Win7/Win8/Win8.1 equivalent for either. If you're working an older host, skip straight past this note; the keys simply aren't there to find.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Part 1 — Task Bar Feature Usage](#part-1--task-bar-feature-usage)
  - [What It Tracks](#what-it-tracks)
  - [Where It Lives](#where-it-lives)
  - [Key Values](#key-values)
  - [Limitations](#limitations)
- [Part 2 — CapabilityAccessManager](#part-2--capabilityaccessmanager)
  - [What It Tracks](#what-it-tracks-1)
  - [Where It Lives](#where-it-lives-1)
  - [Key Fields](#key-fields)
  - [The NonPackaged Subkey](#the-nonpackaged-subkey)
- [Comparative Summary](#comparative-summary)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage against both `NTUSER.DAT\...\FeatureUsage` and `...\CapabilityAccessManager\ConsentStore` before any GUI tool (Registry Explorer) comes out — no third-party modules required. Both artifacts are plain registry keys/values, so PowerShell reads every field either exposes end-to-end; nothing here requires a dedicated parser.

```powershell
# FeatureUsage - AppLaunch counters ranked highest first (persists even after the app is later unpinned)
$k = Get-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch'
$k.GetValueNames() | ForEach-Object { [PSCustomObject]@{ App = $_; Launches = $k.GetValue($_) } } | Sort-Object Launches -Descending

# FeatureUsage - AppSwitched counters ranked highest first (fires for any focus-switch, pinned or not - a broader signal than AppLaunch)
$k = Get-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched'
$k.GetValueNames() | ForEach-Object { [PSCustomObject]@{ App = $_; Switches = $k.GetValue($_) } } | Sort-Object Switches -Descending

# ConsentStore - every capability/app pair that has ever recorded access, packaged and NonPackaged (Win32) entries together
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore' -Recurse |
    Where-Object { $_.GetValue('LastUsedTimeStart') } | Select-Object PSChildName, PSParentPath

# Decode LastUsedTimeStart/LastUsedTimeStop into real dates, most recent session first - the actual timeline this note offers
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore' -Recurse |
    Where-Object { $_.GetValue('LastUsedTimeStart') } |
    ForEach-Object {
        [PSCustomObject]@{
            Capability = ($_.Name -split '\\ConsentStore\\')[1].Split('\')[0]
            App        = $_.PSChildName
            Start      = [DateTime]::FromFileTime($_.GetValue('LastUsedTimeStart'))
            Stop       = [DateTime]::FromFileTime($_.GetValue('LastUsedTimeStop'))
        }
    } | Sort-Object Stop -Descending

# Flag webcam/microphone access under NonPackaged (traditional Win32 apps, not Store apps) - the most direct spyware/insider-surveillance lead here
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged',
              'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged' -ErrorAction SilentlyContinue |
    ForEach-Object { [PSCustomObject]@{ App = $_.PSChildName; Start = [DateTime]::FromFileTime($_.GetValue('LastUsedTimeStart')); Stop = [DateTime]::FromFileTime($_.GetValue('LastUsedTimeStop')) } }

# Cross-reference: AppLaunch entries whose recorded path no longer resolves on disk - pinned/launched from somewhere since removed
$k = Get-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch'
$k.GetValueNames() | Where-Object { $_ -match '\\' -and -not (Test-Path $_) }
```

## Part 1 — Task Bar Feature Usage

### What It Tracks

Windows 10 (1903+) keeps a small usage counter for how a user has interacted with the taskbar itself — which apps got pinned and launched from it, and which apps the user switched focus to. It's part of the shell's own usage telemetry, not a security feature, but the byproduct is a durable record of taskbar-level habits that survives well after the fact.

### Where It Lives

| Detail | Value |
|---|---|
| Registry key | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage` |
| Hive | `NTUSER.DAT`, per user profile — see Registry Forensics Fundamentals (note 04) for hive location and offline-access mechanics |
| OS availability | Windows 10 1903 and later only |

### PowerShell

List the usage-category subkeys, then pull the raw per-app counters under one of them (on a live host, `HKCU:` resolves to the interactive user's own loaded `NTUSER.DAT`):

```powershell
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage' | Select-Object PSChildName

Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch'
```

### Key Values

| Value name | What it proves | Notes |
|---|---|---|
| **AppLaunch** | The app was launched **while pinned to the taskbar** — a counter of pin-launched executions | 🔴 Only tracks apps actually pinned; **critically, the counter's data persists even after the app is later unpinned** — so a nonzero `AppLaunch` entry can prove an app was pinned and launched at some point in the past, even if the taskbar shows no trace of it today |
| **AppSwitched** | A count of times the app was brought into focus / switched to (Alt-Tab, taskbar click, etc.) | **Not tied to pinning at all** — this fires for any running app the user brings into focus, pinned or not, which makes it a broader (if shallower) signal than `AppLaunch` |
| **ShowJumpView**, **TrayButtonClicked**, **AppBadgeUpdated** | Other `FeatureUsage` values seen alongside the two above, evidently tied to jump-list invocation, taskbar/tray button clicks, and notification-badge updates respectively | Their exact semantics and edge-case behavior aren't as well-documented as `AppLaunch`/`AppSwitched` — treat the general "some taskbar interaction happened" signal as solid, but don't assert precise definitions for these three without validating against a controlled test system first |

To rank `AppLaunch` and `AppSwitched` counters independently (since one persists after unpinning while the other doesn't require pinning at all), use native registry queries to pull and sort the values:

```powershell
$k = Get-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch'
$k.GetValueNames() | ForEach-Object { [PSCustomObject]@{ App = $_; Launches = $k.GetValue($_) } } | Sort-Object Launches -Descending | Format-Table -AutoSize

$k = Get-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched'
$k.GetValueNames() | ForEach-Object { [PSCustomObject]@{ App = $_; Switches = $k.GetValue($_) } } | Sort-Object Switches -Descending | Format-Table -AutoSize
```

### Limitations

🔴 **This is a counter-based artifact, not a timestamped one — there are no timestamps anywhere in `FeatureUsage`.** Every value here is a running count, full stop. This changes what you can defensibly claim in a report:

- **Good for:** "was this app ever pinned to the taskbar," "was this app ever launched from the taskbar or switched to," "is the pin/launch count consistent with the user's claimed usage."
- **Not good for:** "when did this happen" — there is no *when* anywhere in this key. If you need timing, you have to get it from a different artifact (Prefetch, BAM/DAM, UserAssist, Security 4688) and merely use `FeatureUsage` to corroborate that taskbar interaction occurred at all.
- **GUI apps only** — this tracks taskbar/shell interaction, so it silently misses command-line, scheduled-task, and service-launched execution the same way UserAssist does (see `UserAssist.md`, same folder).

To sweep `AppLaunch` counters across an estate for a specific pinned tool and export for pivoting, note that `HKCU:` in a remote session resolves to the profile running that session, so target the specific user's loaded hive when hunting non-interactive accounts:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    $k = Get-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch' -ErrorAction SilentlyContinue
    if ($k) {
        $k.GetValueNames() | ForEach-Object { [PSCustomObject]@{ ComputerName = $env:COMPUTERNAME; App = $_; Launches = $k.GetValue($_) } }
    }
} | Export-Csv C:\hunt\featureusage_sweep.csv -NoTypeInformation
```

## Part 2 — CapabilityAccessManager

### What It Tracks

Starting with the same Windows 10 1903 baseline, Windows centralizes user consent and access records for apps touching privacy-sensitive device capabilities — microphone, camera/webcam, location, and other OS-mediated resources gated behind a consent prompt. Every time an app accesses one of these capabilities, Windows records which app, which capability, and the session's start/stop time in a dedicated registry structure. Unlike Task Bar Feature Usage, this one was built with a privacy/consent purpose in mind, and it happens to leave a genuinely useful forensic trail as a direct result.

### Where It Lives

| Scope | Registry key |
|---|---|
| System-wide | `SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore` |
| Per-user | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore` |

Both live under a `ConsentStore` subkey, organized by capability (e.g. `webcam`, `microphone`, `location`) and then by the accessing application underneath each. OS availability is Windows 10 1903+ only, same as Part 1 — check the hive location and `CurrentControlSet`/hive-load notes in Registry Forensics Fundamentals (note 04) for acquisition mechanics on both the `SOFTWARE` and `NTUSER.DAT` hives.

### PowerShell

Pull the raw per-app values under one capability (system-wide, swap `webcam` for `microphone`/`location`), then the full per-user `ConsentStore` tree, packaged and `NonPackaged` together, as a first look:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\*' -ErrorAction SilentlyContinue

Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore' -Recurse
```

### Key Fields

| Field | Meaning |
|---|---|
| **LastUsedTimeStart** | The start time of the application's most recent session accessing that capability |
| **LastUsedTimeStop** | The stop time of that same session |

This is a real, meaningful difference from Part 1: `LastUsedTimeStart`/`LastUsedTimeStop` are genuine timestamped session data — a specific app accessed a specific capability, starting and ending at specific times. That's a fundamentally stronger evidentiary claim than anything `FeatureUsage` can offer.

To decode both `REG_QWORD` FILETIME values into real dates and sort by most recent session start, use this query to produce the actual "when did this app touch the mic/camera/location" answer that Part 1 cannot provide:

```powershell
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore' -Recurse |
    Where-Object { $_.GetValue('LastUsedTimeStart') } |
    ForEach-Object {
        [PSCustomObject]@{
            Capability = ($_.Name -split '\\ConsentStore\\')[1].Split('\')[0]
            App        = $_.PSChildName
            Start      = [DateTime]::FromFileTime($_.GetValue('LastUsedTimeStart'))
            Stop       = [DateTime]::FromFileTime($_.GetValue('LastUsedTimeStop'))
        }
    } | Sort-Object Start -Descending | Format-Table -AutoSize
```

### The NonPackaged Subkey

Underneath `ConsentStore`, entries for traditional Win32/desktop applications are separated out under a **`NonPackaged`** subkey, distinct from the entries for UWP/Microsoft Store apps sitting directly under each capability.

**Why the split exists:** UWP/Store apps declare which capabilities they need up front, in their app manifest, as part of the Store submission and installation process — Windows already knows at install time that a Store camera app might ask for webcam access. Traditional Win32 desktop applications have no such manifest-declared capability list; they request access to the microphone/camera dynamically at runtime through the same consent-broker API, so Windows tracks them in a separate `NonPackaged` bucket rather than trying to fold them into the manifest-driven model.

**Forensic value:** this is exactly the kind of distinction that turns CapabilityAccessManager from a curiosity into an investigative tool. Because `NonPackaged` isolates non-Store desktop applications, this artifact can reveal that a specific, ordinary-looking desktop executable accessed the microphone or webcam at a specific date and time — independent of anything the app's own UI told the user. That's directly relevant to insider-threat, spyware, and unauthorized-surveillance investigations: did a piece of malware quietly enable the webcam, did a rogue employee-installed remote-access tool activate the microphone during a meeting, does a "legitimate" business app have an undisclosed audio-capture habit. `LastUsedTimeStart`/`LastUsedTimeStop` under `NonPackaged` for the suspect executable is often the single most direct piece of evidence available for "did this program listen or watch, and when."

To sweep every host in an estate for Win32 (non-Store) webcam access and export for timeline pivoting, use this cross-host script. To hunt a different capability, swap `webcam` for `microphone` or `location`:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged' -ErrorAction SilentlyContinue |
        ForEach-Object {
            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                App          = $_.PSChildName
                Start        = [DateTime]::FromFileTime($_.GetValue('LastUsedTimeStart'))
                Stop         = [DateTime]::FromFileTime($_.GetValue('LastUsedTimeStop'))
            }
        }
} | Export-Csv C:\hunt\webcam_access_sweep.csv -NoTypeInformation
```

## Comparative Summary

| | Task Bar Feature Usage | CapabilityAccessManager |
|---|---|---|
| Purpose | Taskbar interaction habits (pin/launch/focus-switch) | Sensitive-capability access (mic/camera/location) |
| Timestamps | **None** — counters only | **Yes** — `LastUsedTimeStart`/`LastUsedTimeStop` per session |
| Best evidentiary claim | "This app was pinned/launched/switched to, at some point" | "This app accessed this capability, starting/ending at this time" |
| Scope | Any GUI app touching the taskbar | Any app (Store or Win32) requesting mic/camera/location/etc. |
| Key distinction inside it | `AppLaunch` (pinned-only, survives unpinning) vs `AppSwitched` (any focus, not pin-dependent) | `NonPackaged` (Win32/desktop) vs. Store-app entries under each capability |
| OS availability | Windows 10 1903+ only | Windows 10 1903+ only |
| Hive | `NTUSER.DAT` | `SOFTWARE` (system-wide) **and** `NTUSER.DAT` (per-user) |

For how both of these stack up against the other six artifacts in the "evidence of execution" family (Prefetch, ShimCache, Amcache, BAM/DAM, UserAssist, Jump Lists, SRUM), see the full comparison table in `Prefetch.md`, same folder — this note's row there summarizes both artifacts covered here in one line.

## Tooling

| Tool | Use |
|---|---|
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Both artifacts are plain registry keys/values with no proprietary binary blob to decode (unlike ShimCache's `AppCompatCache` value) — Registry Explorer opens either hive and both key trees directly, human-readable, no dedicated parser required |
| **RECmd batch files** | For repeatable triage, a RECmd batch targeting `FeatureUsage` and `CapabilityAccessManager\ConsentStore` (system + per-user) pulls both artifacts alongside the rest of a standard registry collection in one pass |
| **KAPE** | Targets exist to collect `NTUSER.DAT` and `SOFTWARE` hives as part of a standard triage collection; feed the results to Registry Explorer/RECmd as above |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `AppLaunch` entry for an app that isn't currently pinned to the taskbar | Data persists after unpinning — proves the app *was* pinned and launched at some point, worth timeline-correlating against other execution evidence even though this value carries no timestamp of its own |
| `NonPackaged` entry showing webcam or microphone access for an unfamiliar or unexpected desktop executable | Direct evidence of a specific program accessing a sensitive capability at a specific session window — central to spyware/insider-surveillance investigations; identify the binary and cross-check Amcache/Prefetch/ShimCache for what it is and when it arrived |
| `LastUsedTimeStart`/`LastUsedTimeStop` session window overlapping a known sensitive meeting, call, or user activity, for an app the user didn't knowingly authorize | Suggests covert audio/video capture during a specific, identifiable event — a strong lead in insider-threat or unauthorized-monitoring cases |
| Analyst attempts to derive a launch *time* from `FeatureUsage` alone | Unsupported — no timestamp field exists anywhere in `FeatureUsage`; the correct claim is "occurred at some point," not "occurred at time T" |
| `AppSwitched` count high with no corresponding `AppLaunch` entry | Consistent with the app running via a non-taskbar launch path (command line, scheduled task, service) that the user then alt-tabbed/clicked into — corroborate the actual launch vector with Prefetch/BAM-DAM/UserAssist rather than assuming taskbar-pinned execution |

## Correlate With

- **Prefetch** (same folder) — holds the full "evidence of execution" family comparison table this note's row summarizes; use Prefetch's embedded run-timestamp array to supply the timing that Task Bar Feature Usage cannot.
- **ShimCache (AppCompatCache)** (same folder) — corroborate that a suspicious `NonPackaged` executable existed on disk at all, and since when, independent of whether it ran.
- **Amcache** (same folder) — cross-check SHA-1/install-path/compile-timestamp detail for any executable flagged via `NonPackaged` capability access.
- **BAM-DAM** (same folder) — confirm the single most-recent execution time and user (SID) attribution for an app seen in either `FeatureUsage` or `CapabilityAccessManager`.
- **UserAssist** (same folder) — corroborate GUI-launched execution with run count and last-run time; useful alongside `AppLaunch`/`AppSwitched` since both artifacts track shell-initiated activity from different angles.
- **Jump Lists** (same folder) — cross-reference which files a taskbar-pinned or -switched-to application actually opened around the same period.
- **SRUM** — extend the investigation window for network/CPU activity by the same suspicious application well past what either artifact here retains, at hourly-bucket precision.
- **Registry Forensics Fundamentals** (note 04) — hive structure, `NTUSER.DAT`/`SOFTWARE` load mechanics, and offline-vs-live acquisition details that apply unchanged to both artifacts in this note.

## Resources

- SANS FOR500 poster, "Windows Artifact Analysis: Evidence of… Application Execution" panel (Task Bar Feature Usage) and "Evidence of… Deleted Items and File Existence" panel (CapabilityAccessManager) — `Windows/SANS_DFPS_FOR500_v4.18_09-24.pdf` (bundled in this repo)
- Eric Zimmerman's tools (Registry Explorer, RECmd) — https://ericzimmerman.github.io/
- SANS FOR500 course syllabus (public) — Windows privacy/consent and taskbar-usage artifact coverage checklist
