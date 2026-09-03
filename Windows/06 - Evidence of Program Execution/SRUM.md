# SRUM (System Resource Usage Monitor)

SRUM is the family's memory. Everything else in `06 - Evidence of Program Execution/` trades retention for precision — Prefetch caps out at 128/1024 files, BAM/DAM's window is roughly a week, ShimCache is capped and LRU-evicted on every boot. SRUM alone is built to hold **30 to 60 days** of history, and it holds a kind of data none of its siblings capture at all: how much CPU an application consumed, how much network traffic it moved, and which user account was on the hook for it — bucketed hour by hour. When Prefetch has rolled past the run you care about and BAM/DAM's week-long window has already closed, SRUM is frequently the only artifact left standing.

Like ShimCache's compatibility-database origin and BAM/DAM's power-management origin (see `ShimCache (AppCompatCache).md` and `BAM-DAM.md`, same folder), SRUM is another **accidental forensic goldmine** — a byproduct of an OS feature that has nothing to do with security. Microsoft built it to answer questions like "which apps are draining my battery" and "which apps are burning my data plan," and it surfaces directly to end users as the **App History** tab in Task Manager and the **Data usage** settings page. DFIR gets to read the same underlying database those UI surfaces are drawing from.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [What It Is](#what-it-is)
- [Where It Lives](#where-it-lives)
- [The Three Key Tables](#the-three-key-tables)
- [Recording Cadence: Hourly Batches, Not Real Time](#recording-cadence-hourly-batches-not-real-time)
- [Forensic Value for Program Execution](#forensic-value-for-program-execution)
- [Retention: The Longest Window in the Family](#retention-the-longest-window-in-the-family)
- [The Network/Exfiltration-Hunting Angle](#the-networkexfiltration-hunting-angle)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native triage against `C:\Windows\System32\sru\SRUDB.dat` before any parser (srum-dump, SrumECmd) comes out — no third-party modules required. PowerShell has **no native ESE/JET provider**, so it cannot open or query the database itself; everything below is existence/metadata/service-status triage plus a native technique for lifting the locked file off a live host, not a parse of the SRUM tables themselves (covered under Tooling below).

```powershell
# Confirm SRUDB.dat exists and its current size - missing or zero-byte on a Win8+ host is itself a finding
Get-Item 'C:\Windows\System32\sru\SRUDB.dat' -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime

# Last-write time brackets how recently the hourly commit ran - stale against "now" flags a stopped/broken collector
(Get-Item 'C:\Windows\System32\sru\SRUDB.dat' -ErrorAction SilentlyContinue).LastWriteTime

# DPS (Diagnostic Policy Service) drives SRUM's hourly commit pipeline - stopped/disabled means no new entries are being written
Get-Service -Name DPS | Select-Object Name, Status, StartType

# Every file in \sru, including transaction logs - an unusually thin or missing log set corroborates a tampered/cleared SRU folder
Get-ChildItem 'C:\Windows\System32\sru\' | Select-Object Name, Length, LastWriteTime

# SRUDB.dat is locked while Windows is running - create a VSS shadow copy and pull an unlocked snapshot out through it
(Get-WmiObject -List Win32_ShadowCopy).Create('C:\', 'ClientAccessible')
$shadow = (Get-CimInstance Win32_ShadowCopy | Sort-Object InstallDate -Descending | Select-Object -First 1).DeviceObject
Copy-Item "$shadow\Windows\System32\sru\SRUDB.dat" 'C:\hunt\SRUDB.dat' -Force

# Hand the extracted copy to the real ESE parser - this is an outer harness invoking SrumECmd, not native parsing
& 'C:\Tools\SrumECmd.exe' -f 'C:\hunt\SRUDB.dat' --csv 'C:\hunt\srum_out'
```

## What It Is

The System Resource Usage Monitor is a Windows subsystem, available from **Windows 8 onward**, whose job is to profile how applications consume system resources over time — CPU cycles, network bytes, and (in later builds) additional resource categories — and to keep enough history that Windows itself can show a user meaningful trends rather than just an instantaneous snapshot. That's why the data isn't ephemeral the way a live performance counter would be: SRUM writes it down, per application, per hour, for over a month at a time, and attributes it to whichever user account was responsible.

The forensic upside is that SRUM answers three questions in one place that usually require stitching together several other artifacts: **what ran, who ran it, and did it talk to the network** — all with enough retention to survive well past the point where Prefetch, ShimCache, and BAM/DAM have already aged out or been capped over.

## Where It Lives

| Detail | Value |
|---|---|
| File | `C:\Windows\System32\SRU\SRUDB.dat` |
| Format | **Extensible Storage Engine (ESE)** database — the same underlying database technology behind the Windows Search index (`Windows.edb`, see Deleted Items and File Existence, note 08) |
| Access | Requires the file to be extracted from a live host or a disk image; it is a locked system file while Windows is running, the same acquisition consideration that applies to registry hives (see Registry Forensics Fundamentals, note 04) |

Being an ESE database rather than a registry hive or a flat binary log means SRUM needs an ESE-aware parser (or an ESE-aware viewer) to read — there's no plain "open it in a hex editor and eyeball it" path the way there arguably is for a small registry value.

### PowerShell

To list every file in `\sru` (the main database plus its transaction logs) and pull the full service record for the process behind SRUM's hourly commits, use native cmdlets. This is metadata and service status only, not a parse of the ESE payload:

```powershell
Get-ChildItem 'C:\Windows\System32\sru\' -File | Select-Object Name, Length, CreationTime, LastWriteTime
Get-Service -Name DPS | Format-List Name, DisplayName, Status, StartType, DependentServices
```

## The Three Key Tables

`SRUDB.dat` holds many internal tables, but three carry essentially all of the forensic value:

| Table GUID | Name | What it records |
|---|---|---|
| `{973F5D5C-1D90-4944-BE8E-24B94231A174}` | **Network Data Usage** | Bytes sent and bytes received, per application, per hour, tied to the responsible user SID |
| `{d10ca2fe-6fcf-4f6d-848e-b2e99266fa89}` | **Application Resource Usage** | CPU/resource consumption per application, tied to the responsible user SID |
| `{DD6636C4-8929-4683-974E-22C046A43763}` | **Network Connectivity Usage** | Which network interfaces were used and how long the host stayed connected through them |

Each row in the first two tables is keyed to a **user SID** (see Users, Groups & Authentication, note 05, for resolving a SID to an account) — exactly the same per-user framing BAM/DAM offers, but layered on top of resource and network data BAM/DAM doesn't track at all.

## Recording Cadence: Hourly Batches, Not Real Time

SRUM does not write to `SRUDB.dat` as events happen. Data accumulates in an in-memory buffer and is committed to the on-disk database in batches, on a cadence of roughly **once per hour**.

🔴 **There is a data-loss window between "it happened" and "it's on disk."** Because commits are batched rather than continuous, activity that occurs shortly before a hard shutdown, crash, or forced power-off can still be sitting in the in-memory buffer at the moment of loss — meaning the most recent (up to roughly an hour of) activity may never make it into `SRUDB.dat` at all. Don't treat "no SRUM entry" for the final hour before an incident's abrupt end as proof nothing happened in that window; it may simply not have been flushed yet.

## Forensic Value for Program Execution

SRUM's specific contribution to the "did this program run" question is stronger than most of the family gives credit for:

- It proves the application **executed** — resource and network consumption are only recorded for a process that was actually running, not merely present on disk the way a ShimCache or Amcache entry can be.
- It ties that execution to a **specific user SID**, the same per-user attribution BAM/DAM offers.
- It gives you **hourly-bucketed resource and network activity**, which none of Prefetch, ShimCache, or Amcache attempt to capture at all — those three tell you a binary ran or existed, but none of them tell you whether it moved data over the network or how much CPU it burned while it ran.

Put plainly: SRUM is one of the few artifacts in this family that can support "this program ran, this user ran it, roughly when, and whether it touched the network" as a single finding, without needing to synthesize that claim from several separate sources.

## Retention: The Longest Window in the Family

| Artifact | Typical retention |
|---|---|
| **Prefetch** | Rolling by file count — 128 (XP/Win7) or 1024 (Win8+) `.pf` files, oldest evicted regardless of age |
| **BAM/DAM** | Roughly one week (see `BAM-DAM.md`) |
| **ShimCache (AppCompatCache)** | Capped entry count (96 XP / 1024 Win7+), LRU-evicted, effectively rebuilt each boot |
| **SRUM** | **~30–60 days**, independent of reboot count or file-count caps |

This is frequently the **longest retention window of the entire evidence-of-execution family**. On a host where the intrusion is a month or more old and Prefetch has long since cycled past the relevant `.pf` files, BAM/DAM's week-long window has closed, and ShimCache has been rebuilt across several reboots since — SRUM may be the only artifact still holding the record. Always check it on any case where the incident window is older than a few days, precisely because the rest of the family may have already aged the evidence out from under you.

## The Network/Exfiltration-Hunting Angle

Because Network Data Usage records bytes sent and bytes received per application per hour, SRUM gives you a lightweight, host-resident substitute for full packet capture when hunting for data movement:

- A sudden spike in outbound bytes from a process that has no legitimate reason to be moving significant data (a script host, an unfamiliar binary, a living-off-the-land tool) is a low-effort exfiltration indicator worth pulling into a timeline.
- SRUM can **corroborate or contradict** a suspect process's claimed network activity even when no packet capture or netflow data exists for that time window — if a process claims (or an attacker claims) it never communicated externally, but SRUM shows meaningful bytes sent during the relevant hour, that's a direct contradiction worth pursuing.
- The hourly bucket means you won't get a precise "at 14:32:07 this process sent X bytes to Y" — you get "in the 14:00–15:00 hour, this process sent this many bytes, total" — coarse compared to a network capture, but available for weeks after the fact when a capture never existed in the first place.

See Lateral Movement (forward reference — planned note in this module) for how this network angle plugs into a broader lateral-movement/exfiltration investigation.

## Tooling

| Tool | Form | What it gives you |
|---|---|---|
| **srum-dump** | Python/GUI community tool | The go-to purpose-built SRUM parser — reads `SRUDB.dat`, resolves application and SID references, and exports the Network Data Usage, Application Resource Usage, and Network Connectivity Usage tables (plus others) to a spreadsheet-friendly format for pivoting |
| **ESEDatabaseView** (NirSoft) | Generic ESE viewer | Not SRUM-specific, but a reliable fallback for opening `SRUDB.dat` (or any ESE database, including `Windows.edb`) directly when a dedicated parser isn't available or you need to sanity-check a table srum-dump didn't surface |
| **KAPE** | Collection pipeline | Targets exist to collect `C:\Windows\System32\SRU\SRUDB.dat` (plus its transaction logs) from a live host or triage image as part of a standard collection pass |

### PowerShell

PowerShell has no native ESE/JET provider and cannot open or query `SRUDB.dat` directly; there is no cmdlet-only path from raw bytes to Network Data Usage, Application Resource Usage, or Network Connectivity Usage rows. Treat the checks above as existence/triage only — reading the file any other way just returns unparseable binary noise, not structured data:

```powershell
Get-Content 'C:\Windows\System32\sru\SRUDB.dat' -TotalCount 1
```

Hand the file to srum-dump or SrumECmd for the actual parse instead — PowerShell's role here is to prepare and hand off (see the call-operator invocation in Hunt Evil above), not to interpret ESE structures itself.

Since `SRUDB.dat` is locked while Windows is running (the same acquisition problem covered above for registry hives in note 04), a VSS shadow copy sidesteps the lock without stopping any service, entirely with native cmdlets:

```powershell
# Create a shadow copy of C: so a consistent, unlocked snapshot of SRUDB.dat becomes available
(Get-WmiObject -List Win32_ShadowCopy).Create('C:\', 'ClientAccessible')

# Resolve the newest shadow copy's device path and copy the live SRUDB.dat out through it
$shadow = (Get-CimInstance Win32_ShadowCopy | Sort-Object InstallDate -Descending | Select-Object -First 1).DeviceObject
Copy-Item "$shadow\Windows\System32\sru\SRUDB.dat" 'C:\hunt\SRUDB.dat' -Force
```

- Sweep an estate for SRUM viability, pulling a fresh shadow-copy extraction and service status from each host into a staging path for later offline parsing:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
$sessions  = New-PSSession -ComputerName $computers

Invoke-Command -Session $sessions -ScriptBlock {
    (Get-WmiObject -List Win32_ShadowCopy).Create('C:\', 'ClientAccessible') | Out-Null
    $shadow = (Get-CimInstance Win32_ShadowCopy | Sort-Object InstallDate -Descending | Select-Object -First 1).DeviceObject
    Copy-Item "$shadow\Windows\System32\sru\SRUDB.dat" "C:\hunt_staging\$($env:COMPUTERNAME)_SRUDB.dat" -Force
    [PSCustomObject]@{ ComputerName = $env:COMPUTERNAME; DPSStatus = (Get-Service -Name DPS).Status }
}

foreach ($session in $sessions) {
    Copy-Item -FromSession $session -Path "C:\hunt_staging\$($session.ComputerName)_SRUDB.dat" -Destination 'C:\hunt\collected\'
}
```

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| SRUM entry for a process with no Prefetch/ShimCache/Amcache trace | Still meaningful on its own — resource/network consumption is only logged for something that actually ran; investigate why the other artifacts are silent (rolled over, cleared, or a server SKU with Prefetch disabled) |
| Large outbound byte count from an unfamiliar or short-lived process | Candidate exfiltration indicator — pivot to Network Connectivity Usage and any available netflow/firewall logs to corroborate destination and volume |
| No SRUM data for the final hour before an abrupt shutdown/crash, on a host otherwise known to have been active | Consistent with the in-memory-buffer commit gap, not evidence nothing happened — do not treat the absence as conclusive |
| SRUM shows execution/network activity for a binary the suspect denies ever ran | Direct contradiction — SRUM proves execution, unlike ShimCache/Amcache which only prove presence |
| SID attribution in SRUM doesn't match the account believed responsible | Possible RunAs, scheduled-task execution context, or account compromise wider than initially scoped — resolve via Users, Groups & Authentication (note 05) before concluding |
| Investigation window exceeds ~60 days and SRUM shows nothing | Expected — this is SRUM's outer retention boundary, not evidence the program never ran |

## Correlate With

- **Prefetch** — SRUM extends the investigation window well past Prefetch's rolling 128/1024-file cap, at the cost of hourly-bucket precision instead of Prefetch's ±10-second timestamps; see the full eight-artifact comparison table in `Prefetch.md`.
- **ShimCache (AppCompatCache)** — SRUM proves actual execution where ShimCache (Vista+) only proves presence; use SRUM to settle a ShimCache hit one way or the other when it's still within SRUM's 30–60 day window.
- **Amcache** — cross-check SRUM's execution/network evidence against Amcache's SHA-1/compile-timestamp/install-path detail for the same binary.
- **BAM-DAM** — both are per-SID execution signals; BAM/DAM gives a tighter single last-run timestamp over a much shorter (~1 week) window, SRUM trades that precision for weeks of hourly-bucketed history plus network/resource detail BAM/DAM doesn't track at all.
- **UserAssist** — corroborate GUI-initiated launches specifically; SRUM doesn't distinguish how a process was launched, only that it ran and what it consumed.
- **Jump Lists** — cross-reference which files a resource-heavy or network-active process actually opened around the same hour.
- **Task Bar Feature Usage & CapabilityAccessManager** — corroborate whether a flagged process was taskbar-launched or touched a sensitive capability (mic/camera/location) in the same window SRUM shows it consuming resources.
- **Users, Groups & Authentication** — resolving the SID attached to each SRUM row back to an account, and understanding what that attribution does and doesn't prove about who was at the keyboard.
- **Lateral Movement** (forward reference) — SRUM's Network Data Usage table is a standing source of exfiltration/data-movement leads for that investigation angle.

## Resources

- SANS FOR500 poster, "Windows Artifact Analysis: Evidence of… Application Execution" panel, SRUM entry — `Windows/SANS_DFPS_FOR500_v4.18_09-24.pdf` (bundled in this repo)
- SANS FOR508 "Hunt Evil: Lateral Movement" poster, Evidence of Program Execution strip — `Windows/SANS_DFPS_FOR508_v4.11_0624.pdf` (bundled in this repo)
- NirSoft ESEDatabaseView — https://www.nirsoft.net/utils/ese_database_view.html
- srum-dump (community SRUM parser) — search GitHub for the current maintained fork; project has changed hands over time, verify you have an actively maintained release before relying on it in casework
- SANS FOR500 course syllabus (public) — SRUM Overview / SRUM Registry Keys / SRUM Network Connectivity Usage / SRUM Network Data Usage / SRUM Application Resource Usage / SRUM Summary coverage checklist
