# BAM/DAM (Background/Desktop Activity Moderator)

BAM and DAM are two nearly-identical registry-resident logs that Windows never intended anyone to use for forensics. They belong to the Windows **power-management subsystem** — the code that decides which background apps get throttled, suspended, or deprioritized to save battery and CPU on modern laptops and tablets. To make those throttling decisions, the subsystem needs to know which executables are actually doing something and when they last did it. That bookkeeping is what lands in the registry, and it happens to answer a DFIR question almost perfectly: which user ran which program, and when, most recently. Like ShimCache's compatibility-database origin (see `ShimCache (AppCompatCache).md`, same folder) and much of what's cataloged in Registry Forensics Fundamentals (note 04), BAM/DAM is an **accidental forensic artifact** — a byproduct of an OS feature with zero forensic design intent, which happens to be one of the cleaner execution logs available on a modern Windows host.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [What It Is](#what-it-is)
- [Where It Lives](#where-it-lives)
- [What It Records](#what-it-records)
- [Retention Window](#retention-window)
- [Timestamp Precision Caveat](#timestamp-precision-caveat)
- [Interpretation Strength vs. the Rest of the Family](#interpretation-strength-vs-the-rest-of-the-family)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

BAM/DAM is a rare case in this family where PowerShell needs no third-party parser at all — the value name is already the exe path, and the value data's first 8 bytes are a plain Windows FILETIME that `[DateTime]::FromFileTimeUtc()` decodes natively. Everything below is native, read-only, and paste-ready.

```powershell
# Every SID BAM is tracking on this host - each subkey is one user account with its own execution history
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName

# Full BAM decode across every SID, newest execution first - value name = exe path, first 8 bytes of the value data = FILETIME
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\' -ErrorAction SilentlyContinue | ForEach-Object {
    $sid = $_.PSChildName; $key = Get-Item $_.PSPath
    $key.GetValueNames() | Where-Object { $_ -notin @('Version','SequenceNumber') } | ForEach-Object {
        $bytes = $key.GetValue($_)
        [PSCustomObject]@{ SID = $sid; ExePath = $_; LastRunUtc = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($bytes[0..7], 0)) }
    }
} | Sort-Object LastRunUtc -Descending

# Same sweep, but resolve each SID to an account name instead of leaving it as a raw SID - see note 05 for SID structure
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\' -ErrorAction SilentlyContinue | ForEach-Object {
    $sid = $_.PSChildName
    try { (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { "$sid (unresolved)" }
}

# BAM entries whose exe path runs from Temp/Downloads/AppData - the locations attackers actually drop payloads to
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\' -ErrorAction SilentlyContinue | ForEach-Object {
    $key = Get-Item $_.PSPath
    $key.GetValueNames() | Where-Object { $_ -match '\\(Temp|Downloads|AppData)\\' }
}

# Pre-1809 fallback - if the State-prefixed path above returns nothing, check the older path shape before assuming BAM is empty
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings\' -ErrorAction SilentlyContinue

# Does the host even have BAM (Win10+ only) - confirms whether an empty result above means "no data" or "not applicable to this OS"
Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\bam'
```

## What It Is

**BAM** (Background Activity Moderator) and **DAM** (Desktop Activity Moderator) are two services that ship as part of Windows' power/activity management. Their actual job is to track whether an app is running in the background or foreground so Windows can throttle CPU, network, and other resources for apps the user isn't actively looking at — a battery-life and performance feature, not a security or audit feature. DAM is functionally the same mechanism aimed at a slightly different activity-moderation scope; the two keys are consistently found side by side and are read the same way.

**Availability:** Windows 10 and later only. There is no BAM/DAM equivalent on Windows 7/8/8.1 or Windows XP — those OS versions rely on Prefetch, ShimCache, and (from Win8+) Amcache for execution evidence instead. Where BAM/DAM exists, treat it as a bonus fifth angle on execution, not a baseline you can assume on every host in a mixed-fleet investigation.

🔴 **Forensic value here is a side effect, not the design intent.** Nothing about BAM/DAM was built with logging, auditing, or incident response in mind — Microsoft could change or remove this mechanism in a future release without breaking any forensic-facing contract, because no such contract exists. Treat its continued presence and format as version-dependent, the same caution this repo applies to ShimCache and Amcache.

## Where It Lives

Both keys live in the `SYSTEM` hive (see Registry Forensics Fundamentals, note 04, for hive location, `CurrentControlSet` resolution, and offline-vs-live acquisition mechanics — everything there applies unchanged to BAM/DAM).

| Service | Registry key |
|---|---|
| **BAM** | `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` |
| **DAM** | `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}` |

Each value under `UserSettings\{SID}` is named for a **full file path** to an executable, and the value's binary data encodes the last-execution date/time for that path. `{SID}` is the security identifier of the user account the entries belong to — see Users, Groups & Authentication (note 05) for SID structure and resolving a SID to an account name.

**OS-version delta — the `State` subkey layer:**

| Windows 10 release | Path shape |
|---|---|
| Early Windows 10 (pre-1809) | `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` — no `State` subkey in the path |
| Windows 10 1809 and later, Windows 11 | `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` — `State` subkey inserted between the service name and `UserSettings` |

🔴 If a parser or a manual registry walk comes up empty at the `...\bam\State\UserSettings\{SID}` path on an older Windows 10 build, don't conclude BAM data is absent — check one level up without `State` first. The same delta applies identically to the `dam` key.

## What It Records

Per value, BAM/DAM gives you exactly two facts, but they're two facts nothing else in this family combines as directly:

- **Full file path** of the executable that ran (the value name itself).
- **Last-execution date/time** for that path (decoded from the value's binary data).

Both are scoped **per SID** — every user account on the host gets its own `UserSettings\{SID}` subkey, so a BAM/DAM hit doesn't just tell you a program ran, it tells you **which logged-on account ran it**, directly, without needing to cross-reference a separate logon-session or Security-log table to make that attribution. That per-user framing is BAM/DAM's single biggest structural advantage over ShimCache and (in most builds) Amcache, neither of which is inherently split by user.

Since this is a registry value, not a binary file, `Get-ItemProperty`/`Get-Item` reads it directly with no parser at all. To list every SID BAM is tracking on the host (each subkey represents one user account with its own execution history) and pull the raw value names for a specific SID of interest:

```powershell
# List every SID BAM has a subkey for on this host
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\'

# Raw value names (each one a full exe path) for one SID of interest
Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>' | Select-Object -ExpandProperty Property
```

For the full decode that transforms value name into exe path and the first 8 bytes of value data into a readable FILETIME timestamp, grouped by SID and resolved to account name in one pass:

```powershell
function Get-BamActivity {
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\' -ErrorAction SilentlyContinue | ForEach-Object {
        $sid = $_.PSChildName
        $account = try { (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { 'Unresolved SID' }
        $key = Get-Item $_.PSPath
        foreach ($valueName in ($key.GetValueNames() | Where-Object { $_ -notin @('Version','SequenceNumber') })) {
            $bytes = $key.GetValue($valueName)
            [PSCustomObject]@{
                SID        = $sid
                Account    = $account
                ExePath    = $valueName
                LastRunUtc = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($bytes[0..7], 0))
            }
        }
    }
}

Get-BamActivity | Sort-Object LastRunUtc -Descending | Group-Object Account
```

🔴 Per the Timestamp Precision Caveat above, treat `LastRunUtc` as accurate to within a few minutes, not to the second — report it as "approximately," and corroborate exact timing against Prefetch's embedded run-time array or Security 4688 when the finding depends on second-level precision.

## Retention Window

BAM/DAM's biggest limitation, stated plainly: **typically only about one week of data is available.** Unlike Prefetch's file-count-based rolling cap (128/1024 entries, see `Prefetch.md`) or Amcache's tendency to persist across reboots until the hive is pruned, BAM/DAM appears to age out on a much shorter, time-based horizon in practice.

🔴 **BAM/DAM is excellent for very recent activity and useless for anything older than roughly a week.** If your incident window is more than a few days old, do not expect BAM/DAM to still hold the entry you're looking for — reach for Prefetch, Amcache, or ShimCache instead, and treat BAM/DAM as confirming only the tail end of an intrusion timeline, not its origin.

## Timestamp Precision Caveat

BAM/DAM's last-execution value is a genuine timestamp pulled from a registry value, not a coarse ±10-second file-system approximation the way Prefetch's creation/modified dates are. In principle that means better precision than most of the family.

In practice, hedge this: community research on BAM's last-execution field has documented cases where the recorded time appears to be **approximate rather than exact-to-the-second** — off by several minutes in some observed cases, for reasons not fully nailed down publicly (possible batching/lazy-write behavior in how the power-management subsystem updates the value). This repo does not assert a specific fixed offset, because the bundled SANS sources don't quantify one and independent research findings vary. The practical guidance: treat a BAM/DAM timestamp as accurate to within several minutes, not to the second, and corroborate exact timing against Prefetch's embedded run-time array or Security 4688 process-creation events (note 11) when second-level precision actually matters to the finding.

## Interpretation Strength vs. the Rest of the Family

BAM/DAM's last-execution timestamp is a **real execution timestamp** — unlike ShimCache, which (Vista and later) only ever gives you a file's last-modified time and never proves the file ran at all (see the 🔴 callout in `ShimCache (AppCompatCache).md`). That makes BAM/DAM one of the stronger "this ran, by this user, at roughly this time" artifacts available on a Win10+ host — presence in BAM/DAM is genuine execution evidence, with built-in user attribution, at reasonable (if not second-perfect) timing precision.

The tradeoff is scope: BAM/DAM only exists on Windows 10+, and only covers roughly the last week. It is a **complement** to Prefetch/Amcache/ShimCache, not a replacement for any of them — use it to nail down the most recent activity and the responsible user account, and lean on the longer-retention artifacts for anything further back. For the full eight-artifact side-by-side (what each proves, timestamp precision, retention, presence-vs-execution), see the comparison table in `Prefetch.md` (same folder) — this note doesn't repeat it.

## Tooling

BAM/DAM is a straightforward set of registry values — no specialized binary-format parser is required the way Prefetch needs PECmd or ShimCache needs AppCompatCacheParser.

| Tool | Use |
|---|---|
| **Registry Explorer** (Eric Zimmerman) | Open the `SYSTEM` hive directly, navigate to `Services\bam\State\UserSettings\{SID}` (and `dam`), and read path + decoded last-execution time per value — no special plugin needed |
| **RECmd** (Eric Zimmerman) | Scriptable/batch equivalent of Registry Explorer — useful for pulling BAM/DAM out of many collected `SYSTEM` hives (e.g. KAPE triage output) without opening each one by hand |
| Community BAM/DAM extraction scripts | Several public scripts exist purpose-built to walk every `{SID}` subkey and dump path + last-execution time in bulk across many user accounts on one host, or across many hosts — worth using when a case involves more than a handful of SIDs, since manual review of each `{SID}` subkey doesn't scale |

For sweeping an estate to locate a specific binary's last-run time and SID across multiple hosts, export results for pivoting, and cross-check `bam` against the legacy `dam` key for any discrepancies, native PowerShell can orchestrate the full collection:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\' -ErrorAction SilentlyContinue | ForEach-Object {
        $sid = $_.PSChildName; $key = Get-Item $_.PSPath
        $key.GetValueNames() | Where-Object { $_ -like '*psexec.exe*' } | ForEach-Object {
            $bytes = $key.GetValue($_)
            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                SID          = $sid
                ExePath      = $_
                LastRunUtc   = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($bytes[0..7], 0))
            }
        }
    }
} | Export-Csv C:\hunt\bam_sweep.csv -NoTypeInformation
```

Cross-checking against the legacy DAM key follows the same pattern — use the identical decode against the `dam` key to find any paths present in one but not the other, which is worth closer investigation:

```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\' -ErrorAction SilentlyContinue | ForEach-Object {
    $sid = $_.PSChildName; $key = Get-Item $_.PSPath
    $key.GetValueNames() | Where-Object { $_ -notin @('Version','SequenceNumber') } | ForEach-Object {
        $bytes = $key.GetValue($_)
        [PSCustomObject]@{ SID = $sid; ExePath = $_; LastRunUtc = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($bytes[0..7], 0)) }
    }
}
```

BAM/DAM entries are not targets for deletion during response activities. These values are passive activity records with no persistence mechanisms attached to them — clearing them destroys evidence rather than containing a threat. When an unfamiliar path appears in BAM/DAM, the remediation focus should be on the executable or persistence mechanism itself (see Persistence Mechanisms, note 10 series), not on the BAM/DAM record of it having run.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| BAM/DAM entry for a suspicious executable, no corresponding Prefetch/Amcache/ShimCache trace | Still meaningful on its own — BAM/DAM's timestamp is genuine execution evidence even in isolation, but corroborate if the other artifacts should logically exist and don't |
| BAM/DAM entry attributes execution to a SID that doesn't match the account believed to be responsible | Possible token impersonation, RunAs, scheduled-task "run as" context, or an account compromise wider than initially scoped — resolve the SID via Users, Groups & Authentication (note 05) before concluding |
| Analyst cites a BAM/DAM timestamp as exact-to-the-second in a report | Overstates precision — community research documents cases of multi-minute approximation; state the finding as "approximately" and corroborate against Prefetch/Security 4688 for exact timing |
| Investigation window older than ~1 week and BAM/DAM shows nothing | Expected, not suspicious — this is BAM/DAM's known retention ceiling, not evidence the executable never ran; pivot to Prefetch/Amcache/ShimCache |
| `bam`/`dam` `UserSettings\{SID}` path missing entirely on a Win10 1809+ host | Check the pre-1809 path shape (no `State` subkey) in case of a hive from an older build, or confirm the host predates Win10 entirely (no BAM/DAM key exists at all pre-Win10) |

## Correlate With

- **Prefetch** — corroborate BAM/DAM's single most-recent timestamp against Prefetch's embedded 8-entry run-time array and run counter for a fuller recent-execution picture, and to get second-level precision where BAM/DAM's approximation isn't tight enough.
- **ShimCache (AppCompatCache)** — BAM/DAM's genuine execution timestamp is the strongest available counterpoint to ShimCache's "presence, not execution" limitation; use BAM/DAM to confirm a ShimCache hit actually ran.
- **Amcache** — cross-check BAM/DAM's path against Amcache's SHA-1/compile-timestamp/install-path detail for the same binary when hash-level identity matters.
- **UserAssist** — both are per-user execution signals; UserAssist adds run count and is scoped to GUI-initiated launches specifically, useful for distinguishing a shell double-click from a script/service launch BAM/DAM alone can't tell apart.
- **Persistence Mechanisms** (note 10 series) — a BAM/DAM entry with a recent, unexplained last-execution time for an unfamiliar path is a strong lead into checking autostart keys, scheduled tasks, and services for what's relaunching it.
- **Registry Forensics Fundamentals** (note 04) — hive structure, `CurrentControlSet` resolution, and transaction-log replay mechanics used to acquire and parse `SYSTEM` correctly.
- **Users, Groups & Authentication** (note 05) — resolving the `{SID}` in each `UserSettings\{SID}` subkey back to an account, and understanding what that per-user attribution does and doesn't prove about who was physically at the keyboard.

## Resources

- SANS FOR500 poster, "Windows Artifact Analysis: Evidence of… Application Execution" panel, BAM/DAM entry — `Windows/SANS_DFPS_FOR500_v4.18_09-24.pdf` (bundled in this repo)
- SANS FOR508 "Hunt Evil" poster — `Windows/SANS_DFPS_FOR508_v4.11_0624.pdf` (bundled in this repo)
- Eric Zimmerman's tools (Registry Explorer, RECmd) — https://ericzimmerman.github.io/
- SANS FOR500 course syllabus (public) — BAM/DAM coverage checklist
