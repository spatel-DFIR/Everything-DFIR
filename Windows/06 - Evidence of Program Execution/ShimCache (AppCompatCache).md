# ShimCache (AppCompatCache)

ShimCache — formally the **AppCompatCache**, part of the Windows **Application Compatibility Database** — was never designed to be a forensic artifact. Windows built it to solve a support problem: old executables that break on newer Windows builds. Before running an EXE, Windows checks this cache to see whether the file needs a compatibility "shim" applied (an on-the-fly behavioral patch that makes old software run correctly on a newer OS). The side effect of that compatibility check is what DFIR cares about — the cache records the executable's **full file path** and its **binary's last-modified timestamp**, for every executable Windows has evaluated.

That last sentence is the whole note. Read it twice: Windows evaluates executables for compatibility far more often than it actually runs them, which means ShimCache tells you a binary was *present and evaluated*, not that anyone ever launched it. Nearly every misused Windows artifact in DFIR traces back to skipping this distinction — this note exists to make sure you never do.

For how ShimCache stacks up against Prefetch, Amcache, BAM/DAM, and the rest of the execution-evidence family side by side, see the cross-artifact comparison table in `Prefetch.md` (same folder) — this note only goes deep on ShimCache itself.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [What It Is](#what-it-is)
- [Where It Lives](#where-it-lives)
- [Capacity: A Rolling, Limited-Size Cache](#capacity-a-rolling-limited-size-cache)
- [How to Interpret It](#how-to-interpret-it)
- [Where ShimCache Earns Its Keep](#where-shimcache-earns-its-keep)
- [No Execution Timestamp Post-XP](#no-execution-timestamp-post-xp)
- [Anti-Forensic Angle](#anti-forensic-angle)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Fast triage one-liners for a live host. ShimCache is a single opaque binary blob — these confirm the artifact exists and hand you the entry point into a real parser; they do **not** decode individual path/timestamp entries, and none of them should be mistaken for that.

```powershell
# Confirm the AppCompatCache value exists at all, and get its raw byte-array length
(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -Name AppCompatCache -ErrorAction SilentlyContinue).AppCompatCache.Length

# Some builds name the value "Cache" instead of "AppCompatCache" — check both before concluding the artifact is absent
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -ErrorAction SilentlyContinue | Select-Object AppCompatCache, Cache

# Registry key's own last-write time — a rough, weak proxy for "when this batch of entries last changed," never an execution time (see How to Interpret It below)
(Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache').LastWriteTime

# Confirm which ControlSet is actually live before trusting CurrentControlSet — a stale ControlSetXXX copy will mislead you
Get-ItemProperty -Path 'HKLM:\SYSTEM\Select' | Select-Object Current, Default, LastKnownGood

# Confirm AppCompatCacheParser is reachable before relying on the invocation below
Get-Command AppCompatCacheParser.exe -ErrorAction SilentlyContinue

# Invoke AppCompatCacheParser from PowerShell for the actual entry-level decode — PowerShell is the harness here, not the parser
& 'C:\Tools\AppCompatCacheParser.exe' --live --csv 'C:\triage' --csvf "shimcache_$env:COMPUTERNAME.csv"
```

## What It Is

The Application Compatibility Database exists so Microsoft can keep old software limping along on new Windows versions without rewriting the software itself. When an executable is about to run — and, critically, in several other evaluation paths too (see below) — Windows consults a cache of previously-seen executables to decide whether a known compatibility fix ("shim") needs to be injected for that binary. To make that lookup fast, Windows caches, per executable:

- The **full file path** the executable was found at.
- The **binary's last-modified timestamp** (the file's `$STANDARD_INFORMATION` modified time, i.e. when the EXE itself was last changed on disk) — not a run time.
- A **file size** (older OS versions) or, on newer builds, an **insertion/execution flag** field whose meaning has shifted across releases and is not reliably a clean "this ran" indicator on its own — treat path + last-modified time as the two facts you can trust, and corroborate everything else.

This makes ShimCache one of the oldest, most persistent traces of "an executable existed at this path with this last-modified time" available on a Windows host — it goes back to Windows XP and is present on every version since, including Windows Server editions.

## Where It Lives

| OS version | Registry key |
|---|---|
| Windows XP | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility` |
| Windows Vista / 7 / 8 / 8.1 / 10 / 11 / Server 2008+ | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` |

Both keys live in the `SYSTEM` hive (see Registry Forensics Fundamentals, note 04, for hive location and offline-vs-live access mechanics) — so `CurrentControlSet` resolution and transaction-log replay both apply here exactly as described there. The value itself is a single binary blob (`AppCompatCache` value, or `Cache` depending on OS build) that a parser decodes into individual entries; there is nothing readable by eye in RegEdit beyond "a large binary value exists."

## Capacity: A Rolling, Limited-Size Cache

ShimCache is not an unbounded log — it holds a fixed maximum number of entries, and once that ceiling is hit, the oldest entries are evicted to make room for new ones (LRU-style):

| OS version | Maximum entries |
|---|---|
| Windows XP | 96 |
| Windows 7 and later | 1,024 |

**Investigative implication:** ShimCache can never answer "show me everything that has ever run on this host." It's a rolling window over the most recently *evaluated* executables, capped at 1,024 entries (or 96 on XP) — a single busy day of normal Windows operation, software updates, and AV scanning can be enough to cycle a meaningful fraction of that window. Treat ShimCache as a recent-ish snapshot, and treat even that snapshot with the caveat in the next section — because unlike Prefetch's execution counter or BAM/DAM's session timestamps, that recent window still doesn't guarantee execution at all.

## How to Interpret It

> 🔴 **PRESENCE IN SHIMCACHE DOES NOT PROVE EXECUTION.** This is arguably the single most commonly misinterpreted artifact in all of Windows DFIR, and it has produced bad findings in real casework. Windows populates ShimCache entries by *evaluating* executables for compatibility — a process that can be triggered by the file simply being present and scanned, indexed, or opened by a non-executing process (e.g. antivirus, backup software, `explorer.exe` enumerating a directory, a file-copy operation, or Windows itself probing the file during a compatibility check) — **not only** by a user or process actually launching it. An entry in ShimCache tells you an executable existed at a specific path with a specific last-modified time and was seen by the OS. It does **not**, by itself, tell you the executable ever ran. Never present a ShimCache hit to a client, in a report, or in court as proof of execution without independent corroboration from an artifact that actually carries execution semantics (Prefetch, Amcache's run-related fields where present, BAM/DAM, Security 4688, EDR telemetry). If corroboration is absent, the correct and defensible claim is "this file was present on the system as of [last-modified time]" — full stop.

Beyond that central caveat, treat the two trustworthy fields as follows:

- **File path** — the full path the executable lived at when it was evaluated. If a path shows something like a Recycle Bin location, a temp folder, or a user-writable directory paired with a system-sounding filename, that's a legitimacy question worth chasing (see Windows OS Fundamentals & Versions, note 01, for expected legitimate paths of system binaries).
- **Last-modified time** — the executable file's own last-write time, exactly the same NTFS timestamp you'd see with `dir` or a file listing. This is the file's history, not the host's history — a malicious binary compiled on the attacker's machine six months ago and copied onto the victim host yesterday will show a last-modified time from six months ago, not yesterday. Cross-reference with $MFT/`$STANDARD_INFORMATION` and `$FILE_NAME` timestamps (see NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes) to catch timestomping.

### PowerShell

Read the raw registry value directly; this is the PowerShell-native equivalent of opening RegEdit and looking at the key:

```powershell
# Raw registry read — the AppCompatCache property comes back as an opaque byte array, not text
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'

# Store the raw bytes and print their length — confirms the value exists and roughly how much data it holds
$raw = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache').AppCompatCache
"AppCompatCache is {0} bytes" -f $raw.Length
```

PowerShell alone gets you exactly two facts — the `AppCompatCache` value exists, and it is *N* bytes long. It cannot tell you a single cached path, last-modified time, or entry count. Those live inside a structured binary format (header + per-entry records, with layout differences across XP/Vista/Win7/Win8+) that native cmdlets have no decoder for — `Get-ItemProperty` hands back a raw `byte[]` and stops there. There is no `ConvertFrom-AppCompatCache` cmdlet, and hand-rolling an offset-based binary parser in PowerShell to chase a format that has changed across OS releases is a fragile substitute for a maintained one. Use **AppCompatCacheParser** (see Tooling below) for the real entry-level decode — PowerShell's job here is to fetch/stage the raw hive data and invoke that tool, not to replace it:

```powershell
# Call AppCompatCacheParser from PowerShell against the live hive — PowerShell as the outer harness, not the parser
& 'C:\Tools\AppCompatCacheParser.exe' --live --csv 'C:\triage' --csvf "shimcache_$env:COMPUTERNAME.csv"

# Same tool against an offline SYSTEM hive already exported from a dead-box image, via the call operator
& 'C:\Tools\AppCompatCacheParser.exe' -f 'D:\image\Windows\System32\config\SYSTEM' --csv 'C:\triage'
```

For cross-host operations, either run the parser remotely and pull its CSV back, or (when the parser isn't staged everywhere) pull only the raw registry bytes back for offline parsing later:

```powershell
# Run AppCompatCacheParser on each remote host and collect the resulting CSVs into one fleet-wide file
$computers = Get-Content C:\triage\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    & 'C:\Tools\AppCompatCacheParser.exe' --live --csv 'C:\Windows\Temp\shimcache' --csvf "$env:COMPUTERNAME.csv"
    Import-Csv "C:\Windows\Temp\shimcache\$env:COMPUTERNAME.csv"
} | Export-Csv -Path 'C:\triage\shimcache_fleet.csv' -NoTypeInformation -Append

# Alternative: pull only the raw bytes and key last-write time back for later offline parsing, no parser binary needed on the remote host
Invoke-Command -ComputerName $computers -ScriptBlock {
    [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        RawBytes     = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache').AppCompatCache
        KeyLastWrite = (Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache').LastWriteTime
    }
} | Export-Clixml -Path 'C:\triage\shimcache_raw_fleet.xml'
```

## Where ShimCache Earns Its Keep

Because presence doesn't prove execution, ShimCache's real value is narrower and more specific than beginners expect: it's most useful precisely on hosts where *other* execution-evidence sources are thin or absent.

- **Windows Servers** — Prefetch has historically been disabled by default on server SKUs (see `Prefetch.md` for the exact version-by-version default-enabled table), so a compromised server may have no Prefetch trail at all. ShimCache still exists on servers and can be the only registry-resident trace that a suspicious executable was ever on disk, at a specific path, with a specific last-modified time — even without proof it ran.
- **Anti-forensic scenarios where Prefetch/Amcache were cleared** — an attacker who deletes `C:\Windows\Prefetch\*.pf` or purges `Amcache.hve` entries may not think to (or be able to) scrub ShimCache, since it requires a specific registry-level cleanup most intrusion toolkits don't bother with.
- **Establishing a "this file existed here" fact independent of execution** — sometimes that's all you need. Knowing a webshell or tool dropped into `C:\ProgramData\` existed with a last-modified time inside your incident window is itself valuable timeline evidence, even absent proof it ran.

## No Execution Timestamp Post-XP

Be precise about what timestamp data ShimCache does and does not give you, because this is a frequent source of confusion distinct from (but related to) the presence-vs-execution problem above:

- **Windows XP** ShimCache entries include a **last-modified time** and a **last-update (roughly execution-adjacent) time** — XP is the one version where the cache carries something closer to a run-time field, though even there it should be corroborated rather than trusted alone.
- **Windows Vista and later**, the per-entry data is reduced to **path + last-modified time only** — there is **no execution timestamp field in the entry at all**, full stop. Any argument that an entry's presence implies "and it ran at approximately time T" is unsupported by the data structure itself on these versions.
- The **registry key's own last-write time** (see Registry Forensics Fundamentals, note 04, on per-key last-write times) can serve as a rough, weak proxy for "roughly when this batch of entries was last updated" — but this is the key's write time, not any individual entry's timestamp, and a single key write can silently update or reorder many entries at once. Do not conflate "the AppCompatCache key was last written at time T" with "this specific executable ran at time T." They are not the same fact, and reports should keep that distinction explicit.

## Anti-Forensic Angle

- **Preemptive seeding.** Because ShimCache entries can be created by evaluation alone, a sophisticated adversary (or an analyst's own tooling, unintentionally) can seed misleading entries without the file ever executing — copying a payload to disk, running an AV scan over it, or simply browsing to its folder in Explorer can be enough to plant an entry. Treat any single ShimCache hit for a suspicious binary as a lead to corroborate, never as a conclusion to report.
- **Volatility caveat (hedge deliberately).** Some older Windows versions have been documented as holding ShimCache data primarily in memory and only flushing it to the registry at a controlled shutdown — meaning a hard power-off or crash on those builds could lose recent entries entirely. This behavior is version- and build-dependent and not something to assert confidently across the board; if an expected entry is missing and the host in question is an older build, note the possibility in your findings rather than treating the absence as conclusive, and verify against that specific build's documented behavior before relying on it.

## Tooling

| Tool | Use |
|---|---|
| **AppCompatCacheParser** (Eric Zimmerman) | Primary parser — decodes the raw `AppCompatCache`/`Cache` binary value out of an offline or live `SYSTEM` hive into a readable CSV/table of path + last-modified time (+ XP's extra fields where present) |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Can view the raw key/value directly, useful for confirming the value exists, its size, and the key's own last-write time — pair with AppCompatCacheParser for the actual entry-level decode |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| ShimCache entry for a suspicious binary, with no supporting Prefetch/Amcache/BAM-DAM/Security 4688 evidence | Consistent with presence only — do not report as execution; investigate why other execution artifacts are silent (server SKU, no Prefetch, evidence cleared, or simply never ran) |
| ShimCache entry's last-modified time predates the incident window by a large margin, on a binary otherwise tied to the intrusion | Possible timestomping or a reused/repurposed legitimate binary — cross-check `$MFT` `$STANDARD_INFORMATION` vs `$FILE_NAME` timestamps |
| ShimCache entries for the same suspicious path across many hosts, none corroborated by execution artifacts anywhere | Suggests mass file staging/distribution (e.g. a compromised software deployment or a scanning tool touching the file), not necessarily mass execution |
| Analyst/report asserts a specific execution time derived from a Vista+ ShimCache entry | Unsupported — no execution-timestamp field exists in the entry structure post-XP; only path + last-modified time are present |
| Registry key's last-write time cited as "the execution time" | Conflates key-level write time with entry-level execution — the two are not the same fact |
| Expected ShimCache entry missing for a binary known to exist on an older-build host that suffered a hard shutdown/crash | Possibly lost due to the (build-dependent) in-memory-until-clean-shutdown behavior — verify against that build's documented flush behavior before concluding the file was never there |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Full cross-artifact "evidence of execution" comparison across all 8 artifacts in this family | **Prefetch** (same folder) |
| Execution-count/run-time corroboration, per-server default-enabled behavior | **Prefetch** |
| Executable-metadata-rich alternative with SHA-1 hash, install path, publisher | **Amcache** |
| Per-second-resolution recent-execution timestamps from the power-management subsystem | **BAM-DAM** |
| Deliberate persistence mechanisms that would plant the binary ShimCache is seeing | **Persistence Mechanisms** (note 10 series) |
| Hive structure, `CurrentControlSet` resolution, transaction-log replay mechanics used to acquire/parse this key correctly | **Registry Forensics Fundamentals** (note 04) |
| `$MFT`/`$STANDARD_INFORMATION` vs `$FILE_NAME` timestamp comparison to detect timestomping of the binary itself | **NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes** |

## Resources

- Eric Zimmerman's tools (AppCompatCacheParser, Registry Explorer, RECmd) — https://ericzimmerman.github.io/
- Mandiant — "Shim Cache" whitepaper (community reference on structure/format history)
- SANS FOR500 poster, "Windows Artifact Analysis: Evidence of… Application Execution" panel — coverage checklist for path/key/capacity facts, rewritten in this note's own words
- SANS FOR500 course syllabus (public) — AppCompatCache/ShimCache coverage checklist
