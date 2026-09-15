# Amcache

Amcache is the newest member of the "Evidence of Execution" family covered in this subfolder, and the one most easily confused with ShimCache — both are inventory artifacts that record a binary's presence rather than a confirmed launch. What separates Amcache is depth of metadata: alongside path and timestamp data, it carries a **SHA-1 hash** of the executable or driver it inventoried, plus size, compile-time, and publisher fields that neither ShimCache nor Prefetch offer. That hash is what turns a routine "was this file here" question into a hash-based threat-intel pivot, even after the file itself has been deleted from disk.

For how Amcache stacks up against Prefetch, ShimCache, BAM/DAM, and the rest of the execution-evidence family side by side, see the cross-artifact comparison table in `Prefetch.md` (same folder) — this note only goes deep on Amcache itself.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [What It Is](#what-it-is)
- [Where It Lives](#where-it-lives)
- [Internal Structure and Fields](#internal-structure-and-fields)
- [How to Interpret It](#how-to-interpret-it)
- [Amcache vs ShimCache vs Prefetch — The Presence-to-Execution Spectrum](#amcache-vs-shimcache-vs-prefetch--the-presence-to-execution-spectrum)
- [OS-Version Notes](#os-version-notes)
- [Tooling](#tooling)
- [Anti-Forensic Angle](#anti-forensic-angle)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage against `Amcache.hve` before AmcacheParser comes out — no third-party modules required. Unlike ShimCache (a single value already living inside the always-loaded `SYSTEM` hive), Amcache is its **own hive file on disk** that PowerShell has to mount before it can even browse the key structure, and it still can't decode the per-entry path/SHA-1/compile-timestamp fields once mounted — that decode requires AmcacheParser, covered in Tooling below.

```powershell
# Confirm Amcache.hve exists at its expected path before assuming the artifact is present at all
Test-Path 'C:\Windows\AppCompat\Programs\Amcache.hve'

# The hive file's own last-write time - a rough proxy for when Amcache last recorded new entries, never a per-binary timestamp
(Get-Item 'C:\Windows\AppCompat\Programs\Amcache.hve').LastWriteTime

# Mount the hive read-only under a scratch key so it can be browsed without touching the live SYSTEM/SOFTWARE hives
reg load HKLM\AmcacheHunt 'C:\Windows\AppCompat\Programs\Amcache.hve'

# Confirm the mount worked and see the top-level subkey names (Root, etc.) - structure only, no per-entry data yet
Get-ChildItem 'HKLM:\AmcacheHunt\Root'

# Unmount as soon as you're done browsing - a mounted hive left behind locks the file and can trip up other tools
[gc]::Collect(); reg unload HKLM\AmcacheHunt

# Invoke AmcacheParser from PowerShell for the actual entry-level decode - PowerShell is the harness here, not the parser
& 'C:\Tools\AmcacheParser.exe' -f 'C:\Windows\AppCompat\Programs\Amcache.hve' --csv 'C:\triage' --csvf "amcache_$env:COMPUTERNAME.csv"
```

## What It Is

Amcache is Microsoft's newer application-inventory subsystem, available from Windows 7 onward, that tracks installed applications, executables and drivers that have been present or run on a host, and assorted install/uninstall metadata. Like ShimCache, it exists to support the Application Compatibility infrastructure — helping Windows recognize binaries it has already evaluated — not to serve as an audit log. The forensic value is, once again, a side effect of that housekeeping purpose.

What sets Amcache apart from both Prefetch and ShimCache is that it also records the **SHA-1 hash** of the executables and drivers it catalogs. Neither of those other two artifacts carries a hash at all — Prefetch identifies a binary by path and Amcache-style compile metadata is absent from it entirely, and ShimCache only ever carries a path plus a last-modified time. A hash survives file deletion, renaming, and relocation in a way path strings do not, which is the single biggest reason Amcache earns its own note rather than being folded into the ShimCache comparison.

## Where It Lives

| Detail | Value |
|---|---|
| File | `C:\Windows\AppCompat\Programs\Amcache.hve` |
| Nature of the file | A **complete, standalone registry hive** — not a key living inside `SYSTEM` or `SOFTWARE` the way ShimCache's `AppCompatCache` value does. It is loaded, exported, and parsed exactly like any other hive file (see Registry Forensics Fundamentals, note 04, for hive structure and offline-parsing mechanics) |
| Availability | Windows 7 and later |

🔴 **Because Amcache is its own hive file on disk, it can be collected and parsed completely independently of the live `SYSTEM`/`SOFTWARE` hives** — a useful property during triage when you want Amcache data without mounting or exporting the larger core hives. It also means it's just as easy for an attacker (or an over-eager cleanup script) to delete outright, unlike a registry value buried inside a hive that's harder to selectively edit.

## Internal Structure and Fields

Amcache.hve organizes its data under several GUID-and-name-based subkeys beneath its root. The commonly referenced ones — naming and exact schema vary somewhat by Windows 10 feature-update build, so treat subkey names below as the general landmarks parsers look for rather than a fixed, version-proof map:

| Subkey (general area) | What it tracks |
|---|---|
| `Root\File` (older builds) / `Root\InventoryApplicationFile` (newer builds) | Per-executable/per-driver inventory entries — the bulk of what analysts pull from Amcache |
| `Root\Programs` / `Root\InventoryApplication` | Installed-application records (product name, version, install date, uninstall string) — closer to an "Add/Remove Programs" history than a per-binary record |
| Additional driver- and device-inventory subkeys | Loaded driver metadata, tracked separately from user-mode executables in some builds |

Fields recorded per executable/driver entry, where present:

| Field | Meaning | Interpretation notes |
|---|---|---|
| Full file path | Where the binary lived when inventoried | Same masquerading/legitimacy questions as any other path field — check against expected system-binary locations (Windows OS Fundamentals & Versions, note 01) |
| File size | Size in bytes | Corroborates identity alongside the hash; a mismatch against a known-good sample is worth flagging |
| File modification time | The binary's own `$STANDARD_INFORMATION` last-write time | Same NTFS timestamp category as ShimCache's last-modified field — the file's history, not the host's |
| Compilation/link time (PE header timestamp) | The timestamp embedded in the executable's PE header at build time | 🔴 **Attacker-controllable.** This field comes from inside the file itself, not from the filesystem, so a malware author can set it to whatever value they like at compile time. Treat it as a weak, spoofable data point — never as trustworthy as filesystem or registry timestamps, and never cite it alone as "when this was built" without corroboration |
| Publisher / product metadata | Digital-signature and product-name fields carried in the executable, where present | Useful for quickly separating signed, known-vendor binaries from unsigned or self-signed ones during triage |
| **SHA-1 hash** | Cryptographic hash of the file at inventory time | The field that makes Amcache uniquely valuable — see below |

## How to Interpret It

> 🔴 **AMCACHE PROVES PRESENCE, NOT EXECUTION.** This is the same category of caveat that governs ShimCache: an Amcache entry means Windows inventoried the executable or driver at some point, not that anyone launched it. Some Windows 10 builds' `Program`/`InventoryApplicationFile` structures capture execution-adjacent detail, but this varies by build and should not be assumed present or reliable without confirming it on the specific OS version in front of you. Always corroborate an Amcache hit with an artifact that actually carries execution semantics — Prefetch, BAM/DAM, Security 4688, or EDR telemetry — before asserting a binary ran.

Where Amcache earns its keep over ShimCache is the **SHA-1 hash**. A hash is portable in a way path strings and timestamps are not:

- Pivot the hash against VirusTotal, internal IOC lists, or a threat-intel feed — this works even after the file itself has been deleted from disk, since the hash was captured and persisted at inventory time.
- Match the same malicious binary across multiple hosts in an enterprise by hash, regardless of what path or filename it was dropped under on each host — a masquerading or renaming attacker can't defeat a hash match the way they can defeat a path-based search.
- Confirm (or refute) that a file recovered from disk during the investigation is the *same* file Amcache saw earlier, independent of any filesystem timestamp manipulation.

Treat the compile-time field with the same skepticism you'd apply to any other attacker-influenced metadata: useful as a lead (e.g., a PE timestamp claiming a 2009 build date on a binary tied to a 2026 intrusion is a red flag), never as a verified fact on its own.

### PowerShell

To mount the hive and browse it generically with a real PSDrive rather than raw `reg.exe` output, then unmount cleanly, use the following:

```powershell
reg load HKLM\AmcacheHunt 'C:\Windows\AppCompat\Programs\Amcache.hve'
New-PSDrive -Name AmcacheHunt -PSProvider Registry -Root 'HKLM\AmcacheHunt' -Scope Global | Out-Null

# Browse whatever subkey structure this build actually uses - names vary by Windows 10 feature update (see Internal Structure and Fields)
Get-ChildItem 'AmcacheHunt:\Root' | Select-Object Name
Get-ChildItem 'AmcacheHunt:\Root\InventoryApplicationFile' -ErrorAction SilentlyContinue | Select-Object -First 5 Name

# Clean unmount - remove the PSDrive first, then release the hive so nothing else has it locked
Remove-PSDrive -Name AmcacheHunt
[gc]::Collect(); reg unload HKLM\AmcacheHunt
```

Mounting gets you subkey *names* — GUID-keyed containers, one per inventoried binary — but not the values inside them. Each `Root\File`/`Root\InventoryApplicationFile` entry stores its path, SHA-1, size, and compile timestamp as individual named values under that GUID subkey, and both the GUID naming and the value-name schema shift across Windows 10 feature updates (see Internal Structure and Fields above). There is no native cmdlet that walks every GUID subkey, resolves the build-specific value names, and normalizes them into one row per binary the way AmcacheParser does — hand-rolling that walk means re-deriving a schema Eric Zimmerman already tracks release over release. Use **AmcacheParser** (Tooling below) for the real per-binary path/SHA-1/compile-timestamp decode; PowerShell's job is mounting, staging, and invoking, not parsing:

```powershell
# Same tool as the Hunt Evil block above, run against an offline Amcache.hve already exported from a dead-box image
& 'C:\Tools\AmcacheParser.exe' -f 'D:\image\Windows\AppCompat\Programs\Amcache.hve' --csv 'C:\triage'
```

For cross-host sweeps, copy each host's hive to a scratch path (which avoids fighting the live file's lock), mount just long enough to confirm which subkey schema that build uses, unmount, then run AmcacheParser against the copy and aggregate every host's CSV into one fleet-wide file:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Copy-Item 'C:\Windows\AppCompat\Programs\Amcache.hve' 'C:\Windows\Temp\Amcache_copy.hve' -Force
    reg load HKLM\AmcacheHunt 'C:\Windows\Temp\Amcache_copy.hve' | Out-Null
    $rootSubkeys = (Get-ChildItem 'HKLM:\AmcacheHunt\Root' -ErrorAction SilentlyContinue).PSChildName -join ';'
    [gc]::Collect(); reg unload HKLM\AmcacheHunt | Out-Null

    & 'C:\Tools\AmcacheParser.exe' -f 'C:\Windows\Temp\Amcache_copy.hve' --csv 'C:\Windows\Temp\amcache' --csvf "$env:COMPUTERNAME.csv"
    Import-Csv "C:\Windows\Temp\amcache\$env:COMPUTERNAME.csv" |
        Select-Object *, @{N='ComputerName'; E={ $env:COMPUTERNAME }}, @{N='RootSubkeys'; E={ $rootSubkeys }}
} | Export-Csv -Path 'C:\hunt\amcache_fleet.csv' -NoTypeInformation -Append
```

## Amcache vs ShimCache vs Prefetch — The Presence-to-Execution Spectrum

These three are the most commonly confused members of the family, so it's worth contrasting them directly rather than relying on the full 8-artifact table alone:

| | Prefetch | ShimCache | Amcache |
|---|---|---|---|
| Strength of execution evidence | Strongest — path-specific run proof | Weakest — presence/evaluation only | Presence, with richer metadata than ShimCache |
| Biggest limitation | Volatile (rolling 128/1024-file cap), can be disabled, often absent on servers | No execution timestamp at all post-XP; can be seeded by mere evaluation, not a real launch | Compile-time field is attacker-controllable; execution-adjacent detail is inconsistent across builds |
| Unique strength | Embedded run-count + last-8-runs array | Oldest, most persistent presence trail; survives even on hosts where Prefetch is off | SHA-1 hash — survives file deletion, enables hash-based IOC/threat-intel pivoting |

The practical takeaway: reach for Prefetch first when you need a run-time claim, reach for ShimCache when Prefetch is missing or disabled and you just need "was this file here," and reach for Amcache specifically when you need to identify a binary by hash — including cases where the file has already been deleted and only its registry-hive trace remains.

## OS-Version Notes

- Amcache effectively superseded the older `RecentFileCache.bcf` mechanism used on Windows 8 and earlier iterations of the compatibility subsystem — if you're working an older image and Amcache.hve is thin or absent, `RecentFileCache.bcf` (where present) may be the era-appropriate equivalent to check for.
- Amcache's internal subkey layout and exact field set have changed across Windows 10 feature updates — don't assume a schema learned on one build transfers unchanged to another. Confirm your parser's supported-build list and, where possible, validate field availability against the actual build under investigation rather than assuming parity across versions.

## Tooling

| Tool | Form | What it gives you |
|---|---|---|
| **AmcacheParser** (Eric Zimmerman suite) | CLI | The primary Amcache parser used throughout this repo's convention (matches PECmd/AppCompatCacheParser/RECmd elsewhere) — parses `Amcache.hve` directly, outputs path, size, timestamps, publisher, and SHA-1 per entry in CSV for pivoting or hash-list export |
| **Registry Explorer** (Eric Zimmerman) | GUI | Can open `Amcache.hve` like any other hive for manual inspection of subkey structure when a parser's output needs cross-checking against the raw key |
| **KAPE** | Collection + parsing pipeline | Targets/modules exist to collect `Amcache.hve` from a live or imaged host and run AmcacheParser against it automatically as part of a triage pass |

## Anti-Forensic Angle

🔴 **Amcache.hve is an ordinary file on disk and can be deleted or tampered with like any other hive file.** Unlike ShimCache, which lives buried inside the `SYSTEM` hive and requires registry-level manipulation to selectively edit, `Amcache.hve` is a standalone file that a less careful attacker (or an over-broad anti-forensic script) might delete or replace outright. A **missing or unusually small `Amcache.hve`** on a system that should show a rich, long install/execution history — a production workstation or server with years of software churn — is itself a red flag worth investigating on its own merits, the same way a suspiciously thin `Prefetch\` directory is.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Amcache entry for a suspicious binary with no corroborating Prefetch/BAM-DAM/Security 4688 evidence | Presence only — do not report as execution; treat the hash as your strongest lead and pivot it against threat intel |
| PE compile timestamp wildly inconsistent with the surrounding incident timeline (e.g., years before or after) | Possible attacker manipulation of the PE header — never treat this field as a trustworthy build date on its own |
| SHA-1 hash matches a known-malicious file, but the file itself is no longer present on disk | Confirms the binary existed and was inventoried even after deletion — a strong lead for scoping across other hosts by hash |
| `Amcache.hve` missing entirely, or conspicuously small, on a host with long install history | Possible deliberate deletion/tampering of the hive file — cross-check against ShimCache and Prefetch for the same binaries |
| Same hash appearing under different paths/filenames across multiple hosts | Indicates masquerading or lateral distribution of the same tool — pivot the investigation by hash, not by filename |

## Correlate With

- **Prefetch** (same folder) — Prefetch supplies the run-count and embedded-timestamp evidence Amcache cannot; use it whenever you need to move from "this existed" to "this ran."
- **ShimCache (AppCompatCache)** (same folder) — closest sibling artifact; both are presence-only inventories, but Amcache's SHA-1/publisher/compile-time fields make it the stronger choice whenever hash-based identification or threat-intel pivoting is needed.
- **BAM/DAM** — supplies a genuine last-run timestamp per user SID that Amcache's inventory data cannot provide; useful to confirm execution once Amcache has identified a binary of interest.
- **UserAssist** — corroborates GUI-initiated launches specifically, complementing Amcache's path/hash-level identification with shell-launch context.
- **Persistence Mechanisms** (note 10 series) — a binary Amcache shows was inventoried long before any user-reported activity often traces back to an autostart/scheduled-task/service entry that placed it there.
- **Registry Forensics Fundamentals** (note 04) — hive structure, offline parsing, and transaction-log mechanics that apply to `Amcache.hve` the same as any other hive file.

## Resources

- SANS FOR500 "Windows Artifact Analysis: Evidence of..." poster, "Application Execution" panel, Amcache.hve entry — `Windows/SANS_DFPS_FOR500_v4.18_09-24.pdf` (bundled in this repo)
- SANS FOR508 "Hunt Evil" poster — `Windows/SANS_DFPS_FOR508_v4.11_0624.pdf` (bundled in this repo)
- Eric Zimmerman's tools (AmcacheParser, Registry Explorer) — https://ericzimmerman.github.io/
- SANS FOR500 course syllabus (public) — Amcache coverage checklist
