# Jump Lists

Jump Lists are a taskbar feature, not a security log — Windows built them so a user could right-click (or long-hover) an app's taskbar icon and jump straight back into whatever they'd been doing with it, without reopening the app and re-navigating a menu. That convenience feature has a forensic side effect: to populate the list, Windows (and often the application itself) has to *remember* what the app opened, in what order, and when — and it writes that memory to disk as a per-application, per-user file that survives long after the taskbar click is forgotten.

This note treats Jump Lists as a member of the "Evidence of Program Execution" family — the mere existence of a Jump List for a given application is itself a data point that the application ran under Windows shell integration at least once. For the companion angle — *which specific files* a user opened, independent of which app opened them — see `07 - File and Folder Opening (User Activity).md` (forward reference; not yet written), which covers the file-access side of this same artifact without re-deriving the mechanics laid out here.

For how Jump Lists stack up against Prefetch, ShimCache, Amcache, BAM/DAM, and the rest of the execution-evidence family side by side, see the cross-artifact comparison table in `Prefetch.md` (same folder).

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [What It Is](#what-it-is)
- [Automatic vs. Custom Destinations](#automatic-vs-custom-destinations)
- [Where It Lives](#where-it-lives)
- [AppID Naming](#appid-naming)
- [Internal Structure](#internal-structure)
- [Timestamp Semantics](#timestamp-semantics)
- [Forensic Value for Program Execution](#forensic-value-for-program-execution)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage against `AutomaticDestinations`/`CustomDestinations` before JLECmd comes out — no third-party modules required. PowerShell can enumerate the files themselves (AppID-named, per-user) and pull filesystem timestamps and size; it **cannot** open the OLE/Compound File container or read the embedded LNK-style streams inside — that parsing requires JLECmd, covered in Tooling below.

```powershell
# Every AutomaticDestinations file for the current user, newest activity first
Get-ChildItem "$env:AppData\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms" |
    Sort-Object LastWriteTime -Descending | Select-Object Name, CreationTime, LastWriteTime

# Same sweep for CustomDestinations - app-curated pins, don't expect one for every AppID
Get-ChildItem "$env:AppData\Microsoft\Windows\Recent\CustomDestinations\*.customDestinations-ms" |
    Sort-Object LastWriteTime -Descending | Select-Object Name, CreationTime, LastWriteTime

# Every local profile in one pass - which user accounts have Jump List activity at all
Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms' -ErrorAction SilentlyContinue |
    Select-Object @{N='User'; E={ ($_.FullName -split '\\')[2] }}, Name, LastWriteTime

# File size as a rough proxy for entry volume (bigger file ~ more embedded streams) - exact
# per-entry count still requires JLECmd; this only ranks candidates for a closer look
Get-ChildItem "$env:AppData\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms" |
    Sort-Object Length -Descending | Select-Object Name, Length, LastWriteTime

# Oldest and newest Jump List activity on this profile - brackets the shell-usage window
Get-ChildItem "$env:AppData\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms" |
    Sort-Object LastWriteTime | Select-Object -First 1 -Last 1 Name, CreationTime, LastWriteTime

# AppID files with no match in a known-good lookup list - flag for manual AppID-to-app lookup
# (requires a lookup CSV like the community-maintained lists named in AppID Naming below)
$known = Import-Csv C:\hunt\appid_lookup.csv | Select-Object -ExpandProperty AppID
Get-ChildItem "$env:AppData\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms" |
    Where-Object { $known -notcontains $_.BaseName } | Select-Object Name, LastWriteTime
```

## What It Is

**Jump Lists** were introduced in **Windows 7** as part of the redesigned taskbar and have existed on every Windows version since. Right-clicking, or long-hovering, an application's pinned or running taskbar icon pops up a small menu of items associated with that app — recently opened documents, frequently visited sites, or shortcuts the application itself chose to pin (e.g. "New Message" in an email client, "New Window" in a browser). That menu is the user-facing view of a Jump List; the data behind it is what DFIR cares about.

Two things make Jump Lists distinctive as an artifact, and both matter for interpretation:

- They are **per-application and per-user** — each combination of "this app, this Windows user account" gets its own file, so Jump Lists double as a rough map of which user used which application.
- They are populated by **two different mechanisms** (below) with different forensic guarantees, and conflating the two is the most common analyst mistake with this artifact.

## Automatic vs. Custom Destinations

| | Automatic Destinations | Custom Destinations |
|---|---|---|
| **Who populates it** | Windows itself, automatically, whenever the application opens a file/object through normal shell mechanisms | The application's own code, deliberately, to pin items it considers important |
| **What it tracks** | Every file/object the app opened via standard Windows APIs (recently used documents, recent shell items) | Curated shortcuts the app chose to expose — e.g. a "Frequent" or "Tasks" section, "New Document," pinned items the user manually pinned |
| **File extension** | `.automaticDestinations-ms` | `.customDestinations-ms` |
| **Forensic reliability** | Higher — driven by OS shell integration, consistent across apps that use standard file-open dialogs | Lower and more app-specific — depends entirely on what that particular application's developers chose to write; format/content varies app to app |
| **Best used for** | Reconstructing "what files/objects did this app actually open, and when" | Corroborating app-specific behavior (e.g. confirming a browser's "Frequent" list) — treat as supplementary, not a primary timeline source |

Both file types can exist side by side for the same AppID — check both, but don't expect Custom Destinations to exist for every application; many apps never write one.

## Where It Lives

| Destination type | Path |
|---|---|
| Automatic Destinations | `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` |
| Custom Destinations | `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\` |

**OS-version note:** Jump Lists exist on Windows 7 and every version since (8/8.1/10/11), including Server SKUs that run Explorer/taskbar shell (Server Core builds without the full shell generally won't generate them). There is no Jump List equivalent on Windows XP — the taskbar feature itself didn't exist yet.

### PowerShell

List both destination folders side by side, tagging each result with its destination type; this is filesystem metadata only, `Get-ChildItem` never opens the OLE container:

```powershell
Get-ChildItem "$env:AppData\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms",
              "$env:AppData\Microsoft\Windows\Recent\CustomDestinations\*.customDestinations-ms" |
    Select-Object @{N='DestinationType'; E={ $_.Extension.TrimStart('.') }}, BaseName, CreationTime, LastWriteTime, Length
```

## AppID Naming

Each Jump List file is named after an **Application Identifier (AppID)** — a hash value tied to the specific application, e.g. `5f7b5f1e01b83767.automaticDestinations-ms`. The AppID isn't a random file handle; it's derived in a way that ties it to the application's identity **and, for many apps, its install location**. That has a useful, specific forensic consequence: if a binary is run from a non-standard install path, its AppID can come out different from the AppID you'd expect for the "known good" version of that application. That's a minor but real tell when you're trying to establish whether an executable ran from its expected, legitimately-installed location versus a copy staged somewhere else (e.g. a temp folder or a portable-app layout).

Because AppIDs are opaque hashes rather than human-readable names, mapping a given AppID back to "this is Microsoft Word" or "this is Chrome" requires a lookup. Rather than hand-deriving the hash yourself, use one of the **publicly maintained AppID-to-application mapping lists** that the DFIR community keeps up to date (commonly distributed alongside the Eric Zimmerman tool ecosystem) — treat any specific one as a convenience reference to verify against your own tool's output, not as an authoritative source on its own.

## Internal Structure

A Jump List file — Automatic or Custom — is not a flat log. It's an **OLE/Compound File Binary (CFB)** structured file, the same container format used historically by legacy Office documents, and internally it holds multiple **embedded streams**, each one a **shell-item/LNK-style structure** describing one accessed item. Practically:

- Each stream is functionally a miniature LNK (shortcut) record — see `LNK Files` coverage in note 07 for the shell-item format itself — carrying:
  - **Target filename/path**
  - **Target file's own timestamps** (creation, modification, access, as recorded in the shell-item metadata, separate from the Jump List file's own timestamps — see below)
  - **File size**
  - **Volume/origin information** — whether the target lived on a local fixed drive, removable media, or a network share, including volume serial number and share path where applicable
- A single Automatic Destinations file can hold **up to roughly 2,000 entries** per application before older entries age out.
- Entries are maintained in **MRU (most-recently-used) order**, and each entry individually carries its own access-order position — so beyond the file-level Creation/Modification timestamps (next section), the *internal* ordering of streams tells you the relative recency of each item within that app's history, even without an absolute timestamp on every single stream.

## Timestamp Semantics

The two headline timestamps live on the **Jump List file itself** (its own filesystem `$STANDARD_INFORMATION` metadata) — they describe the *list's* history, not necessarily an exact copy of the target file's own timestamps embedded inside it.

| Timestamp (on the Jump List file) | Meaning |
|---|---|
| **Creation Time** | The first time an item was ever added to this application's Automatic Destinations file — in practice, the first time this application opened that class of object under Windows shell integration. Functionally: first-ever recorded use. |
| **Modification Time** | The last time an item was added or the list was updated — in practice, the most recent time the application opened an object through shell integration. Functionally: most-recent recorded use. |

🔴 **Do not conflate these with the target file's own timestamps.** The Jump List file's Creation/Modification times describe when *the Jump List itself* was created and last updated — they answer "when did this app first/last touch something," not "when was the target document itself created or modified." The target's own timestamps travel separately, embedded in each LNK-style stream (previous section), and can and do diverge from the Jump List file's own dates.

## Forensic Value for Program Execution

For this note's angle — application execution, not file-access history — the single most useful fact about a Jump List is often the simplest one: **its existence.** Windows only creates an Automatic Destinations file for an AppID once that application has been used through the shell's Jump List mechanism, so finding a Jump List file for a given AppID is itself evidence the associated application ran on this host, under this user account, at least once — independent of what's inside it.

🔴 **Absence is not proof of non-execution.** Several legitimate execution paths never touch the Jump List mechanism at all:

- **Portable/non-installed applications** that don't register properly with the shell may never generate a Jump List, even after repeated use.
- **Command-line-launched executables** — run from a shell, a script, a scheduled task, or a remote-execution tool without ever going through Explorer/taskbar interaction — typically bypass Jump List creation entirely, since the mechanism is driven by shell-integrated launches and file-open dialogs, not by process creation itself.
- An application that has genuinely never been opened via the shell (only ever invoked programmatically) can run for months without a Jump List ever appearing.

This makes Jump Lists strong corroborating evidence when present, but a poor artifact to lean on for a negative finding ("this never ran") — pair an absence with Prefetch, ShimCache, Amcache, or BAM/DAM before asserting non-execution.

### PowerShell

Group both destination folders by AppID (BaseName) so the presence check above becomes a per-application timeline anchor; note what this output can and cannot tell you:

```powershell
Get-ChildItem "$env:AppData\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms",
              "$env:AppData\Microsoft\Windows\Recent\CustomDestinations\*.customDestinations-ms" |
    Group-Object BaseName | Select-Object Name, Count, @{N='LatestActivity'; E={ ($_.Group.LastWriteTime | Sort-Object -Descending)[0] }}
```

🔴 **This is filename/AppID/filesystem-timestamp correlation only.** PowerShell can tell you an AppID file exists, when it was first/last written, and its size — it cannot open the OLE/Compound File container to read a single embedded target path, target timestamp, or access-order position. Full internal LNK-target parsing requires JLECmd (below); treat everything above as a triage layer that tells you *which* AppID files deserve a JLECmd pass, not a substitute for running one.

To sweep a specific AppID across every profile on a remote host, export for pivoting, then hand the collected files to JLECmd as an outer harness from the same PowerShell session:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms' -ErrorAction SilentlyContinue |
        Select-Object @{N='ComputerName'; E={ $env:COMPUTERNAME }},
                      @{N='User'; E={ ($_.FullName -split '\\')[2] }},
                      Name, CreationTime, LastWriteTime, Length
} | Export-Csv C:\hunt\jumplist_sweep.csv -NoTypeInformation

# Call operator hands the collected files to JLECmd for the actual OLE/LNK parse - PowerShell
# is the collection/orchestration harness here, not the parser
& 'C:\Tools\JLECmd\JLECmd.exe' -d "$env:AppData\Microsoft\Windows\Recent\AutomaticDestinations" --csv C:\hunt\jlecmd_out
```

## Tooling

| Tool | Use |
|---|---|
| **JLECmd** (Eric Zimmerman) | Primary parser — decodes the AppID (with lookup-list support), unpacks the OLE/CFB container, extracts every embedded LNK-style stream, and outputs structured CSV/table data including target path, target timestamps, file size, volume/origin info, and the Jump List file's own Creation/Modification timestamps |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Jump List exists for an AppID tied to known-malicious or attacker tooling | Strong evidence that application ran under shell integration at least once on this user's profile — corroborate with Prefetch/ShimCache/Amcache/BAM-DAM for a fuller execution picture |
| No Jump List for an application otherwise confirmed to have run (via Prefetch/Amcache/BAM-DAM) | Consistent with a portable app, command-line/scripted launch, or remote execution that never touched the shell — not evidence the app didn't run |
| AppID for a well-known application doesn't match the AppID expected for its standard install path | Possible non-standard install location — worth checking whether the binary ran from an unexpected directory (staged payload, portable copy, DLL-hijack-style relocation) |
| Jump List file's Modification Time falls squarely inside the incident window for an application not otherwise tied to the user's normal workflow | Recent, active use of that application during the relevant timeframe — cross-check embedded stream target paths for what specifically was opened |
| Custom Destinations content inconsistent with the application's known legitimate behavior | Possible tampering or a repurposed/spoofed application masquerading under a legitimate AppID — verify against the app's genuine Custom Destinations format |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Full cross-artifact "evidence of execution" comparison across all 8 artifacts in this family | **Prefetch** (same folder) |
| Execution-count/run-time corroboration, per-server default-enabled behavior | **Prefetch** |
| "Presence ≠ execution" caveat and rolling-cache mechanics for a different angle on file presence | **ShimCache (AppCompatCache)** |
| Executable-metadata-rich alternative with SHA-1 hash, install path, publisher | **Amcache** |
| Per-second-resolution recent-execution timestamps from the power-management subsystem | **BAM-DAM** |
| GUI-driven program execution counts and last-run times tracked per user in the registry | **UserAssist** |
| The file-access-history angle of this same artifact — which files a user opened, LNK shell-item format in depth, and the sibling MRU/shellbag artifacts | **File and Folder Opening (User Activity)** (note 07 — forward reference, not yet written) |
| Deliberate persistence mechanisms whose execution a Jump List might corroborate | **Persistence Mechanisms** (note 10 series) |

## Resources

- Eric Zimmerman's tools (JLECmd) — https://ericzimmerman.github.io/
- Publicly maintained AppID-to-application mapping lists (community-maintained, commonly distributed alongside the Eric Zimmerman tool ecosystem) — verify current location before relying on any single link
- SANS FOR500 poster, "Windows Artifact Analysis: Evidence of… Application Execution" and "Evidence of… File and Folder Opening" panels — coverage checklist for path/AppID/timestamp facts, rewritten in this note's own words
- SANS FOR500 course syllabus (public) — Jump Lists coverage checklist
