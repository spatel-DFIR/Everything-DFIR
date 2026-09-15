# `hunt_lnk.ps1` — Windows LNK (shortcut) DFIR triage

Read-only sweep and forensic deep-dive of Windows `.lnk` shortcut files, in the same house
style as [`hunt_persistence.sh`](<../../macOS/scripts/hunt_persistence.sh>) (macOS) and
[`hunt_intrusion.sh`](<../../Linux/scripts/hunt_intrusion/hunt_intrusion.sh>) (Linux):
evidence-weighted scoring, `[HIGH]`/`[NOTABLE]` tiers, and **flag on evidence, enumerate
everything else.**

- **Script:** [`hunt_lnk.ps1`](hunt_lnk.ps1) · **version:** 1.5 · **author:** Suvas Patel

`hunt_lnk.ps1` replaces two legacy ad hoc snippets — a bulk suspicious-LNK sweep and a single
hardcoded LNK property dumper — with one tool.

---

## 1. Why this exists

LNK files are a persistent DFIR blind spot: Windows Explorer hides the `.lnk` extension by
default, `WScript.Shell` COM only exposes the "human" shortcut properties (target, arguments,
icon…), and the two legacy snippets this replaces had five real bugs (silent no-op on zero
matches, per-iteration COM object churn with no cleanup, single-directory scope, bare substring
"suspicious process" matching, and swallow-everything `catch {}`). None of that is safe to run
unattended against a live host during incident response.

## 2. Safety contract

- **Read-only / non-destructive.** Only reads: file listings, shortcut COM properties
  (`.TargetPath`, `.Arguments`, etc. — never `.Save()` or any other COM **write** method),
  and raw shortcut bytes (`[System.IO.File]::ReadAllBytes`, never written back). Nothing is
  written, moved, deleted, or renamed on the host.
- **Console-only by default.** Default output is to console only (no files left behind). Optional
  CSV export via `-OutFile` (opt-in, full forensic field set). JSON export not supported.
- **RTR-safe.** Designed to run via EDR Real-Time Response (or any other live-response shell)
  on a host you cannot disturb. Single self-contained `.ps1`, PowerShell 5.1 compatible (no
  PS7-only syntax).
- **No elevation required.** Traversing other users' profiles under `C:\Users` typically needs
  elevation; if not running elevated, the script prints a warning banner and tracks every
  access-denied path it skipped — it degrades coverage visibly rather than silently reporting
  a host clean when large parts of it were never read. Known-folder redirection junctions
  (`Cookies`, `SendTo`, `Recent`, `Local Settings`, etc.) are excluded from that tally — they
  deny directory listing by OS design regardless of privilege, so they aren't a real coverage
  gap and would otherwise pad the count on every profile scanned.

---

## 3. The scoring engine

Every `.lnk` gets a fresh evidence accumulator (mirrors the bash tools' `ev()` pattern). Each
condition that fires adds weighted evidence (deduplicated by reason tag); the total decides the
tier: **`HIGH` ≥ 5**, **`NOTABLE` ≥ 3**, else clean (enumerated, never queued as an anomaly).

| Evidence | Weight | Condition |
|---|--:|---|
| `LOLBIN-PAYLOAD` | 5 | Target is a LOLBin/interpreter **and** arguments contain an encoded/obfuscated/download marker |
| `DOUBLE-EXT-MASQUERADE` | 4 | The LNK's own display name still ends in a document/media extension (`Invoice.pdf.lnk` displays as `Invoice.pdf`) |
| `LOLBIN-TARGET` | 2 | Target is a LOLBin/interpreter, **without** a payload marker in args (weaker alone — below the `NOTABLE` threshold by itself; a bare shortcut to `cmd.exe`/`powershell.exe` is the norm on every stock Windows profile, so it only promotes to `NOTABLE` when stacked with another evidence item) |
| `DANGLING-TARGET` | 3 | Target path is non-empty but the file does not exist on disk right now |
| `ICON-SPOOF-SUSPECTED` | 2 | Target is a LOLBin **and** `IconLocation` is set to something other than that binary's own icon |
| `SUSPICIOUS-PATH` | 2 | Target or working directory lives in `%TEMP%`/`\AppData\Local\Temp`, a hidden/dot-prefixed folder, or a non-standard install path (drive root, `\Users\Public\`, `\ProgramData\` root) |
| `RECENT` | 2 | LNK's `LastWriteTime` falls inside the incident window (`-Since`/`-Days`) — modifier only, never promotes alone |
| name-mismatch (`lnkName != targetName`) | **0** | Shown as context, never scored |

**Why name-mismatch was demoted to context-only.** The naive `$lnkName -ne $targetName` check
from the legacy snippet fires on almost every legitimate shortcut — `Google Chrome.lnk` →
`chrome.exe`, `Notepad++.lnk` → `notepad++.exe`, every Start Menu entry ever created by an
installer. As a standalone signal it is noise, not evidence: scoring it would make the anomaly
queue mostly legitimate software. It is still printed with every finding (flagged or clean) as
a one-line note, because it's genuinely useful *context* once something else has already earned
its way into the queue — but it can never by itself turn a shortcut into a finding.

**LOLBin/interpreter list:** `cmd`, `cmd.exe`, `powershell`, `powershell_ise`, `pwsh`,
`wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `forfiles`,
`msiexec`, `msbuild`, `installutil`, `regasm`, `regsvcs`, `cmstp`, `wmic`. Matching is done
against the target's **leaf executable filename**, case-insensitive, with and without
extension — never a bare substring match (the legacy snippet's `-match 'cmd'` matched
`cmder.lnk` and a username like `cmdavis`; that bug is fixed here).

**Encoded/obfuscated/download markers** (any of): `-enc`, `-EncodedCommand`,
`FromBase64String`, `IEX`, `Invoke-Expression`, `DownloadString`, `DownloadFile`,
`http://`/`https://`, or a hidden-window flag (`-w hidden` / `-windowstyle hidden` / `-nop` /
`-noprofile`) **stacked with** a URL or a long base64-looking blob.

---

## 4. Modes

### Default (sweep)

Recursively scans:

| Root | Scope |
|---|---|
| `C:\Users` | every local user profile (needs elevation for full coverage) |
| `%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp` | all-users Startup — real LNK persistence location |
| root of every removable drive (`Win32_LogicalDisk` `DriveType=2`) | **non-recursive**, root only — classic USB-worm LNK pattern |
| any `-Path` value(s) | added to the scan scope (see [`-Path` semantics](#path-semantics) below) |

Prints flagged items grouped `[HIGH]` then `[NOTABLE]`, then a compact enumeration of every
other shortcut found (clean, not scored), then unreadable/parse-failure and access-denied
summaries, then a tally.

### Deep-dive (`-Path <single .lnk file>`)

Prints everything a sweep item would show, in full, for one file: `TargetPath`, `Arguments`,
`WorkingDirectory`, `Description`, `Hotkey`, `IconLocation`, `WindowStyle` — plus the complete
[MS-SHLLINK forensic metadata](#5-ms-shllink-forensic-metadata) and the scoring verdict.

### `-Path` semantics

- **Exactly one path, and it's an existing single `.lnk` file** → deep-dive mode.
- **Anything else** (one or more directories, or multiple files) → each existing directory is
  added to the sweep scope **recursively** (e.g. to point at a mounted/offline profile or a
  specific removable drive), and each existing individual `.lnk` file is added directly to the
  sweep's candidate list. `-Path` is **additive** to the default scope, not a replacement for
  it.

---

## 5. MS-SHLLINK forensic metadata

`WScript.Shell` COM only exposes the "human" shortcut properties. It does **not** expose the
binary header fields or the tracker block, so `hunt_lnk.ps1` reads the raw `.lnk` bytes
directly (`Get-ShellLinkForensicData`), per the [MS-SHLLINK](https://learn.microsoft.com/openspecs/windows_protocols/ms-shllink/)
spec, defensively — every read is bounds-checked and any parse failure returns a descriptive
`N/A`/error note instead of throwing, so a malformed or corrupted LNK can never crash a sweep.

| Field | Source | DFIR value | Limits |
|---|---|---|---|
| **Header CreationTime / AccessTime / WriteTime** | `ShellLinkHeader` FILETIME fields | The LNK-**embedded** timestamps at the moment the shortcut was created — cross-check against the file's own filesystem `LastWriteTime`. A mismatch (e.g. header creation time far newer/older than the filesystem mtime) can indicate the file was copied, replayed, or its filesystem timestamps were tampered with independently of the shortcut's own record. | A zero FILETIME means the field was never set (shown as `N/A (unset)`) — common and not itself suspicious. |
| **DriveSerialNumber** | `LinkInfo` VolumeID (only present if `HasLinkInfo`) | The 8-hex-digit volume serial number of the drive the **target** lived on when the shortcut was made (`vol`-style `XXXX-XXXX` format) — ties a shortcut to a specific physical/removable volume, useful for correlating USB media across hosts or confirming a shortcut was made from a specific drive. | Only present when the LNK has a `LinkInfo` structure at all (`HasLinkInfo` flag) — shown as `N/A` otherwise. Doesn't identify the *machine*, only the *volume*. |
| **MachineID** | `TrackerDataBlock` (ExtraData, signature `0xA0000003`) | The **NetBIOS computer name** of the machine that created or last saved the LNK — real forensic value in lateral-movement and USB-delivery cases (a shortcut recovered on host B whose MachineID says host A places host A in the chain). | Many modern Windows LNKs (especially those created by newer Office/Explorer versions, or deliberately stripped by an attacker) have **no** TrackerDataBlock at all — reported as `MachineID: N/A`, which is a normal, expected outcome, not a parse error. |
| **MAC** | `TrackerDataBlock` → `DroidFileID` GUID, node field | The **NIC MAC address** of the machine that created the LNK, recovered from a version-1 (time-based) GUID's embedded node ID — same provenance value as MachineID, from an independent field. | Only recoverable when a TrackerDataBlock exists **and** its `DroidFileID` is a version-1 GUID. Modern Windows generates version-4 (random) GUIDs by default, so most current LNKs report `MAC: N/A (non-time-based GUID)` — this field is most useful on artifacts from older Windows versions or certain authoring tools. |
| **DroidVolumeID / DroidFileID / DroidBirthVolumeID / DroidBirthFileID** | `TrackerDataBlock` | Raw GUIDs identifying the target file/volume at creation time and at "birth" (original creation, before any copies). The **Birth** variants persist across file copies — if a file has been copied from system to system, the Birth droid still points at the *original* volume/file identity, which the "live" droid does not. | Informational/correlation fields — most useful when comparing multiple LNKs or cross-referencing against other NTFS object-ID artifacts, not meaningful in isolation. |
| **MFT Entry / Sequence** | `LinkTargetIDList` → terminal shell item's `FileEntryExtensionBlock` (signature `0xBEEF0004`) | The target's **NTFS MFT record number and sequence number**, embedded at shortcut-creation time. LECmd-parity feature: survives the target file being deleted, renamed, or moved — the strongest available "this file existed here" evidence when the target is already gone. | Verified against `LECmd` ground truth on a real Windows 10 host — offset was validated against a known good file before deployment. Verified against one host/file, not a broad corpus, and this shell item extension layout isn't officially documented by Microsoft — cross-verify with `LECmd` before citing in a report. Only present at all when the extension version is Windows-7+ (older LNKs show a note instead of a value). |
| **EnvVar target** | `EnvironmentVariableDataBlock` (`0xA0000001`) | The target path **as originally written, with environment variables unexpanded** (e.g. `%TEMP%\x.exe`). Can differ from COM's `TargetPath`, which reports the expanded form. | Only present if the shortcut was authored with an unexpanded env-var target. |
| **Icon env path** | `IconEnvironmentDataBlock` (`0xA0000007`) | Same idea, for the icon path. | Same caveat as above. |
| **Darwin/App ID** | `DarwinDataBlock` (`0xA0000006`) | Application ID for MSI-installed or Store-packaged apps — attributes a shortcut to a specific installed application package. | Only present for MSI/Store-sourced shortcuts. |
| **Shim layer** | `ShimDataBlock` (`0xA0000008`) | Names an application compatibility shim layer applied when the target runs. Forensically notable: shim layers (e.g. `RedirectEXE`) have been abused for persistence and defense evasion. | Rare in practice — most shortcuts have no shim block at all. |
| **KnownFolder** | `KnownFolderDataBlock` (`0xA000000B`) | The `KNOWNFOLDERID` GUID the target resolves through, decoded to a friendly name via a local lookup table (Startup, Desktop, Downloads, AppData, etc. — the folders most relevant to persistence/execution triage). | The lookup table covers ~15 common folders, not the full ~80 defined `KNOWNFOLDERID`s — an unmapped GUID prints as the raw GUID with a note, never a guessed name. |
| **Other ExtraData blocks** | Any `ExtraDataBlock` signature not decoded above (`ConsoleDataBlock`, `PropertyStoreDataBlock`, `VistaAndAboveIDListDataBlock`, or any signature this parser doesn't recognize) | Nothing is silently dropped — every block present is at least named (or shown as a raw signature) with its size, so an analyst knows there's more to inspect manually even where this tool doesn't fully decode it. | Not decoded further; `PropertyStoreDataBlock` in particular can carry an `AppUserModelID` of interest for pinned-taskbar/jump-list attribution, but full serialized-property-store parsing was out of scope. |

**Report locations:** the full forensic block (all fields above) is always printed in
deep-dive (`-Path <file>`) output, and in a sweep under `-Detail` for `[HIGH]`/`[NOTABLE]`
items (`[HIGH]` items always get full detail regardless of `-Detail`). Every field is also
available per-item in the `-OutFile` CSV export regardless of `-Detail`, for an analyst who
wants to review the raw parsed data directly rather than through the console tiering.

---

## 6. Quick start

```powershell
# Default sweep: C:\Users, all-users Startup, and every removable drive's root
.\hunt_lnk.ps1

# Deep-dive a single suspect shortcut -- full COM properties + MS-SHLLINK metadata
.\hunt_lnk.ps1 -Path 'D:\Badmark\2020-05-20.txt.lnk'

# Scope an additional sweep root to one removable drive (in addition to the default scope)
.\hunt_lnk.ps1 -Path 'E:\'

# Sweep with an incident window -- feeds the RECENT modifier, and only show HIGH/NOTABLE
.\hunt_lnk.ps1 -Since 2026-07-01 -MinSeverity notable

# Also SHA-256 the resolved target of every flagged item
.\hunt_lnk.ps1 -Hash

# Point the sweep at a mounted/offline profile in addition to the default scope
.\hunt_lnk.ps1 -Path 'F:\Users\jdoe'

# Full verbose console output (every HIGH/NOTABLE gets a full forensic block, clean list in full)
.\hunt_lnk.ps1 -Detail

# Short console output plus a full CSV export for an analyst to review raw in Timeline Explorer
.\hunt_lnk.ps1 -OutFile C:\triage\lnk_findings.csv -Hash
```

---

## 7. Options

| Option | Effect |
|---|---|
| `-Path <string[]>` | See [`-Path` semantics](#path-semantics): single `.lnk` file → deep-dive; directories/files → added to the sweep scope |
| `-Since <YYYY-MM-DD>` | Incident window start — feeds the `RECENT` evidence modifier |
| `-Days <N>` | Incident window as "last N days" — ignored if `-Since` is given |
| `-MinSeverity high\|notable\|low` | Filters which tiers print in the flagged-anomaly queue (default `low`). This tool has only two scored anomaly tiers (`HIGH`/`NOTABLE`) — `low` behaves the same as the default (both shown); `high` hides `NOTABLE`. |
| `-Hash` | Also SHA-256 the resolved target file of flagged items (and the deep-dive target). Off by default; skipped gracefully if the target is missing. |
| `-Detail` | Verbose evidence mode. Without it, `[HIGH]`/`[NOTABLE]` entries print as one summary line each and the clean-item list collapses to a count — the default output is meant to be short. With it, every `[HIGH]`/`[NOTABLE]` entry gets the full COM-property + MS-SHLLINK forensic detail block, and the clean-item list prints in full. `[HIGH]` items always print full detail regardless of this switch; deep-dive mode always prints full detail regardless of this switch. (Named `-Detail`, not `-Debug` — PowerShell reserves `-Debug` as a built-in common parameter.) |
| `-OutFile <path>` | Optional CSV export. Off by default — console-only stays the default. When given, every HIGH/NOTABLE/clean item is (re-)parsed for its full forensic field set (MFT entry/sequence, tracker MAC/MachineID, every decoded ExtraDataBlock field, etc., regardless of `-Detail`) and written one row per item, for pivoting in Timeline Explorer / a SIEM / a case file. A write failure (bad path, permissions) prints a warning without aborting the console output. |
| `-Help` | Full comment-based help (`Get-Help`-style) |

Coverage is always full within the scanned scope — every `.lnk` found is scanned regardless of
`-MinSeverity`; that option only filters what gets **printed** in the anomaly queue. All
timestamps are shown in UTC.

---

## 8. Reading a finding

```
[HIGH] File             : C:\Users\jdoe\Desktop\Invoice.pdf.lnk
   Target           : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   Arguments        : -w hidden -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...
   WorkingDirectory : C:\Users\jdoe\AppData\Local\Temp
   WindowStyle      : 7 (Minimized)
   LNK LastWriteTime (filesystem) : 2026-07-28 14:02:11 UTC
   Header CreationTime : 2026-07-28 14:02:10 UTC
   Header AccessTime   : 2026-07-28 14:02:11 UTC
   Header WriteTime    : 2026-07-28 14:02:11 UTC
   DriveSerialNumber   : 1A2B-3C4D
   MachineID (tracker) : N/A
   MAC (tracker)       : N/A (no tracker block)
   DroidVolumeID       : N/A
   DroidFileID         : N/A
   DroidBirthVolumeID  : N/A
   DroidBirthFileID    : N/A
   Score / Tier     : 9 / HIGH
   Evidence         : LOLBIN-PAYLOAD, DOUBLE-EXT-MASQUERADE, SUSPICIOUS-PATH
```

Here `LOLBIN-PAYLOAD` (5, PowerShell + hidden window + `-enc` + a base64 blob) stacks with
`DOUBLE-EXT-MASQUERADE` (4, the file displays as `Invoice.pdf` but is really a `.lnk`) and
`SUSPICIOUS-PATH` (2, working directory is `%TEMP%`) for a total of 11 — comfortably `HIGH`.
No TrackerDataBlock was present, so MachineID/MAC/Droid fields correctly report `N/A` rather
than guessing.


