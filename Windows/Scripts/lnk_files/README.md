# `hunt_lnk.ps1` — Windows LNK (shortcut) DFIR triage

Read-only sweep and forensic deep-dive of Windows `.lnk` shortcut files, in the same house
style as [`hunt_persistence.sh`](<../../macOS/scripts/hunt_persistence.sh>) (macOS) and
[`hunt_intrusion.sh`](<../../Linux/scripts/hunt_intrusion/hunt_intrusion.sh>) (Linux):
evidence-weighted scoring, `[HIGH]`/`[NOTABLE]` tiers, and **flag on evidence, enumerate
everything else.**

- **Script:** [`hunt_lnk.ps1`](hunt_lnk.ps1) · **version:** 1.5 · **author:** Suvas Patel

`hunt_lnk.ps1` replaces two legacy ad hoc snippets — a bulk suspicious-LNK sweep and a single
hardcoded LNK property dumper — with one tool. See the [changelog](#changelog) for the exact
bug list fixed in the rewrite.

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
| **MFT Entry / Sequence** | `LinkTargetIDList` → terminal shell item's `FileEntryExtensionBlock` (signature `0xBEEF0004`) | The target's **NTFS MFT record number and sequence number**, embedded at shortcut-creation time. LECmd-parity feature: survives the target file being deleted, renamed, or moved — the strongest available "this file existed here" evidence when the target is already gone. | Offset verified against `LECmd` ground truth on a real Windows 10 host (v1.3) — the v1.2 offset was off by 2 bytes and silently produced a shifted, wrong value with the sequence number always reading `0`; see the changelog. Verified against one host/file, not a broad corpus, and this shell item extension layout isn't officially documented by Microsoft — cross-verify with `LECmd` before citing in a report. Only present at all when the extension version is Windows-7+ (older LNKs show a note instead of a value). |
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

---

## 9. Validation checklist

Run these on a disposable lab host/VM — **never on a production or client machine.** Remove
every planted artifact afterward.

| Plant (lab only) | Expect |
|---|---|
| Create a shortcut to `powershell.exe` with argument `-w hidden -nop -enc <base64 blob>` | `[HIGH] LOLBIN-PAYLOAD` fires |
| Rename any `.lnk` so it ends in `.pdf.lnk` (e.g. `report.pdf.lnk`) | `DOUBLE-EXT-MASQUERADE` fires |
| Point a shortcut's target at a file, then delete that target file | `DANGLING-TARGET` fires |
| Create a shortcut to `cmd.exe` with a custom `IconLocation` (e.g. `shell32.dll,-16`) | `ICON-SPOOF-SUSPECTED` fires (only when the target is also a LOLBin) |
| Point a shortcut's target/working directory at `%TEMP%` | `SUSPICIOUS-PATH` fires |
| Touch a `.lnk`'s `LastWriteTime` inside an `-Since`/`-Days` window | `RECENT` appears as a modifier (does not promote a tier alone) |
| Run `-Path <that single .lnk>` on any planted file | Deep-dive prints full COM properties + MS-SHLLINK metadata + the same score/tier |
| Run the default sweep as a non-admin user | Warning banner prints; other users' profiles under `C:\Users` show up in the access-denied summary, not silently as "clean" |
| Run against a directory with **zero** `.lnk` files | Prints `0 .lnk files found` and a full `0 HIGH · 0 NOTABLE` tally — never a silent no-op (the bug in the legacy snippet) |
| Run `-Help` | Full comment-based help prints |
| Create any shortcut on a real Windows host and deep-dive it (`-Path <that .lnk>`) | `MachineID`/`MAC`/Droid GUID fields populate from the real `TrackerDataBlock` (post-v1.2 signature-comparison fix) rather than reporting `N/A` on a LNK that actually has one |
| Run `-OutFile <path>.csv` on any sweep | CSV is written with one row per HIGH/NOTABLE/clean item and the full forensic field set; deleting/renaming the CSV path's parent directory first should print a warning, not abort the console output |

---

## 10. Changelog

- **v1.0** — Initial professional rewrite. Folds both legacy snippets (the bulk suspicious-LNK
  sweep and the single hardcoded LNK property dumper) into one tool. Fixed five bugs from the
  originals: (1) `Test-Path` on a collection silently no-op'd a zero-match scan — replaced with
  proper array-count checks; (2) a new `WScript.Shell` COM object was created on every loop
  iteration with nothing ever released — now created once, shortcuts released per-iteration via
  `Marshal.ReleaseComObject`, the shell released and `[GC]::Collect()` run once at the end;
  (3) scope was `C:\Users\` only — added the all-users Startup folder, non-recursive removable
  drive roots, and an operator-extensible `-Path`; (4) bare substring "suspicious process"
  matching false-matched inside unrelated strings (`cmd` in `cmder.lnk`) — replaced with
  exact leaf-filename matching against a real LOLBin list (dropped `VBScript`, not an
  executable); (5) bare `catch {}` swallowed every failure — every unreadable/unparseable file
  is now counted and listed in a summary, never silently dropped. Replaced the standalone
  `lnkName != targetName` heuristic (near-universal false positive on legitimate shortcuts)
  with a real evidence-weighted scoring engine (`HIGH` ≥ 5, `NOTABLE` ≥ 3) and demoted
  name-mismatch to informational-only context. Added a dedicated MS-SHLLINK binary parser
  (`Get-ShellLinkForensicData`) surfacing header timestamps, volume serial number, and
  tracker-block MachineID/MAC/Droid GUIDs — fields `WScript.Shell` COM never exposes. Read-only,
  console-only, RTR-safe; no elevation required, degrades gracefully with an access-denied
  summary.

- **v1.1** — Noise reduction, based on real default-sweep runs producing 1000+ line outputs.
  `LOLBIN-TARGET` weight dropped from 3 to 2 (below the `NOTABLE` threshold alone) — a bare
  shortcut to `cmd.exe`/`powershell.exe` with no arguments is the norm on every stock Windows
  profile and was previously flagging dozens of default WinX/Start Menu shortcuts as `NOTABLE`
  on every host. Known-folder redirection junctions (`Cookies`, `SendTo`, `Recent`, `Local
  Settings`, etc.) are now excluded from the access-denied tally — they deny listing by OS
  design regardless of privilege, not a real coverage gap. Added `-Detail`: default sweep output
  now prints `[HIGH]`/`[NOTABLE]` as one-line summaries and collapses the clean-item list to a
  count; `-Detail` restores full per-item forensic blocks. On one real 254-shortcut host sweep,
  this took output from 1170 lines / 43 false-positive-heavy `NOTABLE` findings down to 51 lines
  / 11 genuinely worth reviewing.

- **v1.2** — "PRO" forensic-completeness pass, plus a critical bug fix found while building it.
  **Bug fix:** `ExtraDataBlock` signature comparisons (`$blockSig -eq 0xA0000003` etc.) never
  matched, because PowerShell parses a bare hex literal above `0x7FFFFFFF` as a negative `Int32`
  and compares it against the `UInt32` block signature by numeric *value*, not bit pattern —
  `2684354563 -eq -1610612733` is always false. This meant `TrackerDataBlock` detection
  (MachineID/MAC/Droid GUIDs) silently never fired in v1.0/v1.1, on any LNK, ever — every
  `MAC: N/A (no tracker block)` reported by earlier versions could have been a false negative on
  a real tracker block. Fixed by routing every signature comparison through
  `$LnkExtraDataSignatures`, built with `[Convert]::ToUInt32(...,16)` instead of bare literals.
  Caught by a synthetic-bytes integration test (`Get-ShellLinkForensicData` against a
  hand-built LNK with a known tracker block) before this reached a real host — see the test
  methodology note below.
  **New parsing:** `LinkTargetIDList` shell items are now walked for the terminal item's
  embedded MFT entry/sequence number (LECmd-parity feature, survives target deletion — see the
  best-effort caveat in §5). `EnvironmentVariableDataBlock`, `SpecialFolderDataBlock`,
  `DarwinDataBlock`, `IconEnvironmentDataBlock`, and `ShimDataBlock` are now decoded;
  `ConsoleDataBlock`/`ConsoleFEDataBlock`/`PropertyStoreDataBlock`/`VistaAndAboveIDListDataBlock`
  and any unrecognized signature are now surfaced by name/signature and size rather than
  silently skipped past.
  **New export:** `-OutFile <path>` writes a CSV of every sweep item with the full forensic
  field set, opt-in only — console-only remains the default.
  **Testing methodology:** the shell-item MFT parser and the full `Get-ShellLinkForensicData`
  pipeline (LinkInfo, LinkTargetIDList, every ExtraDataBlock type) were each verified against
  hand-built synthetic MS-SHLLINK byte blobs with known expected values before being wired into
  the tool — this repo has no Windows host to generate real LNKs against, so correctness here
  rested on construction-level verification, not a real-corpus test, going into v1.2. That gap
  caught a real offset bug the same day — see v1.3.

- **v1.3** — Fixed the MFT entry/sequence offset. On a real host run, v1.2's MFT Entry/Sequence
  output was implausible on inspection (every value a round multiple of `0x10000`, sequence
  always `0`) — a real-corpus red flag a synthetic-bytes test alone couldn't have caught, since
  a self-consistent encode/decode pair validates internal logic but not the offset's correctness
  against real Windows-authored files. Cross-checked one of the flagged files against `LECmd`
  ground truth (`chrome.exe`: LECmd reported MFT entry/sequence `240658/3` /
  `0x3AC12/0x3`; this tool reported `0x3AC120000/0x0` — exactly `0x3AC12` shifted left 16 bits
  with the sequence byte dropped off the end of the read window). That's the signature of a
  2-byte-early read offset, not random corruption. Corrected `Get-ShellItemFileReference`'s
  `FileReference` offset from `blockStart+18` to `blockStart+20` and re-verified against the
  same LECmd output (now matches exactly). The offset is now verified against one real host, not
  a broad corpus — still cross-verify with `LECmd` before citing in a report.

- **v1.4** — Robustness pass, prompted by two questions: "don't hardcode logic — this runs on
  hosts we don't control" and a request for a best-practices/dead-code audit. Findings and
  fixes:
  **Hardcoded scan path:** the user-profile sweep root was a literal `C:\Users` rather than
  derived from `$env:SystemDrive` — on a host where Windows is installed on a non-`C:` drive
  (rare but real, e.g. some VDI/imaging setups), this would silently scan nothing while
  reporting success. Now resolved via `Join-Path $env:SystemDrive 'Users'`, matching the
  all-users Startup path's existing `$env:ProgramData`-based resolution. (Everything else
  flagged as a candidate — the LOLBin list, `KNOWNFOLDERID` GUIDs, ExtraDataBlock signatures —
  is legitimate fixed reference/spec data, not a host-specific assumption, and was left as-is.)
  **Unguarded `WScript.Shell` COM creation:** neither the sweep nor deep-dive mode caught a COM
  creation failure — if WSH is disabled by policy/AppLocker/WDAC (a real hardening control on a
  host already under incident response, not hypothetical), the whole run died with an unhandled
  exception. Now wrapped in try/catch on both paths; on failure the sweep reports every
  candidate as unreadable with a clear reason and still completes, and deep-dive still reports
  the (COM-independent) MS-SHLLINK binary forensic data even without shortcut properties.
  **Unguarded `Get-Item` in deep-dive:** could return `$null` into a function with a `Mandatory`
  `[System.IO.FileInfo]` parameter, which in an interactive host means PowerShell **prompts for
  input** — a real hang under RTR, which has no stdin. Now wrapped in try/catch with a clean
  early exit.
  **No upper file-size bound before `ReadAllBytes`:** a multi-GB file renamed to `.lnk` and
  dropped into any scanned location (a user profile, Startup, a removable-drive root — all
  attacker-writable) would be fully buffered into memory. Added a 5MB ceiling (generous for a
  real LNK, which is a few KB) with a graceful `ParseError` skip above it.
  **`Test-DanglingTarget` probing UNC targets:** `Test-Path` on an unreachable `\\host\share`
  target blocks for the OS's SMB connection-timeout; a handful of crafted shortcuts pointing at
  dead hosts could stall a routine sweep. UNC targets are now skipped (reported as not dangling
  rather than risking a hang to find out).
  **Minor:** deduplicated the three near-identical COM-property-object constructions into one
  `Get-LnkComProperties` helper; fixed a stale `C:\Users` reference in the `-Detail` example
  text. No dead code or unused functions were found in the audit.

- **v1.5** — Size pass for CrowdStrike Falcon RTR's confirmed 40KB script limit. The script had
  grown to ~63KB across the v1.1–v1.4 feature additions. Brought it to <40KB (~37% reduction)
  through comment/docstring/whitespace compaction, 4-space→2-space indentation, denser
  hashtable/object literal formatting, merged `Write-Host` calls, and short internal variable
  names throughout (e.g. `$result`→`$r`, `$bytes`→`$b`, `$ForensicData`→`$fd`) — every rename
  applied to both the declaration and every call site, verified with the synthetic-bytes test
  suite (including the LECmd ground-truth check) plus live end-to-end sweep/deep-dive/CSV runs
  after every round. **Bug found and fixed along the way:** `@($emptyList) + @($emptyList)`
  throws `Argument types do not match` in PowerShell — a latent bug in the `-OutFile` CSV
  export's item-concatenation line since v1.2, caught by this pass's testing and fixed with
  `.AddRange()` instead. No functional behavior changed; console output format, CSV schema, and
  all detection logic are unchanged from v1.4 — verified via output-diffing during the rewrite.
