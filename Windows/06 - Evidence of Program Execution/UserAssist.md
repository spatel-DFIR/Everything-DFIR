# UserAssist

UserAssist is the one member of the "Evidence of Execution" family that isn't really trying to answer "did this program run?" — it's answering "what did the user knowingly click on?" Windows Explorer keeps this data so it can build smarter Start Menu recommendations and jump-list-style "most used" lists; the byproduct is a per-user, per-GUI-click record of what got double-clicked, when, how often, and for how long the resulting window stayed in focus. That last part — focus time — is what makes UserAssist unusually good for *user-intent* questions rather than pure malware-execution questions.

For how UserAssist stacks up against Prefetch, ShimCache, Amcache, and BAM/DAM side by side, see the cross-artifact comparison table in `Prefetch.md` (same folder) — this note only goes deep on UserAssist itself.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [What It Is](#what-it-is)
- [Where It Lives](#where-it-lives)
- [ROT-13: Obfuscation, Not Security](#rot-13-obfuscation-not-security)
- [Fields Recorded](#fields-recorded)
- [Scope Limitation: GUI-Launches Only](#scope-limitation-gui-launches-only)
- [Per-User, Not Per-System](#per-user-not-per-system)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage against the current user's `UserAssist` tree before any parser (Registry Explorer/RECmd) comes out — no third-party modules required. PowerShell reads the raw value names and decodes ROT-13 natively (plain char-shift math); the binary run-count/focus-time payload inside each value's data needs a UserAssist-aware parser and isn't covered by the one-liners below.

```powershell
# ROT13 decoder as a reusable one-liner function - every command below depends on this to turn value names back into paths
function ConvertFrom-Rot13 { param([string]$Text) -join ($Text.ToCharArray() | ForEach-Object { if ($_ -match '[a-zA-Z]') { $base = if ([char]::IsUpper($_)) { 65 } else { 97 }; [char]((([int]$_ - $base + 13) % 26) + $base) } else { $_ } }) }

# Which UserAssist GUID subkeys exist under this profile - confirms both the exe and shortcut categories are present before hunting either
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'

# Decode every value name under the Executable File Execution GUID (.exe launches) - direct double-clicks of a binary
(Get-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count').Property |
    ForEach-Object { [PSCustomObject]@{ Encoded = $_; DecodedPath = ConvertFrom-Rot13 $_ } }

# Decode every value name under the Shortcut File Execution GUID (.lnk launches) - desktop icon/Start Menu/taskbar activity
(Get-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count').Property |
    ForEach-Object { [PSCustomObject]@{ Encoded = $_; DecodedPath = ConvertFrom-Rot13 $_ } }

# Both GUIDs in one pass, flagged where the decoded path lands in Temp/Downloads/AppData - classic malware-staging locations
'{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}', '{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}' | ForEach-Object {
    $guidPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\$_\Count"
    (Get-Item $guidPath -ErrorAction SilentlyContinue).Property | ForEach-Object { ConvertFrom-Rot13 $_ }
} | Where-Object { $_ -match 'Temp\\|Downloads\\|AppData\\Local\\Temp' }

# Entry count per GUID - a lopsided or empty subkey confirms which launch method (direct exe vs. shortcut) was actually used
'{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}', '{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}' | ForEach-Object {
    [PSCustomObject]@{ GUID = $_; ValueCount = (Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\$_\Count" -ErrorAction SilentlyContinue).Property.Count }
}
```

## What It Is

UserAssist is a Windows Explorer feature that logs metadata about programs launched **through the shell** — double-clicking an icon on the desktop, launching from the Start Menu, or clicking a pinned taskbar entry. Explorer keeps this data to power its own "frequently used programs" logic; DFIR inherits it as a durable, per-user record of shell-initiated activity. Unlike ShimCache or Amcache, which are compatibility-subsystem byproducts, UserAssist is squarely an Explorer/shell artifact, and its data lives in the same per-user hive that holds most other shell-activity traces covered elsewhere in this subfolder and in note 07.

## Where It Lives

| Detail | Value |
|---|---|
| Hive | `NTUSER.DAT` (per-user — see Registry Forensics Fundamentals, note 04, for hive structure and offline-vs-live parsing) |
| Key | `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` |

The `{GUID}` layer is the part that trips up analysts unfamiliar with the key: UserAssist isn't one flat list, it's a **set of subkeys, each keyed by a GUID that identifies a category of tracked interaction** (Windows 7 and later). Every GUID subkey has its own `Count` subkey underneath it, and that `Count` subkey is where the actual per-program entries live.

| GUID | Meaning |
|---|---|
| `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}` | Executable File Execution — direct launches of `.exe` files |
| `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}` | Shortcut File Execution — launches via `.lnk` shortcut files (desktop icons, Start Menu tiles, pinned taskbar items) |

🔴 **Check both GUID subkeys, not just one.** A program launched by double-clicking its `.exe` directly in `C:\Program Files\` lands under the Executable File Execution GUID; the same program launched via a desktop shortcut or Start Menu tile lands under the Shortcut File Execution GUID instead. An analyst who only checks one subkey can miss a launch that happened through the other path — treat the two `Count` subkeys as complementary views, not duplicates of each other.

Earlier Windows builds (pre-Win7) used a smaller, differently-organized set of GUIDs; treat the two GUIDs above as the current Win7+ baseline and confirm against your parser's documentation if you're working an older image.

### PowerShell

List the raw (still ROT-13-encoded) value names under each GUID's `Count` subkey, then pull the raw binary value data for one specific entry once you've identified it; this is metadata only, no decode applied yet:

```powershell
# Raw value names under the exe-launch GUID
Get-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count' | Select-Object -ExpandProperty Property

# Raw binary value data (byte array) for one specific encoded value name
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count' -Name '<EncodedValueName>' | Select-Object -ExpandProperty '<EncodedValueName>'
```

## ROT-13: Obfuscation, Not Security

Every value name under a `Count` subkey — which encodes the actual application path — is stored **ROT-13 encoded**: each letter is rotated 13 places through the alphabet (`A`↔`N`, `B`↔`O`, and so on; numbers and symbols are left alone). So a raw value name like `Q:\Cebtenz Svyrf\rivy.rkr` decodes to `D:\Program Files\evil.exe`.

This is not encryption and was never meant to be. ROT-13 is a trivial, publicly-documented substitution cipher with no key — reversing it takes no more effort than applying it in the first place. Microsoft's apparent reasoning was cosmetic: keep raw application paths from staring back at a curious user who stumbles into this key in RegEdit, not to stop a forensic examiner or anything resembling real access control. Every parsing tool covered below decodes this transparently and shows you the plain path — the only reason to know about it at all is so a raw-hive manual inspection (RegEdit, a hex viewer, or a hive export opened without a UserAssist-aware tool) doesn't look like garbage or, worse, get mistaken for an actually-encrypted or corrupted value.

### PowerShell

Use the ROT-13 logic as a native function, applied across every entry under both GUIDs in one pass so encoded names become plain paths:

```powershell
function ConvertFrom-Rot13 { param([string]$Text) -join ($Text.ToCharArray() | ForEach-Object { if ($_ -match '[a-zA-Z]') { $base = if ([char]::IsUpper($_)) { 65 } else { 97 }; [char]((([int]$_ - $base + 13) % 26) + $base) } else { $_ } }) }

'{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}', '{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}' | ForEach-Object {
    $guid = $_
    (Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\$guid\Count" -ErrorAction SilentlyContinue).Property |
        ForEach-Object { [PSCustomObject]@{ GUID = $guid; DecodedPath = ConvertFrom-Rot13 $_ } }
}
```

🔴 **Decoding the name is as far as native PowerShell reliably goes.** Run count, last-run FILETIME, and focus time/count all live inside each value's binary data payload, and this note deliberately doesn't itemize byte-level offsets for that structure the way the Prefetch note does for `.pf` internals — inventing an offset here would risk silently misreading the wrong bytes. Pull the raw bytes with `Get-ItemProperty` (see Basic, above) for manual inspection, but treat Registry Explorer or RECmd (Tooling, below) as the authoritative source for parsed run count/last-run/focus fields.

## Fields Recorded

Per application, the `Count` subkey's binary value data (once ROT-13-decoded on the name and parsed on the value) carries:

| Field | Meaning | Interpretation notes |
|---|---|---|
| Application path | Full path to the launched executable or shortcut target | The ROT-13-decoded value name itself |
| Last run time | Timestamp of the most recent shell-initiated launch | Second-level precision, pulled from the value data, not a file-system approximation |
| Run count | Cumulative number of times this path has been launched via the shell | Increments on every qualifying launch since the entry was created |
| Focus time | Total accumulated time the application's window held foreground focus across all sessions | See below — this is UserAssist's most distinctive field |
| Focus count | Number of times the application's window was brought to the foreground | Complements focus time — a high focus count with low total focus time suggests brief check-ins, not sustained use |

**Why focus time/count matter beyond "did it run":** every other artifact in this family answers some flavor of "did this program execute." Focus time and focus count instead answer "did the user actually *work in* this program, or did they just launch it and move on." A user who double-clicks a suspicious email attachment and immediately closes it produces a UserAssist entry with a low run count and near-zero focus time; a user who opens a file and spends twenty minutes reading or editing it produces the same run count but a large focus-time value. That distinction matters directly for insider-threat and user-intent investigations — "did the employee actually review this exfiltrated spreadsheet, or did it just flash open and close" — in a way plain execution evidence (Prefetch, ShimCache, Amcache) has no way to express, since none of those artifacts track window focus at all.

## Scope Limitation: GUI-Launches Only

> 🔴 **UserAssist ONLY records shell/GUI-initiated launches — it captures nothing else, full stop.** Double-clicking in Explorer, launching from the Start Menu, or clicking a pinned taskbar icon all populate UserAssist. Command-line execution (`cmd.exe`, PowerShell), WMI-triggered process creation, scheduled-task launches, service starts, and any other non-interactive execution path leave **zero** UserAssist trace — not a thin entry, not a partial record, nothing at all. A sophisticated intrusion that never touches Explorer — a PowerShell-delivered payload, a WMI event consumer, a scheduled task run under the SYSTEM account — will show up in Prefetch, ShimCache, Amcache, or BAM/DAM if those artifacts are intact, but **UserAssist will be entirely silent on it**, and that silence proves nothing about whether the program ran. Never treat an absent UserAssist entry as evidence a binary didn't execute; it only tells you the binary wasn't launched through the shell.

This scope limitation is also what makes UserAssist most valuable in a specific, narrower kind of question than the rest of the family. Reach for UserAssist when the question is about **user knowledge and intent** — "did this user knowingly double-click the malicious attachment," "did someone at this desk actually launch the tool sitting on their desktop," "was this program something the user chose to open, or something that launched itself" — rather than the general "did malware run on this host" question the rest of this subfolder is built to answer. For general malware-hunting where the execution path is unknown or likely non-interactive, lean on Prefetch/ShimCache/Amcache/BAM-DAM first and treat UserAssist as a corroborating detail, not a primary hunting artifact.

## Per-User, Not Per-System

Because UserAssist lives inside `NTUSER.DAT` — the per-profile hive, not `SYSTEM` or `SOFTWARE` — it is inherently scoped to a single user account. A multi-user host has one `NTUSER.DAT` (and one full UserAssist tree) per profile that has ever logged on, and an entry in one user's UserAssist tree says nothing about what any other account on the same machine did. This mirrors BAM/DAM's per-SID structure, but where BAM/DAM organizes by SID under a single `SYSTEM`-hive location, UserAssist gets its user separation for free, simply by which `NTUSER.DAT` you're looking at.

Practical implication for multi-user systems: collect and parse **every** profile's `NTUSER.DAT` on a host of interest, not just the account believed to be responsible — a shared workstation, a Terminal Server/RDS host, or a compromised admin account used to pivot between profiles can leave relevant UserAssist evidence under a profile nobody thought to check first. See Users, Groups & Authentication (note 05) for resolving profile folders back to account names and SIDs, and for the broader caveat that "this account's artifact shows X" is not the same fact as "the person who owns this account was physically at the keyboard."

## Tooling

| Tool | Form | What it gives you |
|---|---|---|
| **Registry Explorer** (Eric Zimmerman) | GUI | Opens `NTUSER.DAT` and natively decodes UserAssist's ROT-13 value names and binary field layout in its built-in UserAssist view — a good default given this repo's established Eric Zimmerman-suite convention (matches PECmd/AppCompatCacheParser/AmcacheParser/RECmd elsewhere) |
| **RECmd** (Eric Zimmerman) | CLI | Batch/scriptable registry parsing; can be pointed at UserAssist-specific batch definitions for bulk extraction across many collected `NTUSER.DAT` hives |
| RegRipper's `userassist` plugin | CLI (Perl-based plugin framework) | Long-standing purpose-built UserAssist parser predating the Eric Zimmerman suite; still commonly referenced in community write-ups and worth knowing by name even if Registry Explorer/RECmd are this repo's primary picks |

Note: the exact current name and packaging of a dedicated stand-alone Eric Zimmerman "UserAssist parser" utility has shifted over time as the suite has consolidated tooling into Registry Explorer/RECmd — confirm the latest tool list at the link in Resources before assuming a separate named binary exists.

### PowerShell

Sweep every loaded profile on a live host, mount an offline `NTUSER.DAT` from a profile that isn't currently loaded, or sweep an estate and export decoded entries for timeline pivoting:

```powershell
# Live host, every loaded user profile's UserAssist under HKEY_USERS - decode names and tag with the owning SID
# (requires the ConvertFrom-Rot13 function defined above)
Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$' } | ForEach-Object {
    $sid = $_.PSChildName
    Get-ChildItem "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" -ErrorAction SilentlyContinue | ForEach-Object {
        $guid = $_.PSChildName
        (Get-Item "$($_.PSPath)\Count" -ErrorAction SilentlyContinue).Property | ForEach-Object {
            [PSCustomObject]@{ SID = $sid; GUID = $guid; DecodedPath = ConvertFrom-Rot13 $_ }
        }
    }
}

# Offline NTUSER.DAT from a profile not currently loaded - mount under a temp hive name, query, then unload
reg load 'HKU\TempUserAssist' 'C:\Users\<profile>\NTUSER.DAT'
Get-ChildItem 'Registry::HKEY_USERS\TempUserAssist\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count' -ErrorAction SilentlyContinue
reg unload 'HKU\TempUserAssist'

# Cross-host sweep for a specific profile's decoded UserAssist entries, exported for timeline pivoting
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    function ConvertFrom-Rot13 { param([string]$Text) -join ($Text.ToCharArray() | ForEach-Object { if ($_ -match '[a-zA-Z]') { $base = if ([char]::IsUpper($_)) { 65 } else { 97 }; [char]((([int]$_ - $base + 13) % 26) + $base) } else { $_ } }) }
    (Get-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count' -ErrorAction SilentlyContinue).Property |
        ForEach-Object { [PSCustomObject]@{ ComputerName = $env:COMPUTERNAME; DecodedPath = ConvertFrom-Rot13 $_ } }
} | Export-Csv C:\hunt\userassist_sweep.csv -NoTypeInformation
```

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| High run count, near-zero focus time, for a suspicious application | Consistent with a brief/incidental launch (opened and immediately closed) rather than sustained user interaction — useful for "did they actually use it" questions |
| Large focus time and focus count for a file/tool tied to sensitive data shortly before an incident | Suggests the user actively worked in that application/file, not a passing click — relevant to insider-threat scoping |
| No UserAssist entry for a binary otherwise confirmed to have executed via Prefetch/ShimCache/Amcache/BAM-DAM | Expected, not suspicious, if the launch was command-line/scripted/service-initiated — do not treat the absence as contradicting the other artifacts |
| UserAssist entry present under only one of the two GUID subkeys when both were checked | Normal — confirms which launch method (direct exe vs. shortcut) was used; only a problem if the analyst assumed the other subkey was equivalent and skipped it |
| Entry attributed to a profile not believed to be in active use at the time of the incident | Possible lateral use of a secondary/service/shared account profile — resolve via Users, Groups & Authentication (note 05) |
| Analyst report treats a missing UserAssist entry as proof malware never ran | Overstates the artifact's scope — restate as "no shell-initiated launch recorded" and pivot to Prefetch/ShimCache/Amcache/BAM-DAM for a general execution claim |

## Correlate With

- **Prefetch** (same folder) — full eight-artifact "evidence of execution" comparison table lives there; corroborate UserAssist's GUI-launch claim against Prefetch's path-specific run proof.
- **ShimCache (AppCompatCache)** — corroborate whether a file UserAssist shows was double-clicked also existed on disk with a consistent last-modified time.
- **Amcache** — cross-check hash/compile-time/install-path detail for a binary UserAssist shows was launched through the shell.
- **BAM/DAM** — both are per-user execution signals; BAM/DAM adds a genuine recent last-run timestamp with less than a week of retention, while UserAssist persists longer and adds run count plus focus data, but is scoped to shell launches only.
- **Jump Lists** — Explorer-adjacent artifact covering which files were opened with which application; strong complement when the question is "what did the user do inside the program they launched," not just "did they launch it."
- **Users, Groups & Authentication** — resolving which `NTUSER.DAT`/profile an entry belongs to, and the caveats around attributing an artifact to the person who owns the account.
- **Registry Forensics Fundamentals** — hive structure, `NTUSER.DAT` acquisition (live vs. offline), and transaction-log mechanics that apply to parsing this key correctly.

## Resources

- SANS FOR500 poster, "Windows Artifact Analysis: Evidence of… Application Execution" panel, UserAssist entry — `Windows/SANS_DFPS_FOR500_v4.18_09-24.pdf` (bundled in this repo)
- SANS FOR508 "Hunt Evil" poster — `Windows/SANS_DFPS_FOR508_v4.11_0624.pdf` (bundled in this repo)
- Eric Zimmerman's tools (Registry Explorer, RECmd) — https://ericzimmerman.github.io/
- RegRipper (`userassist` plugin) — https://github.com/keydet89/RegRipper3.0
- SANS FOR500 course syllabus (public) — UserAssist coverage checklist
